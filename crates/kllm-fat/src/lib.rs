//! Strict bounded read-only FAT32 provider.
#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;

use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::char::decode_utf16;
use core::fmt;
use kllm_block::{BlockDevice, BlockError, BlockRegion};
use kllm_vfs::{
    DirEntry, FileMetadata, FsError, MAX_NAME_BYTES, NodeKind, ProviderListing, ReadOnlyFileSystem,
    canonicalize,
};

const FAT32_MIN_CLUSTERS: u32 = 65_525;
const FAT32_MAX_CLUSTER: u32 = 0x0fff_ffef;
const FAT32_BAD_CLUSTER: u32 = 0x0fff_fff7;
const FAT32_EOC_MIN: u32 = 0x0fff_fff8;
const DIRECTORY_ENTRY_BYTES: usize = 32;
const LFN_UNITS_PER_ENTRY: usize = 13;
const MAX_LFN_ENTRIES: usize = 20;
const MAX_LFN_UNITS: usize = LFN_UNITS_PER_ENTRY * MAX_LFN_ENTRIES;

/// Per-mount traversal and retention ceilings.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Fat32Limits {
    chain_clusters: u32,
    directory_entries: u32,
    file_bytes: u64,
    read_bytes: usize,
    name_bytes: usize,
}

impl Fat32Limits {
    /// Construct a checked read-only provider profile.
    ///
    /// # Errors
    ///
    /// Rejects empty limits, names above the VFS component bound, reads above
    /// 1 MiB, or file/chain limits that cannot describe one byte.
    pub const fn new(
        max_chain_clusters: u32,
        max_directory_entries: u32,
        max_file_bytes: u64,
        max_read_bytes: usize,
        max_name_bytes: usize,
    ) -> Result<Self, FsError> {
        if max_chain_clusters == 0
            || max_directory_entries == 0
            || max_file_bytes == 0
            || max_read_bytes == 0
            || max_read_bytes > 1024 * 1024
            || max_name_bytes == 0
            || max_name_bytes > MAX_NAME_BYTES
        {
            return Err(FsError::Invalid);
        }
        Ok(Self {
            chain_clusters: max_chain_clusters,
            directory_entries: max_directory_entries,
            file_bytes: max_file_bytes,
            read_bytes: max_read_bytes,
            name_bytes: max_name_bytes,
        })
    }

    /// Maximum clusters retained while validating one chain.
    #[must_use]
    pub const fn max_chain_clusters(self) -> u32 {
        self.chain_clusters
    }

    /// Maximum live entries scanned in one directory.
    #[must_use]
    pub const fn max_directory_entries(self) -> u32 {
        self.directory_entries
    }

    /// Maximum file size exposed through this mount.
    #[must_use]
    pub const fn max_file_bytes(self) -> u64 {
        self.file_bytes
    }

    /// Maximum destination size for one provider read.
    #[must_use]
    pub const fn max_read_bytes(self) -> usize {
        self.read_bytes
    }

    /// Maximum retained UTF-8 bytes in one long or short name.
    #[must_use]
    pub const fn max_name_bytes(self) -> usize {
        self.name_bytes
    }
}

#[derive(Clone, Copy, Debug)]
struct Layout {
    block_bytes: usize,
    sectors_per_cluster: u32,
    fat_start: u64,
    fat_sectors: u32,
    second_fat_start: u64,
    data_start: u64,
    cluster_count: u32,
    root_cluster: u32,
}

impl Layout {
    fn cluster_bytes(self) -> Result<usize, FsError> {
        usize::try_from(self.sectors_per_cluster)
            .ok()
            .and_then(|sectors| sectors.checked_mul(self.block_bytes))
            .ok_or(FsError::Overflow)
    }

    fn last_cluster(self) -> Result<u32, FsError> {
        self.cluster_count.checked_add(1).ok_or(FsError::Overflow)
    }
}

#[derive(Clone, Debug)]
struct FatEntry {
    name: String,
    kind: NodeKind,
    first_cluster: u32,
    byte_count: u64,
}

/// Mounted strict FAT32 provider owning exactly one block-region capability.
pub struct Fat32<D: BlockDevice> {
    region: BlockRegion<D>,
    limits: Fat32Limits,
    layout: Layout,
}

impl<D: BlockDevice> fmt::Debug for Fat32<D> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Fat32")
            .field("limits", &self.limits)
            .field("layout", &self.layout)
            .finish_non_exhaustive()
    }
}

impl<D: BlockDevice> Fat32<D> {
    /// Validate and mount a clean strict FAT32 volume.
    ///
    /// # Errors
    ///
    /// Rejects invalid limits, geometry, BPB/backup/FSInfo fields, FAT copies,
    /// root metadata, unsupported features, allocation failure, and block I/O.
    pub fn mount(mut region: BlockRegion<D>, limits: Fat32Limits) -> Result<Self, FsError> {
        validate_limits(limits)?;
        let info = region.info();
        if info.required_alignment_blocks() != 1 || info.block_bytes() < 512 {
            return Err(FsError::Unsupported);
        }
        let block_bytes = usize::try_from(info.block_bytes()).map_err(|_| FsError::Overflow)?;
        let boot = read_sector(&mut region, 0, block_bytes)?;
        let bpb = parse_bpb(&boot, info.block_count(), block_bytes)?;
        let backup = read_sector(&mut region, u64::from(bpb.backup_sector), block_bytes)?;
        if boot != backup {
            return Err(FsError::Corrupt);
        }
        let fsinfo = read_sector(&mut region, u64::from(bpb.fsinfo_sector), block_bytes)?;
        validate_fsinfo(&fsinfo, bpb.cluster_count)?;
        let layout = Layout {
            block_bytes,
            sectors_per_cluster: u32::from(bpb.sectors_per_cluster),
            fat_start: u64::from(bpb.reserved_sectors),
            fat_sectors: bpb.fat_sectors,
            second_fat_start: u64::from(bpb.reserved_sectors) + u64::from(bpb.fat_sectors),
            data_start: bpb.data_start,
            cluster_count: bpb.cluster_count,
            root_cluster: bpb.root_cluster,
        };
        let mut mounted = Self {
            region,
            limits,
            layout,
        };
        let media = mounted.read_fat_entry(0)?;
        let reserved = mounted.read_fat_entry(1)?;
        if media & 0xff != u32::from(bpb.media) || media < FAT32_EOC_MIN || reserved < FAT32_EOC_MIN
        {
            return Err(FsError::Corrupt);
        }
        let _root = mounted.read_directory(layout.root_cluster)?;
        Ok(mounted)
    }

    fn resolve(&mut self, path: &str) -> Result<FatEntry, FsError> {
        let normalized = canonicalize("/", path)?;
        if normalized != path || !path.starts_with('/') {
            return Err(FsError::Invalid);
        }
        let mut current = FatEntry {
            name: "/".to_string(),
            kind: NodeKind::Directory,
            first_cluster: self.layout.root_cluster,
            byte_count: 0,
        };
        if normalized == "/" {
            return Ok(current);
        }
        for component in normalized.trim_start_matches('/').split('/') {
            if current.kind != NodeKind::Directory {
                return Err(FsError::WrongType);
            }
            let entries = self.read_directory(current.first_cluster)?;
            let mut matched = None;
            for entry in entries {
                if names_equal(&entry.name, component) {
                    if matched.is_some() {
                        return Err(FsError::Corrupt);
                    }
                    matched = Some(entry);
                }
            }
            current = matched.ok_or(FsError::NotFound)?;
        }
        Ok(current)
    }

    fn cluster_chain(&mut self, first: u32) -> Result<Vec<u32>, FsError> {
        if first < 2 || first > self.layout.last_cluster()? {
            return Err(FsError::Corrupt);
        }
        let mut chain = Vec::new();
        chain
            .try_reserve_exact(
                usize::try_from(self.limits.max_chain_clusters()).map_err(|_| FsError::Overflow)?,
            )
            .map_err(|_| FsError::NoSpace)?;
        let mut current = first;
        loop {
            if chain.len()
                >= usize::try_from(self.limits.max_chain_clusters())
                    .map_err(|_| FsError::Overflow)?
                || chain.contains(&current)
            {
                return Err(FsError::Corrupt);
            }
            chain.push(current);
            let next = self.read_fat_entry(current)?;
            if next >= FAT32_EOC_MIN {
                return Ok(chain);
            }
            if next < 2
                || next == FAT32_BAD_CLUSTER
                || next > self.layout.last_cluster()?
                || (0x0fff_fff0..FAT32_EOC_MIN).contains(&next)
            {
                return Err(FsError::Corrupt);
            }
            current = next;
        }
    }

    fn read_fat_entry(&mut self, cluster: u32) -> Result<u32, FsError> {
        if cluster > self.layout.last_cluster()? {
            return Err(FsError::Corrupt);
        }
        let offset = u64::from(cluster).checked_mul(4).ok_or(FsError::Overflow)?;
        let block_bytes = u64::try_from(self.layout.block_bytes).map_err(|_| FsError::Overflow)?;
        let sector_offset = offset / block_bytes;
        if sector_offset >= u64::from(self.layout.fat_sectors) {
            return Err(FsError::Corrupt);
        }
        let byte_offset = usize::try_from(offset % block_bytes).map_err(|_| FsError::Overflow)?;
        let first = read_sector(
            &mut self.region,
            self.layout.fat_start + sector_offset,
            self.layout.block_bytes,
        )?;
        let second = read_sector(
            &mut self.region,
            self.layout.second_fat_start + sector_offset,
            self.layout.block_bytes,
        )?;
        let first_value = read_u32(&first, byte_offset)? & 0x0fff_ffff;
        let second_value = read_u32(&second, byte_offset)? & 0x0fff_ffff;
        if first_value != second_value {
            return Err(FsError::Corrupt);
        }
        Ok(first_value)
    }

    fn cluster_lba(&self, cluster: u32) -> Result<u64, FsError> {
        if cluster < 2 || cluster > self.layout.last_cluster()? {
            return Err(FsError::Corrupt);
        }
        self.layout
            .data_start
            .checked_add(
                u64::from(cluster - 2)
                    .checked_mul(u64::from(self.layout.sectors_per_cluster))
                    .ok_or(FsError::Overflow)?,
            )
            .ok_or(FsError::Overflow)
    }

    fn read_cluster(&mut self, cluster: u32) -> Result<Vec<u8>, FsError> {
        let cluster_bytes = self.layout.cluster_bytes()?;
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(cluster_bytes)
            .map_err(|_| FsError::NoSpace)?;
        bytes.resize(cluster_bytes, 0);
        let first_lba = self.cluster_lba(cluster)?;
        for sector in 0..self.layout.sectors_per_cluster {
            let start = usize::try_from(sector)
                .ok()
                .and_then(|value| value.checked_mul(self.layout.block_bytes))
                .ok_or(FsError::Overflow)?;
            let end = start
                .checked_add(self.layout.block_bytes)
                .ok_or(FsError::Overflow)?;
            self.region
                .read_blocks(first_lba + u64::from(sector), 1, &mut bytes[start..end])
                .map_err(map_block)?;
        }
        Ok(bytes)
    }

    fn read_directory(&mut self, first_cluster: u32) -> Result<Vec<FatEntry>, FsError> {
        let chain = self.cluster_chain(first_cluster)?;
        let mut entries = Vec::new();
        entries
            .try_reserve_exact(
                usize::try_from(self.limits.max_directory_entries())
                    .map_err(|_| FsError::Overflow)?,
            )
            .map_err(|_| FsError::NoSpace)?;
        let mut lfn = LfnState::default();
        for cluster in chain {
            let bytes = self.read_cluster(cluster)?;
            for raw in bytes.chunks_exact(DIRECTORY_ENTRY_BYTES) {
                let first = raw[0];
                if first == 0 {
                    return Ok(entries);
                }
                if first == 0xe5 {
                    lfn.reset();
                    continue;
                }
                let attributes = raw[11];
                if attributes == 0x0f {
                    lfn.push(raw)?;
                    continue;
                }
                if attributes & 0xc0 != 0 {
                    return Err(FsError::Corrupt);
                }
                if attributes & 0x08 != 0 {
                    lfn.reset();
                    continue;
                }
                if entries.len()
                    >= usize::try_from(self.limits.max_directory_entries())
                        .map_err(|_| FsError::Overflow)?
                {
                    return Err(FsError::NoSpace);
                }
                let short_checksum = short_name_checksum(&raw[..11]);
                let name = if lfn.active {
                    lfn.finish(short_checksum, self.limits.max_name_bytes())?
                } else {
                    short_name(raw, self.limits.max_name_bytes())?
                };
                lfn.reset();
                if name == "." || name == ".." {
                    continue;
                }
                let high = u32::from(read_u16(raw, 20)?);
                let low = u32::from(read_u16(raw, 26)?);
                let first_cluster = (high << 16) | low;
                let byte_count = u64::from(read_u32(raw, 28)?);
                let kind = if attributes & 0x10 != 0 {
                    if first_cluster < 2 || byte_count != 0 {
                        return Err(FsError::Corrupt);
                    }
                    NodeKind::Directory
                } else {
                    if byte_count > self.limits.max_file_bytes()
                        || (byte_count == 0 && first_cluster != 0)
                        || (byte_count != 0 && first_cluster < 2)
                    {
                        return Err(FsError::Corrupt);
                    }
                    NodeKind::File
                };
                entries.push(FatEntry {
                    name,
                    kind,
                    first_cluster,
                    byte_count,
                });
            }
        }
        Err(FsError::Corrupt)
    }
}

impl<D: BlockDevice> ReadOnlyFileSystem for Fat32<D> {
    fn metadata(&mut self, path: &str) -> Result<FileMetadata, FsError> {
        let entry = self.resolve(path)?;
        Ok(FileMetadata {
            kind: entry.kind,
            byte_count: entry.byte_count,
        })
    }

    fn read_file(
        &mut self,
        path: &str,
        offset: u64,
        destination: &mut [u8],
    ) -> Result<usize, FsError> {
        if destination.len() > self.limits.max_read_bytes() {
            return Err(FsError::NoSpace);
        }
        let entry = self.resolve(path)?;
        if entry.kind != NodeKind::File {
            return Err(FsError::WrongType);
        }
        if offset >= entry.byte_count || destination.is_empty() {
            return Ok(0);
        }
        let remaining = entry.byte_count - offset;
        let wanted = destination
            .len()
            .min(usize::try_from(remaining).unwrap_or(usize::MAX));
        if entry.byte_count == 0 {
            return Ok(0);
        }
        let chain = self.cluster_chain(entry.first_cluster)?;
        let cluster_bytes = self.layout.cluster_bytes()?;
        let required_clusters = usize::try_from(entry.byte_count)
            .ok()
            .and_then(|bytes| bytes.checked_add(cluster_bytes - 1))
            .map(|bytes| bytes / cluster_bytes)
            .ok_or(FsError::Overflow)?;
        if chain.len() != required_clusters {
            return Err(FsError::Corrupt);
        }
        let mut file_offset = usize::try_from(offset).map_err(|_| FsError::Overflow)?;
        let mut copied = 0_usize;
        while copied < wanted {
            let cluster_index = file_offset / cluster_bytes;
            let in_cluster = file_offset % cluster_bytes;
            let cluster = *chain.get(cluster_index).ok_or(FsError::Corrupt)?;
            let bytes = self.read_cluster(cluster)?;
            let count = (wanted - copied).min(cluster_bytes - in_cluster);
            destination[copied..copied + count]
                .copy_from_slice(&bytes[in_cluster..in_cluster + count]);
            copied += count;
            file_offset = file_offset.checked_add(count).ok_or(FsError::Overflow)?;
        }
        Ok(copied)
    }

    fn list(
        &mut self,
        path: &str,
        cursor: u64,
        max_entries: usize,
        max_name_bytes: usize,
    ) -> Result<ProviderListing, FsError> {
        let directory = self.resolve(path)?;
        if directory.kind != NodeKind::Directory {
            return Err(FsError::WrongType);
        }
        let mut source = self.read_directory(directory.first_cluster)?;
        source.sort_unstable_by(|left, right| left.name.as_bytes().cmp(right.name.as_bytes()));
        let start = usize::try_from(cursor).map_err(|_| FsError::Invalid)?;
        if start > source.len() {
            return Err(FsError::Invalid);
        }
        let mut output = Vec::new();
        output
            .try_reserve_exact(max_entries.min(source.len() - start))
            .map_err(|_| FsError::NoSpace)?;
        let mut retained = 0_usize;
        let mut index = start;
        while index < source.len() {
            let entry = &source[index];
            let next = retained
                .checked_add(entry.name.len())
                .ok_or(FsError::Overflow)?;
            if output.len() >= max_entries || next > max_name_bytes {
                break;
            }
            output.push(DirEntry {
                name: entry.name.clone(),
                kind: entry.kind,
            });
            retained = next;
            index += 1;
        }
        Ok(ProviderListing {
            entries: output,
            next_cursor: (index < source.len()).then(|| u64::try_from(index).unwrap_or(u64::MAX)),
        })
    }
}

#[derive(Clone, Copy, Debug)]
struct Bpb {
    sectors_per_cluster: u8,
    reserved_sectors: u16,
    fat_sectors: u32,
    root_cluster: u32,
    fsinfo_sector: u16,
    backup_sector: u16,
    data_start: u64,
    cluster_count: u32,
    media: u8,
}

fn parse_bpb(boot: &[u8], region_blocks: u64, block_bytes: usize) -> Result<Bpb, FsError> {
    if boot.len() != block_bytes
        || boot.len() < 512
        || !((boot[0] == 0xeb && boot[2] == 0x90) || boot[0] == 0xe9)
        || boot[510..512] != [0x55, 0xaa]
        || read_u16(boot, 11)? != u16::try_from(block_bytes).map_err(|_| FsError::Unsupported)?
        || !boot[13].is_power_of_two()
        || boot[13] == 0
        || read_u16(boot, 17)? != 0
        || read_u16(boot, 19)? != 0
        || read_u16(boot, 22)? != 0
        || boot[16] != 2
        || read_u16(boot, 40)? != 0
        || read_u16(boot, 42)? != 0
        || boot[52..64].iter().any(|byte| *byte != 0)
        || boot[66] != 0x29
        || boot.get(82..90) != Some(b"FAT32   ")
    {
        return Err(FsError::Unsupported);
    }
    let reserved_sectors = read_u16(boot, 14)?;
    let total_sectors = read_u32(boot, 32)?;
    let fat_sectors = read_u32(boot, 36)?;
    let root_cluster = read_u32(boot, 44)?;
    let fsinfo_sector = read_u16(boot, 48)?;
    let backup_sector = read_u16(boot, 50)?;
    if reserved_sectors < 8
        || total_sectors == 0
        || u64::from(total_sectors) != region_blocks
        || fat_sectors == 0
        || fsinfo_sector == 0
        || fsinfo_sector >= reserved_sectors
        || backup_sector == 0
        || backup_sector >= reserved_sectors
        || fsinfo_sector == backup_sector
    {
        return Err(FsError::Corrupt);
    }
    let fats_total = u64::from(fat_sectors)
        .checked_mul(2)
        .ok_or(FsError::Overflow)?;
    let data_start = u64::from(reserved_sectors)
        .checked_add(fats_total)
        .ok_or(FsError::Overflow)?;
    let data_sectors = u64::from(total_sectors)
        .checked_sub(data_start)
        .ok_or(FsError::Corrupt)?;
    let cluster_count_u64 = data_sectors / u64::from(boot[13]);
    let cluster_count = u32::try_from(cluster_count_u64).map_err(|_| FsError::Unsupported)?;
    let fat_entries = u64::from(fat_sectors)
        .checked_mul(u64::try_from(block_bytes).map_err(|_| FsError::Overflow)?)
        .ok_or(FsError::Overflow)?
        / 4;
    if !(FAT32_MIN_CLUSTERS..=FAT32_MAX_CLUSTER - 1).contains(&cluster_count)
        || fat_entries < u64::from(cluster_count) + 2
        || root_cluster < 2
        || root_cluster > cluster_count + 1
    {
        return Err(FsError::Unsupported);
    }
    Ok(Bpb {
        sectors_per_cluster: boot[13],
        reserved_sectors,
        fat_sectors,
        root_cluster,
        fsinfo_sector,
        backup_sector,
        data_start,
        cluster_count,
        media: boot[21],
    })
}

fn validate_fsinfo(bytes: &[u8], cluster_count: u32) -> Result<(), FsError> {
    if bytes.len() < 512
        || read_u32(bytes, 0)? != 0x4161_5252
        || read_u32(bytes, 484)? != 0x6141_7272
        || read_u32(bytes, 508)? != 0xaa55_0000
    {
        return Err(FsError::Corrupt);
    }
    let free = read_u32(bytes, 488)?;
    let next = read_u32(bytes, 492)?;
    if (free != u32::MAX && free > cluster_count)
        || (next != u32::MAX && !(2..=cluster_count + 1).contains(&next))
    {
        return Err(FsError::Corrupt);
    }
    Ok(())
}

#[derive(Clone, Debug)]
struct LfnState {
    units: [u16; MAX_LFN_UNITS],
    expected: u8,
    checksum: u8,
    active: bool,
}

impl Default for LfnState {
    fn default() -> Self {
        Self {
            units: [0xffff; MAX_LFN_UNITS],
            expected: 0,
            checksum: 0,
            active: false,
        }
    }
}

impl LfnState {
    fn reset(&mut self) {
        *self = Self::default();
    }

    fn push(&mut self, raw: &[u8]) -> Result<(), FsError> {
        if raw.len() != DIRECTORY_ENTRY_BYTES || raw[12] != 0 || read_u16(raw, 26)? != 0 {
            return Err(FsError::Corrupt);
        }
        let sequence = raw[0];
        let ordinal = sequence & 0x1f;
        if ordinal == 0 || usize::from(ordinal) > MAX_LFN_ENTRIES || sequence & 0x80 != 0 {
            return Err(FsError::Corrupt);
        }
        if sequence & 0x40 != 0 {
            if self.active {
                return Err(FsError::Corrupt);
            }
            self.active = true;
            self.expected = ordinal;
            self.checksum = raw[13];
        }
        if !self.active || ordinal != self.expected || raw[13] != self.checksum {
            return Err(FsError::Corrupt);
        }
        let start = usize::from(ordinal - 1) * LFN_UNITS_PER_ENTRY;
        let offsets = [1, 3, 5, 7, 9, 14, 16, 18, 20, 22, 24, 28, 30];
        for (index, offset) in offsets.iter().enumerate() {
            self.units[start + index] = read_u16(raw, *offset)?;
        }
        self.expected -= 1;
        Ok(())
    }

    fn finish(&self, checksum: u8, max_name_bytes: usize) -> Result<String, FsError> {
        if !self.active || self.expected != 0 || self.checksum != checksum {
            return Err(FsError::Corrupt);
        }
        let mut length = self.units.len();
        let mut terminated = false;
        for (index, unit) in self.units.iter().enumerate() {
            if *unit == 0 {
                if !terminated {
                    length = index;
                    terminated = true;
                }
            } else if terminated && *unit != 0xffff {
                return Err(FsError::Corrupt);
            }
        }
        while length > 0 && self.units[length - 1] == 0xffff {
            length -= 1;
        }
        if length == 0 || self.units[..length].contains(&0xffff) {
            return Err(FsError::Corrupt);
        }
        let mut name = String::new();
        name.try_reserve(max_name_bytes)
            .map_err(|_| FsError::NoSpace)?;
        for character in decode_utf16(self.units[..length].iter().copied()) {
            let character = character.map_err(|_| FsError::Corrupt)?;
            if character == '/' || character == '\0' {
                return Err(FsError::Corrupt);
            }
            name.push(character);
            if name.len() > max_name_bytes {
                return Err(FsError::NoSpace);
            }
        }
        Ok(name)
    }
}

fn short_name(raw: &[u8], max_name_bytes: usize) -> Result<String, FsError> {
    let base = short_component(&raw[..8], raw[12] & 0x08 != 0)?;
    let extension = short_component(&raw[8..11], raw[12] & 0x10 != 0)?;
    if base.is_empty() {
        return Err(FsError::Corrupt);
    }
    let name = if extension.is_empty() {
        base
    } else {
        format!("{base}.{extension}")
    };
    if name.len() > max_name_bytes {
        return Err(FsError::NoSpace);
    }
    Ok(name)
}

fn short_component(bytes: &[u8], lowercase: bool) -> Result<String, FsError> {
    let end = bytes
        .iter()
        .position(|byte| *byte == b' ')
        .unwrap_or(bytes.len());
    if bytes[end..].iter().any(|byte| *byte != b' ') {
        return Err(FsError::Corrupt);
    }
    let mut output = String::new();
    for byte in &bytes[..end] {
        if !byte.is_ascii() || *byte < 0x20 || b"\"*+,/:;<=>?[\\]|".contains(byte) {
            return Err(FsError::Unsupported);
        }
        output.push(if lowercase {
            char::from(byte.to_ascii_lowercase())
        } else {
            char::from(*byte)
        });
    }
    Ok(output)
}

fn short_name_checksum(bytes: &[u8]) -> u8 {
    bytes
        .iter()
        .fold(0_u8, |sum, byte| sum.rotate_right(1).wrapping_add(*byte))
}

fn names_equal(left: &str, right: &str) -> bool {
    left == right || (left.is_ascii() && right.is_ascii() && left.eq_ignore_ascii_case(right))
}

fn read_sector<D: BlockDevice>(
    region: &mut BlockRegion<D>,
    lba: u64,
    block_bytes: usize,
) -> Result<Vec<u8>, FsError> {
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(block_bytes)
        .map_err(|_| FsError::NoSpace)?;
    bytes.resize(block_bytes, 0);
    region.read_blocks(lba, 1, &mut bytes).map_err(map_block)?;
    Ok(bytes)
}

fn validate_limits(limits: Fat32Limits) -> Result<(), FsError> {
    Fat32Limits::new(
        limits.max_chain_clusters(),
        limits.max_directory_entries(),
        limits.max_file_bytes(),
        limits.max_read_bytes(),
        limits.max_name_bytes(),
    )
    .map(|_| ())
}

const fn map_block(_error: BlockError) -> FsError {
    FsError::Io
}

fn read_u16(bytes: &[u8], offset: usize) -> Result<u16, FsError> {
    let value = bytes
        .get(offset..offset + 2)
        .and_then(|slice| <[u8; 2]>::try_from(slice).ok())
        .ok_or(FsError::Corrupt)?;
    Ok(u16::from_le_bytes(value))
}

fn read_u32(bytes: &[u8], offset: usize) -> Result<u32, FsError> {
    let value = bytes
        .get(offset..offset + 4)
        .and_then(|slice| <[u8; 4]>::try_from(slice).ok())
        .ok_or(FsError::Corrupt)?;
    Ok(u32::from_le_bytes(value))
}

#[cfg(test)]
mod tests {
    use alloc::collections::BTreeMap;
    use alloc::vec;
    use kllm_block::{BlockAccess, BlockGeometry, BlockLimits};

    use super::{
        BlockDevice, BlockError, BlockRegion, Fat32, Fat32Limits, FsError, NodeKind,
        ReadOnlyFileSystem, short_name_checksum,
    };

    const BLOCK_BYTES: usize = 512;
    const BLOCK_COUNT: u64 = 66_581;
    const FAT_SECTORS: u32 = 512;
    const FAT1: u64 = 32;
    const FAT2: u64 = FAT1 + FAT_SECTORS as u64;
    const DATA: u64 = FAT2 + FAT_SECTORS as u64;

    #[derive(Debug)]
    struct SparseDevice {
        geometry: BlockGeometry,
        blocks: BTreeMap<u64, [u8; BLOCK_BYTES]>,
    }

    impl BlockDevice for SparseDevice {
        fn geometry(&self) -> BlockGeometry {
            self.geometry
        }

        fn read_blocks(
            &mut self,
            start_block: u64,
            block_count: u32,
            destination: &mut [u8],
        ) -> Result<(), BlockError> {
            if block_count != 1 || destination.len() != BLOCK_BYTES || start_block >= BLOCK_COUNT {
                return Err(BlockError::Device);
            }
            destination.fill(0);
            if let Some(block) = self.blocks.get(&start_block) {
                destination.copy_from_slice(block);
            }
            Ok(())
        }
    }

    fn limits() -> Result<Fat32Limits, FsError> {
        Fat32Limits::new(32, 64, 64 * 1024, 4096, 64)
    }

    fn mount(device: SparseDevice) -> Result<Fat32<SparseDevice>, FsError> {
        let block_limits = BlockLimits::new(1, BLOCK_BYTES, 1).map_err(|_| FsError::Io)?;
        let region = BlockRegion::whole_device(device, BlockAccess::ReadOnly, block_limits)
            .map_err(|_| FsError::Io)?;
        Fat32::mount(region, limits()?)
    }

    fn valid_device() -> Result<SparseDevice, BlockError> {
        let mut blocks = BTreeMap::new();
        let mut boot = [0_u8; BLOCK_BYTES];
        boot[0..3].copy_from_slice(&[0xeb, 0x58, 0x90]);
        boot[3..11].copy_from_slice(b"KLLMFAT ");
        put_u16(&mut boot, 11, 512);
        boot[13] = 1;
        put_u16(&mut boot, 14, 32);
        boot[16] = 2;
        boot[21] = 0xf8;
        put_u32(&mut boot, 32, 66_581);
        put_u32(&mut boot, 36, FAT_SECTORS);
        put_u32(&mut boot, 44, 2);
        put_u16(&mut boot, 48, 1);
        put_u16(&mut boot, 50, 6);
        boot[64] = 0x80;
        boot[66] = 0x29;
        boot[67..71].copy_from_slice(&1_u32.to_le_bytes());
        boot[71..82].copy_from_slice(b"KLLM DATA  ");
        boot[82..90].copy_from_slice(b"FAT32   ");
        boot[510..512].copy_from_slice(&[0x55, 0xaa]);
        blocks.insert(0, boot);
        blocks.insert(6, boot);

        let mut fsinfo = [0_u8; BLOCK_BYTES];
        put_u32(&mut fsinfo, 0, 0x4161_5252);
        put_u32(&mut fsinfo, 484, 0x6141_7272);
        put_u32(&mut fsinfo, 488, u32::MAX);
        put_u32(&mut fsinfo, 492, u32::MAX);
        put_u32(&mut fsinfo, 508, 0xaa55_0000);
        blocks.insert(1, fsinfo);

        let mut fat = [0_u8; BLOCK_BYTES];
        for (cluster, value) in [
            (0, 0x0fff_fff8),
            (1, 0x0fff_ffff),
            (2, 0x0fff_ffff),
            (3, 0x0fff_ffff),
            (4, 0x0fff_ffff),
            (5, 0x0fff_ffff),
        ] {
            put_u32(&mut fat, cluster * 4, value);
        }
        blocks.insert(FAT1, fat);
        blocks.insert(FAT2, fat);

        let mut root = [0_u8; BLOCK_BYTES];
        short_entry(&mut root[0..32], b"HELLO   TXT", 0x20, 3, 5);
        short_entry(&mut root[32..64], b"SUBDIR     ", 0x10, 4, 0);
        lfn_entry(&mut root[64..96], b"LONGNA~1TXT", "Long Name.txt");
        short_entry(&mut root[96..128], b"LONGNA~1TXT", 0x20, 5, 4);
        root[128] = 0;
        blocks.insert(DATA, root);

        let mut hello = [0_u8; BLOCK_BYTES];
        hello[..5].copy_from_slice(b"hello");
        blocks.insert(DATA + 1, hello);
        let mut subdir = [0_u8; BLOCK_BYTES];
        short_entry(&mut subdir[0..32], b".          ", 0x10, 4, 0);
        short_entry(&mut subdir[32..64], b"..         ", 0x10, 2, 0);
        subdir[64] = 0;
        blocks.insert(DATA + 2, subdir);
        let mut long = [0_u8; BLOCK_BYTES];
        long[..4].copy_from_slice(b"long");
        blocks.insert(DATA + 3, long);

        Ok(SparseDevice {
            geometry: BlockGeometry::new(512, BLOCK_COUNT, 1, false, false)?,
            blocks,
        })
    }

    fn short_entry(raw: &mut [u8], name: &[u8; 11], attributes: u8, cluster: u32, size: u32) {
        raw.fill(0);
        raw[..11].copy_from_slice(name);
        raw[11] = attributes;
        let cluster_bytes = cluster.to_le_bytes();
        raw[20..22].copy_from_slice(&cluster_bytes[2..4]);
        raw[26..28].copy_from_slice(&cluster_bytes[..2]);
        put_u32(raw, 28, size);
    }

    fn lfn_entry(raw: &mut [u8], short: &[u8; 11], name: &str) {
        raw.fill(0xff);
        raw[0] = 0x41;
        raw[11] = 0x0f;
        raw[12] = 0;
        raw[13] = short_name_checksum(short);
        raw[26..28].fill(0);
        let offsets = [1, 3, 5, 7, 9, 14, 16, 18, 20, 22, 24, 28, 30];
        let mut units = name.encode_utf16().chain(core::iter::once(0));
        for offset in offsets {
            put_u16(raw, offset, units.next().unwrap_or(0xffff));
        }
    }

    fn put_u16(bytes: &mut [u8], offset: usize, value: u16) {
        bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
    }

    fn put_u32(bytes: &mut [u8], offset: usize, value: u32) {
        bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }

    #[test]
    fn mounts_lists_resolves_and_reads_short_and_long_names() -> Result<(), FsError> {
        let mut fat = mount(valid_device().map_err(|_| FsError::Io)?)?;
        assert_eq!(fat.metadata("/hello.txt")?.byte_count, 5);
        assert_eq!(fat.metadata("/SUBDIR")?.kind, NodeKind::Directory);
        assert_eq!(fat.metadata("/Long Name.txt")?.byte_count, 4);
        let listing = fat.list("/", 0, 2, 64)?;
        assert_eq!(listing.entries.len(), 2);
        assert!(listing.next_cursor.is_some());
        let mut bytes = [0_u8; 3];
        assert_eq!(fat.read_file("/HELLO.TXT", 1, &mut bytes)?, 3);
        assert_eq!(&bytes, b"ell");
        Ok(())
    }

    #[test]
    fn backup_fat_and_chain_corruption_fail_closed() -> Result<(), FsError> {
        let mut backup = valid_device().map_err(|_| FsError::Io)?;
        backup.blocks.get_mut(&6).ok_or(FsError::Io)?[3] ^= 1;
        assert!(matches!(mount(backup), Err(FsError::Corrupt)));

        let mut copies = valid_device().map_err(|_| FsError::Io)?;
        put_u32(copies.blocks.get_mut(&FAT2).ok_or(FsError::Io)?, 2 * 4, 3);
        assert!(matches!(mount(copies), Err(FsError::Corrupt)));
        Ok(())
    }

    #[test]
    fn invalid_bpb_lfn_and_limits_are_rejected() -> Result<(), FsError> {
        let mut bpb = valid_device().map_err(|_| FsError::Io)?;
        bpb.blocks.get_mut(&0).ok_or(FsError::Io)?[13] = 3;
        assert!(matches!(mount(bpb), Err(FsError::Unsupported)));

        let mut lfn = valid_device().map_err(|_| FsError::Io)?;
        lfn.blocks.get_mut(&DATA).ok_or(FsError::Io)?[64 + 13] ^= 1;
        assert!(matches!(mount(lfn), Err(FsError::Corrupt)));
        assert_eq!(Fat32Limits::new(0, 1, 1, 1, 1), Err(FsError::Invalid));
        Ok(())
    }

    #[test]
    fn read_and_listing_budgets_are_hard() -> Result<(), FsError> {
        let mut fat = mount(valid_device().map_err(|_| FsError::Io)?)?;
        let mut oversized = vec![0_u8; 4097];
        assert_eq!(
            fat.read_file("/HELLO.TXT", 0, &mut oversized),
            Err(FsError::NoSpace)
        );
        let page = fat.list("/", 0, 0, 0)?;
        assert!(page.entries.is_empty());
        assert_eq!(page.next_cursor, Some(0));
        assert_eq!(fat.list("/", 99, 1, 64), Err(FsError::Invalid));
        Ok(())
    }
}
