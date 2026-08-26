//! Strict bounded FAT32 provider with copy-on-write file mutation.
#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;
#[cfg(test)]
extern crate std;

use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::char::decode_utf16;
use core::fmt;
use troe_block::{BlockAccess, BlockDevice, BlockError, BlockRegion};
use troe_vfs::{
    DirEntry, FileMetadata, FsError, MAX_NAME_BYTES, NodeKind, ProviderListing, ReadOnlyFileSystem,
    canonicalize,
};

const FAT32_MIN_CLUSTERS: u32 = 65_525;
const FAT32_MAX_CLUSTER: u32 = 0x0fff_ffef;
const FAT32_BAD_CLUSTER: u32 = 0x0fff_fff7;
const FAT32_EOC_MIN: u32 = 0x0fff_fff8;
const FAT32_CLEAN_SHUTDOWN: u32 = 0x0800_0000;
const FAT32_NO_HARD_ERROR: u32 = 0x0400_0000;
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
    /// Construct a checked provider profile.
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
    reserved_sectors: u16,
    fsinfo_sector: u16,
    backup_sector: u16,
    volume_id: u32,
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
    short_name: [u8; 11],
    directory_slots: Vec<DirectorySlot>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct DirectorySlot {
    cluster: u32,
    offset: usize,
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
            reserved_sectors: bpb.reserved_sectors,
            fsinfo_sector: bpb.fsinfo_sector,
            backup_sector: bpb.backup_sector,
            volume_id: bpb.volume_id,
        };
        let mut mounted = Self {
            region,
            limits,
            layout,
        };
        let media = mounted.read_fat_entry(0)?;
        let reserved = mounted.read_fat_entry(1)?;
        if media & 0xff != u32::from(bpb.media)
            || media < FAT32_EOC_MIN
            || reserved < FAT32_EOC_MIN
            || reserved & (FAT32_CLEAN_SHUTDOWN | FAT32_NO_HARD_ERROR)
                != FAT32_CLEAN_SHUTDOWN | FAT32_NO_HARD_ERROR
        {
            return Err(FsError::Corrupt);
        }
        let _root = mounted.read_directory(layout.root_cluster)?;
        Ok(mounted)
    }

    /// FAT32 volume identifier copied from the extended BPB.
    #[must_use]
    pub const fn volume_id(&self) -> u32 {
        self.layout.volume_id
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
            short_name: [0; 11],
            directory_slots: Vec::new(),
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
        let mut lfn_slots = Vec::new();
        for cluster in chain {
            let bytes = self.read_cluster(cluster)?;
            for (slot_index, raw) in bytes.chunks_exact(DIRECTORY_ENTRY_BYTES).enumerate() {
                let slot = DirectorySlot {
                    cluster,
                    offset: slot_index
                        .checked_mul(DIRECTORY_ENTRY_BYTES)
                        .ok_or(FsError::Overflow)?,
                };
                let first = raw[0];
                if first == 0 {
                    return Ok(entries);
                }
                if first == 0xe5 {
                    lfn.reset();
                    lfn_slots.clear();
                    continue;
                }
                let attributes = raw[11];
                if attributes == 0x0f {
                    lfn.push(raw)?;
                    lfn_slots.try_reserve(1).map_err(|_| FsError::NoSpace)?;
                    lfn_slots.push(slot);
                    continue;
                }
                if attributes & 0xc0 != 0 {
                    return Err(FsError::Corrupt);
                }
                if attributes & 0x08 != 0 {
                    lfn.reset();
                    lfn_slots.clear();
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
                let mut directory_slots = core::mem::take(&mut lfn_slots);
                directory_slots
                    .try_reserve(1)
                    .map_err(|_| FsError::NoSpace)?;
                directory_slots.push(slot);
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
                    short_name: raw[..11].try_into().map_err(|_| FsError::Corrupt)?,
                    directory_slots,
                });
            }
        }
        Err(FsError::Corrupt)
    }

    fn ensure_writable(&self) -> Result<(), FsError> {
        let info = self.region.info();
        if info.access() != BlockAccess::ReadWrite {
            return Err(FsError::ReadOnly);
        }
        if !info.supports_flush() && !info.supports_force_unit_access() {
            return Err(FsError::Unsupported);
        }
        Ok(())
    }

    fn force_unit_access(&self) -> bool {
        let info = self.region.info();
        !info.supports_flush() && info.supports_force_unit_access()
    }

    fn write_sector(&mut self, lba: u64, bytes: &[u8]) -> Result<(), FsError> {
        if bytes.len() != self.layout.block_bytes {
            return Err(FsError::Invalid);
        }
        self.region
            .write_blocks(lba, 1, bytes, self.force_unit_access())
            .map_err(map_block)
    }

    fn durability_barrier(&mut self) -> Result<(), FsError> {
        self.ensure_writable()?;
        if self.region.info().supports_flush() {
            self.region.flush().map_err(map_block)?;
        }
        Ok(())
    }

    fn begin_mutation(&mut self) -> Result<(), FsError> {
        let reserved = self.read_fat_entry(1)?;
        self.write_fat_entry(1, reserved & !FAT32_CLEAN_SHUTDOWN)?;
        self.durability_barrier()
    }

    fn finish_mutation(&mut self) -> Result<(), FsError> {
        let reserved = self.read_fat_entry(1)?;
        self.write_fat_entry(1, reserved | FAT32_CLEAN_SHUTDOWN | FAT32_NO_HARD_ERROR)?;
        self.durability_barrier()
    }

    fn write_cluster(&mut self, cluster: u32, bytes: &[u8]) -> Result<(), FsError> {
        if bytes.len() != self.layout.cluster_bytes()? {
            return Err(FsError::Invalid);
        }
        let first_lba = self.cluster_lba(cluster)?;
        for sector in 0..self.layout.sectors_per_cluster {
            let start = usize::try_from(sector)
                .ok()
                .and_then(|value| value.checked_mul(self.layout.block_bytes))
                .ok_or(FsError::Overflow)?;
            let end = start
                .checked_add(self.layout.block_bytes)
                .ok_or(FsError::Overflow)?;
            self.write_sector(first_lba + u64::from(sector), &bytes[start..end])?;
        }
        Ok(())
    }

    fn write_fat_entry(&mut self, cluster: u32, value: u32) -> Result<(), FsError> {
        if cluster > self.layout.last_cluster()? || value > 0x0fff_ffff {
            return Err(FsError::Invalid);
        }
        let offset = u64::from(cluster).checked_mul(4).ok_or(FsError::Overflow)?;
        let block_bytes = u64::try_from(self.layout.block_bytes).map_err(|_| FsError::Overflow)?;
        let sector_offset = offset / block_bytes;
        if sector_offset >= u64::from(self.layout.fat_sectors) {
            return Err(FsError::Corrupt);
        }
        let byte_offset = usize::try_from(offset % block_bytes).map_err(|_| FsError::Overflow)?;
        let first_lba = self
            .layout
            .fat_start
            .checked_add(sector_offset)
            .ok_or(FsError::Overflow)?;
        let second_lba = self
            .layout
            .second_fat_start
            .checked_add(sector_offset)
            .ok_or(FsError::Overflow)?;
        let mut first = read_sector(&mut self.region, first_lba, self.layout.block_bytes)?;
        let second = read_sector(&mut self.region, second_lba, self.layout.block_bytes)?;
        if first != second {
            return Err(FsError::Corrupt);
        }
        let preserved = read_u32(&first, byte_offset)? & 0xf000_0000;
        first[byte_offset..byte_offset + 4].copy_from_slice(&(preserved | value).to_le_bytes());
        self.write_sector(first_lba, &first)?;
        self.write_sector(second_lba, &first)
    }

    fn find_free_clusters(&mut self, count: usize) -> Result<Vec<u32>, FsError> {
        if count == 0 {
            return Ok(Vec::new());
        }
        if count
            > usize::try_from(self.limits.max_chain_clusters()).map_err(|_| FsError::Overflow)?
        {
            return Err(FsError::NoSpace);
        }
        let entries_per_sector = self.layout.block_bytes / 4;
        let mut output = Vec::new();
        output
            .try_reserve_exact(count)
            .map_err(|_| FsError::NoSpace)?;
        for sector in 0..self.layout.fat_sectors {
            let first = read_sector(
                &mut self.region,
                self.layout.fat_start + u64::from(sector),
                self.layout.block_bytes,
            )?;
            let second = read_sector(
                &mut self.region,
                self.layout.second_fat_start + u64::from(sector),
                self.layout.block_bytes,
            )?;
            if first != second {
                return Err(FsError::Corrupt);
            }
            for index in 0..entries_per_sector {
                let cluster = usize::try_from(sector)
                    .ok()
                    .and_then(|value| value.checked_mul(entries_per_sector))
                    .and_then(|value| value.checked_add(index))
                    .and_then(|value| u32::try_from(value).ok())
                    .ok_or(FsError::Overflow)?;
                if cluster < 2 || cluster > self.layout.last_cluster()? {
                    continue;
                }
                if read_u32(&first, index * 4)?.trailing_zeros() >= 28 {
                    output.push(cluster);
                    if output.len() == count {
                        return Ok(output);
                    }
                }
            }
        }
        Err(FsError::NoSpace)
    }

    fn program_chain(&mut self, clusters: &[u32]) -> Result<(), FsError> {
        for (index, cluster) in clusters.iter().copied().enumerate() {
            let next = clusters.get(index + 1).copied().unwrap_or(0x0fff_ffff);
            self.write_fat_entry(cluster, next)?;
        }
        Ok(())
    }

    fn invalidate_fsinfo(&mut self) -> Result<(), FsError> {
        let primary_lba = u64::from(self.layout.fsinfo_sector);
        let mut bytes = read_sector(&mut self.region, primary_lba, self.layout.block_bytes)?;
        validate_fsinfo(&bytes, self.layout.cluster_count)?;
        bytes[488..496].fill(0xff);
        self.write_sector(primary_lba, &bytes)?;
        let backup = self
            .layout
            .backup_sector
            .checked_add(self.layout.fsinfo_sector)
            .filter(|sector| *sector < self.layout.reserved_sectors);
        if let Some(backup_sector) = backup {
            self.write_sector(u64::from(backup_sector), &bytes)?;
        }
        Ok(())
    }

    fn release_clusters(&mut self, clusters: &[u32]) -> Result<(), FsError> {
        if clusters.is_empty() {
            return Ok(());
        }
        for cluster in clusters {
            self.write_fat_entry(*cluster, 0)?;
        }
        self.invalidate_fsinfo()?;
        self.durability_barrier()
    }

    fn allocate_file_chain(&mut self, bytes: &[u8]) -> Result<Vec<u32>, FsError> {
        if bytes.is_empty() {
            return Ok(Vec::new());
        }
        let cluster_bytes = self.layout.cluster_bytes()?;
        let count = bytes
            .len()
            .checked_add(cluster_bytes - 1)
            .map(|value| value / cluster_bytes)
            .ok_or(FsError::Overflow)?;
        let clusters = self.find_free_clusters(count)?;
        let mut block = Vec::new();
        block
            .try_reserve_exact(cluster_bytes)
            .map_err(|_| FsError::NoSpace)?;
        block.resize(cluster_bytes, 0);
        for (index, cluster) in clusters.iter().copied().enumerate() {
            block.fill(0);
            let start = index.checked_mul(cluster_bytes).ok_or(FsError::Overflow)?;
            let end = start
                .checked_add(cluster_bytes)
                .map_or(bytes.len(), |candidate| candidate.min(bytes.len()));
            block[..end - start].copy_from_slice(&bytes[start..end]);
            self.write_cluster(cluster, &block)?;
        }
        if let Err(error) = self.program_chain(&clusters) {
            for cluster in &clusters {
                let _ignored = self.write_fat_entry(*cluster, 0);
            }
            return Err(error);
        }
        self.invalidate_fsinfo()?;
        self.durability_barrier()?;
        Ok(clusters)
    }

    fn resolve_parent(&mut self, path: &str) -> Result<(FatEntry, String), FsError> {
        let normalized = canonicalize("/", path)?;
        if normalized != path || path == "/" || !path.starts_with('/') {
            return Err(FsError::Invalid);
        }
        let (parent, name) = path.rsplit_once('/').ok_or(FsError::Invalid)?;
        if name.is_empty() || name.len() > self.limits.max_name_bytes() {
            return Err(FsError::Invalid);
        }
        let parent_path = if parent.is_empty() { "/" } else { parent };
        let parent = self.resolve(parent_path)?;
        if parent.kind != NodeKind::Directory {
            return Err(FsError::WrongType);
        }
        Ok((parent, name.to_string()))
    }

    fn reserve_directory_slots(
        &mut self,
        directory_cluster: u32,
        required: usize,
    ) -> Result<Vec<DirectorySlot>, FsError> {
        let cluster_bytes = self.layout.cluster_bytes()?;
        if required == 0 || required > cluster_bytes / DIRECTORY_ENTRY_BYTES {
            return Err(FsError::NoSpace);
        }
        let chain = self.cluster_chain(directory_cluster)?;
        let mut past_end = false;
        for cluster in &chain {
            let bytes = self.read_cluster(*cluster)?;
            let mut run = Vec::new();
            run.try_reserve_exact(required)
                .map_err(|_| FsError::NoSpace)?;
            for (index, raw) in bytes.chunks_exact(DIRECTORY_ENTRY_BYTES).enumerate() {
                if raw[0] == 0 {
                    past_end = true;
                }
                if past_end || raw[0] == 0xe5 {
                    run.push(DirectorySlot {
                        cluster: *cluster,
                        offset: index
                            .checked_mul(DIRECTORY_ENTRY_BYTES)
                            .ok_or(FsError::Overflow)?,
                    });
                    if run.len() == required {
                        return Ok(run);
                    }
                } else {
                    run.clear();
                }
            }
        }
        if chain.len()
            >= usize::try_from(self.limits.max_chain_clusters()).map_err(|_| FsError::Overflow)?
        {
            return Err(FsError::NoSpace);
        }
        let cluster = *self
            .find_free_clusters(1)?
            .first()
            .ok_or(FsError::NoSpace)?;
        let zeroes = alloc::vec![0_u8; cluster_bytes];
        self.write_cluster(cluster, &zeroes)?;
        self.write_fat_entry(cluster, 0x0fff_ffff)?;
        let tail = *chain.last().ok_or(FsError::Corrupt)?;
        if let Err(error) = self.write_fat_entry(tail, cluster) {
            let _ignored = self.write_fat_entry(cluster, 0);
            return Err(error);
        }
        self.invalidate_fsinfo()?;
        self.durability_barrier()?;
        let mut slots = Vec::new();
        slots
            .try_reserve_exact(required)
            .map_err(|_| FsError::NoSpace)?;
        for index in 0..required {
            slots.push(DirectorySlot {
                cluster,
                offset: index
                    .checked_mul(DIRECTORY_ENTRY_BYTES)
                    .ok_or(FsError::Overflow)?,
            });
        }
        Ok(slots)
    }

    fn write_directory_records(
        &mut self,
        slots: &[DirectorySlot],
        records: &[[u8; DIRECTORY_ENTRY_BYTES]],
    ) -> Result<(), FsError> {
        if slots.len() != records.len() || slots.is_empty() {
            return Err(FsError::Invalid);
        }
        let cluster = slots[0].cluster;
        if slots.iter().any(|slot| slot.cluster != cluster) {
            return Err(FsError::Unsupported);
        }
        let mut bytes = self.read_cluster(cluster)?;
        for (slot, record) in slots.iter().zip(records) {
            let destination = bytes
                .get_mut(slot.offset..slot.offset + DIRECTORY_ENTRY_BYTES)
                .ok_or(FsError::Corrupt)?;
            destination.copy_from_slice(record);
        }
        self.write_cluster(cluster, &bytes)
    }

    fn replace_directory_entry(
        &mut self,
        entry: &FatEntry,
        first_cluster: u32,
        byte_count: usize,
    ) -> Result<(), FsError> {
        let slot = *entry.directory_slots.last().ok_or(FsError::Corrupt)?;
        let mut bytes = self.read_cluster(slot.cluster)?;
        let raw = bytes
            .get_mut(slot.offset..slot.offset + DIRECTORY_ENTRY_BYTES)
            .ok_or(FsError::Corrupt)?;
        let cluster_bytes = first_cluster.to_le_bytes();
        raw[20..22].copy_from_slice(&cluster_bytes[2..4]);
        raw[26..28].copy_from_slice(&cluster_bytes[..2]);
        raw[28..32].copy_from_slice(
            &u32::try_from(byte_count)
                .map_err(|_| FsError::NoSpace)?
                .to_le_bytes(),
        );
        self.write_cluster(slot.cluster, &bytes)?;
        self.durability_barrier()
    }

    fn delete_directory_entry(&mut self, entry: &FatEntry) -> Result<(), FsError> {
        if entry.directory_slots.is_empty() {
            return Err(FsError::Corrupt);
        }
        let mut index = 0;
        while index < entry.directory_slots.len() {
            let cluster = entry.directory_slots[index].cluster;
            let mut bytes = self.read_cluster(cluster)?;
            while index < entry.directory_slots.len()
                && entry.directory_slots[index].cluster == cluster
            {
                let offset = entry.directory_slots[index].offset;
                *bytes.get_mut(offset).ok_or(FsError::Corrupt)? = 0xe5;
                index += 1;
            }
            self.write_cluster(cluster, &bytes)?;
        }
        self.durability_barrier()
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

    fn write_file(&mut self, path: &str, bytes: &[u8]) -> Result<(), FsError> {
        self.ensure_writable()?;
        if u64::try_from(bytes.len()).map_err(|_| FsError::NoSpace)? > self.limits.max_file_bytes()
            || u32::try_from(bytes.len()).is_err()
        {
            return Err(FsError::NoSpace);
        }
        let (parent, name) = self.resolve_parent(path)?;
        let entries = self.read_directory(parent.first_cluster)?;
        let mut matching = entries
            .iter()
            .filter(|entry| names_equal(&entry.name, &name));
        let existing = matching.next().cloned();
        if matching.next().is_some() {
            return Err(FsError::Corrupt);
        }
        if let Some(existing) = existing {
            if existing.kind != NodeKind::File {
                return Err(FsError::WrongType);
            }
            let old_chain = if existing.byte_count == 0 {
                Vec::new()
            } else {
                self.cluster_chain(existing.first_cluster)?
            };
            self.begin_mutation()?;
            let new_chain = self.allocate_file_chain(bytes)?;
            let first_cluster = new_chain.first().copied().unwrap_or(0);
            if let Err(error) = self.replace_directory_entry(&existing, first_cluster, bytes.len())
            {
                let _ignored = self.release_clusters(&new_chain);
                return Err(error);
            }
            self.release_clusters(&old_chain)?;
            return self.finish_mutation();
        }

        let provisional = directory_records(&name, &entries, 0, 0)?;
        self.begin_mutation()?;
        let slots = self.reserve_directory_slots(parent.first_cluster, provisional.len())?;
        let new_chain = self.allocate_file_chain(bytes)?;
        let records = directory_records(
            &name,
            &entries,
            new_chain.first().copied().unwrap_or(0),
            u32::try_from(bytes.len()).map_err(|_| FsError::NoSpace)?,
        )?;
        if let Err(error) = self
            .write_directory_records(&slots, &records)
            .and_then(|()| self.durability_barrier())
        {
            let _ignored = self.release_clusters(&new_chain);
            return Err(error);
        }
        self.finish_mutation()
    }

    fn remove_file(&mut self, path: &str) -> Result<(), FsError> {
        self.ensure_writable()?;
        let (parent, name) = self.resolve_parent(path)?;
        let entries = self.read_directory(parent.first_cluster)?;
        let mut matching = entries
            .into_iter()
            .filter(|entry| names_equal(&entry.name, &name));
        let entry = matching.next().ok_or(FsError::NotFound)?;
        if matching.next().is_some() {
            return Err(FsError::Corrupt);
        }
        if entry.kind != NodeKind::File {
            return Err(FsError::WrongType);
        }
        let old_chain = if entry.byte_count == 0 {
            Vec::new()
        } else {
            self.cluster_chain(entry.first_cluster)?
        };
        self.begin_mutation()?;
        self.delete_directory_entry(&entry)?;
        self.release_clusters(&old_chain)?;
        self.finish_mutation()
    }

    fn create_symlink(&mut self, _target: &str, _link_path: &str) -> Result<(), FsError> {
        self.ensure_writable()?;
        Err(FsError::Unsupported)
    }

    fn create_hard_link(&mut self, _existing: &str, _new_path: &str) -> Result<(), FsError> {
        self.ensure_writable()?;
        Err(FsError::Unsupported)
    }
}

fn directory_records(
    name: &str,
    entries: &[FatEntry],
    first_cluster: u32,
    byte_count: u32,
) -> Result<Vec<[u8; DIRECTORY_ENTRY_BYTES]>, FsError> {
    validate_writable_name(name)?;
    let exact = encode_exact_short_name(name);
    let exact_available = exact
        .as_ref()
        .is_some_and(|(raw, _)| entries.iter().all(|entry| entry.short_name != *raw));
    let (short, case_flags, long_name) = if exact_available {
        let (raw, flags) = exact.ok_or(FsError::Invalid)?;
        (raw, flags, false)
    } else {
        (unique_short_alias(name, entries)?, 0, true)
    };
    let mut records = Vec::new();
    if long_name {
        let units: Vec<u16> = name.encode_utf16().collect();
        if units.is_empty() || units.len() > 255 {
            return Err(FsError::Invalid);
        }
        let count = units.len().div_ceil(LFN_UNITS_PER_ENTRY);
        if count == 0 || count > MAX_LFN_ENTRIES {
            return Err(FsError::NoSpace);
        }
        records
            .try_reserve_exact(count + 1)
            .map_err(|_| FsError::NoSpace)?;
        let checksum = short_name_checksum(&short);
        for ordinal in (1..=count).rev() {
            let mut raw = [0xff_u8; DIRECTORY_ENTRY_BYTES];
            raw[0] = u8::try_from(ordinal).map_err(|_| FsError::Overflow)?;
            if ordinal == count {
                raw[0] |= 0x40;
            }
            raw[11] = 0x0f;
            raw[12] = 0;
            raw[13] = checksum;
            raw[26..28].fill(0);
            let offsets = [1, 3, 5, 7, 9, 14, 16, 18, 20, 22, 24, 28, 30];
            let start = (ordinal - 1)
                .checked_mul(LFN_UNITS_PER_ENTRY)
                .ok_or(FsError::Overflow)?;
            for (index, offset) in offsets.iter().copied().enumerate() {
                let unit_index = start.checked_add(index).ok_or(FsError::Overflow)?;
                let unit = units
                    .get(unit_index)
                    .copied()
                    .unwrap_or(if unit_index == units.len() { 0 } else { 0xffff });
                raw[offset..offset + 2].copy_from_slice(&unit.to_le_bytes());
            }
            records.push(raw);
        }
    } else {
        records.try_reserve_exact(1).map_err(|_| FsError::NoSpace)?;
    }
    let mut raw = [0_u8; DIRECTORY_ENTRY_BYTES];
    raw[..11].copy_from_slice(&short);
    raw[11] = 0x20;
    raw[12] = case_flags;
    let cluster = first_cluster.to_le_bytes();
    raw[20..22].copy_from_slice(&cluster[2..4]);
    raw[26..28].copy_from_slice(&cluster[..2]);
    raw[28..32].copy_from_slice(&byte_count.to_le_bytes());
    records.push(raw);
    Ok(records)
}

fn validate_writable_name(name: &str) -> Result<(), FsError> {
    if name.is_empty()
        || name == "."
        || name == ".."
        || name.ends_with([' ', '.'])
        || name
            .chars()
            .any(|character| character <= '\u{1f}' || "\"*/:<>?\\|".contains(character))
    {
        return Err(FsError::Invalid);
    }
    Ok(())
}

fn encode_exact_short_name(name: &str) -> Option<([u8; 11], u8)> {
    let (base, extension) = match name.rsplit_once('.') {
        Some((base, extension)) if !base.is_empty() && !extension.is_empty() => (base, extension),
        Some(_) => return None,
        None => (name, ""),
    };
    if base.len() > 8
        || extension.len() > 3
        || !base.bytes().all(short_name_byte)
        || !extension.bytes().all(short_name_byte)
    {
        return None;
    }
    let base_lower = component_case(base)?;
    let extension_lower = component_case(extension)?;
    let mut raw = [b' '; 11];
    for (destination, source) in raw[..8].iter_mut().zip(base.bytes()) {
        *destination = source.to_ascii_uppercase();
    }
    for (destination, source) in raw[8..].iter_mut().zip(extension.bytes()) {
        *destination = source.to_ascii_uppercase();
    }
    if raw[0] == 0xe5 {
        raw[0] = 0x05;
    }
    Some((
        raw,
        u8::from(base_lower) << 3 | u8::from(extension_lower) << 4,
    ))
}

fn short_name_byte(byte: u8) -> bool {
    byte.is_ascii() && byte > 0x20 && byte != 0x7f && !b"\"*+,./:;<=>?[\\]|".contains(&byte)
}

fn component_case(component: &str) -> Option<bool> {
    let has_lower = component.bytes().any(|byte| byte.is_ascii_lowercase());
    let has_upper = component.bytes().any(|byte| byte.is_ascii_uppercase());
    (!has_lower || !has_upper).then_some(has_lower)
}

fn unique_short_alias(name: &str, entries: &[FatEntry]) -> Result<[u8; 11], FsError> {
    let (base_source, extension_source) = name
        .rsplit_once('.')
        .filter(|(base, extension)| !base.is_empty() && !extension.is_empty())
        .unwrap_or((name, ""));
    let mut base = String::new();
    for character in base_source.chars() {
        if character.is_ascii_alphanumeric() || "$%'-_@~`!(){}^#&".contains(character) {
            base.push(character.to_ascii_uppercase());
        }
    }
    if base.is_empty() {
        base.push_str("FILE");
    }
    let mut extension = String::new();
    for character in extension_source.chars() {
        if extension.len() >= 3 {
            break;
        }
        if character.is_ascii_alphanumeric() || "$%'-_@~`!(){}^#&".contains(character) {
            extension.push(character.to_ascii_uppercase());
        }
    }
    for sequence in 1_u16..=9999 {
        let suffix = format!("~{sequence}");
        let prefix_bytes = 8_usize.checked_sub(suffix.len()).ok_or(FsError::Overflow)?;
        let mut raw = [b' '; 11];
        for (destination, source) in raw[..prefix_bytes].iter_mut().zip(base.bytes()) {
            *destination = source;
        }
        let suffix_start = prefix_bytes.min(base.len());
        raw[suffix_start..suffix_start + suffix.len()].copy_from_slice(suffix.as_bytes());
        for (destination, source) in raw[8..].iter_mut().zip(extension.bytes()) {
            *destination = source;
        }
        if entries.iter().all(|entry| entry.short_name != raw) {
            return Ok(raw);
        }
    }
    Err(FsError::NoSpace)
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
    volume_id: u32,
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
        volume_id: read_u32(boot, 67)?,
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

const fn map_block(error: BlockError) -> FsError {
    match error {
        BlockError::ReadOnly => FsError::ReadOnly,
        BlockError::Unsupported => FsError::Unsupported,
        _ => FsError::Io,
    }
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
    use alloc::format;
    use alloc::string::{String, ToString};
    use alloc::vec;
    use std::fs::{self, File, OpenOptions};
    use std::io::{Read, Seek, SeekFrom, Write};
    use std::path::{Path, PathBuf};
    use std::process::{Command, Output};
    use std::time::{SystemTime, UNIX_EPOCH};
    use troe_block::{BlockAccess, BlockGeometry, BlockLimits};

    use super::{
        BlockDevice, BlockError, BlockRegion, Fat32, Fat32Limits, FsError, NodeKind,
        ReadOnlyFileSystem, short_name_checksum,
    };

    const BLOCK_BYTES: usize = 512;
    const BLOCK_BYTES_U32: u32 = 512;
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

    #[derive(Debug)]
    struct FileDevice {
        file: File,
        geometry: BlockGeometry,
    }

    impl FileDevice {
        fn open(path: &Path) -> Result<Self, String> {
            let file = File::open(path).map_err(|error| error.to_string())?;
            let bytes = file.metadata().map_err(|error| error.to_string())?.len();
            if bytes == 0 || !bytes.is_multiple_of(BLOCK_BYTES as u64) {
                return Err("FAT32 test image has invalid length".into());
            }
            let geometry =
                BlockGeometry::new(BLOCK_BYTES_U32, bytes / BLOCK_BYTES as u64, 1, false, false)
                    .map_err(|error| format!("invalid image geometry: {error:?}"))?;
            Ok(Self { file, geometry })
        }

        fn open_writable(path: &Path) -> Result<Self, String> {
            let file = OpenOptions::new()
                .read(true)
                .write(true)
                .open(path)
                .map_err(|error| error.to_string())?;
            let bytes = file.metadata().map_err(|error| error.to_string())?.len();
            if bytes == 0 || !bytes.is_multiple_of(BLOCK_BYTES as u64) {
                return Err("FAT32 test image has invalid length".into());
            }
            let geometry =
                BlockGeometry::new(BLOCK_BYTES_U32, bytes / BLOCK_BYTES as u64, 1, true, false)
                    .map_err(|error| format!("invalid image geometry: {error:?}"))?;
            Ok(Self { file, geometry })
        }
    }

    impl BlockDevice for FileDevice {
        fn geometry(&self) -> BlockGeometry {
            self.geometry
        }

        fn read_blocks(
            &mut self,
            start_block: u64,
            block_count: u32,
            destination: &mut [u8],
        ) -> Result<(), BlockError> {
            let offset = start_block
                .checked_mul(BLOCK_BYTES as u64)
                .ok_or(BlockError::Device)?;
            let expected = usize::try_from(block_count)
                .ok()
                .and_then(|count| count.checked_mul(BLOCK_BYTES))
                .ok_or(BlockError::Device)?;
            if destination.len() != expected {
                return Err(BlockError::Device);
            }
            self.file
                .seek(SeekFrom::Start(offset))
                .and_then(|_| self.file.read_exact(destination))
                .map_err(|_| BlockError::Device)
        }

        fn write_blocks(
            &mut self,
            start_block: u64,
            block_count: u32,
            source: &[u8],
            force_unit_access: bool,
        ) -> Result<(), BlockError> {
            let offset = start_block
                .checked_mul(BLOCK_BYTES as u64)
                .ok_or(BlockError::Device)?;
            let expected = usize::try_from(block_count)
                .ok()
                .and_then(|count| count.checked_mul(BLOCK_BYTES))
                .ok_or(BlockError::Device)?;
            if source.len() != expected || force_unit_access {
                return Err(BlockError::Device);
            }
            self.file
                .seek(SeekFrom::Start(offset))
                .and_then(|_| self.file.write_all(source))
                .map_err(|_| BlockError::Device)
        }

        fn flush(&mut self) -> Result<(), BlockError> {
            self.file.sync_all().map_err(|_| BlockError::Device)
        }
    }

    struct TestDirectory(PathBuf);

    impl TestDirectory {
        fn create(label: &str) -> Result<Self, String> {
            let nonce = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(|error| error.to_string())?
                .as_nanos();
            let path =
                std::env::temp_dir().join(format!("troe-{label}-{}-{nonce}", std::process::id()));
            fs::create_dir(&path).map_err(|error| error.to_string())?;
            Ok(Self(path))
        }

        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ignored = fs::remove_dir_all(&self.0);
        }
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

        fn write_blocks(
            &mut self,
            start_block: u64,
            block_count: u32,
            source: &[u8],
            force_unit_access: bool,
        ) -> Result<(), BlockError> {
            if block_count != 1
                || source.len() != BLOCK_BYTES
                || start_block >= BLOCK_COUNT
                || force_unit_access
            {
                return Err(BlockError::Device);
            }
            let mut block = [0_u8; BLOCK_BYTES];
            block.copy_from_slice(source);
            self.blocks.insert(start_block, block);
            Ok(())
        }

        fn flush(&mut self) -> Result<(), BlockError> {
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

    fn mount_writable(device: SparseDevice) -> Result<Fat32<SparseDevice>, FsError> {
        let block_limits = BlockLimits::new(1, BLOCK_BYTES, 1).map_err(|_| FsError::Io)?;
        let region = BlockRegion::whole_device(device, BlockAccess::ReadWrite, block_limits)
            .map_err(|_| FsError::Io)?;
        Fat32::mount(region, limits()?)
    }

    fn mount_file(path: &Path) -> Result<Fat32<FileDevice>, String> {
        let device = FileDevice::open(path)?;
        let block_limits = BlockLimits::new(1, BLOCK_BYTES, 1)
            .map_err(|error| format!("invalid block limits: {error:?}"))?;
        let region = BlockRegion::whole_device(device, BlockAccess::ReadOnly, block_limits)
            .map_err(|error| format!("cannot grant image region: {error:?}"))?;
        Fat32::mount(region, limits().map_err(|error| error.to_string())?)
            .map_err(|error| error.to_string())
    }

    fn mount_file_writable(path: &Path) -> Result<Fat32<FileDevice>, String> {
        let device = FileDevice::open_writable(path)?;
        let block_limits = BlockLimits::new(1, BLOCK_BYTES, 1)
            .map_err(|error| format!("invalid block limits: {error:?}"))?;
        let region = BlockRegion::whole_device(device, BlockAccess::ReadWrite, block_limits)
            .map_err(|error| format!("cannot grant writable image region: {error:?}"))?;
        Fat32::mount(region, limits().map_err(|error| error.to_string())?)
            .map_err(|error| error.to_string())
    }

    fn fat_tool(name: &str) -> Option<PathBuf> {
        for prefix in ["/opt/homebrew/sbin", "/usr/local/sbin"] {
            let candidate = Path::new(prefix).join(name);
            if candidate.is_file() {
                return Some(candidate);
            }
        }
        Command::new(name)
            .arg("--help")
            .output()
            .ok()
            .map(|_| PathBuf::from(name))
    }

    fn mtool(name: &str) -> Option<PathBuf> {
        for prefix in ["/opt/homebrew/bin", "/usr/local/bin"] {
            let candidate = Path::new(prefix).join(name);
            if candidate.is_file() {
                return Some(candidate);
            }
        }
        Command::new(name)
            .arg("--version")
            .output()
            .ok()
            .map(|_| PathBuf::from(name))
    }

    fn command_succeeded(output: &Output, operation: &str) -> Result<(), String> {
        if output.status.success() {
            Ok(())
        } else {
            Err(format!(
                "{operation} failed with {}\nstdout:\n{}\nstderr:\n{}",
                output.status,
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            ))
        }
    }

    fn unavailable_tool(name: &str) -> Result<(), String> {
        if std::env::var_os("TROE_REQUIRE_FS_TOOLS").is_some() {
            Err(format!(
                "FAT32 interoperability test requires unavailable tool {name}"
            ))
        } else {
            std::eprintln!("FAT32 interoperability test skipped: {name} is unavailable");
            Ok(())
        }
    }

    fn valid_device() -> Result<SparseDevice, BlockError> {
        let mut blocks = BTreeMap::new();
        let mut boot = [0_u8; BLOCK_BYTES];
        boot[0..3].copy_from_slice(&[0xeb, 0x58, 0x90]);
        boot[3..11].copy_from_slice(b"TROEFAT ");
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
        boot[71..82].copy_from_slice(b"TROE DATA  ");
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
            geometry: BlockGeometry::new(512, BLOCK_COUNT, 1, true, false)?,
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

    fn verify_writer_interoperability(image: &Path, fsck_fat: &Path) -> Result<(), String> {
        let mut writable = mount_file_writable(image)?;
        writable
            .write_file("/Long Name.txt", b"modified by troe\n")
            .map_err(|error| error.to_string())?;
        writable
            .write_file("/Created Here.txt", b"created by troe\n")
            .map_err(|error| error.to_string())?;
        writable
            .remove_file("/nested/Message.txt")
            .map_err(|error| error.to_string())?;
        drop(writable);
        let post_write_check = Command::new(fsck_fat)
            .args(["-vn"])
            .arg(image)
            .output()
            .map_err(|error| error.to_string())?;
        command_succeeded(&post_write_check, "fsck.fat after TROE writes")?;
        let mut remounted = mount_file(image)?;
        let mut modified = [0_u8; 17];
        let count = remounted
            .read_file("/Long Name.txt", 0, &mut modified)
            .map_err(|error| error.to_string())?;
        assert_eq!(&modified[..count], b"modified by troe\n");
        assert!(matches!(
            remounted.metadata("/nested/Message.txt"),
            Err(FsError::NotFound)
        ));
        Ok(())
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

    #[test]
    fn creates_replaces_and_removes_short_long_and_nested_files() -> Result<(), FsError> {
        let mut fat = mount_writable(valid_device().map_err(|_| FsError::Io)?)?;

        let replacement = vec![b'r'; 700];
        fat.write_file("/hello.txt", &replacement)?;
        assert_eq!(fat.metadata("/HELLO.TXT")?.byte_count, 700);
        let mut replaced = vec![0_u8; 700];
        assert_eq!(fat.read_file("/hello.txt", 0, &mut replaced[..700])?, 700);
        assert_eq!(replaced, replacement);

        fat.write_file("/new.txt", b"short")?;
        fat.write_file("/A fresh file.txt", b"long name")?;
        fat.write_file("/SUBDIR/nested.bin", b"nested")?;
        assert_eq!(fat.metadata("/new.txt")?.byte_count, 5);
        assert_eq!(fat.metadata("/A fresh file.txt")?.byte_count, 9);
        assert_eq!(fat.metadata("/subdir/nested.bin")?.byte_count, 6);

        fat.remove_file("/Long Name.txt")?;
        assert_eq!(fat.metadata("/Long Name.txt"), Err(FsError::NotFound));
        fat.write_file("/empty", b"")?;
        assert_eq!(fat.metadata("/empty")?.byte_count, 0);
        fat.remove_file("/empty")?;
        assert_eq!(fat.metadata("/empty"), Err(FsError::NotFound));
        Ok(())
    }

    #[test]
    fn read_only_capability_rejects_mutation() -> Result<(), FsError> {
        let mut fat = mount(valid_device().map_err(|_| FsError::Io)?)?;
        assert_eq!(fat.write_file("/new.txt", b"data"), Err(FsError::ReadOnly));
        assert_eq!(fat.remove_file("/HELLO.TXT"), Err(FsError::ReadOnly));
        Ok(())
    }

    #[test]
    fn fat32_explicitly_rejects_symbolic_and_hard_links() -> Result<(), FsError> {
        let mut fat = mount_writable(valid_device().map_err(|_| FsError::Io)?)?;
        assert_eq!(
            fat.create_symlink("/HELLO.TXT", "/link"),
            Err(FsError::Unsupported)
        );
        assert_eq!(
            fat.create_hard_link("/HELLO.TXT", "/hard"),
            Err(FsError::Unsupported)
        );
        Ok(())
    }

    #[test]
    fn mutation_dirty_marker_brackets_durable_changes() -> Result<(), FsError> {
        let mut fat = mount_writable(valid_device().map_err(|_| FsError::Io)?)?;
        fat.begin_mutation()?;
        assert_eq!(fat.read_fat_entry(1)? & super::FAT32_CLEAN_SHUTDOWN, 0);
        fat.finish_mutation()?;
        assert_ne!(fat.read_fat_entry(1)? & super::FAT32_CLEAN_SHUTDOWN, 0);
        Ok(())
    }

    #[test]
    fn mounts_image_created_by_dosfstools_and_populated_by_mtools() -> Result<(), String> {
        let Some(mkfs_fat) = fat_tool("mkfs.fat") else {
            return unavailable_tool("mkfs.fat");
        };
        let Some(fsck_fat) = fat_tool("fsck.fat") else {
            return unavailable_tool("fsck.fat");
        };
        let Some(mmd) = mtool("mmd") else {
            return unavailable_tool("mmd");
        };
        let Some(mcopy) = mtool("mcopy") else {
            return unavailable_tool("mcopy");
        };
        let temporary = TestDirectory::create("fat32-real")?;
        let image = temporary.path().join("filesystem.fat32");
        File::create(&image)
            .and_then(|file| file.set_len(64 * 1024 * 1024))
            .map_err(|error| error.to_string())?;
        let format = Command::new(mkfs_fat)
            .args(["-F", "32", "-n", "TROETEST"])
            .arg(&image)
            .output()
            .map_err(|error| error.to_string())?;
        command_succeeded(&format, "mkfs.fat")?;
        let make_directory = Command::new(mmd)
            .args(["-i"])
            .arg(&image)
            .arg("::/nested")
            .output()
            .map_err(|error| error.to_string())?;
        command_succeeded(&make_directory, "mmd")?;
        let long_source = temporary.path().join("long-source.txt");
        fs::write(&long_source, b"hello from dosfstools\n").map_err(|error| error.to_string())?;
        let copy_long = Command::new(&mcopy)
            .args(["-i"])
            .arg(&image)
            .arg(&long_source)
            .arg("::/Long Name.txt")
            .output()
            .map_err(|error| error.to_string())?;
        command_succeeded(&copy_long, "mcopy long name")?;
        let nested_source = temporary.path().join("nested-source.txt");
        fs::write(&nested_source, b"nested FAT32 file\n").map_err(|error| error.to_string())?;
        let copy_nested = Command::new(mcopy)
            .args(["-i"])
            .arg(&image)
            .arg(&nested_source)
            .arg("::/nested/Message.txt")
            .output()
            .map_err(|error| error.to_string())?;
        command_succeeded(&copy_nested, "mcopy nested file")?;
        let check = Command::new(&fsck_fat)
            .args(["-vn"])
            .arg(&image)
            .output()
            .map_err(|error| error.to_string())?;
        command_succeeded(&check, "fsck.fat")?;

        let mut fat = mount_file(&image)?;
        let root = fat
            .list("/", 0, 16, 256)
            .map_err(|error| error.to_string())?;
        assert!(
            root.entries
                .iter()
                .any(|entry| entry.name == "Long Name.txt")
        );
        assert!(root.entries.iter().any(|entry| entry.name == "nested"));
        let mut long = [0_u8; 23];
        let count = fat
            .read_file("/Long Name.txt", 0, &mut long)
            .map_err(|error| error.to_string())?;
        assert_eq!(&long[..count], b"hello from dosfstools\n");
        let mut nested = [0_u8; 18];
        let count = fat
            .read_file("/nested/Message.txt", 0, &mut nested)
            .map_err(|error| error.to_string())?;
        assert_eq!(&nested[..count], b"nested FAT32 file\n");

        drop(fat);
        verify_writer_interoperability(&image, &fsck_fat)
    }
}
