//! Strict bounded FAT32 provider with copy-on-write file mutation.
#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;
#[cfg(test)]
extern crate std;

use alloc::format;
use alloc::rc::Rc;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::char::decode_utf16;
use core::fmt;
use troe_block::{BlockAccess, BlockDevice, BlockError, BlockRegion};
use troe_fs_api::{
    DirEntry, FileMetadata, FileSystemProvider, FsError, MAX_NAME_BYTES, NodeKind, ProviderListing,
    WallClock, canonicalize,
};

const FAT32_MIN_CLUSTERS: u32 = 65_525;
const FAT32_MAX_CLUSTER: u32 = 0x0fff_ffef;
const FAT32_BAD_CLUSTER: u32 = 0x0fff_fff7;
const FAT32_EOC_MIN: u32 = 0x0fff_fff8;
const FAT32_CLEAN_SHUTDOWN: u32 = 0x0800_0000;
const FAT32_NO_HARD_ERROR: u32 = 0x0400_0000;
const DIRECTORY_ENTRY_BYTES: usize = 32;
/// Short-entry offset of the creation time's tenths-of-a-second remainder.
const DIRECTORY_CREATE_TENTHS: usize = 13;
/// Short-entry offset of the creation time and date pair.
const DIRECTORY_CREATE_TIME: usize = 14;
/// Short-entry offset of the last-access date, which has no time part.
const DIRECTORY_ACCESS_DATE: usize = 18;
/// Short-entry offset of the last-write time and date pair.
const DIRECTORY_WRITE_TIME: usize = 22;
/// Short-entry byte ranges holding timestamps. They are disjoint because the
/// high half of the first cluster sits between the access date and the write
/// time.
const DIRECTORY_STAMP_RANGES: [core::ops::Range<usize>; 2] =
    [DIRECTORY_CREATE_TENTHS..20, DIRECTORY_WRITE_TIME..26];
/// First instant a FAT date encodes: its year field counts from 1980.
const DOS_EPOCH_SECONDS: u64 = 315_532_800;
/// Last instant a FAT date encodes, 2107-12-31T23:59:58, at the two-second
/// granularity of the write time.
const DOS_LAST_SECONDS: u64 = 4_354_819_198;
/// Seconds in one day, the step between DOS date fields.
const SECONDS_PER_DAY: u64 = 86_400;
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
    append_cursor: Option<FatAppendCursor>,
    read_cursor: Option<FatReadCursor>,
    /// Clock this provider stamps into the entries it writes.
    ///
    /// `None`, or a clock that reports no time, leaves an entry's date and
    /// time fields exactly as they were, which for a new entry means zero.
    wall_clock: Option<Rc<dyn WallClock>>,
}

#[derive(Clone, Debug)]
struct FatAppendCursor {
    path: String,
    byte_count: u64,
    tail: Option<u32>,
}

#[derive(Clone, Debug)]
struct FatReadCursor {
    path: String,
    byte_count: u64,
    cluster_index: usize,
    cluster: u32,
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
            append_cursor: None,
            read_cursor: None,
            wall_clock: None,
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

    /// The instant to stamp into an entry, or `None` to leave its fields be.
    ///
    /// The clock is read here, at the mutation, so a mount never stamps the
    /// instant it was attached onto a write that happened much later.
    fn wall_stamp(&self) -> Result<Option<DosStamp>, FsError> {
        self.wall_clock
            .as_ref()
            .and_then(|clock| clock.unix_seconds())
            .map(DosStamp::from_unix_seconds)
            .transpose()
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
        chain.try_reserve_exact(64).map_err(|_| FsError::NoSpace)?;
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

    fn chain_tail_for_bytes(&mut self, first: u32, byte_count: u64) -> Result<u32, FsError> {
        let cluster_bytes =
            u64::try_from(self.layout.cluster_bytes()?).map_err(|_| FsError::Overflow)?;
        let required = byte_count
            .checked_add(cluster_bytes - 1)
            .ok_or(FsError::Overflow)?
            / cluster_bytes;
        if required == 0 || required > u64::from(self.limits.max_chain_clusters()) {
            return Err(FsError::Corrupt);
        }
        let mut current = first;
        for index in 0..required {
            let next = self.read_fat_entry(current)?;
            if index + 1 == required {
                return (next >= FAT32_EOC_MIN)
                    .then_some(current)
                    .ok_or(FsError::Corrupt);
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
        Err(FsError::Corrupt)
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

    fn append_regular_file(&mut self, path: &str, bytes: &[u8]) -> Result<(), FsError> {
        self.read_cursor = None;
        self.ensure_writable()?;
        if bytes.is_empty() {
            return Ok(());
        }
        let normalized = canonicalize("/", path)?;
        if normalized != path {
            return Err(FsError::Invalid);
        }
        let (parent, name) = self.resolve_parent(path)?;
        let entries = self.read_directory(parent.first_cluster)?;
        let mut matching = entries
            .iter()
            .filter(|entry| names_equal(&entry.name, &name));
        let existing = matching.next().cloned().ok_or(FsError::NotFound)?;
        if matching.next().is_some() {
            return Err(FsError::Corrupt);
        }
        if existing.kind != NodeKind::File {
            return Err(FsError::WrongType);
        }
        let added = u64::try_from(bytes.len()).map_err(|_| FsError::Overflow)?;
        let next_size = existing
            .byte_count
            .checked_add(added)
            .ok_or(FsError::Overflow)?;
        if next_size > self.limits.max_file_bytes() || next_size > u64::from(u32::MAX) {
            return Err(FsError::NoSpace);
        }
        let mut tail = self
            .append_cursor
            .as_ref()
            .filter(|cursor| cursor.path == path && cursor.byte_count == existing.byte_count)
            .and_then(|cursor| cursor.tail);
        if existing.byte_count != 0 && tail.is_none() {
            tail = Some(self.chain_tail_for_bytes(existing.first_cluster, existing.byte_count)?);
        }

        self.begin_mutation()?;
        let cluster_bytes = self.layout.cluster_bytes()?;
        let partial = usize::try_from(
            existing.byte_count % u64::try_from(cluster_bytes).map_err(|_| FsError::Overflow)?,
        )
        .map_err(|_| FsError::Overflow)?;
        let mut consumed = 0_usize;
        if partial != 0 {
            let tail_cluster = tail.ok_or(FsError::Corrupt)?;
            let mut cluster = self.read_cluster(tail_cluster)?;
            consumed = bytes.len().min(cluster_bytes - partial);
            cluster[partial..partial + consumed].copy_from_slice(&bytes[..consumed]);
            self.write_cluster(tail_cluster, &cluster)?;
        }

        let new_chain = self.allocate_file_chain(&bytes[consumed..])?;
        let previous_tail = tail;
        if let Some(first_new) = new_chain.first().copied() {
            if let Some(previous) = previous_tail
                && let Err(error) = self.write_fat_entry(previous, first_new)
            {
                let _ignored = self.release_clusters(&new_chain);
                return Err(error);
            }
            tail = new_chain.last().copied();
        }
        let first_cluster = if existing.first_cluster == 0 {
            new_chain.first().copied().ok_or(FsError::Corrupt)?
        } else {
            existing.first_cluster
        };
        if let Err(error) = self.replace_directory_entry(
            &existing,
            first_cluster,
            usize::try_from(next_size).map_err(|_| FsError::NoSpace)?,
        ) {
            if let Some(previous) = previous_tail
                && !new_chain.is_empty()
            {
                let _ignored = self.write_fat_entry(previous, 0x0fff_ffff);
            }
            let _ignored = self.release_clusters(&new_chain);
            return Err(error);
        }
        self.finish_mutation()?;
        self.append_cursor = Some(FatAppendCursor {
            path: normalized,
            byte_count: next_size,
            tail,
        });
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

    fn release_chain_for_bytes(&mut self, first: u32, byte_count: u64) -> Result<(), FsError> {
        let cluster_bytes =
            u64::try_from(self.layout.cluster_bytes()?).map_err(|_| FsError::Overflow)?;
        let required = byte_count
            .checked_add(cluster_bytes - 1)
            .ok_or(FsError::Overflow)?
            / cluster_bytes;
        if required == 0 || required > u64::from(self.limits.max_chain_clusters()) {
            return Err(FsError::Corrupt);
        }
        let mut current = first;
        for index in 0..required {
            let next = self.read_fat_entry(current)?;
            let final_cluster = index + 1 == required;
            if final_cluster != (next >= FAT32_EOC_MIN) {
                return Err(FsError::Corrupt);
            }
            self.write_fat_entry(current, 0)?;
            if final_cluster {
                self.invalidate_fsinfo()?;
                return self.durability_barrier();
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
        Err(FsError::Corrupt)
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
        // Every caller reaches here because the file's payload changed, so the
        // write time advances while the creation time is left alone.
        let stamp = self.wall_stamp()?;
        let slot = *entry.directory_slots.last().ok_or(FsError::Corrupt)?;
        let mut bytes = self.read_cluster(slot.cluster)?;
        let raw = bytes
            .get_mut(slot.offset..slot.offset + DIRECTORY_ENTRY_BYTES)
            .ok_or(FsError::Corrupt)?;
        if let Some(stamp) = stamp {
            stamp.write_modification(raw)?;
        }
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

    fn update_directory_parent(
        &mut self,
        directory_cluster: u32,
        parent_cluster: u32,
    ) -> Result<(), FsError> {
        let mut bytes = self.read_cluster(directory_cluster)?;
        let raw = bytes
            .get_mut(DIRECTORY_ENTRY_BYTES..2 * DIRECTORY_ENTRY_BYTES)
            .ok_or(FsError::Corrupt)?;
        if raw[..11] != *b"..         " || raw[11] & 0x10 == 0 {
            return Err(FsError::Corrupt);
        }
        let encoded = parent_cluster.to_le_bytes();
        raw[20..22].copy_from_slice(&encoded[2..4]);
        raw[26..28].copy_from_slice(&encoded[..2]);
        self.write_cluster(directory_cluster, &bytes)?;
        self.durability_barrier()
    }
}

impl<D: BlockDevice> FileSystemProvider for Fat32<D> {
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
        let cluster_bytes = self.layout.cluster_bytes()?;
        let mut file_offset = usize::try_from(offset).map_err(|_| FsError::Overflow)?;
        let cluster_index = file_offset / cluster_bytes;
        let (mut current_index, mut cluster) = self
            .read_cursor
            .as_ref()
            .filter(|cursor| {
                cursor.path == path
                    && cursor.byte_count == entry.byte_count
                    && cursor.cluster_index <= cluster_index
            })
            .map_or((0, entry.first_cluster), |cursor| {
                (cursor.cluster_index, cursor.cluster)
            });
        while current_index < cluster_index {
            let next = self.read_fat_entry(cluster)?;
            if !(2..FAT32_EOC_MIN).contains(&next) || next > self.layout.last_cluster()? {
                return Err(FsError::Corrupt);
            }
            cluster = next;
            current_index += 1;
        }
        let mut copied = 0_usize;
        while copied < wanted {
            let in_cluster = file_offset % cluster_bytes;
            let bytes = self.read_cluster(cluster)?;
            let count = (wanted - copied).min(cluster_bytes - in_cluster);
            destination[copied..copied + count]
                .copy_from_slice(&bytes[in_cluster..in_cluster + count]);
            copied += count;
            file_offset = file_offset.checked_add(count).ok_or(FsError::Overflow)?;
            if copied < wanted {
                let next = self.read_fat_entry(cluster)?;
                if !(2..FAT32_EOC_MIN).contains(&next) || next > self.layout.last_cluster()? {
                    return Err(FsError::Corrupt);
                }
                cluster = next;
                current_index += 1;
            } else if offset
                .checked_add(u64::try_from(copied).map_err(|_| FsError::Overflow)?)
                .ok_or(FsError::Overflow)?
                == entry.byte_count
                && self.read_fat_entry(cluster)? < FAT32_EOC_MIN
            {
                return Err(FsError::Corrupt);
            }
        }
        self.read_cursor = Some(FatReadCursor {
            path: path.to_string(),
            byte_count: entry.byte_count,
            cluster_index: current_index,
            cluster,
        });
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

    fn truncate_file(&mut self, path: &str) -> Result<(), FsError> {
        self.write_file(path, &[])?;
        let normalized = canonicalize("/", path)?;
        self.append_cursor = Some(FatAppendCursor {
            path: normalized,
            byte_count: 0,
            tail: None,
        });
        Ok(())
    }

    fn append_file(&mut self, path: &str, bytes: &[u8]) -> Result<(), FsError> {
        self.append_regular_file(path, bytes)
    }

    fn sync_file(&mut self, _path: &str) -> Result<(), FsError> {
        self.durability_barrier()
    }

    fn write_file(&mut self, path: &str, bytes: &[u8]) -> Result<(), FsError> {
        self.append_cursor = None;
        self.read_cursor = None;
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
            self.begin_mutation()?;
            let new_chain = self.allocate_file_chain(bytes)?;
            let first_cluster = new_chain.first().copied().unwrap_or(0);
            if let Err(error) = self.replace_directory_entry(&existing, first_cluster, bytes.len())
            {
                let _ignored = self.release_clusters(&new_chain);
                return Err(error);
            }
            if existing.byte_count != 0 {
                self.release_chain_for_bytes(existing.first_cluster, existing.byte_count)?;
            }
            return self.finish_mutation();
        }

        let stamp = self.wall_stamp()?;
        let provisional = directory_records(stamp, &name, &entries, 0, 0)?;
        self.begin_mutation()?;
        let slots = self.reserve_directory_slots(parent.first_cluster, provisional.len())?;
        let new_chain = self.allocate_file_chain(bytes)?;
        let records = directory_records(
            stamp,
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

    fn create_directory(&mut self, path: &str) -> Result<(), FsError> {
        self.append_cursor = None;
        self.read_cursor = None;
        self.ensure_writable()?;
        let (parent, name) = self.resolve_parent(path)?;
        let entries = self.read_directory(parent.first_cluster)?;
        let mut matching = entries
            .iter()
            .filter(|entry| names_equal(&entry.name, &name));
        if matching.next().is_some() {
            if matching.next().is_some() {
                return Err(FsError::Corrupt);
            }
            return Err(FsError::Exists);
        }

        self.begin_mutation()?;
        let cluster_bytes = self.layout.cluster_bytes()?;
        let zeroes = alloc::vec![0_u8; cluster_bytes];
        let clusters = self.allocate_file_chain(&zeroes)?;
        let Some(cluster) = clusters.first().copied().filter(|_| clusters.len() == 1) else {
            let _ignored = self.release_clusters(&clusters);
            return Err(FsError::Corrupt);
        };
        let stamp = self.wall_stamp()?;
        let mut directory = zeroes;
        // `.` and `..` describe this directory, so they carry its own stamp
        // rather than one of their own.
        let initialize_entry = |raw: &mut [u8], name: &[u8; 11], target: u32| {
            raw.fill(0);
            raw[..11].copy_from_slice(name);
            raw[11] = 0x10;
            if let Some(stamp) = stamp {
                stamp.write_creation(raw)?;
                stamp.write_modification(raw)?;
            }
            let encoded = target.to_le_bytes();
            raw[20..22].copy_from_slice(&encoded[2..4]);
            raw[26..28].copy_from_slice(&encoded[..2]);
            Ok::<(), FsError>(())
        };
        initialize_entry(
            &mut directory[..DIRECTORY_ENTRY_BYTES],
            b".          ",
            cluster,
        )?;
        initialize_entry(
            &mut directory[DIRECTORY_ENTRY_BYTES..2 * DIRECTORY_ENTRY_BYTES],
            b"..         ",
            if parent.name == "/" {
                0
            } else {
                parent.first_cluster
            },
        )?;
        if let Err(error) = self.write_cluster(cluster, &directory) {
            let _ignored = self.release_clusters(&clusters);
            return Err(error);
        }

        let mut records = directory_records(stamp, &name, &entries, cluster, 0)?;
        let Some(short) = records.last_mut() else {
            let _ignored = self.release_clusters(&clusters);
            return Err(FsError::Corrupt);
        };
        short[11] = 0x10;
        let slots = match self.reserve_directory_slots(parent.first_cluster, records.len()) {
            Ok(slots) => slots,
            Err(error) => {
                let _ignored = self.release_clusters(&clusters);
                return Err(error);
            }
        };
        if let Err(error) = self
            .write_directory_records(&slots, &records)
            .and_then(|()| self.durability_barrier())
        {
            let _ignored = self.release_clusters(&clusters);
            return Err(error);
        }
        self.finish_mutation()
    }

    fn remove_file(&mut self, path: &str) -> Result<(), FsError> {
        self.append_cursor = None;
        self.read_cursor = None;
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
        self.begin_mutation()?;
        self.delete_directory_entry(&entry)?;
        if entry.byte_count != 0 {
            self.release_chain_for_bytes(entry.first_cluster, entry.byte_count)?;
        }
        self.finish_mutation()
    }

    fn remove_directory(&mut self, path: &str) -> Result<(), FsError> {
        self.append_cursor = None;
        self.read_cursor = None;
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
        if entry.kind != NodeKind::Directory {
            return Err(FsError::WrongType);
        }
        if !self.read_directory(entry.first_cluster)?.is_empty() {
            return Err(FsError::NotEmpty);
        }
        let clusters = self.cluster_chain(entry.first_cluster)?;
        self.begin_mutation()?;
        self.delete_directory_entry(&entry)?;
        self.release_clusters(&clusters)?;
        self.finish_mutation()
    }

    fn rename(&mut self, source: &str, destination: &str) -> Result<(), FsError> {
        self.append_cursor = None;
        self.read_cursor = None;
        self.ensure_writable()?;
        let normalized_source = canonicalize("/", source)?;
        let normalized_destination = canonicalize("/", destination)?;
        if normalized_source != source || normalized_destination != destination {
            return Err(FsError::Invalid);
        }
        if source == destination {
            self.resolve(source)?;
            return Ok(());
        }
        let (source_parent, source_name) = self.resolve_parent(source)?;
        let source_entries = self.read_directory(source_parent.first_cluster)?;
        let mut matching = source_entries
            .iter()
            .filter(|entry| names_equal(&entry.name, &source_name));
        let source_entry = matching.next().cloned().ok_or(FsError::NotFound)?;
        if matching.next().is_some() {
            return Err(FsError::Corrupt);
        }
        if source_entry.kind == NodeKind::Directory {
            let mut source_prefix = normalized_source.clone();
            source_prefix.push('/');
            if normalized_destination.starts_with(&source_prefix) {
                return Err(FsError::Invalid);
            }
        }
        let (destination_parent, destination_name) = self.resolve_parent(destination)?;
        let destination_entries = self.read_directory(destination_parent.first_cluster)?;
        if destination_entries
            .iter()
            .any(|entry| names_equal(&entry.name, &destination_name))
        {
            return Err(FsError::Exists);
        }
        let mut records = directory_records(
            None,
            &destination_name,
            &destination_entries,
            source_entry.first_cluster,
            u32::try_from(source_entry.byte_count).map_err(|_| FsError::Overflow)?,
        )?;
        if source_entry.kind == NodeKind::Directory {
            records.last_mut().ok_or(FsError::Corrupt)?[11] = 0x10;
        }
        // A rename moves a name, not its contents, so the destination record
        // inherits the source's stamps instead of taking the current time.
        let source_slot = *source_entry
            .directory_slots
            .last()
            .ok_or(FsError::Corrupt)?;
        let source_cluster = self.read_cluster(source_slot.cluster)?;
        let source_raw = source_cluster
            .get(source_slot.offset..source_slot.offset + DIRECTORY_ENTRY_BYTES)
            .ok_or(FsError::Corrupt)?;
        copy_timestamps(source_raw, records.last_mut().ok_or(FsError::Corrupt)?)?;

        self.begin_mutation()?;
        let slots =
            self.reserve_directory_slots(destination_parent.first_cluster, records.len())?;
        self.write_directory_records(&slots, &records)?;
        self.durability_barrier()?;
        if source_entry.kind == NodeKind::Directory
            && source_parent.first_cluster != destination_parent.first_cluster
        {
            self.update_directory_parent(
                source_entry.first_cluster,
                if destination_parent.name == "/" {
                    0
                } else {
                    destination_parent.first_cluster
                },
            )?;
        }
        self.delete_directory_entry(&source_entry)?;
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

    fn set_wall_clock(&mut self, clock: Rc<dyn WallClock>) {
        self.wall_clock = Some(clock);
    }
}

fn directory_records(
    stamp: Option<DosStamp>,
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
    // A record is created and written in the same instant, so both stamps and
    // the access date are the same reading of the clock.
    if let Some(stamp) = stamp {
        stamp.write_creation(&mut raw)?;
        stamp.write_modification(&mut raw)?;
    }
    let cluster = first_cluster.to_le_bytes();
    raw[20..22].copy_from_slice(&cluster[2..4]);
    raw[26..28].copy_from_slice(&cluster[..2]);
    raw[28..32].copy_from_slice(&byte_count.to_le_bytes());
    records.push(raw);
    Ok(records)
}

/// One instant already reduced to the fields a FAT directory entry stores.
///
/// FAT records local time with no timezone field. TROE has no timezone source,
/// so the wall clock's UTC reading is written unconverted and a host reading
/// the volume sees UTC. Inventing an offset would be a guess, and a wrong one
/// would be indistinguishable from a correct one on the media.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct DosStamp {
    /// Year from 1980, month, and day, packed as FAT stores them.
    date: u16,
    /// Hour, minute, and seconds/2: the write time's granularity is 2 seconds.
    time: u16,
    /// The second the packed time cannot express, in tenths.
    tenths: u8,
}

impl DosStamp {
    /// Reduce a Unix UTC instant to the FAT fields, clamped to what FAT can
    /// encode.
    ///
    /// The representable range is 1980-01-01 through 2107-12-31. A clock
    /// outside it is clamped to the nearer end rather than refused, because a
    /// refusal would leave the fields zero and a zero DOS date is not an old
    /// date but an invalid one that `fsck.vfat` reports.
    fn from_unix_seconds(seconds: u64) -> Result<Self, FsError> {
        let seconds = seconds.clamp(DOS_EPOCH_SECONDS, DOS_LAST_SECONDS);
        let (year, month, day) = civil_from_days(seconds / SECONDS_PER_DAY)?;
        let day_seconds = seconds % SECONDS_PER_DAY;
        let hour = u16::try_from(day_seconds / 3_600).map_err(|_| FsError::Overflow)?;
        let minute = u16::try_from((day_seconds % 3_600) / 60).map_err(|_| FsError::Overflow)?;
        let second = u16::try_from(day_seconds % 60).map_err(|_| FsError::Overflow)?;
        let from_1980 = year.checked_sub(1980).ok_or(FsError::Overflow)?;
        Ok(Self {
            date: (from_1980 << 9) | (month << 5) | day,
            time: (hour << 11) | (minute << 5) | (second / 2),
            tenths: u8::try_from((second % 2) * 10).map_err(|_| FsError::Overflow)?,
        })
    }

    /// Stamp this instant as an entry's creation time, and as the access date.
    fn write_creation(self, raw: &mut [u8]) -> Result<(), FsError> {
        *raw.get_mut(DIRECTORY_CREATE_TENTHS)
            .ok_or(FsError::Corrupt)? = self.tenths;
        put_u16_at(raw, DIRECTORY_CREATE_TIME, self.time)?;
        put_u16_at(raw, DIRECTORY_CREATE_TIME + 2, self.date)?;
        put_u16_at(raw, DIRECTORY_ACCESS_DATE, self.date)
    }

    /// Stamp this instant as an entry's last-write time, and as the access
    /// date, which FAT records to the day only.
    fn write_modification(self, raw: &mut [u8]) -> Result<(), FsError> {
        put_u16_at(raw, DIRECTORY_WRITE_TIME, self.time)?;
        put_u16_at(raw, DIRECTORY_WRITE_TIME + 2, self.date)?;
        put_u16_at(raw, DIRECTORY_ACCESS_DATE, self.date)
    }
}

/// Carry an entry's timestamps to the record that replaces it.
///
/// Renaming a name does not change when its contents were created or written,
/// so the new record inherits both stamps instead of taking a fresh one.
fn copy_timestamps(source: &[u8], destination: &mut [u8]) -> Result<(), FsError> {
    for range in DIRECTORY_STAMP_RANGES {
        let bytes = source.get(range.clone()).ok_or(FsError::Corrupt)?;
        destination
            .get_mut(range)
            .ok_or(FsError::Corrupt)?
            .copy_from_slice(bytes);
    }
    Ok(())
}

/// Split a day count since 1970-01-01 into its proleptic Gregorian date.
///
/// The era arithmetic is the standard shift of the year's origin to March, so
/// that a leap day falls at the end of a cycle and every month before it has a
/// fixed length.
fn civil_from_days(days: u64) -> Result<(u16, u16, u16), FsError> {
    let shifted = days.checked_add(719_468).ok_or(FsError::Overflow)?;
    let era = shifted / 146_097;
    let day_of_era = shifted % 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_index = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_index + 2) / 5 + 1;
    let month = if month_index < 10 {
        month_index + 3
    } else {
        month_index - 9
    };
    // A March-based year rolls over at January, not at the shifted origin.
    let year = if month <= 2 { year + 1 } else { year };
    Ok((
        u16::try_from(year).map_err(|_| FsError::Overflow)?,
        u16::try_from(month).map_err(|_| FsError::Overflow)?,
        u16::try_from(day).map_err(|_| FsError::Overflow)?,
    ))
}

fn put_u16_at(bytes: &mut [u8], offset: usize, value: u16) -> Result<(), FsError> {
    bytes
        .get_mut(offset..offset.checked_add(2).ok_or(FsError::Overflow)?)
        .ok_or(FsError::Corrupt)?
        .copy_from_slice(&value.to_le_bytes());
    Ok(())
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
        BlockDevice, BlockError, BlockRegion, DIRECTORY_ACCESS_DATE, DIRECTORY_CREATE_TENTHS,
        DIRECTORY_CREATE_TIME, DIRECTORY_ENTRY_BYTES, DIRECTORY_WRITE_TIME, DOS_EPOCH_SECONDS,
        DOS_LAST_SECONDS, DosStamp, Fat32, Fat32Limits, FileSystemProvider, FsError, NodeKind, Rc,
        WallClock, read_u16, short_name_checksum,
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
        mount_file_writable_with_limits(path, limits().map_err(|error| error.to_string())?)
    }

    fn mount_file_writable_with_limits(
        path: &Path,
        limits: Fat32Limits,
    ) -> Result<Fat32<FileDevice>, String> {
        let device = FileDevice::open_writable(path)?;
        let block_limits = BlockLimits::new(1, BLOCK_BYTES, 1)
            .map_err(|error| format!("invalid block limits: {error:?}"))?;
        let region = BlockRegion::whole_device(device, BlockAccess::ReadWrite, block_limits)
            .map_err(|error| format!("cannot grant writable image region: {error:?}"))?;
        Fat32::mount(region, limits).map_err(|error| error.to_string())
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
            .create_directory("/Archive Output")
            .map_err(|error| error.to_string())?;
        writable
            .write_file("/Archive Output/member.txt", b"member\n")
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
        assert_eq!(
            remounted
                .metadata("/Archive Output")
                .map_err(|error| error.to_string())?
                .kind,
            NodeKind::Directory
        );
        assert_eq!(
            remounted
                .metadata("/Archive Output/member.txt")
                .map_err(|error| error.to_string())?
                .byte_count,
            7
        );
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
        fat.create_directory("/Archive Output")?;
        assert_eq!(fat.metadata("/Archive Output")?.kind, NodeKind::Directory);
        fat.write_file("/Archive Output/member.txt", b"nested")?;
        assert_eq!(fat.metadata("/Archive Output/member.txt")?.byte_count, 6);
        assert_eq!(
            fat.create_directory("/Archive Output"),
            Err(FsError::Exists)
        );
        Ok(())
    }

    #[test]
    fn renames_files_and_directories_and_removes_only_empty_directories() -> Result<(), FsError> {
        let mut fat = mount_writable(valid_device().map_err(|_| FsError::Io)?)?;
        fat.rename("/HELLO.TXT", "/renamed.txt")?;
        assert_eq!(fat.metadata("/HELLO.TXT"), Err(FsError::NotFound));
        assert_eq!(fat.metadata("/renamed.txt")?.byte_count, 5);
        fat.create_directory("/tree")?;
        fat.write_file("/tree/member", b"member")?;
        assert_eq!(fat.remove_directory("/tree"), Err(FsError::NotEmpty));
        fat.rename("/tree", "/moved")?;
        assert_eq!(fat.metadata("/moved/member")?.byte_count, 6);
        assert_eq!(
            fat.rename("/moved", "/moved/member/loop"),
            Err(FsError::Invalid)
        );
        fat.remove_file("/moved/member")?;
        fat.remove_directory("/moved")?;
        assert_eq!(fat.metadata("/moved"), Err(FsError::NotFound));
        Ok(())
    }

    #[test]
    fn read_only_capability_rejects_mutation() -> Result<(), FsError> {
        let mut fat = mount(valid_device().map_err(|_| FsError::Io)?)?;
        assert_eq!(fat.write_file("/new.txt", b"data"), Err(FsError::ReadOnly));
        assert_eq!(fat.remove_file("/HELLO.TXT"), Err(FsError::ReadOnly));
        assert_eq!(fat.remove_directory("/SUBDIR"), Err(FsError::ReadOnly));
        assert_eq!(
            fat.rename("/HELLO.TXT", "/renamed.txt"),
            Err(FsError::ReadOnly)
        );
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

    /// A clock whose reading the test controls, including reporting none.
    #[derive(Debug)]
    struct TestClock(core::cell::Cell<Option<u64>>);

    impl TestClock {
        fn new(seconds: Option<u64>) -> Rc<Self> {
            Rc::new(Self(core::cell::Cell::new(seconds)))
        }

        fn set(&self, seconds: Option<u64>) {
            self.0.set(seconds);
        }
    }

    impl WallClock for TestClock {
        fn unix_seconds(&self) -> Option<u64> {
            self.0.get()
        }
    }

    /// Read one short entry's creation, access, and write fields.
    fn entry_stamps<D: BlockDevice>(
        fat: &mut Fat32<D>,
        path: &str,
    ) -> Result<(DosStamp, u16, DosStamp), FsError> {
        let entry = fat.resolve(path)?;
        let slot = *entry.directory_slots.last().ok_or(FsError::Corrupt)?;
        let cluster = fat.read_cluster(slot.cluster)?;
        let raw = cluster
            .get(slot.offset..slot.offset + DIRECTORY_ENTRY_BYTES)
            .ok_or(FsError::Corrupt)?;
        Ok((
            DosStamp {
                date: read_u16(raw, DIRECTORY_CREATE_TIME + 2)?,
                time: read_u16(raw, DIRECTORY_CREATE_TIME)?,
                tenths: *raw.get(DIRECTORY_CREATE_TENTHS).ok_or(FsError::Corrupt)?,
            },
            read_u16(raw, DIRECTORY_ACCESS_DATE)?,
            DosStamp {
                date: read_u16(raw, DIRECTORY_WRITE_TIME + 2)?,
                time: read_u16(raw, DIRECTORY_WRITE_TIME)?,
                tenths: 0,
            },
        ))
    }

    #[test]
    fn dos_stamps_encode_the_fat_range_and_clamp_outside_it() -> Result<(), FsError> {
        // 1980-01-01T00:00:00, the first instant a FAT date can express.
        assert_eq!(
            DosStamp::from_unix_seconds(DOS_EPOCH_SECONDS)?,
            DosStamp {
                date: 33,
                time: 0,
                tenths: 0
            }
        );
        // 2026-08-29T10:40:00, an ordinary instant well inside the range.
        assert_eq!(
            DosStamp::from_unix_seconds(1_788_000_000)?,
            DosStamp {
                date: 23_837,
                time: 21_760,
                tenths: 0
            }
        );
        // The write time counts two-second units, so the odd second is carried
        // by the creation entry's tenths field instead.
        assert_eq!(
            DosStamp::from_unix_seconds(1_788_000_001)?,
            DosStamp {
                date: 23_837,
                time: 21_760,
                tenths: 10
            }
        );
        // 2107-12-31T23:59:58, the last instant a FAT date can express.
        assert_eq!(
            DosStamp::from_unix_seconds(DOS_LAST_SECONDS)?,
            DosStamp {
                date: 65_439,
                time: 49_021,
                tenths: 0
            }
        );
        // Outside the range the stamp clamps rather than encoding a year the
        // field cannot hold; a zero date would be invalid, not merely old.
        assert_eq!(
            DosStamp::from_unix_seconds(0)?,
            DosStamp::from_unix_seconds(DOS_EPOCH_SECONDS)?
        );
        assert_eq!(
            DosStamp::from_unix_seconds(u64::MAX)?,
            DosStamp::from_unix_seconds(DOS_LAST_SECONDS)?
        );
        Ok(())
    }

    #[test]
    fn stamps_directory_entries_only_when_a_clock_is_supplied() -> Result<(), FsError> {
        const CREATED: u64 = 1_788_000_000;
        const WRITTEN: u64 = CREATED + 90_000;

        // Without a clock every date and time field stays zero, which is the
        // only honest encoding of an unknown instant.
        let mut fat = mount_writable(valid_device().map_err(|_| FsError::Io)?)?;
        fat.write_file("/unstamped.txt", b"no clock")?;
        let zero = DosStamp {
            date: 0,
            time: 0,
            tenths: 0,
        };
        assert_eq!(entry_stamps(&mut fat, "/unstamped.txt")?, (zero, 0, zero));

        // A clock that reports no time is the same as having none at all.
        fat.set_wall_clock(TestClock::new(None));
        fat.write_file("/unavailable.txt", b"time unknown")?;
        assert_eq!(entry_stamps(&mut fat, "/unavailable.txt")?, (zero, 0, zero));

        let clock = TestClock::new(Some(CREATED));
        fat.set_wall_clock(clock.clone());
        fat.write_file("/stamped.txt", b"clocked")?;
        let created = DosStamp::from_unix_seconds(CREATED)?;
        assert_eq!(
            entry_stamps(&mut fat, "/stamped.txt")?,
            (created, created.date, created)
        );

        // Replacing the contents advances the write time and the access date
        // while the creation time stays at the instant the name appeared.
        clock.set(Some(WRITTEN));
        fat.write_file("/stamped.txt", b"clocked again")?;
        let written = DosStamp::from_unix_seconds(WRITTEN)?;
        assert_eq!(
            entry_stamps(&mut fat, "/stamped.txt")?,
            (created, written.date, written)
        );

        // Appending is a content change too.
        clock.set(Some(WRITTEN + 4));
        fat.append_file("/stamped.txt", b" and appended")?;
        let appended = DosStamp::from_unix_seconds(WRITTEN + 4)?;
        assert_eq!(
            entry_stamps(&mut fat, "/stamped.txt")?,
            (created, appended.date, appended)
        );

        // A rename moves the name, not the contents, so both stamps survive it.
        clock.set(Some(WRITTEN + 200_000));
        fat.rename("/stamped.txt", "/renamed.txt")?;
        assert_eq!(
            entry_stamps(&mut fat, "/renamed.txt")?,
            (created, appended.date, appended)
        );

        // `.` and `..` describe their directory, so they carry its stamp.
        clock.set(Some(CREATED));
        fat.create_directory("/stamped")?;
        assert_eq!(
            entry_stamps(&mut fat, "/stamped")?,
            (created, created.date, created)
        );
        let directory = fat.resolve("/stamped")?;
        let cluster = fat.read_cluster(directory.first_cluster)?;
        for index in 0..2 {
            let raw = cluster
                .get(index * DIRECTORY_ENTRY_BYTES..(index + 1) * DIRECTORY_ENTRY_BYTES)
                .ok_or(FsError::Corrupt)?;
            assert_eq!(read_u16(raw, DIRECTORY_CREATE_TIME + 2)?, created.date);
            assert_eq!(read_u16(raw, DIRECTORY_WRITE_TIME + 2)?, created.date);
            assert_eq!(read_u16(raw, DIRECTORY_WRITE_TIME)?, created.time);
        }
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

    #[test]
    fn stamps_real_fat32_entries_a_host_tool_renders() -> Result<(), String> {
        // 2026-08-29T10:40:00Z. FAT stores local time with no timezone, and
        // TROE has no timezone source, so this UTC reading is written
        // unconverted and a host reads back exactly these digits.
        const CREATED: u64 = 1_788_000_000;
        const RENDERED: &str = "2026-08-29  10:40";
        let Some(mkfs_fat) = fat_tool("mkfs.fat") else {
            return unavailable_tool("mkfs.fat");
        };
        let Some(fsck_fat) = fat_tool("fsck.fat") else {
            return unavailable_tool("fsck.fat");
        };
        let Some(mdir) = mtool("mdir") else {
            return unavailable_tool("mdir");
        };
        let temporary = TestDirectory::create("fat32-stamps")?;
        let image = temporary.path().join("filesystem.fat32");
        File::create(&image)
            .and_then(|file| file.set_len(64 * 1024 * 1024))
            .map_err(|error| error.to_string())?;
        let format = Command::new(mkfs_fat)
            .args(["-F", "32", "-n", "TROESTAMP"])
            .arg(&image)
            .output()
            .map_err(|error| error.to_string())?;
        command_succeeded(&format, "mkfs.fat for stamped entries")?;

        {
            let mut fat = mount_file_writable(&image)?;
            fat.set_wall_clock(TestClock::new(Some(CREATED)));
            fat.write_file("/Stamped Name.txt", b"written by troe\n")
                .map_err(|error| error.to_string())?;
            fat.create_directory("/stamped")
                .map_err(|error| error.to_string())?;
            fat.write_file("/stamped/member.txt", b"member\n")
                .map_err(|error| error.to_string())?;
        }

        let check = Command::new(&fsck_fat)
            .args(["-vn"])
            .arg(&image)
            .output()
            .map_err(|error| error.to_string())?;
        command_succeeded(&check, "fsck.fat after stamped writes")?;

        for directory in ["::/", "::/stamped"] {
            let listing = Command::new(&mdir)
                .args(["-i"])
                .arg(&image)
                .arg(directory)
                .output()
                .map_err(|error| error.to_string())?;
            command_succeeded(&listing, "mdir")?;
            let report = String::from_utf8_lossy(&listing.stdout).to_string();
            assert!(
                report.contains(RENDERED),
                "{directory} must render {RENDERED}, got:\n{report}"
            );
        }
        Ok(())
    }

    #[test]
    #[ignore = "writes and verifies a 128 MiB real FAT32 file"]
    fn streams_128_mib_to_real_fat32_with_bounded_chunks() -> Result<(), String> {
        const IMAGE_BYTES: u64 = 256 * 1024 * 1024;
        const FILE_BYTES: u64 = 128 * 1024 * 1024;
        const CHUNK_BYTES: usize = 1024 * 1024;
        let Some(mkfs_fat) = fat_tool("mkfs.fat") else {
            return unavailable_tool("mkfs.fat");
        };
        let Some(fsck_fat) = fat_tool("fsck.fat") else {
            return unavailable_tool("fsck.fat");
        };
        let temporary = TestDirectory::create("fat32-large-stream")?;
        let image = temporary.path().join("filesystem.fat32");
        File::create(&image)
            .and_then(|file| file.set_len(IMAGE_BYTES))
            .map_err(|error| error.to_string())?;
        let format = Command::new(mkfs_fat)
            .args(["-F", "32", "-n", "TROESTRESS"])
            .arg(&image)
            .output()
            .map_err(|error| error.to_string())?;
        command_succeeded(&format, "mkfs.fat for large stream")?;

        let stress_limits = Fat32Limits::new(u32::MAX, 128, FILE_BYTES, CHUNK_BYTES, 64)
            .map_err(|error| error.to_string())?;
        let mut fat = mount_file_writable_with_limits(&image, stress_limits)?;
        fat.truncate_file("/large.bin")
            .map_err(|error| error.to_string())?;
        let chunk = vec![0xa5; CHUNK_BYTES];
        for _ in 0..FILE_BYTES / CHUNK_BYTES as u64 {
            fat.append_file("/large.bin", &chunk)
                .map_err(|error| error.to_string())?;
        }
        fat.sync_file("/large.bin")
            .map_err(|error| error.to_string())?;
        assert_eq!(
            fat.metadata("/large.bin")
                .map_err(|error| error.to_string())?
                .byte_count,
            FILE_BYTES
        );
        for offset in [0, FILE_BYTES / 2, FILE_BYTES - 4096] {
            let mut sample = [0_u8; 4096];
            assert_eq!(
                fat.read_file("/large.bin", offset, &mut sample)
                    .map_err(|error| error.to_string())?,
                sample.len()
            );
            assert!(sample.iter().all(|byte| *byte == 0xa5));
        }
        drop(fat);

        let check = Command::new(fsck_fat)
            .args(["-vn"])
            .arg(&image)
            .output()
            .map_err(|error| error.to_string())?;
        command_succeeded(&check, "fsck.fat after 128 MiB streamed write")
    }
}
