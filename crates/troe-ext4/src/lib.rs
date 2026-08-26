//! Strict, bounded ext4 profile v1 provider with metadata-preserving file mutation.
#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;
#[cfg(test)]
extern crate std;

use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::{fmt, str};
use troe_block::{BlockAccess, BlockDevice, BlockError, BlockRegion};
use troe_vfs::{
    DirEntry, FileMetadata, FsError, MAX_NAME_BYTES, MAX_PATH_BYTES, NodeKind, ProviderListing,
    ReadOnlyFileSystem, canonicalize,
};

const EXT4_MAGIC: u16 = 0xef53;
const EXT4_DYNAMIC_REV: u32 = 1;
const EXT4_VALID_FS: u16 = 1;
const EXT4_ERROR_FS: u16 = 2;
const EXT4_BLOCK_BYTES: usize = 4096;
#[cfg(test)]
const EXT4_BLOCK_BYTES_U32: u32 = 4096;
const EXT4_BLOCK_BYTES_U64: u64 = 4096;
const EXT4_INODE_BYTES: usize = 256;
const EXT4_INODE_BYTES_U16: u16 = 256;
const EXT4_GROUP_DESC_BYTES: usize = 32;
const EXT4_GROUP_DESC_BYTES_U16: u16 = 32;
const EXT4_BITMAP_BITS: u32 = 32_768;
const EXT4_ROOT_INO: u32 = 2;
const EXT4_EXTENTS_FL: u32 = 0x0008_0000;
const EXT4_EXT_MAGIC: u16 = 0xf30a;
const EXT4_FT_REG_FILE: u8 = 1;
const EXT4_FT_DIR: u8 = 2;
const EXT4_FT_SYMLINK: u8 = 7;
const EXT4_FAST_SYMLINK_BYTES: usize = 60;
const MAX_SYMLINK_EXPANSIONS: u8 = 8;
const EXT4_DIR_TAIL_FT: u8 = 0xde;
const EXT4_DIR_TAIL_BYTES: usize = 12;
const EXT4_DIR_TAIL_BYTES_U16: u16 = 12;
const EXT4_FEATURE_COMPAT: u32 = 0x0000_0004 | 0x0000_0008;
const EXT4_FEATURE_INCOMPAT: u32 = 0x0000_0002 | 0x0000_0040;
const EXT4_FEATURE_RO_COMPAT: u32 = 0x0000_0001 | 0x0000_0002 | 0x0000_0040 | 0x0000_0400;
const CRC32C_POLYNOMIAL: u32 = 0x82f6_3b78;
const HARD_MAX_GROUPS: u32 = 32;
const HARD_MAX_INODES_PER_OPERATION: u32 = 64;
const HARD_MAX_DIRECTORY_BLOCKS: u32 = 256;
const HARD_MAX_DIRECTORY_ENTRIES: u32 = 4096;
const HARD_MAX_READ_BYTES: usize = 1024 * 1024;

/// Raw ext4 ownership and mode applied only to newly created regular files.
///
/// Existing inode metadata is preserved byte-for-byte during replacement.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Ext4WriteDefaults {
    uid: u32,
    gid: u32,
    mode: u16,
}

impl Ext4WriteDefaults {
    /// Construct defaults for new files. Only ordinary permission bits are accepted.
    ///
    /// # Errors
    ///
    /// Rejects type, set-ID, sticky, or otherwise non-permission mode bits.
    pub const fn new(uid: u32, gid: u32, mode: u16) -> Result<Self, FsError> {
        if mode & !0o777 != 0 {
            return Err(FsError::Invalid);
        }
        Ok(Self { uid, gid, mode })
    }

    /// Raw UID stored in a newly allocated inode.
    #[must_use]
    pub const fn uid(self) -> u32 {
        self.uid
    }

    /// Raw GID stored in a newly allocated inode.
    #[must_use]
    pub const fn gid(self) -> u32 {
        self.gid
    }

    /// Permission bits stored in a newly allocated inode.
    #[must_use]
    pub const fn mode(self) -> u16 {
        self.mode
    }
}

impl Default for Ext4WriteDefaults {
    fn default() -> Self {
        Self {
            uid: 1000,
            gid: 1000,
            mode: 0o600,
        }
    }
}

/// Per-mount traversal and retention ceilings for the ext4 v1 profile.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Ext4Limits {
    groups: u32,
    inodes: u32,
    directory_blocks: u32,
    directory_entries: u32,
    file_bytes: u64,
    read_bytes: usize,
    name_bytes: usize,
}

impl Ext4Limits {
    /// Construct checked ext4 provider ceilings.
    ///
    /// # Errors
    ///
    /// Rejects empty limits or values above the provider's hard profile.
    pub const fn new(
        max_groups: u32,
        max_inodes_per_operation: u32,
        max_directory_blocks: u32,
        max_directory_entries: u32,
        max_file_bytes: u64,
        max_read_bytes: usize,
        max_name_bytes: usize,
    ) -> Result<Self, FsError> {
        if max_groups == 0
            || max_groups > HARD_MAX_GROUPS
            || max_inodes_per_operation == 0
            || max_inodes_per_operation > HARD_MAX_INODES_PER_OPERATION
            || max_directory_blocks == 0
            || max_directory_blocks > HARD_MAX_DIRECTORY_BLOCKS
            || max_directory_entries == 0
            || max_directory_entries > HARD_MAX_DIRECTORY_ENTRIES
            || max_file_bytes == 0
            || max_read_bytes == 0
            || max_read_bytes > HARD_MAX_READ_BYTES
            || max_name_bytes == 0
            || max_name_bytes > MAX_NAME_BYTES
        {
            return Err(FsError::Invalid);
        }
        Ok(Self {
            groups: max_groups,
            inodes: max_inodes_per_operation,
            directory_blocks: max_directory_blocks,
            directory_entries: max_directory_entries,
            file_bytes: max_file_bytes,
            read_bytes: max_read_bytes,
            name_bytes: max_name_bytes,
        })
    }

    /// Maximum block groups accepted at mount.
    #[must_use]
    pub const fn max_groups(self) -> u32 {
        self.groups
    }

    /// Maximum inode records consumed by one VFS operation.
    #[must_use]
    pub const fn max_inodes_per_operation(self) -> u32 {
        self.inodes
    }

    /// Maximum blocks scanned in one directory.
    #[must_use]
    pub const fn max_directory_blocks(self) -> u32 {
        self.directory_blocks
    }

    /// Maximum live entries retained from one directory.
    #[must_use]
    pub const fn max_directory_entries(self) -> u32 {
        self.directory_entries
    }

    /// Maximum regular-file size exposed by the mount.
    #[must_use]
    pub const fn max_file_bytes(self) -> u64 {
        self.file_bytes
    }

    /// Maximum destination length of one VFS read.
    #[must_use]
    pub const fn max_read_bytes(self) -> usize {
        self.read_bytes
    }

    /// Maximum UTF-8 bytes retained in one name.
    #[must_use]
    pub const fn max_name_bytes(self) -> usize {
        self.name_bytes
    }
}

/// Stable ext4 filesystem identifier copied from the superblock.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct Ext4Uuid([u8; 16]);

impl Ext4Uuid {
    /// Return the exact UUID bytes in standard ext4 on-disk order.
    #[must_use]
    pub const fn bytes(self) -> [u8; 16] {
        self.0
    }
}

#[derive(Clone, Copy, Debug)]
struct Layout {
    blocks: u32,
    inodes: u32,
    blocks_per_group: u32,
    inodes_per_group: u32,
    first_inode: u32,
    groups: u32,
    device_blocks_per_fs_block: u32,
    checksum_seed: u32,
    uuid: Ext4Uuid,
}

#[derive(Clone, Copy, Debug)]
struct Extent {
    logical: u32,
    physical: u32,
    blocks: u16,
    unwritten: bool,
}

#[derive(Clone, Debug)]
struct Inode {
    number: u32,
    generation: u32,
    kind: NodeKind,
    size: u64,
    extents: Vec<Extent>,
}

#[derive(Clone, Debug)]
struct DirectoryEntry {
    inode: u32,
    name: String,
    kind: NodeKind,
}

/// Mounted strict ext4 v1 provider owning exactly one block-region capability.
pub struct Ext4<D: BlockDevice> {
    region: BlockRegion<D>,
    limits: Ext4Limits,
    layout: Layout,
    write_defaults: Ext4WriteDefaults,
}

impl<D: BlockDevice> fmt::Debug for Ext4<D> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Ext4")
            .field("limits", &self.limits)
            .field("layout", &self.layout)
            .finish_non_exhaustive()
    }
}

impl<D: BlockDevice> Ext4<D> {
    /// Validate and mount a clean ext4 v1 volume.
    ///
    /// # Errors
    ///
    /// Rejects unsupported geometry or feature bits, dirty media, checksum or
    /// structural corruption, resource-limit violations, and block failures.
    pub fn mount(region: BlockRegion<D>, limits: Ext4Limits) -> Result<Self, FsError> {
        Self::mount_with_write_defaults(region, limits, Ext4WriteDefaults::default())
    }

    /// Validate and mount with explicit raw metadata defaults for newly created files.
    ///
    /// # Errors
    ///
    /// Applies the same strict profile checks as [`Self::mount`].
    pub fn mount_with_write_defaults(
        mut region: BlockRegion<D>,
        limits: Ext4Limits,
        write_defaults: Ext4WriteDefaults,
    ) -> Result<Self, FsError> {
        validate_limits(limits)?;
        let info = region.info();
        let device_block_bytes =
            usize::try_from(info.block_bytes()).map_err(|_| FsError::Overflow)?;
        if info.required_alignment_blocks() != 1
            || device_block_bytes > EXT4_BLOCK_BYTES
            || !EXT4_BLOCK_BYTES.is_multiple_of(device_block_bytes)
        {
            return Err(FsError::Unsupported);
        }
        let device_blocks_per_fs_block =
            u32::try_from(EXT4_BLOCK_BYTES / device_block_bytes).map_err(|_| FsError::Overflow)?;
        if info.limits().max_transfer_blocks() < device_blocks_per_fs_block
            || info.limits().max_transfer_bytes() < EXT4_BLOCK_BYTES
        {
            return Err(FsError::Unsupported);
        }
        let block_zero = read_raw_fs_block(&mut region, 0, device_blocks_per_fs_block)?;
        let superblock = block_zero.get(1024..2048).ok_or(FsError::Corrupt)?;
        let layout = parse_superblock(
            superblock,
            info.block_count(),
            device_blocks_per_fs_block,
            limits,
        )?;
        let mut mounted = Self {
            region,
            limits,
            layout,
            write_defaults,
        };
        let root = mounted.read_inode(EXT4_ROOT_INO)?;
        if root.kind != NodeKind::Directory {
            return Err(FsError::Corrupt);
        }
        let root_entries = mounted.read_directory(&root)?;
        if !root_entries
            .iter()
            .any(|entry| entry.name == "." && entry.inode == EXT4_ROOT_INO)
            || !root_entries
                .iter()
                .any(|entry| entry.name == ".." && entry.inode == EXT4_ROOT_INO)
        {
            return Err(FsError::Corrupt);
        }
        Ok(mounted)
    }

    /// Filesystem UUID validated at mount.
    #[must_use]
    pub const fn uuid(&self) -> Ext4Uuid {
        self.layout.uuid
    }

    fn read_fs_block(&mut self, block: u32) -> Result<Vec<u8>, FsError> {
        if block >= self.layout.blocks {
            return Err(FsError::Corrupt);
        }
        read_raw_fs_block(
            &mut self.region,
            block,
            self.layout.device_blocks_per_fs_block,
        )
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

    fn write_fs_block(&mut self, block: u32, bytes: &[u8]) -> Result<(), FsError> {
        if block >= self.layout.blocks || bytes.len() != EXT4_BLOCK_BYTES {
            return Err(FsError::Invalid);
        }
        let start = u64::from(block)
            .checked_mul(u64::from(self.layout.device_blocks_per_fs_block))
            .ok_or(FsError::Overflow)?;
        self.region
            .write_blocks(
                start,
                self.layout.device_blocks_per_fs_block,
                bytes,
                self.force_unit_access(),
            )
            .map_err(map_block_error)
    }

    fn durability_barrier(&mut self) -> Result<(), FsError> {
        self.ensure_writable()?;
        if self.region.info().supports_flush() {
            self.region.flush().map_err(map_block_error)?;
        }
        Ok(())
    }

    fn set_clean_state(&mut self, clean: bool) -> Result<(), FsError> {
        let mut block = self.read_fs_block(0)?;
        let superblock = block.get_mut(1024..2048).ok_or(FsError::Corrupt)?;
        let state = read_u16(superblock, 58)?;
        let updated = if clean {
            (state | EXT4_VALID_FS) & !EXT4_ERROR_FS
        } else {
            state & !EXT4_VALID_FS
        };
        put_u16(superblock, 58, updated)?;
        superblock[1020..1024].fill(0);
        let checksum = crc32c(u32::MAX, &superblock[..1020]);
        put_u32(superblock, 1020, checksum)?;
        self.write_fs_block(0, &block)?;
        self.durability_barrier()
    }

    fn begin_mutation(&mut self) -> Result<(), FsError> {
        self.set_clean_state(false)
    }

    fn finish_mutation(&mut self) -> Result<(), FsError> {
        self.set_clean_state(true)
    }

    fn write_group_descriptor(
        &mut self,
        group: u32,
        mut descriptor: [u8; EXT4_GROUP_DESC_BYTES],
    ) -> Result<(), FsError> {
        if group >= self.layout.groups {
            return Err(FsError::Corrupt);
        }
        descriptor[30..32].fill(0);
        let checksum = crc32c(
            crc32c(self.layout.checksum_seed, &group.to_le_bytes()),
            &descriptor,
        );
        descriptor[30..32].copy_from_slice(&checksum.to_le_bytes()[..2]);
        let byte_offset = usize::try_from(group)
            .ok()
            .and_then(|value| value.checked_mul(EXT4_GROUP_DESC_BYTES))
            .ok_or(FsError::Overflow)?;
        let table_block = 1_u32
            .checked_add(
                u32::try_from(byte_offset / EXT4_BLOCK_BYTES).map_err(|_| FsError::Overflow)?,
            )
            .ok_or(FsError::Overflow)?;
        let offset = byte_offset % EXT4_BLOCK_BYTES;
        let mut block = self.read_fs_block(table_block)?;
        block
            .get_mut(offset..offset + EXT4_GROUP_DESC_BYTES)
            .ok_or(FsError::Corrupt)?
            .copy_from_slice(&descriptor);
        self.write_fs_block(table_block, &block)
    }

    fn adjust_superblock_counter(&mut self, offset: usize, allocate: bool) -> Result<(), FsError> {
        let mut block = self.read_fs_block(0)?;
        let superblock = block.get_mut(1024..2048).ok_or(FsError::Corrupt)?;
        let current = read_u32(superblock, offset)?;
        let updated = if allocate {
            current.checked_sub(1)
        } else {
            current.checked_add(1)
        }
        .ok_or(FsError::Corrupt)?;
        put_u32(superblock, offset, updated)?;
        superblock[1020..1024].fill(0);
        let checksum = crc32c(u32::MAX, &superblock[..1020]);
        put_u32(superblock, 1020, checksum)?;
        self.write_fs_block(0, &block)
    }

    fn validate_bitmap_checksum(
        &self,
        descriptor: &[u8],
        bitmap: &[u8],
        bytes: usize,
        checksum_offset: usize,
    ) -> Result<(), FsError> {
        let stored = read_u16(descriptor, checksum_offset)?;
        let calculated = crc32c(
            self.layout.checksum_seed,
            bitmap.get(..bytes).ok_or(FsError::Corrupt)?,
        );
        if stored != u16::from_le_bytes([calculated.to_le_bytes()[0], calculated.to_le_bytes()[1]])
        {
            return Err(FsError::Corrupt);
        }
        Ok(())
    }

    fn set_block_allocated(&mut self, block_number: u32, allocate: bool) -> Result<(), FsError> {
        if block_number == 0 || block_number >= self.layout.blocks {
            return Err(FsError::Corrupt);
        }
        let group = block_number / self.layout.blocks_per_group;
        let bit = block_number % self.layout.blocks_per_group;
        let mut descriptor = self.group_descriptor(group)?;
        let bitmap_block = read_u32(&descriptor, 0)?;
        if bitmap_block == 0 || bitmap_block >= self.layout.blocks {
            return Err(FsError::Corrupt);
        }
        let mut bitmap = self.read_fs_block(bitmap_block)?;
        let bitmap_bytes =
            usize::try_from(self.layout.blocks_per_group / 8).map_err(|_| FsError::Overflow)?;
        self.validate_bitmap_checksum(&descriptor, &bitmap, bitmap_bytes, 24)?;
        let bit = usize::try_from(bit).map_err(|_| FsError::Overflow)?;
        let byte = bitmap.get_mut(bit / 8).ok_or(FsError::Corrupt)?;
        let mask = 1_u8 << (bit % 8);
        if (*byte & mask != 0) == allocate {
            return Err(FsError::Corrupt);
        }
        if allocate {
            *byte |= mask;
        } else {
            *byte &= !mask;
        }
        self.write_fs_block(bitmap_block, &bitmap)?;
        let checksum = crc32c(self.layout.checksum_seed, &bitmap[..bitmap_bytes]);
        descriptor[24..26].copy_from_slice(&checksum.to_le_bytes()[..2]);
        let free = read_u16(&descriptor, 12)?;
        put_u16(
            &mut descriptor,
            12,
            if allocate {
                free.checked_sub(1)
            } else {
                free.checked_add(1)
            }
            .ok_or(FsError::Corrupt)?,
        )?;
        self.write_group_descriptor(group, descriptor)?;
        self.adjust_superblock_counter(12, allocate)
    }

    fn set_inode_allocated(&mut self, number: u32, allocate: bool) -> Result<(), FsError> {
        if number < self.layout.first_inode || number > self.layout.inodes {
            return Err(FsError::Corrupt);
        }
        let zero_based = number - 1;
        let group = zero_based / self.layout.inodes_per_group;
        let bit = zero_based % self.layout.inodes_per_group;
        let mut descriptor = self.group_descriptor(group)?;
        let bitmap_block = read_u32(&descriptor, 4)?;
        if bitmap_block == 0 || bitmap_block >= self.layout.blocks {
            return Err(FsError::Corrupt);
        }
        let mut bitmap = self.read_fs_block(bitmap_block)?;
        let bitmap_bytes =
            usize::try_from(self.layout.inodes_per_group / 8).map_err(|_| FsError::Overflow)?;
        self.validate_bitmap_checksum(&descriptor, &bitmap, bitmap_bytes, 26)?;
        let bit = usize::try_from(bit).map_err(|_| FsError::Overflow)?;
        let byte = bitmap.get_mut(bit / 8).ok_or(FsError::Corrupt)?;
        let mask = 1_u8 << (bit % 8);
        if (*byte & mask != 0) == allocate {
            return Err(FsError::Corrupt);
        }
        if allocate {
            *byte |= mask;
        } else {
            *byte &= !mask;
        }
        self.write_fs_block(bitmap_block, &bitmap)?;
        let checksum = crc32c(self.layout.checksum_seed, &bitmap[..bitmap_bytes]);
        descriptor[26..28].copy_from_slice(&checksum.to_le_bytes()[..2]);
        let free = read_u16(&descriptor, 14)?;
        put_u16(
            &mut descriptor,
            14,
            if allocate {
                free.checked_sub(1)
            } else {
                free.checked_add(1)
            }
            .ok_or(FsError::Corrupt)?,
        )?;
        let inodes_in_group = self
            .layout
            .inodes
            .saturating_sub(group.saturating_mul(self.layout.inodes_per_group))
            .min(self.layout.inodes_per_group);
        let mut unused = 0_u16;
        for candidate in (0..inodes_in_group).rev() {
            let candidate = usize::try_from(candidate).map_err(|_| FsError::Overflow)?;
            if bitmap[candidate / 8] & (1 << (candidate % 8)) != 0 {
                break;
            }
            unused = unused.checked_add(1).ok_or(FsError::Overflow)?;
        }
        put_u16(&mut descriptor, 28, unused)?;
        self.write_group_descriptor(group, descriptor)?;
        self.adjust_superblock_counter(16, allocate)
    }

    fn set_directory_allocated(
        &mut self,
        inode_number: u32,
        allocate: bool,
    ) -> Result<(), FsError> {
        if inode_number < self.layout.first_inode || inode_number > self.layout.inodes {
            return Err(FsError::Corrupt);
        }
        let group = (inode_number - 1) / self.layout.inodes_per_group;
        let mut descriptor = self.group_descriptor(group)?;
        let current = read_u16(&descriptor, 16)?;
        let updated = if allocate {
            current.checked_add(1)
        } else {
            current.checked_sub(1)
        }
        .ok_or(FsError::Corrupt)?;
        put_u16(&mut descriptor, 16, updated)?;
        self.write_group_descriptor(group, descriptor)
    }

    fn retain_free_run(runs: &mut Vec<(u32, u32)>, start: u32, blocks: u32) {
        if blocks == 0 {
            return;
        }
        if runs.len() < 4 {
            runs.push((start, blocks));
            return;
        }
        if let Some((index, _)) = runs
            .iter()
            .enumerate()
            .min_by_key(|(_, (_, length))| *length)
            && blocks > runs[index].1
        {
            runs[index] = (start, blocks);
        }
    }

    fn find_free_blocks(&mut self, count: usize) -> Result<Vec<u32>, FsError> {
        if count == 0 {
            return Ok(Vec::new());
        }
        let count_u32 = u32::try_from(count).map_err(|_| FsError::NoSpace)?;
        let mut runs = Vec::new();
        runs.try_reserve_exact(4).map_err(|_| FsError::NoSpace)?;
        for group in 0..self.layout.groups {
            let descriptor = self.group_descriptor(group)?;
            let bitmap_block = read_u32(&descriptor, 0)?;
            if bitmap_block == 0 || bitmap_block >= self.layout.blocks {
                return Err(FsError::Corrupt);
            }
            let bitmap = self.read_fs_block(bitmap_block)?;
            let bitmap_bytes =
                usize::try_from(self.layout.blocks_per_group / 8).map_err(|_| FsError::Overflow)?;
            self.validate_bitmap_checksum(&descriptor, &bitmap, bitmap_bytes, 24)?;
            let group_start = group
                .checked_mul(self.layout.blocks_per_group)
                .ok_or(FsError::Overflow)?;
            let blocks_in_group = self
                .layout
                .blocks
                .saturating_sub(group_start)
                .min(self.layout.blocks_per_group);
            let mut run_start = 0_u32;
            let mut run_length = 0_u32;
            for bit in 0..blocks_in_group {
                let index = usize::try_from(bit).map_err(|_| FsError::Overflow)?;
                let free = bitmap
                    .get(index / 8)
                    .is_some_and(|byte| byte & (1 << (index % 8)) == 0);
                let block = group_start.checked_add(bit).ok_or(FsError::Overflow)?;
                if free && block != 0 {
                    if run_length == 0 {
                        run_start = block;
                    }
                    run_length = run_length.checked_add(1).ok_or(FsError::Overflow)?;
                } else {
                    Self::retain_free_run(&mut runs, run_start, run_length);
                    run_length = 0;
                }
            }
            Self::retain_free_run(&mut runs, run_start, run_length);
        }
        runs.sort_unstable_by(|left, right| {
            right.1.cmp(&left.1).then_with(|| left.0.cmp(&right.0))
        });
        if runs.iter().try_fold(0_u32, |total, (_, length)| {
            total.checked_add(*length).ok_or(FsError::Overflow)
        })? < count_u32
        {
            return Err(FsError::NoSpace);
        }
        let mut blocks = Vec::new();
        blocks
            .try_reserve_exact(count)
            .map_err(|_| FsError::NoSpace)?;
        for (start, length) in runs {
            let wanted = usize::try_from(length)
                .map_err(|_| FsError::Overflow)?
                .min(count - blocks.len());
            for offset in 0..wanted {
                blocks.push(
                    start
                        .checked_add(u32::try_from(offset).map_err(|_| FsError::Overflow)?)
                        .ok_or(FsError::Overflow)?,
                );
            }
            if blocks.len() == count {
                break;
            }
        }
        Ok(blocks)
    }

    fn find_free_inode(&mut self) -> Result<u32, FsError> {
        for group in 0..self.layout.groups {
            let descriptor = self.group_descriptor(group)?;
            let bitmap_block = read_u32(&descriptor, 4)?;
            if bitmap_block == 0 || bitmap_block >= self.layout.blocks {
                return Err(FsError::Corrupt);
            }
            let bitmap = self.read_fs_block(bitmap_block)?;
            let bitmap_bytes =
                usize::try_from(self.layout.inodes_per_group / 8).map_err(|_| FsError::Overflow)?;
            self.validate_bitmap_checksum(&descriptor, &bitmap, bitmap_bytes, 26)?;
            let first = group
                .checked_mul(self.layout.inodes_per_group)
                .and_then(|value| value.checked_add(1))
                .ok_or(FsError::Overflow)?;
            let inodes_in_group = self
                .layout
                .inodes
                .saturating_sub(first - 1)
                .min(self.layout.inodes_per_group);
            for bit in 0..inodes_in_group {
                let number = first.checked_add(bit).ok_or(FsError::Overflow)?;
                if number < self.layout.first_inode {
                    continue;
                }
                let index = usize::try_from(bit).map_err(|_| FsError::Overflow)?;
                if bitmap
                    .get(index / 8)
                    .is_some_and(|byte| byte & (1 << (index % 8)) == 0)
                {
                    return Ok(number);
                }
            }
        }
        Err(FsError::NoSpace)
    }

    fn allocate_file_blocks(&mut self, bytes: &[u8]) -> Result<Vec<u32>, FsError> {
        if bytes.is_empty() {
            return Ok(Vec::new());
        }
        let count = bytes
            .len()
            .checked_add(EXT4_BLOCK_BYTES - 1)
            .map(|value| value / EXT4_BLOCK_BYTES)
            .ok_or(FsError::Overflow)?;
        let blocks = self.find_free_blocks(count)?;
        let mut payload = alloc::vec![0_u8; EXT4_BLOCK_BYTES];
        for (logical, physical) in blocks.iter().copied().enumerate() {
            payload.fill(0);
            let start = logical
                .checked_mul(EXT4_BLOCK_BYTES)
                .ok_or(FsError::Overflow)?;
            let end = start
                .checked_add(EXT4_BLOCK_BYTES)
                .map_or(bytes.len(), |candidate| candidate.min(bytes.len()));
            payload[..end - start].copy_from_slice(&bytes[start..end]);
            self.write_fs_block(physical, &payload)?;
        }
        let mut allocated = 0_usize;
        while allocated < blocks.len() {
            if let Err(error) = self.set_block_allocated(blocks[allocated], true) {
                for block in &blocks[..allocated] {
                    let _ignored = self.set_block_allocated(*block, false);
                }
                return Err(error);
            }
            allocated += 1;
        }
        self.durability_barrier()?;
        Ok(blocks)
    }

    fn release_blocks(&mut self, blocks: &[u32]) -> Result<(), FsError> {
        for block in blocks {
            self.set_block_allocated(*block, false)?;
        }
        if !blocks.is_empty() {
            self.durability_barrier()?;
        }
        Ok(())
    }

    fn inode_record_location(&mut self, number: u32) -> Result<(u32, usize), FsError> {
        if number == 0 || number > self.layout.inodes {
            return Err(FsError::Corrupt);
        }
        let zero_based = number - 1;
        let group = zero_based / self.layout.inodes_per_group;
        let index = zero_based % self.layout.inodes_per_group;
        let descriptor = self.group_descriptor(group)?;
        let inode_table = read_u32(&descriptor, 8)?;
        if inode_table == 0 || inode_table >= self.layout.blocks {
            return Err(FsError::Corrupt);
        }
        let byte_offset = usize::try_from(index)
            .ok()
            .and_then(|value| value.checked_mul(EXT4_INODE_BYTES))
            .ok_or(FsError::Overflow)?;
        let block = inode_table
            .checked_add(
                u32::try_from(byte_offset / EXT4_BLOCK_BYTES).map_err(|_| FsError::Overflow)?,
            )
            .ok_or(FsError::Overflow)?;
        Ok((block, byte_offset % EXT4_BLOCK_BYTES))
    }

    fn physical_inode_blocks(inode: &Inode) -> Result<Vec<u32>, FsError> {
        let mut blocks = Vec::new();
        for extent in &inode.extents {
            blocks
                .try_reserve_exact(usize::from(extent.blocks))
                .map_err(|_| FsError::NoSpace)?;
            for offset in 0..u32::from(extent.blocks) {
                blocks.push(
                    extent
                        .physical
                        .checked_add(offset)
                        .ok_or(FsError::Overflow)?,
                );
            }
        }
        Ok(blocks)
    }

    fn initialize_inode(&self, raw: &mut [u8], number: u32, kind: NodeKind) -> Result<(), FsError> {
        raw.fill(0);
        let mode = match kind {
            NodeKind::File => 0x8000 | self.write_defaults.mode(),
            NodeKind::Directory => 0x4000 | self.write_defaults.mode(),
            NodeKind::Symlink => 0xa000 | 0o777,
        };
        let uid = self.write_defaults.uid();
        let gid = self.write_defaults.gid();
        put_u16(raw, 0, mode)?;
        put_u16(
            raw,
            2,
            u16::try_from(uid & u32::from(u16::MAX)).map_err(|_| FsError::Overflow)?,
        )?;
        put_u16(
            raw,
            24,
            u16::try_from(gid & u32::from(u16::MAX)).map_err(|_| FsError::Overflow)?,
        )?;
        put_u16(raw, 26, if kind == NodeKind::Directory { 2 } else { 1 })?;
        put_u16(
            raw,
            120,
            u16::try_from(uid >> 16).map_err(|_| FsError::Overflow)?,
        )?;
        put_u16(
            raw,
            122,
            u16::try_from(gid >> 16).map_err(|_| FsError::Overflow)?,
        )?;
        put_u32(raw, 100, self.layout.checksum_seed ^ number ^ 0xa5a5_5a5a)?;
        put_u16(raw, 128, 32)
    }

    fn inode_sector_count(raw: &[u8]) -> Result<u64, FsError> {
        Ok(u64::from(read_u32(raw, 28)?) | (u64::from(read_u16(raw, 116)?) << 32))
    }

    fn extent_sector_count(raw: &[u8], volume_blocks: u32) -> Result<u64, FsError> {
        parse_extents(raw.get(40..100).ok_or(FsError::Corrupt)?, volume_blocks)?
            .iter()
            .try_fold(0_u64, |total, extent| {
                total
                    .checked_add(u64::from(extent.blocks) * (EXT4_BLOCK_BYTES_U64 / 512))
                    .ok_or(FsError::Overflow)
            })
    }

    fn encode_inode_content(
        raw: &mut [u8],
        size: u64,
        blocks: &[u32],
        metadata_sectors: u64,
    ) -> Result<(), FsError> {
        let size_bytes = size.to_le_bytes();
        put_u32(
            raw,
            4,
            u32::from_le_bytes(size_bytes[..4].try_into().map_err(|_| FsError::Overflow)?),
        )?;
        put_u32(
            raw,
            108,
            u32::from_le_bytes(size_bytes[4..].try_into().map_err(|_| FsError::Overflow)?),
        )?;
        let sectors = u64::try_from(blocks.len())
            .map_err(|_| FsError::Overflow)?
            .checked_mul(EXT4_BLOCK_BYTES_U64 / 512)
            .and_then(|data_sectors| data_sectors.checked_add(metadata_sectors))
            .ok_or(FsError::Overflow)?;
        put_u32(
            raw,
            28,
            u32::try_from(sectors & u64::from(u32::MAX)).map_err(|_| FsError::Overflow)?,
        )?;
        put_u16(
            raw,
            116,
            u16::try_from(sectors >> 32).map_err(|_| FsError::Overflow)?,
        )?;
        put_u32(raw, 32, read_u32(raw, 32)? | EXT4_EXTENTS_FL)?;
        raw[40..100].fill(0);
        put_u16(raw, 40, EXT4_EXT_MAGIC)?;
        put_u16(raw, 44, 4)?;
        let mut extent_count = 0_u16;
        let mut logical = 0_u32;
        let mut index = 0_usize;
        while index < blocks.len() {
            let physical = blocks[index];
            let mut length = 1_usize;
            while index + length < blocks.len()
                && length < 0x8000
                && blocks[index + length]
                    == physical
                        .checked_add(u32::try_from(length).map_err(|_| FsError::Overflow)?)
                        .ok_or(FsError::Overflow)?
            {
                length += 1;
            }
            if extent_count >= 4 {
                return Err(FsError::NoSpace);
            }
            let extent_offset = 52_usize
                .checked_add(usize::from(extent_count) * 12)
                .ok_or(FsError::Overflow)?;
            put_u32(raw, extent_offset, logical)?;
            put_u16(
                raw,
                extent_offset + 4,
                u16::try_from(length).map_err(|_| FsError::Overflow)?,
            )?;
            put_u16(raw, extent_offset + 6, 0)?;
            put_u32(raw, extent_offset + 8, physical)?;
            logical = logical
                .checked_add(u32::try_from(length).map_err(|_| FsError::Overflow)?)
                .ok_or(FsError::Overflow)?;
            index += length;
            extent_count += 1;
        }
        put_u16(raw, 42, extent_count)
    }

    fn refresh_inode_checksum(&self, raw: &mut [u8], number: u32) -> Result<(), FsError> {
        raw[124..126].fill(0);
        raw[130..132].fill(0);
        let generation = read_u32(raw, 100)?;
        let checksum = crc32c(
            crc32c(
                crc32c(self.layout.checksum_seed, &number.to_le_bytes()),
                &generation.to_le_bytes(),
            ),
            raw,
        );
        put_u16(
            raw,
            124,
            u16::from_le_bytes([checksum.to_le_bytes()[0], checksum.to_le_bytes()[1]]),
        )?;
        put_u16(
            raw,
            130,
            u16::from_le_bytes([checksum.to_le_bytes()[2], checksum.to_le_bytes()[3]]),
        )
    }

    fn write_inode_extents(
        &mut self,
        number: u32,
        kind: NodeKind,
        size: u64,
        blocks: &[u32],
        create: bool,
    ) -> Result<(), FsError> {
        let (table_block, offset) = self.inode_record_location(number)?;
        let mut table = self.read_fs_block(table_block)?;
        let raw = table
            .get_mut(offset..offset + EXT4_INODE_BYTES)
            .ok_or(FsError::Corrupt)?;
        let metadata_sectors = if create {
            self.initialize_inode(raw, number, kind)?;
            0
        } else {
            let existing_kind = match read_u16(raw, 0)? & 0xf000 {
                0x4000 => NodeKind::Directory,
                0x8000 => NodeKind::File,
                0xa000 => NodeKind::Symlink,
                _ => return Err(FsError::Corrupt),
            };
            if existing_kind != kind {
                return Err(FsError::WrongType);
            }
            Self::inode_sector_count(raw)?
                .checked_sub(Self::extent_sector_count(raw, self.layout.blocks)?)
                .ok_or(FsError::Corrupt)?
        };
        Self::encode_inode_content(raw, size, blocks, metadata_sectors)?;
        self.refresh_inode_checksum(raw, number)?;
        self.write_fs_block(table_block, &table)
    }

    fn raw_inode_record(&mut self, number: u32) -> Result<[u8; EXT4_INODE_BYTES], FsError> {
        let (block, offset) = self.inode_record_location(number)?;
        let table = self.read_fs_block(block)?;
        table
            .get(offset..offset + EXT4_INODE_BYTES)
            .ok_or(FsError::Corrupt)?
            .try_into()
            .map_err(|_| FsError::Corrupt)
    }

    fn write_inline_symlink_inode(&mut self, number: u32, target: &[u8]) -> Result<(), FsError> {
        if target.is_empty() || target.len() > EXT4_FAST_SYMLINK_BYTES {
            return Err(FsError::Invalid);
        }
        let (block, offset) = self.inode_record_location(number)?;
        let mut table = self.read_fs_block(block)?;
        let raw = table
            .get_mut(offset..offset + EXT4_INODE_BYTES)
            .ok_or(FsError::Corrupt)?;
        self.initialize_inode(raw, number, NodeKind::Symlink)?;
        put_u32(
            raw,
            4,
            u32::try_from(target.len()).map_err(|_| FsError::Overflow)?,
        )?;
        put_u32(raw, 108, 0)?;
        put_u32(raw, 28, 0)?;
        put_u16(raw, 116, 0)?;
        put_u32(raw, 32, read_u32(raw, 32)? & !EXT4_EXTENTS_FL)?;
        raw[40..100].fill(0);
        raw[40..40 + target.len()].copy_from_slice(target);
        self.refresh_inode_checksum(raw, number)?;
        self.write_fs_block(block, &table)
    }

    fn update_inode_links(
        &mut self,
        number: u32,
        expected: u16,
        replacement: u16,
    ) -> Result<(), FsError> {
        if expected == 0 || replacement == 0 {
            return Err(FsError::Corrupt);
        }
        let (block, offset) = self.inode_record_location(number)?;
        let mut table = self.read_fs_block(block)?;
        let raw = table
            .get_mut(offset..offset + EXT4_INODE_BYTES)
            .ok_or(FsError::Corrupt)?;
        if read_u16(raw, 26)? != expected {
            return Err(FsError::Corrupt);
        }
        put_u16(raw, 26, replacement)?;
        self.refresh_inode_checksum(raw, number)?;
        self.write_fs_block(block, &table)
    }

    fn clear_inode_record(&mut self, number: u32) -> Result<(), FsError> {
        let (block, offset) = self.inode_record_location(number)?;
        let mut table = self.read_fs_block(block)?;
        table
            .get_mut(offset..offset + EXT4_INODE_BYTES)
            .ok_or(FsError::Corrupt)?
            .fill(0);
        self.write_fs_block(block, &table)
    }

    fn group_descriptor(&mut self, group: u32) -> Result<[u8; EXT4_GROUP_DESC_BYTES], FsError> {
        if group >= self.layout.groups {
            return Err(FsError::Corrupt);
        }
        let byte_offset = usize::try_from(group)
            .ok()
            .and_then(|value| value.checked_mul(EXT4_GROUP_DESC_BYTES))
            .ok_or(FsError::Overflow)?;
        let table_block = 1_u32
            .checked_add(
                u32::try_from(byte_offset / EXT4_BLOCK_BYTES).map_err(|_| FsError::Overflow)?,
            )
            .ok_or(FsError::Overflow)?;
        let offset = byte_offset % EXT4_BLOCK_BYTES;
        let bytes = self.read_fs_block(table_block)?;
        let mut descriptor = <[u8; EXT4_GROUP_DESC_BYTES]>::try_from(
            bytes
                .get(offset..offset + EXT4_GROUP_DESC_BYTES)
                .ok_or(FsError::Corrupt)?,
        )
        .map_err(|_| FsError::Corrupt)?;
        let stored = read_u16(&descriptor, 30)?;
        descriptor[30..32].fill(0);
        let checksum = crc32c(
            crc32c(self.layout.checksum_seed, &group.to_le_bytes()),
            &descriptor,
        );
        if stored
            != u16::from_le_bytes(
                checksum.to_le_bytes()[..2]
                    .try_into()
                    .map_err(|_| FsError::Corrupt)?,
            )
        {
            return Err(FsError::Corrupt);
        }
        descriptor[30..32].copy_from_slice(&stored.to_le_bytes());
        Ok(descriptor)
    }

    fn read_inode(&mut self, number: u32) -> Result<Inode, FsError> {
        if number == 0 || number > self.layout.inodes {
            return Err(FsError::Corrupt);
        }
        let zero_based = number - 1;
        let group = zero_based / self.layout.inodes_per_group;
        let index = zero_based % self.layout.inodes_per_group;
        let descriptor = self.group_descriptor(group)?;
        let inode_bitmap = read_u32(&descriptor, 4)?;
        let inode_table = read_u32(&descriptor, 8)?;
        if inode_bitmap == 0
            || inode_bitmap >= self.layout.blocks
            || inode_table == 0
            || inode_table >= self.layout.blocks
        {
            return Err(FsError::Corrupt);
        }
        let bitmap = self.read_fs_block(inode_bitmap)?;
        let stored_bitmap_checksum = read_u16(&descriptor, 26)?;
        let bitmap_bytes =
            usize::try_from(self.layout.inodes_per_group / 8).map_err(|_| FsError::Overflow)?;
        let bitmap_checksum = crc32c(
            self.layout.checksum_seed,
            bitmap.get(..bitmap_bytes).ok_or(FsError::Corrupt)?,
        );
        if stored_bitmap_checksum
            != u16::from_le_bytes(
                bitmap_checksum.to_le_bytes()[..2]
                    .try_into()
                    .map_err(|_| FsError::Corrupt)?,
            )
        {
            return Err(FsError::Corrupt);
        }
        let bit = usize::try_from(index).map_err(|_| FsError::Overflow)?;
        if bitmap
            .get(bit / 8)
            .is_none_or(|byte| byte & (1 << (bit % 8)) == 0)
        {
            return Err(FsError::Corrupt);
        }
        let byte_offset = usize::try_from(index)
            .ok()
            .and_then(|value| value.checked_mul(EXT4_INODE_BYTES))
            .ok_or(FsError::Overflow)?;
        let table_offset_blocks =
            u32::try_from(byte_offset / EXT4_BLOCK_BYTES).map_err(|_| FsError::Overflow)?;
        let table_block = inode_table
            .checked_add(table_offset_blocks)
            .ok_or(FsError::Overflow)?;
        let offset = byte_offset % EXT4_BLOCK_BYTES;
        let block = self.read_fs_block(table_block)?;
        let raw = block
            .get(offset..offset + EXT4_INODE_BYTES)
            .ok_or(FsError::Corrupt)?;
        parse_inode(raw, number, self.layout, self.limits)
    }

    fn read_inode_payload(
        &mut self,
        inode: &Inode,
        offset: u64,
        destination: &mut [u8],
    ) -> Result<usize, FsError> {
        if inode.kind == NodeKind::Directory {
            return Err(FsError::WrongType);
        }
        if offset >= inode.size || destination.is_empty() {
            return Ok(0);
        }
        let remaining = inode.size - offset;
        let wanted = destination
            .len()
            .min(usize::try_from(remaining).unwrap_or(usize::MAX));
        let mut copied = 0_usize;
        while copied < wanted {
            let file_offset = offset
                .checked_add(u64::try_from(copied).map_err(|_| FsError::Overflow)?)
                .ok_or(FsError::Overflow)?;
            let logical =
                u32::try_from(file_offset / EXT4_BLOCK_BYTES_U64).map_err(|_| FsError::Overflow)?;
            let in_block = usize::try_from(file_offset % EXT4_BLOCK_BYTES_U64)
                .map_err(|_| FsError::Overflow)?;
            let count = (wanted - copied).min(EXT4_BLOCK_BYTES - in_block);
            match map_block(inode, logical)? {
                Some((physical, false)) => {
                    let block = self.read_fs_block(physical)?;
                    destination[copied..copied + count]
                        .copy_from_slice(&block[in_block..in_block + count]);
                }
                Some((_, true)) | None => destination[copied..copied + count].fill(0),
            }
            copied += count;
        }
        Ok(copied)
    }

    fn read_symlink_inode(&mut self, inode: &Inode) -> Result<String, FsError> {
        if inode.kind != NodeKind::Symlink {
            return Err(FsError::WrongType);
        }
        let target_bytes = usize::try_from(inode.size).map_err(|_| FsError::NoSpace)?;
        if target_bytes == 0 || target_bytes > MAX_PATH_BYTES {
            return Err(FsError::Corrupt);
        }
        let mut target = Vec::new();
        target
            .try_reserve_exact(target_bytes)
            .map_err(|_| FsError::NoSpace)?;
        target.resize(target_bytes, 0);
        if inode.extents.is_empty() && target_bytes <= EXT4_FAST_SYMLINK_BYTES {
            let raw = self.raw_inode_record(inode.number)?;
            target.copy_from_slice(raw.get(40..40 + target_bytes).ok_or(FsError::Corrupt)?);
        } else if self.read_inode_payload(inode, 0, &mut target)? != target_bytes {
            return Err(FsError::Corrupt);
        }
        if target.contains(&0) {
            return Err(FsError::Corrupt);
        }
        str::from_utf8(&target)
            .map(str::to_string)
            .map_err(|_| FsError::Unsupported)
    }

    fn resolve(&mut self, path: &str) -> Result<Inode, FsError> {
        self.resolve_with_final(path, true)
    }

    fn resolve_no_follow(&mut self, path: &str) -> Result<Inode, FsError> {
        self.resolve_with_final(path, false)
    }

    fn resolve_with_final(&mut self, path: &str, follow_final: bool) -> Result<Inode, FsError> {
        let normalized = canonicalize("/", path)?;
        if normalized != path || !path.starts_with('/') {
            return Err(FsError::Invalid);
        }
        let mut remaining = normalized;
        let mut consumed = 0_u32;
        let mut expansions = 0_u8;
        'resolution: loop {
            let mut current = self.read_inode(EXT4_ROOT_INO)?;
            consumed = consumed.checked_add(1).ok_or(FsError::Overflow)?;
            if consumed > self.limits.max_inodes_per_operation() {
                return Err(FsError::NoSpace);
            }
            if remaining == "/" {
                return Ok(current);
            }
            let components: Vec<String> = remaining
                .trim_start_matches('/')
                .split('/')
                .map(str::to_string)
                .collect();
            let mut resolved_parent = "/".to_string();
            for (index, component) in components.iter().enumerate() {
                if current.kind != NodeKind::Directory {
                    return Err(FsError::WrongType);
                }
                let entries = self.read_directory(&current)?;
                let mut matched = None;
                for entry in entries {
                    if entry.name == *component && matched.replace(entry).is_some() {
                        return Err(FsError::Corrupt);
                    }
                }
                let entry = matched.ok_or(FsError::NotFound)?;
                consumed = consumed.checked_add(1).ok_or(FsError::Overflow)?;
                if consumed > self.limits.max_inodes_per_operation() {
                    return Err(FsError::NoSpace);
                }
                current = self.read_inode(entry.inode)?;
                if current.kind != entry.kind {
                    return Err(FsError::Corrupt);
                }
                let final_component = index + 1 == components.len();
                if current.kind == NodeKind::Symlink && (follow_final || !final_component) {
                    expansions = expansions.checked_add(1).ok_or(FsError::Overflow)?;
                    if expansions > MAX_SYMLINK_EXPANSIONS {
                        return Err(FsError::NoSpace);
                    }
                    let mut target = self.read_symlink_inode(&current)?;
                    for suffix in &components[index + 1..] {
                        target.push('/');
                        target.push_str(suffix);
                    }
                    remaining = if target.starts_with('/') {
                        canonicalize("/", &target)?
                    } else {
                        canonicalize(&resolved_parent, &target)?
                    };
                    continue 'resolution;
                }
                if !final_component {
                    if resolved_parent != "/" {
                        resolved_parent.push('/');
                    }
                    resolved_parent.push_str(component);
                }
            }
            return Ok(current);
        }
    }

    fn read_directory(&mut self, inode: &Inode) -> Result<Vec<DirectoryEntry>, FsError> {
        if inode.kind != NodeKind::Directory {
            return Err(FsError::WrongType);
        }
        if inode.size == 0 || !inode.size.is_multiple_of(EXT4_BLOCK_BYTES_U64) {
            return Err(FsError::Corrupt);
        }
        let block_count =
            u32::try_from(inode.size / EXT4_BLOCK_BYTES_U64).map_err(|_| FsError::NoSpace)?;
        if block_count > self.limits.max_directory_blocks() {
            return Err(FsError::NoSpace);
        }
        let mut entries = Vec::new();
        entries
            .try_reserve_exact(
                usize::try_from(self.limits.max_directory_entries())
                    .map_err(|_| FsError::Overflow)?,
            )
            .map_err(|_| FsError::NoSpace)?;
        for logical in 0..block_count {
            let (physical, unwritten) = map_block(inode, logical)?.ok_or(FsError::Corrupt)?;
            if unwritten {
                return Err(FsError::Corrupt);
            }
            let block = self.read_fs_block(physical)?;
            verify_directory_checksum(self.layout.checksum_seed, inode, &block)?;
            parse_directory_block(
                &block,
                inode.number,
                self.layout.inodes,
                self.limits,
                &mut entries,
            )?;
        }
        Ok(entries)
    }

    fn resolve_parent(&mut self, path: &str) -> Result<(Inode, String), FsError> {
        let normalized = canonicalize("/", path)?;
        if normalized != path || path == "/" || !path.starts_with('/') {
            return Err(FsError::Invalid);
        }
        let (parent, name) = path.rsplit_once('/').ok_or(FsError::Invalid)?;
        if name.is_empty()
            || name.len() > self.limits.max_name_bytes()
            || name.as_bytes().contains(&0)
        {
            return Err(FsError::Invalid);
        }
        let parent_path = if parent.is_empty() { "/" } else { parent };
        let inode = self.resolve(parent_path)?;
        if inode.kind != NodeKind::Directory {
            return Err(FsError::WrongType);
        }
        Ok((inode, name.to_string()))
    }

    fn try_add_directory_entry_to_block(
        &mut self,
        directory: &Inode,
        physical: u32,
        name: &str,
        inode_number: u32,
        required: usize,
        file_type: u8,
    ) -> Result<bool, FsError> {
        let mut block = self.read_fs_block(physical)?;
        verify_directory_checksum(self.layout.checksum_seed, directory, &block)?;
        let tail_offset = EXT4_BLOCK_BYTES - EXT4_DIR_TAIL_BYTES;
        let mut offset = 0_usize;
        while offset < tail_offset {
            let current_inode = read_u32(&block, offset)?;
            let record_bytes = usize::from(read_u16(&block, offset + 4)?);
            let name_bytes = usize::from(*block.get(offset + 6).ok_or(FsError::Corrupt)?);
            if record_bytes < 8
                || !record_bytes.is_multiple_of(4)
                || offset
                    .checked_add(record_bytes)
                    .is_none_or(|end| end > tail_offset)
                || name_bytes > record_bytes - 8
            {
                return Err(FsError::Corrupt);
            }
            if current_inode == 0 && record_bytes >= required {
                let used = if record_bytes - required >= 8 {
                    required
                } else {
                    record_bytes
                };
                write_directory_record(
                    &mut block,
                    offset,
                    used,
                    inode_number,
                    name.as_bytes(),
                    file_type,
                )?;
                if used < record_bytes {
                    write_directory_record(
                        &mut block,
                        offset + used,
                        record_bytes - used,
                        0,
                        &[],
                        0,
                    )?;
                }
                refresh_directory_checksum(self.layout.checksum_seed, directory, &mut block)?;
                self.write_fs_block(physical, &block)?;
                self.durability_barrier()?;
                return Ok(true);
            }
            if current_inode != 0 {
                let minimum = directory_record_bytes(name_bytes)?;
                if record_bytes - minimum >= required {
                    put_u16(
                        &mut block,
                        offset + 4,
                        u16::try_from(minimum).map_err(|_| FsError::Overflow)?,
                    )?;
                    write_directory_record(
                        &mut block,
                        offset + minimum,
                        record_bytes - minimum,
                        inode_number,
                        name.as_bytes(),
                        file_type,
                    )?;
                    refresh_directory_checksum(self.layout.checksum_seed, directory, &mut block)?;
                    self.write_fs_block(physical, &block)?;
                    self.durability_barrier()?;
                    return Ok(true);
                }
            }
            offset = offset.checked_add(record_bytes).ok_or(FsError::Overflow)?;
        }
        Ok(false)
    }

    fn add_directory_entry(
        &mut self,
        directory: &Inode,
        name: &str,
        inode_number: u32,
        kind: NodeKind,
    ) -> Result<(), FsError> {
        let file_type = match kind {
            NodeKind::File => EXT4_FT_REG_FILE,
            NodeKind::Symlink => EXT4_FT_SYMLINK,
            NodeKind::Directory => EXT4_FT_DIR,
        };
        let required = directory_record_bytes(name.len())?;
        let block_count =
            u32::try_from(directory.size / EXT4_BLOCK_BYTES_U64).map_err(|_| FsError::Overflow)?;
        for logical in 0..block_count {
            let (physical, false) = map_block(directory, logical)?.ok_or(FsError::Corrupt)? else {
                return Err(FsError::Corrupt);
            };
            if self.try_add_directory_entry_to_block(
                directory,
                physical,
                name,
                inode_number,
                required,
                file_type,
            )? {
                return Ok(());
            }
        }

        let zeroes = alloc::vec![0_u8; EXT4_BLOCK_BYTES];
        let new_blocks = self.allocate_file_blocks(&zeroes)?;
        let physical = *new_blocks.first().ok_or(FsError::NoSpace)?;
        let mut block = alloc::vec![0_u8; EXT4_BLOCK_BYTES];
        write_directory_record(
            &mut block,
            0,
            EXT4_BLOCK_BYTES - EXT4_DIR_TAIL_BYTES,
            inode_number,
            name.as_bytes(),
            file_type,
        )?;
        initialize_directory_tail(&mut block)?;
        refresh_directory_checksum(self.layout.checksum_seed, directory, &mut block)?;
        if let Err(error) = self
            .write_fs_block(physical, &block)
            .and_then(|()| self.durability_barrier())
        {
            let _ignored = self.release_blocks(&new_blocks);
            return Err(error);
        }
        let mut directory_blocks = Self::physical_inode_blocks(directory)?;
        directory_blocks
            .try_reserve_exact(1)
            .map_err(|_| FsError::NoSpace)?;
        directory_blocks.push(physical);
        if let Err(error) = self
            .write_inode_extents(
                directory.number,
                NodeKind::Directory,
                directory
                    .size
                    .checked_add(EXT4_BLOCK_BYTES_U64)
                    .ok_or(FsError::Overflow)?,
                &directory_blocks,
                false,
            )
            .and_then(|()| self.durability_barrier())
        {
            let _ignored = self.release_blocks(&new_blocks);
            return Err(error);
        }
        Ok(())
    }

    fn remove_directory_entry(
        &mut self,
        directory: &Inode,
        name: &str,
    ) -> Result<DirectoryEntry, FsError> {
        let entries = self.read_directory(directory)?;
        let mut matching = entries.into_iter().filter(|entry| entry.name == name);
        let found = matching.next().ok_or(FsError::NotFound)?;
        if matching.next().is_some() {
            return Err(FsError::Corrupt);
        }
        if found.kind == NodeKind::Directory {
            return Err(FsError::WrongType);
        }
        let block_count =
            u32::try_from(directory.size / EXT4_BLOCK_BYTES_U64).map_err(|_| FsError::Overflow)?;
        for logical in 0..block_count {
            let (physical, false) = map_block(directory, logical)?.ok_or(FsError::Corrupt)? else {
                return Err(FsError::Corrupt);
            };
            let mut block = self.read_fs_block(physical)?;
            verify_directory_checksum(self.layout.checksum_seed, directory, &block)?;
            let tail_offset = EXT4_BLOCK_BYTES - EXT4_DIR_TAIL_BYTES;
            let mut offset = 0_usize;
            while offset < tail_offset {
                let inode = read_u32(&block, offset)?;
                let record_bytes = usize::from(read_u16(&block, offset + 4)?);
                let name_bytes = usize::from(*block.get(offset + 6).ok_or(FsError::Corrupt)?);
                if record_bytes < 8
                    || !record_bytes.is_multiple_of(4)
                    || offset
                        .checked_add(record_bytes)
                        .is_none_or(|end| end > tail_offset)
                    || name_bytes > record_bytes - 8
                {
                    return Err(FsError::Corrupt);
                }
                let raw_name = block
                    .get(offset + 8..offset + 8 + name_bytes)
                    .ok_or(FsError::Corrupt)?;
                if inode == found.inode && raw_name == name.as_bytes() {
                    put_u32(&mut block, offset, 0)?;
                    block[offset + 6] = 0;
                    block[offset + 7] = 0;
                    block[offset + 8..offset + record_bytes].fill(0);
                    refresh_directory_checksum(self.layout.checksum_seed, directory, &mut block)?;
                    self.write_fs_block(physical, &block)?;
                    self.durability_barrier()?;
                    return Ok(found);
                }
                offset = offset.checked_add(record_bytes).ok_or(FsError::Overflow)?;
            }
        }
        Err(FsError::Corrupt)
    }
}

impl<D: BlockDevice> ReadOnlyFileSystem for Ext4<D> {
    fn metadata(&mut self, path: &str) -> Result<FileMetadata, FsError> {
        let inode = self.resolve(path)?;
        Ok(FileMetadata {
            kind: inode.kind,
            byte_count: if inode.kind == NodeKind::File {
                inode.size
            } else {
                0
            },
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
        let inode = self.resolve(path)?;
        if inode.kind != NodeKind::File {
            return Err(FsError::WrongType);
        }
        self.read_inode_payload(&inode, offset, destination)
    }

    fn list(
        &mut self,
        path: &str,
        cursor: u64,
        max_entries: usize,
        max_name_bytes: usize,
    ) -> Result<ProviderListing, FsError> {
        let inode = self.resolve(path)?;
        if inode.kind != NodeKind::Directory {
            return Err(FsError::WrongType);
        }
        let mut source = self.read_directory(&inode)?;
        source.retain(|entry| entry.name != "." && entry.name != "..");
        source.sort_unstable_by(|left, right| left.name.as_bytes().cmp(right.name.as_bytes()));
        for pair in source.windows(2) {
            if pair[0].name == pair[1].name {
                return Err(FsError::Corrupt);
            }
        }
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
        {
            return Err(FsError::NoSpace);
        }
        let (parent, name) = self.resolve_parent(path)?;
        let entries = self.read_directory(&parent)?;
        let mut matching = entries.iter().filter(|entry| entry.name == name);
        let existing = matching.next().cloned();
        if matching.next().is_some() {
            return Err(FsError::Corrupt);
        }
        if existing.is_some() {
            let inode = self.resolve(path)?;
            if inode.kind != NodeKind::File {
                return Err(FsError::WrongType);
            }
            let old_blocks = Self::physical_inode_blocks(&inode)?;
            self.begin_mutation()?;
            let new_blocks = self.allocate_file_blocks(bytes)?;
            if let Err(error) = self
                .write_inode_extents(
                    inode.number,
                    NodeKind::File,
                    u64::try_from(bytes.len()).map_err(|_| FsError::Overflow)?,
                    &new_blocks,
                    false,
                )
                .and_then(|()| self.durability_barrier())
            {
                let _ignored = self.release_blocks(&new_blocks);
                return Err(error);
            }
            self.release_blocks(&old_blocks)?;
            return self.finish_mutation();
        }

        let inode_number = self.find_free_inode()?;
        self.begin_mutation()?;
        self.set_inode_allocated(inode_number, true)?;
        let new_blocks = match self.allocate_file_blocks(bytes) {
            Ok(blocks) => blocks,
            Err(error) => {
                let _ignored = self.set_inode_allocated(inode_number, false);
                return Err(error);
            }
        };
        if let Err(error) = self
            .write_inode_extents(
                inode_number,
                NodeKind::File,
                u64::try_from(bytes.len()).map_err(|_| FsError::Overflow)?,
                &new_blocks,
                true,
            )
            .and_then(|()| self.durability_barrier())
            .and_then(|()| self.add_directory_entry(&parent, &name, inode_number, NodeKind::File))
        {
            let _ignored = self.clear_inode_record(inode_number);
            let _ignored = self.set_inode_allocated(inode_number, false);
            let _ignored = self.release_blocks(&new_blocks);
            return Err(error);
        }
        self.finish_mutation()
    }

    fn create_directory(&mut self, path: &str) -> Result<(), FsError> {
        self.ensure_writable()?;
        let (parent, name) = self.resolve_parent(path)?;
        let entries = self.read_directory(&parent)?;
        let mut matching = entries.iter().filter(|entry| entry.name == name);
        if matching.next().is_some() {
            if matching.next().is_some() {
                return Err(FsError::Corrupt);
            }
            return Err(FsError::Exists);
        }

        let inode_number = self.find_free_inode()?;
        self.begin_mutation()?;
        self.set_inode_allocated(inode_number, true)?;
        if let Err(error) = self.set_directory_allocated(inode_number, true) {
            let _ignored = self.set_inode_allocated(inode_number, false);
            return Err(error);
        }
        let zeroes = alloc::vec![0_u8; EXT4_BLOCK_BYTES];
        let blocks = match self.allocate_file_blocks(&zeroes) {
            Ok(blocks) if blocks.len() == 1 => blocks,
            Ok(blocks) => {
                let _ignored = self.release_blocks(&blocks);
                let _ignored = self.set_directory_allocated(inode_number, false);
                let _ignored = self.set_inode_allocated(inode_number, false);
                return Err(FsError::Corrupt);
            }
            Err(error) => {
                let _ignored = self.set_directory_allocated(inode_number, false);
                let _ignored = self.set_inode_allocated(inode_number, false);
                return Err(error);
            }
        };
        if let Err(error) = self.write_inode_extents(
            inode_number,
            NodeKind::Directory,
            EXT4_BLOCK_BYTES_U64,
            &blocks,
            true,
        ) {
            let _ignored = self.clear_inode_record(inode_number);
            let _ignored = self.set_directory_allocated(inode_number, false);
            let _ignored = self.set_inode_allocated(inode_number, false);
            let _ignored = self.release_blocks(&blocks);
            return Err(error);
        }
        let directory = match self.read_inode(inode_number) {
            Ok(inode) => inode,
            Err(error) => {
                let _ignored = self.clear_inode_record(inode_number);
                let _ignored = self.set_directory_allocated(inode_number, false);
                let _ignored = self.set_inode_allocated(inode_number, false);
                let _ignored = self.release_blocks(&blocks);
                return Err(error);
            }
        };
        let mut block = alloc::vec![0_u8; EXT4_BLOCK_BYTES];
        let tail = EXT4_BLOCK_BYTES - EXT4_DIR_TAIL_BYTES;
        let initialize = write_directory_record(&mut block, 0, 12, inode_number, b".", EXT4_FT_DIR)
            .and_then(|()| {
                write_directory_record(&mut block, 12, tail - 12, parent.number, b"..", EXT4_FT_DIR)
            })
            .and_then(|()| initialize_directory_tail(&mut block))
            .and_then(|()| {
                refresh_directory_checksum(self.layout.checksum_seed, &directory, &mut block)
            })
            .and_then(|()| self.write_fs_block(blocks[0], &block))
            .and_then(|()| self.durability_barrier());
        if let Err(error) = initialize {
            let _ignored = self.clear_inode_record(inode_number);
            let _ignored = self.set_directory_allocated(inode_number, false);
            let _ignored = self.set_inode_allocated(inode_number, false);
            let _ignored = self.release_blocks(&blocks);
            return Err(error);
        }

        let parent_raw = self.raw_inode_record(parent.number)?;
        let parent_links = read_u16(&parent_raw, 26)?;
        let next_parent_links = parent_links.checked_add(1).ok_or(FsError::NoSpace)?;
        self.update_inode_links(parent.number, parent_links, next_parent_links)?;
        if let Err(error) =
            self.add_directory_entry(&parent, &name, inode_number, NodeKind::Directory)
        {
            let _ignored = self.update_inode_links(parent.number, next_parent_links, parent_links);
            let _ignored = self.clear_inode_record(inode_number);
            let _ignored = self.set_directory_allocated(inode_number, false);
            let _ignored = self.set_inode_allocated(inode_number, false);
            let _ignored = self.release_blocks(&blocks);
            return Err(error);
        }
        self.finish_mutation()
    }

    fn remove_file(&mut self, path: &str) -> Result<(), FsError> {
        self.ensure_writable()?;
        let (parent, name) = self.resolve_parent(path)?;
        let entries = self.read_directory(&parent)?;
        let mut matching = entries.iter().filter(|entry| entry.name == name);
        let entry = matching.next().ok_or(FsError::NotFound)?;
        if matching.next().is_some() {
            return Err(FsError::Corrupt);
        }
        if entry.kind == NodeKind::Directory {
            return Err(FsError::WrongType);
        }
        let inode = self.read_inode(entry.inode)?;
        if inode.kind != entry.kind {
            return Err(FsError::Corrupt);
        }
        let raw = self.raw_inode_record(inode.number)?;
        let links = read_u16(&raw, 26)?;
        if links == 0 {
            return Err(FsError::Corrupt);
        }
        let external_xattr_block =
            u64::from(read_u32(&raw, 104)?) | (u64::from(read_u16(&raw, 118)?) << 32);
        if links == 1 && external_xattr_block != 0 {
            // External xattr blocks may be shared. Removing the final link would need
            // bounded refcount/checksum mutation, which is outside ext4-v1.
            return Err(FsError::Unsupported);
        }
        let blocks = (links == 1)
            .then(|| Self::physical_inode_blocks(&inode))
            .transpose()?;
        self.begin_mutation()?;
        let removed = self.remove_directory_entry(&parent, &name)?;
        if removed.inode != inode.number {
            return Err(FsError::Corrupt);
        }
        if links > 1 {
            self.update_inode_links(inode.number, links, links - 1)?;
            self.durability_barrier()?;
            return self.finish_mutation();
        }
        self.release_blocks(blocks.as_deref().ok_or(FsError::Corrupt)?)?;
        self.clear_inode_record(inode.number)?;
        self.set_inode_allocated(inode.number, false)?;
        self.durability_barrier()?;
        self.finish_mutation()
    }

    fn read_link(&mut self, path: &str) -> Result<String, FsError> {
        let inode = self.resolve_no_follow(path)?;
        self.read_symlink_inode(&inode)
    }

    fn create_symlink(&mut self, target: &str, link_path: &str) -> Result<(), FsError> {
        self.ensure_writable()?;
        if target.is_empty() || target.len() > MAX_PATH_BYTES || target.as_bytes().contains(&0) {
            return Err(FsError::Invalid);
        }
        let (parent, name) = self.resolve_parent(link_path)?;
        let entries = self.read_directory(&parent)?;
        if entries.iter().any(|entry| entry.name == name) {
            return Err(FsError::Exists);
        }
        let inode_number = self.find_free_inode()?;
        self.begin_mutation()?;
        self.set_inode_allocated(inode_number, true)?;
        let blocks = if target.len() <= EXT4_FAST_SYMLINK_BYTES {
            Vec::new()
        } else {
            match self.allocate_file_blocks(target.as_bytes()) {
                Ok(blocks) => blocks,
                Err(error) => {
                    let _ignored = self.set_inode_allocated(inode_number, false);
                    return Err(error);
                }
            }
        };
        let write_inode = if blocks.is_empty() {
            self.write_inline_symlink_inode(inode_number, target.as_bytes())
        } else {
            self.write_inode_extents(
                inode_number,
                NodeKind::Symlink,
                u64::try_from(target.len()).map_err(|_| FsError::Overflow)?,
                &blocks,
                true,
            )
        };
        if let Err(error) = write_inode
            .and_then(|()| self.durability_barrier())
            .and_then(|()| {
                self.add_directory_entry(&parent, &name, inode_number, NodeKind::Symlink)
            })
        {
            let _ignored = self.clear_inode_record(inode_number);
            let _ignored = self.set_inode_allocated(inode_number, false);
            let _ignored = self.release_blocks(&blocks);
            return Err(error);
        }
        self.finish_mutation()
    }

    fn create_hard_link(&mut self, existing: &str, new_path: &str) -> Result<(), FsError> {
        self.ensure_writable()?;
        let inode = self.resolve_no_follow(existing)?;
        if inode.kind != NodeKind::File {
            return Err(FsError::WrongType);
        }
        let (parent, name) = self.resolve_parent(new_path)?;
        let entries = self.read_directory(&parent)?;
        if entries.iter().any(|entry| entry.name == name) {
            return Err(FsError::Exists);
        }
        let raw = self.raw_inode_record(inode.number)?;
        let links = read_u16(&raw, 26)?;
        let replacement = links.checked_add(1).ok_or(FsError::NoSpace)?;
        self.begin_mutation()?;
        self.add_directory_entry(&parent, &name, inode.number, NodeKind::File)?;
        self.update_inode_links(inode.number, links, replacement)?;
        self.durability_barrier()?;
        self.finish_mutation()
    }
}

fn parse_superblock(
    superblock: &[u8],
    region_device_blocks: u64,
    device_blocks_per_fs_block: u32,
    limits: Ext4Limits,
) -> Result<Layout, FsError> {
    if superblock.len() != 1024
        || read_u16(superblock, 56)? != EXT4_MAGIC
        || read_u32(superblock, 76)? != EXT4_DYNAMIC_REV
        || read_u32(superblock, 24)? != 2
        || read_u32(superblock, 28)? != 2
        || read_u32(superblock, 72)? != 0
        || read_u16(superblock, 88)? != EXT4_INODE_BYTES_U16
        || !matches!(read_u16(superblock, 254)?, 0 | EXT4_GROUP_DESC_BYTES_U16)
        || superblock[373] != 1
        || read_u32(superblock, 92)? != EXT4_FEATURE_COMPAT
        || read_u32(superblock, 96)? != EXT4_FEATURE_INCOMPAT
        || read_u32(superblock, 100)? != EXT4_FEATURE_RO_COMPAT
    {
        return Err(FsError::Unsupported);
    }
    let state = read_u16(superblock, 58)?;
    if state & EXT4_VALID_FS == 0 || state & EXT4_ERROR_FS != 0 {
        return Err(FsError::Corrupt);
    }
    let stored_checksum = read_u32(superblock, 1020)?;
    if stored_checksum != crc32c(u32::MAX, &superblock[..1020]) {
        return Err(FsError::Corrupt);
    }
    let inodes = read_u32(superblock, 0)?;
    let blocks = read_u32(superblock, 4)?;
    let first_data_block = read_u32(superblock, 20)?;
    let blocks_per_group = read_u32(superblock, 32)?;
    let clusters_per_group = read_u32(superblock, 36)?;
    let inodes_per_group = read_u32(superblock, 40)?;
    let journal_inode = read_u32(superblock, 224)?;
    if inodes == 0
        || blocks < 2
        || first_data_block != 0
        || blocks_per_group == 0
        || blocks_per_group > EXT4_BITMAP_BITS
        || !blocks_per_group.is_multiple_of(8)
        || clusters_per_group != blocks_per_group
        || inodes_per_group == 0
        || inodes_per_group > EXT4_BITMAP_BITS
        || !inodes_per_group.is_multiple_of(8)
        || read_u32(superblock, 84)? != 11
        || journal_inode == 0
        || journal_inode > inodes
        || read_u32(superblock, 228)? != 0
        || read_u32(superblock, 232)? != 0
        || superblock[208..224].iter().any(|byte| *byte != 0)
        || read_u32(superblock, 336)? != 0
    {
        return Err(FsError::Corrupt);
    }
    let required_device_blocks = u64::from(blocks)
        .checked_mul(u64::from(device_blocks_per_fs_block))
        .ok_or(FsError::Overflow)?;
    if required_device_blocks > region_device_blocks {
        return Err(FsError::Corrupt);
    }
    let groups = blocks
        .checked_add(blocks_per_group - 1)
        .ok_or(FsError::Overflow)?
        / blocks_per_group;
    let inode_groups = inodes
        .checked_add(inodes_per_group - 1)
        .ok_or(FsError::Overflow)?
        / inodes_per_group;
    if groups == 0 || groups != inode_groups || groups > limits.max_groups() {
        return Err(FsError::NoSpace);
    }
    let uuid = Ext4Uuid(
        <[u8; 16]>::try_from(superblock.get(104..120).ok_or(FsError::Corrupt)?)
            .map_err(|_| FsError::Corrupt)?,
    );
    if uuid.0.iter().all(|byte| *byte == 0) {
        return Err(FsError::Corrupt);
    }
    Ok(Layout {
        blocks,
        inodes,
        blocks_per_group,
        inodes_per_group,
        first_inode: read_u32(superblock, 84)?,
        groups,
        device_blocks_per_fs_block,
        checksum_seed: crc32c(u32::MAX, &uuid.0),
        uuid,
    })
}

fn parse_inode(
    raw: &[u8],
    number: u32,
    layout: Layout,
    limits: Ext4Limits,
) -> Result<Inode, FsError> {
    if raw.len() != EXT4_INODE_BYTES {
        return Err(FsError::Corrupt);
    }
    let extra_isize = read_u16(raw, 128)?;
    if !(32..=128).contains(&extra_isize) || !extra_isize.is_multiple_of(4) {
        return Err(FsError::Unsupported);
    }
    let generation = read_u32(raw, 100)?;
    let stored = u32::from(read_u16(raw, 124)?) | (u32::from(read_u16(raw, 130)?) << 16);
    let mut checksummed = <[u8; EXT4_INODE_BYTES]>::try_from(raw).map_err(|_| FsError::Corrupt)?;
    checksummed[124..126].fill(0);
    checksummed[130..132].fill(0);
    let checksum = crc32c(
        crc32c(
            crc32c(layout.checksum_seed, &number.to_le_bytes()),
            &generation.to_le_bytes(),
        ),
        &checksummed,
    );
    if stored != checksum {
        return Err(FsError::Corrupt);
    }
    let mode = read_u16(raw, 0)? & 0xf000;
    let kind = match mode {
        0x4000 => NodeKind::Directory,
        0x8000 => NodeKind::File,
        0xa000 => NodeKind::Symlink,
        _ => return Err(FsError::Unsupported),
    };
    if read_u16(raw, 26)? == 0 {
        return Err(FsError::Corrupt);
    }
    let size = u64::from(read_u32(raw, 4)?) | (u64::from(read_u32(raw, 108)?) << 32);
    if (kind == NodeKind::File && size > limits.max_file_bytes())
        || (kind == NodeKind::Symlink
            && (size == 0
                || size > u64::try_from(MAX_PATH_BYTES).map_err(|_| FsError::Overflow)?))
    {
        return Err(FsError::NoSpace);
    }
    let flags = read_u32(raw, 32)?;
    let inode_sectors = u64::from(read_u32(raw, 28)?) | (u64::from(read_u16(raw, 116)?) << 32);
    let external_xattr_block =
        u64::from(read_u32(raw, 104)?) | (u64::from(read_u16(raw, 118)?) << 32);
    let symlink_metadata_sectors = u64::from(external_xattr_block != 0)
        .checked_mul(EXT4_BLOCK_BYTES_U64 / 512)
        .ok_or(FsError::Overflow)?;
    let inline_symlink = kind == NodeKind::Symlink
        && size <= u64::try_from(EXT4_FAST_SYMLINK_BYTES).map_err(|_| FsError::Overflow)?
        && inode_sectors == symlink_metadata_sectors;
    let extents = if inline_symlink {
        if flags & EXT4_EXTENTS_FL != 0 {
            return Err(FsError::Corrupt);
        }
        Vec::new()
    } else {
        if flags & EXT4_EXTENTS_FL == 0 {
            return Err(FsError::Corrupt);
        }
        parse_extents(raw.get(40..100).ok_or(FsError::Corrupt)?, layout.blocks)?
    };
    let file_blocks = size
        .checked_add(EXT4_BLOCK_BYTES_U64 - 1)
        .ok_or(FsError::Overflow)?
        / EXT4_BLOCK_BYTES_U64;
    for extent in &extents {
        let end = u64::from(extent.logical) + u64::from(extent.blocks);
        if end > file_blocks || (kind != NodeKind::File && extent.unwritten) {
            return Err(FsError::Corrupt);
        }
    }
    Ok(Inode {
        number,
        generation,
        kind,
        size,
        extents,
    })
}

fn parse_extents(raw: &[u8], volume_blocks: u32) -> Result<Vec<Extent>, FsError> {
    if raw.len() != 60
        || read_u16(raw, 0)? != EXT4_EXT_MAGIC
        || read_u16(raw, 4)? != 4
        || read_u16(raw, 6)? != 0
        || read_u32(raw, 8)? != 0
    {
        return Err(FsError::Unsupported);
    }
    let count = read_u16(raw, 2)?;
    if count > 4 {
        return Err(FsError::Corrupt);
    }
    let mut extents = Vec::new();
    extents
        .try_reserve_exact(usize::from(count))
        .map_err(|_| FsError::NoSpace)?;
    let mut previous_end = 0_u32;
    for index in 0..count {
        let offset = 12 + usize::from(index) * 12;
        let logical = read_u32(raw, offset)?;
        let encoded_blocks = read_u16(raw, offset + 4)?;
        let physical_high = read_u16(raw, offset + 6)?;
        let physical = read_u32(raw, offset + 8)?;
        let unwritten = encoded_blocks > 0x8000;
        let blocks = if unwritten {
            encoded_blocks - 0x8000
        } else {
            encoded_blocks
        };
        let logical_end = logical
            .checked_add(u32::from(blocks))
            .ok_or(FsError::Overflow)?;
        let physical_end = physical
            .checked_add(u32::from(blocks))
            .ok_or(FsError::Overflow)?;
        if blocks == 0
            || physical_high != 0
            || physical == 0
            || physical_end > volume_blocks
            || (index != 0 && logical < previous_end)
        {
            return Err(FsError::Corrupt);
        }
        extents.push(Extent {
            logical,
            physical,
            blocks,
            unwritten,
        });
        previous_end = logical_end;
    }
    Ok(extents)
}

fn map_block(inode: &Inode, logical: u32) -> Result<Option<(u32, bool)>, FsError> {
    for extent in &inode.extents {
        let end = extent
            .logical
            .checked_add(u32::from(extent.blocks))
            .ok_or(FsError::Overflow)?;
        if (extent.logical..end).contains(&logical) {
            let physical = extent
                .physical
                .checked_add(logical - extent.logical)
                .ok_or(FsError::Overflow)?;
            return Ok(Some((physical, extent.unwritten)));
        }
    }
    Ok(None)
}

fn verify_directory_checksum(seed: u32, inode: &Inode, block: &[u8]) -> Result<(), FsError> {
    if block.len() != EXT4_BLOCK_BYTES {
        return Err(FsError::Corrupt);
    }
    let tail_offset = EXT4_BLOCK_BYTES - EXT4_DIR_TAIL_BYTES;
    let tail = &block[tail_offset..];
    if read_u32(tail, 0)? != 0
        || read_u16(tail, 4)? != EXT4_DIR_TAIL_BYTES_U16
        || tail[6] != 0
        || tail[7] != EXT4_DIR_TAIL_FT
    {
        return Err(FsError::Corrupt);
    }
    let stored = read_u32(tail, 8)?;
    let inode_seed = crc32c(
        crc32c(seed, &inode.number.to_le_bytes()),
        &inode.generation.to_le_bytes(),
    );
    if stored != crc32c(inode_seed, &block[..tail_offset]) {
        return Err(FsError::Corrupt);
    }
    Ok(())
}

fn parse_directory_block(
    block: &[u8],
    directory_inode: u32,
    maximum_inode: u32,
    limits: Ext4Limits,
    entries: &mut Vec<DirectoryEntry>,
) -> Result<(), FsError> {
    let tail_offset = EXT4_BLOCK_BYTES - EXT4_DIR_TAIL_BYTES;
    let mut offset = 0_usize;
    while offset < tail_offset {
        let inode = read_u32(block, offset)?;
        let record_bytes = usize::from(read_u16(block, offset + 4)?);
        let name_bytes = usize::from(*block.get(offset + 6).ok_or(FsError::Corrupt)?);
        let file_type = *block.get(offset + 7).ok_or(FsError::Corrupt)?;
        if record_bytes < 8
            || !record_bytes.is_multiple_of(4)
            || offset
                .checked_add(record_bytes)
                .is_none_or(|end| end > tail_offset)
            || name_bytes > record_bytes - 8
        {
            return Err(FsError::Corrupt);
        }
        if inode != 0 {
            if inode > maximum_inode {
                return Err(FsError::Corrupt);
            }
            if entries.len()
                >= usize::try_from(limits.max_directory_entries()).map_err(|_| FsError::Overflow)?
                || name_bytes == 0
                || name_bytes > limits.max_name_bytes()
            {
                return Err(FsError::NoSpace);
            }
            let raw_name = block
                .get(offset + 8..offset + 8 + name_bytes)
                .ok_or(FsError::Corrupt)?;
            if raw_name.contains(&0) || raw_name.contains(&b'/') {
                return Err(FsError::Corrupt);
            }
            let name = str::from_utf8(raw_name)
                .map_err(|_| FsError::Unsupported)?
                .to_string();
            let kind = match file_type {
                EXT4_FT_REG_FILE => NodeKind::File,
                EXT4_FT_DIR => NodeKind::Directory,
                EXT4_FT_SYMLINK => NodeKind::Symlink,
                _ => return Err(FsError::Unsupported),
            };
            if name == "." && (inode != directory_inode || kind != NodeKind::Directory) {
                return Err(FsError::Corrupt);
            }
            entries.push(DirectoryEntry { inode, name, kind });
        }
        offset = offset.checked_add(record_bytes).ok_or(FsError::Overflow)?;
    }
    if offset != tail_offset {
        return Err(FsError::Corrupt);
    }
    Ok(())
}

fn directory_record_bytes(name_bytes: usize) -> Result<usize, FsError> {
    name_bytes
        .checked_add(8)
        .and_then(|value| value.checked_add(3))
        .map(|value| value & !3)
        .ok_or(FsError::Overflow)
}

fn write_directory_record(
    block: &mut [u8],
    offset: usize,
    record_bytes: usize,
    inode: u32,
    name: &[u8],
    file_type: u8,
) -> Result<(), FsError> {
    if record_bytes < 8
        || !record_bytes.is_multiple_of(4)
        || name.len() > u8::MAX.into()
        || directory_record_bytes(name.len())? > record_bytes
    {
        return Err(FsError::Invalid);
    }
    let raw = block
        .get_mut(offset..offset + record_bytes)
        .ok_or(FsError::Corrupt)?;
    raw.fill(0);
    put_u32(raw, 0, inode)?;
    put_u16(
        raw,
        4,
        u16::try_from(record_bytes).map_err(|_| FsError::Overflow)?,
    )?;
    raw[6] = u8::try_from(name.len()).map_err(|_| FsError::Overflow)?;
    raw[7] = file_type;
    raw[8..8 + name.len()].copy_from_slice(name);
    Ok(())
}

fn initialize_directory_tail(block: &mut [u8]) -> Result<(), FsError> {
    if block.len() != EXT4_BLOCK_BYTES {
        return Err(FsError::Invalid);
    }
    let offset = EXT4_BLOCK_BYTES - EXT4_DIR_TAIL_BYTES;
    let tail = &mut block[offset..];
    tail.fill(0);
    put_u16(tail, 4, EXT4_DIR_TAIL_BYTES_U16)?;
    tail[7] = EXT4_DIR_TAIL_FT;
    Ok(())
}

fn refresh_directory_checksum(seed: u32, inode: &Inode, block: &mut [u8]) -> Result<(), FsError> {
    if block.len() != EXT4_BLOCK_BYTES {
        return Err(FsError::Invalid);
    }
    let tail_offset = EXT4_BLOCK_BYTES - EXT4_DIR_TAIL_BYTES;
    let inode_seed = crc32c(
        crc32c(seed, &inode.number.to_le_bytes()),
        &inode.generation.to_le_bytes(),
    );
    let checksum = crc32c(inode_seed, &block[..tail_offset]);
    put_u32(block, tail_offset + 8, checksum)
}

fn read_raw_fs_block<D: BlockDevice>(
    region: &mut BlockRegion<D>,
    fs_block: u32,
    device_blocks_per_fs_block: u32,
) -> Result<Vec<u8>, FsError> {
    let start = u64::from(fs_block)
        .checked_mul(u64::from(device_blocks_per_fs_block))
        .ok_or(FsError::Overflow)?;
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(EXT4_BLOCK_BYTES)
        .map_err(|_| FsError::NoSpace)?;
    bytes.resize(EXT4_BLOCK_BYTES, 0);
    region
        .read_blocks(start, device_blocks_per_fs_block, &mut bytes)
        .map_err(|_| FsError::Io)?;
    Ok(bytes)
}

const fn map_block_error(error: BlockError) -> FsError {
    match error {
        BlockError::ReadOnly => FsError::ReadOnly,
        BlockError::Unsupported => FsError::Unsupported,
        _ => FsError::Io,
    }
}

fn validate_limits(limits: Ext4Limits) -> Result<(), FsError> {
    Ext4Limits::new(
        limits.max_groups(),
        limits.max_inodes_per_operation(),
        limits.max_directory_blocks(),
        limits.max_directory_entries(),
        limits.max_file_bytes(),
        limits.max_read_bytes(),
        limits.max_name_bytes(),
    )
    .map(|_| ())
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

fn put_u16(bytes: &mut [u8], offset: usize, value: u16) -> Result<(), FsError> {
    bytes
        .get_mut(offset..offset + 2)
        .ok_or(FsError::Corrupt)?
        .copy_from_slice(&value.to_le_bytes());
    Ok(())
}

fn put_u32(bytes: &mut [u8], offset: usize, value: u32) -> Result<(), FsError> {
    bytes
        .get_mut(offset..offset + 4)
        .ok_or(FsError::Corrupt)?
        .copy_from_slice(&value.to_le_bytes());
    Ok(())
}

fn crc32c(seed: u32, bytes: &[u8]) -> u32 {
    let mut checksum = seed;
    for byte in bytes {
        checksum ^= u32::from(*byte);
        for _ in 0..8 {
            checksum = (checksum >> 1) ^ (CRC32C_POLYNOMIAL & 0_u32.wrapping_sub(checksum & 1));
        }
    }
    checksum
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
    use troe_block::{BlockAccess, BlockError, BlockGeometry, BlockLimits};

    use super::{
        BlockDevice, BlockRegion, CRC32C_POLYNOMIAL, EXT4_BLOCK_BYTES, EXT4_BLOCK_BYTES_U32,
        EXT4_EXTENTS_FL, EXT4_FAST_SYMLINK_BYTES, EXT4_FEATURE_COMPAT, EXT4_FEATURE_INCOMPAT,
        EXT4_FEATURE_RO_COMPAT, EXT4_INODE_BYTES, EXT4_ROOT_INO, EXT4_VALID_FS, Ext4, Ext4Limits,
        FsError, NodeKind, ReadOnlyFileSystem, crc32c, read_u16, read_u32,
    };

    const DEVICE_BLOCK_BYTES_U32: u32 = 512;
    const DEVICE_BLOCK_BYTES_USIZE: usize = 512;
    const DEVICE_BLOCKS_PER_FS_BLOCK: u32 = 8;
    const FS_BLOCKS: u32 = 32;
    const DEVICE_BLOCKS: u64 = FS_BLOCKS as u64 * DEVICE_BLOCKS_PER_FS_BLOCK as u64;
    const UUID: [u8; 16] = *b"troe-ext4-test!!";
    const INODE_BITMAP_BLOCK: u32 = 2;
    const INODE_TABLE_BLOCK: u32 = 3;
    const ROOT_DIRECTORY_BLOCK: u32 = 4;
    const FILE_BLOCK: u32 = 5;
    const SUB_DIRECTORY_BLOCK: u32 = 6;
    const ROOT_GENERATION: u32 = 11;
    const FILE_GENERATION: u32 = 12;
    const SUB_GENERATION: u32 = 13;

    #[derive(Debug)]
    struct SparseDevice {
        blocks: BTreeMap<u32, [u8; EXT4_BLOCK_BYTES]>,
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
            if bytes == 0 || !bytes.is_multiple_of(u64::from(DEVICE_BLOCK_BYTES_U32)) {
                return Err("ext4 test image has invalid length".into());
            }
            let geometry = BlockGeometry::new(
                DEVICE_BLOCK_BYTES_U32,
                bytes / u64::from(DEVICE_BLOCK_BYTES_U32),
                1,
                false,
                false,
            )
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
            if bytes == 0 || !bytes.is_multiple_of(u64::from(DEVICE_BLOCK_BYTES_U32)) {
                return Err("ext4 test image has invalid length".into());
            }
            let geometry = BlockGeometry::new(
                DEVICE_BLOCK_BYTES_U32,
                bytes / u64::from(DEVICE_BLOCK_BYTES_U32),
                1,
                true,
                false,
            )
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
                .checked_mul(u64::from(DEVICE_BLOCK_BYTES_U32))
                .ok_or(BlockError::Device)?;
            let expected = usize::try_from(block_count)
                .ok()
                .and_then(|count| count.checked_mul(DEVICE_BLOCK_BYTES_USIZE))
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
                .checked_mul(u64::from(DEVICE_BLOCK_BYTES_U32))
                .ok_or(BlockError::Device)?;
            let expected = usize::try_from(block_count)
                .ok()
                .and_then(|count| count.checked_mul(DEVICE_BLOCK_BYTES_USIZE))
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
            BlockGeometry::new(DEVICE_BLOCK_BYTES_U32, DEVICE_BLOCKS, 1, true, false)
                .unwrap_or_else(|_| unreachable!())
        }

        fn read_blocks(
            &mut self,
            start_block: u64,
            block_count: u32,
            destination: &mut [u8],
        ) -> Result<(), BlockError> {
            if block_count != DEVICE_BLOCKS_PER_FS_BLOCK
                || destination.len() != EXT4_BLOCK_BYTES
                || !start_block.is_multiple_of(u64::from(DEVICE_BLOCKS_PER_FS_BLOCK))
            {
                return Err(BlockError::Device);
            }
            let fs_block = u32::try_from(start_block / u64::from(DEVICE_BLOCKS_PER_FS_BLOCK))
                .map_err(|_| BlockError::Device)?;
            destination.fill(0);
            if let Some(block) = self.blocks.get(&fs_block) {
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
            if block_count != DEVICE_BLOCKS_PER_FS_BLOCK
                || source.len() != EXT4_BLOCK_BYTES
                || !start_block.is_multiple_of(u64::from(DEVICE_BLOCKS_PER_FS_BLOCK))
                || force_unit_access
            {
                return Err(BlockError::Device);
            }
            let fs_block = u32::try_from(start_block / u64::from(DEVICE_BLOCKS_PER_FS_BLOCK))
                .map_err(|_| BlockError::Device)?;
            let mut block = [0_u8; EXT4_BLOCK_BYTES];
            block.copy_from_slice(source);
            self.blocks.insert(fs_block, block);
            Ok(())
        }

        fn flush(&mut self) -> Result<(), BlockError> {
            Ok(())
        }
    }

    fn limits() -> Result<Ext4Limits, FsError> {
        Ext4Limits::new(1, 16, 8, 32, 64 * 1024, 4096, 64)
    }

    fn mount(device: SparseDevice) -> Result<Ext4<SparseDevice>, FsError> {
        let block_limits = BlockLimits::new(8, EXT4_BLOCK_BYTES, 1).map_err(|_| FsError::Io)?;
        let region = BlockRegion::whole_device(device, BlockAccess::ReadOnly, block_limits)
            .map_err(|_| FsError::Io)?;
        Ext4::mount(region, limits()?)
    }

    fn mount_writable(device: SparseDevice) -> Result<Ext4<SparseDevice>, FsError> {
        let block_limits = BlockLimits::new(8, EXT4_BLOCK_BYTES, 1).map_err(|_| FsError::Io)?;
        let region = BlockRegion::whole_device(device, BlockAccess::ReadWrite, block_limits)
            .map_err(|_| FsError::Io)?;
        Ext4::mount(region, limits()?)
    }

    fn mount_file(path: &Path) -> Result<Ext4<FileDevice>, String> {
        let device = FileDevice::open(path)?;
        let block_limits = BlockLimits::new(8, EXT4_BLOCK_BYTES, 1)
            .map_err(|error| format!("invalid block limits: {error:?}"))?;
        let region = BlockRegion::whole_device(device, BlockAccess::ReadOnly, block_limits)
            .map_err(|error| format!("cannot grant image region: {error:?}"))?;
        Ext4::mount(region, limits().map_err(|error| error.to_string())?)
            .map_err(|error| error.to_string())
    }

    fn mount_file_writable(path: &Path) -> Result<Ext4<FileDevice>, String> {
        let device = FileDevice::open_writable(path)?;
        let block_limits = BlockLimits::new(8, EXT4_BLOCK_BYTES, 1)
            .map_err(|error| format!("invalid block limits: {error:?}"))?;
        let region = BlockRegion::whole_device(device, BlockAccess::ReadWrite, block_limits)
            .map_err(|error| format!("cannot grant writable image region: {error:?}"))?;
        Ext4::mount(region, limits().map_err(|error| error.to_string())?)
            .map_err(|error| error.to_string())
    }

    fn e2fs_tool(name: &str) -> Option<PathBuf> {
        for prefix in [
            "/opt/homebrew/opt/e2fsprogs/sbin",
            "/usr/local/opt/e2fsprogs/sbin",
            "/home/linuxbrew/.linuxbrew/opt/e2fsprogs/sbin",
        ] {
            let candidate = Path::new(prefix).join(name);
            if candidate.is_file() {
                return Some(candidate);
            }
        }
        Command::new(name)
            .arg("-V")
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
                "ext4 interoperability test requires unavailable tool {name}"
            ))
        } else {
            std::eprintln!("ext4 interoperability test skipped: {name} is unavailable");
            Ok(())
        }
    }

    fn valid_device() -> SparseDevice {
        let seed = crc32c(u32::MAX, &UUID);
        let mut blocks = BTreeMap::new();

        let mut block_zero = [0_u8; EXT4_BLOCK_BYTES];
        let superblock = &mut block_zero[1024..2048];
        put_u32(superblock, 0, 16);
        put_u32(superblock, 4, FS_BLOCKS);
        put_u32(superblock, 12, 24);
        put_u32(superblock, 16, 11);
        put_u32(superblock, 20, 0);
        put_u32(superblock, 24, 2);
        put_u32(superblock, 28, 2);
        put_u32(superblock, 32, FS_BLOCKS);
        put_u32(superblock, 36, FS_BLOCKS);
        put_u32(superblock, 40, 16);
        put_u16(superblock, 56, 0xef53);
        put_u16(superblock, 58, 1);
        put_u32(superblock, 76, 1);
        put_u32(superblock, 84, 11);
        put_u16(superblock, 88, 256);
        put_u32(superblock, 92, EXT4_FEATURE_COMPAT);
        put_u32(superblock, 96, EXT4_FEATURE_INCOMPAT);
        put_u32(superblock, 100, EXT4_FEATURE_RO_COMPAT);
        superblock[104..120].copy_from_slice(&UUID);
        put_u32(superblock, 224, 8);
        put_u16(superblock, 254, 32);
        superblock[373] = 1;
        let super_checksum = crc32c(u32::MAX, &superblock[..1020]);
        put_u32(superblock, 1020, super_checksum);
        blocks.insert(0, block_zero);

        let mut block_bitmap = [0xff_u8; EXT4_BLOCK_BYTES];
        block_bitmap[..4].fill(0);
        for block in 0_u32..=7 {
            let bit = usize::try_from(block).unwrap_or_else(|_| unreachable!());
            block_bitmap[bit / 8] |= 1 << (bit % 8);
        }
        let block_bitmap_checksum = crc32c(seed, &block_bitmap[..4]);
        blocks.insert(7, block_bitmap);

        let mut bitmap = [0xff_u8; EXT4_BLOCK_BYTES];
        bitmap[..2].fill(0);
        for inode in [1_u32, EXT4_ROOT_INO, 3, 4, 8] {
            let bit = usize::try_from(inode - 1).unwrap_or_else(|_| unreachable!());
            bitmap[bit / 8] |= 1 << (bit % 8);
        }
        let bitmap_checksum = crc32c(seed, &bitmap[..2]);
        blocks.insert(INODE_BITMAP_BLOCK, bitmap);

        let mut descriptor_block = [0_u8; EXT4_BLOCK_BYTES];
        put_u32(&mut descriptor_block, 0, 7);
        put_u32(&mut descriptor_block, 4, INODE_BITMAP_BLOCK);
        put_u32(&mut descriptor_block, 8, INODE_TABLE_BLOCK);
        put_u16(&mut descriptor_block, 12, 24);
        put_u16(&mut descriptor_block, 14, 11);
        put_u16(&mut descriptor_block, 28, 8);
        put_u16(
            &mut descriptor_block,
            24,
            u16::from_le_bytes([
                block_bitmap_checksum.to_le_bytes()[0],
                block_bitmap_checksum.to_le_bytes()[1],
            ]),
        );
        put_u16(
            &mut descriptor_block,
            26,
            u16::from_le_bytes([
                bitmap_checksum.to_le_bytes()[0],
                bitmap_checksum.to_le_bytes()[1],
            ]),
        );
        let mut checksum_descriptor = [0_u8; 32];
        checksum_descriptor.copy_from_slice(&descriptor_block[..32]);
        let descriptor_checksum = crc32c(crc32c(seed, &0_u32.to_le_bytes()), &checksum_descriptor);
        put_u16(
            &mut descriptor_block,
            30,
            u16::from_le_bytes([
                descriptor_checksum.to_le_bytes()[0],
                descriptor_checksum.to_le_bytes()[1],
            ]),
        );
        blocks.insert(1, descriptor_block);

        blocks.insert(INODE_TABLE_BLOCK, valid_inode_table(seed));

        let mut root = [0_u8; EXT4_BLOCK_BYTES];
        dir_entry(&mut root, 0, EXT4_ROOT_INO, 12, b".", 2);
        dir_entry(&mut root, 12, EXT4_ROOT_INO, 12, b"..", 2);
        dir_entry(&mut root, 24, 3, 16, b"hello", 1);
        dir_entry(&mut root, 40, 4, 4044, b"sub", 2);
        directory_tail(&mut root, EXT4_ROOT_INO, ROOT_GENERATION, seed);
        blocks.insert(ROOT_DIRECTORY_BLOCK, root);

        let mut file = [0_u8; EXT4_BLOCK_BYTES];
        file[..13].copy_from_slice(b"hello, ext4!\n");
        blocks.insert(FILE_BLOCK, file);

        let mut sub = [0_u8; EXT4_BLOCK_BYTES];
        dir_entry(&mut sub, 0, 4, 12, b".", 2);
        dir_entry(&mut sub, 12, EXT4_ROOT_INO, 12, b"..", 2);
        put_u16(&mut sub, 24 + 4, 4060);
        directory_tail(&mut sub, 4, SUB_GENERATION, seed);
        blocks.insert(SUB_DIRECTORY_BLOCK, sub);

        SparseDevice { blocks }
    }

    fn valid_device_with_file_xattr() -> SparseDevice {
        let seed = crc32c(u32::MAX, &UUID);
        let mut device = valid_device();
        let xattr_block = FS_BLOCKS - 1;

        let bitmap = device.blocks.get_mut(&7).unwrap_or_else(|| unreachable!());
        let bit = usize::try_from(xattr_block).unwrap_or_else(|_| unreachable!());
        bitmap[bit / 8] |= 1 << (bit % 8);
        let bitmap_checksum = crc32c(seed, &bitmap[..4]);

        let descriptor = device.blocks.get_mut(&1).unwrap_or_else(|| unreachable!());
        put_u16(descriptor, 12, 23);
        put_u16(
            descriptor,
            24,
            u16::from_le_bytes([
                bitmap_checksum.to_le_bytes()[0],
                bitmap_checksum.to_le_bytes()[1],
            ]),
        );
        descriptor[30..32].fill(0);
        let descriptor_checksum = crc32c(crc32c(seed, &0_u32.to_le_bytes()), &descriptor[..32]);
        put_u16(
            descriptor,
            30,
            u16::from_le_bytes([
                descriptor_checksum.to_le_bytes()[0],
                descriptor_checksum.to_le_bytes()[1],
            ]),
        );

        let superblock =
            &mut device.blocks.get_mut(&0).unwrap_or_else(|| unreachable!())[1024..2048];
        put_u32(superblock, 12, 23);
        let super_checksum = crc32c(u32::MAX, &superblock[..1020]);
        put_u32(superblock, 1020, super_checksum);

        let raw = &mut device
            .blocks
            .get_mut(&INODE_TABLE_BLOCK)
            .unwrap_or_else(|| unreachable!())[512..768];
        put_u32(raw, 28, 2 * (EXT4_BLOCK_BYTES_U32 / 512));
        put_u32(raw, 104, xattr_block);
        refresh_test_inode_checksum(raw, 3, FILE_GENERATION, seed);

        let mut xattr = [0_u8; EXT4_BLOCK_BYTES];
        xattr[..20].copy_from_slice(b"opaque-xattr-payload");
        device.blocks.insert(xattr_block, xattr);
        device
    }

    fn valid_device_with_file_hard_link() -> SparseDevice {
        let seed = crc32c(u32::MAX, &UUID);
        let mut device = valid_device();
        let root = device
            .blocks
            .get_mut(&ROOT_DIRECTORY_BLOCK)
            .unwrap_or_else(|| unreachable!());
        put_u16(root, 40 + 4, 12);
        dir_entry(root, 52, 3, 4032, b"alias", 1);
        directory_tail(root, EXT4_ROOT_INO, ROOT_GENERATION, seed);

        let raw = &mut device
            .blocks
            .get_mut(&INODE_TABLE_BLOCK)
            .unwrap_or_else(|| unreachable!())[512..768];
        put_u16(raw, 26, 2);
        refresh_test_inode_checksum(raw, 3, FILE_GENERATION, seed);
        device
    }

    fn valid_inode_table(seed: u32) -> [u8; EXT4_BLOCK_BYTES] {
        let mut inode_table = [0_u8; EXT4_BLOCK_BYTES];
        inode(
            &mut inode_table[256..512],
            EXT4_ROOT_INO,
            ROOT_GENERATION,
            0x4000 | 0o700,
            EXT4_BLOCK_BYTES as u64,
            Some((0, ROOT_DIRECTORY_BLOCK, 1)),
            seed,
        );
        inode(
            &mut inode_table[512..768],
            3,
            FILE_GENERATION,
            0x8000 | 0o777,
            4101,
            Some((0, FILE_BLOCK, 1)),
            seed,
        );
        inode(
            &mut inode_table[768..1024],
            4,
            SUB_GENERATION,
            0x4000 | 0o700,
            EXT4_BLOCK_BYTES as u64,
            Some((0, SUB_DIRECTORY_BLOCK, 1)),
            seed,
        );
        inode_table
    }

    fn inode(
        raw: &mut [u8],
        number: u32,
        generation: u32,
        mode: u16,
        size: u64,
        extent: Option<(u32, u32, u16)>,
        seed: u32,
    ) {
        raw.fill(0);
        put_u16(raw, 0, mode);
        put_u16(raw, 2, 42);
        put_u16(raw, 24, 43);
        let size_bytes = size.to_le_bytes();
        put_u32(
            raw,
            4,
            u32::from_le_bytes([size_bytes[0], size_bytes[1], size_bytes[2], size_bytes[3]]),
        );
        put_u16(raw, 26, 1);
        put_u32(
            raw,
            28,
            u32::from(extent.map_or(0, |(_, _, count)| count)) * (EXT4_BLOCK_BYTES_U32 / 512),
        );
        put_u32(raw, 32, EXT4_EXTENTS_FL);
        put_u32(raw, 100, generation);
        put_u32(
            raw,
            108,
            u32::from_le_bytes([size_bytes[4], size_bytes[5], size_bytes[6], size_bytes[7]]),
        );
        put_u16(raw, 128, 32);
        put_u16(raw, 40, 0xf30a);
        put_u16(raw, 42, u16::from(extent.is_some()));
        put_u16(raw, 44, 4);
        if let Some((logical, physical, count)) = extent {
            put_u32(raw, 52, logical);
            put_u16(raw, 56, count);
            put_u32(raw, 60, physical);
        }
        refresh_test_inode_checksum(raw, number, generation, seed);
    }

    fn refresh_test_inode_checksum(raw: &mut [u8], number: u32, generation: u32, seed: u32) {
        raw[124..126].fill(0);
        raw[130..132].fill(0);
        let checksum = crc32c(
            crc32c(
                crc32c(seed, &number.to_le_bytes()),
                &generation.to_le_bytes(),
            ),
            raw,
        );
        put_u16(
            raw,
            124,
            u16::from_le_bytes([checksum.to_le_bytes()[0], checksum.to_le_bytes()[1]]),
        );
        put_u16(
            raw,
            130,
            u16::from_le_bytes([checksum.to_le_bytes()[2], checksum.to_le_bytes()[3]]),
        );
    }

    fn dir_entry(
        block: &mut [u8],
        offset: usize,
        inode: u32,
        record_bytes: u16,
        name: &[u8],
        file_type: u8,
    ) {
        put_u32(block, offset, inode);
        put_u16(block, offset + 4, record_bytes);
        block[offset + 6] = u8::try_from(name.len()).unwrap_or_else(|_| unreachable!());
        block[offset + 7] = file_type;
        block[offset + 8..offset + 8 + name.len()].copy_from_slice(name);
    }

    fn directory_tail(block: &mut [u8], inode: u32, generation: u32, seed: u32) {
        let offset = EXT4_BLOCK_BYTES - 12;
        put_u16(block, offset + 4, 12);
        block[offset + 7] = 0xde;
        let inode_seed = crc32c(
            crc32c(seed, &inode.to_le_bytes()),
            &generation.to_le_bytes(),
        );
        let checksum = crc32c(inode_seed, &block[..offset]);
        put_u32(block, offset + 8, checksum);
    }

    fn put_u16(bytes: &mut [u8], offset: usize, value: u16) {
        bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
    }

    fn put_u32(bytes: &mut [u8], offset: usize, value: u32) {
        bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }

    fn refresh_super_checksum(device: &mut SparseDevice) {
        let block = device.blocks.get_mut(&0).unwrap_or_else(|| unreachable!());
        let superblock = &mut block[1024..2048];
        let checksum = crc32c(u32::MAX, &superblock[..1020]);
        put_u32(superblock, 1020, checksum);
    }

    #[test]
    fn mounts_lists_resolves_and_reads_files_and_holes() -> Result<(), FsError> {
        let mut ext4 = mount(valid_device())?;
        assert_eq!(ext4.uuid().bytes(), UUID);
        assert_eq!(ext4.metadata("/hello")?.byte_count, 4101);
        assert_eq!(ext4.metadata("/sub")?.kind, NodeKind::Directory);
        let listing = ext4.list("/", 0, 1, 64)?;
        assert_eq!(listing.entries[0].name, "hello");
        assert_eq!(listing.next_cursor, Some(1));
        let mut beginning = [0_u8; 13];
        assert_eq!(ext4.read_file("/hello", 0, &mut beginning)?, 13);
        assert_eq!(&beginning, b"hello, ext4!\n");
        let mut boundary = [0xff_u8; 7];
        assert_eq!(ext4.read_file("/hello", 4094, &mut boundary)?, 7);
        assert_eq!(boundary, [0, 0, 0, 0, 0, 0, 0]);
        Ok(())
    }

    #[test]
    fn every_consumed_metadata_checksum_fails_closed() -> Result<(), FsError> {
        let mut superblock = valid_device();
        superblock.blocks.get_mut(&0).ok_or(FsError::Io)?[1024 + 48] ^= 1;
        assert!(matches!(mount(superblock), Err(FsError::Corrupt)));

        let mut descriptor = valid_device();
        descriptor.blocks.get_mut(&1).ok_or(FsError::Io)?[12] ^= 1;
        assert!(matches!(mount(descriptor), Err(FsError::Corrupt)));

        let mut bitmap = valid_device();
        bitmap
            .blocks
            .get_mut(&INODE_BITMAP_BLOCK)
            .ok_or(FsError::Io)?[0] ^= 0x40;
        assert!(matches!(mount(bitmap), Err(FsError::Corrupt)));

        let mut inode = valid_device();
        inode
            .blocks
            .get_mut(&INODE_TABLE_BLOCK)
            .ok_or(FsError::Io)?[256 + 8] ^= 1;
        assert!(matches!(mount(inode), Err(FsError::Corrupt)));

        let mut directory = valid_device();
        directory
            .blocks
            .get_mut(&ROOT_DIRECTORY_BLOCK)
            .ok_or(FsError::Io)?[100] ^= 1;
        assert!(matches!(mount(directory), Err(FsError::Corrupt)));
        Ok(())
    }

    #[test]
    fn dirty_unknown_features_and_extent_trees_are_rejected() -> Result<(), FsError> {
        let mut dirty = valid_device();
        put_u16(
            &mut dirty.blocks.get_mut(&0).ok_or(FsError::Io)?[1024..2048],
            58,
            0,
        );
        refresh_super_checksum(&mut dirty);
        assert!(matches!(mount(dirty), Err(FsError::Corrupt)));

        let mut feature = valid_device();
        let superblock = &mut feature.blocks.get_mut(&0).ok_or(FsError::Io)?[1024..2048];
        put_u32(superblock, 96, EXT4_FEATURE_INCOMPAT | 0x80);
        refresh_super_checksum(&mut feature);
        assert!(matches!(mount(feature), Err(FsError::Unsupported)));

        let mut tree = valid_device();
        put_u16(
            &mut tree.blocks.get_mut(&INODE_TABLE_BLOCK).ok_or(FsError::Io)?[256..512],
            46,
            1,
        );
        assert!(matches!(mount(tree), Err(FsError::Corrupt)));
        Ok(())
    }

    #[test]
    fn operation_and_mount_budgets_are_hard() -> Result<(), FsError> {
        assert_eq!(Ext4Limits::new(0, 1, 1, 1, 1, 1, 1), Err(FsError::Invalid));
        let mut ext4 = mount(valid_device())?;
        let mut oversized = vec![0_u8; 4097];
        assert_eq!(
            ext4.read_file("/hello", 0, &mut oversized),
            Err(FsError::NoSpace)
        );
        let page = ext4.list("/", 0, 0, 0)?;
        assert!(page.entries.is_empty());
        assert_eq!(page.next_cursor, Some(0));
        assert_eq!(ext4.list("/", 99, 1, 64), Err(FsError::Invalid));
        assert_eq!(CRC32C_POLYNOMIAL, 0x82f6_3b78);
        Ok(())
    }

    #[test]
    fn replaces_content_without_changing_existing_inode_metadata() -> Result<(), FsError> {
        let mut ext4 = mount_writable(valid_device_with_file_xattr())?;
        let before_block = ext4.read_fs_block(INODE_TABLE_BLOCK)?;
        let mut before = before_block[512..768].to_vec();
        let replacement = vec![b'x'; 5000];
        ext4.write_file("/hello", &replacement)?;
        let after_block = ext4.read_fs_block(INODE_TABLE_BLOCK)?;
        let mut after = after_block[512..768].to_vec();
        for range in [
            4..8,
            28..32,
            40..100,
            108..112,
            116..118,
            124..126,
            130..132,
        ] {
            before[range.clone()].fill(0);
            after[range].fill(0);
        }
        assert_eq!(before, after);
        assert_eq!(
            u16::from_le_bytes(
                after_block[512..514]
                    .try_into()
                    .map_err(|_| FsError::Corrupt)?
            ),
            0x8000 | 0o777
        );
        assert_eq!(
            u16::from_le_bytes(
                after_block[514..516]
                    .try_into()
                    .map_err(|_| FsError::Corrupt)?
            ),
            42
        );
        assert_eq!(
            u16::from_le_bytes(
                after_block[536..538]
                    .try_into()
                    .map_err(|_| FsError::Corrupt)?
            ),
            43
        );
        assert_eq!(read_u32(&after_block[512..768], 104)?, FS_BLOCKS - 1);
        assert_eq!(
            Ext4::<SparseDevice>::inode_sector_count(&after_block[512..768])?,
            24
        );
        let mut read_back = vec![0_u8; 5000];
        assert_eq!(ext4.read_file("/hello", 0, &mut read_back[..4096])?, 4096);
        assert_eq!(ext4.read_file("/hello", 4096, &mut read_back[4096..])?, 904);
        assert_eq!(read_back, replacement);
        Ok(())
    }

    #[test]
    fn creates_and_removes_files_with_safe_defaults() -> Result<(), FsError> {
        let mut ext4 = mount_writable(valid_device())?;
        ext4.write_file("/created.txt", b"created")?;
        let created = ext4.resolve("/created.txt")?;
        let (block, offset) = ext4.inode_record_location(created.number)?;
        let raw = ext4.read_fs_block(block)?;
        let inode = &raw[offset..offset + EXT4_INODE_BYTES];
        assert_eq!(read_u16(inode, 0)?, 0x8000 | 0o600);
        assert_eq!(read_u16(inode, 2)?, 1000);
        assert_eq!(read_u16(inode, 24)?, 1000);
        assert_eq!(ext4.metadata("/created.txt")?.byte_count, 7);
        ext4.remove_file("/created.txt")?;
        assert_eq!(ext4.metadata("/created.txt"), Err(FsError::NotFound));
        ext4.write_file("/empty", b"")?;
        assert_eq!(ext4.metadata("/empty")?.byte_count, 0);
        ext4.create_directory("/archive")?;
        assert_eq!(ext4.metadata("/archive")?.kind, NodeKind::Directory);
        ext4.write_file("/archive/member", b"nested")?;
        assert_eq!(ext4.metadata("/archive/member")?.byte_count, 6);
        assert_eq!(ext4.create_directory("/archive"), Err(FsError::Exists));
        Ok(())
    }

    #[test]
    fn final_unlink_with_external_xattrs_fails_without_mutation() -> Result<(), FsError> {
        let mut ext4 = mount_writable(valid_device_with_file_xattr())?;
        assert_eq!(ext4.remove_file("/hello"), Err(FsError::Unsupported));
        assert_eq!(ext4.metadata("/hello")?.byte_count, 4101);
        let superblock = ext4.read_fs_block(0)?;
        assert_ne!(read_u16(&superblock[1024..2048], 58)? & EXT4_VALID_FS, 0);
        Ok(())
    }

    #[test]
    fn removing_one_hard_link_preserves_the_inode_and_other_name() -> Result<(), FsError> {
        let mut ext4 = mount_writable(valid_device_with_file_hard_link())?;
        ext4.remove_file("/alias")?;
        assert_eq!(ext4.metadata("/alias"), Err(FsError::NotFound));
        assert_eq!(ext4.metadata("/hello")?.byte_count, 4101);
        let raw = ext4.raw_inode_record(3)?;
        assert_eq!(read_u16(&raw, 26)?, 1);
        let mut content = [0_u8; 13];
        assert_eq!(ext4.read_file("/hello", 0, &mut content)?, content.len());
        assert_eq!(&content, b"hello, ext4!\n");
        Ok(())
    }

    #[test]
    fn creates_follows_writes_and_unlinks_hard_and_symbolic_links() -> Result<(), FsError> {
        let mut ext4 = mount_writable(valid_device())?;
        ext4.create_hard_link("/hello", "/alias")?;
        let linked = ext4.raw_inode_record(3)?;
        assert_eq!(read_u16(&linked, 26)?, 2);

        ext4.create_symlink("/alias", "/fast-link")?;
        assert_eq!(ext4.read_link("/fast-link")?, "/alias");
        assert_eq!(ext4.metadata("/fast-link")?.kind, NodeKind::File);
        assert!(
            ext4.list("/", 0, 32, 512)?
                .entries
                .iter()
                .any(|entry| entry.name == "fast-link" && entry.kind == NodeKind::Symlink)
        );

        ext4.create_symlink("../hello", "/sub/relative")?;
        let mut original = [0_u8; 13];
        assert_eq!(
            ext4.read_file("/sub/relative", 0, &mut original)?,
            original.len()
        );
        assert_eq!(&original, b"hello, ext4!\n");

        let long_target = "/sub/../sub/../sub/../sub/../sub/../sub/../sub/../sub/../hello";
        assert!(long_target.len() > EXT4_FAST_SYMLINK_BYTES);
        ext4.create_symlink(long_target, "/slow-link")?;
        assert_eq!(ext4.read_link("/slow-link")?, long_target);
        assert!(!ext4.resolve_no_follow("/slow-link")?.extents.is_empty());

        ext4.write_file("/fast-link", b"linked write\n")?;
        let mut updated = [0_u8; 13];
        assert_eq!(ext4.read_file("/hello", 0, &mut updated)?, updated.len());
        assert_eq!(&updated, b"linked write\n");
        assert_eq!(ext4.read_file("/alias", 0, &mut updated)?, updated.len());

        ext4.remove_file("/fast-link")?;
        assert_eq!(ext4.read_link("/fast-link"), Err(FsError::NotFound));
        ext4.remove_file("/alias")?;
        assert_eq!(ext4.metadata("/hello")?.byte_count, 13);
        assert_eq!(read_u16(&ext4.raw_inode_record(3)?, 26)?, 1);

        ext4.create_symlink("/cycle-b", "/cycle-a")?;
        ext4.create_symlink("/cycle-a", "/cycle-b")?;
        assert_eq!(ext4.metadata("/cycle-a"), Err(FsError::NoSpace));
        Ok(())
    }

    #[test]
    fn read_only_capability_rejects_mutation() -> Result<(), FsError> {
        let mut ext4 = mount(valid_device())?;
        assert_eq!(ext4.write_file("/new", b"data"), Err(FsError::ReadOnly));
        assert_eq!(ext4.remove_file("/hello"), Err(FsError::ReadOnly));
        assert_eq!(
            ext4.create_symlink("/hello", "/link"),
            Err(FsError::ReadOnly)
        );
        assert_eq!(
            ext4.create_hard_link("/hello", "/hard"),
            Err(FsError::ReadOnly)
        );
        Ok(())
    }

    #[test]
    fn mutation_dirty_marker_brackets_durable_changes() -> Result<(), FsError> {
        let mut ext4 = mount_writable(valid_device())?;
        ext4.begin_mutation()?;
        let dirty = ext4.read_fs_block(0)?;
        assert_eq!(read_u16(&dirty[1024..2048], 58)? & super::EXT4_VALID_FS, 0);
        ext4.finish_mutation()?;
        let clean = ext4.read_fs_block(0)?;
        assert_ne!(read_u16(&clean[1024..2048], 58)? & super::EXT4_VALID_FS, 0);
        Ok(())
    }

    fn verify_writer_interoperability(image: &Path, e2fsck: &Path) -> Result<(), String> {
        let mut writable = mount_file_writable(image)?;
        writable
            .create_hard_link("/config.txt", "/config-hard")
            .map_err(|error| error.to_string())?;
        writable
            .create_symlink("/config.txt", "/config-link")
            .map_err(|error| error.to_string())?;
        writable
            .create_symlink(
                "/nested/../nested/../nested/../nested/../nested/../nested/../config.txt",
                "/config-slow-link",
            )
            .map_err(|error| error.to_string())?;
        writable
            .write_file("/config-link", b"profile=modified\n")
            .map_err(|error| error.to_string())?;
        writable
            .write_file("/created.txt", b"created by troe\n")
            .map_err(|error| error.to_string())?;
        writable
            .create_directory("/archive")
            .map_err(|error| error.to_string())?;
        writable
            .write_file("/archive/member.txt", b"member\n")
            .map_err(|error| error.to_string())?;
        writable
            .remove_file("/nested/message.txt")
            .map_err(|error| error.to_string())?;
        drop(writable);
        let post_write_check = Command::new(e2fsck)
            .args(["-fn"])
            .arg(image)
            .output()
            .map_err(|error| error.to_string())?;
        command_succeeded(&post_write_check, "e2fsck after TROE writes")?;

        let mut remounted = mount_file(image)?;
        for path in ["/config.txt", "/config-hard", "/config-slow-link"] {
            let mut content = [0_u8; 17];
            let count = remounted
                .read_file(path, 0, &mut content)
                .map_err(|error| error.to_string())?;
            assert_eq!(&content[..count], b"profile=modified\n");
        }
        assert_eq!(
            remounted
                .read_link("/config-link")
                .map_err(|error| error.to_string())?,
            "/config.txt"
        );
        assert_eq!(
            remounted
                .metadata("/archive")
                .map_err(|error| error.to_string())?
                .kind,
            NodeKind::Directory
        );
        assert_eq!(
            remounted
                .metadata("/archive/member.txt")
                .map_err(|error| error.to_string())?
                .byte_count,
            7
        );
        assert!(matches!(
            remounted.metadata("/nested/message.txt"),
            Err(FsError::NotFound)
        ));
        Ok(())
    }

    #[test]
    fn mounts_image_created_and_checked_by_e2fsprogs() -> Result<(), String> {
        let Some(mke2fs) = e2fs_tool("mke2fs") else {
            return unavailable_tool("mke2fs");
        };
        let Some(e2fsck) = e2fs_tool("e2fsck") else {
            return unavailable_tool("e2fsck");
        };
        let temporary = TestDirectory::create("ext4-real")?;
        let source = temporary.path().join("source");
        let nested = source.join("nested");
        fs::create_dir_all(&nested).map_err(|error| error.to_string())?;
        fs::write(source.join("config.txt"), b"profile=real-ext4\n")
            .map_err(|error| error.to_string())?;
        fs::write(nested.join("message.txt"), b"hello from e2fsprogs\n")
            .map_err(|error| error.to_string())?;
        #[cfg(unix)]
        std::os::unix::fs::symlink("../config.txt", nested.join("config-link"))
            .map_err(|error| error.to_string())?;
        let image = temporary.path().join("filesystem.ext4");
        File::create(&image)
            .and_then(|file| file.set_len(64 * 1024 * 1024))
            .map_err(|error| error.to_string())?;
        let format = Command::new(mke2fs)
            .args([
                "-q",
                "-F",
                "-t",
                "ext4",
                "-b",
                "4096",
                "-I",
                "256",
                "-O",
                "none,has_journal,ext_attr,extent,filetype,sparse_super,large_file,extra_isize,metadata_csum",
                "-E",
                "lazy_itable_init=0,lazy_journal_init=0",
                "-d",
            ])
            .arg(&source)
            .arg(&image)
            .output()
            .map_err(|error| error.to_string())?;
        command_succeeded(&format, "mke2fs")?;
        let check = Command::new(&e2fsck)
            .args(["-fn"])
            .arg(&image)
            .output()
            .map_err(|error| error.to_string())?;
        command_succeeded(&check, "e2fsck")?;

        let mut ext4 = mount_file(&image)?;
        let root = ext4
            .list("/", 0, 32, 512)
            .map_err(|error| error.to_string())?;
        assert!(root.entries.iter().any(|entry| entry.name == "config.txt"));
        assert!(root.entries.iter().any(|entry| entry.name == "nested"));
        let mut config = [0_u8; 18];
        let count = ext4
            .read_file("/config.txt", 0, &mut config)
            .map_err(|error| error.to_string())?;
        assert_eq!(&config[..count], b"profile=real-ext4\n");
        let mut message = [0_u8; 22];
        let count = ext4
            .read_file("/nested/message.txt", 0, &mut message)
            .map_err(|error| error.to_string())?;
        assert_eq!(&message[..count], b"hello from e2fsprogs\n");
        #[cfg(unix)]
        assert_eq!(
            ext4.read_link("/nested/config-link")
                .map_err(|error| error.to_string())?,
            "../config.txt"
        );

        drop(ext4);
        verify_writer_interoperability(&image, &e2fsck)
    }
}
