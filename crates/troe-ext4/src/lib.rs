//! Strict, bounded read-only ext4 profile v1 provider.
#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;
#[cfg(test)]
extern crate std;

use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::{fmt, str};
use troe_block::{BlockDevice, BlockRegion};
use troe_vfs::{
    DirEntry, FileMetadata, FsError, MAX_NAME_BYTES, NodeKind, ProviderListing, ReadOnlyFileSystem,
    canonicalize,
};

const EXT4_MAGIC: u16 = 0xef53;
const EXT4_DYNAMIC_REV: u32 = 1;
const EXT4_VALID_FS: u16 = 1;
const EXT4_ERROR_FS: u16 = 2;
const EXT4_BLOCK_BYTES: usize = 4096;
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
    inodes_per_group: u32,
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
    pub fn mount(mut region: BlockRegion<D>, limits: Ext4Limits) -> Result<Self, FsError> {
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

    fn resolve(&mut self, path: &str) -> Result<Inode, FsError> {
        let normalized = canonicalize("/", path)?;
        if normalized != path || !path.starts_with('/') {
            return Err(FsError::Invalid);
        }
        let mut current = self.read_inode(EXT4_ROOT_INO)?;
        let mut consumed = 1_u32;
        if normalized == "/" {
            return Ok(current);
        }
        for component in normalized.trim_start_matches('/').split('/') {
            if current.kind != NodeKind::Directory {
                return Err(FsError::WrongType);
            }
            let entries = self.read_directory(&current)?;
            let mut matched = None;
            for entry in entries {
                if entry.name == component && matched.replace(entry).is_some() {
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
        }
        Ok(current)
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
            match map_block(&inode, logical)? {
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
        inodes_per_group,
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
        _ => return Err(FsError::Unsupported),
    };
    if read_u16(raw, 26)? == 0 || read_u32(raw, 32)? & EXT4_EXTENTS_FL == 0 {
        return Err(FsError::Corrupt);
    }
    let size = u64::from(read_u32(raw, 4)?) | (u64::from(read_u32(raw, 108)?) << 32);
    if kind == NodeKind::File && size > limits.max_file_bytes() {
        return Err(FsError::NoSpace);
    }
    let extents = parse_extents(raw.get(40..100).ok_or(FsError::Corrupt)?, layout.blocks)?;
    let file_blocks = size
        .checked_add(EXT4_BLOCK_BYTES_U64 - 1)
        .ok_or(FsError::Overflow)?
        / EXT4_BLOCK_BYTES_U64;
    for extent in &extents {
        let end = u64::from(extent.logical) + u64::from(extent.blocks);
        if end > file_blocks || (kind == NodeKind::Directory && extent.unwritten) {
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
    use std::fs::{self, File};
    use std::io::{Read, Seek, SeekFrom};
    use std::path::{Path, PathBuf};
    use std::process::{Command, Output};
    use std::time::{SystemTime, UNIX_EPOCH};
    use troe_block::{BlockAccess, BlockError, BlockGeometry, BlockLimits};

    use super::{
        BlockDevice, BlockRegion, CRC32C_POLYNOMIAL, EXT4_BLOCK_BYTES, EXT4_EXTENTS_FL,
        EXT4_FEATURE_COMPAT, EXT4_FEATURE_INCOMPAT, EXT4_FEATURE_RO_COMPAT, EXT4_ROOT_INO, Ext4,
        Ext4Limits, FsError, NodeKind, ReadOnlyFileSystem, crc32c,
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
            BlockGeometry::new(DEVICE_BLOCK_BYTES_U32, DEVICE_BLOCKS, 1, false, false)
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

    fn mount_file(path: &Path) -> Result<Ext4<FileDevice>, String> {
        let device = FileDevice::open(path)?;
        let block_limits = BlockLimits::new(8, EXT4_BLOCK_BYTES, 1)
            .map_err(|error| format!("invalid block limits: {error:?}"))?;
        let region = BlockRegion::whole_device(device, BlockAccess::ReadOnly, block_limits)
            .map_err(|error| format!("cannot grant image region: {error:?}"))?;
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

        let mut bitmap = [0_u8; EXT4_BLOCK_BYTES];
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

    fn valid_inode_table(seed: u32) -> [u8; EXT4_BLOCK_BYTES] {
        let mut inode_table = [0_u8; EXT4_BLOCK_BYTES];
        inode(
            &mut inode_table[256..512],
            EXT4_ROOT_INO,
            ROOT_GENERATION,
            0x4000,
            EXT4_BLOCK_BYTES as u64,
            Some((0, ROOT_DIRECTORY_BLOCK, 1)),
            seed,
        );
        inode(
            &mut inode_table[512..768],
            3,
            FILE_GENERATION,
            0x8000,
            4101,
            Some((0, FILE_BLOCK, 1)),
            seed,
        );
        inode(
            &mut inode_table[768..1024],
            4,
            SUB_GENERATION,
            0x4000,
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
        put_u16(raw, 0, mode | 0o600);
        let size_bytes = size.to_le_bytes();
        put_u32(
            raw,
            4,
            u32::from_le_bytes([size_bytes[0], size_bytes[1], size_bytes[2], size_bytes[3]]),
        );
        put_u16(raw, 26, 1);
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
        let check = Command::new(e2fsck)
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
        Ok(())
    }
}
