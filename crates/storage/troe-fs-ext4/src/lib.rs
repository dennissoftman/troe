//! Strict, bounded ext4 profile v1 provider with metadata-preserving file mutation.
#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;
#[cfg(test)]
extern crate std;

mod htree;
mod journal;

use alloc::rc::Rc;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::{fmt, str};
use troe_block::{BlockAccess, BlockDevice, BlockError, BlockRegion};
use troe_fs_api::{
    DirEntry, FileMetadata, FileSystemProvider, FsError, MAX_NAME_BYTES, MAX_PATH_BYTES, NodeKind,
    ProviderListing, WallClock, canonicalize,
};

const EXT4_MAGIC: u16 = 0xef53;
const EXT4_DYNAMIC_REV: u32 = 1;
const EXT4_VALID_FS: u16 = 1;
const EXT4_ERROR_FS: u16 = 2;
/// Largest filesystem block this provider reads or writes.
const EXT4_MAX_BLOCK_BYTES: usize = 4096;
/// Smallest filesystem block ext4 defines.
const EXT4_MIN_BLOCK_BYTES: usize = 1024;
#[cfg(test)]
const EXT4_BLOCK_BYTES: usize = 4096;
#[cfg(test)]
const EXT4_BLOCK_BYTES_U32: u32 = 4096;
#[cfg(test)]
const EXT4_BLOCK_BYTES_U64: u64 = 4096;
const EXT4_INODE_BYTES: usize = 256;
const EXT4_INODE_BYTES_U16: u16 = 256;
const EXT4_GROUP_DESC_BYTES: usize = 32;
const EXT4_GROUP_DESC_BYTES_U16: u16 = 32;
/// Largest group descriptor this provider reads or writes.
const EXT4_GROUP_DESC_MAX: usize = 64;
/// Superblock offset of the checksum seed used when `metadata_csum_seed` is set.
const EXT4_SUPER_CHECKSUM_SEED: usize = 0x270;
const EXT4_BITMAP_BITS: u32 = 32_768;
const EXT4_ROOT_INO: u32 = 2;
const EXT4_EXTENTS_FL: u32 = 0x0008_0000;
/// Set on a directory whose entries are described by a hashed index.
const EXT4_INDEX_FL: u32 = 0x0000_1000;
/// Group flag: the inode table and bitmap were never initialized.
const EXT4_BG_INODE_UNINIT: u16 = 0x0001;
/// Group flag: the block bitmap was never initialized.
const EXT4_BG_BLOCK_UNINIT: u16 = 0x0002;
/// Group descriptor offset of the flag word.
const EXT4_BG_FLAGS_OFFSET: usize = 18;
/// Group descriptor offsets of the block bitmap checksum halves.
const EXT4_BG_BLOCK_CSUM_LO: usize = 24;
const EXT4_BG_BLOCK_CSUM_HI: usize = 56;
/// Group descriptor offsets of the inode bitmap checksum halves.
const EXT4_BG_INODE_CSUM_LO: usize = 26;
const EXT4_BG_INODE_CSUM_HI: usize = 58;
const EXT4_EXT_MAGIC: u16 = 0xf30a;
const EXT4_INLINE_EXTENTS: usize = 4;
const EXT4_EXTENT_HEADER_BYTES: usize = 12;
const EXT4_EXTENT_RECORD_BYTES: usize = 12;
const EXT4_EXTENT_TAIL_BYTES: usize = 4;
/// Extents one leaf block can hold at the given block size.
const fn leaf_extents(block_bytes: usize) -> usize {
    (block_bytes - EXT4_EXTENT_HEADER_BYTES - EXT4_EXTENT_TAIL_BYTES) / EXT4_EXTENT_RECORD_BYTES
}

/// Offset of the checksum tail inside one extent leaf block.
const fn extent_tail_offset(block_bytes: usize) -> usize {
    EXT4_EXTENT_HEADER_BYTES + leaf_extents(block_bytes) * EXT4_EXTENT_RECORD_BYTES
}

/// Index entries one interior node holds at the given block size.
///
/// An index record and an extent record are both twelve bytes behind the same
/// header and checksum tail, so a node and a leaf hold the same number.
const fn node_entries(block_bytes: usize) -> usize {
    leaf_extents(block_bytes)
}

/// Largest extent count a tree this provider can both write and walk back.
///
/// Each level below the inode multiplies the block count by one node's
/// capacity. The ceiling is not the depth ext4 permits but the per-level tree
/// block bound the read path enforces, because a tree the reader would refuse
/// must never be written.
const fn max_tree_extents(block_bytes: usize) -> usize {
    let per_node = node_entries(block_bytes);
    let mut leaves = EXT4_ROOT_INDEXES;
    let mut depth = 1_u16;
    while depth < EXT4_MAX_EXTENT_DEPTH {
        let deeper = leaves * per_node;
        if deeper > EXT4_MAX_EXTENT_TREE_BLOCKS {
            break;
        }
        leaves = deeper;
        depth += 1;
    }
    leaves * leaf_extents(block_bytes)
}

#[cfg(test)]
const EXT4_LEAF_EXTENTS: usize = leaf_extents(EXT4_BLOCK_BYTES);
#[cfg(test)]
const EXT4_EXTENT_TAIL_OFFSET: usize =
    EXT4_EXTENT_HEADER_BYTES + EXT4_LEAF_EXTENTS * EXT4_EXTENT_RECORD_BYTES;
const EXT4_ROOT_INDEXES: usize = 4;
/// Deepest extent tree this provider walks; ext4 itself never exceeds five.
const EXT4_MAX_EXTENT_DEPTH: u16 = 5;
/// Hard ceiling on interior blocks one extent tree may occupy.
const EXT4_MAX_EXTENT_TREE_BLOCKS: usize = 2048;
/// Inode offsets of each timestamp: the 32-bit base field and the extra word
/// whose low two bits extend it past 2038.
const EXT4_ATIME: (usize, usize) = (8, 140);
const EXT4_CTIME: (usize, usize) = (12, 132);
const EXT4_MTIME: (usize, usize) = (16, 136);
const EXT4_CRTIME: (usize, usize) = (144, 148);
/// Inode offset of the extra-field size, which says how far the record's
/// declared fields reach beyond the original 128-byte inode.
const EXT4_EXTRA_ISIZE_OFFSET: usize = 128;
/// Bytes of the inode record every ext4 revision defines.
const EXT4_BASE_INODE_BYTES: usize = 128;
/// Extra bytes this provider declares on an inode it creates, covering every
/// timestamp field including the creation time and its epoch bits.
const EXT4_EXTRA_ISIZE: u16 = 32;
/// Latest instant a bare 32-bit timestamp field encodes, because ext4 reads it
/// as signed when the record declares no epoch bits: 2038-01-19T03:14:07Z.
const EXT4_MAX_BASE_SECONDS: u64 = i32::MAX as u64;
/// Latest instant the 32-bit field plus two epoch bits encodes, 2446-05-10.
const EXT4_MAX_EXTENDED_SECONDS: u64 = 0x3_ffff_ffff;
const EXT4_FT_REG_FILE: u8 = 1;
const EXT4_FT_DIR: u8 = 2;
const EXT4_FT_SYMLINK: u8 = 7;
const EXT4_FAST_SYMLINK_BYTES: usize = 60;
const MAX_SYMLINK_EXPANSIONS: u8 = 8;
/// Offset of the `..` record inside a hashed directory's root block, after the
/// fixed 12-byte `.` record.
const EXT4_DX_PARENT_OFFSET: usize = 12;
const EXT4_DIR_TAIL_FT: u8 = 0xde;
const EXT4_DIR_TAIL_BYTES: usize = 12;
const EXT4_DIR_TAIL_BYTES_U16: u16 = 12;
const EXT4_JOURNAL_INO: u32 = 8;

// Compatible features never change how existing metadata is read, so an
// unknown one is ignored. `dir_index` is listed because directory mutation
// must keep a hashed index consistent, not because reading needs it.
#[cfg(test)]
const EXT4_COMPAT_DIR_INDEX: u32 = 0x0000_0020;

// Incompatible features change on-disk structure. An unknown one must refuse
// the volume outright rather than risk misreading it.
const EXT4_INCOMPAT_FILETYPE: u32 = 0x0000_0002;
const EXT4_FEATURE_INCOMPAT_RECOVER: u32 = 0x0000_0004;
const EXT4_INCOMPAT_EXTENTS: u32 = 0x0000_0040;
const EXT4_INCOMPAT_64BIT: u32 = 0x0000_0080;
const EXT4_INCOMPAT_FLEX_BG: u32 = 0x0000_0200;
const EXT4_INCOMPAT_CSUM_SEED: u32 = 0x0000_2000;

// Read-only-compatible features only change how a writer must maintain
// metadata. An unknown one downgrades the volume to read-only instead of
// refusing it, so foreign media stays readable and untouched.
const EXT4_RO_COMPAT_SPARSE_SUPER: u32 = 0x0000_0001;
const EXT4_RO_COMPAT_LARGE_FILE: u32 = 0x0000_0002;
const EXT4_RO_COMPAT_HUGE_FILE: u32 = 0x0000_0008;
const EXT4_RO_COMPAT_DIR_NLINK: u32 = 0x0000_0020;
const EXT4_RO_COMPAT_EXTRA_ISIZE: u32 = 0x0000_0040;
const EXT4_RO_COMPAT_METADATA_CSUM: u32 = 0x0000_0400;

/// Incompatible features this provider understands well enough to mount.
const EXT4_KNOWN_INCOMPAT: u32 = EXT4_INCOMPAT_FILETYPE
    | EXT4_FEATURE_INCOMPAT_RECOVER
    | EXT4_INCOMPAT_EXTENTS
    | EXT4_INCOMPAT_64BIT
    | EXT4_INCOMPAT_FLEX_BG
    | EXT4_INCOMPAT_CSUM_SEED;

/// Read-only-compatible features this provider maintains correctly on write.
const EXT4_KNOWN_RO_COMPAT: u32 = EXT4_RO_COMPAT_SPARSE_SUPER
    | EXT4_RO_COMPAT_LARGE_FILE
    | EXT4_RO_COMPAT_HUGE_FILE
    | EXT4_RO_COMPAT_DIR_NLINK
    | EXT4_RO_COMPAT_EXTRA_ISIZE
    | EXT4_RO_COMPAT_METADATA_CSUM;

/// Structure this provider requires in every volume it will mount.
const EXT4_REQUIRED_INCOMPAT: u32 = EXT4_INCOMPAT_FILETYPE | EXT4_INCOMPAT_EXTENTS;
const EXT4_REQUIRED_RO_COMPAT: u32 = EXT4_RO_COMPAT_EXTRA_ISIZE | EXT4_RO_COMPAT_METADATA_CSUM;

/// The exact feature set TROE's own image recipe produces.
#[cfg(test)]
const EXT4_FEATURE_COMPAT: u32 = 0x0000_0004 | 0x0000_0008;
#[cfg(test)]
const EXT4_FEATURE_INCOMPAT: u32 = EXT4_REQUIRED_INCOMPAT;
#[cfg(test)]
const EXT4_FEATURE_RO_COMPAT: u32 =
    EXT4_RO_COMPAT_SPARSE_SUPER | EXT4_RO_COMPAT_LARGE_FILE | EXT4_REQUIRED_RO_COMPAT;
const CRC32C_POLYNOMIAL: u32 = 0x82f6_3b78;
/// Hard ceiling on block groups.
///
/// A group holds at most [`EXT4_BITMAP_BITS`] blocks, so this covers the whole
/// 32-bit block space: 16 TiB at the 4 KiB block size. A volume larger than
/// that sets `s_blocks_count_hi`, which the mount parser refuses rather than
/// truncating to 32 bits. Allocation stays bounded because the free-block scan
/// stops as soon as the retained runs can satisfy the request.
const HARD_MAX_GROUPS: u32 = 131_072;
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
    /// Filesystem block size in bytes: 1024, 2048, or 4096.
    block_bytes: usize,
    /// First block that may hold data; 1 only at the 1 KiB block size.
    first_data_block: u32,
    /// The same block size as a 32-bit value.
    block_bytes_u32: u32,
    /// The same block size as a 64-bit value.
    block_bytes_u64: u64,
    checksum_seed: u32,
    /// On-disk group descriptor size; 64 whenever the `64bit` feature is set.
    desc_size: usize,
    uuid: Ext4Uuid,
    /// Cleared when the volume declares a read-only-compatible feature this
    /// provider cannot maintain, so foreign media stays readable but untouched.
    writable: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Extent {
    logical: u32,
    physical: u32,
    blocks: u16,
    unwritten: bool,
}

#[derive(Clone, Debug)]
struct ParsedExtentRoot {
    /// Tree depth: zero when the root holds extents directly.
    depth: u16,
    extents: Vec<Extent>,
    tree_blocks: Vec<u32>,
    tree_logicals: Vec<u32>,
}

#[derive(Clone, Debug)]
struct Inode {
    number: u32,
    generation: u32,
    kind: NodeKind,
    size: u64,
    /// Set when this directory carries a hashed index this provider does not
    /// maintain. Its blocks do not follow the linear record layout.
    indexed: bool,
    extents: Vec<Extent>,
    extent_tree_blocks: Vec<u32>,
    /// Depth of the extent tree this inode's root describes.
    extent_depth: u16,
    /// Interior tree blocks above the leaf level, recorded so a rewrite can
    /// release the entire tree.
    interior_extent_blocks: Vec<u32>,
    extent_tree_logicals: Vec<u32>,
    /// Last payload modification in whole Unix UTC seconds, when stamped.
    modified_unix_seconds: Option<u64>,
    changed_unix_seconds: Option<u64>,
    created_unix_seconds: Option<u64>,
}

#[derive(Clone, Debug)]
struct DirectoryEntry {
    inode: u32,
    name: String,
    kind: NodeKind,
}

/// Whether a parse is the ordinary fail-closed mount or an authorized recovery.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Admission {
    /// The ordinary path. Dirty media and a pending journal are both refused.
    Clean,
    /// The explicitly authorized recovery path, which alone may open a volume
    /// whose journal still needs replay.
    Recovery,
}

/// What one bounded recovery pass did.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecoveryOutcome {
    /// The volume was already clean; no recovery was required.
    AlreadyClean,
    /// A committed transaction was replayed and checkpointed in place.
    Replayed {
        /// Number of filesystem blocks restored from the log.
        blocks: u32,
    },
    /// An interrupted transaction never committed, so it was discarded.
    ///
    /// Nothing it staged had reached media, so the volume was already at its
    /// exact pre-mutation state.
    Discarded,
}

/// Mounted strict ext4 v1 provider owning exactly one block-region capability.
pub struct Ext4<D: BlockDevice> {
    region: BlockRegion<D>,
    limits: Ext4Limits,
    layout: Layout,
    write_defaults: Ext4WriteDefaults,
    journal: Option<JournalGeometry>,
    transaction: Option<Transaction>,
    /// Clock this provider stamps into the inodes it mutates.
    ///
    /// `None`, or a clock that reports no time, leaves every timestamp exactly
    /// as it was rather than inventing one.
    wall_clock: Option<Rc<dyn WallClock>>,
}

/// Which timestamps one inode write should advance.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum InodeTouch {
    /// Only the inode itself changed, so the change time advances.
    Metadata,
    /// The file's contents changed, so the modification time advances too.
    Content,
}

/// Where the internal journal lives, resolved once from inode 8.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct JournalGeometry {
    /// First physical filesystem block of the journal file.
    first_block: u32,
    /// Journal block count, taken from the parsed journal superblock.
    superblock: journal::JournalSuperblock,
}

/// One in-flight metadata mutation staged entirely in memory.
///
/// Nothing a mutation writes reaches media until the transaction commits, so
/// an interruption before the commit record leaves media at its exact
/// pre-state. That is what makes recovery on an empty log safe.
#[derive(Debug, Default)]
struct Transaction {
    staged: Vec<(u32, Vec<u8>)>,
}

impl Transaction {
    fn staged_image(&self, block: u32) -> Option<&[u8]> {
        self.staged
            .iter()
            .find(|(candidate, _)| *candidate == block)
            .map(|(_, image)| image.as_slice())
    }

    fn stage(&mut self, block: u32, bytes: &[u8]) -> Result<(), FsError> {
        if let Some(slot) = self
            .staged
            .iter_mut()
            .find(|(candidate, _)| *candidate == block)
        {
            slot.1.clear();
            slot.1
                .try_reserve_exact(bytes.len())
                .map_err(|_| FsError::NoSpace)?;
            slot.1.extend_from_slice(bytes);
            return Ok(());
        }
        if self.staged.len() >= journal::MAX_TRANSACTION_BLOCKS {
            return Err(FsError::NoSpace);
        }
        let mut image = Vec::new();
        image
            .try_reserve_exact(bytes.len())
            .map_err(|_| FsError::NoSpace)?;
        image.extend_from_slice(bytes);
        self.staged.try_reserve(1).map_err(|_| FsError::NoSpace)?;
        self.staged.push((block, image));
        Ok(())
    }
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
        region: BlockRegion<D>,
        limits: Ext4Limits,
        write_defaults: Ext4WriteDefaults,
    ) -> Result<Self, FsError> {
        Self::open(region, limits, write_defaults, Admission::Clean)
    }

    /// Replay one interrupted mutation, then mount the recovered volume.
    ///
    /// This is the only entry point that may open a volume whose journal still
    /// needs replay, and it refuses a volume that is already clean. Recovery
    /// authority is therefore explicit at the call site and unavailable to any
    /// caller that only holds the ordinary mount path.
    ///
    /// Recovery is idempotent: it may be interrupted and re-run. A committed
    /// transaction is re-applied from the log, and an uncommitted one is
    /// discarded, because nothing it staged ever reached media.
    ///
    /// # Errors
    ///
    /// Returns [`FsError::Invalid`] when the volume needs no recovery, and the
    /// ordinary mount errors when the recovered volume still fails validation.
    pub fn recover(
        region: BlockRegion<D>,
        limits: Ext4Limits,
    ) -> Result<(Self, RecoveryOutcome), FsError> {
        let mut provisional = Self::open(
            region,
            limits,
            Ext4WriteDefaults::default(),
            Admission::Recovery,
        )?;
        provisional.ensure_writable()?;
        let outcome = provisional.replay()?;
        provisional.set_clean_state(true)?;
        let mounted = Self::mount(provisional.region, limits)?;
        Ok((mounted, outcome))
    }

    fn open(
        mut region: BlockRegion<D>,
        limits: Ext4Limits,
        write_defaults: Ext4WriteDefaults,
        admission: Admission,
    ) -> Result<Self, FsError> {
        validate_limits(limits)?;
        let info = region.info();
        let device_block_bytes =
            usize::try_from(info.block_bytes()).map_err(|_| FsError::Overflow)?;
        if info.required_alignment_blocks() != 1
            || device_block_bytes > EXT4_MIN_BLOCK_BYTES
            || !EXT4_MIN_BLOCK_BYTES.is_multiple_of(device_block_bytes)
        {
            return Err(FsError::Unsupported);
        }
        // The superblock always lives at byte 1024 regardless of block size, so
        // it is read before the block size it declares is known.
        let probe_blocks = u32::try_from(EXT4_MAX_BLOCK_BYTES / device_block_bytes)
            .map_err(|_| FsError::Overflow)?;
        let probe = read_raw_device_span(&mut region, 0, probe_blocks, EXT4_MAX_BLOCK_BYTES)?;
        let superblock = probe.get(1024..2048).ok_or(FsError::Corrupt)?;
        let layout = parse_superblock(
            superblock,
            info.block_count(),
            device_block_bytes,
            limits,
            admission,
        )?;
        if info.limits().max_transfer_blocks() < layout.device_blocks_per_fs_block
            || info.limits().max_transfer_bytes() < layout.block_bytes
        {
            return Err(FsError::Unsupported);
        }
        let mut mounted = Self {
            region,
            limits,
            layout,
            write_defaults,
            journal: None,
            transaction: None,
            wall_clock: None,
        };
        // A half-checkpointed volume may hold a torn root directory that
        // replay is about to restore, so recovery validates the root only
        // after it has finished and re-mounts through the ordinary path.
        if admission == Admission::Clean {
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
        }
        Ok(mounted)
    }

    /// Replay or discard the one transaction the log may hold.
    ///
    /// An empty log means the volume is already consistent: either the
    /// interrupted mutation never committed, in which case nothing it staged
    /// reached media, or its checkpoint completed before the interruption.
    fn replay(&mut self) -> Result<RecoveryOutcome, FsError> {
        let geometry = self.journal_geometry()?;
        let head = geometry.superblock.start;
        if head == 0 {
            return Ok(RecoveryOutcome::AlreadyClean);
        }
        let sequence = geometry.superblock.sequence;
        let descriptor_block = self.journal_physical(&geometry, head)?;
        let descriptor = self.read_fs_block(descriptor_block)?;
        let tags = journal::decode_descriptor(&descriptor, sequence, self.layout.blocks)?;

        let payload_len = u32::try_from(tags.len()).map_err(|_| FsError::Overflow)?;
        let commit_index = head
            .checked_add(payload_len)
            .and_then(|index| index.checked_add(1))
            .ok_or(FsError::Overflow)?;
        let commit_block = self.journal_physical(&geometry, commit_index)?;
        let commit = self.read_fs_block(commit_block)?;
        if journal::verify_commit(&commit, sequence).is_err() {
            // The interruption landed before the commit record, so media is
            // still exactly the pre-mutation state.
            self.retire_journal_head(&geometry, sequence)?;
            return Ok(RecoveryOutcome::Discarded);
        }

        for (index, tag) in tags.iter().enumerate() {
            let offset = u32::try_from(index).map_err(|_| FsError::Overflow)?;
            let source = self.journal_physical(
                &geometry,
                head.checked_add(offset)
                    .and_then(|value| value.checked_add(1))
                    .ok_or(FsError::Overflow)?,
            )?;
            let mut image = self.read_fs_block(source)?;
            if tag.escaped {
                journal::unescape(&mut image)?;
            }
            self.write_fs_block_direct(tag.block, &image)?;
        }
        self.durability_barrier()?;
        self.retire_journal_head(&geometry, sequence)?;
        Ok(RecoveryOutcome::Replayed {
            blocks: payload_len,
        })
    }

    /// Wall time to stamp into an inode, or `None` to leave its times alone.
    ///
    /// The clock is read here, at the mutation, so a mount never stamps the
    /// instant it was attached onto a write that happened much later.
    fn wall_seconds(&self) -> Option<u64> {
        self.wall_clock.as_ref()?.unix_seconds()
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
        if let Some(transaction) = self.transaction.as_ref()
            && let Some(image) = transaction.staged_image(block)
        {
            let mut copy = Vec::new();
            copy.try_reserve_exact(image.len())
                .map_err(|_| FsError::NoSpace)?;
            copy.extend_from_slice(image);
            return Ok(copy);
        }
        read_raw_fs_block(
            &mut self.region,
            block,
            self.layout.device_blocks_per_fs_block,
            self.layout.block_bytes,
        )
    }

    /// Block holding the superblock, and its offset inside that block.
    ///
    /// The superblock always lives at byte 1024, which is block 1 at the 1 KiB
    /// block size and an offset inside block 0 at every larger size.
    const fn superblock_location(&self) -> (u32, usize) {
        if self.layout.block_bytes == EXT4_MIN_BLOCK_BYTES {
            (1, 0)
        } else {
            (0, 1024)
        }
    }

    fn ensure_writable(&self) -> Result<(), FsError> {
        if !self.layout.writable {
            return Err(FsError::ReadOnly);
        }
        let info = self.region.info();
        if info.access() != BlockAccess::ReadWrite {
            return Err(FsError::ReadOnly);
        }
        // Every ordering guarantee this provider makes is enforced by an
        // explicit flush, so a device without one cannot be mutated safely.
        if !info.supports_flush() {
            return Err(FsError::Unsupported);
        }
        Ok(())
    }

    fn write_fs_block(&mut self, block: u32, bytes: &[u8]) -> Result<(), FsError> {
        if block >= self.layout.blocks || bytes.len() != self.layout.block_bytes {
            return Err(FsError::Invalid);
        }
        if let Some(transaction) = self.transaction.as_mut() {
            return transaction.stage(block, bytes);
        }
        self.write_fs_block_direct(block, bytes)
    }

    fn write_fs_block_direct(&mut self, block: u32, bytes: &[u8]) -> Result<(), FsError> {
        if block >= self.layout.blocks || bytes.len() != self.layout.block_bytes {
            return Err(FsError::Invalid);
        }
        let start = u64::from(block)
            .checked_mul(u64::from(self.layout.device_blocks_per_fs_block))
            .ok_or(FsError::Overflow)?;
        self.region
            .write_blocks(start, self.layout.device_blocks_per_fs_block, bytes, false)
            .map_err(map_block_error)
    }

    fn durability_barrier(&mut self) -> Result<(), FsError> {
        self.ensure_writable()?;
        self.region.flush().map_err(map_block_error)
    }

    /// Stamp the clean marker and the recovery flag in one flushed block-0
    /// write.
    ///
    /// Both signals live in the same block under the same checksum, so writing
    /// them together keeps the cost identical to the previous dirty marker.
    /// The ordinary mount refuses on either signal, and a foreign Linux host is
    /// forced to recover rather than mount half-applied metadata.
    fn set_clean_state(&mut self, clean: bool) -> Result<(), FsError> {
        let (holder, holder_offset) = self.superblock_location();
        let mut block = read_raw_fs_block(
            &mut self.region,
            holder,
            self.layout.device_blocks_per_fs_block,
            self.layout.block_bytes,
        )?;
        let superblock = block
            .get_mut(holder_offset..holder_offset + 1024)
            .ok_or(FsError::Corrupt)?;
        let state = read_u16(superblock, 58)?;
        let updated = if clean {
            (state | EXT4_VALID_FS) & !EXT4_ERROR_FS
        } else {
            state & !EXT4_VALID_FS
        };
        put_u16(superblock, 58, updated)?;
        let incompat = read_u32(superblock, 96)?;
        let features = if clean {
            incompat & !EXT4_FEATURE_INCOMPAT_RECOVER
        } else {
            incompat | EXT4_FEATURE_INCOMPAT_RECOVER
        };
        put_u32(superblock, 96, features)?;
        superblock[1020..1024].fill(0);
        let checksum = crc32c(u32::MAX, &superblock[..1020]);
        put_u32(superblock, 1020, checksum)?;
        self.write_fs_block_direct(holder, &block)?;
        self.durability_barrier()
    }

    /// Resolve the internal journal once from inode 8.
    ///
    /// The profile requires one contiguous extent covering the whole journal,
    /// which is exactly what `mke2fs -E lazy_journal_init=0` produces.
    fn journal_geometry(&mut self) -> Result<JournalGeometry, FsError> {
        if let Some(geometry) = self.journal {
            return Ok(geometry);
        }
        let raw = self.raw_inode_record(EXT4_JOURNAL_INO)?;
        let inline = raw.get(40..100).ok_or(FsError::Corrupt)?;
        let parsed = parse_extents(inline, self.layout.blocks)?;
        let [extent] = parsed.extents.as_slice() else {
            return Err(FsError::Unsupported);
        };
        if extent.logical != 0 || extent.unwritten || !parsed.tree_blocks.is_empty() {
            return Err(FsError::Unsupported);
        }
        let first_block = extent.physical;
        let image = self.read_fs_block(first_block)?;
        let superblock = journal::JournalSuperblock::parse(&image, self.layout.block_bytes_u32)?;
        if u32::from(extent.blocks) != superblock.maxlen {
            return Err(FsError::Corrupt);
        }
        let geometry = JournalGeometry {
            first_block,
            superblock,
        };
        self.journal = Some(geometry);
        Ok(geometry)
    }

    fn journal_physical(&self, geometry: &JournalGeometry, index: u32) -> Result<u32, FsError> {
        if index >= geometry.superblock.maxlen {
            return Err(FsError::Corrupt);
        }
        geometry
            .first_block
            .checked_add(index)
            .filter(|block| *block < self.layout.blocks)
            .ok_or(FsError::Corrupt)
    }

    fn begin_mutation(&mut self) -> Result<(), FsError> {
        self.ensure_writable()?;
        self.journal_geometry()?;
        // The dirty marker and the recovery flag reach media before any
        // staged byte, so an interruption is always visible as one or the
        // other.
        self.set_clean_state(false)?;
        self.transaction = Some(Transaction::default());
        Ok(())
    }

    /// Commit, checkpoint, and retire the open transaction.
    ///
    /// Ordering is load-bearing: the log payload is durable before the commit
    /// record, the commit record is durable before any in-place checkpoint
    /// write is issued, the checkpoint is durable before the log head is
    /// retired, and the head is retired before the volume is marked clean.
    fn finish_mutation(&mut self) -> Result<(), FsError> {
        let Some(transaction) = self.transaction.take() else {
            return Err(FsError::Invalid);
        };
        if transaction.staged.is_empty() {
            return self.set_clean_state(true);
        }
        let geometry = self.journal_geometry()?;
        let sequence = geometry.superblock.sequence;
        let mut staged = Vec::new();
        staged
            .try_reserve_exact(transaction.staged.len())
            .map_err(|_| FsError::NoSpace)?;
        for (block, image) in &transaction.staged {
            let mut copy = Vec::new();
            copy.try_reserve_exact(image.len())
                .map_err(|_| FsError::NoSpace)?;
            copy.extend_from_slice(image);
            staged.push(journal::StagedBlock {
                block: *block,
                image: copy,
            });
        }
        let images = journal::encode_transaction(&geometry.superblock, sequence, &staged)?;

        let head = geometry.superblock.first;
        for (index, image) in images.iter().enumerate().take(images.len() - 1) {
            let offset = u32::try_from(index).map_err(|_| FsError::Overflow)?;
            let physical = self.journal_physical(
                &geometry,
                head.checked_add(offset).ok_or(FsError::Overflow)?,
            )?;
            self.write_fs_block_direct(physical, image)?;
        }
        self.durability_barrier()?;

        let commit = images.last().ok_or(FsError::Corrupt)?;
        let commit_index = u32::try_from(images.len() - 1).map_err(|_| FsError::Overflow)?;
        let commit_physical = self.journal_physical(
            &geometry,
            head.checked_add(commit_index).ok_or(FsError::Overflow)?,
        )?;
        self.arm_journal_head(&geometry, head, sequence)?;
        self.write_fs_block_direct(commit_physical, commit)?;
        self.durability_barrier()?;

        for entry in &staged {
            self.write_fs_block_direct(entry.block, &entry.image)?;
        }
        self.durability_barrier()?;

        self.retire_journal_head(&geometry, sequence)?;
        self.set_clean_state(true)
    }

    /// Publish the log head so a replay can find this transaction.
    fn arm_journal_head(
        &mut self,
        geometry: &JournalGeometry,
        head: u32,
        sequence: u32,
    ) -> Result<(), FsError> {
        let mut image = read_raw_fs_block(
            &mut self.region,
            geometry.first_block,
            self.layout.device_blocks_per_fs_block,
            self.layout.block_bytes,
        )?;
        journal::JournalSuperblock::write_head(&mut image, head, sequence)?;
        self.write_fs_block_direct(geometry.first_block, &image)?;
        self.durability_barrier()
    }

    /// Retire the log so the next mount finds nothing to replay.
    ///
    /// The sequence advances so a stale commit record can never be mistaken
    /// for the next transaction.
    fn retire_journal_head(
        &mut self,
        geometry: &JournalGeometry,
        sequence: u32,
    ) -> Result<(), FsError> {
        let next = sequence.checked_add(1).unwrap_or(1);
        let mut image = read_raw_fs_block(
            &mut self.region,
            geometry.first_block,
            self.layout.device_blocks_per_fs_block,
            self.layout.block_bytes,
        )?;
        journal::JournalSuperblock::write_head(&mut image, 0, next)?;
        self.write_fs_block_direct(geometry.first_block, &image)?;
        self.durability_barrier()?;
        if let Some(stored) = self.journal.as_mut() {
            stored.superblock.sequence = next;
            stored.superblock.start = 0;
        }
        Ok(())
    }

    /// Abandon any open transaction without touching media.
    ///
    /// A mutation that fails after `begin_mutation` leaves its staged blocks
    /// behind. Discarding them is always correct because nothing they hold
    /// ever reached media, and it stops a later read from observing bytes that
    /// were never committed.
    fn abort_mutation(&mut self) {
        self.transaction = None;
    }

    /// Locate one group descriptor as a table block and byte offset inside it.
    fn descriptor_location(&self, group: u32) -> Result<(u32, usize), FsError> {
        if group >= self.layout.groups {
            return Err(FsError::Corrupt);
        }
        let byte_offset = usize::try_from(group)
            .ok()
            .and_then(|value| value.checked_mul(self.layout.desc_size))
            .ok_or(FsError::Overflow)?;
        let table_block = self
            .layout
            .first_data_block
            .checked_add(1)
            .and_then(|first| {
                first.checked_add(u32::try_from(byte_offset / self.layout.block_bytes).ok()?)
            })
            .ok_or(FsError::Overflow)?;
        Ok((table_block, byte_offset % self.layout.block_bytes))
    }

    fn write_group_descriptor(
        &mut self,
        group: u32,
        mut descriptor: [u8; EXT4_GROUP_DESC_MAX],
    ) -> Result<(), FsError> {
        let (table_block, offset) = self.descriptor_location(group)?;
        let size = self.layout.desc_size;
        descriptor[30..32].fill(0);
        let checksum = crc32c(
            crc32c(self.layout.checksum_seed, &group.to_le_bytes()),
            descriptor.get(..size).ok_or(FsError::Corrupt)?,
        );
        descriptor[30..32].copy_from_slice(&checksum.to_le_bytes()[..2]);
        let mut block = self.read_fs_block(table_block)?;
        block
            .get_mut(offset..offset + size)
            .ok_or(FsError::Corrupt)?
            .copy_from_slice(descriptor.get(..size).ok_or(FsError::Corrupt)?);
        self.write_fs_block(table_block, &block)
    }

    fn adjust_superblock_counter(&mut self, offset: usize, allocate: bool) -> Result<(), FsError> {
        let (holder, holder_offset) = self.superblock_location();
        let mut block = self.read_fs_block(holder)?;
        let superblock = block
            .get_mut(holder_offset..holder_offset + 1024)
            .ok_or(FsError::Corrupt)?;
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
        self.write_fs_block(holder, &block)
    }

    /// Whether this volume stores the upper half of a bitmap checksum.
    ///
    /// The high half exists only when the group descriptor is long enough to
    /// contain it, which is exactly what `e2fsprogs` tests before using it.
    fn has_checksum_high(&self, high_offset: usize) -> bool {
        self.layout.desc_size >= high_offset + 2
    }

    /// Read a stored bitmap checksum, joining both halves when present.
    fn stored_bitmap_checksum(
        &self,
        descriptor: &[u8],
        low_offset: usize,
        high_offset: usize,
    ) -> Result<u32, FsError> {
        let low = u32::from(read_u16(descriptor, low_offset)?);
        if !self.has_checksum_high(high_offset) {
            return Ok(low);
        }
        Ok(low | (u32::from(read_u16(descriptor, high_offset)?) << 16))
    }

    /// Store a bitmap checksum, splitting it across both halves when present.
    fn put_bitmap_checksum(
        &self,
        descriptor: &mut [u8],
        low_offset: usize,
        high_offset: usize,
        checksum: u32,
    ) -> Result<(), FsError> {
        put_u16(
            descriptor,
            low_offset,
            u16::try_from(checksum & 0xFFFF).map_err(|_| FsError::Overflow)?,
        )?;
        if self.has_checksum_high(high_offset) {
            put_u16(
                descriptor,
                high_offset,
                u16::try_from(checksum >> 16).map_err(|_| FsError::Overflow)?,
            )?;
        }
        Ok(())
    }

    fn validate_bitmap_checksum(
        &self,
        descriptor: &[u8],
        bitmap: &[u8],
        bytes: usize,
        low_offset: usize,
        high_offset: usize,
    ) -> Result<(), FsError> {
        let stored = self.stored_bitmap_checksum(descriptor, low_offset, high_offset)?;
        let calculated = crc32c(
            self.layout.checksum_seed,
            bitmap.get(..bytes).ok_or(FsError::Corrupt)?,
        );
        let expected = if self.has_checksum_high(high_offset) {
            calculated
        } else {
            calculated & 0xFFFF
        };
        if stored != expected {
            return Err(FsError::Corrupt);
        }
        Ok(())
    }

    fn set_block_allocated(&mut self, block_number: u32, allocate: bool) -> Result<(), FsError> {
        if block_number == 0 || block_number >= self.layout.blocks {
            return Err(FsError::Corrupt);
        }
        // Bit zero of group zero describes `first_data_block`, which is block
        // one at the 1 KiB block size.
        let relative = block_number
            .checked_sub(self.layout.first_data_block)
            .ok_or(FsError::Corrupt)?;
        let group = relative / self.layout.blocks_per_group;
        let bit = relative % self.layout.blocks_per_group;
        let mut descriptor = self.group_descriptor(group)?;
        let bitmap_block = read_u32(&descriptor, 0)?;
        if bitmap_block == 0 || bitmap_block >= self.layout.blocks {
            return Err(FsError::Corrupt);
        }
        let mut bitmap = self.read_fs_block(bitmap_block)?;
        let bitmap_bytes =
            usize::try_from(self.layout.blocks_per_group / 8).map_err(|_| FsError::Overflow)?;
        self.validate_bitmap_checksum(
            &descriptor,
            &bitmap,
            bitmap_bytes,
            EXT4_BG_BLOCK_CSUM_LO,
            EXT4_BG_BLOCK_CSUM_HI,
        )?;
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
        self.put_bitmap_checksum(
            &mut descriptor,
            EXT4_BG_BLOCK_CSUM_LO,
            EXT4_BG_BLOCK_CSUM_HI,
            checksum,
        )?;
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
        self.validate_bitmap_checksum(
            &descriptor,
            &bitmap,
            bitmap_bytes,
            EXT4_BG_INODE_CSUM_LO,
            EXT4_BG_INODE_CSUM_HI,
        )?;
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
        self.put_bitmap_checksum(
            &mut descriptor,
            EXT4_BG_INODE_CSUM_LO,
            EXT4_BG_INODE_CSUM_HI,
            checksum,
        )?;
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
            // An uninitialized bitmap holds no meaningful bits and no
            // allocations, so the group is skipped rather than misread.
            if read_u16(&descriptor, EXT4_BG_FLAGS_OFFSET)? & EXT4_BG_BLOCK_UNINIT != 0 {
                continue;
            }
            let bitmap_block = read_u32(&descriptor, 0)?;
            if bitmap_block == 0 || bitmap_block >= self.layout.blocks {
                return Err(FsError::Corrupt);
            }
            let bitmap = self.read_fs_block(bitmap_block)?;
            let bitmap_bytes =
                usize::try_from(self.layout.blocks_per_group / 8).map_err(|_| FsError::Overflow)?;
            self.validate_bitmap_checksum(
                &descriptor,
                &bitmap,
                bitmap_bytes,
                EXT4_BG_BLOCK_CSUM_LO,
                EXT4_BG_BLOCK_CSUM_HI,
            )?;
            let group_start = group
                .checked_mul(self.layout.blocks_per_group)
                .and_then(|start| start.checked_add(self.layout.first_data_block))
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
            // Stop as soon as the retained runs can satisfy the request, so a
            // large volume never pays for a whole-volume bitmap scan.
            let retained = runs.iter().try_fold(0_u32, |total, (_, length)| {
                total.checked_add(*length).ok_or(FsError::Overflow)
            })?;
            if retained >= count_u32 {
                break;
            }
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
            // An uninitialized inode table holds no allocated inode.
            if read_u16(&descriptor, EXT4_BG_FLAGS_OFFSET)? & EXT4_BG_INODE_UNINIT != 0 {
                continue;
            }
            let bitmap_block = read_u32(&descriptor, 4)?;
            if bitmap_block == 0 || bitmap_block >= self.layout.blocks {
                return Err(FsError::Corrupt);
            }
            let bitmap = self.read_fs_block(bitmap_block)?;
            let bitmap_bytes =
                usize::try_from(self.layout.inodes_per_group / 8).map_err(|_| FsError::Overflow)?;
            self.validate_bitmap_checksum(
                &descriptor,
                &bitmap,
                bitmap_bytes,
                EXT4_BG_INODE_CSUM_LO,
                EXT4_BG_INODE_CSUM_HI,
            )?;
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
            .checked_add(self.layout.block_bytes - 1)
            .map(|value| value / self.layout.block_bytes)
            .ok_or(FsError::Overflow)?;
        let blocks = self.find_free_blocks(count)?;
        let mut payload = alloc::vec![0_u8; self.layout.block_bytes];
        for (logical, physical) in blocks.iter().copied().enumerate() {
            payload.fill(0);
            let start = logical
                .checked_mul(self.layout.block_bytes)
                .ok_or(FsError::Overflow)?;
            let end = start
                .checked_add(self.layout.block_bytes)
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

    fn release_extents(&mut self, extents: &[Extent]) -> Result<(), FsError> {
        let mut released = false;
        for extent in extents {
            for offset in 0..u32::from(extent.blocks) {
                self.set_block_allocated(
                    extent
                        .physical
                        .checked_add(offset)
                        .ok_or(FsError::Overflow)?,
                    false,
                )?;
                released = true;
            }
        }
        if released {
            self.durability_barrier()?;
        }
        Ok(())
    }

    fn append_physical_blocks(
        extents: &mut Vec<Extent>,
        mut logical: u32,
        blocks: &[u32],
        block_bytes: usize,
    ) -> Result<(), FsError> {
        for physical in blocks.iter().copied() {
            if let Some(last) = extents.last_mut() {
                let logical_end = last
                    .logical
                    .checked_add(u32::from(last.blocks))
                    .ok_or(FsError::Overflow)?;
                let physical_end = last
                    .physical
                    .checked_add(u32::from(last.blocks))
                    .ok_or(FsError::Overflow)?;
                if logical_end == logical
                    && physical_end == physical
                    && last.blocks < 0x8000
                    && !last.unwritten
                {
                    last.blocks += 1;
                    logical = logical.checked_add(1).ok_or(FsError::Overflow)?;
                    continue;
                }
            }
            if extents.len() >= max_tree_extents(block_bytes) {
                return Err(FsError::NoSpace);
            }
            extents.push(Extent {
                logical,
                physical,
                blocks: 1,
                unwritten: false,
            });
            logical = logical.checked_add(1).ok_or(FsError::Overflow)?;
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
                u32::try_from(byte_offset / self.layout.block_bytes)
                    .map_err(|_| FsError::Overflow)?,
            )
            .ok_or(FsError::Overflow)?;
        Ok((block, byte_offset % self.layout.block_bytes))
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
        // The extra-field size must be declared before any timestamp is
        // written, because it is what makes the epoch bits a defined field.
        put_u16(raw, EXT4_EXTRA_ISIZE_OFFSET, EXT4_EXTRA_ISIZE)?;
        if let Some(seconds) = self.wall_seconds() {
            // A newly allocated inode is born now, so every time it carries
            // starts at the same instant, including its creation time.
            for field in [EXT4_ATIME, EXT4_CTIME, EXT4_MTIME, EXT4_CRTIME] {
                put_inode_time(raw, field, seconds)?;
            }
        }
        put_u32(raw, 100, self.layout.checksum_seed ^ number ^ 0xa5a5_5a5a)?;
        Ok(())
    }

    fn inode_sector_count(raw: &[u8]) -> Result<u64, FsError> {
        Ok(u64::from(read_u32(raw, 28)?) | (u64::from(read_u16(raw, 116)?) << 32))
    }

    fn extent_sector_count(
        raw: &[u8],
        volume_blocks: u32,
        block_bytes_u64: u64,
    ) -> Result<u64, FsError> {
        let parsed = parse_extents(raw.get(40..100).ok_or(FsError::Corrupt)?, volume_blocks)?;
        if !parsed.tree_blocks.is_empty() {
            return Err(FsError::Unsupported);
        }
        parsed.extents.iter().try_fold(0_u64, |total, extent| {
            total
                .checked_add(u64::from(extent.blocks) * (block_bytes_u64 / 512))
                .ok_or(FsError::Overflow)
        })
    }

    fn encode_inode_content(
        raw: &mut [u8],
        size: u64,
        blocks: &[u32],
        metadata_sectors: u64,
        block_bytes_u64: u64,
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
            .checked_mul(block_bytes_u64 / 512)
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

    /// Write the sixty-byte extent root inside one inode record.
    ///
    /// `root` is empty for a file whose extents fit in the inode, and is
    /// otherwise the index entries naming the top level of the tree, each
    /// paired with the lowest logical block its subtree covers.
    fn encode_inode_extent_records(
        raw: &mut [u8],
        size: u64,
        extents: &[Extent],
        root: &[(u32, u32)],
        tree: &ExtentTreePlan,
        metadata_sectors: u64,
        block_bytes: usize,
    ) -> Result<(), FsError> {
        let block_bytes_u64 = u64::try_from(block_bytes).map_err(|_| FsError::Overflow)?;
        if extents.len() > max_tree_extents(block_bytes)
            || extents.iter().any(|extent| extent.unwritten)
            || root.len() != tree.levels.last().copied().unwrap_or(0)
            || root.len() > EXT4_ROOT_INDEXES
        {
            return Err(FsError::NoSpace);
        }
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
        let data_blocks = extents.iter().try_fold(0_u64, |total, extent| {
            total
                .checked_add(u64::from(extent.blocks))
                .ok_or(FsError::Overflow)
        })?;
        let sectors = data_blocks
            .checked_add(u64::try_from(tree.total_blocks()).map_err(|_| FsError::Overflow)?)
            .ok_or(FsError::Overflow)?
            .checked_mul(block_bytes_u64 / 512)
            .and_then(|data| data.checked_add(metadata_sectors))
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
        if root.is_empty() {
            put_u16(
                raw,
                42,
                u16::try_from(extents.len()).map_err(|_| FsError::Overflow)?,
            )?;
            for (index, extent) in extents.iter().enumerate() {
                let offset = 52_usize
                    .checked_add(index.checked_mul(12).ok_or(FsError::Overflow)?)
                    .ok_or(FsError::Overflow)?;
                put_u32(raw, offset, extent.logical)?;
                put_u16(raw, offset + 4, extent.blocks)?;
                put_u16(raw, offset + 6, 0)?;
                put_u32(raw, offset + 8, extent.physical)?;
            }
        } else {
            put_u16(
                raw,
                42,
                u16::try_from(root.len()).map_err(|_| FsError::Overflow)?,
            )?;
            put_u16(raw, 46, tree.depth()?)?;
            for (index, (logical, block)) in root.iter().copied().enumerate() {
                let offset = 52_usize
                    .checked_add(index.checked_mul(12).ok_or(FsError::Overflow)?)
                    .ok_or(FsError::Overflow)?;
                put_u32(raw, offset, logical)?;
                put_u32(raw, offset + 4, block)?;
                put_u16(raw, offset + 8, 0)?;
                put_u16(raw, offset + 10, 0)?;
            }
        }
        Ok(())
    }

    /// Write one interior node of an extent tree.
    fn encode_extent_index_block(
        raw: &mut [u8],
        depth: u16,
        children: &[(u32, u32)],
        checksum_seed: u32,
        inode_number: u32,
        inode_generation: u32,
    ) -> Result<(), FsError> {
        if children.is_empty() || children.len() > node_entries(raw.len()) || depth == 0 {
            return Err(FsError::Invalid);
        }
        raw.fill(0);
        put_u16(raw, 0, EXT4_EXT_MAGIC)?;
        put_u16(
            raw,
            2,
            u16::try_from(children.len()).map_err(|_| FsError::Overflow)?,
        )?;
        put_u16(
            raw,
            4,
            u16::try_from(node_entries(raw.len())).map_err(|_| FsError::Overflow)?,
        )?;
        put_u16(raw, 6, depth)?;
        for (index, (logical, block)) in children.iter().copied().enumerate() {
            let offset = EXT4_EXTENT_HEADER_BYTES
                .checked_add(
                    index
                        .checked_mul(EXT4_EXTENT_RECORD_BYTES)
                        .ok_or(FsError::Overflow)?,
                )
                .ok_or(FsError::Overflow)?;
            put_u32(raw, offset, logical)?;
            put_u32(raw, offset + 4, block)?;
            put_u16(raw, offset + 8, 0)?;
            put_u16(raw, offset + 10, 0)?;
        }
        let inode_seed = crc32c(
            crc32c(checksum_seed, &inode_number.to_le_bytes()),
            &inode_generation.to_le_bytes(),
        );
        let tail_offset = extent_tail_offset(raw.len());
        let checksum = crc32c(inode_seed, raw.get(..tail_offset).ok_or(FsError::Corrupt)?);
        put_u32(raw, tail_offset, checksum)
    }

    fn encode_extent_leaf(
        raw: &mut [u8],
        extents: &[Extent],
        checksum_seed: u32,
        inode_number: u32,
        inode_generation: u32,
    ) -> Result<(), FsError> {
        if extents.is_empty() || extents.len() > leaf_extents(raw.len()) {
            return Err(FsError::Invalid);
        }
        raw.fill(0);
        put_u16(raw, 0, EXT4_EXT_MAGIC)?;
        put_u16(
            raw,
            2,
            u16::try_from(extents.len()).map_err(|_| FsError::Overflow)?,
        )?;
        put_u16(
            raw,
            4,
            u16::try_from(leaf_extents(raw.len())).map_err(|_| FsError::Overflow)?,
        )?;
        for (index, extent) in extents.iter().enumerate() {
            let offset = 12_usize
                .checked_add(index.checked_mul(12).ok_or(FsError::Overflow)?)
                .ok_or(FsError::Overflow)?;
            put_u32(raw, offset, extent.logical)?;
            put_u16(raw, offset + 4, extent.blocks)?;
            put_u16(raw, offset + 6, 0)?;
            put_u32(raw, offset + 8, extent.physical)?;
        }
        let inode_seed = crc32c(
            crc32c(checksum_seed, &inode_number.to_le_bytes()),
            &inode_generation.to_le_bytes(),
        );
        let checksum = crc32c(inode_seed, &raw[..extent_tail_offset(raw.len())]);
        put_u32(raw, extent_tail_offset(raw.len()), checksum)
    }

    fn refresh_inode_checksum(
        &self,
        raw: &mut [u8],
        number: u32,
        touch: InodeTouch,
    ) -> Result<(), FsError> {
        if let Some(seconds) = self.wall_seconds() {
            // The change time advances on every inode write; the modification
            // time only when the file's contents actually changed.
            put_inode_time(raw, EXT4_CTIME, seconds)?;
            if touch == InodeTouch::Content {
                put_inode_time(raw, EXT4_MTIME, seconds)?;
            }
        }
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
                .checked_sub(Self::extent_sector_count(
                    raw,
                    self.layout.blocks,
                    self.layout.block_bytes_u64,
                )?)
                .ok_or(FsError::Corrupt)?
        };
        Self::encode_inode_content(
            raw,
            size,
            blocks,
            metadata_sectors,
            self.layout.block_bytes_u64,
        )?;
        self.refresh_inode_checksum(raw, number, InodeTouch::Content)?;
        self.write_fs_block(table_block, &table)
    }

    fn write_inode_extent_records(
        &mut self,
        number: u32,
        kind: NodeKind,
        size: u64,
        extents: &[Extent],
        existing: &Inode,
    ) -> Result<(), FsError> {
        if existing.number != number || existing.kind != kind {
            return Err(FsError::Corrupt);
        }
        let tree = ExtentTreePlan::new(extents.len(), self.layout.block_bytes)?;
        // A tree of the same shape is rewritten in place. Any other shape is
        // built beside the old one and the old one released only after the
        // inode names the new tree, so a failure leaves the file intact.
        let previous = ExtentTreePlan::new(existing.extents.len(), self.layout.block_bytes).ok();
        let reuse = tree.depth()? == 1
            && previous.as_ref() == Some(&tree)
            && existing.extent_depth == 1
            && existing.extent_tree_blocks.len() == tree.total_blocks();
        let blocks = if reuse {
            existing.extent_tree_blocks.clone()
        } else {
            self.allocate_metadata_blocks(tree.total_blocks())?
        };
        let outcome = self.write_extent_tree(number, existing.generation, extents, &tree, &blocks);
        let root = match outcome {
            Ok(root) => root,
            Err(error) => {
                if !reuse {
                    let _ignored = self.release_blocks(&blocks);
                }
                return Err(error);
            }
        };
        let (table_block, offset) = self.inode_record_location(number)?;
        let mut table = self.read_fs_block(table_block)?;
        let raw = table
            .get_mut(offset..offset + EXT4_INODE_BYTES)
            .ok_or(FsError::Corrupt)?;
        let data_blocks = existing.extents.iter().try_fold(0_u64, |total, extent| {
            total
                .checked_add(u64::from(extent.blocks))
                .ok_or(FsError::Overflow)
        })?;
        let existing_tree_blocks = existing
            .extent_tree_blocks
            .len()
            .checked_add(existing.interior_extent_blocks.len())
            .ok_or(FsError::Overflow)?;
        let allocated_sectors = data_blocks
            .checked_add(u64::try_from(existing_tree_blocks).map_err(|_| FsError::Overflow)?)
            .and_then(|blocks| blocks.checked_mul(self.layout.block_bytes_u64 / 512))
            .ok_or(FsError::Overflow)?;
        let metadata_sectors = Self::inode_sector_count(raw)?
            .checked_sub(allocated_sectors)
            .ok_or(FsError::Corrupt)?;
        let encoded = Self::encode_inode_extent_records(
            raw,
            size,
            extents,
            &root,
            &tree,
            metadata_sectors,
            self.layout.block_bytes,
        )
        .and_then(|()| self.refresh_inode_checksum(raw, number, InodeTouch::Content))
        .and_then(|()| self.write_fs_block(table_block, &table))
        .and_then(|()| self.durability_barrier());
        if let Err(error) = encoded {
            if !reuse {
                let _ignored = self.release_blocks(&blocks);
            }
            return Err(error);
        }
        if reuse {
            Ok(())
        } else {
            // Release every level, not just the leaves, so a deeper tree
            // leaves nothing allocated behind.
            self.release_blocks(&existing.interior_extent_blocks)?;
            self.release_blocks(&existing.extent_tree_blocks)
        }
    }

    /// Fill a planned extent tree and return the entries the inode root names.
    ///
    /// `blocks` is the planned block count taken level by level, leaves first.
    /// Each level is written from the level below it, so an interior node
    /// records the lowest logical block of every subtree it covers.
    fn write_extent_tree(
        &mut self,
        number: u32,
        generation: u32,
        extents: &[Extent],
        tree: &ExtentTreePlan,
        blocks: &[u32],
    ) -> Result<Vec<(u32, u32)>, FsError> {
        let mut root = Vec::new();
        if tree.levels.is_empty() {
            return Ok(root);
        }
        let per_node = node_entries(self.layout.block_bytes);
        let mut taken = 0_usize;
        let mut children: Vec<(u32, u32)> = Vec::new();
        for (level, count) in tree.levels.iter().copied().enumerate() {
            let level_blocks = blocks
                .get(taken..taken.checked_add(count).ok_or(FsError::Overflow)?)
                .ok_or(FsError::Corrupt)?;
            taken = taken.checked_add(count).ok_or(FsError::Overflow)?;
            let mut parents = Vec::new();
            parents
                .try_reserve_exact(count)
                .map_err(|_| FsError::NoSpace)?;
            let mut raw = alloc::vec![0_u8; self.layout.block_bytes];
            for (index, block) in level_blocks.iter().copied().enumerate() {
                let start = index.checked_mul(per_node).ok_or(FsError::Overflow)?;
                let lowest = if level == 0 {
                    let end = start
                        .checked_add(per_node)
                        .ok_or(FsError::Overflow)?
                        .min(extents.len());
                    let leaf = extents.get(start..end).ok_or(FsError::Corrupt)?;
                    Self::encode_extent_leaf(
                        &mut raw,
                        leaf,
                        self.layout.checksum_seed,
                        number,
                        generation,
                    )?;
                    leaf.first().ok_or(FsError::Corrupt)?.logical
                } else {
                    let end = start
                        .checked_add(per_node)
                        .ok_or(FsError::Overflow)?
                        .min(children.len());
                    let node = children.get(start..end).ok_or(FsError::Corrupt)?;
                    Self::encode_extent_index_block(
                        &mut raw,
                        u16::try_from(level).map_err(|_| FsError::Overflow)?,
                        node,
                        self.layout.checksum_seed,
                        number,
                        generation,
                    )?;
                    node.first().ok_or(FsError::Corrupt)?.0
                };
                self.write_fs_block(block, &raw)?;
                parents.push((lowest, block));
            }
            children = parents;
        }
        if taken != blocks.len() {
            return Err(FsError::Corrupt);
        }
        root.try_reserve_exact(children.len())
            .map_err(|_| FsError::NoSpace)?;
        root.extend_from_slice(&children);
        Ok(root)
    }

    /// Reserve blocks for metadata without materializing their contents.
    ///
    /// A deep extent tree can run to thousands of blocks, so the caller writes
    /// each one's real bytes rather than staging that many zeroes first.
    fn allocate_metadata_blocks(&mut self, count: usize) -> Result<Vec<u32>, FsError> {
        if count == 0 {
            return Ok(Vec::new());
        }
        let blocks = self.find_free_blocks(count)?;
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

    fn append_regular_file(&mut self, path: &str, bytes: &[u8]) -> Result<(), FsError> {
        self.ensure_writable()?;
        if bytes.is_empty() {
            return Ok(());
        }
        let inode = self.resolve(path)?;
        if inode.kind != NodeKind::File {
            return Err(FsError::WrongType);
        }
        let added = u64::try_from(bytes.len()).map_err(|_| FsError::Overflow)?;
        let next_size = inode.size.checked_add(added).ok_or(FsError::Overflow)?;
        if next_size > self.limits.max_file_bytes() {
            return Err(FsError::NoSpace);
        }
        self.begin_mutation()?;
        let partial = usize::try_from(inode.size % self.layout.block_bytes_u64)
            .map_err(|_| FsError::Overflow)?;
        let mut consumed = 0_usize;
        if partial != 0 {
            let logical = u32::try_from(inode.size / self.layout.block_bytes_u64)
                .map_err(|_| FsError::NoSpace)?;
            let (physical, unwritten) = map_block(&inode, logical)?.ok_or(FsError::Corrupt)?;
            if unwritten {
                return Err(FsError::Corrupt);
            }
            let mut block = self.read_fs_block(physical)?;
            consumed = bytes.len().min(self.layout.block_bytes - partial);
            block[partial..partial + consumed].copy_from_slice(&bytes[..consumed]);
            self.write_fs_block(physical, &block)?;
        }
        let new_blocks = self.allocate_file_blocks(&bytes[consumed..])?;
        let mut extents = inode.extents.clone();
        let logical = u32::try_from(
            inode
                .size
                .checked_add(self.layout.block_bytes_u64 - 1)
                .ok_or(FsError::Overflow)?
                / self.layout.block_bytes_u64,
        )
        .map_err(|_| FsError::NoSpace)?;
        if let Err(error) = Self::append_physical_blocks(
            &mut extents,
            logical,
            &new_blocks,
            self.layout.block_bytes,
        ) {
            let _ignored = self.release_blocks(&new_blocks);
            return Err(error);
        }
        if let Err(error) = self
            .write_inode_extent_records(inode.number, NodeKind::File, next_size, &extents, &inode)
            .and_then(|()| self.durability_barrier())
        {
            let _ignored = self.release_blocks(&new_blocks);
            return Err(error);
        }
        self.finish_mutation()
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
        self.refresh_inode_checksum(raw, number, InodeTouch::Content)?;
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
        self.refresh_inode_checksum(raw, number, InodeTouch::Metadata)?;
        self.write_fs_block(block, &table)
    }

    /// Advance one inode's times without altering any of its fields.
    ///
    /// `InodeTouch::Metadata` advances only the change time, which is what a
    /// rename needs: it rewrites directory entries and never the inode it
    /// moves, so nothing else would record that the object changed.
    /// `InodeTouch::Content` advances the modification time too, which is what
    /// a directory needs when a name inside it is created, removed or renamed.
    ///
    /// Without a wall clock there is nothing to record, so the write is skipped
    /// rather than spent rewriting an unchanged record.
    fn touch_inode(&mut self, number: u32, touch: InodeTouch) -> Result<(), FsError> {
        if self.wall_seconds().is_none() {
            return Ok(());
        }
        let (block, offset) = self.inode_record_location(number)?;
        let mut table = self.read_fs_block(block)?;
        let raw = table
            .get_mut(offset..offset + EXT4_INODE_BYTES)
            .ok_or(FsError::Corrupt)?;
        self.refresh_inode_checksum(raw, number, touch)?;
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

    fn group_descriptor(&mut self, group: u32) -> Result<[u8; EXT4_GROUP_DESC_MAX], FsError> {
        let (table_block, offset) = self.descriptor_location(group)?;
        let size = self.layout.desc_size;
        let bytes = self.read_fs_block(table_block)?;
        let mut descriptor = [0_u8; EXT4_GROUP_DESC_MAX];
        descriptor
            .get_mut(..size)
            .ok_or(FsError::Corrupt)?
            .copy_from_slice(bytes.get(offset..offset + size).ok_or(FsError::Corrupt)?);
        let stored = read_u16(&descriptor, 30)?;
        descriptor[30..32].fill(0);
        let checksum = crc32c(
            crc32c(self.layout.checksum_seed, &group.to_le_bytes()),
            descriptor.get(..size).ok_or(FsError::Corrupt)?,
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

    /// Walk an extent tree down to the level that holds its leaves.
    ///
    /// Above depth one the root's children are interior nodes, so each level is
    /// expanded in turn. Every interior block stays recorded so a later rewrite
    /// releases the whole tree rather than leaking its upper levels.
    fn descend_extent_tree(&mut self, inode: &mut Inode) -> Result<(), FsError> {
        let mut depth = inode.extent_depth;
        while depth > 1 {
            let mut children = Vec::new();
            let mut logicals = Vec::new();
            for block in inode.extent_tree_blocks.iter().copied() {
                let node = self.read_fs_block(block)?;
                let parsed = parse_extent_index_block(
                    &node,
                    self.layout.blocks,
                    depth - 1,
                    self.layout.checksum_seed,
                    inode.number,
                    inode.generation,
                )?;
                if children
                    .len()
                    .checked_add(parsed.len())
                    .is_none_or(|total| total > EXT4_MAX_EXTENT_TREE_BLOCKS)
                {
                    return Err(FsError::NoSpace);
                }
                children
                    .try_reserve(parsed.len())
                    .map_err(|_| FsError::NoSpace)?;
                logicals
                    .try_reserve(parsed.len())
                    .map_err(|_| FsError::NoSpace)?;
                for (logical, physical) in parsed {
                    logicals.push(logical);
                    children.push(physical);
                }
            }
            inode
                .interior_extent_blocks
                .try_reserve(inode.extent_tree_blocks.len())
                .map_err(|_| FsError::NoSpace)?;
            inode
                .interior_extent_blocks
                .extend_from_slice(&inode.extent_tree_blocks);
            inode.extent_tree_blocks = children;
            inode.extent_tree_logicals = logicals;
            depth -= 1;
        }
        Ok(())
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
            u32::try_from(byte_offset / self.layout.block_bytes).map_err(|_| FsError::Overflow)?;
        let table_block = inode_table
            .checked_add(table_offset_blocks)
            .ok_or(FsError::Overflow)?;
        let offset = byte_offset % self.layout.block_bytes;
        let block = self.read_fs_block(table_block)?;
        let raw = block
            .get(offset..offset + EXT4_INODE_BYTES)
            .ok_or(FsError::Corrupt)?;
        let mut inode = parse_inode(raw, number, self.layout, self.limits)?;
        if !inode.extent_tree_blocks.is_empty() {
            self.descend_extent_tree(&mut inode)?;
            let mut extents = Vec::new();
            for (index, block) in inode.extent_tree_blocks.iter().copied().enumerate() {
                let leaf = self.read_fs_block(block)?;
                let parsed = parse_extent_leaf(
                    &leaf,
                    self.layout.blocks,
                    self.layout.checksum_seed,
                    inode.number,
                    inode.generation,
                )?;
                if parsed.first().map(|extent| extent.logical)
                    != inode.extent_tree_logicals.get(index).copied()
                {
                    return Err(FsError::Corrupt);
                }
                extents
                    .try_reserve_exact(parsed.len())
                    .map_err(|_| FsError::NoSpace)?;
                extents.extend_from_slice(&parsed);
            }
            let file_blocks = inode
                .size
                .checked_add(self.layout.block_bytes_u64 - 1)
                .ok_or(FsError::Overflow)?
                / self.layout.block_bytes_u64;
            let mut previous_end = 0_u32;
            for extent in &extents {
                let end = extent
                    .logical
                    .checked_add(u32::from(extent.blocks))
                    .ok_or(FsError::Overflow)?;
                if extent.logical < previous_end
                    || u64::from(end) > file_blocks
                    || (inode.kind != NodeKind::File && extent.unwritten)
                {
                    return Err(FsError::Corrupt);
                }
                previous_end = end;
            }
            inode.extents = extents;
        }
        Ok(inode)
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
            let logical = u32::try_from(file_offset / self.layout.block_bytes_u64)
                .map_err(|_| FsError::Overflow)?;
            let in_block = usize::try_from(file_offset % self.layout.block_bytes_u64)
                .map_err(|_| FsError::Overflow)?;
            let count = (wanted - copied).min(self.layout.block_bytes - in_block);
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

    /// Logical blocks that may hold ordinary records for this directory.
    ///
    /// A hashed directory keeps records only in its leaves; its root and
    /// interior nodes hold the index instead.
    fn record_blocks(&mut self, directory: &Inode) -> Result<Vec<u32>, FsError> {
        if directory.indexed {
            return self.hashed_leaf_blocks(directory);
        }
        let block_count = u32::try_from(directory.size / self.layout.block_bytes_u64)
            .map_err(|_| FsError::Overflow)?;
        let mut blocks = Vec::new();
        blocks
            .try_reserve_exact(usize::try_from(block_count).map_err(|_| FsError::Overflow)?)
            .map_err(|_| FsError::NoSpace)?;
        for logical in 0..block_count {
            blocks.push(logical);
        }
        Ok(blocks)
    }

    /// The one leaf a name belongs in, chosen by the directory's own index.
    ///
    /// Placing a record anywhere else would leave the index describing the
    /// wrong leaf, so a name whose hash cannot be reproduced is refused.
    fn hashed_target_leaf(&mut self, directory: &Inode, name: &str) -> Result<u32, FsError> {
        Ok(self.hashed_path(directory, name)?.leaf)
    }

    /// Walk the index to a name's leaf, keeping the entry followed at each
    /// level so a split can insert its separator exactly beside it.
    fn hashed_path(&mut self, directory: &Inode, name: &str) -> Result<HashedPath, FsError> {
        let hashing = self.directory_hash()?;
        let seed = self.inode_checksum_seed(directory);
        let root_block = self.directory_block(directory, 0)?;
        let root = htree::parse_root(&root_block, seed, crc32c)?;
        let hash = hashing.hash(name.as_bytes(), root.hash_version)?;
        let root_index = covering_entry(&root.entries, hash)?;
        let followed = *root.entries.get(root_index).ok_or(FsError::Corrupt)?;
        if root.indirect_levels == 0 {
            return Ok(HashedPath {
                root: root.entries,
                root_index,
                node: None,
                leaf: followed.block,
            });
        }
        let node_block = self.directory_block(directory, followed.block)?;
        let entries = htree::parse_node(&node_block, seed, crc32c)?;
        let index = covering_entry(&entries, hash)?;
        let leaf = entries.get(index).ok_or(FsError::Corrupt)?.block;
        Ok(HashedPath {
            root: root.entries,
            root_index,
            node: Some(HashedNode {
                logical: followed.block,
                entries,
                index,
            }),
            leaf,
        })
    }

    /// Split the full leaf a name maps to and rewrite the index over both
    /// halves.
    ///
    /// Records are redistributed by hash so that every name still lands in the
    /// leaf its own hash selects, and the separator is inserted beside the
    /// entry the walk followed. A parent with no room splits in turn: a root
    /// still addressing leaves directly grows one level of interior nodes, and
    /// a full interior node splits under a root that still has room.
    fn split_hashed_leaf(&mut self, directory: &Inode, name: &str) -> Result<(), FsError> {
        let seed = self.inode_checksum_seed(directory);
        let path = self.hashed_path(directory, name)?;
        let hashing = self.directory_hash()?;
        let root_block = self.directory_block(directory, 0)?;
        let hash_version = htree::parse_root(&root_block, seed, crc32c)?.hash_version;

        let leaf_block = self.directory_block(directory, path.leaf)?;
        verify_directory_checksum(self.layout.checksum_seed, directory, &leaf_block)?;
        let mut records = Vec::new();
        for record in read_directory_records(&leaf_block)? {
            let hash = hashing.hash(&record.name, hash_version)?;
            records.try_reserve(1).map_err(|_| FsError::NoSpace)?;
            records.push((hash, record));
        }
        // A hash decides a record's leaf, so redistribution is by hash and the
        // order within one hash does not matter.
        records.sort_by_key(|(hash, _)| *hash);
        let boundary = balanced_hash_boundary(&records)?;
        let separator = records.get(boundary).ok_or(FsError::Corrupt)?.0;

        // Refuse before allocating anything when the index cannot describe the
        // extra leaf however the parents are rearranged.
        let plan = self.plan_index_growth(&path)?;
        let base_logical = u32::try_from(directory.size / self.layout.block_bytes_u64)
            .map_err(|_| FsError::Overflow)?;
        let zeroes = alloc::vec![0_u8; plan.blocks * self.layout.block_bytes];
        let physical = self.allocate_file_blocks(&zeroes)?;
        if physical.len() != plan.blocks {
            let _ignored = self.release_blocks(&physical);
            return Err(FsError::Corrupt);
        }
        let new_leaf = base_logical;
        let new_index_block = base_logical.checked_add(1).ok_or(FsError::Overflow)?;

        let outcome = self.write_hashed_split(
            directory,
            &path,
            &records,
            boundary,
            separator,
            plan,
            (new_leaf, new_index_block),
            &physical,
            base_logical,
        );
        if outcome.is_err() {
            let _ignored = self.release_blocks(&physical);
        }
        outcome
    }

    /// Decide how the index must change to describe one more leaf.
    fn plan_index_growth(&mut self, path: &HashedPath) -> Result<IndexGrowth, FsError> {
        let root_capacity =
            htree::entry_capacity(self.layout.block_bytes, htree::DX_ROOT_COUNT_OFFSET)?;
        let node_capacity =
            htree::entry_capacity(self.layout.block_bytes, htree::DX_NODE_COUNT_OFFSET)?;
        match path.node.as_ref() {
            None if path.root.len() < root_capacity => Ok(IndexGrowth {
                shape: IndexShape::RootHasRoom,
                blocks: 1,
            }),
            // A root addressing leaves directly cannot hold another separator,
            // so its entries move down into one interior node. They always fit:
            // a node's array starts earlier in the block than a root's.
            None => Ok(IndexGrowth {
                shape: IndexShape::DeepenRoot,
                blocks: 2,
            }),
            Some(node) if node.entries.len() < node_capacity => Ok(IndexGrowth {
                shape: IndexShape::NodeHasRoom,
                blocks: 1,
            }),
            Some(_) if path.root.len() < root_capacity => Ok(IndexGrowth {
                shape: IndexShape::SplitNode,
                blocks: 2,
            }),
            // Both levels are full, and ext4 defines no third one here.
            Some(_) => Err(FsError::NoSpace),
        }
    }

    /// Write both halves of the split leaf and the index that describes them.
    #[allow(clippy::too_many_arguments)]
    fn write_hashed_split(
        &mut self,
        directory: &Inode,
        path: &HashedPath,
        records: &[(u32, DirectoryRecord)],
        boundary: usize,
        separator: u32,
        plan: IndexGrowth,
        logicals: (u32, u32),
        physical: &[u32],
        base_logical: u32,
    ) -> Result<(), FsError> {
        let (new_leaf, new_index_block) = logicals;
        let (lower, upper) = records.split_at(boundary);
        for (blocks, target) in [(lower, path.leaf), (upper, new_leaf)] {
            let mut block = alloc::vec![0_u8; self.layout.block_bytes];
            self.pack_directory_leaf(&mut block, blocks)?;
            refresh_directory_checksum(self.layout.checksum_seed, directory, &mut block)?;
            let physical_target = if target == new_leaf {
                *physical.first().ok_or(FsError::Corrupt)?
            } else {
                let (found, false) = map_block(directory, target)?.ok_or(FsError::Corrupt)? else {
                    return Err(FsError::Corrupt);
                };
                found
            };
            self.write_fs_block(physical_target, &block)?;
        }

        self.apply_index_growth(
            directory,
            path,
            plan.shape,
            (new_leaf, new_index_block),
            separator,
            physical,
        )?;

        let mut extents = directory.extents.clone();
        Self::append_physical_blocks(
            &mut extents,
            base_logical,
            physical,
            self.layout.block_bytes,
        )?;
        let size = directory
            .size
            .checked_add(
                u64::try_from(plan.blocks)
                    .ok()
                    .and_then(|blocks| blocks.checked_mul(self.layout.block_bytes_u64))
                    .ok_or(FsError::Overflow)?,
            )
            .ok_or(FsError::Overflow)?;
        self.write_inode_extent_records(
            directory.number,
            NodeKind::Directory,
            size,
            &extents,
            directory,
        )?;
        self.durability_barrier()
    }

    /// Rearrange the index levels so they describe the new leaf.
    ///
    /// The separator goes directly beside the entry the walk followed, and a
    /// parent with no room for it is reshaped first.
    fn apply_index_growth(
        &mut self,
        directory: &Inode,
        path: &HashedPath,
        shape: IndexShape,
        logicals: (u32, u32),
        separator: u32,
        physical: &[u32],
    ) -> Result<(), FsError> {
        let (new_leaf, new_index_block) = logicals;
        let entry = htree::DxEntry {
            hash: separator,
            block: new_leaf,
        };
        match shape {
            IndexShape::RootHasRoom => {
                let mut entries = path.root.clone();
                insert_index_entry(&mut entries, path.root_index, entry)?;
                self.write_index_root(directory, &entries, 0)?;
            }
            IndexShape::DeepenRoot => {
                let mut entries = path.root.clone();
                insert_index_entry(&mut entries, path.root_index, entry)?;
                let node = *physical.get(1).ok_or(FsError::Corrupt)?;
                self.write_index_node(directory, node, &entries)?;
                self.write_index_root(
                    directory,
                    &[htree::DxEntry {
                        hash: 0,
                        block: new_index_block,
                    }],
                    1,
                )?;
            }
            IndexShape::NodeHasRoom => {
                let node = path.node.as_ref().ok_or(FsError::Corrupt)?;
                let mut entries = node.entries.clone();
                insert_index_entry(&mut entries, node.index, entry)?;
                let (found, false) = map_block(directory, node.logical)?.ok_or(FsError::Corrupt)?
                else {
                    return Err(FsError::Corrupt);
                };
                self.write_index_node(directory, found, &entries)?;
            }
            IndexShape::SplitNode => {
                let node = path.node.as_ref().ok_or(FsError::Corrupt)?;
                let mut entries = node.entries.clone();
                insert_index_entry(&mut entries, node.index, entry)?;
                let middle = entries.len() / 2;
                let promoted = entries.get(middle).ok_or(FsError::Corrupt)?.hash;
                let mut upper = Vec::new();
                upper
                    .try_reserve_exact(entries.len() - middle)
                    .map_err(|_| FsError::NoSpace)?;
                upper.extend_from_slice(entries.get(middle..).ok_or(FsError::Corrupt)?);
                entries.truncate(middle);
                // The first entry of a node covers everything below the second,
                // so the hash it was carrying is what the parent records.
                upper.first_mut().ok_or(FsError::Corrupt)?.hash = 0;
                let (found, false) = map_block(directory, node.logical)?.ok_or(FsError::Corrupt)?
                else {
                    return Err(FsError::Corrupt);
                };
                self.write_index_node(directory, found, &entries)?;
                self.write_index_node(
                    directory,
                    *physical.get(1).ok_or(FsError::Corrupt)?,
                    &upper,
                )?;
                let mut root = path.root.clone();
                insert_index_entry(
                    &mut root,
                    path.root_index,
                    htree::DxEntry {
                        hash: promoted,
                        block: new_index_block,
                    },
                )?;
                self.write_index_root(directory, &root, 1)?;
            }
        }
        Ok(())
    }

    /// Lay a set of records out from the start of one empty leaf block.
    fn pack_directory_leaf(
        &self,
        block: &mut [u8],
        records: &[(u32, DirectoryRecord)],
    ) -> Result<(), FsError> {
        let tail_offset = self.layout.block_bytes - EXT4_DIR_TAIL_BYTES;
        let mut offset = 0_usize;
        for (index, (_, record)) in records.iter().enumerate() {
            let minimum = directory_record_bytes(record.name.len())?;
            // The last record's length runs to the tail so that the block is
            // one unbroken chain of records.
            let bytes = if index + 1 == records.len() {
                tail_offset.checked_sub(offset).ok_or(FsError::NoSpace)?
            } else {
                minimum
            };
            if bytes < minimum {
                return Err(FsError::NoSpace);
            }
            write_directory_record(
                block,
                offset,
                bytes,
                record.inode,
                &record.name,
                record.file_type,
            )?;
            offset = offset.checked_add(bytes).ok_or(FsError::Overflow)?;
        }
        if records.is_empty() {
            write_directory_record(block, 0, tail_offset, 0, &[], 0)?;
        }
        initialize_directory_tail(block)
    }

    /// Rewrite the index root over a new entry array.
    fn write_index_root(
        &mut self,
        directory: &Inode,
        entries: &[htree::DxEntry],
        indirect_levels: u8,
    ) -> Result<(), FsError> {
        let seed = self.inode_checksum_seed(directory);
        let (physical, false) = map_block(directory, 0)?.ok_or(FsError::Corrupt)? else {
            return Err(FsError::Corrupt);
        };
        let mut block = self.read_fs_block(physical)?;
        htree::set_indirect_levels(&mut block, indirect_levels)?;
        htree::write_entries(
            &mut block,
            htree::DX_ROOT_COUNT_OFFSET,
            entries,
            seed,
            crc32c,
        )?;
        self.write_fs_block(physical, &block)
    }

    /// Write one interior index node over a physical block.
    fn write_index_node(
        &mut self,
        directory: &Inode,
        physical: u32,
        entries: &[htree::DxEntry],
    ) -> Result<(), FsError> {
        let seed = self.inode_checksum_seed(directory);
        let mut block = alloc::vec![0_u8; self.layout.block_bytes];
        htree::initialize_node(&mut block)?;
        htree::write_entries(
            &mut block,
            htree::DX_NODE_COUNT_OFFSET,
            entries,
            seed,
            crc32c,
        )?;
        self.write_fs_block(physical, &block)
    }

    /// Read the filesystem-wide inputs to a directory name hash.
    fn directory_hash(&mut self) -> Result<htree::DxHash, FsError> {
        let (holder, offset) = self.superblock_location();
        let block = self.read_fs_block(holder)?;
        let superblock = block.get(offset..offset + 1024).ok_or(FsError::Corrupt)?;
        htree::DxHash::parse(superblock)
    }

    /// Seed every per-inode metadata checksum in this directory is built from.
    fn inode_checksum_seed(&self, inode: &Inode) -> u32 {
        crc32c(
            crc32c(self.layout.checksum_seed, &inode.number.to_le_bytes()),
            &inode.generation.to_le_bytes(),
        )
    }

    /// Read one logical block of a directory.
    fn directory_block(&mut self, inode: &Inode, logical: u32) -> Result<Vec<u8>, FsError> {
        let (physical, unwritten) = map_block(inode, logical)?.ok_or(FsError::Corrupt)?;
        if unwritten {
            return Err(FsError::Corrupt);
        }
        self.read_fs_block(physical)
    }

    /// Collect the logical leaf blocks a hashed directory keeps its records in.
    fn hashed_leaf_blocks(&mut self, inode: &Inode) -> Result<Vec<u32>, FsError> {
        let seed = self.inode_checksum_seed(inode);
        let root_block = self.directory_block(inode, 0)?;
        let root = htree::parse_root(&root_block, seed, crc32c)?;
        let ceiling =
            usize::try_from(self.limits.max_directory_blocks()).map_err(|_| FsError::Overflow)?;

        let mut leaves = Vec::new();
        if root.indirect_levels == 0 {
            leaves
                .try_reserve_exact(root.entries.len())
                .map_err(|_| FsError::NoSpace)?;
            for entry in &root.entries {
                leaves.push(entry.block);
            }
        } else {
            for entry in &root.entries {
                let node_block = self.directory_block(inode, entry.block)?;
                let node = htree::parse_node(&node_block, seed, crc32c)?;
                if leaves
                    .len()
                    .checked_add(node.len())
                    .is_none_or(|total| total > ceiling)
                {
                    return Err(FsError::NoSpace);
                }
                leaves
                    .try_reserve(node.len())
                    .map_err(|_| FsError::NoSpace)?;
                for child in &node {
                    leaves.push(child.block);
                }
            }
        }
        if leaves.is_empty() || leaves.len() > ceiling {
            return Err(FsError::NoSpace);
        }
        Ok(leaves)
    }

    /// Enumerate a hashed directory by reading every leaf the index names.
    ///
    /// The root block holds `.` and `..` in records whose lengths hide the
    /// index from an unaware reader, so those two are taken directly and every
    /// other record comes from a leaf.
    fn read_hashed_directory(&mut self, inode: &Inode) -> Result<Vec<DirectoryEntry>, FsError> {
        let root_block = self.directory_block(inode, 0)?;
        let dot = read_u32(&root_block, 0)?;
        let dot_dot = read_u32(&root_block, 12)?;
        if dot != inode.number || dot_dot == 0 || dot_dot > self.layout.inodes {
            return Err(FsError::Corrupt);
        }
        let leaves = self.hashed_leaf_blocks(inode)?;

        let mut entries = Vec::new();
        entries
            .try_reserve_exact(
                usize::try_from(self.limits.max_directory_entries())
                    .map_err(|_| FsError::Overflow)?,
            )
            .map_err(|_| FsError::NoSpace)?;
        entries.push(DirectoryEntry {
            inode: dot,
            name: ".".to_string(),
            kind: NodeKind::Directory,
        });
        entries.push(DirectoryEntry {
            inode: dot_dot,
            name: "..".to_string(),
            kind: NodeKind::Directory,
        });
        for logical in leaves {
            let block = self.directory_block(inode, logical)?;
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

    fn read_directory(&mut self, inode: &Inode) -> Result<Vec<DirectoryEntry>, FsError> {
        if inode.kind != NodeKind::Directory {
            return Err(FsError::WrongType);
        }
        if inode.indexed {
            return self.read_hashed_directory(inode);
        }
        if inode.size == 0 || !inode.size.is_multiple_of(self.layout.block_bytes_u64) {
            return Err(FsError::Corrupt);
        }
        let block_count = u32::try_from(inode.size / self.layout.block_bytes_u64)
            .map_err(|_| FsError::NoSpace)?;
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
        let tail_offset = self.layout.block_bytes - EXT4_DIR_TAIL_BYTES;
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

    /// Link one name into a directory and record that the directory changed.
    ///
    /// POSIX advances a directory's modification and change times whenever a
    /// name inside it is created, removed or renamed. The record itself is
    /// rewritten only when the directory gains or loses a block, so the stamp
    /// is applied here rather than left to that incidental write. It joins the
    /// open transaction, so it costs one more staged block and no extra
    /// durability barrier.
    fn add_directory_entry(
        &mut self,
        directory: &Inode,
        name: &str,
        inode_number: u32,
        kind: NodeKind,
    ) -> Result<(), FsError> {
        self.insert_directory_record(directory, name, inode_number, kind)?;
        self.touch_inode(directory.number, InodeTouch::Content)
    }

    fn insert_directory_record(
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
        // An indexed directory admits a name only into the leaf its own index
        // maps that name's hash to.
        let candidates = if directory.indexed {
            let leaf = self.hashed_target_leaf(directory, name)?;
            let mut only = Vec::new();
            only.try_reserve_exact(1).map_err(|_| FsError::NoSpace)?;
            only.push(leaf);
            only
        } else {
            self.record_blocks(directory)?
        };
        for logical in candidates {
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
        if directory.indexed {
            // The target leaf is full, so it splits and the index is rewritten
            // to describe both halves. The name is then placed by the same walk
            // as before, into whichever half now covers its hash.
            self.split_hashed_leaf(directory, name)?;
            let grown = self.read_inode(directory.number)?;
            let leaf = self.hashed_target_leaf(&grown, name)?;
            let (physical, false) = map_block(&grown, leaf)?.ok_or(FsError::Corrupt)? else {
                return Err(FsError::Corrupt);
            };
            if self.try_add_directory_entry_to_block(
                &grown,
                physical,
                name,
                inode_number,
                required,
                file_type,
            )? {
                return Ok(());
            }
            // The split ran but left no room in the half this name belongs to,
            // which takes an uneven division forced by records sharing a hash.
            return Err(FsError::NoSpace);
        }

        let zeroes = alloc::vec![0_u8; self.layout.block_bytes];
        let new_blocks = self.allocate_file_blocks(&zeroes)?;
        let physical = *new_blocks.first().ok_or(FsError::NoSpace)?;
        let mut block = alloc::vec![0_u8; self.layout.block_bytes];
        write_directory_record(
            &mut block,
            0,
            self.layout.block_bytes - EXT4_DIR_TAIL_BYTES,
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
                    .checked_add(self.layout.block_bytes_u64)
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

    /// Unlink one name from a directory and record that the directory changed.
    ///
    /// The stamp follows the same rule as `add_directory_entry`: losing a name
    /// changes the directory whether or not its own record was rewritten.
    fn remove_directory_entry(
        &mut self,
        directory: &Inode,
        name: &str,
    ) -> Result<DirectoryEntry, FsError> {
        let removed = self.take_directory_record(directory, name)?;
        self.touch_inode(directory.number, InodeTouch::Content)?;
        Ok(removed)
    }

    fn take_directory_record(
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
        // Removing a record leaves the index still describing its leaf, so no
        // index rewrite is needed.
        for logical in self.record_blocks(directory)? {
            let (physical, false) = map_block(directory, logical)?.ok_or(FsError::Corrupt)? else {
                return Err(FsError::Corrupt);
            };
            let mut block = self.read_fs_block(physical)?;
            verify_directory_checksum(self.layout.checksum_seed, directory, &block)?;
            let tail_offset = self.layout.block_bytes - EXT4_DIR_TAIL_BYTES;
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

    fn update_directory_parent(
        &mut self,
        directory: &Inode,
        parent_number: u32,
    ) -> Result<(), FsError> {
        if directory.kind != NodeKind::Directory {
            return Err(FsError::WrongType);
        }
        // An indexed directory keeps `..` in its root block, where the record
        // that holds it spans the index and the block carries the index
        // checksum rather than a linear directory tail.
        if directory.indexed {
            return self.update_indexed_directory_parent(directory, parent_number);
        }
        let (physical, false) = map_block(directory, 0)?.ok_or(FsError::Corrupt)? else {
            return Err(FsError::Corrupt);
        };
        let mut block = self.read_fs_block(physical)?;
        verify_directory_checksum(self.layout.checksum_seed, directory, &block)?;
        let tail_offset = self.layout.block_bytes - EXT4_DIR_TAIL_BYTES;
        let mut offset = 0_usize;
        while offset < tail_offset {
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
            let name = block
                .get(offset + 8..offset + 8 + name_bytes)
                .ok_or(FsError::Corrupt)?;
            if name == b".." {
                put_u32(&mut block, offset, parent_number)?;
                refresh_directory_checksum(self.layout.checksum_seed, directory, &mut block)?;
                self.write_fs_block(physical, &block)?;
                return self.durability_barrier();
            }
            offset = offset.checked_add(record_bytes).ok_or(FsError::Overflow)?;
        }
        Err(FsError::Corrupt)
    }

    /// Repoint `..` inside the root block of a hashed directory.
    ///
    /// The root's `..` record spans the rest of the block so an unaware reader
    /// sees nothing past it, so the record is located by the layout the index
    /// fixes rather than by walking record lengths. The inode field sits inside
    /// the range the index checksum covers, so the entries are rewritten
    /// unchanged to refresh it.
    fn update_indexed_directory_parent(
        &mut self,
        directory: &Inode,
        parent_number: u32,
    ) -> Result<(), FsError> {
        let seed = self.inode_checksum_seed(directory);
        let (physical, false) = map_block(directory, 0)?.ok_or(FsError::Corrupt)? else {
            return Err(FsError::Corrupt);
        };
        let mut block = self.read_fs_block(physical)?;
        let root = htree::parse_root(&block, seed, crc32c)?;
        put_u32(&mut block, EXT4_DX_PARENT_OFFSET, parent_number)?;
        htree::set_indirect_levels(&mut block, root.indirect_levels)?;
        htree::write_entries(
            &mut block,
            htree::DX_ROOT_COUNT_OFFSET,
            &root.entries,
            seed,
            crc32c,
        )?;
        self.write_fs_block(physical, &block)?;
        self.durability_barrier()
    }
}

impl<D: BlockDevice> FileSystemProvider for Ext4<D> {
    fn metadata(&mut self, path: &str) -> Result<FileMetadata, FsError> {
        self.abort_mutation();
        let inode = self.resolve(path)?;
        Ok(FileMetadata {
            kind: inode.kind,
            byte_count: if inode.kind == NodeKind::File {
                inode.size
            } else {
                0
            },
            modified_unix_seconds: inode.modified_unix_seconds,
            changed_unix_seconds: inode.changed_unix_seconds,
            created_unix_seconds: inode.created_unix_seconds,
        })
    }

    fn metadata_no_follow(&mut self, path: &str) -> Result<FileMetadata, FsError> {
        self.abort_mutation();
        let inode = self.resolve_no_follow(path)?;
        Ok(FileMetadata {
            kind: inode.kind,
            byte_count: if inode.kind == NodeKind::File {
                inode.size
            } else {
                0
            },
            modified_unix_seconds: inode.modified_unix_seconds,
            changed_unix_seconds: inode.changed_unix_seconds,
            created_unix_seconds: inode.created_unix_seconds,
        })
    }

    fn read_file(
        &mut self,
        path: &str,
        offset: u64,
        destination: &mut [u8],
    ) -> Result<usize, FsError> {
        self.abort_mutation();
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
        self.abort_mutation();
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

    fn truncate_file(&mut self, path: &str) -> Result<(), FsError> {
        self.abort_mutation();
        match self.resolve(path) {
            Ok(inode) => {
                if inode.kind != NodeKind::File {
                    return Err(FsError::WrongType);
                }
                self.begin_mutation()?;
                self.write_inode_extent_records(inode.number, NodeKind::File, 0, &[], &inode)?;
                self.release_extents(&inode.extents)?;
                self.finish_mutation()
            }
            Err(FsError::NotFound) => self.write_file(path, &[]),
            Err(error) => Err(error),
        }
    }

    fn append_file(&mut self, path: &str, bytes: &[u8]) -> Result<(), FsError> {
        self.abort_mutation();
        self.append_regular_file(path, bytes)
    }

    fn sync_file(&mut self, _path: &str) -> Result<(), FsError> {
        self.abort_mutation();
        self.durability_barrier()
    }

    fn write_file(&mut self, path: &str, bytes: &[u8]) -> Result<(), FsError> {
        self.abort_mutation();
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
            let old_extents = inode.extents.clone();
            self.begin_mutation()?;
            let new_blocks = self.allocate_file_blocks(bytes)?;
            // The replacement goes through the tree writer rather than the
            // inline encoder, because the file being replaced may itself be
            // described by a tree whose every level has to be released.
            let mut extents = Vec::new();
            if let Err(error) =
                Self::append_physical_blocks(&mut extents, 0, &new_blocks, self.layout.block_bytes)
                    .and_then(|()| {
                        self.write_inode_extent_records(
                            inode.number,
                            NodeKind::File,
                            u64::try_from(bytes.len()).map_err(|_| FsError::Overflow)?,
                            &extents,
                            &inode,
                        )
                    })
            {
                let _ignored = self.release_blocks(&new_blocks);
                return Err(error);
            }
            self.release_extents(&old_extents)?;
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

    fn set_modified_time(&mut self, path: &str, unix_seconds: Option<u64>) -> Result<(), FsError> {
        self.abort_mutation();
        self.ensure_writable()?;
        // `None` asks for the clock's instant. Refusing when no wall time is
        // known keeps ADR 0058's rule that a provider never invents one.
        let seconds = match unix_seconds {
            Some(seconds) => seconds,
            None => self.wall_seconds().ok_or(FsError::NotConfigured)?,
        };
        let inode = self.resolve(path)?;
        let (block, offset) = self.inode_record_location(inode.number)?;
        let mut table = self.read_fs_block(block)?;
        let raw = table
            .get_mut(offset..offset + EXT4_INODE_BYTES)
            .ok_or(FsError::Corrupt)?;
        put_inode_time(raw, EXT4_MTIME, seconds)?;
        // The change time advances because the inode itself changed, which
        // `refresh_inode_checksum` does from the clock for any metadata write.
        self.refresh_inode_checksum(raw, inode.number, InodeTouch::Metadata)?;
        self.write_fs_block(block, &table)
    }

    fn create_directory(&mut self, path: &str) -> Result<(), FsError> {
        self.abort_mutation();
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
        let zeroes = alloc::vec![0_u8; self.layout.block_bytes];
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
            self.layout.block_bytes_u64,
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
        let mut block = alloc::vec![0_u8; self.layout.block_bytes];
        let tail = self.layout.block_bytes - EXT4_DIR_TAIL_BYTES;
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
        self.abort_mutation();
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
        self.release_extents(&inode.extents)?;
        self.release_blocks(&inode.extent_tree_blocks)?;
        self.release_blocks(&inode.interior_extent_blocks)?;
        // The inode record is zeroed rather than left with `i_dtime` set:
        // nothing in this profile reads a freed record, so a deletion time in
        // one whose mode and link count are already zero records nothing.
        self.clear_inode_record(inode.number)?;
        self.set_inode_allocated(inode.number, false)?;
        self.durability_barrier()?;
        self.finish_mutation()
    }

    fn remove_directory(&mut self, path: &str) -> Result<(), FsError> {
        self.abort_mutation();
        self.ensure_writable()?;
        let (parent, name) = self.resolve_parent(path)?;
        let entries = self.read_directory(&parent)?;
        let mut matching = entries.iter().filter(|entry| entry.name == name);
        let entry = matching.next().ok_or(FsError::NotFound)?;
        if matching.next().is_some() {
            return Err(FsError::Corrupt);
        }
        if entry.kind != NodeKind::Directory {
            return Err(FsError::WrongType);
        }
        let directory = self.read_inode(entry.inode)?;
        if directory.kind != NodeKind::Directory {
            return Err(FsError::Corrupt);
        }
        let children = self.read_directory(&directory)?;
        if children
            .iter()
            .any(|child| child.name != "." && child.name != "..")
        {
            return Err(FsError::NotEmpty);
        }
        let raw = self.raw_inode_record(directory.number)?;
        if read_u16(&raw, 26)? != 2 || read_u32(&raw, 104)? != 0 || read_u16(&raw, 118)? != 0 {
            return Err(FsError::Unsupported);
        }
        let parent_raw = self.raw_inode_record(parent.number)?;
        let parent_links = read_u16(&parent_raw, 26)?;
        let next_parent_links = parent_links.checked_sub(1).ok_or(FsError::Corrupt)?;

        self.begin_mutation()?;
        let removed = self.remove_directory_entry(&parent, &name)?;
        if removed.inode != directory.number || removed.kind != NodeKind::Directory {
            return Err(FsError::Corrupt);
        }
        self.update_inode_links(parent.number, parent_links, next_parent_links)?;
        self.release_extents(&directory.extents)?;
        self.release_blocks(&directory.extent_tree_blocks)?;
        self.release_blocks(&directory.interior_extent_blocks)?;
        self.clear_inode_record(directory.number)?;
        self.set_directory_allocated(directory.number, false)?;
        self.set_inode_allocated(directory.number, false)?;
        self.durability_barrier()?;
        self.finish_mutation()
    }

    fn rename(&mut self, source: &str, destination: &str) -> Result<(), FsError> {
        self.abort_mutation();
        self.ensure_writable()?;
        let normalized_source = canonicalize("/", source)?;
        let normalized_destination = canonicalize("/", destination)?;
        if normalized_source != source || normalized_destination != destination {
            return Err(FsError::Invalid);
        }
        if source == destination {
            self.resolve_no_follow(source)?;
            return Ok(());
        }
        let (source_parent, source_name) = self.resolve_parent(source)?;
        let source_entries = self.read_directory(&source_parent)?;
        let mut matching = source_entries
            .iter()
            .filter(|entry| entry.name == source_name);
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
        if self
            .read_directory(&destination_parent)?
            .iter()
            .any(|entry| entry.name == destination_name)
        {
            return Err(FsError::Exists);
        }
        let moving_directory = source_entry.kind == NodeKind::Directory
            && source_parent.number != destination_parent.number;
        let source_parent_links = if moving_directory {
            Some(read_u16(&self.raw_inode_record(source_parent.number)?, 26)?)
        } else {
            None
        };
        let destination_parent_links = if moving_directory {
            Some(read_u16(
                &self.raw_inode_record(destination_parent.number)?,
                26,
            )?)
        } else {
            None
        };
        let next_source_links = source_parent_links
            .map(|links| links.checked_sub(1).ok_or(FsError::Corrupt))
            .transpose()?;
        let next_destination_links = destination_parent_links
            .map(|links| links.checked_add(1).ok_or(FsError::NoSpace))
            .transpose()?;
        let moved_inode = self.read_inode(source_entry.inode)?;
        if moved_inode.kind != source_entry.kind {
            return Err(FsError::Corrupt);
        }

        self.begin_mutation()?;
        self.add_directory_entry(
            &destination_parent,
            &destination_name,
            source_entry.inode,
            source_entry.kind,
        )?;
        if moving_directory {
            self.update_directory_parent(&moved_inode, destination_parent.number)?;
            self.update_inode_links(
                source_parent.number,
                source_parent_links.ok_or(FsError::Corrupt)?,
                next_source_links.ok_or(FsError::Corrupt)?,
            )?;
            self.update_inode_links(
                destination_parent.number,
                destination_parent_links.ok_or(FsError::Corrupt)?,
                next_destination_links.ok_or(FsError::Corrupt)?,
            )?;
        }
        let removed = self.remove_directory_entry(&source_parent, &source_name)?;
        if removed.inode != source_entry.inode
            || removed.name != source_entry.name
            || removed.kind != source_entry.kind
        {
            return Err(FsError::Corrupt);
        }
        // The moved object itself changed, even though none of its own fields
        // did, so its change time advances with the rest of the mutation.
        self.touch_inode(source_entry.inode, InodeTouch::Metadata)?;
        self.finish_mutation()
    }

    fn read_link(&mut self, path: &str) -> Result<String, FsError> {
        self.abort_mutation();
        let inode = self.resolve_no_follow(path)?;
        self.read_symlink_inode(&inode)
    }

    fn create_symlink(&mut self, target: &str, link_path: &str) -> Result<(), FsError> {
        self.abort_mutation();
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
        self.abort_mutation();
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

    fn set_wall_clock(&mut self, clock: Rc<dyn WallClock>) {
        self.wall_clock = Some(clock);
    }
}

/// Decide whether this admission may open a volume in the recorded state.
fn admit_state(state: u16, needs_recovery: bool, admission: Admission) -> Result<(), FsError> {
    if state & EXT4_ERROR_FS != 0 {
        return Err(FsError::Corrupt);
    }
    match admission {
        // The ordinary mount stays fail-closed on either signal.
        Admission::Clean => {
            if needs_recovery {
                return Err(FsError::Unsupported);
            }
            if state & EXT4_VALID_FS == 0 {
                return Err(FsError::Corrupt);
            }
            Ok(())
        }
        // Recovery is the only path that may open an interrupted volume, and
        // only when the volume actually says it was interrupted.
        Admission::Recovery => {
            if !needs_recovery && state & EXT4_VALID_FS != 0 {
                return Err(FsError::Invalid);
            }
            Ok(())
        }
    }
}

/// Resolve the on-disk group descriptor size.
///
/// `s_desc_size` is meaningful only with the 64bit feature; without it the
/// descriptor is always the historical 32 bytes.
fn parse_descriptor_size(superblock: &[u8], incompat: u32) -> Result<usize, FsError> {
    let declared = read_u16(superblock, 254)?;
    if incompat & EXT4_INCOMPAT_64BIT == 0 {
        if !matches!(declared, 0 | EXT4_GROUP_DESC_BYTES_U16) {
            return Err(FsError::Corrupt);
        }
        return Ok(EXT4_GROUP_DESC_BYTES);
    }
    if usize::from(declared) != EXT4_GROUP_DESC_MAX {
        return Err(FsError::Unsupported);
    }
    Ok(EXT4_GROUP_DESC_MAX)
}

/// Resolve the seed every metadata checksum is computed from.
///
/// With `metadata_csum_seed` the seed is stored rather than derived, so a
/// volume keeps its checksums valid across a UUID change.
fn parse_checksum_seed(superblock: &[u8], incompat: u32, uuid: Ext4Uuid) -> Result<u32, FsError> {
    if incompat & EXT4_INCOMPAT_CSUM_SEED == 0 {
        return Ok(crc32c(u32::MAX, &uuid.0));
    }
    read_u32(superblock, EXT4_SUPER_CHECKSUM_SEED)
}

/// Resolve the filesystem block size and its device-block ratio.
///
/// `s_log_block_size` selects 1024, 2048 or 4096 bytes, and the cluster size
/// must agree with it because this provider does not implement `bigalloc`.
fn parse_block_geometry(
    superblock: &[u8],
    device_block_bytes: usize,
) -> Result<(usize, u32), FsError> {
    let log_block_size = read_u32(superblock, 24)?;
    if log_block_size > 2 || read_u32(superblock, 28)? != log_block_size {
        return Err(FsError::Unsupported);
    }
    let block_bytes = EXT4_MIN_BLOCK_BYTES
        .checked_shl(log_block_size)
        .ok_or(FsError::Overflow)?;
    if !block_bytes.is_multiple_of(device_block_bytes) {
        return Err(FsError::Unsupported);
    }
    let ratio = u32::try_from(block_bytes / device_block_bytes).map_err(|_| FsError::Overflow)?;
    Ok((block_bytes, ratio))
}

fn parse_superblock(
    superblock: &[u8],
    region_device_blocks: u64,
    device_block_bytes: usize,
    limits: Ext4Limits,
    admission: Admission,
) -> Result<Layout, FsError> {
    if superblock.len() != 1024
        || read_u16(superblock, 56)? != EXT4_MAGIC
        || read_u32(superblock, 76)? != EXT4_DYNAMIC_REV
        || read_u32(superblock, 72)? != 0
        || read_u16(superblock, 88)? != EXT4_INODE_BYTES_U16
        || superblock[373] != 1
    {
        return Err(FsError::Unsupported);
    }
    let incompat = read_u32(superblock, 96)?;
    let ro_compat = read_u32(superblock, 100)?;
    // An unknown incompatible feature changes structure this provider would
    // misread, so the volume is refused outright.
    if incompat & !EXT4_KNOWN_INCOMPAT != 0
        || incompat & EXT4_REQUIRED_INCOMPAT != EXT4_REQUIRED_INCOMPAT
    {
        return Err(FsError::Unsupported);
    }
    // This provider validates metadata checksums and the extended inode area,
    // so it cannot read a volume that lacks them.
    if ro_compat & EXT4_REQUIRED_RO_COMPAT != EXT4_REQUIRED_RO_COMPAT {
        return Err(FsError::Unsupported);
    }
    // An unknown read-only-compatible feature only affects what a writer must
    // maintain, so the volume stays readable and is never mutated.
    // A hashed index is a per-directory property, so the volume stays writable
    // and only the indexed directories themselves are refused.
    let writable = ro_compat & !EXT4_KNOWN_RO_COMPAT == 0;
    let needs_recovery = incompat & EXT4_FEATURE_INCOMPAT_RECOVER != 0;
    admit_state(read_u16(superblock, 58)?, needs_recovery, admission)?;
    let stored_checksum = read_u32(superblock, 1020)?;
    if stored_checksum != crc32c(u32::MAX, &superblock[..1020]) {
        return Err(FsError::Corrupt);
    }
    let inodes = read_u32(superblock, 0)?;
    let blocks = read_u32(superblock, 4)?;
    let (block_bytes, device_blocks_per_fs_block) =
        parse_block_geometry(superblock, device_block_bytes)?;
    let block_bytes_u32 = u32::try_from(block_bytes).map_err(|_| FsError::Overflow)?;
    let block_bytes_u64 = u64::from(block_bytes_u32);
    let first_data_block = read_u32(superblock, 20)?;
    let blocks_per_group = read_u32(superblock, 32)?;
    let clusters_per_group = read_u32(superblock, 36)?;
    let inodes_per_group = read_u32(superblock, 40)?;
    let journal_inode = read_u32(superblock, 224)?;
    if inodes == 0
        || blocks < 2
        || first_data_block != u32::from(block_bytes == EXT4_MIN_BLOCK_BYTES)
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
    let desc_size = parse_descriptor_size(superblock, incompat)?;
    let checksum_seed = parse_checksum_seed(superblock, incompat, uuid)?;
    Ok(Layout {
        blocks,
        inodes,
        blocks_per_group,
        inodes_per_group,
        first_inode: read_u32(superblock, 84)?,
        groups,
        device_blocks_per_fs_block,
        block_bytes,
        first_data_block,
        block_bytes_u32,
        block_bytes_u64,
        checksum_seed,
        desc_size,
        uuid,
        writable,
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
        .checked_mul(layout.block_bytes_u64 / 512)
        .ok_or(FsError::Overflow)?;
    let inline_symlink = kind == NodeKind::Symlink
        && size <= u64::try_from(EXT4_FAST_SYMLINK_BYTES).map_err(|_| FsError::Overflow)?
        && inode_sectors == symlink_metadata_sectors;
    let parsed_extents = if inline_symlink {
        if flags & EXT4_EXTENTS_FL != 0 {
            return Err(FsError::Corrupt);
        }
        ParsedExtentRoot {
            depth: 0,
            extents: Vec::new(),
            tree_blocks: Vec::new(),
            tree_logicals: Vec::new(),
        }
    } else {
        if flags & EXT4_EXTENTS_FL == 0 {
            return Err(FsError::Corrupt);
        }
        parse_extents(raw.get(40..100).ok_or(FsError::Corrupt)?, layout.blocks)?
    };
    let file_blocks = size
        .checked_add(layout.block_bytes_u64 - 1)
        .ok_or(FsError::Overflow)?
        / layout.block_bytes_u64;
    for extent in &parsed_extents.extents {
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
        indexed: kind == NodeKind::Directory && flags & EXT4_INDEX_FL != 0,
        extents: parsed_extents.extents,
        extent_tree_blocks: parsed_extents.tree_blocks,
        extent_depth: parsed_extents.depth,
        interior_extent_blocks: Vec::new(),
        extent_tree_logicals: parsed_extents.tree_logicals,
        modified_unix_seconds: get_inode_time(raw, EXT4_MTIME)?,
        changed_unix_seconds: get_inode_time(raw, EXT4_CTIME)?,
        created_unix_seconds: get_inode_time(raw, EXT4_CRTIME)?,
    })
}

fn parse_extents(raw: &[u8], volume_blocks: u32) -> Result<ParsedExtentRoot, FsError> {
    if raw.len() != 60
        || read_u16(raw, 0)? != EXT4_EXT_MAGIC
        || read_u16(raw, 4)? != 4
        || read_u32(raw, 8)? != 0
    {
        return Err(FsError::Unsupported);
    }
    let count = read_u16(raw, 2)?;
    let depth = read_u16(raw, 6)?;
    if count > 4 {
        return Err(FsError::Corrupt);
    }
    if depth > EXT4_MAX_EXTENT_DEPTH {
        return Err(FsError::Unsupported);
    }
    if depth >= 1 {
        let mut tree_blocks = Vec::new();
        tree_blocks
            .try_reserve_exact(usize::from(count))
            .map_err(|_| FsError::NoSpace)?;
        let mut tree_logicals = Vec::new();
        tree_logicals
            .try_reserve_exact(usize::from(count))
            .map_err(|_| FsError::NoSpace)?;
        let mut previous_logical = None;
        for index in 0..count {
            let offset = 12 + usize::from(index) * 12;
            let logical = read_u32(raw, offset)?;
            let physical = read_u32(raw, offset + 4)?;
            let physical_high = read_u16(raw, offset + 8)?;
            if physical == 0
                || physical >= volume_blocks
                || physical_high != 0
                || previous_logical.is_some_and(|previous| logical <= previous)
            {
                return Err(FsError::Corrupt);
            }
            previous_logical = Some(logical);
            tree_logicals.push(logical);
            tree_blocks.push(physical);
        }
        return Ok(ParsedExtentRoot {
            depth,
            extents: Vec::new(),
            tree_blocks,
            tree_logicals,
        });
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
    Ok(ParsedExtentRoot {
        depth: 0,
        extents,
        tree_blocks: Vec::new(),
        tree_logicals: Vec::new(),
    })
}

/// Parse one interior extent-tree node into its child logicals and blocks.
///
/// # Errors
///
/// Returns [`FsError::Corrupt`] when the node is malformed and
/// [`FsError::Unsupported`] when it declares a depth outside the tree.
fn parse_extent_index_block(
    raw: &[u8],
    volume_blocks: u32,
    expected_depth: u16,
    seed: u32,
    inode_number: u32,
    inode_generation: u32,
) -> Result<Vec<(u32, u32)>, FsError> {
    if !matches!(raw.len(), 1024 | 2048 | 4096)
        || read_u16(raw, 0)? != EXT4_EXT_MAGIC
        || read_u16(raw, 6)? != expected_depth
        || read_u32(raw, 8)? != 0
    {
        return Err(FsError::Corrupt);
    }
    let capacity =
        (raw.len() - EXT4_EXTENT_HEADER_BYTES - EXT4_EXTENT_TAIL_BYTES) / EXT4_EXTENT_RECORD_BYTES;
    if usize::from(read_u16(raw, 4)?) != capacity {
        return Err(FsError::Corrupt);
    }
    let count = usize::from(read_u16(raw, 2)?);
    if count == 0 || count > capacity {
        return Err(FsError::Corrupt);
    }
    let tail_offset = EXT4_EXTENT_HEADER_BYTES + capacity * EXT4_EXTENT_RECORD_BYTES;
    let inode_seed = crc32c(
        crc32c(seed, &inode_number.to_le_bytes()),
        &inode_generation.to_le_bytes(),
    );
    if read_u32(raw, tail_offset)?
        != crc32c(inode_seed, raw.get(..tail_offset).ok_or(FsError::Corrupt)?)
    {
        return Err(FsError::Corrupt);
    }
    let mut children = Vec::new();
    children
        .try_reserve_exact(count)
        .map_err(|_| FsError::NoSpace)?;
    let mut previous = None;
    for index in 0..count {
        let offset = EXT4_EXTENT_HEADER_BYTES + index * EXT4_EXTENT_RECORD_BYTES;
        let logical = read_u32(raw, offset)?;
        let physical = read_u32(raw, offset + 4)?;
        if physical == 0
            || physical >= volume_blocks
            || read_u16(raw, offset + 8)? != 0
            || previous.is_some_and(|last: u32| logical <= last)
        {
            return Err(FsError::Corrupt);
        }
        previous = Some(logical);
        children.push((logical, physical));
    }
    Ok(children)
}

fn parse_extent_leaf(
    raw: &[u8],
    volume_blocks: u32,
    checksum_seed: u32,
    inode_number: u32,
    inode_generation: u32,
) -> Result<Vec<Extent>, FsError> {
    if !matches!(raw.len(), 1024 | 2048 | 4096)
        || read_u16(raw, 0)? != EXT4_EXT_MAGIC
        || read_u16(raw, 4)?
            != u16::try_from(leaf_extents(raw.len())).map_err(|_| FsError::Overflow)?
        || read_u16(raw, 6)? != 0
        || read_u32(raw, 8)? != 0
    {
        return Err(FsError::Unsupported);
    }
    let count = usize::from(read_u16(raw, 2)?);
    if count == 0 || count > leaf_extents(raw.len()) {
        return Err(FsError::Corrupt);
    }
    // The tail sits after as many records as this block size holds, which is
    // not the same place at every block size the profile reads.
    let tail_offset = extent_tail_offset(raw.len());
    let stored_checksum = read_u32(raw, tail_offset)?;
    let inode_seed = crc32c(
        crc32c(checksum_seed, &inode_number.to_le_bytes()),
        &inode_generation.to_le_bytes(),
    );
    if stored_checksum != crc32c(inode_seed, raw.get(..tail_offset).ok_or(FsError::Corrupt)?) {
        return Err(FsError::Corrupt);
    }
    let mut extents = Vec::new();
    extents
        .try_reserve_exact(count)
        .map_err(|_| FsError::NoSpace)?;
    let mut previous_end = 0_u32;
    for index in 0..count {
        let offset = 12_usize
            .checked_add(index.checked_mul(12).ok_or(FsError::Overflow)?)
            .ok_or(FsError::Overflow)?;
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
    if !matches!(block.len(), 1024 | 2048 | 4096) {
        return Err(FsError::Corrupt);
    }
    let tail_offset = block.len() - EXT4_DIR_TAIL_BYTES;
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
    let tail_offset = block.len() - EXT4_DIR_TAIL_BYTES;
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

/// The shape of one extent tree: how many blocks each level holds.
///
/// Levels run leaves first, so the last entry is the level the inode's own
/// sixty-byte root names directly. An empty plan means the extents fit in the
/// inode with no tree at all.
#[derive(Clone, Debug, Eq, PartialEq)]
struct ExtentTreePlan {
    levels: Vec<usize>,
}

impl ExtentTreePlan {
    /// Plan the shallowest tree that describes this many extents.
    ///
    /// Levels are added until the top one fits in the inode's four records.
    /// A level wider than the read path's tree-block bound, or a tree deeper
    /// than ext4 defines, is refused here rather than written and then found
    /// unreadable.
    fn new(extents: usize, block_bytes: usize) -> Result<Self, FsError> {
        let mut levels = Vec::new();
        if extents <= EXT4_INLINE_EXTENTS {
            return Ok(Self { levels });
        }
        let mut count = extents.div_ceil(leaf_extents(block_bytes));
        loop {
            if count > EXT4_MAX_EXTENT_TREE_BLOCKS
                || levels.len() >= usize::from(EXT4_MAX_EXTENT_DEPTH)
            {
                return Err(FsError::NoSpace);
            }
            levels.try_reserve(1).map_err(|_| FsError::NoSpace)?;
            levels.push(count);
            if count <= EXT4_ROOT_INDEXES {
                return Ok(Self { levels });
            }
            count = count.div_ceil(node_entries(block_bytes));
        }
    }

    /// Depth recorded in the inode's extent header.
    fn depth(&self) -> Result<u16, FsError> {
        u16::try_from(self.levels.len()).map_err(|_| FsError::Overflow)
    }

    /// Blocks the whole tree occupies, across every level.
    fn total_blocks(&self) -> usize {
        self.levels.iter().sum()
    }
}

/// One live directory record, detached from the block it was read out of.
struct DirectoryRecord {
    inode: u32,
    file_type: u8,
    name: Vec<u8>,
}

/// The path the index took to one leaf.
///
/// A split needs more than the leaf: it must place the new separator beside
/// the entry the walk actually followed at each level.
struct HashedPath {
    /// Entries of the index root, in ascending hash order.
    root: Vec<htree::DxEntry>,
    /// Root entry whose subtree covers the hash.
    root_index: usize,
    /// Interior node the walk followed, when the tree has a level of them.
    node: Option<HashedNode>,
    /// Logical block of the leaf the hash maps to.
    leaf: u32,
}

/// One interior index node the walk descended through.
struct HashedNode {
    /// Logical block of the node within the directory.
    logical: u32,
    /// Entries of the node, in ascending hash order.
    entries: Vec<htree::DxEntry>,
    /// Node entry whose leaf covers the hash.
    index: usize,
}

/// How the index must change to describe one more leaf.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct IndexGrowth {
    shape: IndexShape,
    /// Directory blocks the change allocates, the new leaf included.
    blocks: usize,
}

/// The rearrangement one leaf split forces on the levels above it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum IndexShape {
    /// The root addresses leaves directly and has a free slot.
    RootHasRoom,
    /// The root addresses leaves directly and is full, so it gains a level.
    DeepenRoot,
    /// An interior node holds the leaf and has a free slot.
    NodeHasRoom,
    /// An interior node is full, so it splits under a root that has room.
    SplitNode,
}

/// Index of the entry whose subtree covers this hash.
///
/// The first entry covers everything below the second, so a hash lower than
/// every recorded one still resolves rather than falling off the front.
fn covering_entry(entries: &[htree::DxEntry], hash: u32) -> Result<usize, FsError> {
    if entries.is_empty() {
        return Err(FsError::Corrupt);
    }
    let mut chosen = 0_usize;
    for (index, entry) in entries.iter().enumerate() {
        if entry.hash > hash {
            break;
        }
        chosen = index;
    }
    Ok(chosen)
}

/// Insert one separator directly after the entry its subtree was split from.
fn insert_index_entry(
    entries: &mut Vec<htree::DxEntry>,
    after: usize,
    entry: htree::DxEntry,
) -> Result<(), FsError> {
    let position = after.checked_add(1).ok_or(FsError::Overflow)?;
    if entries
        .get(after)
        .is_none_or(|left| left.hash >= entry.hash)
        || entries
            .get(position)
            .is_some_and(|right| right.hash <= entry.hash)
    {
        return Err(FsError::Corrupt);
    }
    entries.try_reserve(1).map_err(|_| FsError::NoSpace)?;
    entries.insert(position, entry);
    Ok(())
}

/// Split point that divides a leaf's records most evenly by bytes.
///
/// Two records with the same hash must stay in the same leaf, because the
/// index can only send one hash to one place, so only a strict hash change is
/// a candidate. A leaf whose records all share one hash has no split point at
/// all and says so rather than producing a leaf the index cannot address.
fn balanced_hash_boundary(records: &[(u32, DirectoryRecord)]) -> Result<usize, FsError> {
    let mut total = 0_usize;
    for (_, record) in records {
        total = total
            .checked_add(directory_record_bytes(record.name.len())?)
            .ok_or(FsError::Overflow)?;
    }
    let target = total / 2;
    let mut used = 0_usize;
    let mut best: Option<(usize, usize)> = None;
    for (index, (hash, record)) in records.iter().enumerate() {
        if index != 0 && *hash != records.get(index - 1).ok_or(FsError::Corrupt)?.0 {
            let distance = used.abs_diff(target);
            if best.is_none_or(|(_, closest)| distance < closest) {
                best = Some((index, distance));
            }
        }
        used = used
            .checked_add(directory_record_bytes(record.name.len())?)
            .ok_or(FsError::Overflow)?;
    }
    best.map(|(index, _)| index).ok_or(FsError::NoSpace)
}

/// Collect the live records of one directory block.
fn read_directory_records(block: &[u8]) -> Result<Vec<DirectoryRecord>, FsError> {
    let tail_offset = block
        .len()
        .checked_sub(EXT4_DIR_TAIL_BYTES)
        .ok_or(FsError::Corrupt)?;
    let mut records = Vec::new();
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
            let raw = block
                .get(offset + 8..offset + 8 + name_bytes)
                .ok_or(FsError::Corrupt)?;
            let mut name = Vec::new();
            name.try_reserve_exact(raw.len())
                .map_err(|_| FsError::NoSpace)?;
            name.extend_from_slice(raw);
            records.try_reserve(1).map_err(|_| FsError::NoSpace)?;
            records.push(DirectoryRecord {
                inode,
                file_type,
                name,
            });
        }
        offset = offset.checked_add(record_bytes).ok_or(FsError::Overflow)?;
    }
    if offset != tail_offset {
        return Err(FsError::Corrupt);
    }
    Ok(records)
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
    if !matches!(block.len(), 1024 | 2048 | 4096) {
        return Err(FsError::Invalid);
    }
    let offset = block.len() - EXT4_DIR_TAIL_BYTES;
    let tail = &mut block[offset..];
    tail.fill(0);
    put_u16(tail, 4, EXT4_DIR_TAIL_BYTES_U16)?;
    tail[7] = EXT4_DIR_TAIL_FT;
    Ok(())
}

fn refresh_directory_checksum(seed: u32, inode: &Inode, block: &mut [u8]) -> Result<(), FsError> {
    if !matches!(block.len(), 1024 | 2048 | 4096) {
        return Err(FsError::Invalid);
    }
    let tail_offset = block.len() - EXT4_DIR_TAIL_BYTES;
    let inode_seed = crc32c(
        crc32c(seed, &inode.number.to_le_bytes()),
        &inode.generation.to_le_bytes(),
    );
    let checksum = crc32c(inode_seed, &block[..tail_offset]);
    put_u32(block, tail_offset + 8, checksum)
}

/// Read an exact device-block span without assuming a filesystem block size.
fn read_raw_device_span<D: BlockDevice>(
    region: &mut BlockRegion<D>,
    start_block: u64,
    device_blocks: u32,
    bytes_wanted: usize,
) -> Result<Vec<u8>, FsError> {
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(bytes_wanted)
        .map_err(|_| FsError::NoSpace)?;
    bytes.resize(bytes_wanted, 0);
    region
        .read_blocks(start_block, device_blocks, &mut bytes)
        .map_err(map_block_error)?;
    Ok(bytes)
}

fn read_raw_fs_block<D: BlockDevice>(
    region: &mut BlockRegion<D>,
    fs_block: u32,
    device_blocks_per_fs_block: u32,
    block_bytes: usize,
) -> Result<Vec<u8>, FsError> {
    let start = u64::from(fs_block)
        .checked_mul(u64::from(device_blocks_per_fs_block))
        .ok_or(FsError::Overflow)?;
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(block_bytes)
        .map_err(|_| FsError::NoSpace)?;
    bytes.resize(block_bytes, 0);
    region
        .read_blocks(start, device_blocks_per_fs_block, &mut bytes)
        .map_err(map_block_error)?;
    Ok(bytes)
}

/// Map one block-capability failure without collapsing distinct conditions.
///
/// The match is exhaustive on purpose. A wildcard arm silently turns every
/// block condition added later into `Io`, which is how a bounded-wait expiry
/// became indistinguishable from a device-reported read failure.
const fn map_block_error(error: BlockError) -> FsError {
    match error {
        BlockError::ReadOnly => FsError::ReadOnly,
        BlockError::Unsupported => FsError::Unsupported,
        BlockError::Timeout => FsError::Timeout,
        BlockError::InvalidGeometry
        | BlockError::InvalidLimits
        | BlockError::InvalidRegion
        | BlockError::EmptyTransfer
        | BlockError::Misaligned
        | BlockError::OutOfBounds
        | BlockError::TransferTooLarge
        | BlockError::BufferLength
        | BlockError::Device => FsError::Io,
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

/// Write one inode timestamp as its 32-bit base field and its epoch bits.
///
/// ext4 reads the base field as signed, so a record that declares no room for
/// the extra word cannot carry an instant past 2038 without reading as 1901.
/// The clock is therefore clamped to whatever the record can actually encode,
/// which keeps a far-future time implausible rather than wrong by a century.
/// Read one inode timestamp, or `None` when it was never stamped.
///
/// The 32-bit base field is extended past 2038 by the low two bits of the
/// record's extra word, so a record that declares room for that word is read
/// with them and one that does not is read without. A zero is an absent time
/// rather than 1970: ADR 0058 leaves the fields it would write untouched
/// whenever no wall time is known, so zero is exactly what "never stamped"
/// looks like.
fn get_inode_time(raw: &[u8], field: (usize, usize)) -> Result<Option<u64>, FsError> {
    let (base, extra) = field;
    let declared = EXT4_BASE_INODE_BYTES
        .checked_add(usize::from(read_u16(raw, EXT4_EXTRA_ISIZE_OFFSET)?))
        .ok_or(FsError::Overflow)?;
    let mut seconds = u64::from(read_u32(raw, base)?);
    if extra.checked_add(4).ok_or(FsError::Overflow)? <= declared {
        seconds |= u64::from(read_u32(raw, extra)? & 0x3) << 32;
    }
    Ok(if seconds == 0 { None } else { Some(seconds) })
}

fn put_inode_time(raw: &mut [u8], field: (usize, usize), seconds: u64) -> Result<(), FsError> {
    let (base, extra) = field;
    let declared = EXT4_BASE_INODE_BYTES
        .checked_add(usize::from(read_u16(raw, EXT4_EXTRA_ISIZE_OFFSET)?))
        .ok_or(FsError::Overflow)?;
    let extended = extra.checked_add(4).ok_or(FsError::Overflow)? <= declared;
    let seconds = seconds.min(if extended {
        EXT4_MAX_EXTENDED_SECONDS
    } else {
        EXT4_MAX_BASE_SECONDS
    });
    put_u32(
        raw,
        base,
        u32::try_from(seconds & u64::from(u32::MAX)).map_err(|_| FsError::Overflow)?,
    )?;
    if !extended {
        return Ok(());
    }
    let epoch = u32::try_from(seconds >> 32).map_err(|_| FsError::Overflow)?;
    // The extra word also carries nanoseconds above its low two bits, so the
    // epoch is merged in rather than overwriting the whole field.
    put_u32(raw, extra, (read_u32(raw, extra)? & !0x3) | epoch)
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
    use crate::journal::{JBD2_COMMIT_BLOCK, JBD2_DESCRIPTOR_BLOCK, JBD2_MAGIC};
    use crate::{
        EXT4_CRTIME, EXT4_DX_PARENT_OFFSET, EXT4_EXT_MAGIC, EXT4_EXTENT_HEADER_BYTES,
        EXT4_EXTENT_RECORD_BYTES, EXT4_EXTENT_TAIL_BYTES, EXT4_MAX_EXTENT_DEPTH, EXT4_MTIME,
        ExtentTreePlan, htree, parse_directory_block, parse_extent_index_block,
    };
    use alloc::collections::BTreeMap;
    use alloc::format;
    use alloc::rc::Rc;
    use alloc::string::{String, ToString};
    use alloc::vec;
    use alloc::vec::Vec;
    use std::fmt::Write as _;
    use std::fs::{self, File, OpenOptions};
    use std::io::{Read, Seek, SeekFrom, Write};
    use std::path::{Path, PathBuf};
    use std::process::{Command, Output};
    use std::time::{SystemTime, UNIX_EPOCH};
    use troe_block::{BlockAccess, BlockError, BlockGeometry, BlockLimits};
    use troe_fs_api::{MAX_NAME_BYTES, WallClock};

    use super::{
        BlockDevice, BlockRegion, CRC32C_POLYNOMIAL, EXT4_BLOCK_BYTES, EXT4_BLOCK_BYTES_U32,
        EXT4_BLOCK_BYTES_U64, EXT4_COMPAT_DIR_INDEX, EXT4_EXTENT_TAIL_OFFSET, EXT4_EXTENTS_FL,
        EXT4_FAST_SYMLINK_BYTES, EXT4_FEATURE_COMPAT, EXT4_FEATURE_INCOMPAT,
        EXT4_FEATURE_RO_COMPAT, EXT4_INCOMPAT_EXTENTS, EXT4_INDEX_FL, EXT4_INODE_BYTES,
        EXT4_JOURNAL_INO, EXT4_RO_COMPAT_METADATA_CSUM, EXT4_ROOT_INO, EXT4_VALID_FS, Ext4,
        Ext4Limits, Extent, FileSystemProvider, FsError, HARD_MAX_GROUPS, NodeKind,
        RecoveryOutcome, crc32c, parse_extent_leaf, parse_extents, read_u16, read_u32,
    };

    const DEVICE_BLOCK_BYTES_U32: u32 = 512;
    const DEVICE_BLOCK_BYTES_USIZE: usize = 512;
    const DEVICE_BLOCKS_PER_FS_BLOCK: u32 = 8;
    const FS_BLOCKS: u32 = 64;
    const BLOCK_BITMAP_BYTES: usize = FS_BLOCKS as usize / 8;
    const JOURNAL_FIRST_BLOCK: u32 = 8;
    const JOURNAL_BLOCKS: u16 = 16;
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

    /// A device that models a volatile write-back cache and injectable faults.
    ///
    /// Writes land in a volatile cache and become durable only at a flush, so
    /// unbarriered writes have no ordering, exactly like a real disk. A power
    /// loss discards whatever has not been flushed. Faults can fail the Nth
    /// write or flush, or tear one write so that only a prefix of its sectors
    /// reaches media.
    ///
    /// A torn write models one that was landing on the platter when power was
    /// lost rather than one sitting in the cache: the sectors that made it are
    /// durable immediately, the rest never happen, and no flush ever
    /// reconciles the two halves. A tear whose prefix would cover the whole
    /// request is an ordinary cached write.
    #[derive(Debug, Clone)]
    struct PowerLossDevice {
        geometry: BlockGeometry,
        durable: BTreeMap<u64, [u8; DEVICE_BLOCK_BYTES_USIZE]>,
        pending: BTreeMap<u64, [u8; DEVICE_BLOCK_BYTES_USIZE]>,
        blocks: u64,
        writes: usize,
        flushes: usize,
        fail_write_at: Option<usize>,
        fail_flush_at: Option<usize>,
        tear_write_at: Option<(usize, u32)>,
        /// Block condition the next read reports instead of its sectors, so a
        /// test can name the exact failure the transport would have raised.
        fail_read_with: Option<BlockError>,
        /// Start block and leading eight bytes of every write in issue order,
        /// so a test names a boundary by what the provider was writing rather
        /// than by a hardcoded index.
        issued: Vec<(u64, [u8; 8])>,
    }

    impl PowerLossDevice {
        fn new(blocks: u64) -> Result<Self, BlockError> {
            Ok(Self {
                geometry: BlockGeometry::new(DEVICE_BLOCK_BYTES_U32, blocks, 1, true, false)?,
                durable: BTreeMap::new(),
                pending: BTreeMap::new(),
                blocks,
                writes: 0,
                flushes: 0,
                fail_write_at: None,
                fail_flush_at: None,
                tear_write_at: None,
                fail_read_with: None,
                issued: Vec::new(),
            })
        }

        /// Discard every write that has not reached durable media.
        fn power_loss(&mut self) {
            self.pending.clear();
        }

        /// Count the writes and flushes one operation performs.
        fn counts(&self) -> (usize, usize) {
            (self.writes, self.flushes)
        }

        /// Start fault counting from the next operation.
        fn reset_counts(&mut self) {
            self.writes = 0;
            self.flushes = 0;
            self.issued.clear();
        }

        /// Every durable sector in device-block order, unwritten blocks zero.
        fn durable_image(&self) -> Vec<u8> {
            let blocks = usize::try_from(DEVICE_BLOCKS).unwrap_or_else(|_| unreachable!());
            let mut image = vec![0_u8; blocks * DEVICE_BLOCK_BYTES_USIZE];
            for (block, sector) in &self.durable {
                let start = usize::try_from(*block).unwrap_or_else(|_| unreachable!())
                    * DEVICE_BLOCK_BYTES_USIZE;
                image[start..start + DEVICE_BLOCK_BYTES_USIZE].copy_from_slice(sector);
            }
            image
        }

        /// The durable bytes of one filesystem block.
        fn durable_fs_block(&self, block: u32) -> Vec<u8> {
            let start = block as usize * EXT4_BLOCK_BYTES;
            self.durable_image()[start..start + EXT4_BLOCK_BYTES].to_vec()
        }

        fn sector(&self, block: u64) -> [u8; DEVICE_BLOCK_BYTES_USIZE] {
            self.pending
                .get(&block)
                .or_else(|| self.durable.get(&block))
                .copied()
                .unwrap_or([0; DEVICE_BLOCK_BYTES_USIZE])
        }
    }

    impl BlockDevice for PowerLossDevice {
        fn geometry(&self) -> BlockGeometry {
            self.geometry
        }

        fn read_blocks(
            &mut self,
            start_block: u64,
            block_count: u32,
            destination: &mut [u8],
        ) -> Result<(), BlockError> {
            let expected = usize::try_from(block_count)
                .ok()
                .and_then(|count| count.checked_mul(DEVICE_BLOCK_BYTES_USIZE))
                .ok_or(BlockError::Device)?;
            if destination.len() != expected
                || start_block
                    .checked_add(u64::from(block_count))
                    .is_none_or(|end| end > self.blocks)
            {
                return Err(BlockError::Device);
            }
            if let Some(error) = self.fail_read_with.take() {
                return Err(error);
            }
            for index in 0..u64::from(block_count) {
                let sector = self.sector(start_block + index);
                let offset = usize::try_from(index)
                    .ok()
                    .and_then(|value| value.checked_mul(DEVICE_BLOCK_BYTES_USIZE))
                    .ok_or(BlockError::Device)?;
                destination
                    .get_mut(offset..offset + DEVICE_BLOCK_BYTES_USIZE)
                    .ok_or(BlockError::Device)?
                    .copy_from_slice(&sector);
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
            let expected = usize::try_from(block_count)
                .ok()
                .and_then(|count| count.checked_mul(DEVICE_BLOCK_BYTES_USIZE))
                .ok_or(BlockError::Device)?;
            if source.len() != expected
                || force_unit_access
                || start_block
                    .checked_add(u64::from(block_count))
                    .is_none_or(|end| end > self.blocks)
            {
                return Err(BlockError::Device);
            }
            self.writes += 1;
            let mut head = [0_u8; 8];
            head.copy_from_slice(source.get(..8).ok_or(BlockError::Device)?);
            self.issued.push((start_block, head));
            if self.fail_write_at == Some(self.writes) {
                return Err(BlockError::Device);
            }
            let persisted = match self.tear_write_at {
                Some((index, sectors)) if index == self.writes => sectors.min(block_count),
                _ => block_count,
            };
            let torn = persisted != block_count;
            for index in 0..u64::from(persisted) {
                let offset = usize::try_from(index)
                    .ok()
                    .and_then(|value| value.checked_mul(DEVICE_BLOCK_BYTES_USIZE))
                    .ok_or(BlockError::Device)?;
                let mut sector = [0_u8; DEVICE_BLOCK_BYTES_USIZE];
                sector.copy_from_slice(
                    source
                        .get(offset..offset + DEVICE_BLOCK_BYTES_USIZE)
                        .ok_or(BlockError::Device)?,
                );
                if torn {
                    self.durable.insert(start_block + index, sector);
                } else {
                    self.pending.insert(start_block + index, sector);
                }
            }
            if torn {
                return Err(BlockError::Device);
            }
            Ok(())
        }

        fn flush(&mut self) -> Result<(), BlockError> {
            self.flushes += 1;
            if self.fail_flush_at == Some(self.flushes) {
                return Err(BlockError::Device);
            }
            for (block, sector) in core::mem::take(&mut self.pending) {
                self.durable.insert(block, sector);
            }
            Ok(())
        }
    }

    /// A cloneable handle so a test can inspect and fault a mounted device.
    #[derive(Debug, Clone)]
    struct SharedDevice(std::rc::Rc<core::cell::RefCell<PowerLossDevice>>);

    impl SharedDevice {
        fn new(device: PowerLossDevice) -> Self {
            Self(std::rc::Rc::new(core::cell::RefCell::new(device)))
        }

        fn device(&self) -> core::cell::RefMut<'_, PowerLossDevice> {
            self.0.borrow_mut()
        }
    }

    impl BlockDevice for SharedDevice {
        fn geometry(&self) -> BlockGeometry {
            self.0.borrow().geometry
        }

        fn read_blocks(
            &mut self,
            start_block: u64,
            block_count: u32,
            destination: &mut [u8],
        ) -> Result<(), BlockError> {
            self.0
                .borrow_mut()
                .read_blocks(start_block, block_count, destination)
        }

        fn write_blocks(
            &mut self,
            start_block: u64,
            block_count: u32,
            source: &[u8],
            force_unit_access: bool,
        ) -> Result<(), BlockError> {
            self.0
                .borrow_mut()
                .write_blocks(start_block, block_count, source, force_unit_access)
        }

        fn flush(&mut self) -> Result<(), BlockError> {
            self.0.borrow_mut().flush()
        }
    }

    /// A device that offers force unit access and no cache flush.
    ///
    /// Nothing in this system produces one: virtio-blk, the only block
    /// transport, has no per-request force-unit-access flag to negotiate, so
    /// the geometry exists only to prove the provider refuses it rather than
    /// mutating a volume whose durability barriers would all be no-ops.
    #[derive(Debug)]
    struct ForceUnitAccessDevice(SparseDevice);

    impl BlockDevice for ForceUnitAccessDevice {
        fn geometry(&self) -> BlockGeometry {
            BlockGeometry::new(DEVICE_BLOCK_BYTES_U32, DEVICE_BLOCKS, 1, false, true)
                .unwrap_or_else(|_| unreachable!())
        }

        fn read_blocks(
            &mut self,
            start_block: u64,
            block_count: u32,
            destination: &mut [u8],
        ) -> Result<(), BlockError> {
            self.0.read_blocks(start_block, block_count, destination)
        }

        fn write_blocks(
            &mut self,
            start_block: u64,
            block_count: u32,
            source: &[u8],
            force_unit_access: bool,
        ) -> Result<(), BlockError> {
            self.0
                .write_blocks(start_block, block_count, source, force_unit_access)
        }

        fn flush(&mut self) -> Result<(), BlockError> {
            Err(BlockError::Unsupported)
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

    #[test]
    fn depth_one_extent_metadata_describes_two_gib_without_payload_staging() -> Result<(), FsError>
    {
        let mut extents = Vec::new();
        for index in 0..16_u32 {
            extents.push(Extent {
                logical: index * 0x8000,
                physical: 10 + index * 0x8000,
                blocks: 0x8000,
                unwritten: false,
            });
        }
        let mut raw = [0_u8; EXT4_INODE_BYTES];
        let tree = ExtentTreePlan::new(extents.len(), EXT4_BLOCK_BYTES)?;
        assert_eq!(tree.levels, [1]);
        Ext4::<SparseDevice>::encode_inode_extent_records(
            &mut raw,
            2 * 1024 * 1024 * 1024,
            &extents,
            &[(0, 600_000)],
            &tree,
            0,
            EXT4_BLOCK_BYTES,
        )?;
        let root = parse_extents(&raw[40..100], 700_000)?;
        assert_eq!(root.tree_blocks, [600_000]);
        assert_eq!(root.tree_logicals, [0]);

        let mut leaf = [0_u8; EXT4_BLOCK_BYTES];
        let seed = crc32c(u32::MAX, &UUID);
        Ext4::<SparseDevice>::encode_extent_leaf(&mut leaf, &extents, seed, 3, FILE_GENERATION)?;
        assert_eq!(
            parse_extent_leaf(&leaf, 700_000, seed, 3, FILE_GENERATION)?,
            extents
        );
        leaf[EXT4_EXTENT_TAIL_OFFSET] ^= 1;
        assert_eq!(
            parse_extent_leaf(&leaf, 700_000, seed, 3, FILE_GENERATION),
            Err(FsError::Corrupt)
        );
        Ok(())
    }

    fn mount(device: SparseDevice) -> Result<Ext4<SparseDevice>, FsError> {
        let block_limits = BlockLimits::new(8, EXT4_BLOCK_BYTES, 1).map_err(|_| FsError::Io)?;
        let region = BlockRegion::whole_device(device, BlockAccess::ReadOnly, block_limits)
            .map_err(|_| FsError::Io)?;
        Ext4::mount(region, limits()?)
    }

    fn mount_writable(device: SparseDevice) -> Result<Ext4<SparseDevice>, FsError> {
        mount_device_writable(device)
    }

    fn mount_device_writable<D: BlockDevice>(device: D) -> Result<Ext4<D>, FsError> {
        let block_limits = BlockLimits::new(8, EXT4_BLOCK_BYTES, 1).map_err(|_| FsError::Io)?;
        let region = BlockRegion::whole_device(device, BlockAccess::ReadWrite, block_limits)
            .map_err(|_| FsError::Io)?;
        Ext4::mount(region, limits()?)
    }

    /// Seed a power-loss device with the same valid image the other tests use.
    fn power_loss_device() -> Result<SharedDevice, FsError> {
        let source = valid_device();
        let mut device = PowerLossDevice::new(DEVICE_BLOCKS).map_err(|_| FsError::Io)?;
        for (fs_block, bytes) in &source.blocks {
            let base = u64::from(*fs_block) * u64::from(DEVICE_BLOCKS_PER_FS_BLOCK);
            for index in 0..DEVICE_BLOCKS_PER_FS_BLOCK {
                let offset = index as usize * DEVICE_BLOCK_BYTES_USIZE;
                let mut sector = [0_u8; DEVICE_BLOCK_BYTES_USIZE];
                sector.copy_from_slice(
                    bytes
                        .get(offset..offset + DEVICE_BLOCK_BYTES_USIZE)
                        .ok_or(FsError::Io)?,
                );
                device.durable.insert(base + u64::from(index), sector);
            }
        }
        Ok(SharedDevice::new(device))
    }

    fn mount_file_with_limits(path: &Path, limits: Ext4Limits) -> Result<Ext4<FileDevice>, String> {
        let device = FileDevice::open(path)?;
        let block_limits = BlockLimits::new(8, EXT4_BLOCK_BYTES, 1)
            .map_err(|error| format!("invalid block limits: {error:?}"))?;
        let region = BlockRegion::whole_device(device, BlockAccess::ReadOnly, block_limits)
            .map_err(|error| format!("cannot grant image region: {error:?}"))?;
        Ext4::mount(region, limits).map_err(|error| format!("cannot mount: {error:?}"))
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
        mount_file_writable_with_limits(path, limits().map_err(|error| error.to_string())?)
    }

    fn mount_file_writable_with_limits(
        path: &Path,
        limits: Ext4Limits,
    ) -> Result<Ext4<FileDevice>, String> {
        let device = FileDevice::open_writable(path)?;
        let block_limits = BlockLimits::new(8, EXT4_BLOCK_BYTES, 1)
            .map_err(|error| format!("invalid block limits: {error:?}"))?;
        let region = BlockRegion::whole_device(device, BlockAccess::ReadWrite, block_limits)
            .map_err(|error| format!("cannot grant writable image region: {error:?}"))?;
        Ext4::mount(region, limits).map_err(|error| error.to_string())
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
        put_u32(superblock, 12, 40);
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
        block_bitmap[..BLOCK_BITMAP_BYTES].fill(0);
        let journal_last = JOURNAL_FIRST_BLOCK + u32::from(JOURNAL_BLOCKS) - 1;
        for block in 0_u32..=journal_last {
            let bit = usize::try_from(block).unwrap_or_else(|_| unreachable!());
            block_bitmap[bit / 8] |= 1 << (bit % 8);
        }
        let block_bitmap_checksum = crc32c(seed, &block_bitmap[..BLOCK_BITMAP_BYTES]);
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
        put_u16(&mut descriptor_block, 12, 40);
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

        blocks.insert(JOURNAL_FIRST_BLOCK, journal_superblock_image());

        SparseDevice { blocks }
    }

    fn valid_device_with_file_xattr() -> SparseDevice {
        let seed = crc32c(u32::MAX, &UUID);
        let mut device = valid_device();
        let xattr_block = FS_BLOCKS - 1;

        let bitmap = device.blocks.get_mut(&7).unwrap_or_else(|| unreachable!());
        let bit = usize::try_from(xattr_block).unwrap_or_else(|_| unreachable!());
        bitmap[bit / 8] |= 1 << (bit % 8);
        let bitmap_checksum = crc32c(seed, &bitmap[..BLOCK_BITMAP_BYTES]);

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

    /// Build the clean, empty internal journal `mke2fs` writes at format time.
    fn journal_superblock_image() -> [u8; EXT4_BLOCK_BYTES] {
        let mut block = [0_u8; EXT4_BLOCK_BYTES];
        block[0..4].copy_from_slice(&0xC03B_3998_u32.to_be_bytes());
        block[4..8].copy_from_slice(&4_u32.to_be_bytes());
        block[0x0C..0x10].copy_from_slice(&EXT4_BLOCK_BYTES_U32.to_be_bytes());
        block[0x10..0x14].copy_from_slice(&u32::from(JOURNAL_BLOCKS).to_be_bytes());
        block[0x14..0x18].copy_from_slice(&1_u32.to_be_bytes());
        block[0x18..0x1C].copy_from_slice(&1_u32.to_be_bytes());
        block[0x1C..0x20].copy_from_slice(&0_u32.to_be_bytes());
        block[0x30..0x40].copy_from_slice(&UUID);
        block[0x40..0x44].copy_from_slice(&1_u32.to_be_bytes());
        block
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
        inode(
            &mut inode_table[1792..2048],
            EXT4_JOURNAL_INO,
            0,
            0x8000 | 0o600,
            u64::from(JOURNAL_BLOCKS) * EXT4_BLOCK_BYTES_U64,
            Some((0, JOURNAL_FIRST_BLOCK, JOURNAL_BLOCKS)),
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

        // An incompatible feature this provider does not implement changes
        // structure it would misread, so the volume is refused outright.
        // 0x10000 is `encrypt`.
        let mut feature = valid_device();
        let superblock = &mut feature.blocks.get_mut(&0).ok_or(FsError::Io)?[1024..2048];
        put_u32(superblock, 96, EXT4_FEATURE_INCOMPAT | 0x0001_0000);
        refresh_super_checksum(&mut feature);
        assert!(matches!(mount(feature), Err(FsError::Unsupported)));

        // Dropping a structural feature this provider depends on is also
        // refused rather than guessed at.
        for (offset, value) in [
            (96_usize, EXT4_FEATURE_INCOMPAT & !EXT4_INCOMPAT_EXTENTS),
            (100, EXT4_FEATURE_RO_COMPAT & !EXT4_RO_COMPAT_METADATA_CSUM),
        ] {
            let mut missing = valid_device();
            let superblock = &mut missing.blocks.get_mut(&0).ok_or(FsError::Io)?[1024..2048];
            put_u32(superblock, offset, value);
            refresh_super_checksum(&mut missing);
            assert!(matches!(mount(missing), Err(FsError::Unsupported)));
        }

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
    fn an_unknown_read_only_feature_keeps_the_volume_readable_but_untouched() -> Result<(), FsError>
    {
        // `bigalloc` (0x200) changes only how a writer must allocate, so the
        // volume must stay readable and must never be mutated.
        let mut device = valid_device();
        let superblock = &mut device.blocks.get_mut(&0).ok_or(FsError::Io)?[1024..2048];
        put_u32(superblock, 100, EXT4_FEATURE_RO_COMPAT | 0x0000_0200);
        refresh_super_checksum(&mut device);

        let mut ext4 = mount_writable(device)?;
        let mut bytes = [0_u8; 13];
        assert_eq!(ext4.read_file("/hello", 0, &mut bytes)?, 13);
        assert_eq!(
            ext4.write_file("/blocked.txt", b"nope"),
            Err(FsError::ReadOnly),
            "an unmaintainable feature must block every mutation"
        );
        assert_eq!(ext4.remove_file("/hello"), Err(FsError::ReadOnly));
        assert_eq!(ext4.create_directory("/nope"), Err(FsError::ReadOnly));
        Ok(())
    }

    #[test]
    fn a_device_without_flush_is_refused_even_when_it_offers_force_unit_access()
    -> Result<(), FsError> {
        // Every ordering guarantee this provider makes is a flush. Admitting a
        // flush-incapable device on a force-unit-access claim would turn each
        // durability barrier into a no-op, so mutation is refused outright
        // while the read path stays unaffected.
        let block_limits = BlockLimits::new(8, EXT4_BLOCK_BYTES, 1).map_err(|_| FsError::Io)?;
        let region = BlockRegion::whole_device(
            ForceUnitAccessDevice(valid_device()),
            BlockAccess::ReadWrite,
            block_limits,
        )
        .map_err(|_| FsError::Io)?;
        let mut ext4 = Ext4::mount(region, limits()?)?;
        let mut bytes = [0_u8; 13];
        assert_eq!(ext4.read_file("/hello", 0, &mut bytes)?, 13);
        for outcome in [
            ext4.write_file("/blocked.txt", b"nope"),
            ext4.remove_file("/hello"),
            ext4.create_directory("/nope"),
        ] {
            assert_eq!(outcome, Err(FsError::Unsupported));
        }
        Ok(())
    }

    #[test]
    fn a_directory_claiming_an_index_it_lacks_is_refused() -> Result<(), FsError> {
        // The feature only says indexed directories may exist, so a volume
        // carrying it stays writable.
        let mut device = valid_device();
        let superblock = &mut device.blocks.get_mut(&0).ok_or(FsError::Io)?[1024..2048];
        put_u32(superblock, 92, EXT4_FEATURE_COMPAT | EXT4_COMPAT_DIR_INDEX);
        refresh_super_checksum(&mut device);
        let mut ext4 = mount_writable(device)?;
        ext4.write_file("/created.txt", b"still writable")?;

        // A directory flagged as indexed whose block is an ordinary linear
        // directory is refused rather than misread as an index.
        let mut indexed = valid_device();
        let superblock = &mut indexed.blocks.get_mut(&0).ok_or(FsError::Io)?[1024..2048];
        put_u32(superblock, 92, EXT4_FEATURE_COMPAT | EXT4_COMPAT_DIR_INDEX);
        refresh_super_checksum(&mut indexed);
        let seed = crc32c(u32::MAX, &UUID);
        let table = indexed
            .blocks
            .get_mut(&INODE_TABLE_BLOCK)
            .ok_or(FsError::Io)?;
        let root = table.get_mut(256..512).ok_or(FsError::Io)?;
        put_u32(root, 32, read_u32(root, 32)? | EXT4_INDEX_FL);
        refresh_test_inode_checksum(root, EXT4_ROOT_INO, ROOT_GENERATION, seed);
        assert!(matches!(mount(indexed), Err(FsError::Corrupt)));
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
    fn append_extends_the_existing_partial_final_block() -> Result<(), FsError> {
        let mut ext4 = mount_writable(valid_device_with_file_xattr())?;
        ext4.truncate_file("/partial")?;
        ext4.append_file("/partial", b"prefix")?;
        ext4.append_file("/partial", b"-tail")?;
        ext4.sync_file("/partial")?;
        assert_eq!(ext4.metadata("/partial")?.byte_count, 11);
        let mut content = [0_u8; 11];
        assert_eq!(ext4.read_file("/partial", 0, &mut content)?, 11);
        assert_eq!(&content, b"prefix-tail");
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
    fn renames_all_node_kinds_and_removes_only_empty_directories() -> Result<(), FsError> {
        let mut ext4 = mount_writable(valid_device())?;
        ext4.rename("/hello", "/renamed")?;
        assert_eq!(ext4.metadata("/hello"), Err(FsError::NotFound));
        assert_eq!(ext4.metadata("/renamed")?.byte_count, 4101);
        ext4.create_symlink("/renamed", "/link")?;
        ext4.rename("/link", "/moved-link")?;
        assert_eq!(ext4.read_link("/moved-link")?, "/renamed");
        ext4.create_directory("/tree")?;
        ext4.write_file("/tree/member", b"member")?;
        assert_eq!(ext4.remove_directory("/tree"), Err(FsError::NotEmpty));
        ext4.rename("/tree", "/sub/moved")?;
        assert_eq!(ext4.metadata("/sub/moved/member")?.byte_count, 6);
        assert_eq!(
            ext4.rename("/sub/moved", "/sub/moved/member/loop"),
            Err(FsError::Invalid)
        );
        ext4.remove_file("/sub/moved/member")?;
        ext4.remove_directory("/sub/moved")?;
        assert_eq!(ext4.metadata("/sub/moved"), Err(FsError::NotFound));
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
        assert_eq!(ext4.remove_directory("/sub"), Err(FsError::ReadOnly));
        assert_eq!(ext4.rename("/hello", "/renamed"), Err(FsError::ReadOnly));
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

    fn recover_device<D: BlockDevice>(device: D) -> Result<(Ext4<D>, RecoveryOutcome), FsError> {
        let block_limits = BlockLimits::new(8, EXT4_BLOCK_BYTES, 1).map_err(|_| FsError::Io)?;
        let region = BlockRegion::whole_device(device, BlockAccess::ReadWrite, block_limits)
            .map_err(|_| FsError::Io)?;
        Ext4::recover(region, limits()?)
    }

    /// One durable image with the log blanked, so two images compare on
    /// filesystem state alone rather than on log scratch space.
    fn outside_log(image: &[u8]) -> Vec<u8> {
        let mut copy = image.to_vec();
        let start = JOURNAL_FIRST_BLOCK as usize * EXT4_BLOCK_BYTES;
        copy[start..start + JOURNAL_BLOCKS as usize * EXT4_BLOCK_BYTES].fill(0);
        copy
    }

    /// Assert two durable images agree, naming the blocks that differ.
    fn assert_same_blocks(actual: &[u8], expected: &[u8], label: &str) {
        let differing = (0..actual.len() / EXT4_BLOCK_BYTES)
            .filter(|block| {
                let start = block * EXT4_BLOCK_BYTES;
                actual[start..start + EXT4_BLOCK_BYTES] != expected[start..start + EXT4_BLOCK_BYTES]
            })
            .collect::<Vec<_>>();
        assert!(differing.is_empty(), "{label}: blocks {differing:?} differ");
    }

    /// One journal block header: the magic followed by its block type.
    fn journal_head(block_type: u32) -> [u8; 8] {
        let mut head = [0_u8; 8];
        head[..4].copy_from_slice(&JBD2_MAGIC.to_be_bytes());
        head[4..].copy_from_slice(&block_type.to_be_bytes());
        head
    }

    const fn device_block_of(fs_block: u32) -> u64 {
        fs_block as u64 * DEVICE_BLOCKS_PER_FS_BLOCK as u64
    }

    /// A create and the two byte-exact media states it moves between.
    struct TornWriteFixture {
        /// Every durable byte before the mutation.
        before: Vec<u8>,
        /// Every durable byte after the same mutation completes uninterrupted.
        after: Vec<u8>,
        /// Start block and leading eight bytes of each write it issued.
        issued: Vec<(u64, [u8; 8])>,
    }

    impl TornWriteFixture {
        /// The one-based index of the first write matching `predicate`.
        fn first_write<P>(&self, predicate: P) -> Option<usize>
        where
            P: Fn(u64, &[u8; 8]) -> bool,
        {
            self.issued
                .iter()
                .position(|(block, head)| predicate(*block, head))
                .map(|index| index + 1)
        }

        /// Blocks the mutation checkpointed in place, which is exactly what a
        /// replay of its log must restore: every write after the commit record
        /// except the log retire and the clean marker that close the mutation.
        fn checkpointed_blocks(&self) -> Result<u32, FsError> {
            let commit = self
                .first_write(|_, head| *head == journal_head(JBD2_COMMIT_BLOCK))
                .ok_or(FsError::Corrupt)?;
            let blocks = self
                .issued
                .len()
                .checked_sub(commit + 2)
                .ok_or(FsError::Corrupt)?;
            u32::try_from(blocks).map_err(|_| FsError::Overflow)
        }
    }

    const TORN_PATH: &str = "/created.txt";
    const TORN_CONTENT: &[u8] = b"created by troe\n";
    /// Sectors of a torn 4 KiB write that reach media; the rest never land.
    const TORN_SECTORS: u32 = 4;

    fn torn_write_fixture() -> Result<TornWriteFixture, FsError> {
        let baseline = power_loss_device()?;
        let before = baseline.device().durable_image();
        {
            let mut ext4 = mount_device_writable(baseline.clone())?;
            ext4.write_file(TORN_PATH, TORN_CONTENT)?;
        }
        let device = baseline.device();
        Ok(TornWriteFixture {
            before,
            after: device.durable_image(),
            issued: device.issued.clone(),
        })
    }

    /// Run the create again, tearing write `boundary` after `TORN_SECTORS`.
    fn tear_create_at(boundary: usize) -> Result<SharedDevice, FsError> {
        tear_create_at_with(boundary, TORN_SECTORS)
    }

    /// Run the create again, tearing write `boundary` after `sectors`.
    fn tear_create_at_with(boundary: usize, sectors: u32) -> Result<SharedDevice, FsError> {
        let device = power_loss_device()?;
        device.device().tear_write_at = Some((boundary, sectors));
        {
            let mut ext4 = mount_device_writable(device.clone())?;
            assert_eq!(
                ext4.write_file(TORN_PATH, TORN_CONTENT),
                Err(FsError::Io),
                "a torn write must fail the mutation that issued it"
            );
        }
        device.device().power_loss();
        Ok(device)
    }

    /// Recover a volume the ordinary mount refuses, then prove that one pass
    /// was enough: a second recovery finds nothing to do and the ordinary
    /// mount opens the volume.
    fn recover_once(device: &SharedDevice) -> Result<RecoveryOutcome, FsError> {
        assert!(
            mount_device_writable(device.clone()).is_err(),
            "an interrupted volume must stay fail-closed to the ordinary mount"
        );
        let (_recovered, outcome) = recover_device(device.clone())?;
        assert_eq!(
            recover_device(device.clone()).err(),
            Some(FsError::Invalid),
            "recovery must be idempotent"
        );
        mount_device_writable(device.clone())?;
        Ok(outcome)
    }

    /// A metadata read is the shortest path from an application to the block
    /// transport, so every block condition it can raise has to arrive as its
    /// own filesystem error. Collapsing them made an intermittent bounded-wait
    /// expiry on `virtio-mmio` indistinguishable from a device that reported a
    /// failed read, which is the whole diagnostic value of the distinction.
    #[test]
    fn a_metadata_read_reports_each_block_condition_distinctly() -> Result<(), FsError> {
        for (raised, expected) in [
            (BlockError::Timeout, FsError::Timeout),
            (BlockError::Device, FsError::Io),
            (BlockError::Unsupported, FsError::Unsupported),
            (BlockError::ReadOnly, FsError::ReadOnly),
            (BlockError::OutOfBounds, FsError::Io),
        ] {
            let device = power_loss_device()?;
            let mut ext4 = mount_device_writable(device.clone())?;
            assert_eq!(
                ext4.metadata("/hello")?.byte_count,
                4101,
                "the mounted image must answer before a fault is injected"
            );
            device.device().fail_read_with = Some(raised);
            assert_eq!(
                ext4.metadata("/hello").err(),
                Some(expected),
                "a {raised:?} block read must reach the caller as {expected:?}"
            );
            // The injected condition is consumed by the read that observed it,
            // so the very next metadata read of the same path succeeds. That is
            // the observed acceptance shape: one failed read between two good
            // ones, with the media never in doubt.
            assert_eq!(ext4.metadata("/hello")?.byte_count, 4101);
        }
        Ok(())
    }

    #[test]
    fn a_torn_journal_descriptor_is_discarded_and_leaves_media_untouched() -> Result<(), FsError> {
        // The descriptor is written before the log head is armed, so a tear
        // there can only discard: nothing the mutation staged ever reached an
        // in-place block, and no replay can find the half-written record.
        let fixture = torn_write_fixture()?;
        let boundary = fixture
            .first_write(|_, head| *head == journal_head(JBD2_DESCRIPTOR_BLOCK))
            .ok_or(FsError::Corrupt)?;
        let device = tear_create_at(boundary)?;

        // Half a descriptor really is on media, so the tear was injected.
        let torn = device.device().durable_fs_block(JOURNAL_FIRST_BLOCK + 1);
        assert_eq!(&torn[..8], &journal_head(JBD2_DESCRIPTOR_BLOCK));
        assert!(
            torn[TORN_SECTORS as usize * DEVICE_BLOCK_BYTES_USIZE..]
                .iter()
                .all(|byte| *byte == 0),
            "only the torn prefix may reach media"
        );

        assert_eq!(recover_once(&device)?, RecoveryOutcome::AlreadyClean);
        // Byte for byte, every filesystem block is exactly as it was.
        assert_same_blocks(
            &outside_log(&device.device().durable_image()),
            &outside_log(&fixture.before),
            "a discarded transaction must leave media untouched",
        );
        let mut ext4 = mount_device_writable(device.clone())?;
        assert_eq!(
            ext4.metadata(TORN_PATH).err(),
            Some(FsError::NotFound),
            "a discarded transaction leaves nothing behind"
        );
        // The stale half-descriptor is inert: the next mutation still lands.
        ext4.write_file(TORN_PATH, TORN_CONTENT)?;
        let mut bytes = [0_u8; TORN_CONTENT.len()];
        assert_eq!(
            ext4.read_file(TORN_PATH, 0, &mut bytes)?,
            TORN_CONTENT.len()
        );
        assert_eq!(&bytes, TORN_CONTENT);
        Ok(())
    }

    #[test]
    fn a_torn_commit_record_recovers_to_exactly_one_of_two_states() -> Result<(), FsError> {
        // Every log payload block is already durable when the commit record is
        // issued, so both fates are whole states: a commit record whose
        // identifying header reached media replays the transaction the log
        // fully describes, and one that did not is discarded.
        let fixture = torn_write_fixture()?;
        let boundary = fixture
            .first_write(|_, head| *head == journal_head(JBD2_COMMIT_BLOCK))
            .ok_or(FsError::Corrupt)?;

        let landed = tear_create_at(boundary)?;
        assert_eq!(
            recover_once(&landed)?,
            RecoveryOutcome::Replayed {
                blocks: fixture.checkpointed_blocks()?
            },
            "a commit record whose header is durable commits the transaction"
        );
        assert_same_blocks(
            &outside_log(&landed.device().durable_image()),
            &outside_log(&fixture.after),
            "a replayed transaction must reach the post-state",
        );

        let lost = tear_create_at_with(boundary, 0)?;
        assert_eq!(recover_once(&lost)?, RecoveryOutcome::Discarded);
        assert_same_blocks(
            &outside_log(&lost.device().durable_image()),
            &outside_log(&fixture.before),
            "a discarded transaction must reach the pre-state",
        );

        let mut replayed = mount_device_writable(landed)?;
        let mut bytes = [0_u8; TORN_CONTENT.len()];
        assert_eq!(
            replayed.read_file(TORN_PATH, 0, &mut bytes)?,
            TORN_CONTENT.len()
        );
        assert_eq!(&bytes, TORN_CONTENT);
        assert_eq!(
            mount_device_writable(lost)?.metadata(TORN_PATH).err(),
            Some(FsError::NotFound)
        );
        Ok(())
    }

    #[test]
    fn a_torn_checkpoint_write_is_healed_by_replay() -> Result<(), FsError> {
        // The root directory block changes at both ends when an entry is
        // added: the record near its start and the checksum tail at its end.
        // Tearing its in-place rewrite therefore leaves media a real mixture
        // of the two states, which the whole-block replay images restore.
        let fixture = torn_write_fixture()?;
        let boundary = fixture
            .first_write(|block, _| block == device_block_of(ROOT_DIRECTORY_BLOCK))
            .ok_or(FsError::Corrupt)?;
        let device = tear_create_at(boundary)?;

        let split = TORN_SECTORS as usize * DEVICE_BLOCK_BYTES_USIZE;
        let start = ROOT_DIRECTORY_BLOCK as usize * EXT4_BLOCK_BYTES;
        let before = &fixture.before[start..start + EXT4_BLOCK_BYTES];
        let after = &fixture.after[start..start + EXT4_BLOCK_BYTES];
        let torn = device.device().durable_fs_block(ROOT_DIRECTORY_BLOCK);
        assert_ne!(before, after, "the checkpoint must change this block");
        assert_eq!(&torn[..split], &after[..split]);
        assert_eq!(&torn[split..], &before[split..]);
        assert_ne!(
            torn.as_slice(),
            before,
            "media must hold neither whole state"
        );
        assert_ne!(torn.as_slice(), after);

        assert_eq!(
            recover_once(&device)?,
            RecoveryOutcome::Replayed {
                blocks: fixture.checkpointed_blocks()?
            }
        );
        // Replay re-blits whole images, so the volume is byte-identical to the
        // one the same mutation produces when nothing interrupts it.
        assert_same_blocks(
            &device.device().durable_image(),
            &fixture.after,
            "replay must reproduce the uninterrupted volume",
        );
        let mut ext4 = mount_device_writable(device)?;
        let mut bytes = [0_u8; TORN_CONTENT.len()];
        assert_eq!(
            ext4.read_file(TORN_PATH, 0, &mut bytes)?,
            TORN_CONTENT.len()
        );
        assert_eq!(&bytes, TORN_CONTENT);
        Ok(())
    }

    #[test]
    fn a_recovery_torn_part_way_through_replays_again_to_the_same_bytes() -> Result<(), FsError> {
        // Recovery writes to the same media it is repairing, so it can be torn
        // exactly like the mutation was. Nothing it does consumes the log: the
        // commit record still stands until the whole checkpoint is durable, so
        // a second pass re-blits the same whole images.
        let fixture = torn_write_fixture()?;
        let boundary = fixture
            .first_write(|block, _| block == device_block_of(ROOT_DIRECTORY_BLOCK))
            .ok_or(FsError::Corrupt)?;
        let device = tear_create_at(boundary)?;

        device.device().reset_counts();
        device.device().tear_write_at = Some((1, TORN_SECTORS));
        assert!(
            recover_device(device.clone()).is_err(),
            "a torn replay write must fail the recovery that issued it"
        );
        device.device().power_loss();
        device.device().tear_write_at = None;

        assert_eq!(
            recover_once(&device)?,
            RecoveryOutcome::Replayed {
                blocks: fixture.checkpointed_blocks()?
            }
        );
        assert_same_blocks(
            &device.device().durable_image(),
            &fixture.after,
            "a re-run recovery must reach the same bytes",
        );
        Ok(())
    }

    #[test]
    fn every_interrupted_mutation_boundary_recovers_to_exactly_one_valid_state()
    -> Result<(), FsError> {
        const CONTENT: &[u8] = b"created by troe\n";

        let baseline = power_loss_device()?;
        {
            let mut ext4 = mount_device_writable(baseline.clone())?;
            ext4.write_file("/created.txt", CONTENT)?;
        }
        let (writes, flushes) = baseline.device().counts();
        assert!(writes >= 3, "a journaled create performs several writes");
        assert!(
            flushes >= 4,
            "commit, checkpoint, retire, and clean each flush"
        );
        // A completed mutation leaves a clean volume the ordinary mount opens.
        let mut settled = mount_device_writable(baseline.clone())?;
        let mut bytes = [0_u8; CONTENT.len()];
        assert_eq!(
            settled.read_file("/created.txt", 0, &mut bytes)?,
            CONTENT.len()
        );
        assert_eq!(&bytes, CONTENT);

        let mut replayed = 0_u32;
        let mut discarded = 0_u32;
        for boundary in 1..=writes {
            let device = power_loss_device()?;
            device.device().fail_write_at = Some(boundary);
            {
                let mut ext4 = mount_device_writable(device.clone())?;
                let _interrupted = ext4.write_file("/created.txt", CONTENT);
            }
            device.device().power_loss();

            // The ordinary mount stays fail-closed at every boundary that left
            // the volume mid-mutation.
            let refused = mount_device_writable(device.clone()).is_err();
            if !refused {
                // The interruption landed before the dirty marker reached
                // media, so the volume never entered a mutation.
                continue;
            }
            let (mut recovered, outcome) = recover_device(device.clone())?;
            match outcome {
                RecoveryOutcome::Replayed { .. } => replayed += 1,
                RecoveryOutcome::Discarded | RecoveryOutcome::AlreadyClean => discarded += 1,
            }
            // Exactly one valid state: either the create is fully present with
            // its exact bytes, or it is entirely absent. Never anything else.
            let mut recovered_bytes = [0_u8; CONTENT.len()];
            match recovered.read_file("/created.txt", 0, &mut recovered_bytes) {
                Ok(read) => {
                    assert_eq!(read, CONTENT.len(), "boundary {boundary} is partial");
                    assert_eq!(
                        &recovered_bytes, CONTENT,
                        "boundary {boundary} recovered wrong bytes"
                    );
                }
                Err(FsError::NotFound) => {}
                Err(error) => {
                    return Err(error);
                }
            }
            // Recovery is idempotent: a volume it already fixed needs no more.
            assert_eq!(
                recover_device(device.clone()).err(),
                Some(FsError::Invalid),
                "boundary {boundary} must not need a second recovery"
            );
            // And the recovered volume mounts cleanly through the ordinary path.
            mount_device_writable(device.clone())?;
        }
        assert!(
            replayed > 0,
            "some boundary must land after the commit record"
        );
        assert!(
            discarded > 0,
            "some boundary must land before the commit record"
        );
        Ok(())
    }

    /// A device holding one committed file with a partial tail block.
    fn prepared_append_device() -> Result<SharedDevice, FsError> {
        let device = power_loss_device()?;
        {
            let mut ext4 = mount_device_writable(device.clone())?;
            ext4.write_file("/appendme", b"prefix")?;
        }
        device.device().reset_counts();
        Ok(device)
    }

    #[test]
    fn an_interrupted_append_never_leaves_a_torn_tail_block() -> Result<(), FsError> {
        // The tail block of an append is rewritten in place over live, already
        // durable bytes. Staging routes that write through the log, so an
        // interruption can only leave the old content or the whole new
        // content, never a mixture of the two.
        const HEAD: &[u8] = b"prefix";
        const TAIL: &[u8] = b"-tail";

        let baseline = prepared_append_device()?;
        {
            let mut ext4 = mount_device_writable(baseline.clone())?;
            ext4.append_file("/appendme", TAIL)?;
        }
        let (writes, _) = baseline.device().counts();
        assert!(writes >= 3, "an append performs several writes");

        for boundary in 1..=writes {
            let device = prepared_append_device()?;
            device.device().fail_write_at = Some(boundary);
            {
                let mut ext4 = mount_device_writable(device.clone())?;
                let _interrupted = ext4.append_file("/appendme", TAIL);
            }
            device.device().power_loss();

            let mut recovered = match mount_device_writable(device.clone()) {
                Ok(ext4) => ext4,
                Err(_) => recover_device(device.clone())?.0,
            };
            let size = recovered.metadata("/appendme")?.byte_count;
            let appended = [HEAD, TAIL].concat();
            assert!(
                size == HEAD.len() as u64 || size == appended.len() as u64,
                "boundary {boundary} left size {size}: neither pre nor post state"
            );
            let mut bytes = [0_u8; 16];
            let read = recovered.read_file("/appendme", 0, &mut bytes)?;
            let content = bytes.get(..read).ok_or(FsError::Corrupt)?;
            assert!(
                content == HEAD || content == appended.as_slice(),
                "boundary {boundary} tore the tail block"
            );
        }
        Ok(())
    }

    /// Build an image with `mke2fs` defaults, i.e. what an arbitrary disk looks
    /// like: `64bit`, `flex_bg`, `metadata_csum_seed`, `dir_index` and
    /// `orphan_file`.
    fn default_mke2fs_image(
        directory: &Path,
        mke2fs: &Path,
        bytes: u64,
    ) -> Result<PathBuf, String> {
        let image = directory.join("default.ext4");
        File::create(&image)
            .and_then(|file| file.set_len(bytes))
            .map_err(|error| error.to_string())?;
        let source = directory.join("payload");
        let nested = source.join("nested");
        fs::create_dir_all(&nested).map_err(|error| error.to_string())?;
        fs::write(source.join("config.txt"), b"profile=default-ext4\n")
            .map_err(|error| error.to_string())?;
        fs::write(nested.join("message.txt"), b"hello from a default volume\n")
            .map_err(|error| error.to_string())?;
        #[cfg(unix)]
        std::os::unix::fs::symlink("../config.txt", nested.join("config-link"))
            .map_err(|error| error.to_string())?;
        let format = Command::new(mke2fs)
            .args(["-q", "-F", "-t", "ext4", "-d"])
            .arg(&source)
            .arg(&image)
            .output()
            .map_err(|error| error.to_string())?;
        command_succeeded(&format, "mke2fs default")?;
        Ok(image)
    }

    #[test]
    fn mounts_and_reads_a_default_mke2fs_volume() -> Result<(), String> {
        let Some(mke2fs) = e2fs_tool("mke2fs") else {
            return unavailable_tool("mke2fs");
        };
        let temporary = TestDirectory::create("ext4-default")?;
        let image = default_mke2fs_image(temporary.path(), &mke2fs, 1024 * 1024 * 1024)?;
        let limits = Ext4Limits::new(
            HARD_MAX_GROUPS,
            64,
            256,
            4096,
            1 << 40,
            1024 * 1024,
            MAX_NAME_BYTES,
        )
        .map_err(|error| format!("invalid default-volume limits: {error:?}"))?;
        let device = FileDevice::open(&image)?;
        let block_limits = BlockLimits::new(8, EXT4_BLOCK_BYTES, 1)
            .map_err(|error| format!("invalid block limits: {error:?}"))?;
        let region = BlockRegion::whole_device(device, BlockAccess::ReadOnly, block_limits)
            .map_err(|error| format!("cannot grant image region: {error:?}"))?;
        let mut ext4 =
            Ext4::mount(region, limits).map_err(|error| format!("cannot mount: {error:?}"))?;
        let listing = ext4
            .list("/", 0, 16, 64)
            .map_err(|error| format!("cannot list default volume root: {error:?}"))?;
        assert!(
            listing
                .entries
                .iter()
                .any(|entry| entry.name == "lost+found"),
            "a default volume root contains lost+found"
        );

        // Real content, not just a directory listing.
        let mut bytes = [0_u8; 32];
        let read = ext4
            .read_file("/config.txt", 0, &mut bytes)
            .map_err(|error| format!("cannot read a file on a default volume: {error:?}"))?;
        assert_eq!(&bytes[..read], b"profile=default-ext4\n");

        let read = ext4
            .read_file("/nested/message.txt", 0, &mut bytes)
            .map_err(|error| format!("cannot read a nested file: {error:?}"))?;
        assert_eq!(&bytes[..read], b"hello from a default volume\n");

        // A symbolic link resolves through the same default metadata.
        let read = ext4
            .read_file("/nested/config-link", 0, &mut bytes)
            .map_err(|error| format!("cannot follow a link: {error:?}"))?;
        assert_eq!(&bytes[..read], b"profile=default-ext4\n");

        Ok(())
    }

    fn default_volume_limits() -> Result<Ext4Limits, String> {
        Ext4Limits::new(
            HARD_MAX_GROUPS,
            64,
            256,
            4096,
            1 << 40,
            1024 * 1024,
            MAX_NAME_BYTES,
        )
        .map_err(|error| format!("invalid default-volume limits: {error:?}"))
    }

    #[test]
    fn writes_to_a_default_mke2fs_volume_and_passes_e2fsck() -> Result<(), String> {
        let Some(mke2fs) = e2fs_tool("mke2fs") else {
            return unavailable_tool("mke2fs");
        };
        let Some(e2fsck) = e2fs_tool("e2fsck") else {
            return unavailable_tool("e2fsck");
        };
        let temporary = TestDirectory::create("ext4-default-write")?;
        let image = default_mke2fs_image(temporary.path(), &mke2fs, 1024 * 1024 * 1024)?;
        {
            let mut ext4 = mount_file_writable_with_limits(&image, default_volume_limits()?)?;
            ext4.write_file("/created.txt", b"written by troe\n")
                .map_err(|error| format!("cannot create on a default volume: {error:?}"))?;
            ext4.write_file("/nested/message.txt", b"replaced by troe\n")
                .map_err(|error| format!("cannot replace on a default volume: {error:?}"))?;
            ext4.create_directory("/archive")
                .map_err(|error| format!("cannot create a directory: {error:?}"))?;
            ext4.remove_file("/config.txt")
                .map_err(|error| format!("cannot remove on a default volume: {error:?}"))?;
        }

        // The independent oracle must accept every byte this provider wrote.
        let check = Command::new(&e2fsck)
            .args(["-f", "-n"])
            .arg(&image)
            .output()
            .map_err(|error| error.to_string())?;
        command_succeeded(&check, "e2fsck after default-volume mutation")?;

        let mut ext4 = mount_file_with_limits(&image, default_volume_limits()?)?;
        let mut bytes = [0_u8; 32];
        let read = ext4
            .read_file("/created.txt", 0, &mut bytes)
            .map_err(|error| format!("cannot read back: {error:?}"))?;
        assert_eq!(&bytes[..read], b"written by troe\n");
        let read = ext4
            .read_file("/nested/message.txt", 0, &mut bytes)
            .map_err(|error| format!("cannot read replacement: {error:?}"))?;
        assert_eq!(&bytes[..read], b"replaced by troe\n");
        assert_eq!(
            ext4.metadata("/config.txt").err(),
            Some(FsError::NotFound),
            "the removed entry must be gone"
        );
        Ok(())
    }

    #[test]
    fn writes_to_a_multi_group_volume_beyond_the_previous_ceiling() -> Result<(), String> {
        let Some(mke2fs) = e2fs_tool("mke2fs") else {
            return unavailable_tool("mke2fs");
        };
        let Some(e2fsck) = e2fs_tool("e2fsck") else {
            return unavailable_tool("e2fsck");
        };
        let temporary = TestDirectory::create("ext4-large")?;
        // 16 GiB is 128 groups at the ext4 default, four times the ceiling this
        // provider previously accepted.
        let image = default_mke2fs_image(temporary.path(), &mke2fs, 16 * 1024 * 1024 * 1024)?;
        {
            let mut ext4 = mount_file_writable_with_limits(&image, default_volume_limits()?)?;
            ext4.write_file("/created.txt", b"written across many groups\n")
                .map_err(|error| format!("cannot create on a large volume: {error:?}"))?;
            ext4.create_directory("/archive")
                .map_err(|error| format!("cannot create a directory: {error:?}"))?;
        }
        let check = Command::new(&e2fsck)
            .args(["-f", "-n"])
            .arg(&image)
            .output()
            .map_err(|error| error.to_string())?;
        command_succeeded(&check, "e2fsck after large-volume mutation")?;

        let mut ext4 = mount_file_with_limits(&image, default_volume_limits()?)?;
        let mut bytes = [0_u8; 32];
        let read = ext4
            .read_file("/created.txt", 0, &mut bytes)
            .map_err(|error| format!("cannot read back: {error:?}"))?;
        assert_eq!(&bytes[..read], b"written across many groups\n");
        Ok(())
    }

    #[test]
    fn reads_and_writes_a_kibibyte_block_volume() -> Result<(), String> {
        let Some(mke2fs) = e2fs_tool("mke2fs") else {
            return unavailable_tool("mke2fs");
        };
        let Some(e2fsck) = e2fs_tool("e2fsck") else {
            return unavailable_tool("e2fsck");
        };
        let temporary = TestDirectory::create("ext4-small-block")?;
        // `mke2fs` selects 1 KiB blocks for a small volume, so this exercises
        // the block size the shipped profile never uses.
        let image = default_mke2fs_image(temporary.path(), &mke2fs, 64 * 1024 * 1024)?;
        {
            let mut ext4 = mount_file_writable_with_limits(&image, default_volume_limits()?)?;
            let mut bytes = [0_u8; 32];
            let read = ext4
                .read_file("/config.txt", 0, &mut bytes)
                .map_err(|error| format!("cannot read a 1 KiB-block volume: {error:?}"))?;
            assert_eq!(&bytes[..read], b"profile=default-ext4\n");

            ext4.write_file("/created.txt", b"written at 1 KiB blocks\n")
                .map_err(|error| format!("cannot create at 1 KiB blocks: {error:?}"))?;
            ext4.create_directory("/archive")
                .map_err(|error| format!("cannot mkdir at 1 KiB blocks: {error:?}"))?;
            ext4.remove_file("/config.txt")
                .map_err(|error| format!("cannot remove at 1 KiB blocks: {error:?}"))?;
        }
        let check = Command::new(&e2fsck)
            .args(["-f", "-n"])
            .arg(&image)
            .output()
            .map_err(|error| error.to_string())?;
        command_succeeded(&check, "e2fsck after 1 KiB-block mutation")?;

        let mut ext4 = mount_file_with_limits(&image, default_volume_limits()?)?;
        let mut bytes = [0_u8; 32];
        let read = ext4
            .read_file("/created.txt", 0, &mut bytes)
            .map_err(|error| format!("cannot read back at 1 KiB blocks: {error:?}"))?;
        assert_eq!(&bytes[..read], b"written at 1 KiB blocks\n");
        Ok(())
    }

    /// Build a volume whose large directory carries a real hashed index.
    ///
    /// `mke2fs -d` writes linear directories at any size, so `e2fsck -D` is
    /// used to reindex them exactly as a Linux host would.
    fn hashed_directory_image(
        directory: &Path,
        mke2fs: &Path,
        e2fsck: &Path,
        names: usize,
    ) -> Result<PathBuf, String> {
        let image = directory.join("hashed.ext4");
        File::create(&image)
            .and_then(|file| file.set_len(256 * 1024 * 1024))
            .map_err(|error| error.to_string())?;
        let source = directory.join("tree");
        let many = source.join("many");
        fs::create_dir_all(&many).map_err(|error| error.to_string())?;
        for index in 0..names {
            fs::write(many.join(format!("file-{index:05}.txt")), b"x")
                .map_err(|error| error.to_string())?;
        }
        let format = Command::new(mke2fs)
            .args(["-q", "-F", "-t", "ext4", "-b", "4096", "-d"])
            .arg(&source)
            .arg(&image)
            .output()
            .map_err(|error| error.to_string())?;
        command_succeeded(&format, "mke2fs hashed")?;
        // `-D` reindexes directories; it reports modification, not failure.
        let reindex = Command::new(e2fsck)
            .args(["-fD", "-y"])
            .arg(&image)
            .output()
            .map_err(|error| error.to_string())?;
        if !matches!(reindex.status.code(), Some(0 | 1)) {
            return Err(format!("e2fsck -D failed: {:?}", reindex.status));
        }
        Ok(image)
    }

    #[test]
    fn reads_a_hashed_directory_through_its_index() -> Result<(), String> {
        const NAMES: usize = 2000;
        let Some(mke2fs) = e2fs_tool("mke2fs") else {
            return unavailable_tool("mke2fs");
        };
        let Some(e2fsck) = e2fs_tool("e2fsck") else {
            return unavailable_tool("e2fsck");
        };
        let temporary = TestDirectory::create("ext4-hashed")?;
        let image = hashed_directory_image(temporary.path(), &mke2fs, &e2fsck, NAMES)?;
        let limits = Ext4Limits::new(
            HARD_MAX_GROUPS,
            64,
            256,
            4096,
            1 << 40,
            1024 * 1024,
            MAX_NAME_BYTES,
        )
        .map_err(|error| format!("invalid limits: {error:?}"))?;
        let mut ext4 = mount_file_with_limits(&image, limits)?;

        // Every name the index describes must be enumerated exactly once.
        let mut seen = 0_usize;
        let mut cursor = 0_u64;
        loop {
            let page = ext4
                .list("/many", cursor, 64, 64)
                .map_err(|error| format!("cannot list a hashed directory: {error:?}"))?;
            seen += page.entries.len();
            match page.next_cursor {
                Some(next) => cursor = next,
                None => break,
            }
        }
        assert_eq!(seen, NAMES, "the index must enumerate every name once");

        // A name resolves through the same leaves.
        let mut bytes = [0_u8; 4];
        let read = ext4
            .read_file("/many/file-01234.txt", 0, &mut bytes)
            .map_err(|error| format!("cannot read through a hashed directory: {error:?}"))?;
        assert_eq!(&bytes[..read], b"x");

        // An unindexed directory on the same volume stays writable.
        let mut writable = mount_file_writable_with_limits(&image, limits)?;
        writable
            .write_file("/created.txt", b"written beside a hashed directory\n")
            .map_err(|error| format!("cannot write beside a hashed directory: {error:?}"))?;
        Ok(())
    }

    #[test]
    fn the_name_hash_agrees_with_a_real_on_disk_index() -> Result<(), String> {
        const NAMES: usize = 2000;
        let Some(mke2fs) = e2fs_tool("mke2fs") else {
            return unavailable_tool("mke2fs");
        };
        let Some(e2fsck) = e2fs_tool("e2fsck") else {
            return unavailable_tool("e2fsck");
        };
        let temporary = TestDirectory::create("ext4-hash-agree")?;
        let image = hashed_directory_image(temporary.path(), &mke2fs, &e2fsck, NAMES)?;
        let limits = Ext4Limits::new(
            HARD_MAX_GROUPS,
            64,
            256,
            4096,
            1 << 40,
            1024 * 1024,
            MAX_NAME_BYTES,
        )
        .map_err(|error| format!("invalid limits: {error:?}"))?;
        let mut ext4 = mount_file_with_limits(&image, limits)?;

        let hash = ext4
            .directory_hash()
            .map_err(|error| format!("cannot read hash inputs: {error:?}"))?;
        assert!(
            hash.is_reproducible(),
            "the volume records its byte signedness"
        );
        let inode = ext4
            .resolve("/many")
            .map_err(|error| format!("cannot resolve: {error:?}"))?;
        assert!(inode.indexed, "e2fsck -D must have indexed this directory");

        let seed = ext4.inode_checksum_seed(&inode);
        let root_block = ext4
            .directory_block(&inode, 0)
            .map_err(|error| format!("cannot read root: {error:?}"))?;
        let root = htree::parse_root(&root_block, seed, crc32c)
            .map_err(|error| format!("cannot parse root: {error:?}"))?;
        assert_eq!(root.indirect_levels, 0, "one level is enough for this size");
        assert!(root.entries.len() > 1, "the directory must really be split");

        // Every name a leaf holds must hash into that leaf's own range. A hash
        // that disagreed with the kernel's would place names in the wrong leaf.
        let mut checked = 0_usize;
        for (index, entry) in root.entries.iter().enumerate() {
            let upper = root.entries.get(index + 1).map(|next| next.hash);
            let block = ext4
                .directory_block(&inode, entry.block)
                .map_err(|error| format!("cannot read leaf: {error:?}"))?;
            let mut records = Vec::new();
            parse_directory_block(&block, inode.number, 1 << 20, limits, &mut records)
                .map_err(|error| format!("cannot parse leaf: {error:?}"))?;
            for record in &records {
                let computed = hash
                    .hash(record.name.as_bytes(), root.hash_version)
                    .map_err(|error| format!("cannot hash: {error:?}"))?;
                assert!(
                    computed >= entry.hash,
                    "{} hashed to {computed:#x}, below its leaf floor {:#x}",
                    record.name,
                    entry.hash
                );
                if let Some(limit) = upper {
                    assert!(
                        computed < limit,
                        "{} hashed to {computed:#x}, at or above the next leaf {limit:#x}",
                        record.name
                    );
                }
                checked += 1;
            }
        }
        assert_eq!(checked, NAMES, "every name must be placed by the index");
        Ok(())
    }

    #[test]
    fn writes_into_a_hashed_directory_and_passes_e2fsck() -> Result<(), String> {
        const NAMES: usize = 2000;
        const TARGET: &str = "/many/file-01234.txt";
        let Some(mke2fs) = e2fs_tool("mke2fs") else {
            return unavailable_tool("mke2fs");
        };
        let Some(e2fsck) = e2fs_tool("e2fsck") else {
            return unavailable_tool("e2fsck");
        };
        let temporary = TestDirectory::create("ext4-hashed-write")?;
        let image = hashed_directory_image(temporary.path(), &mke2fs, &e2fsck, NAMES)?;
        let limits = Ext4Limits::new(
            HARD_MAX_GROUPS,
            64,
            256,
            4096,
            1 << 40,
            1024 * 1024,
            MAX_NAME_BYTES,
        )
        .map_err(|error| format!("invalid limits: {error:?}"))?;
        {
            let mut ext4 = mount_file_writable_with_limits(&image, limits)?;
            ext4.remove_file(TARGET)
                .map_err(|error| format!("cannot remove from a hashed directory: {error:?}"))?;
            assert_eq!(ext4.metadata(TARGET).err(), Some(FsError::NotFound));

            // The same name hashes to the same leaf, which now has room again.
            ext4.write_file(TARGET, b"rewritten by troe\n")
                .map_err(|error| format!("cannot insert into a hashed directory: {error:?}"))?;

            // A brand-new name either fits its leaf or is refused; it must
            // never be placed where the index cannot find it.
            match ext4.write_file("/many/inserted-by-troe.txt", b"new\n") {
                Ok(()) | Err(FsError::NoSpace) => {}
                Err(error) => return Err(format!("unexpected insert failure: {error:?}")),
            }
        }

        // e2fsck validates hashed-directory ordering, so a record placed in the
        // wrong leaf would be reported here.
        let check = Command::new(&e2fsck)
            .args(["-f", "-n"])
            .arg(&image)
            .output()
            .map_err(|error| error.to_string())?;
        command_succeeded(&check, "e2fsck after hashed-directory mutation")?;

        let mut ext4 = mount_file_with_limits(&image, limits)?;
        let mut bytes = [0_u8; 32];
        let read = ext4
            .read_file(TARGET, 0, &mut bytes)
            .map_err(|error| format!("cannot read the reinserted name: {error:?}"))?;
        assert_eq!(&bytes[..read], b"rewritten by troe\n");
        Ok(())
    }

    /// Build a volume whose 1 KiB-block directory carries a shallow index.
    ///
    /// Long names fill a small leaf quickly, so a few hundred of them give a
    /// root that still addresses leaves directly and is close to full. That is
    /// the shape a split has to grow out of.
    fn shallow_index_image(
        directory: &Path,
        mke2fs: &Path,
        e2fsck: &Path,
        names: usize,
        name_bytes: usize,
    ) -> Result<PathBuf, String> {
        let image = directory.join("shallow.ext4");
        File::create(&image)
            // `mke2fs` selects 1 KiB blocks for a volume this small, and a
            // small block gives a small leaf.
            .and_then(|file| file.set_len(64 * 1024 * 1024))
            .map_err(|error| error.to_string())?;
        let source = directory.join("tree");
        let many = source.join("many");
        fs::create_dir_all(&many).map_err(|error| error.to_string())?;
        for index in 0..names {
            fs::write(many.join(long_name("seed", index, name_bytes)), b"x")
                .map_err(|error| error.to_string())?;
        }
        let format = Command::new(mke2fs)
            .args(["-q", "-F", "-t", "ext4", "-d"])
            .arg(&source)
            .arg(&image)
            .output()
            .map_err(|error| error.to_string())?;
        command_succeeded(&format, "mke2fs shallow index")?;
        let reindex = Command::new(e2fsck)
            .args(["-fD", "-y"])
            .arg(&image)
            .output()
            .map_err(|error| error.to_string())?;
        if !matches!(reindex.status.code(), Some(0 | 1)) {
            return Err(format!("e2fsck -D failed: {:?}", reindex.status));
        }
        Ok(image)
    }

    /// One distinct name of an exact byte length.
    fn long_name(prefix: &str, index: usize, bytes: usize) -> String {
        let mut name = format!("{prefix}-{index:05}-");
        while name.len() < bytes {
            name.push('n');
        }
        name.truncate(bytes);
        name
    }

    /// The levels, root entry count, and leaf count of one hashed directory.
    fn index_shape<D: BlockDevice>(
        ext4: &mut Ext4<D>,
        path: &str,
    ) -> Result<(u8, usize, usize), String> {
        let inode = ext4
            .resolve(path)
            .map_err(|error| format!("cannot resolve {path}: {error:?}"))?;
        if !inode.indexed {
            return Err(format!("{path} is not indexed"));
        }
        let seed = ext4.inode_checksum_seed(&inode);
        let root_block = ext4
            .directory_block(&inode, 0)
            .map_err(|error| format!("cannot read the index root: {error:?}"))?;
        let root = htree::parse_root(&root_block, seed, crc32c)
            .map_err(|error| format!("cannot parse the index root: {error:?}"))?;
        let leaves = ext4
            .hashed_leaf_blocks(&inode)
            .map_err(|error| format!("cannot collect leaves: {error:?}"))?;
        Ok((root.indirect_levels, root.entries.len(), leaves.len()))
    }

    #[test]
    fn splits_full_hashed_leaves_and_deepens_a_full_index_root() -> Result<(), String> {
        const SEEDED: usize = 300;
        const NAME_BYTES: usize = 255;
        const ATTEMPTS: usize = 250;
        let Some(mke2fs) = e2fs_tool("mke2fs") else {
            return unavailable_tool("mke2fs");
        };
        let Some(e2fsck) = e2fs_tool("e2fsck") else {
            return unavailable_tool("e2fsck");
        };
        let temporary = TestDirectory::create("ext4-hashed-split")?;
        let image = shallow_index_image(temporary.path(), &mke2fs, &e2fsck, SEEDED, NAME_BYTES)?;
        let limits = default_volume_limits()?;

        let mut inserted = Vec::new();
        {
            let mut ext4 = mount_file_writable_with_limits(&image, limits)?;
            let (levels, _, seeded_leaves) = index_shape(&mut ext4, "/many")?;
            assert_eq!(levels, 0, "the seeded index must address leaves directly");
            assert!(
                seeded_leaves > 1,
                "the seeded index must have leaves to fill"
            );

            // Every name lands in the one leaf its hash selects, so a full leaf
            // has to split before the name fits. Enough of those fill the root,
            // which then grows a level of interior nodes; enough more fill that
            // node, which then splits and puts a second entry in the root.
            let mut split_leaves = false;
            let mut deepened = false;
            let mut split_node = false;
            for index in 0..ATTEMPTS {
                let name = long_name("troe", index, NAME_BYTES);
                ext4.write_file(&format!("/many/{name}"), b"inserted by troe\n")
                    .map_err(|error| format!("cannot insert {name}: {error:?}"))?;
                inserted.push(name);
                let (levels, root_entries, leaves) = index_shape(&mut ext4, "/many")?;
                split_leaves |= leaves > seeded_leaves;
                deepened |= levels == 1;
                split_node |= levels == 1 && root_entries > 1;
                if split_node {
                    break;
                }
            }
            assert!(split_leaves, "no leaf split in {ATTEMPTS} inserts");
            assert!(
                deepened,
                "the full root never grew a level in {ATTEMPTS} inserts"
            );
            assert!(
                split_node,
                "the full interior node never split in {ATTEMPTS} inserts"
            );
        }

        // e2fsck validates hashed-directory ordering and every index checksum,
        // so a record placed in the wrong leaf, or a stale separator, fails
        // here rather than silently.
        let check = Command::new(&e2fsck)
            .args(["-f", "-n"])
            .arg(&image)
            .output()
            .map_err(|error| error.to_string())?;
        command_succeeded(&check, "e2fsck after hashed-directory splits")?;

        let mut ext4 = mount_file_with_limits(&image, limits)?;
        let mut listed = BTreeMap::new();
        let mut cursor = 0_u64;
        loop {
            let page = ext4
                .list("/many", cursor, 64, MAX_NAME_BYTES)
                .map_err(|error| format!("cannot list: {error:?}"))?;
            for entry in page.entries {
                listed.insert(entry.name, entry.kind);
            }
            match page.next_cursor {
                Some(next) => cursor = next,
                None => break,
            }
        }
        for index in 0..SEEDED {
            let name = long_name("seed", index, NAME_BYTES);
            assert!(listed.contains_key(&name), "{name} was lost by a split");
        }
        for name in &inserted {
            assert!(listed.contains_key(name), "{name} was lost by a split");
            let mut bytes = [0_u8; 32];
            let read = ext4
                .read_file(&format!("/many/{name}"), 0, &mut bytes)
                .map_err(|error| format!("cannot read {name}: {error:?}"))?;
            assert_eq!(&bytes[..read], b"inserted by troe\n");
        }
        Ok(())
    }

    /// The inode `..` names inside one directory's first block.
    fn recorded_parent<D: BlockDevice>(ext4: &mut Ext4<D>, path: &str) -> Result<u32, String> {
        let inode = ext4
            .resolve(path)
            .map_err(|error| format!("cannot resolve {path}: {error:?}"))?;
        let block = ext4
            .directory_block(&inode, 0)
            .map_err(|error| format!("cannot read the first block of {path}: {error:?}"))?;
        read_u32(&block, EXT4_DX_PARENT_OFFSET)
            .map_err(|error| format!("cannot read the parent record: {error:?}"))
    }

    #[test]
    fn renames_a_hashed_directory_between_parents() -> Result<(), String> {
        const SEEDED: usize = 300;
        const NAME_BYTES: usize = 255;
        let Some(mke2fs) = e2fs_tool("mke2fs") else {
            return unavailable_tool("mke2fs");
        };
        let Some(e2fsck) = e2fs_tool("e2fsck") else {
            return unavailable_tool("e2fsck");
        };
        let temporary = TestDirectory::create("ext4-hashed-rename")?;
        let image = shallow_index_image(temporary.path(), &mke2fs, &e2fsck, SEEDED, NAME_BYTES)?;
        let limits = default_volume_limits()?;

        let sample = long_name("seed", 7, NAME_BYTES);
        {
            let mut ext4 = mount_file_writable_with_limits(&image, limits)?;
            assert!(
                ext4.resolve("/many")
                    .map_err(|error| format!("cannot resolve: {error:?}"))?
                    .indexed
            );
            ext4.create_directory("/holder")
                .map_err(|error| format!("cannot create the destination: {error:?}"))?;
            let holder = ext4
                .resolve("/holder")
                .map_err(|error| format!("cannot resolve the destination: {error:?}"))?
                .number;
            let root = ext4
                .resolve("/")
                .map_err(|error| format!("cannot resolve the root: {error:?}"))?
                .number;
            assert_eq!(recorded_parent(&mut ext4, "/many")?, root);

            // Moving an indexed directory rewrites the `..` record that shares
            // its root block with the index.
            ext4.rename("/many", "/holder/many")
                .map_err(|error| format!("cannot move a hashed directory in: {error:?}"))?;
            assert_eq!(recorded_parent(&mut ext4, "/holder/many")?, holder);
            assert_eq!(
                ext4.metadata(&format!("/holder/many/{sample}"))
                    .map_err(|error| format!("cannot reach a moved name: {error:?}"))?
                    .byte_count,
                1
            );

            // And moving it back out restores the original parent.
            ext4.rename("/holder/many", "/many")
                .map_err(|error| format!("cannot move a hashed directory out: {error:?}"))?;
            assert_eq!(recorded_parent(&mut ext4, "/many")?, root);
        }

        // e2fsck checks every `..` against the parent that actually holds the
        // directory, so a stale record or a broken index checksum fails here.
        let check = Command::new(&e2fsck)
            .args(["-f", "-n"])
            .arg(&image)
            .output()
            .map_err(|error| error.to_string())?;
        command_succeeded(&check, "e2fsck after moving a hashed directory")?;

        let mut ext4 = mount_file_with_limits(&image, limits)?;
        assert_eq!(
            ext4.metadata(&format!("/many/{sample}"))
                .map_err(|error| format!("cannot reach a restored name: {error:?}"))?
                .byte_count,
            1
        );
        Ok(())
    }

    #[test]
    fn accepts_the_longest_name_ext4_allows() -> Result<(), String> {
        const LENGTH: usize = 255;
        let Some(mke2fs) = e2fs_tool("mke2fs") else {
            return unavailable_tool("mke2fs");
        };
        let Some(e2fsck) = e2fs_tool("e2fsck") else {
            return unavailable_tool("e2fsck");
        };
        let temporary = TestDirectory::create("ext4-long-name")?;
        let image = default_mke2fs_image(temporary.path(), &mke2fs, 1024 * 1024 * 1024)?;
        let name: String = core::iter::repeat_n('n', LENGTH).collect();
        let path = format!("/{name}");
        assert_eq!(name.len(), LENGTH);
        {
            let mut ext4 = mount_file_writable_with_limits(&image, default_volume_limits()?)?;
            ext4.write_file(&path, b"a very long name\n")
                .map_err(|error| format!("cannot create a {LENGTH}-byte name: {error:?}"))?;
        }
        let check = Command::new(&e2fsck)
            .args(["-f", "-n"])
            .arg(&image)
            .output()
            .map_err(|error| error.to_string())?;
        command_succeeded(&check, "e2fsck after a long-name insert")?;

        let mut ext4 = mount_file_with_limits(&image, default_volume_limits()?)?;
        let mut bytes = [0_u8; 32];
        let read = ext4
            .read_file(&path, 0, &mut bytes)
            .map_err(|error| format!("cannot read a {LENGTH}-byte name: {error:?}"))?;
        assert_eq!(&bytes[..read], b"a very long name\n");
        // The listing byte budget is an aggregate, so a 255-byte name may need
        // its own page.
        let mut found = false;
        let mut cursor = 0_u64;
        loop {
            let page = ext4
                .list("/", cursor, 8, MAX_NAME_BYTES)
                .map_err(|error| format!("cannot list: {error:?}"))?;
            found |= page.entries.iter().any(|entry| entry.name == name);
            match page.next_cursor {
                Some(next) => cursor = next,
                None => break,
            }
        }
        assert!(found, "the long name must be enumerable");
        Ok(())
    }

    /// Build a volume holding one file whose extent tree is deeper than one
    /// level.
    ///
    /// `mke2fs` and this provider both allocate whole runs, so neither can
    /// produce the shape under test. Deleting alternate small files with
    /// `debugfs` leaves a comb of single-block holes, and `debugfs write`
    /// fills them one block at a time, which is the fragmentation an ordinary
    /// Linux host produces over a long life.
    fn fragmented_file_image(
        directory: &Path,
        mke2fs: &Path,
        e2fsck: &Path,
        debugfs: &Path,
        payload: &[u8],
    ) -> Result<PathBuf, String> {
        const SEEDS: usize = 3000;
        let image = directory.join("fragmented.ext4");
        File::create(&image)
            // `mke2fs` selects 1 KiB blocks for a volume this small, so one
            // leaf holds few extents and the tree needs a level sooner.
            .and_then(|file| file.set_len(64 * 1024 * 1024))
            .map_err(|error| error.to_string())?;
        let source = directory.join("tree");
        let many = source.join("many");
        fs::create_dir_all(&many).map_err(|error| error.to_string())?;
        for index in 0..SEEDS {
            fs::write(many.join(format!("f{index:05}")), b"x")
                .map_err(|error| error.to_string())?;
        }
        let format = Command::new(mke2fs)
            .args(["-q", "-F", "-t", "ext4", "-d"])
            .arg(&source)
            .arg(&image)
            .output()
            .map_err(|error| error.to_string())?;
        command_succeeded(&format, "mke2fs fragmented")?;

        let mut script = String::new();
        for index in (1..SEEDS).step_by(2) {
            writeln!(script, "kill_file /many/f{index:05}\nrm /many/f{index:05}")
                .map_err(|error| error.to_string())?;
        }
        let script_path = directory.join("holes.debugfs");
        fs::write(&script_path, script.as_bytes()).map_err(|error| error.to_string())?;
        let punch = Command::new(debugfs)
            .arg("-w")
            .arg("-f")
            .arg(&script_path)
            .arg(&image)
            .output()
            .map_err(|error| error.to_string())?;
        command_succeeded(&punch, "debugfs punching holes")?;

        let payload_path = directory.join("payload.bin");
        fs::write(&payload_path, payload).map_err(|error| error.to_string())?;
        let write = Command::new(debugfs)
            .arg("-w")
            .arg("-R")
            .arg(format!("write {} big.bin", payload_path.display()))
            .arg(&image)
            .output()
            .map_err(|error| error.to_string())?;
        command_succeeded(&write, "debugfs writing a fragmented file")?;

        // Deleting through `debugfs` leaves the group counters stale, so the
        // volume is repaired once and then required to be clean.
        let repair = Command::new(e2fsck)
            .args(["-fy"])
            .arg(&image)
            .output()
            .map_err(|error| error.to_string())?;
        if !matches!(repair.status.code(), Some(0..=2)) {
            return Err(format!("e2fsck repair failed: {:?}", repair.status));
        }
        let check = Command::new(e2fsck)
            .args(["-f", "-n"])
            .arg(&image)
            .output()
            .map_err(|error| error.to_string())?;
        command_succeeded(&check, "e2fsck on the fragmented volume")?;
        Ok(image)
    }

    /// Levels `debugfs` reports in one file's extent tree.
    fn host_extent_depth(debugfs: &Path, image: &Path, path: &str) -> Result<u16, String> {
        let listing = Command::new(debugfs)
            .arg("-R")
            .arg(format!("ex {path}"))
            .arg(image)
            .output()
            .map_err(|error| error.to_string())?;
        command_succeeded(&listing, "debugfs ex")?;
        let report = String::from_utf8_lossy(&listing.stdout).to_string();
        // Each row starts with `level/ depth`, so the depth is the same on
        // every row and the root row is enough.
        let depth = report
            .lines()
            .filter_map(|line| line.trim().split('/').nth(1))
            .filter_map(|field| field.split_whitespace().next())
            .find_map(|field| field.parse::<u16>().ok())
            .ok_or_else(|| format!("no extent rows in:\n{report}"))?;
        Ok(depth)
    }

    /// Read one file out of an image with the host's own reader.
    fn host_file_bytes(
        debugfs: &Path,
        image: &Path,
        path: &str,
        destination: &Path,
    ) -> Result<Vec<u8>, String> {
        let dump = Command::new(debugfs)
            .arg("-R")
            .arg(format!("dump {path} {}", destination.display()))
            .arg(image)
            .output()
            .map_err(|error| error.to_string())?;
        command_succeeded(&dump, "debugfs dump")?;
        fs::read(destination).map_err(|error| error.to_string())
    }

    /// Read one whole file through the provider in bounded chunks.
    fn provider_file_bytes<D: BlockDevice>(
        ext4: &mut Ext4<D>,
        path: &str,
    ) -> Result<Vec<u8>, String> {
        let byte_count = ext4
            .metadata(path)
            .map_err(|error| format!("cannot stat {path}: {error:?}"))?
            .byte_count;
        let mut bytes = Vec::new();
        let mut chunk = vec![0_u8; 64 * 1024];
        while u64::try_from(bytes.len()).map_err(|error| error.to_string())? < byte_count {
            let offset = u64::try_from(bytes.len()).map_err(|error| error.to_string())?;
            let read = ext4
                .read_file(path, offset, &mut chunk)
                .map_err(|error| format!("cannot read {path}: {error:?}"))?;
            if read == 0 {
                break;
            }
            bytes.extend_from_slice(&chunk[..read]);
        }
        Ok(bytes)
    }

    #[test]
    fn rewrites_a_file_whose_extent_tree_is_deeper_than_one_level() -> Result<(), String> {
        const BLOCKS: usize = 1000;
        const BLOCK: usize = 1024;
        let Some(mke2fs) = e2fs_tool("mke2fs") else {
            return unavailable_tool("mke2fs");
        };
        let Some(e2fsck) = e2fs_tool("e2fsck") else {
            return unavailable_tool("e2fsck");
        };
        let Some(debugfs) = e2fs_tool("debugfs") else {
            return unavailable_tool("debugfs");
        };
        let temporary = TestDirectory::create("ext4-deep-extents")?;
        let payload: Vec<u8> = (0..BLOCKS * BLOCK)
            .map(|index| u8::try_from(index % 251).unwrap_or_default())
            .collect();
        let image = fragmented_file_image(temporary.path(), &mke2fs, &e2fsck, &debugfs, &payload)?;
        assert_eq!(
            host_extent_depth(&debugfs, &image, "/big.bin")?,
            2,
            "the seeded file must already need two levels"
        );

        let limits = default_volume_limits()?;
        let appended = b"appended by troe\n";
        {
            let mut ext4 = mount_file_writable_with_limits(&image, limits)?;
            let inode = ext4
                .resolve("/big.bin")
                .map_err(|error| format!("cannot resolve: {error:?}"))?;
            assert_eq!(inode.extent_depth, 2);
            assert!(
                inode.extents.len() > max_depth_one_extent_ceiling(BLOCK),
                "the file must need more extents than one level holds: {}",
                inode.extents.len()
            );
            assert_eq!(provider_file_bytes(&mut ext4, "/big.bin")?, payload);

            // Appending rewrites the whole tree, which is the operation that
            // used to be refused once the extents no longer fit one level.
            ext4.append_file("/big.bin", appended)
                .map_err(|error| format!("cannot append to a deep tree: {error:?}"))?;
            // And again, so the tree TROE wrote is itself read back, rebuilt,
            // and released.
            ext4.append_file("/big.bin", appended)
                .map_err(|error| format!("cannot append twice: {error:?}"))?;

            // Replacing the file releases the whole deep tree rather than only
            // its leaves, and leaves a shallow one behind.
            ext4.write_file("/replaced.bin", b"seed\n")
                .map_err(|error| format!("cannot create beside a deep tree: {error:?}"))?;
            let deep = ext4
                .resolve("/big.bin")
                .map_err(|error| format!("cannot resolve: {error:?}"))?;
            assert_eq!(deep.extent_depth, 2, "the appended tree must be deep");
        }

        // A leaked or doubly-claimed tree block is a block-bitmap difference,
        // which this reports as an error rather than repairing.
        let check = Command::new(&e2fsck)
            .args(["-f", "-n"])
            .arg(&image)
            .output()
            .map_err(|error| error.to_string())?;
        command_succeeded(&check, "e2fsck after rewriting a deep extent tree")?;
        assert_eq!(
            host_extent_depth(&debugfs, &image, "/big.bin")?,
            2,
            "the tree TROE wrote must still have two levels"
        );

        let mut expected = payload.clone();
        expected.extend_from_slice(appended);
        expected.extend_from_slice(appended);
        let dumped = host_file_bytes(
            &debugfs,
            &image,
            "/big.bin",
            &temporary.path().join("dumped.bin"),
        )?;
        assert_eq!(dumped.len(), expected.len(), "host-visible length");
        assert!(
            dumped == expected,
            "the host must read back what TROE wrote"
        );

        {
            let mut ext4 = mount_file_with_limits(&image, limits)?;
            assert_eq!(provider_file_bytes(&mut ext4, "/big.bin")?, expected);
        }

        // Replacing the deep file entirely must release every level it held.
        {
            let mut ext4 = mount_file_writable_with_limits(&image, limits)?;
            ext4.write_file("/big.bin", b"replaced by troe\n")
                .map_err(|error| format!("cannot replace a deep tree: {error:?}"))?;
            let replaced = ext4
                .resolve("/big.bin")
                .map_err(|error| format!("cannot resolve: {error:?}"))?;
            assert_eq!(replaced.extent_depth, 0, "the replacement needs no tree");
        }
        let after_replace = Command::new(&e2fsck)
            .args(["-f", "-n"])
            .arg(&image)
            .output()
            .map_err(|error| error.to_string())?;
        command_succeeded(&after_replace, "e2fsck after replacing a deep extent tree")?;

        let mut ext4 = mount_file_with_limits(&image, limits)?;
        assert_eq!(
            provider_file_bytes(&mut ext4, "/big.bin")?,
            b"replaced by troe\n"
        );
        Ok(())
    }

    /// Extents a one-level tree holds at this block size, for test assertions.
    fn max_depth_one_extent_ceiling(block_bytes: usize) -> usize {
        crate::leaf_extents(block_bytes) * crate::EXT4_ROOT_INDEXES
    }

    /// Build one interior extent node with the given children.
    fn extent_index_block(depth: u16, children: &[(u32, u32)], seed: u32) -> Vec<u8> {
        let mut raw = alloc::vec![0_u8; EXT4_BLOCK_BYTES];
        let capacity = (EXT4_BLOCK_BYTES - EXT4_EXTENT_HEADER_BYTES - EXT4_EXTENT_TAIL_BYTES)
            / EXT4_EXTENT_RECORD_BYTES;
        put_u16(&mut raw, 0, EXT4_EXT_MAGIC);
        put_u16(&mut raw, 2, u16::try_from(children.len()).unwrap_or(0));
        put_u16(&mut raw, 4, u16::try_from(capacity).unwrap_or(0));
        put_u16(&mut raw, 6, depth);
        for (index, (logical, physical)) in children.iter().enumerate() {
            let offset = EXT4_EXTENT_HEADER_BYTES + index * EXT4_EXTENT_RECORD_BYTES;
            put_u32(&mut raw, offset, *logical);
            put_u32(&mut raw, offset + 4, *physical);
        }
        let tail = EXT4_EXTENT_HEADER_BYTES + capacity * EXT4_EXTENT_RECORD_BYTES;
        let checksum = crc32c(seed, &raw[..tail]);
        put_u32(&mut raw, tail, checksum);
        raw
    }

    #[test]
    fn walks_an_extent_tree_deeper_than_one_level() -> Result<(), FsError> {
        let seed = crc32c(u32::MAX, &UUID);
        let inode_seed = crc32c(
            crc32c(seed, &3_u32.to_le_bytes()),
            &FILE_GENERATION.to_le_bytes(),
        );

        // A root two levels above its leaves is accepted and reports its depth.
        let mut root = [0_u8; 60];
        put_u16(&mut root, 0, EXT4_EXT_MAGIC);
        put_u16(&mut root, 2, 1);
        put_u16(&mut root, 4, 4);
        put_u16(&mut root, 6, 2);
        put_u32(&mut root, 12, 0);
        put_u32(&mut root, 16, 30);
        let parsed = parse_extents(&root, 700_000)?;
        assert_eq!(parsed.depth, 2);
        assert_eq!(parsed.tree_blocks, [30]);

        // A node one level down names the leaves.
        let node = extent_index_block(1, &[(0, 31), (16, 32)], inode_seed);
        assert_eq!(
            parse_extent_index_block(&node, 700_000, 1, seed, 3, FILE_GENERATION)?,
            alloc::vec![(0, 31), (16, 32)]
        );

        // A node whose declared depth disagrees with its parent is refused,
        // because a mismatched level would be read as the wrong record kind.
        assert_eq!(
            parse_extent_index_block(&node, 700_000, 2, seed, 3, FILE_GENERATION),
            Err(FsError::Corrupt)
        );
        // So is a child pointing outside the volume, or a broken checksum.
        assert_eq!(
            parse_extent_index_block(&node, 31, 1, seed, 3, FILE_GENERATION),
            Err(FsError::Corrupt)
        );
        let mut torn = node.clone();
        torn[EXT4_EXTENT_HEADER_BYTES] ^= 0xFF;
        assert_eq!(
            parse_extent_index_block(&torn, 700_000, 1, seed, 3, FILE_GENERATION),
            Err(FsError::Corrupt)
        );
        // Children must ascend, so an out-of-order pair is refused.
        let unordered = extent_index_block(1, &[(16, 31), (0, 32)], inode_seed);
        assert_eq!(
            parse_extent_index_block(&unordered, 700_000, 1, seed, 3, FILE_GENERATION),
            Err(FsError::Corrupt)
        );
        // Truncation never panics.
        for length in 0..node.len() {
            assert!(
                parse_extent_index_block(&node[..length], 700_000, 1, seed, 3, FILE_GENERATION)
                    .is_err()
            );
        }

        // A tree deeper than ext4 itself builds is refused rather than walked.
        put_u16(&mut root, 6, EXT4_MAX_EXTENT_DEPTH + 1);
        assert!(matches!(
            parse_extents(&root, 700_000),
            Err(FsError::Unsupported)
        ));
        Ok(())
    }

    #[test]
    fn writes_to_a_volume_past_one_tebibyte() -> Result<(), String> {
        let Some(mke2fs) = e2fs_tool("mke2fs") else {
            return unavailable_tool("mke2fs");
        };
        let Some(e2fsck) = e2fs_tool("e2fsck") else {
            return unavailable_tool("e2fsck");
        };
        let temporary = TestDirectory::create("ext4-huge")?;
        let image = temporary.path().join("huge.ext4");
        File::create(&image)
            .and_then(|file| file.set_len(2 * 1024 * 1024 * 1024 * 1024))
            .map_err(|error| error.to_string())?;
        // The inode and journal ceilings only keep the sparse image small; the
        // point of this volume is its 16384 block groups.
        let format = Command::new(&mke2fs)
            .args(["-q", "-F", "-t", "ext4", "-N", "65536", "-J", "size=16"])
            .arg(&image)
            .output()
            .map_err(|error| error.to_string())?;
        command_succeeded(&format, "mke2fs two-tebibyte")?;

        {
            let mut ext4 = mount_file_writable_with_limits(&image, default_volume_limits()?)?;
            ext4.write_file("/created.txt", b"written past a tebibyte\n")
                .map_err(|error| format!("cannot write past a tebibyte: {error:?}"))?;
            ext4.create_directory("/archive")
                .map_err(|error| format!("cannot mkdir past a tebibyte: {error:?}"))?;
        }
        let check = Command::new(&e2fsck)
            .args(["-f", "-n"])
            .arg(&image)
            .output()
            .map_err(|error| error.to_string())?;
        command_succeeded(&check, "e2fsck after a two-tebibyte mutation")?;

        let mut ext4 = mount_file_with_limits(&image, default_volume_limits()?)?;
        let mut bytes = [0_u8; 32];
        let read = ext4
            .read_file("/created.txt", 0, &mut bytes)
            .map_err(|error| format!("cannot read back: {error:?}"))?;
        assert_eq!(&bytes[..read], b"written past a tebibyte\n");
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

    #[test]
    fn stamps_timestamps_only_when_a_clock_is_supplied() -> Result<(), String> {
        const NOW: u32 = 1_788_000_000;
        let Some(mke2fs) = e2fs_tool("mke2fs") else {
            return unavailable_tool("mke2fs");
        };
        let Some(e2fsck) = e2fs_tool("e2fsck") else {
            return unavailable_tool("e2fsck");
        };
        let temporary = TestDirectory::create("ext4-times")?;
        let image = default_mke2fs_image(temporary.path(), &mke2fs, 1024 * 1024 * 1024)?;

        // Without a clock the provider leaves every timestamp alone.
        {
            let mut ext4 = mount_file_writable_with_limits(&image, default_volume_limits()?)?;
            ext4.write_file("/unstamped.txt", b"no clock\n")
                .map_err(|error| format!("cannot create: {error:?}"))?;
            let times = inode_times(&mut ext4, "/unstamped.txt")?;
            assert_eq!(times, (0, 0, 0), "no clock must invent no time");
        }

        // A clock that reports no time is the same as having none at all.
        {
            let mut ext4 = mount_file_writable_with_limits(&image, default_volume_limits()?)?;
            ext4.set_wall_clock(TestClock::new(None));
            ext4.write_file("/unavailable.txt", b"clock present, time unknown\n")
                .map_err(|error| format!("cannot create: {error:?}"))?;
            let times = inode_times(&mut ext4, "/unavailable.txt")?;
            assert_eq!(times, (0, 0, 0), "an unreadable clock must invent no time");
        }

        // With a readable one, a created inode carries it and a later write
        // advances the modification time.
        {
            let mut ext4 = mount_file_writable_with_limits(&image, default_volume_limits()?)?;
            let clock = TestClock::new(Some(u64::from(NOW)));
            ext4.set_wall_clock(clock.clone());
            ext4.write_file("/stamped.txt", b"clocked\n")
                .map_err(|error| format!("cannot create: {error:?}"))?;
            assert_eq!(inode_times(&mut ext4, "/stamped.txt")?, (NOW, NOW, NOW));

            // The same mount reads the clock again, so it stamps the later
            // instant rather than the one it was mounted at.
            clock.set(Some(u64::from(NOW) + 60));
            ext4.write_file("/stamped.txt", b"clocked again\n")
                .map_err(|error| format!("cannot replace: {error:?}"))?;
            let (atime, ctime, mtime) = inode_times(&mut ext4, "/stamped.txt")?;
            assert_eq!(atime, NOW, "a write does not advance the access time");
            assert_eq!(ctime, NOW + 60);
            assert_eq!(mtime, NOW + 60);

            // A clock that moves backwards is recorded as it reads; the
            // provider reports the time it was told, not one of its own.
            clock.set(Some(u64::from(NOW) - 3_600));
            ext4.write_file("/stamped.txt", b"clocked backwards\n")
                .map_err(|error| format!("cannot rewrite: {error:?}"))?;
            let (_, ctime, mtime) = inode_times(&mut ext4, "/stamped.txt")?;
            assert_eq!(ctime, NOW - 3_600);
            assert_eq!(mtime, NOW - 3_600);
        }

        // Past 2038 the base field alone would read as 1901, so the epoch bits
        // in the extra word carry the instant instead.
        {
            const BEYOND_2038: u64 = 0x1_0000_0000 + 12_345;
            let mut ext4 = mount_file_writable_with_limits(&image, default_volume_limits()?)?;
            ext4.set_wall_clock(TestClock::new(Some(BEYOND_2038)));
            ext4.write_file("/far-future.txt", b"after 2038\n")
                .map_err(|error| format!("cannot create: {error:?}"))?;
            let inode = ext4
                .resolve("/far-future.txt")
                .map_err(|error| format!("cannot resolve: {error:?}"))?;
            let raw = ext4
                .raw_inode_record(inode.number)
                .map_err(|error| format!("cannot read inode: {error:?}"))?;
            for (base, extra) in [EXT4_MTIME, EXT4_CRTIME] {
                let seconds = u64::from(
                    read_u32(&raw, base)
                        .map_err(|error| format!("cannot read the time at {base}: {error:?}"))?,
                ) | (u64::from(
                    read_u32(&raw, extra)
                        .map_err(|error| format!("cannot read the epoch at {extra}: {error:?}"))?
                        & 0x3,
                ) << 32);
                assert_eq!(seconds, BEYOND_2038);
            }
        }

        let check = Command::new(&e2fsck)
            .args(["-f", "-n"])
            .arg(&image)
            .output()
            .map_err(|error| error.to_string())?;
        command_succeeded(&check, "e2fsck after stamped mutations")?;

        // The e2fsprogs reader decodes what a Linux host would, including the
        // epoch bits that carry an instant past 2038.
        let Some(debugfs) = e2fs_tool("debugfs") else {
            return unavailable_tool("debugfs");
        };
        for (path, seconds) in [
            ("/stamped.txt", u64::from(NOW) - 3_600),
            ("/far-future.txt", 0x1_0000_0000 + 12_345),
        ] {
            let stat = Command::new(&debugfs)
                .arg("-R")
                .arg(format!("stat {path}"))
                .arg(&image)
                .output()
                .map_err(|error| error.to_string())?;
            command_succeeded(&stat, "debugfs stat")?;
            let report = String::from_utf8_lossy(&stat.stdout).to_string();
            // e2fsprogs prints the base field and the extra word separately,
            // and the extra word here holds only the epoch bits.
            let base = seconds & u64::from(u32::MAX);
            let epoch = seconds >> 32;
            let expected = format!("mtime: {base:#010x}:{epoch:08x}");
            assert!(
                report.contains(&expected),
                "{path} must report {expected}, got:\n{report}"
            );
        }
        Ok(())
    }

    #[test]
    fn directory_times_advance_when_names_inside_change() -> Result<(), String> {
        const START: u64 = 1_788_000_000;
        let Some(mke2fs) = e2fs_tool("mke2fs") else {
            return unavailable_tool("mke2fs");
        };
        let temporary = TestDirectory::create("ext4-directory-times")?;
        let image = default_mke2fs_image(temporary.path(), &mke2fs, 1024 * 1024 * 1024)?;

        let mut ext4 = mount_file_writable_with_limits(&image, default_volume_limits()?)?;
        let clock = TestClock::new(Some(START));
        ext4.set_wall_clock(clock.clone());
        ext4.create_directory("/dir")
            .map_err(|error| format!("cannot create directory: {error:?}"))?;

        let stat = |ext4: &mut Ext4<_>| -> Result<(Option<u64>, Option<u64>), String> {
            let metadata = ext4
                .metadata("/dir")
                .map_err(|error| format!("cannot stat: {error:?}"))?;
            Ok((
                metadata.modified_unix_seconds,
                metadata.changed_unix_seconds,
            ))
        };

        let born = stat(&mut ext4)?;
        assert_eq!(born, (Some(START), Some(START)));

        // Each of the three name mutations advances both times, even though
        // none of them makes the directory gain or lose a block, which is the
        // only thing that used to rewrite its record.
        for (offset, action) in [(60_u64, "create"), (120, "rename"), (180, "remove")] {
            clock.set(Some(START + offset));
            match action {
                "create" => ext4.write_file("/dir/child.txt", b"inside\n"),
                "rename" => ext4.rename("/dir/child.txt", "/dir/renamed.txt"),
                _ => ext4.remove_file("/dir/renamed.txt"),
            }
            .map_err(|error| format!("cannot {action}: {error:?}"))?;
            assert_eq!(
                stat(&mut ext4)?,
                (Some(START + offset), Some(START + offset)),
                "a {action} inside a directory must advance both of its times"
            );
        }

        // Rewriting a file's contents changes the file, not its parent's set
        // of names, so the directory's times stand.
        clock.set(Some(START + 240));
        ext4.write_file("/dir/stable.txt", b"first\n")
            .map_err(|error| format!("cannot create: {error:?}"))?;
        let after_add = stat(&mut ext4)?;
        clock.set(Some(START + 300));
        ext4.write_file("/dir/stable.txt", b"second\n")
            .map_err(|error| format!("cannot rewrite: {error:?}"))?;
        assert_eq!(
            stat(&mut ext4)?,
            after_add,
            "replacing a file's contents must not advance its parent"
        );

        drop(ext4);
        let Some(e2fsck) = e2fs_tool("e2fsck") else {
            return unavailable_tool("e2fsck");
        };
        let check = Command::new(&e2fsck)
            .args(["-f", "-n"])
            .arg(&image)
            .output()
            .map_err(|error| error.to_string())?;
        command_succeeded(&check, "e2fsck after directory stamping")?;

        // e2fsck proves the image is consistent, not that a host reads the
        // time we meant. The last name mutation was creating stable.txt, so
        // that is the instant the e2fsprogs reader must report for /dir.
        let Some(debugfs) = e2fs_tool("debugfs") else {
            return unavailable_tool("debugfs");
        };
        let stat_output = Command::new(&debugfs)
            .arg("-R")
            .arg("stat /dir")
            .arg(&image)
            .output()
            .map_err(|error| error.to_string())?;
        command_succeeded(&stat_output, "debugfs stat /dir")?;
        let report = String::from_utf8_lossy(&stat_output.stdout).to_string();
        let expected = format!("mtime: {:#010x}:00000000", START + 240);
        assert!(
            report.contains(&expected),
            "/dir must report {expected} after a name was created inside it, \
             got:\n{report}"
        );
        Ok(())
    }

    #[test]
    fn metadata_reports_change_and_creation_times() -> Result<(), String> {
        const NOW: u64 = 1_788_000_000;
        let Some(mke2fs) = e2fs_tool("mke2fs") else {
            return unavailable_tool("mke2fs");
        };
        let temporary = TestDirectory::create("ext4-change-creation")?;
        let image = default_mke2fs_image(temporary.path(), &mke2fs, 1024 * 1024 * 1024)?;

        let mut ext4 = mount_file_writable_with_limits(&image, default_volume_limits()?)?;
        let clock = TestClock::new(Some(NOW));
        ext4.set_wall_clock(clock.clone());
        ext4.write_file("/tracked.txt", b"first\n")
            .map_err(|error| format!("cannot create: {error:?}"))?;

        // An inode is born with all three at the same instant.
        let born = ext4
            .metadata("/tracked.txt")
            .map_err(|error| format!("cannot stat: {error:?}"))?;
        assert_eq!(born.modified_unix_seconds, Some(NOW));
        assert_eq!(born.changed_unix_seconds, Some(NOW));
        assert_eq!(born.created_unix_seconds, Some(NOW));

        // A rename changes the record without touching the payload, which is
        // exactly the case a modification time cannot see. This is the whole
        // reason the change time is worth exposing.
        clock.set(Some(NOW + 60));
        ext4.rename("/tracked.txt", "/renamed.txt")
            .map_err(|error| format!("cannot rename: {error:?}"))?;
        let renamed = ext4
            .metadata("/renamed.txt")
            .map_err(|error| format!("cannot stat: {error:?}"))?;
        assert_eq!(
            renamed.modified_unix_seconds,
            Some(NOW),
            "a rename leaves the payload, so the modification time stands"
        );
        assert_eq!(
            renamed.changed_unix_seconds,
            Some(NOW + 60),
            "a rename rewrites the record, so the change time advances"
        );
        assert_eq!(
            renamed.created_unix_seconds,
            Some(NOW),
            "creation never advances"
        );

        // A payload write advances both, and still leaves creation alone.
        clock.set(Some(NOW + 120));
        ext4.write_file("/renamed.txt", b"second\n")
            .map_err(|error| format!("cannot rewrite: {error:?}"))?;
        let rewritten = ext4
            .metadata("/renamed.txt")
            .map_err(|error| format!("cannot stat: {error:?}"))?;
        assert_eq!(rewritten.modified_unix_seconds, Some(NOW + 120));
        assert_eq!(rewritten.changed_unix_seconds, Some(NOW + 120));
        assert_eq!(rewritten.created_unix_seconds, Some(NOW));
        Ok(())
    }

    /// Read one inode's access, change, and modification times.
    fn inode_times<D: BlockDevice>(
        ext4: &mut Ext4<D>,
        path: &str,
    ) -> Result<(u32, u32, u32), String> {
        let inode = ext4
            .resolve(path)
            .map_err(|error| format!("cannot resolve {path}: {error:?}"))?;
        let raw = ext4
            .raw_inode_record(inode.number)
            .map_err(|error| format!("cannot read inode: {error:?}"))?;
        let field = |offset: usize| {
            read_u32(&raw, offset).map_err(|error| format!("short inode: {error:?}"))
        };
        Ok((field(8)?, field(12)?, field(16)?))
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

    #[test]
    #[ignore = "writes and verifies a 128 MiB real ext4 file"]
    fn streams_128_mib_to_real_ext4_with_bounded_chunks() -> Result<(), String> {
        const IMAGE_BYTES: u64 = 256 * 1024 * 1024;
        const FILE_BYTES: u64 = 128 * 1024 * 1024;
        const CHUNK_BYTES: usize = 1024 * 1024;
        let Some(mke2fs) = e2fs_tool("mke2fs") else {
            return unavailable_tool("mke2fs");
        };
        let Some(e2fsck) = e2fs_tool("e2fsck") else {
            return unavailable_tool("e2fsck");
        };
        let temporary = TestDirectory::create("ext4-large-stream")?;
        let image = temporary.path().join("filesystem.ext4");
        File::create(&image)
            .and_then(|file| file.set_len(IMAGE_BYTES))
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
            ])
            .arg(&image)
            .output()
            .map_err(|error| error.to_string())?;
        command_succeeded(&format, "mke2fs for large stream")?;

        let stress_limits = Ext4Limits::new(8, 32, 16, 128, IMAGE_BYTES, CHUNK_BYTES, 64)
            .map_err(|error| error.to_string())?;
        let mut ext4 = mount_file_writable_with_limits(&image, stress_limits)?;
        ext4.truncate_file("/large.bin")
            .map_err(|error| error.to_string())?;
        let chunk = vec![0x5a; CHUNK_BYTES];
        for _ in 0..FILE_BYTES / CHUNK_BYTES as u64 {
            ext4.append_file("/large.bin", &chunk)
                .map_err(|error| error.to_string())?;
        }
        ext4.sync_file("/large.bin")
            .map_err(|error| error.to_string())?;
        assert_eq!(
            ext4.metadata("/large.bin")
                .map_err(|error| error.to_string())?
                .byte_count,
            FILE_BYTES
        );
        for offset in [0, FILE_BYTES / 2, FILE_BYTES - 4096] {
            let mut sample = [0_u8; 4096];
            assert_eq!(
                ext4.read_file("/large.bin", offset, &mut sample)
                    .map_err(|error| error.to_string())?,
                sample.len()
            );
            assert!(sample.iter().all(|byte| *byte == 0x5a));
        }
        drop(ext4);

        let check = Command::new(e2fsck)
            .args(["-fn"])
            .arg(&image)
            .output()
            .map_err(|error| error.to_string())?;
        command_succeeded(&check, "e2fsck after 128 MiB streamed write")
    }
}
