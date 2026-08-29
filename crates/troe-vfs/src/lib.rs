//! Portable virtual namespace with immutable and quota-bound writable nodes.
#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;

use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::{fmt, str};
use troe_core::MemoryStats;

/// Maximum encoded path length.
pub const MAX_PATH_BYTES: usize = 1024;
/// Maximum single path component length.
///
/// This is ext4's own limit, so a foreign volume's names are representable.
pub const MAX_NAME_BYTES: usize = 255;
/// Maximum normalized path depth.
pub const MAX_PATH_DEPTH: usize = 16;
/// Product-name-independent KEFS v1 format identifier.
pub const KEFS_V1_MAGIC: [u8; 8] = *b"KEFSv1\0\0";
const KEFS_HEADER_LEN: usize = 16;
const PROVIDER_READ_CHUNK: usize = 4 * 1024;
/// Default working-set target used when complete-file compatibility helpers stream.
///
/// This is four ext4 blocks. It is a transfer size, never a file-size ceiling.
pub const FILE_IO_BUFFER_BYTES: usize = 16 * 1024;
/// Largest app-selected file-stream aggregation size.
pub const MAX_FILE_IO_BUFFER_BYTES: usize = 1024 * 1024;
const MAX_PROVIDER_DIRECTORY_ENTRIES: usize = 1024;
const MAX_PROVIDER_DIRECTORY_BYTES: usize = 64 * 1024;
/// Maximum files in one active-generation `/sys/config` projection.
pub const MAX_SYSTEM_CONFIG_FILES: usize = 128;
/// Maximum aggregate bytes in one active-generation configuration projection.
pub const MAX_SYSTEM_CONFIG_BYTES: usize = 64 * 1024;
/// Maximum bytes in one projected configuration file.
pub const MAX_SYSTEM_CONFIG_FILE_BYTES: usize = 8 * 1024;

/// Node kind visible through the namespace.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NodeKind {
    /// Directory node.
    Directory,
    /// Regular byte file.
    File,
    /// Symbolic link resolved by its owning provider.
    Symlink,
}

/// Filesystem failures.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FsError {
    /// Path syntax or embedded metadata is invalid.
    Invalid,
    /// The named node was not found.
    NotFound,
    /// A file was used as a directory or the reverse.
    WrongType,
    /// The requested mutation targets immutable content.
    ReadOnly,
    /// A byte, node, file-size, or depth quota would be exceeded.
    NoSpace,
    /// Checked offset or size arithmetic overflowed.
    Overflow,
    /// A node already exists.
    Exists,
    /// Persistent provider metadata is malformed or internally inconsistent.
    Corrupt,
    /// The provider's bounded transport failed.
    Io,
    /// The media uses a feature outside the selected provider profile.
    Unsupported,
    /// A directory removal targeted a directory that still has children.
    NotEmpty,
    /// A name operation crossed filesystem-provider boundaries.
    CrossDevice,
}

impl fmt::Display for FsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Invalid => f.write_str("invalid path or filesystem image"),
            Self::NotFound => f.write_str("not found"),
            Self::WrongType => f.write_str("wrong node type"),
            Self::ReadOnly => f.write_str("read-only filesystem"),
            Self::NoSpace => f.write_str("filesystem quota exceeded"),
            Self::Overflow => f.write_str("filesystem size overflow"),
            Self::Exists => f.write_str("already exists"),
            Self::Corrupt => f.write_str("filesystem metadata is corrupt"),
            Self::Io => f.write_str("filesystem transport failed"),
            Self::Unsupported => f.write_str("filesystem feature is unsupported"),
            Self::NotEmpty => f.write_str("directory not empty"),
            Self::CrossDevice => f.write_str("cross-device operation"),
        }
    }
}

/// Provider-independent metadata returned without exposing format structures.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FileMetadata {
    /// Visible object kind.
    pub kind: NodeKind,
    /// Exact file payload bytes, or zero for a directory.
    pub byte_count: u64,
}

/// One bounded page of a provider directory traversal.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProviderListing {
    /// Entries retained within the caller's count and byte ceilings.
    pub entries: Vec<DirEntry>,
    /// Opaque provider cursor for the next page, or `None` at end-of-directory.
    pub next_cursor: Option<u64>,
}

/// Narrow filesystem-provider interface consumed by the VFS.
///
/// Paths are absolute within the provider root and must already satisfy the
/// VFS normalization bounds. Providers independently validate them because a
/// capability client must not be able to bypass the namespace layer.
pub trait ReadOnlyFileSystem: fmt::Debug {
    /// Resolve one path without reading file payload data.
    ///
    /// # Errors
    ///
    /// Rejects invalid or missing paths, wrong types, corrupt or unsupported
    /// media, transport failures, and provider resource exhaustion.
    fn metadata(&mut self, path: &str) -> Result<FileMetadata, FsError>;

    /// Resolve one path without following its final symbolic link.
    ///
    /// Providers without symbolic links may retain this default. Providers
    /// that implement symbolic links must override it so directory-capability
    /// validation can reject traversal before the requested operation.
    ///
    /// # Errors
    ///
    /// Rejects invalid or missing paths, corrupt media, transport failures, and
    /// provider resource exhaustion.
    fn metadata_no_follow(&mut self, path: &str) -> Result<FileMetadata, FsError> {
        self.metadata(path)
    }

    /// Read at most `destination.len()` bytes at an exact file offset.
    ///
    /// A successful zero return is EOF. Providers must either fill the returned
    /// prefix completely or fail without claiming those bytes.
    ///
    /// # Errors
    ///
    /// Rejects invalid or non-file paths, offset arithmetic, requests above the
    /// provider profile, corrupt or unsupported media, and transport failures.
    fn read_file(
        &mut self,
        path: &str,
        offset: u64,
        destination: &mut [u8],
    ) -> Result<usize, FsError>;

    /// Return a bounded lexical page of immediate directory children.
    ///
    /// `cursor` is zero for the first page and otherwise must be a value returned
    /// by the same provider instance. Entry-name bytes are charged to
    /// `max_name_bytes`; a zero budget returns an empty page and, when entries
    /// remain, a continuation cursor.
    ///
    /// # Errors
    ///
    /// Rejects invalid cursors or paths, non-directories, corrupt or unsupported
    /// media, transport failures, and provider resource exhaustion.
    fn list(
        &mut self,
        path: &str,
        cursor: u64,
        max_entries: usize,
        max_name_bytes: usize,
    ) -> Result<ProviderListing, FsError>;

    /// Truncate an existing regular file or create an empty one.
    ///
    /// Read-only providers retain this default. A writable provider must not
    /// report success until its declared durability transaction completes.
    ///
    /// # Errors
    ///
    /// The default rejects every request as read-only. Writable providers
    /// report their bounded path, space, corruption, or transport failures.
    fn truncate_file(&mut self, _path: &str) -> Result<(), FsError> {
        Err(FsError::ReadOnly)
    }

    /// Append one nonempty chunk to a regular file.
    ///
    /// Providers must retain only bounded working state independent of the
    /// resulting file size. The file may be partially extended if later I/O
    /// fails, matching ordinary streamed file-write semantics.
    ///
    /// # Errors
    ///
    /// The default rejects every request as read-only. Writable providers
    /// report format, media-capacity, corruption, or transport failures.
    fn append_file(&mut self, _path: &str, _bytes: &[u8]) -> Result<(), FsError> {
        Err(FsError::ReadOnly)
    }

    /// Complete and durably order a streamed file write.
    ///
    /// # Errors
    ///
    /// The default rejects every request as read-only.
    fn sync_file(&mut self, _path: &str) -> Result<(), FsError> {
        Err(FsError::ReadOnly)
    }

    /// Compatibility helper that replaces one complete regular file by
    /// feeding it to the provider in bounded chunks.
    ///
    /// # Errors
    ///
    /// Reports the first truncate, append, or durability failure. A failure
    /// after truncation can leave a prefix, as for a conventional write loop.
    fn write_file(&mut self, path: &str, bytes: &[u8]) -> Result<(), FsError> {
        self.truncate_file(path)?;
        for chunk in bytes.chunks(FILE_IO_BUFFER_BYTES) {
            self.append_file(path, chunk)?;
        }
        self.sync_file(path)
    }

    /// Create one empty directory without replacing an existing entry.
    ///
    /// Read-only providers retain this default.
    ///
    /// # Errors
    ///
    /// The default rejects every request as read-only. Writable providers
    /// report invalid parents, collisions, space, corruption, or transport failures.
    fn create_directory(&mut self, _path: &str) -> Result<(), FsError> {
        Err(FsError::ReadOnly)
    }

    /// Atomically remove one regular file or symbolic-link directory entry.
    ///
    /// Read-only providers retain this default.
    ///
    /// # Errors
    ///
    /// The default rejects every request as read-only. Writable providers
    /// report their bounded path, corruption, or transport failures.
    fn remove_file(&mut self, _path: &str) -> Result<(), FsError> {
        Err(FsError::ReadOnly)
    }

    /// Atomically remove one empty directory entry.
    ///
    /// Provider roots are never valid targets. Read-only providers retain this
    /// default; writable providers must reject nonempty directories precisely.
    ///
    /// # Errors
    ///
    /// The default rejects every request as read-only.
    fn remove_directory(&mut self, _path: &str) -> Result<(), FsError> {
        Err(FsError::ReadOnly)
    }

    /// Atomically rename one object within this provider.
    ///
    /// Both paths are absolute within the same provider. Providers must reject
    /// their root and must not expose a partially renamed namespace on error.
    ///
    /// # Errors
    ///
    /// The default rejects every request as read-only.
    fn rename(&mut self, _source: &str, _destination: &str) -> Result<(), FsError> {
        Err(FsError::ReadOnly)
    }

    /// Read the exact UTF-8 target stored in one symbolic link without following it.
    ///
    /// # Errors
    ///
    /// Providers without symbolic-link support return [`FsError::Unsupported`].
    fn read_link(&mut self, _path: &str) -> Result<String, FsError> {
        Err(FsError::Unsupported)
    }

    /// Create one symbolic link without replacing an existing directory entry.
    ///
    /// # Errors
    ///
    /// Read-only providers retain this default. Writable providers report
    /// unsupported formats, invalid targets, collisions, or persistence failures.
    fn create_symlink(&mut self, _target: &str, _link_path: &str) -> Result<(), FsError> {
        Err(FsError::ReadOnly)
    }

    /// Add a hard-link name for an existing regular file.
    ///
    /// # Errors
    ///
    /// Read-only providers retain this default. Providers must reject directories
    /// and cross-filesystem requests.
    fn create_hard_link(&mut self, _existing: &str, _new_path: &str) -> Result<(), FsError> {
        Err(FsError::ReadOnly)
    }
}

#[derive(Clone, Debug)]
enum Node {
    Directory,
    File { bytes: Vec<u8>, writable: bool },
}

impl Node {
    const fn kind(&self) -> NodeKind {
        match self {
            Self::Directory => NodeKind::Directory,
            Self::File { .. } => NodeKind::File,
        }
    }
}

/// Explicit limits for the writable `/tmp` filesystem.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RamFsQuota {
    /// Maximum total file payload bytes.
    pub max_bytes: usize,
    /// Maximum writable file count.
    pub max_nodes: usize,
    /// Maximum payload bytes in one file.
    pub max_file_bytes: usize,
}

/// Closed rights attached to one package-resolved directory capability.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DirectoryRights(u8);

impl DirectoryRights {
    /// Read metadata, directory entries, links, and file bytes.
    pub const READ: Self = Self(1);
    /// Mutate names and file payloads without implicitly granting reads.
    pub const MUTATE: Self = Self(2);
    /// Read and mutate beneath the same resolved directory object.
    pub const READ_MUTATE: Self = Self(Self::READ.0 | Self::MUTATE.0);

    const fn allows(self, required: Self) -> bool {
        self.0 & required.0 == required.0
    }
}

/// One immutable, generation-bound directory authority.
///
/// Applications never receive `root` or `provider_root` as path authority.
/// They submit relative paths through their typed service handle; the service
/// validates those paths against this retained object before namespace access.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DirectoryCapability {
    root: String,
    provider_root: Option<String>,
    generation: u64,
    rights: DirectoryRights,
}

impl DirectoryCapability {
    /// Absolute namespace root selected during generation activation.
    #[must_use]
    pub fn root(&self) -> &str {
        &self.root
    }

    /// Immutable system generation which owns this authority.
    #[must_use]
    pub const fn generation(&self) -> u64 {
        self.generation
    }

    /// Exact read/mutation rights fixed at activation.
    #[must_use]
    pub const fn rights(&self) -> DirectoryRights {
        self.rights
    }
}

impl Default for RamFsQuota {
    fn default() -> Self {
        Self {
            max_bytes: 1024 * 1024,
            max_nodes: 128,
            max_file_bytes: 1024 * 1024,
        }
    }
}

/// One deterministic directory entry.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DirEntry {
    /// Base name, without its parent path.
    pub name: String,
    /// Kind of node.
    pub kind: NodeKind,
}

/// Bounded directory query result.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DirectoryListing {
    /// Matching entries retained within the requested budgets.
    pub entries: Vec<DirEntry>,
    /// Whether at least one matching entry was omitted by a budget.
    pub truncated: bool,
}

/// Unified immutable-root and writable-RAM namespace.
#[derive(Debug)]
struct ProviderMount {
    path: String,
    provider: Box<dyn ReadOnlyFileSystem>,
    writable: bool,
}

/// Unified immutable-root, writable-RAM, and mounted-provider namespace.
#[derive(Debug)]
pub struct Namespace {
    nodes: BTreeMap<String, Node>,
    mounts: Vec<ProviderMount>,
    command_revision: u64,
    quota: RamFsQuota,
    ramfs_bytes: usize,
    ramfs_nodes: usize,
    ramfs_high_water: usize,
    system_config_generation: u64,
}

impl Namespace {
    /// Create the fixed root skeleton.
    #[must_use]
    pub fn new(quota: RamFsQuota) -> Self {
        let mut nodes = BTreeMap::new();
        nodes.insert("/".to_string(), Node::Directory);
        nodes.insert("/tmp".to_string(), Node::Directory);
        nodes.insert("/sys".to_string(), Node::Directory);
        nodes.insert("/config".to_string(), Node::Directory);
        nodes.insert("/sys/config".to_string(), Node::Directory);
        Self {
            nodes,
            mounts: Vec::new(),
            command_revision: 0,
            quota,
            ramfs_bytes: 0,
            ramfs_nodes: 0,
            ramfs_high_water: 0,
            system_config_generation: 0,
        }
    }

    /// Atomically replace the read-only active-generation configuration view.
    ///
    /// Relative paths must be unique, strictly sorted, and canonical. Missing
    /// parent directories are constructed inside the staged projection. The
    /// desired `/config` tree is not read or changed by this operation.
    ///
    /// # Errors
    ///
    /// Rejects generation zero, count/byte/depth limits, noncanonical paths,
    /// duplicate or unsorted entries, and file/directory collisions without
    /// changing the visible projection or its generation identity.
    pub fn replace_system_config(
        &mut self,
        generation: u64,
        files: &[(&str, &[u8])],
    ) -> Result<(), FsError> {
        if generation == 0 || files.len() > MAX_SYSTEM_CONFIG_FILES {
            return Err(FsError::Invalid);
        }
        let mut total_bytes = 0_usize;
        let mut previous: Option<&str> = None;
        let mut staged = self.nodes.clone();
        staged.retain(|path, _node| !path.starts_with("/sys/config/"));
        for (relative, bytes) in files {
            if relative.is_empty()
                || bytes.len() > MAX_SYSTEM_CONFIG_FILE_BYTES
                || previous.is_some_and(|value| value >= *relative)
            {
                return Err(FsError::Invalid);
            }
            previous = Some(relative);
            total_bytes = total_bytes
                .checked_add(bytes.len())
                .ok_or(FsError::Overflow)?;
            if total_bytes > MAX_SYSTEM_CONFIG_BYTES {
                return Err(FsError::NoSpace);
            }
            let resolved = canonicalize_beneath("/sys/config", relative)?;
            let expected = String::from("/sys/config/") + relative;
            if resolved != expected {
                return Err(FsError::Invalid);
            }
            let mut parent = String::from("/sys/config");
            let mut components = relative.split('/').peekable();
            while let Some(component) = components.next() {
                if components.peek().is_none() {
                    break;
                }
                parent.push('/');
                parent.push_str(component);
                match staged.get(&parent) {
                    Some(Node::Directory) => {}
                    Some(Node::File { .. }) => return Err(FsError::WrongType),
                    None => {
                        staged.insert(parent.clone(), Node::Directory);
                    }
                }
            }
            if staged.contains_key(&resolved) {
                return Err(FsError::WrongType);
            }
            staged.insert(
                resolved,
                Node::File {
                    bytes: bytes.to_vec(),
                    writable: false,
                },
            );
        }
        self.nodes = staged;
        self.system_config_generation = generation;
        Ok(())
    }

    /// Generation whose normalized configuration is visible under `/sys/config`.
    #[must_use]
    pub const fn system_config_generation(&self) -> u64 {
        self.system_config_generation
    }

    /// Insert an immutable directory while composing the initial namespace.
    ///
    /// # Errors
    ///
    /// Fails for an invalid, duplicate, root, or parentless path.
    pub fn add_read_only_dir(&mut self, path: &str) -> Result<(), FsError> {
        let path = canonicalize("/", path)?;
        if self.mount_for_path(&path).is_some() {
            return Err(FsError::ReadOnly);
        }
        self.insert_composed(path, Node::Directory)
    }

    /// Insert an immutable file while composing the initial namespace.
    ///
    /// # Errors
    ///
    /// Fails for an invalid, duplicate, root, or parentless path.
    pub fn add_read_only_file(&mut self, path: &str, bytes: &[u8]) -> Result<(), FsError> {
        let path = canonicalize("/", path)?;
        if self.mount_for_path(&path).is_some() {
            return Err(FsError::ReadOnly);
        }
        self.insert_composed(
            path,
            Node::File {
                bytes: bytes.to_vec(),
                writable: false,
            },
        )
    }

    /// Create or refresh a generated `/sys` file during trusted composition.
    ///
    /// # Errors
    ///
    /// Fails outside `/sys`, for an invalid path, or for a directory target.
    pub fn set_system_file(&mut self, path: &str, bytes: &[u8]) -> Result<(), FsError> {
        let path = canonicalize("/", path)?;
        if !path.starts_with("/sys/") || is_active_configuration_path(&path) {
            return Err(FsError::ReadOnly);
        }
        let parent = parent_path(&path).ok_or(FsError::Invalid)?;
        if !matches!(self.nodes.get(parent), Some(Node::Directory)) {
            return Err(FsError::NotFound);
        }
        if matches!(self.nodes.get(&path), Some(Node::Directory)) {
            return Err(FsError::WrongType);
        }
        self.nodes.insert(
            path,
            Node::File {
                bytes: bytes.to_vec(),
                writable: false,
            },
        );
        Ok(())
    }

    fn insert_composed(&mut self, path: String, node: Node) -> Result<(), FsError> {
        if is_reserved_configuration_content(&path) {
            return Err(FsError::ReadOnly);
        }
        if path == "/" || self.nodes.contains_key(&path) {
            return Err(FsError::Exists);
        }
        let parent = parent_path(&path).ok_or(FsError::Invalid)?;
        if !matches!(self.nodes.get(parent), Some(Node::Directory)) {
            return Err(FsError::NotFound);
        }
        let changes_commands = is_command_path(&path);
        self.nodes.insert(path, node);
        if changes_commands {
            self.bump_command_revision();
        }
        Ok(())
    }

    /// Validate and mount a deterministic KEFS v1 image.
    ///
    /// # Errors
    ///
    /// Fails atomically if metadata, bounds, ordering, paths, or parents are invalid.
    pub fn mount_embedded(&mut self, image: &[u8]) -> Result<(), FsError> {
        let parsed = parse_embedded(image)?;
        let changes_commands = parsed.iter().any(|entry| is_command_path(&entry.path));
        let mut staged = self.nodes.clone();
        for entry in parsed {
            if is_reserved_configuration_content(&entry.path)
                || self.mount_for_path(&entry.path).is_some()
            {
                return Err(FsError::ReadOnly);
            }
            let node = match entry.kind {
                NodeKind::Directory => Node::Directory,
                NodeKind::File => Node::File {
                    bytes: entry.data,
                    writable: false,
                },
                NodeKind::Symlink => return Err(FsError::Unsupported),
            };
            insert_node(&mut staged, entry.path, node)?;
        }
        self.nodes = staged;
        if changes_commands {
            self.bump_command_revision();
        }
        Ok(())
    }

    /// Attach a validated read-only provider at one empty namespace path.
    ///
    /// # Errors
    ///
    /// Rejects root, invalid or duplicate mount paths, missing internal parent
    /// directories, nested mounts, and providers whose root is not a directory.
    pub fn mount_read_only(
        &mut self,
        path: &str,
        provider: Box<dyn ReadOnlyFileSystem>,
    ) -> Result<(), FsError> {
        self.mount_provider(path, provider, false)
    }

    /// Attach a validated writable provider at one empty namespace path.
    ///
    /// # Errors
    ///
    /// Applies the same path, collision, nesting, and provider-root checks as
    /// [`Self::mount_read_only`].
    pub fn mount_writable(
        &mut self,
        path: &str,
        provider: Box<dyn ReadOnlyFileSystem>,
    ) -> Result<(), FsError> {
        self.mount_provider(path, provider, true)
    }

    /// Resolve one immutable directory capability during generation activation.
    ///
    /// The root must be an existing directory reached without symbolic-link
    /// traversal. The returned object fixes the current provider boundary so a
    /// later namespace mount cannot silently widen it.
    ///
    /// # Errors
    ///
    /// Rejects generation zero, invalid or non-directory roots, symbolic-link
    /// traversal, allocation failure, and provider errors.
    pub fn grant_directory(
        &mut self,
        root: &str,
        generation: u64,
        rights: DirectoryRights,
    ) -> Result<DirectoryCapability, FsError> {
        if generation == 0 {
            return Err(FsError::Invalid);
        }
        let normalized_root = canonicalize("/", root)?;
        if normalized_root == "/" || normalized_root != root {
            return Err(FsError::Invalid);
        }
        let root = normalized_root;
        let metadata = self.metadata_no_follow_absolute(&root)?;
        if metadata.kind != NodeKind::Directory {
            return Err(FsError::WrongType);
        }
        self.validate_no_symlink_path(&root, &root, false)?;
        let provider_root = self
            .mount_for_path(&root)
            .map(|(index, _)| self.mounts[index].path.clone());
        Ok(DirectoryCapability {
            root,
            provider_root,
            generation,
            rights,
        })
    }

    /// Resolve one existing read target beneath a directory capability.
    ///
    /// # Errors
    ///
    /// Rejects stale generations, missing read authority, absolute paths,
    /// parent escape, mount crossing, symbolic links, and provider failures.
    pub fn resolve_directory_read(
        &mut self,
        capability: &DirectoryCapability,
        active_generation: u64,
        path: &str,
    ) -> Result<String, FsError> {
        self.resolve_directory_path(
            capability,
            active_generation,
            path,
            DirectoryRights::READ,
            false,
            false,
        )
    }

    /// Resolve a mutation target beneath a directory capability.
    ///
    /// `allow_missing_final` permits creation only after every retained parent
    /// has been proven directory-valued and symlink-free.
    ///
    /// # Errors
    ///
    /// Rejects stale generations, missing mutation authority, escape attempts,
    /// mount crossing, symbolic links, invalid parents, and provider failures.
    pub fn resolve_directory_mutation(
        &mut self,
        capability: &DirectoryCapability,
        active_generation: u64,
        path: &str,
        allow_missing_final: bool,
    ) -> Result<String, FsError> {
        self.resolve_directory_path(
            capability,
            active_generation,
            path,
            DirectoryRights::MUTATE,
            allow_missing_final,
            false,
        )
    }

    /// Resolve a final symbolic-link entry without following it.
    ///
    /// Intermediate symbolic links and mount crossings remain forbidden.
    ///
    /// # Errors
    ///
    /// Rejects stale generations, missing authority, escape attempts, invalid
    /// parents, or a final non-link object.
    pub fn resolve_directory_link(
        &mut self,
        capability: &DirectoryCapability,
        active_generation: u64,
        path: &str,
        mutation: bool,
    ) -> Result<String, FsError> {
        let required = if mutation {
            DirectoryRights::MUTATE
        } else {
            DirectoryRights::READ
        };
        let resolved = self.resolve_directory_path(
            capability,
            active_generation,
            path,
            required,
            false,
            true,
        )?;
        if self.metadata_no_follow_absolute(&resolved)?.kind != NodeKind::Symlink {
            return Err(FsError::WrongType);
        }
        Ok(resolved)
    }

    fn resolve_directory_path(
        &mut self,
        capability: &DirectoryCapability,
        active_generation: u64,
        path: &str,
        required: DirectoryRights,
        allow_missing_final: bool,
        allow_final_symlink: bool,
    ) -> Result<String, FsError> {
        if active_generation == 0
            || active_generation != capability.generation
            || !capability.rights.allows(required)
        {
            return Err(FsError::ReadOnly);
        }
        let resolved = canonicalize_beneath(&capability.root, path)?;
        let current_provider = self
            .mount_for_path(&resolved)
            .map(|(index, _)| self.mounts[index].path.as_str());
        if current_provider != capability.provider_root.as_deref() {
            return Err(FsError::Invalid);
        }
        self.validate_no_symlink_path(&capability.root, &resolved, allow_missing_final)?;
        if !allow_final_symlink
            && self
                .metadata_no_follow_absolute(&resolved)
                .is_ok_and(|metadata| metadata.kind == NodeKind::Symlink)
        {
            return Err(FsError::Invalid);
        }
        Ok(resolved)
    }

    fn validate_no_symlink_path(
        &mut self,
        root: &str,
        target: &str,
        allow_missing_final: bool,
    ) -> Result<(), FsError> {
        let suffix = target
            .strip_prefix(root)
            .filter(|suffix| suffix.is_empty() || suffix.starts_with('/'))
            .ok_or(FsError::Invalid)?;
        let root_metadata = self.metadata_no_follow_absolute(root)?;
        if root_metadata.kind != NodeKind::Directory {
            return Err(FsError::WrongType);
        }
        let mut current = root.to_string();
        let components: Vec<&str> = suffix
            .trim_start_matches('/')
            .split('/')
            .filter(|component| !component.is_empty())
            .collect();
        for (index, component) in components.iter().enumerate() {
            if current != "/" {
                current.push('/');
            }
            current.push_str(component);
            let final_component = index + 1 == components.len();
            let metadata = match self.metadata_no_follow_absolute(&current) {
                Ok(metadata) => metadata,
                Err(FsError::NotFound) if final_component && allow_missing_final => return Ok(()),
                Err(error) => return Err(error),
            };
            if metadata.kind == NodeKind::Symlink {
                if final_component {
                    return Ok(());
                }
                return Err(FsError::Invalid);
            }
            if !final_component && metadata.kind != NodeKind::Directory {
                return Err(FsError::WrongType);
            }
        }
        Ok(())
    }

    fn metadata_no_follow_absolute(&mut self, path: &str) -> Result<FileMetadata, FsError> {
        let path = canonicalize("/", path)?;
        if let Some((index, relative)) = self.mount_for_path(&path) {
            return self.mounts[index].provider.metadata_no_follow(&relative);
        }
        match self.nodes.get(&path) {
            Some(Node::Directory) => Ok(FileMetadata {
                kind: NodeKind::Directory,
                byte_count: 0,
            }),
            Some(Node::File { bytes, .. }) => Ok(FileMetadata {
                kind: NodeKind::File,
                byte_count: u64::try_from(bytes.len()).map_err(|_| FsError::Overflow)?,
            }),
            None => Err(FsError::NotFound),
        }
    }

    fn mount_provider(
        &mut self,
        path: &str,
        mut provider: Box<dyn ReadOnlyFileSystem>,
        writable: bool,
    ) -> Result<(), FsError> {
        let path = canonicalize("/", path)?;
        if is_active_configuration_path(&path)
            || path.starts_with("/config/")
            || (path == "/config" && !writable)
        {
            return Err(FsError::ReadOnly);
        }
        if path == "/" || self.mount_for_path(&path).is_some() {
            return Err(FsError::Exists);
        }
        let target_exists = match self.nodes.get(&path) {
            None => false,
            Some(Node::Directory)
                if !self.nodes.keys().any(|candidate| {
                    candidate != &path
                        && parent_path(candidate).is_some_and(|parent| parent == path)
                }) =>
            {
                true
            }
            Some(_) => return Err(FsError::Exists),
        };
        let parent = parent_path(&path).ok_or(FsError::Invalid)?;
        if !matches!(self.nodes.get(parent), Some(Node::Directory))
            || self.mount_for_path(parent).is_some()
        {
            return Err(FsError::NotFound);
        }
        if provider.metadata("/")?.kind != NodeKind::Directory {
            return Err(FsError::WrongType);
        }
        if !target_exists {
            self.nodes.insert(path.clone(), Node::Directory);
        }
        let changes_commands = is_command_path(&path);
        self.mounts.push(ProviderMount {
            path,
            provider,
            writable,
        });
        self.mounts.sort_unstable_by(|left, right| {
            right
                .path
                .len()
                .cmp(&left.path.len())
                .then_with(|| left.path.cmp(&right.path))
        });
        if changes_commands {
            self.bump_command_revision();
        }
        Ok(())
    }

    /// Return metadata for one resolved namespace node.
    ///
    /// # Errors
    ///
    /// Fails if the path is invalid, missing, or its mounted provider fails.
    pub fn metadata(&mut self, cwd: &str, path: &str) -> Result<FileMetadata, FsError> {
        let path = canonicalize(cwd, path)?;
        if let Some((index, relative)) = self.mount_for_path(&path) {
            return self.mounts[index].provider.metadata(&relative);
        }
        match self.nodes.get(&path) {
            Some(Node::Directory) => Ok(FileMetadata {
                kind: NodeKind::Directory,
                byte_count: 0,
            }),
            Some(Node::File { bytes, .. }) => Ok(FileMetadata {
                kind: NodeKind::File,
                byte_count: u64::try_from(bytes.len()).map_err(|_| FsError::Overflow)?,
            }),
            None => Err(FsError::NotFound),
        }
    }

    /// Return metadata without following the final symbolic-link component.
    ///
    /// # Errors
    ///
    /// Fails if the path is invalid, missing, or its mounted provider fails.
    pub fn metadata_no_follow(&mut self, cwd: &str, path: &str) -> Result<FileMetadata, FsError> {
        let path = canonicalize(cwd, path)?;
        self.metadata_no_follow_absolute(&path)
    }

    /// Read a bounded file range without retaining the complete file.
    ///
    /// # Errors
    ///
    /// Fails if the path is invalid, missing, not a file, or the backing
    /// provider violates its read contract.
    pub fn read_file_at(
        &mut self,
        cwd: &str,
        path: &str,
        offset: u64,
        destination: &mut [u8],
    ) -> Result<usize, FsError> {
        let path = canonicalize(cwd, path)?;
        if let Some((index, relative)) = self.mount_for_path(&path) {
            let count = self.mounts[index]
                .provider
                .read_file(&relative, offset, destination)?;
            if count > destination.len() {
                return Err(FsError::Corrupt);
            }
            return Ok(count);
        }
        match self.nodes.get(&path) {
            Some(Node::File { bytes, .. }) => {
                let start = usize::try_from(offset).map_err(|_| FsError::Overflow)?;
                if start >= bytes.len() || destination.is_empty() {
                    return Ok(0);
                }
                let count = destination.len().min(bytes.len() - start);
                destination[..count].copy_from_slice(&bytes[start..start + count]);
                Ok(count)
            }
            Some(Node::Directory) => Err(FsError::WrongType),
            None => Err(FsError::NotFound),
        }
    }

    /// Resolve and read a complete file under a caller-selected hard limit.
    ///
    /// # Errors
    ///
    /// Fails if the path is invalid, missing, not a file, exceeds `max_bytes`,
    /// cannot be allocated, or its provider fails or makes no progress.
    pub fn read_file_bounded(
        &mut self,
        cwd: &str,
        path: &str,
        max_bytes: usize,
    ) -> Result<Vec<u8>, FsError> {
        let metadata = self.metadata(cwd, path)?;
        if metadata.kind != NodeKind::File {
            return Err(FsError::WrongType);
        }
        let byte_count = usize::try_from(metadata.byte_count).map_err(|_| FsError::NoSpace)?;
        if byte_count > max_bytes {
            return Err(FsError::NoSpace);
        }
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(byte_count)
            .map_err(|_| FsError::NoSpace)?;
        bytes.resize(byte_count, 0);
        let mut offset = 0_usize;
        while offset < bytes.len() {
            let end = offset
                .checked_add(PROVIDER_READ_CHUNK)
                .map_or(bytes.len(), |candidate| candidate.min(bytes.len()));
            let count = self.read_file_at(
                cwd,
                path,
                u64::try_from(offset).map_err(|_| FsError::Overflow)?,
                &mut bytes[offset..end],
            )?;
            if count == 0 || count > end - offset {
                return Err(FsError::Corrupt);
            }
            offset = offset.checked_add(count).ok_or(FsError::Overflow)?;
        }
        Ok(bytes)
    }

    /// Resolve and read one complete file for compatibility callers.
    ///
    /// Stream-oriented callers should use [`Self::read_file_at`] so memory use
    /// does not scale with file size.
    ///
    /// # Errors
    ///
    /// Fails if the path is invalid, missing, or not a file.
    pub fn read_file(&mut self, cwd: &str, path: &str) -> Result<Vec<u8>, FsError> {
        self.read_file_bounded(cwd, path, usize::MAX)
    }

    /// Truncate an existing writable file or create an empty one.
    ///
    /// # Errors
    ///
    /// Fails for invalid paths, immutable targets, missing parents, or quota exhaustion.
    pub fn truncate_file(&mut self, cwd: &str, path: &str) -> Result<(), FsError> {
        let path = canonicalize(cwd, path)?;
        let changes_commands = is_command_path(&path);
        if let Some((index, relative)) = self.mount_for_path(&path) {
            if !self.mounts[index].writable {
                return Err(FsError::ReadOnly);
            }
            self.mounts[index].provider.truncate_file(&relative)?;
            if changes_commands {
                self.bump_command_revision();
            }
            return Ok(());
        }
        if !is_under_tmp(&path) {
            return Err(FsError::ReadOnly);
        }
        let parent = parent_path(&path).ok_or(FsError::Invalid)?;
        if !matches!(self.nodes.get(parent), Some(Node::Directory)) {
            return Err(FsError::NotFound);
        }

        let old_len = match self.nodes.get(&path) {
            Some(Node::File {
                bytes,
                writable: true,
            }) => bytes.len(),
            Some(Node::File { .. }) => return Err(FsError::ReadOnly),
            Some(Node::Directory) => return Err(FsError::WrongType),
            None => 0,
        };
        let is_new = !self.nodes.contains_key(&path);
        if is_new && self.ramfs_nodes >= self.quota.max_nodes {
            return Err(FsError::NoSpace);
        }
        let without_old = self
            .ramfs_bytes
            .checked_sub(old_len)
            .ok_or(FsError::Overflow)?;
        self.nodes.insert(
            path,
            Node::File {
                bytes: Vec::new(),
                writable: true,
            },
        );
        self.ramfs_bytes = without_old;
        if is_new {
            self.ramfs_nodes += 1;
        }
        if changes_commands {
            self.bump_command_revision();
        }
        Ok(())
    }

    /// Append one chunk without retaining a second complete-file copy.
    ///
    /// RAMFS payload memory is the file's backing storage itself. Mounted
    /// providers receive the chunk directly.
    ///
    /// # Errors
    ///
    /// Fails for invalid or immutable paths, wrong node types, quota/media
    /// exhaustion, or provider I/O errors.
    pub fn append_file(&mut self, cwd: &str, path: &str, bytes: &[u8]) -> Result<(), FsError> {
        if bytes.is_empty() {
            return Ok(());
        }
        let path = canonicalize(cwd, path)?;
        let changes_commands = is_command_path(&path);
        if let Some((index, relative)) = self.mount_for_path(&path) {
            if !self.mounts[index].writable {
                return Err(FsError::ReadOnly);
            }
            self.mounts[index].provider.append_file(&relative, bytes)?;
            if changes_commands {
                self.bump_command_revision();
            }
            return Ok(());
        }
        if !is_under_tmp(&path) {
            return Err(FsError::ReadOnly);
        }
        let current_len = match self.nodes.get(&path) {
            Some(Node::File {
                bytes,
                writable: true,
            }) => bytes.len(),
            Some(Node::File { .. }) => return Err(FsError::ReadOnly),
            Some(Node::Directory) => return Err(FsError::WrongType),
            None => return Err(FsError::NotFound),
        };
        let next_len = current_len
            .checked_add(bytes.len())
            .ok_or(FsError::Overflow)?;
        if next_len > self.quota.max_file_bytes {
            return Err(FsError::NoSpace);
        }
        let next_total = self
            .ramfs_bytes
            .checked_add(bytes.len())
            .ok_or(FsError::Overflow)?;
        if next_total > self.quota.max_bytes {
            return Err(FsError::NoSpace);
        }
        let Some(Node::File {
            bytes: destination,
            writable: true,
        }) = self.nodes.get_mut(&path)
        else {
            return Err(FsError::Corrupt);
        };
        destination
            .try_reserve_exact(bytes.len())
            .map_err(|_| FsError::NoSpace)?;
        destination.extend_from_slice(bytes);
        self.ramfs_bytes = next_total;
        self.ramfs_high_water = self.ramfs_high_water.max(next_total);
        if changes_commands {
            self.bump_command_revision();
        }
        Ok(())
    }

    /// Complete a streamed write and request provider durability.
    ///
    /// RAMFS needs no additional operation.
    ///
    /// # Errors
    ///
    /// Reports invalid paths, immutable mounts, or durability failures.
    pub fn sync_file(&mut self, cwd: &str, path: &str) -> Result<(), FsError> {
        let path = canonicalize(cwd, path)?;
        if let Some((index, relative)) = self.mount_for_path(&path) {
            if !self.mounts[index].writable {
                return Err(FsError::ReadOnly);
            }
            return self.mounts[index].provider.sync_file(&relative);
        }
        match self.nodes.get(&path) {
            Some(Node::File { writable: true, .. }) => Ok(()),
            Some(Node::File { .. }) => Err(FsError::ReadOnly),
            Some(Node::Directory) => Err(FsError::WrongType),
            None => Err(FsError::NotFound),
        }
    }

    /// Replace one complete file through the streaming provider interface.
    ///
    /// This compatibility helper never creates a second aggregate buffer; it
    /// writes the caller-owned slice in [`FILE_IO_BUFFER_BYTES`] chunks.
    ///
    /// # Errors
    ///
    /// Reports the first truncate, append, or durability failure.
    pub fn write_file(&mut self, cwd: &str, path: &str, bytes: &[u8]) -> Result<(), FsError> {
        self.truncate_file(cwd, path)?;
        for chunk in bytes.chunks(FILE_IO_BUFFER_BYTES) {
            self.append_file(cwd, path, chunk)?;
        }
        self.sync_file(cwd, path)
    }

    /// Delete a writable file and release its complete quota charge.
    ///
    /// # Errors
    ///
    /// Fails if the path is invalid, missing, immutable, or not a file.
    pub fn remove_file(&mut self, cwd: &str, path: &str) -> Result<(), FsError> {
        let path = canonicalize(cwd, path)?;
        let changes_commands = is_command_path(&path);
        if let Some((index, relative)) = self.mount_for_path(&path) {
            if !self.mounts[index].writable {
                return Err(FsError::ReadOnly);
            }
            self.mounts[index].provider.remove_file(&relative)?;
            if changes_commands {
                self.bump_command_revision();
            }
            return Ok(());
        }
        match self.nodes.get(&path) {
            Some(Node::File {
                bytes,
                writable: true,
            }) => {
                self.ramfs_bytes = self
                    .ramfs_bytes
                    .checked_sub(bytes.len())
                    .ok_or(FsError::Overflow)?;
                self.ramfs_nodes = self.ramfs_nodes.checked_sub(1).ok_or(FsError::Overflow)?;
            }
            Some(Node::File { .. }) => return Err(FsError::ReadOnly),
            Some(Node::Directory) => return Err(FsError::WrongType),
            None => return Err(FsError::NotFound),
        }
        self.nodes.remove(&path);
        if changes_commands {
            self.bump_command_revision();
        }
        Ok(())
    }

    /// Create one empty writable directory.
    ///
    /// # Errors
    ///
    /// Fails for invalid paths, immutable mounts, missing parents, collisions,
    /// unsupported providers, or RAMFS quota exhaustion.
    pub fn create_directory(&mut self, cwd: &str, path: &str) -> Result<(), FsError> {
        let path = canonicalize(cwd, path)?;
        let changes_commands = is_command_path(&path);
        if let Some((index, relative)) = self.mount_for_path(&path) {
            if !self.mounts[index].writable {
                return Err(FsError::ReadOnly);
            }
            self.mounts[index].provider.create_directory(&relative)?;
            if changes_commands {
                self.bump_command_revision();
            }
            return Ok(());
        }
        if !is_under_tmp(&path) {
            return Err(FsError::ReadOnly);
        }
        if self.nodes.contains_key(&path) {
            return Err(FsError::Exists);
        }
        if self.ramfs_nodes >= self.quota.max_nodes {
            return Err(FsError::NoSpace);
        }
        let parent = parent_path(&path).ok_or(FsError::Invalid)?;
        if !matches!(self.nodes.get(parent), Some(Node::Directory)) {
            return Err(FsError::NotFound);
        }
        self.nodes.insert(path, Node::Directory);
        self.ramfs_nodes = self.ramfs_nodes.checked_add(1).ok_or(FsError::Overflow)?;
        if changes_commands {
            self.bump_command_revision();
        }
        Ok(())
    }

    /// Remove one empty writable directory without crossing a mount boundary.
    ///
    /// # Errors
    ///
    /// Rejects roots, mountpoints, non-directories, nonempty directories,
    /// immutable content, and provider failures.
    pub fn remove_directory(&mut self, cwd: &str, path: &str) -> Result<(), FsError> {
        let path = canonicalize(cwd, path)?;
        if path == "/" || self.mounts.iter().any(|mount| mount.path == path) {
            return Err(FsError::ReadOnly);
        }
        let changes_commands = is_command_path(&path);
        if let Some((index, relative)) = self.mount_for_path(&path) {
            if relative == "/" || !self.mounts[index].writable {
                return Err(FsError::ReadOnly);
            }
            self.mounts[index].provider.remove_directory(&relative)?;
            if changes_commands {
                self.bump_command_revision();
            }
            return Ok(());
        }
        if !is_under_tmp(&path) || path == "/tmp" {
            return Err(FsError::ReadOnly);
        }
        match self.nodes.get(&path) {
            Some(Node::Directory) => {}
            Some(Node::File { .. }) => return Err(FsError::WrongType),
            None => return Err(FsError::NotFound),
        }
        let mut prefix = path.clone();
        prefix.push('/');
        if self
            .nodes
            .range(prefix.clone()..)
            .next()
            .is_some_and(|(candidate, _)| candidate.starts_with(&prefix))
        {
            return Err(FsError::NotEmpty);
        }
        self.nodes.remove(&path);
        self.ramfs_nodes = self.ramfs_nodes.checked_sub(1).ok_or(FsError::Overflow)?;
        if changes_commands {
            self.bump_command_revision();
        }
        Ok(())
    }

    /// Atomically rename one object within one writable provider.
    ///
    /// The destination must not already exist. Root and mountpoint names are
    /// immutable, and provider crossings report [`FsError::CrossDevice`].
    ///
    /// # Errors
    ///
    /// Reports invalid paths, collisions, immutable objects, provider crossings,
    /// allocation failure, or provider-specific persistence failures.
    pub fn rename(&mut self, cwd: &str, source: &str, destination: &str) -> Result<(), FsError> {
        let source = canonicalize(cwd, source)?;
        let destination = canonicalize(cwd, destination)?;
        if source == destination {
            return self.metadata_no_follow_absolute(&source).map(|_| ());
        }
        if source == "/"
            || destination == "/"
            || self
                .mounts
                .iter()
                .any(|mount| mount.path == source || mount.path == destination)
        {
            return Err(FsError::ReadOnly);
        }
        match (
            self.mount_for_path(&source),
            self.mount_for_path(&destination),
        ) {
            (
                Some((source_index, source_relative)),
                Some((destination_index, destination_relative)),
            ) => {
                if source_index != destination_index {
                    return Err(FsError::CrossDevice);
                }
                if !self.mounts[source_index].writable {
                    return Err(FsError::ReadOnly);
                }
                self.mounts[source_index]
                    .provider
                    .rename(&source_relative, &destination_relative)?;
            }
            (None, None) => self.rename_ramfs(&source, &destination)?,
            _ => return Err(FsError::CrossDevice),
        }
        if is_command_path(&source) || is_command_path(&destination) {
            self.bump_command_revision();
        }
        Ok(())
    }

    fn rename_ramfs(&mut self, source: &str, destination: &str) -> Result<(), FsError> {
        if !is_under_tmp(source) || !is_under_tmp(destination) || source == "/tmp" {
            return Err(FsError::ReadOnly);
        }
        let source_is_directory = match self.nodes.get(source) {
            Some(Node::Directory) => true,
            Some(Node::File { writable: true, .. }) => false,
            Some(Node::File { .. }) => return Err(FsError::ReadOnly),
            None => return Err(FsError::NotFound),
        };
        if self.nodes.contains_key(destination) {
            return Err(FsError::Exists);
        }
        let parent = parent_path(destination).ok_or(FsError::Invalid)?;
        if !matches!(self.nodes.get(parent), Some(Node::Directory)) {
            return Err(FsError::NotFound);
        }
        let mut prefix = source.to_string();
        prefix.push('/');
        if source_is_directory && destination.starts_with(&prefix) {
            return Err(FsError::Invalid);
        }
        if self.mounts.iter().any(|mount| {
            mount.path.starts_with(&prefix)
                || mount
                    .path
                    .strip_prefix(destination)
                    .is_some_and(|suffix| suffix.starts_with('/'))
        }) {
            return Err(FsError::ReadOnly);
        }

        let mut moves = Vec::new();
        for candidate in self.nodes.keys() {
            if candidate == source || candidate.starts_with(&prefix) {
                let suffix = &candidate[source.len()..];
                let capacity = destination
                    .len()
                    .checked_add(suffix.len())
                    .ok_or(FsError::Overflow)?;
                if capacity > MAX_PATH_BYTES {
                    return Err(FsError::NoSpace);
                }
                let mut renamed = String::new();
                renamed
                    .try_reserve_exact(capacity)
                    .map_err(|_| FsError::NoSpace)?;
                renamed.push_str(destination);
                renamed.push_str(suffix);
                moves.try_reserve(1).map_err(|_| FsError::NoSpace)?;
                moves.push((candidate.clone(), renamed));
            }
        }
        if moves.is_empty() {
            return Err(FsError::NotFound);
        }
        if moves.iter().any(|(_, renamed)| {
            self.nodes.contains_key(renamed)
                && !moves.iter().any(|(original, _)| original == renamed)
        }) {
            return Err(FsError::Exists);
        }
        let mut removed = Vec::new();
        removed
            .try_reserve_exact(moves.len())
            .map_err(|_| FsError::NoSpace)?;
        for (original, _) in &moves {
            removed.push(self.nodes.remove(original).ok_or(FsError::Corrupt)?);
        }
        for ((_, renamed), node) in moves.into_iter().zip(removed) {
            self.nodes.insert(renamed, node);
        }
        Ok(())
    }

    /// Return a mounted provider's symbolic-link target without following it.
    ///
    /// # Errors
    ///
    /// Fails for invalid, non-provider, missing, or non-symbolic-link paths.
    pub fn read_link(&mut self, cwd: &str, path: &str) -> Result<String, FsError> {
        let path = canonicalize(cwd, path)?;
        let (index, relative) = self.mount_for_path(&path).ok_or(FsError::Unsupported)?;
        self.mounts[index].provider.read_link(&relative)
    }

    /// Create a symbolic link on one writable mounted provider.
    ///
    /// # Errors
    ///
    /// Fails for invalid paths, immutable mounts, unsupported providers, or
    /// provider persistence failures.
    pub fn create_symlink(
        &mut self,
        cwd: &str,
        target: &str,
        link_path: &str,
    ) -> Result<(), FsError> {
        let link_path = canonicalize(cwd, link_path)?;
        let changes_commands = is_command_path(&link_path);
        let (index, relative) = self
            .mount_for_path(&link_path)
            .ok_or(FsError::Unsupported)?;
        if !self.mounts[index].writable {
            return Err(FsError::ReadOnly);
        }
        self.mounts[index]
            .provider
            .create_symlink(target, &relative)?;
        if changes_commands {
            self.bump_command_revision();
        }
        Ok(())
    }

    /// Add a hard-link name within one writable mounted provider.
    ///
    /// # Errors
    ///
    /// Fails for cross-provider links, invalid paths, immutable mounts,
    /// unsupported providers, or provider persistence failures.
    pub fn create_hard_link(
        &mut self,
        cwd: &str,
        existing: &str,
        new_path: &str,
    ) -> Result<(), FsError> {
        let existing = canonicalize(cwd, existing)?;
        let new_path = canonicalize(cwd, new_path)?;
        let changes_commands = is_command_path(&new_path);
        let (existing_index, existing_relative) =
            self.mount_for_path(&existing).ok_or(FsError::Unsupported)?;
        let (new_index, new_relative) =
            self.mount_for_path(&new_path).ok_or(FsError::Unsupported)?;
        if existing_index != new_index {
            return Err(FsError::CrossDevice);
        }
        if !self.mounts[existing_index].writable {
            return Err(FsError::ReadOnly);
        }
        self.mounts[existing_index]
            .provider
            .create_hard_link(&existing_relative, &new_relative)?;
        if changes_commands {
            self.bump_command_revision();
        }
        Ok(())
    }

    /// List immediate children in lexical order.
    ///
    /// # Errors
    ///
    /// Fails if the path is invalid, missing, or not a directory.
    pub fn list(&mut self, cwd: &str, path: &str) -> Result<Vec<DirEntry>, FsError> {
        let path = canonicalize(cwd, path)?;
        if let Some((index, relative)) = self.mount_for_path(&path) {
            let listing = self.mounts[index].provider.list(
                &relative,
                0,
                MAX_PROVIDER_DIRECTORY_ENTRIES,
                MAX_PROVIDER_DIRECTORY_BYTES,
            )?;
            if listing.next_cursor.is_some() {
                return Err(FsError::NoSpace);
            }
            return Ok(listing.entries);
        }
        match self.nodes.get(&path) {
            Some(Node::Directory) => {}
            Some(Node::File { .. }) => return Err(FsError::WrongType),
            None => return Err(FsError::NotFound),
        }
        let prefix = if path == "/" {
            "/".to_string()
        } else {
            let mut prefix = path;
            prefix.push('/');
            prefix
        };
        let mut entries = Vec::new();
        for (candidate, node) in self.nodes.range(prefix.clone()..) {
            if !candidate.starts_with(&prefix) {
                break;
            }
            let suffix = &candidate[prefix.len()..];
            if !suffix.is_empty() && !suffix.contains('/') {
                entries.push(DirEntry {
                    name: suffix.to_string(),
                    kind: node.kind(),
                });
            }
        }
        Ok(entries)
    }

    /// List one bounded lexical page of immediate children.
    ///
    /// The opaque cursor is zero for the first page and otherwise must be a
    /// value returned by this method for the same directory and namespace
    /// state. Entry-name bytes, rather than allocator metadata, are charged to
    /// `max_name_bytes`.
    ///
    /// # Errors
    ///
    /// Fails for invalid paths/cursors, missing or non-directory nodes,
    /// provider contract violations, arithmetic overflow, or allocation
    /// failure within the supplied budgets.
    pub fn list_bounded(
        &mut self,
        cwd: &str,
        path: &str,
        cursor: u64,
        max_entries: usize,
        max_name_bytes: usize,
    ) -> Result<ProviderListing, FsError> {
        let path = canonicalize(cwd, path)?;
        if let Some((index, relative)) = self.mount_for_path(&path) {
            let listing = self.mounts[index].provider.list(
                &relative,
                cursor,
                max_entries.min(MAX_PROVIDER_DIRECTORY_ENTRIES),
                max_name_bytes.min(MAX_PROVIDER_DIRECTORY_BYTES),
            )?;
            validate_listing(&listing, max_entries, max_name_bytes)?;
            return Ok(listing);
        }
        match self.nodes.get(&path) {
            Some(Node::Directory) => {}
            Some(Node::File { .. }) => return Err(FsError::WrongType),
            None => return Err(FsError::NotFound),
        }
        let start = usize::try_from(cursor).map_err(|_| FsError::Invalid)?;
        let prefix = if path == "/" {
            "/".to_string()
        } else {
            let mut prefix = path;
            prefix.push('/');
            prefix
        };
        let mut entries = Vec::new();
        entries
            .try_reserve_exact(max_entries.min(MAX_PROVIDER_DIRECTORY_ENTRIES))
            .map_err(|_| FsError::NoSpace)?;
        let mut child_index = 0_usize;
        let mut retained_bytes = 0_usize;
        for (candidate, node) in self.nodes.range(prefix.clone()..) {
            if !candidate.starts_with(&prefix) {
                break;
            }
            let name = &candidate[prefix.len()..];
            if name.is_empty() || name.contains('/') {
                continue;
            }
            if child_index < start {
                child_index = child_index.checked_add(1).ok_or(FsError::Overflow)?;
                continue;
            }
            let next_bytes = retained_bytes
                .checked_add(name.len())
                .ok_or(FsError::Overflow)?;
            if entries.len() >= max_entries || next_bytes > max_name_bytes {
                return Ok(ProviderListing {
                    entries,
                    next_cursor: Some(u64::try_from(child_index).map_err(|_| FsError::Overflow)?),
                });
            }
            entries.push(DirEntry {
                name: name.to_string(),
                kind: node.kind(),
            });
            retained_bytes = next_bytes;
            child_index = child_index.checked_add(1).ok_or(FsError::Overflow)?;
        }
        if child_index < start {
            return Err(FsError::Invalid);
        }
        Ok(ProviderListing {
            entries,
            next_cursor: None,
        })
    }

    /// List matching immediate children without exceeding caller-supplied budgets.
    ///
    /// Entry names, rather than allocator metadata, are charged to `max_bytes`.
    /// A zero entry or byte budget returns no entries and reports truncation when
    /// the directory contains a match.
    ///
    /// # Errors
    ///
    /// Fails if the path is invalid, missing, or not a directory.
    pub fn list_matching_bounded(
        &mut self,
        cwd: &str,
        path: &str,
        name_prefix: &str,
        directories_only: bool,
        max_entries: usize,
        max_bytes: usize,
    ) -> Result<DirectoryListing, FsError> {
        let path = canonicalize(cwd, path)?;
        if let Some((index, relative)) = self.mount_for_path(&path) {
            let mut cursor = 0_u64;
            let mut entries = Vec::new();
            let mut retained_bytes = 0_usize;
            let mut truncated = false;
            let mut scanned = 0_usize;
            loop {
                let page = self.mounts[index].provider.list(
                    &relative,
                    cursor,
                    32,
                    MAX_PROVIDER_DIRECTORY_BYTES,
                )?;
                let page_len = page.entries.len();
                for entry in page.entries {
                    scanned = scanned.checked_add(1).ok_or(FsError::Overflow)?;
                    if scanned > MAX_PROVIDER_DIRECTORY_ENTRIES {
                        return Err(FsError::NoSpace);
                    }
                    if !entry.name.starts_with(name_prefix)
                        || (directories_only && entry.kind != NodeKind::Directory)
                    {
                        continue;
                    }
                    let next_bytes = retained_bytes
                        .checked_add(entry.name.len())
                        .ok_or(FsError::Overflow)?;
                    if entries.len() >= max_entries || next_bytes > max_bytes {
                        truncated = true;
                        return Ok(DirectoryListing { entries, truncated });
                    }
                    retained_bytes = next_bytes;
                    entries.push(entry);
                }
                match page.next_cursor {
                    Some(next) if next != cursor && page_len != 0 => cursor = next,
                    Some(_) => return Err(FsError::Corrupt),
                    None => return Ok(DirectoryListing { entries, truncated }),
                }
            }
        }
        match self.nodes.get(&path) {
            Some(Node::Directory) => {}
            Some(Node::File { .. }) => return Err(FsError::WrongType),
            None => return Err(FsError::NotFound),
        }
        let prefix = if path == "/" {
            "/".to_string()
        } else {
            let mut prefix = path;
            prefix.push('/');
            prefix
        };
        let mut entries = Vec::new();
        let mut retained_bytes = 0_usize;
        let mut truncated = false;
        for (candidate, node) in self.nodes.range(prefix.clone()..) {
            if !candidate.starts_with(&prefix) {
                break;
            }
            let suffix = &candidate[prefix.len()..];
            if suffix.is_empty()
                || suffix.contains('/')
                || !suffix.starts_with(name_prefix)
                || (directories_only && node.kind() != NodeKind::Directory)
            {
                continue;
            }
            let Some(next_bytes) = retained_bytes.checked_add(suffix.len()) else {
                truncated = true;
                break;
            };
            if entries.len() >= max_entries || next_bytes > max_bytes {
                truncated = true;
                break;
            }
            entries.push(DirEntry {
                name: suffix.to_string(),
                kind: node.kind(),
            });
            retained_bytes = next_bytes;
        }
        Ok(DirectoryListing { entries, truncated })
    }

    /// Resolve a path and require it to be a directory.
    ///
    /// # Errors
    ///
    /// Fails if the path is invalid, missing, or not a directory.
    pub fn resolve_dir(&mut self, cwd: &str, path: &str) -> Result<String, FsError> {
        let path = canonicalize(cwd, path)?;
        if let Some((index, relative)) = self.mount_for_path(&path) {
            return match self.mounts[index].provider.metadata(&relative)?.kind {
                NodeKind::Directory => Ok(path),
                NodeKind::File | NodeKind::Symlink => Err(FsError::WrongType),
            };
        }
        match self.nodes.get(&path) {
            Some(Node::Directory) => Ok(path),
            Some(Node::File { .. }) => Err(FsError::WrongType),
            None => Err(FsError::NotFound),
        }
    }

    /// Current RAMFS accounting for system reporting.
    #[must_use]
    pub fn memory_stats(&self) -> MemoryStats {
        MemoryStats {
            ramfs_used: self.ramfs_bytes as u64,
            ramfs_limit: self.quota.max_bytes as u64,
            ramfs_high_water: self.ramfs_high_water as u64,
            ..MemoryStats::default()
        }
    }

    /// Revision of namespace changes that can alter `/bin` command discovery.
    ///
    /// Consumers may cache a validated command catalog until this value
    /// changes. Unrelated file and generated-system-node mutations leave it
    /// unchanged.
    #[must_use]
    pub const fn command_revision(&self) -> u64 {
        self.command_revision
    }

    fn bump_command_revision(&mut self) {
        self.command_revision = self.command_revision.wrapping_add(1);
    }

    fn mount_for_path(&self, path: &str) -> Option<(usize, String)> {
        self.mounts.iter().enumerate().find_map(|(index, mount)| {
            if path == mount.path {
                Some((index, "/".to_string()))
            } else {
                path.strip_prefix(&mount.path)
                    .filter(|suffix| suffix.starts_with('/'))
                    .map(|suffix| (index, suffix.to_string()))
            }
        })
    }
}

fn is_command_path(path: &str) -> bool {
    path == "/bin" || path.starts_with("/bin/")
}

fn validate_listing(
    listing: &ProviderListing,
    max_entries: usize,
    max_name_bytes: usize,
) -> Result<(), FsError> {
    if listing.entries.len() > max_entries {
        return Err(FsError::Corrupt);
    }
    let mut retained_bytes = 0_usize;
    let mut previous: Option<&str> = None;
    for entry in &listing.entries {
        if entry.name.is_empty()
            || entry.name.len() > MAX_NAME_BYTES
            || entry.name.contains('/')
            || matches!(entry.name.as_str(), "." | "..")
            || previous.is_some_and(|name| name >= entry.name.as_str())
        {
            return Err(FsError::Corrupt);
        }
        retained_bytes = retained_bytes
            .checked_add(entry.name.len())
            .ok_or(FsError::Overflow)?;
        if retained_bytes > max_name_bytes {
            return Err(FsError::Corrupt);
        }
        previous = Some(entry.name.as_str());
    }
    Ok(())
}

fn insert_node(
    nodes: &mut BTreeMap<String, Node>,
    path: String,
    node: Node,
) -> Result<(), FsError> {
    if path == "/" || nodes.contains_key(&path) {
        return Err(FsError::Exists);
    }
    let parent = parent_path(&path).ok_or(FsError::Invalid)?;
    if !matches!(nodes.get(parent), Some(Node::Directory)) {
        return Err(FsError::NotFound);
    }
    nodes.insert(path, node);
    Ok(())
}

/// Normalize an absolute or cwd-relative path without permitting root escape.
///
/// # Errors
///
/// Fails for empty/NUL paths, invalid cwd values, length/depth overflow, or
/// checked-arithmetic overflow.
pub fn canonicalize(cwd: &str, path: &str) -> Result<String, FsError> {
    if path.is_empty() || path.as_bytes().contains(&0) {
        return Err(FsError::Invalid);
    }
    let mut components: Vec<&str> = Vec::new();
    if !path.starts_with('/') {
        if !cwd.starts_with('/') {
            return Err(FsError::Invalid);
        }
        apply_components(&mut components, cwd)?;
    }
    apply_components(&mut components, path)?;

    let length = 1_usize
        .checked_add(components.iter().map(|part| part.len()).sum::<usize>())
        .and_then(|value| value.checked_add(components.len().saturating_sub(1)))
        .ok_or(FsError::Overflow)?;
    if length > MAX_PATH_BYTES {
        return Err(FsError::NoSpace);
    }
    if components.is_empty() {
        return Ok("/".to_string());
    }
    let mut normalized = String::with_capacity(length);
    for component in components {
        normalized.push('/');
        normalized.push_str(component);
    }
    Ok(normalized)
}

/// Normalize one relative path without permitting escape above `root`.
///
/// Unlike [`canonicalize`], an absolute input or a `..` component at the root
/// boundary is rejected rather than interpreted relative to the global
/// namespace.
///
/// # Errors
///
/// Fails for an invalid root, empty/absolute/NUL input, parent escape, or the
/// ordinary path length, depth, and arithmetic bounds.
pub fn canonicalize_beneath(root: &str, path: &str) -> Result<String, FsError> {
    if path.is_empty() || path.starts_with('/') || path.as_bytes().contains(&0) {
        return Err(FsError::Invalid);
    }
    let normalized_root = canonicalize("/", root)?;
    if normalized_root != root || root == "/" {
        return Err(FsError::Invalid);
    }
    let mut components: Vec<&str> = Vec::new();
    apply_components(&mut components, root)?;
    let floor = components.len();
    for component in path.split('/') {
        match component {
            "" | "." => {}
            ".." => {
                if components.len() == floor {
                    return Err(FsError::Invalid);
                }
                components.pop();
            }
            value => {
                if value.len() > MAX_NAME_BYTES || components.len() >= MAX_PATH_DEPTH {
                    return Err(FsError::NoSpace);
                }
                components.push(value);
            }
        }
    }
    let length = 1_usize
        .checked_add(components.iter().map(|part| part.len()).sum::<usize>())
        .and_then(|value| value.checked_add(components.len().saturating_sub(1)))
        .ok_or(FsError::Overflow)?;
    if length > MAX_PATH_BYTES {
        return Err(FsError::NoSpace);
    }
    let mut normalized = String::with_capacity(length);
    for component in components {
        normalized.push('/');
        normalized.push_str(component);
    }
    Ok(normalized)
}

fn apply_components<'a>(components: &mut Vec<&'a str>, path: &'a str) -> Result<(), FsError> {
    for component in path.split('/') {
        match component {
            "" | "." => {}
            ".." => {
                components.pop();
            }
            value => {
                if value.len() > MAX_NAME_BYTES || components.len() >= MAX_PATH_DEPTH {
                    return Err(FsError::NoSpace);
                }
                components.push(value);
            }
        }
    }
    Ok(())
}

fn parent_path(path: &str) -> Option<&str> {
    let index = path.rfind('/')?;
    Some(if index == 0 { "/" } else { &path[..index] })
}

fn is_under_tmp(path: &str) -> bool {
    path.starts_with("/tmp/") && path.len() > "/tmp/".len()
}

fn is_active_configuration_path(path: &str) -> bool {
    path == "/sys/config" || path.starts_with("/sys/config/")
}

fn is_reserved_configuration_content(path: &str) -> bool {
    path.starts_with("/config/") || is_active_configuration_path(path)
}

#[derive(Debug)]
struct EmbeddedEntry {
    path: String,
    kind: NodeKind,
    data: Vec<u8>,
}

fn parse_embedded(image: &[u8]) -> Result<Vec<EmbeddedEntry>, FsError> {
    if image.len() < KEFS_HEADER_LEN
        || image[..8] != KEFS_V1_MAGIC
        || image.get(10..12) != Some(&[0, 0])
    {
        return Err(FsError::Invalid);
    }
    let count = usize::from(read_u16(image, 8)?);
    let declared_len = usize::try_from(read_u32(image, 12)?).map_err(|_| FsError::Overflow)?;
    if declared_len != image.len() {
        return Err(FsError::Invalid);
    }
    let mut offset = KEFS_HEADER_LEN;
    let mut previous: Option<String> = None;
    let mut entries = Vec::with_capacity(count);
    for _ in 0..count {
        let kind = match *image.get(offset).ok_or(FsError::Invalid)? {
            1 => NodeKind::File,
            2 => NodeKind::Directory,
            _ => return Err(FsError::Invalid),
        };
        offset = offset.checked_add(1).ok_or(FsError::Overflow)?;
        let path_len = usize::from(read_u16(image, offset)?);
        offset = offset.checked_add(2).ok_or(FsError::Overflow)?;
        let data_len = usize::try_from(read_u32(image, offset)?).map_err(|_| FsError::Overflow)?;
        offset = offset.checked_add(4).ok_or(FsError::Overflow)?;
        let path_end = offset.checked_add(path_len).ok_or(FsError::Overflow)?;
        let path_bytes = image.get(offset..path_end).ok_or(FsError::Invalid)?;
        let raw_path = str::from_utf8(path_bytes).map_err(|_| FsError::Invalid)?;
        let path = canonicalize("/", raw_path)?;
        if path != raw_path || path == "/" {
            return Err(FsError::Invalid);
        }
        if previous.as_ref().is_some_and(|value| value >= &path) {
            return Err(FsError::Invalid);
        }
        previous = Some(path.clone());
        offset = path_end;
        let data_end = offset.checked_add(data_len).ok_or(FsError::Overflow)?;
        let data = image.get(offset..data_end).ok_or(FsError::Invalid)?;
        if kind == NodeKind::Directory && !data.is_empty() {
            return Err(FsError::Invalid);
        }
        entries.push(EmbeddedEntry {
            path,
            kind,
            data: data.to_vec(),
        });
        offset = data_end;
    }
    if offset != image.len() {
        return Err(FsError::Invalid);
    }
    Ok(entries)
}

fn read_u16(image: &[u8], offset: usize) -> Result<u16, FsError> {
    let end = offset.checked_add(2).ok_or(FsError::Overflow)?;
    let bytes: [u8; 2] = image
        .get(offset..end)
        .ok_or(FsError::Invalid)?
        .try_into()
        .map_err(|_| FsError::Invalid)?;
    Ok(u16::from_le_bytes(bytes))
}

fn read_u32(image: &[u8], offset: usize) -> Result<u32, FsError> {
    let end = offset.checked_add(4).ok_or(FsError::Overflow)?;
    let bytes: [u8; 4] = image
        .get(offset..end)
        .ok_or(FsError::Invalid)?
        .try_into()
        .map_err(|_| FsError::Invalid)?;
    Ok(u32::from_le_bytes(bytes))
}

#[cfg(test)]
mod tests {
    use super::{
        DirEntry, DirectoryRights, FileMetadata, FsError, KEFS_V1_MAGIC, Namespace, NodeKind,
        ProviderListing, RamFsQuota, ReadOnlyFileSystem, canonicalize, canonicalize_beneath,
    };
    use alloc::{boxed::Box, rc::Rc, string::String, vec, vec::Vec};
    use core::cell::RefCell;

    #[derive(Debug)]
    struct TestProvider;

    #[derive(Debug)]
    struct ScopedProvider;

    #[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
    struct CountingState {
        bytes: u64,
        largest_chunk: usize,
        syncs: u32,
    }

    #[derive(Debug)]
    struct CountingProvider {
        state: Rc<RefCell<CountingState>>,
    }

    impl ReadOnlyFileSystem for CountingProvider {
        fn metadata(&mut self, path: &str) -> Result<FileMetadata, FsError> {
            match path {
                "/" => Ok(FileMetadata {
                    kind: NodeKind::Directory,
                    byte_count: 0,
                }),
                "/large" => Ok(FileMetadata {
                    kind: NodeKind::File,
                    byte_count: self.state.borrow().bytes,
                }),
                _ => Err(FsError::NotFound),
            }
        }

        fn read_file(
            &mut self,
            path: &str,
            offset: u64,
            destination: &mut [u8],
        ) -> Result<usize, FsError> {
            if path != "/large" {
                return Err(FsError::NotFound);
            }
            let available = self.state.borrow().bytes.saturating_sub(offset);
            let count = destination
                .len()
                .min(usize::try_from(available).unwrap_or(usize::MAX));
            destination[..count].fill(0xa5);
            Ok(count)
        }

        fn list(
            &mut self,
            _path: &str,
            _cursor: u64,
            _max_entries: usize,
            _max_name_bytes: usize,
        ) -> Result<ProviderListing, FsError> {
            Ok(ProviderListing {
                entries: Vec::new(),
                next_cursor: None,
            })
        }

        fn truncate_file(&mut self, path: &str) -> Result<(), FsError> {
            if path != "/large" {
                return Err(FsError::Invalid);
            }
            self.state.borrow_mut().bytes = 0;
            Ok(())
        }

        fn append_file(&mut self, path: &str, bytes: &[u8]) -> Result<(), FsError> {
            if path != "/large" || bytes.is_empty() {
                return Err(FsError::Invalid);
            }
            let mut state = self.state.borrow_mut();
            state.bytes = state
                .bytes
                .checked_add(u64::try_from(bytes.len()).map_err(|_| FsError::Overflow)?)
                .ok_or(FsError::Overflow)?;
            state.largest_chunk = state.largest_chunk.max(bytes.len());
            Ok(())
        }

        fn sync_file(&mut self, path: &str) -> Result<(), FsError> {
            if path != "/large" {
                return Err(FsError::Invalid);
            }
            let mut state = self.state.borrow_mut();
            state.syncs = state.syncs.saturating_add(1);
            Ok(())
        }
    }

    impl ReadOnlyFileSystem for TestProvider {
        fn metadata(&mut self, path: &str) -> Result<FileMetadata, FsError> {
            match path {
                "/" => Ok(FileMetadata {
                    kind: NodeKind::Directory,
                    byte_count: 0,
                }),
                "/data" => Ok(FileMetadata {
                    kind: NodeKind::File,
                    byte_count: 7,
                }),
                _ => Err(FsError::NotFound),
            }
        }

        fn read_file(
            &mut self,
            path: &str,
            offset: u64,
            destination: &mut [u8],
        ) -> Result<usize, FsError> {
            if path != "/data" {
                return Err(FsError::NotFound);
            }
            let bytes = b"mounted";
            let offset = usize::try_from(offset).map_err(|_| FsError::Overflow)?;
            if offset >= bytes.len() {
                return Ok(0);
            }
            let count = destination.len().min(bytes.len() - offset);
            destination[..count].copy_from_slice(&bytes[offset..offset + count]);
            Ok(count)
        }

        fn list(
            &mut self,
            path: &str,
            cursor: u64,
            max_entries: usize,
            max_name_bytes: usize,
        ) -> Result<ProviderListing, FsError> {
            if path != "/" || cursor > 1 {
                return Err(FsError::Invalid);
            }
            if cursor == 1 {
                return Ok(ProviderListing {
                    entries: Vec::new(),
                    next_cursor: None,
                });
            }
            if max_entries == 0 || max_name_bytes < 4 {
                return Ok(ProviderListing {
                    entries: Vec::new(),
                    next_cursor: Some(0),
                });
            }
            Ok(ProviderListing {
                entries: vec![DirEntry {
                    name: "data".into(),
                    kind: NodeKind::File,
                }],
                next_cursor: None,
            })
        }

        fn read_link(&mut self, path: &str) -> Result<alloc::string::String, FsError> {
            (path == "/link")
                .then(|| "/data".into())
                .ok_or(FsError::WrongType)
        }

        fn create_symlink(&mut self, target: &str, link_path: &str) -> Result<(), FsError> {
            if target == "/data" && link_path == "/link" {
                Ok(())
            } else {
                Err(FsError::Invalid)
            }
        }

        fn create_hard_link(&mut self, existing: &str, new_path: &str) -> Result<(), FsError> {
            if existing == "/data" && new_path == "/hard" {
                Ok(())
            } else {
                Err(FsError::Invalid)
            }
        }

        fn create_directory(&mut self, path: &str) -> Result<(), FsError> {
            if path == "/directory" {
                Ok(())
            } else {
                Err(FsError::Invalid)
            }
        }
    }

    impl ReadOnlyFileSystem for ScopedProvider {
        fn metadata(&mut self, path: &str) -> Result<FileMetadata, FsError> {
            match path {
                "/" | "/scope" | "/outside" => Ok(FileMetadata {
                    kind: NodeKind::Directory,
                    byte_count: 0,
                }),
                "/scope/file" | "/scope/link" | "/outside/secret" => Ok(FileMetadata {
                    kind: NodeKind::File,
                    byte_count: 6,
                }),
                _ => Err(FsError::NotFound),
            }
        }

        fn metadata_no_follow(&mut self, path: &str) -> Result<FileMetadata, FsError> {
            if path == "/scope/link" {
                return Ok(FileMetadata {
                    kind: NodeKind::Symlink,
                    byte_count: 0,
                });
            }
            self.metadata(path)
        }

        fn read_file(
            &mut self,
            path: &str,
            offset: u64,
            destination: &mut [u8],
        ) -> Result<usize, FsError> {
            let bytes: &[u8] = match path {
                "/scope/file" => b"inside",
                "/scope/link" | "/outside/secret" => b"secret",
                _ => return Err(FsError::NotFound),
            };
            let start = usize::try_from(offset).map_err(|_| FsError::Overflow)?;
            if start >= bytes.len() {
                return Ok(0);
            }
            let count = destination.len().min(bytes.len() - start);
            destination[..count].copy_from_slice(&bytes[start..start + count]);
            Ok(count)
        }

        fn list(
            &mut self,
            _path: &str,
            _cursor: u64,
            _max_entries: usize,
            _max_name_bytes: usize,
        ) -> Result<ProviderListing, FsError> {
            Ok(ProviderListing {
                entries: Vec::new(),
                next_cursor: None,
            })
        }

        fn read_link(&mut self, path: &str) -> Result<String, FsError> {
            if path == "/scope/link" {
                Ok("/outside/secret".into())
            } else {
                Err(FsError::WrongType)
            }
        }
    }

    #[test]
    fn paths_are_bounded_and_cannot_escape_root() {
        assert_eq!(canonicalize("/a/b", "../../../../c"), Ok("/c".into()));
        assert_eq!(canonicalize("/", "//a/./b/../c"), Ok("/a/c".into()));
        assert_eq!(canonicalize("/", "bad\0name"), Err(FsError::Invalid));
    }

    #[test]
    fn scoped_paths_are_relative_and_cannot_escape_the_granted_root() {
        assert_eq!(canonicalize_beneath("/vol/app", "."), Ok("/vol/app".into()));
        assert_eq!(
            canonicalize_beneath("/vol/app", "data/file"),
            Ok("/vol/app/data/file".into())
        );
        assert_eq!(
            canonicalize_beneath("/vol/app", "data/../file"),
            Ok("/vol/app/file".into())
        );
        for path in [
            "",
            "/vol/app/file",
            "..",
            "../outside",
            "data/../../outside",
        ] {
            assert_eq!(
                canonicalize_beneath("/vol/app", path),
                Err(FsError::Invalid)
            );
        }
        assert_eq!(canonicalize_beneath("/", "file"), Err(FsError::Invalid));
    }

    #[test]
    fn directory_capabilities_bind_generation_rights_mounts_and_links() -> Result<(), FsError> {
        let mut namespace = Namespace::new(RamFsQuota::default());
        namespace.mount_read_only("/vol", Box::new(ScopedProvider))?;
        let read = namespace.grant_directory("/vol/scope", 7, DirectoryRights::READ)?;
        assert_eq!(read.root(), "/vol/scope");
        assert_eq!(read.generation(), 7);
        assert_eq!(read.rights(), DirectoryRights::READ);
        assert_eq!(
            namespace.resolve_directory_read(&read, 7, "file"),
            Ok("/vol/scope/file".into())
        );
        assert_eq!(
            namespace.resolve_directory_read(&read, 8, "file"),
            Err(FsError::ReadOnly)
        );
        assert_eq!(
            namespace.resolve_directory_mutation(&read, 7, "file", false),
            Err(FsError::ReadOnly)
        );
        assert_eq!(
            namespace.resolve_directory_read(&read, 7, "../outside/secret"),
            Err(FsError::Invalid)
        );
        assert_eq!(
            namespace.resolve_directory_read(&read, 7, "/outside/secret"),
            Err(FsError::Invalid)
        );
        assert_eq!(
            namespace.resolve_directory_read(&read, 7, "link"),
            Err(FsError::Invalid)
        );
        assert_eq!(
            namespace.resolve_directory_link(&read, 7, "link", false),
            Ok("/vol/scope/link".into())
        );

        namespace.add_read_only_dir("/share")?;
        namespace.add_read_only_dir("/share/app")?;
        let assets = namespace.grant_directory("/share/app", 7, DirectoryRights::READ)?;
        namespace.mount_read_only("/share/app/mounted", Box::new(TestProvider))?;
        assert_eq!(
            namespace.resolve_directory_read(&assets, 7, "mounted/data"),
            Err(FsError::Invalid)
        );
        Ok(())
    }

    #[test]
    fn mutation_capability_validates_existing_parents_before_creation() -> Result<(), FsError> {
        let mut namespace = Namespace::new(RamFsQuota::default());
        let mutation = namespace.grant_directory("/tmp", 9, DirectoryRights::READ_MUTATE)?;
        assert_eq!(
            namespace.resolve_directory_mutation(&mutation, 9, "new", true),
            Ok("/tmp/new".into())
        );
        assert_eq!(
            namespace.resolve_directory_mutation(&mutation, 9, "missing/new", true),
            Err(FsError::NotFound)
        );
        namespace.create_directory("/tmp", "present")?;
        assert_eq!(
            namespace.resolve_directory_mutation(&mutation, 9, "present/new", true),
            Ok("/tmp/present/new".into())
        );
        Ok(())
    }

    #[test]
    fn ramfs_quota_and_deletion_accounting() {
        let mut fs = Namespace::new(RamFsQuota {
            max_bytes: 4,
            max_nodes: 1,
            max_file_bytes: 4,
        });
        assert_eq!(fs.write_file("/", "/tmp/a", b"1234"), Ok(()));
        assert_eq!(fs.write_file("/", "/tmp/b", b"x"), Err(FsError::NoSpace));
        assert_eq!(fs.remove_file("/", "/tmp/a"), Ok(()));
        assert_eq!(fs.write_file("/", "/tmp/b", b"x"), Ok(()));
        assert_eq!(fs.memory_stats().ramfs_used, 1);
        assert_eq!(fs.memory_stats().ramfs_high_water, 4);
    }

    #[test]
    fn streamed_provider_scales_to_two_gib_with_one_mib_working_chunks() {
        const TOTAL_BYTES: u64 = 2 * 1024 * 1024 * 1024;
        const CHUNK_BYTES: usize = 1024 * 1024;
        let state = Rc::new(RefCell::new(CountingState::default()));
        let provider = CountingProvider {
            state: Rc::clone(&state),
        };
        let mut fs = Namespace::new(RamFsQuota::default());
        assert_eq!(fs.mount_writable("/media", Box::new(provider)), Ok(()));
        assert_eq!(fs.truncate_file("/", "/media/large"), Ok(()));
        let chunk = vec![0x5a; CHUNK_BYTES];
        for _ in 0..TOTAL_BYTES / CHUNK_BYTES as u64 {
            assert_eq!(fs.append_file("/", "/media/large", &chunk), Ok(()));
        }
        assert_eq!(fs.sync_file("/", "/media/large"), Ok(()));
        assert_eq!(
            *state.borrow(),
            CountingState {
                bytes: TOTAL_BYTES,
                largest_chunk: CHUNK_BYTES,
                syncs: 1,
            }
        );
    }

    #[test]
    fn ramfs_directory_creation_is_bounded_and_requires_existing_parents() {
        let mut fs = Namespace::new(RamFsQuota {
            max_bytes: 4,
            max_nodes: 2,
            max_file_bytes: 4,
        });
        assert_eq!(fs.create_directory("/", "/tmp/one"), Ok(()));
        assert_eq!(fs.create_directory("/", "/tmp/one/two"), Ok(()));
        assert_eq!(
            fs.create_directory("/", "/tmp/one/three"),
            Err(FsError::NoSpace)
        );
        assert_eq!(
            fs.create_directory("/", "/tmp/one/two"),
            Err(FsError::Exists)
        );
    }

    #[test]
    fn ramfs_rename_and_directory_removal_are_atomic_and_precise() {
        let mut fs = Namespace::new(RamFsQuota {
            max_bytes: 64,
            max_nodes: 16,
            max_file_bytes: 64,
        });
        assert_eq!(fs.create_directory("/", "/tmp/tree"), Ok(()));
        assert_eq!(fs.create_directory("/", "/tmp/tree/nested"), Ok(()));
        assert_eq!(fs.write_file("/", "/tmp/tree/nested/file", b"data"), Ok(()));
        assert_eq!(
            fs.remove_directory("/", "/tmp/tree"),
            Err(FsError::NotEmpty)
        );
        assert_eq!(fs.rename("/", "/tmp/tree", "/tmp/moved"), Ok(()));
        assert_eq!(fs.metadata("/", "/tmp/tree"), Err(FsError::NotFound));
        assert_eq!(
            fs.read_file("/", "/tmp/moved/nested/file"),
            Ok(b"data".to_vec())
        );
        assert_eq!(
            fs.rename("/", "/tmp/moved", "/tmp/moved/nested/loop"),
            Err(FsError::Invalid)
        );
        assert_eq!(fs.write_file("/", "/tmp/existing", b"keep"), Ok(()));
        assert_eq!(
            fs.rename("/", "/tmp/moved", "/tmp/existing"),
            Err(FsError::Exists)
        );
        assert_eq!(fs.read_file("/", "/tmp/existing"), Ok(b"keep".to_vec()));
        assert_eq!(
            fs.read_file("/", "/tmp/moved/nested/file"),
            Ok(b"data".to_vec())
        );
        assert_eq!(fs.remove_file("/", "/tmp/moved/nested/file"), Ok(()));
        assert_eq!(fs.remove_directory("/", "/tmp/moved/nested"), Ok(()));
        assert_eq!(fs.remove_directory("/", "/tmp/moved"), Ok(()));
        assert_eq!(fs.remove_file("/", "/tmp/existing"), Ok(()));
        assert_eq!(fs.remove_directory("/", "/tmp"), Err(FsError::ReadOnly));
    }

    #[test]
    fn rename_rejects_provider_crossings_and_mountpoint_names() -> Result<(), FsError> {
        let mut fs = Namespace::new(RamFsQuota::default());
        fs.add_read_only_dir("/first")?;
        fs.add_read_only_dir("/second")?;
        fs.mount_writable("/first", Box::new(TestProvider))?;
        fs.mount_writable("/second", Box::new(TestProvider))?;
        assert_eq!(
            fs.rename("/", "/first/data", "/second/moved"),
            Err(FsError::CrossDevice)
        );
        assert_eq!(
            fs.rename("/", "/first", "/tmp/first"),
            Err(FsError::ReadOnly)
        );
        assert_eq!(fs.remove_directory("/", "/first"), Err(FsError::ReadOnly));
        Ok(())
    }

    #[test]
    fn command_revision_changes_only_for_successful_bin_updates() {
        let mut fs = Namespace::new(RamFsQuota::default());
        assert_eq!(fs.command_revision(), 0);
        assert_eq!(fs.write_file("/", "/tmp/data", b"x"), Ok(()));
        assert_eq!(fs.set_system_file("/sys/status", b"ready"), Ok(()));
        assert_eq!(fs.command_revision(), 0);

        assert_eq!(fs.add_read_only_dir("/bin"), Ok(()));
        assert_eq!(fs.command_revision(), 1);
        assert_eq!(fs.add_read_only_file("/bin/echo.kex", b"kex"), Ok(()));
        assert_eq!(fs.command_revision(), 2);
        assert_eq!(
            fs.add_read_only_file("/bin/echo.kex", b"duplicate"),
            Err(FsError::Exists)
        );
        assert_eq!(fs.command_revision(), 2);
    }

    #[test]
    fn metadata_range_reads_and_caller_whole_file_limits_are_distinct() {
        let mut fs = Namespace::new(RamFsQuota::default());
        assert_eq!(fs.write_file("/", "/tmp/app.kex", b"0123456789"), Ok(()));
        assert_eq!(
            fs.metadata("/", "/tmp/app.kex"),
            Ok(FileMetadata {
                kind: NodeKind::File,
                byte_count: 10,
            })
        );
        let mut range = [0_u8; 4];
        assert_eq!(fs.read_file_at("/", "/tmp/app.kex", 3, &mut range), Ok(4));
        assert_eq!(&range, b"3456");
        assert_eq!(
            fs.read_file_bounded("/", "/tmp/app.kex", 9),
            Err(FsError::NoSpace)
        );
        assert_eq!(
            fs.read_file_bounded("/", "/tmp/app.kex", 10),
            Ok(b"0123456789".to_vec())
        );
    }

    #[test]
    fn mounted_link_operations_require_one_writable_provider() {
        let mut fs = Namespace::new(RamFsQuota::default());
        assert_eq!(fs.mount_writable("/media", Box::new(TestProvider)), Ok(()));
        assert_eq!(fs.create_symlink("/", "/data", "/media/link"), Ok(()));
        assert_eq!(fs.read_link("/", "/media/link"), Ok("/data".into()));
        assert_eq!(
            fs.create_hard_link("/", "/media/data", "/media/hard"),
            Ok(())
        );
        assert_eq!(
            fs.create_hard_link("/", "/media/data", "/tmp/hard"),
            Err(FsError::Unsupported)
        );
    }

    #[test]
    fn listing_is_lexical_and_shallow() {
        let mut fs = Namespace::new(RamFsQuota::default());
        assert_eq!(fs.write_file("/", "/tmp/z", b""), Ok(()));
        assert_eq!(fs.write_file("/", "/tmp/a", b""), Ok(()));
        let list = fs.list("/", "/tmp").unwrap_or_default();
        assert_eq!(list.len(), 2);
        assert_eq!(list[0].name, "a");
        assert_eq!(list[0].kind, NodeKind::File);
        assert_eq!(list[1].name, "z");
    }

    #[test]
    fn bounded_listing_cursor_is_opaque_progress_without_duplication() {
        let mut fs = Namespace::new(RamFsQuota::default());
        for name in ["alpha", "beta", "gamma"] {
            assert_eq!(
                fs.write_file("/", &alloc::format!("/tmp/{name}"), b""),
                Ok(())
            );
        }
        let first = fs
            .list_bounded("/", "/tmp", 0, 1, 64)
            .unwrap_or_else(|_| ProviderListing {
                entries: Vec::new(),
                next_cursor: None,
            });
        assert_eq!(first.entries[0].name, "alpha");
        let second = fs
            .list_bounded("/", "/tmp", first.next_cursor.unwrap_or(u64::MAX), 2, 64)
            .unwrap_or_else(|_| ProviderListing {
                entries: Vec::new(),
                next_cursor: Some(u64::MAX),
            });
        assert_eq!(
            second
                .entries
                .iter()
                .map(|entry| entry.name.as_str())
                .collect::<Vec<_>>(),
            ["beta", "gamma"]
        );
        assert_eq!(second.next_cursor, None);
        assert_eq!(
            fs.list_bounded("/", "/tmp", 4, 1, 64),
            Err(FsError::Invalid)
        );
    }

    #[test]
    fn matching_listing_obeys_injected_entry_and_byte_budgets() {
        let mut fs = Namespace::new(RamFsQuota::default());
        assert_eq!(fs.write_file("/", "/tmp/alpha", b""), Ok(()));
        assert_eq!(fs.write_file("/", "/tmp/alpine", b""), Ok(()));
        assert_eq!(fs.write_file("/", "/tmp/beta", b""), Ok(()));
        let listing = fs
            .list_matching_bounded("/", "/tmp", "al", false, 1, 16)
            .unwrap_or_else(|_| super::DirectoryListing {
                entries: Vec::new(),
                truncated: false,
            });
        assert_eq!(listing.entries.len(), 1);
        assert_eq!(listing.entries[0].name, "alpha");
        assert!(listing.truncated);

        let disabled = fs
            .list_matching_bounded("/", "/tmp", "a", false, 0, 0)
            .unwrap_or_else(|_| super::DirectoryListing {
                entries: Vec::new(),
                truncated: false,
            });
        assert!(disabled.entries.is_empty());
        assert!(disabled.truncated);
    }

    #[test]
    fn corrupt_embedded_image_is_rejected_without_partial_mount() {
        let mut image = vec![0_u8; 16];
        image[..8].copy_from_slice(&KEFS_V1_MAGIC);
        image[8..10].copy_from_slice(&1_u16.to_le_bytes());
        image[12..16].copy_from_slice(&16_u32.to_le_bytes());
        let mut fs = Namespace::new(RamFsQuota::default());
        assert_eq!(fs.mount_embedded(&image), Err(FsError::Invalid));
        assert!(fs.list("/", "/").is_ok());
    }

    #[test]
    fn format_identifier_is_product_name_independent() {
        assert_eq!(KEFS_V1_MAGIC, *b"KEFSv1\0\0");
    }

    #[test]
    fn mounted_providers_are_routed_and_remain_read_only() {
        let mut fs = Namespace::new(RamFsQuota::default());
        assert_eq!(fs.mount_read_only("/media", Box::new(TestProvider)), Ok(()));
        assert_eq!(fs.read_file("/", "/media/data"), Ok(b"mounted".to_vec()));
        assert_eq!(fs.resolve_dir("/", "/media"), Ok("/media".into()));
        assert_eq!(fs.list("/", "/media").map(|entries| entries.len()), Ok(1));
        assert_eq!(
            fs.list_matching_bounded("/", "/media", "da", false, 1, 4)
                .map(|listing| listing.entries.len()),
            Ok(1)
        );
        assert_eq!(
            fs.write_file("/", "/media/data", b"changed"),
            Err(FsError::ReadOnly)
        );
        assert_eq!(fs.remove_file("/", "/media/data"), Err(FsError::ReadOnly));
        assert!(fs.list("/", "/").is_ok_and(|entries| {
            entries
                .iter()
                .any(|entry| entry.name == "media" && entry.kind == NodeKind::Directory)
        }));
    }

    #[test]
    fn provider_can_overlay_only_an_empty_recovery_mountpoint() {
        let mut fs = Namespace::new(RamFsQuota::default());
        assert_eq!(fs.add_read_only_dir("/vol"), Ok(()));
        assert_eq!(fs.add_read_only_dir("/vol/root"), Ok(()));
        assert_eq!(
            fs.mount_read_only("/vol/root", Box::new(TestProvider)),
            Ok(())
        );
        assert_eq!(fs.read_file("/", "/vol/root/data"), Ok(b"mounted".to_vec()));

        let mut occupied = Namespace::new(RamFsQuota::default());
        assert_eq!(occupied.add_read_only_dir("/vol"), Ok(()));
        assert_eq!(occupied.add_read_only_dir("/vol/root"), Ok(()));
        assert_eq!(
            occupied.add_read_only_file("/vol/root/local", b"reserved"),
            Ok(())
        );
        assert_eq!(
            occupied.mount_read_only("/vol/root", Box::new(TestProvider)),
            Err(FsError::Exists)
        );
    }

    #[test]
    fn desired_and_active_configuration_namespaces_are_distinct_and_atomic() {
        let mut fs = Namespace::new(RamFsQuota::default());
        assert_eq!(
            fs.mount_read_only("/config", Box::new(TestProvider)),
            Err(FsError::ReadOnly)
        );
        assert_eq!(fs.mount_writable("/config", Box::new(TestProvider)), Ok(()));
        assert_eq!(
            fs.mount_writable("/sys/config", Box::new(TestProvider)),
            Err(FsError::ReadOnly)
        );
        assert_eq!(fs.read_file("/", "/config/data"), Ok(b"mounted".to_vec()));
        assert_eq!(fs.system_config_generation(), 0);

        assert_eq!(
            fs.replace_system_config(
                7,
                &[
                    ("app/endpoint", b"old".as_slice()),
                    ("app/limit", b"4".as_slice()),
                ],
            ),
            Ok(())
        );
        assert_eq!(fs.system_config_generation(), 7);
        assert_eq!(
            fs.read_file("/", "/sys/config/app/endpoint"),
            Ok(b"old".to_vec())
        );

        assert_eq!(
            fs.replace_system_config(
                8,
                &[
                    ("app", b"collision".as_slice()),
                    ("app/new", b"candidate".as_slice()),
                ],
            ),
            Err(FsError::WrongType)
        );
        assert_eq!(fs.system_config_generation(), 7);
        assert_eq!(
            fs.read_file("/", "/sys/config/app/endpoint"),
            Ok(b"old".to_vec())
        );
        assert_eq!(
            fs.read_file("/", "/sys/config/app/new"),
            Err(FsError::NotFound)
        );
        assert_eq!(
            fs.replace_system_config(8, &[("app/../escape", b"bad".as_slice())]),
            Err(FsError::Invalid)
        );
        assert_eq!(fs.system_config_generation(), 7);

        assert_eq!(
            fs.replace_system_config(8, &[("app/endpoint", b"new".as_slice())]),
            Ok(())
        );
        assert_eq!(fs.system_config_generation(), 8);
        assert_eq!(
            fs.read_file("/", "/sys/config/app/endpoint"),
            Ok(b"new".to_vec())
        );
        assert_eq!(
            fs.read_file("/", "/sys/config/app/limit"),
            Err(FsError::NotFound)
        );
        assert_eq!(
            fs.write_file("/", "/sys/config/app/endpoint", b"draft"),
            Err(FsError::ReadOnly)
        );
        assert_eq!(
            fs.set_system_file("/sys/config/app/endpoint", b"override"),
            Err(FsError::ReadOnly)
        );
    }

    #[test]
    fn embedded_and_composed_files_cannot_populate_configuration_roots() {
        let mut fs = Namespace::new(RamFsQuota::default());
        assert_eq!(
            fs.add_read_only_file("/config/default", b"ambient"),
            Err(FsError::ReadOnly)
        );
        assert_eq!(
            fs.add_read_only_file("/sys/config/default", b"ambient"),
            Err(FsError::ReadOnly)
        );

        let path = b"/config/default";
        let mut image = vec![0_u8; 16];
        image[..8].copy_from_slice(&KEFS_V1_MAGIC);
        image[8..10].copy_from_slice(&1_u16.to_le_bytes());
        image.push(1);
        image.extend_from_slice(&u16::try_from(path.len()).unwrap_or(0).to_le_bytes());
        image.extend_from_slice(&0_u32.to_le_bytes());
        image.extend_from_slice(path);
        let image_len = u32::try_from(image.len()).unwrap_or(0);
        image[12..16].copy_from_slice(&image_len.to_le_bytes());
        assert_eq!(fs.mount_embedded(&image), Err(FsError::ReadOnly));
        assert_eq!(fs.read_file("/", "/config/default"), Err(FsError::NotFound));
    }
}
