//! Portable virtual namespace over mounted filesystem providers.
#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;

use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::rc::Rc;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::str;
use troe_core::MemoryStats;
use troe_fs_api::{
    DirEntry, DirectoryListing, FILE_IO_BUFFER_BYTES, FileMetadata, FileSystemProvider, FsError,
    MAX_NAME_BYTES, NodeKind, ProviderListing, ProviderUsage, WallClock, canonicalize,
    canonicalize_beneath,
};
use troe_fs_client::NamespaceClient;

const PROVIDER_READ_CHUNK: usize = 4 * 1024;
const MAX_PROVIDER_DIRECTORY_ENTRIES: usize = 1024;
const MAX_PROVIDER_DIRECTORY_BYTES: usize = 64 * 1024;
/// Maximum files in one active-generation `/sys/config` projection.
pub const MAX_SYSTEM_CONFIG_FILES: usize = 128;
/// Maximum aggregate bytes in one active-generation configuration projection.
pub const MAX_SYSTEM_CONFIG_BYTES: usize = 64 * 1024;
/// Maximum bytes in one projected configuration file.
pub const MAX_SYSTEM_CONFIG_FILE_BYTES: usize = 8 * 1024;

#[derive(Clone, Debug)]
enum Node {
    Directory,
    File { bytes: Vec<u8> },
}

impl Node {
    const fn kind(&self) -> NodeKind {
        match self {
            Self::Directory => NodeKind::Directory,
            Self::File { .. } => NodeKind::File,
        }
    }
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

/// One provider attached at an exact namespace path.
#[derive(Debug)]
struct ProviderMount {
    path: String,
    provider: Box<dyn FileSystemProvider>,
    writable: bool,
}

/// Immutable composed nodes plus the mounted providers layered over them.
#[derive(Debug)]
pub struct Namespace {
    nodes: BTreeMap<String, Node>,
    mounts: Vec<ProviderMount>,
    command_revision: u64,
    system_config_generation: u64,
    wall_clock: Option<Rc<dyn WallClock>>,
}

impl Default for Namespace {
    fn default() -> Self {
        Self::new()
    }
}

impl Namespace {
    /// Create the fixed root skeleton with no provider attached.
    ///
    /// The caller composes the namespace by mounting providers, including the
    /// writable filesystem for `/tmp`. The namespace deliberately knows no
    /// filesystem implementation.
    #[must_use]
    pub fn new() -> Self {
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
            system_config_generation: 0,
            wall_clock: None,
        }
    }

    /// Install the clock every mounted and later-mounted provider stamps with.
    ///
    /// The handle is shared, not sampled, so a provider mounted before the
    /// clock existed starts stamping from here on and a long-lived mount never
    /// writes its mount time onto a later mutation.
    pub fn set_wall_clock(&mut self, clock: Rc<dyn WallClock>) {
        for mount in &mut self.mounts {
            mount.provider.set_wall_clock(Rc::clone(&clock));
        }
        self.wall_clock = Some(clock);
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

    /// Attach a validated read-only provider at one empty namespace path.
    ///
    /// # Errors
    ///
    /// Rejects root, invalid or duplicate mount paths, missing internal parent
    /// directories, nested mounts, and providers whose root is not a directory.
    pub fn mount_read_only(
        &mut self,
        path: &str,
        provider: Box<dyn FileSystemProvider>,
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
        provider: Box<dyn FileSystemProvider>,
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
        mut provider: Box<dyn FileSystemProvider>,
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
        if let Some(clock) = self.wall_clock.as_ref() {
            provider.set_wall_clock(Rc::clone(clock));
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
        Err(FsError::ReadOnly)
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
        Err(FsError::ReadOnly)
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
            Some(Node::File { .. }) => Err(FsError::ReadOnly),
            Some(Node::Directory) => Err(FsError::WrongType),
            None => Err(FsError::NotFound),
        }
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
        Err(FsError::ReadOnly)
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
        Err(FsError::ReadOnly)
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
            (None, None) => return Err(FsError::ReadOnly),
            _ => return Err(FsError::CrossDevice),
        }
        if is_command_path(&source) || is_command_path(&destination) {
            self.bump_command_revision();
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
        let usage = self
            .mounts
            .iter()
            .filter_map(|mount| mount.provider.usage())
            .fold(ProviderUsage::default(), |total, mount| ProviderUsage {
                used_bytes: total.used_bytes.saturating_add(mount.used_bytes),
                limit_bytes: total.limit_bytes.saturating_add(mount.limit_bytes),
                high_water_bytes: total
                    .high_water_bytes
                    .saturating_add(mount.high_water_bytes),
            });
        MemoryStats {
            ramfs_used: usage.used_bytes,
            ramfs_limit: usage.limit_bytes,
            ramfs_high_water: usage.high_water_bytes,
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

fn parent_path(path: &str) -> Option<&str> {
    let index = path.rfind('/')?;
    Some(if index == 0 { "/" } else { &path[..index] })
}

fn is_active_configuration_path(path: &str) -> bool {
    path == "/sys/config" || path.starts_with("/sys/config/")
}

fn is_reserved_configuration_content(path: &str) -> bool {
    path.starts_with("/config/") || is_active_configuration_path(path)
}

/// The in-process namespace is the direct implementation of the client
/// contract. Every method forwards to the inherent one, which takes precedence
/// over the trait, so this adds no behavior of its own.
///
/// A second implementation carrying the same calls over IPC is what moves the
/// namespace into a server without changing a single client.
impl NamespaceClient for Namespace {
    fn metadata(&mut self, cwd: &str, path: &str) -> Result<FileMetadata, FsError> {
        Self::metadata(self, cwd, path)
    }

    fn metadata_no_follow(&mut self, cwd: &str, path: &str) -> Result<FileMetadata, FsError> {
        Self::metadata_no_follow(self, cwd, path)
    }

    fn read_file_at(
        &mut self,
        cwd: &str,
        path: &str,
        offset: u64,
        destination: &mut [u8],
    ) -> Result<usize, FsError> {
        Self::read_file_at(self, cwd, path, offset, destination)
    }

    fn read_file_bounded(
        &mut self,
        cwd: &str,
        path: &str,
        max_bytes: usize,
    ) -> Result<Vec<u8>, FsError> {
        Self::read_file_bounded(self, cwd, path, max_bytes)
    }

    fn read_file(&mut self, cwd: &str, path: &str) -> Result<Vec<u8>, FsError> {
        Self::read_file(self, cwd, path)
    }

    fn truncate_file(&mut self, cwd: &str, path: &str) -> Result<(), FsError> {
        Self::truncate_file(self, cwd, path)
    }

    fn append_file(&mut self, cwd: &str, path: &str, bytes: &[u8]) -> Result<(), FsError> {
        Self::append_file(self, cwd, path, bytes)
    }

    fn sync_file(&mut self, cwd: &str, path: &str) -> Result<(), FsError> {
        Self::sync_file(self, cwd, path)
    }

    fn write_file(&mut self, cwd: &str, path: &str, bytes: &[u8]) -> Result<(), FsError> {
        Self::write_file(self, cwd, path, bytes)
    }

    fn remove_file(&mut self, cwd: &str, path: &str) -> Result<(), FsError> {
        Self::remove_file(self, cwd, path)
    }

    fn create_directory(&mut self, cwd: &str, path: &str) -> Result<(), FsError> {
        Self::create_directory(self, cwd, path)
    }

    fn remove_directory(&mut self, cwd: &str, path: &str) -> Result<(), FsError> {
        Self::remove_directory(self, cwd, path)
    }

    fn rename(&mut self, cwd: &str, source: &str, destination: &str) -> Result<(), FsError> {
        Self::rename(self, cwd, source, destination)
    }

    fn read_link(&mut self, cwd: &str, path: &str) -> Result<String, FsError> {
        Self::read_link(self, cwd, path)
    }

    fn create_symlink(&mut self, cwd: &str, target: &str, link_path: &str) -> Result<(), FsError> {
        Self::create_symlink(self, cwd, target, link_path)
    }

    fn create_hard_link(
        &mut self,
        cwd: &str,
        existing: &str,
        new_path: &str,
    ) -> Result<(), FsError> {
        Self::create_hard_link(self, cwd, existing, new_path)
    }

    fn list(&mut self, cwd: &str, path: &str) -> Result<Vec<DirEntry>, FsError> {
        Self::list(self, cwd, path)
    }

    fn list_bounded(
        &mut self,
        cwd: &str,
        path: &str,
        cursor: u64,
        max_entries: usize,
        max_name_bytes: usize,
    ) -> Result<ProviderListing, FsError> {
        Self::list_bounded(self, cwd, path, cursor, max_entries, max_name_bytes)
    }

    fn list_matching_bounded(
        &mut self,
        cwd: &str,
        path: &str,
        name_prefix: &str,
        directories_only: bool,
        max_entries: usize,
        max_bytes: usize,
    ) -> Result<DirectoryListing, FsError> {
        Self::list_matching_bounded(
            self,
            cwd,
            path,
            name_prefix,
            directories_only,
            max_entries,
            max_bytes,
        )
    }

    fn resolve_dir(&mut self, cwd: &str, path: &str) -> Result<String, FsError> {
        Self::resolve_dir(self, cwd, path)
    }

    fn memory_stats(&self) -> MemoryStats {
        Self::memory_stats(self)
    }

    fn command_revision(&self) -> u64 {
        Self::command_revision(self)
    }
}

#[cfg(test)]
mod tests {
    use troe_fs_kefs::Kefs;
    use troe_fs_ramfs::{RamFs, RamFsQuota};

    /// Compose the namespace the way a composition root does: a skeleton plus
    /// one writable filesystem mounted at `/tmp`.
    fn writable_namespace() -> Namespace {
        namespace_with_quota(RamFsQuota::default())
    }

    fn namespace_with_quota(quota: RamFsQuota) -> Namespace {
        let mut namespace = Namespace::new();
        assert_eq!(
            namespace.mount_writable("/tmp", Box::new(RamFs::new(quota))),
            Ok(())
        );
        namespace
    }

    use super::{
        DirEntry, DirectoryRights, FileMetadata, FileSystemProvider, FsError, Namespace, NodeKind,
        ProviderListing, canonicalize, canonicalize_beneath,
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

    impl FileSystemProvider for CountingProvider {
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

    impl FileSystemProvider for TestProvider {
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

    impl FileSystemProvider for ScopedProvider {
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
        let mut namespace = writable_namespace();
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
        let mut namespace = writable_namespace();
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
        let mut fs = namespace_with_quota(RamFsQuota {
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
        let mut fs = writable_namespace();
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
        let mut fs = namespace_with_quota(RamFsQuota {
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
        let mut fs = namespace_with_quota(RamFsQuota {
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
        let mut fs = writable_namespace();
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
        let mut fs = writable_namespace();
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
        let mut fs = writable_namespace();
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
        let mut fs = writable_namespace();
        assert_eq!(fs.mount_writable("/media", Box::new(TestProvider)), Ok(()));
        assert_eq!(fs.create_symlink("/", "/data", "/media/link"), Ok(()));
        assert_eq!(fs.read_link("/", "/media/link"), Ok("/data".into()));
        assert_eq!(
            fs.create_hard_link("/", "/media/data", "/media/hard"),
            Ok(())
        );
        // /tmp is an ordinary writable provider, so linking into it crosses a
        // filesystem boundary like any other provider pair.
        assert_eq!(
            fs.create_hard_link("/", "/media/data", "/tmp/hard"),
            Err(FsError::CrossDevice)
        );
        // A path served by no provider at all still has no link support.
        assert_eq!(
            fs.create_hard_link("/", "/media/data", "/sys/hard"),
            Err(FsError::Unsupported)
        );
        assert_eq!(
            fs.create_symlink("/", "/data", "/sys/link"),
            Err(FsError::Unsupported)
        );
    }

    #[test]
    fn listing_is_lexical_and_shallow() {
        let mut fs = writable_namespace();
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
        let mut fs = writable_namespace();
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
        let mut fs = writable_namespace();
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
    fn mounted_providers_are_routed_and_remain_read_only() {
        let mut fs = writable_namespace();
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
        let mut fs = writable_namespace();
        assert_eq!(fs.add_read_only_dir("/vol"), Ok(()));
        assert_eq!(fs.add_read_only_dir("/vol/root"), Ok(()));
        assert_eq!(
            fs.mount_read_only("/vol/root", Box::new(TestProvider)),
            Ok(())
        );
        assert_eq!(fs.read_file("/", "/vol/root/data"), Ok(b"mounted".to_vec()));

        let mut occupied = writable_namespace();
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
        let mut fs = writable_namespace();
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
    fn volumes_mount_beneath_a_reserved_embedded_directory() {
        // The boot manifest mounts volumes under /vol, which the embedded image
        // also populates. Reserving that root keeps it namespace-owned so the
        // volume mounts are ordinary mounts rather than rejected nested ones.
        let mut image = vec![0_u8; 16];
        image[..8].copy_from_slice(b"KEFSv1\0\0");
        image[8..10].copy_from_slice(&3_u16.to_le_bytes());
        for (kind, path) in [(2_u8, "/bin"), (2, "/vol"), (2, "/vol/root")] {
            image.push(kind);
            image.extend_from_slice(&u16::try_from(path.len()).unwrap_or(0).to_le_bytes());
            image.extend_from_slice(&0_u32.to_le_bytes());
            image.extend_from_slice(path.as_bytes());
        }
        let length = u32::try_from(image.len()).unwrap_or(0);
        image[12..16].copy_from_slice(&length.to_le_bytes());

        let mut fs = writable_namespace();
        let Ok(parsed) = Kefs::parse(&image) else {
            unreachable!("the image is well formed")
        };
        let embedded = parsed.into_mounts(&["/vol"]);
        for path in embedded.directories {
            assert_eq!(fs.add_read_only_dir(&path), Ok(()));
        }
        for (path, view) in embedded.mounts {
            assert_eq!(fs.mount_read_only(&path, Box::new(view)), Ok(()));
        }
        assert_eq!(
            fs.mount_writable("/vol/root", Box::new(TestProvider)),
            Ok(())
        );
        assert_eq!(
            fs.metadata("/", "/vol/root").map(|entry| entry.kind),
            Ok(NodeKind::Directory)
        );
        assert_eq!(
            fs.metadata("/", "/bin").map(|entry| entry.kind),
            Ok(NodeKind::Directory)
        );
    }

    #[test]
    fn embedded_and_composed_files_cannot_populate_configuration_roots() {
        let mut fs = writable_namespace();
        assert_eq!(
            fs.add_read_only_file("/config/default", b"ambient"),
            Err(FsError::ReadOnly)
        );
        assert_eq!(
            fs.add_read_only_file("/sys/config/default", b"ambient"),
            Err(FsError::ReadOnly)
        );

        // An embedded image naming /config produces a mount at that root, and
        // the namespace must refuse it rather than let the image supply
        // configuration content.
        let path = b"/config/default";
        let mut image = vec![0_u8; 16];
        image[..8].copy_from_slice(b"KEFSv1\0\0");
        image[8..10].copy_from_slice(&1_u16.to_le_bytes());
        image.push(1);
        image.extend_from_slice(&u16::try_from(path.len()).unwrap_or(0).to_le_bytes());
        image.extend_from_slice(&0_u32.to_le_bytes());
        image.extend_from_slice(path);
        let image_len = u32::try_from(image.len()).unwrap_or(0);
        image[12..16].copy_from_slice(&image_len.to_le_bytes());
        let mut outcomes = Vec::new();
        if let Ok(embedded) = Kefs::parse(&image) {
            for (mount, view) in embedded.into_mounts(&[]).mounts {
                outcomes.push(fs.mount_read_only(&mount, Box::new(view)));
            }
        }
        assert_eq!(outcomes, vec![Err(FsError::ReadOnly)]);
        assert_eq!(fs.read_file("/", "/config/default"), Err(FsError::NotFound));
    }
}
