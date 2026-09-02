//! Implementation-independent filesystem contract shared by providers and clients.
//!
//! This crate owns the vocabulary every filesystem participant agrees on: error
//! and metadata types, directory entries, canonical path rules, and the provider
//! trait itself. It deliberately depends on nothing, so a provider, a namespace,
//! a client, or a service protocol can be linked without pulling in any
//! filesystem implementation.
#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;

use alloc::rc::Rc;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::fmt;

/// Maximum encoded path length.
pub const MAX_PATH_BYTES: usize = 1024;
/// Maximum single path component length.
///
/// This is ext4's own limit, so a foreign volume's names are representable.
pub const MAX_NAME_BYTES: usize = 255;
/// Maximum normalized path depth.
pub const MAX_PATH_DEPTH: usize = 16;

/// Default working-set target used when complete-file compatibility helpers stream.
///
/// This is four ext4 blocks. It is a transfer size, never a file-size ceiling.
pub const FILE_IO_BUFFER_BYTES: usize = 16 * 1024;
/// Largest app-selected file-stream aggregation size.
pub const MAX_FILE_IO_BUFFER_BYTES: usize = 1024 * 1024;

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
    /// The provider's bounded transport did not complete a request in time.
    ///
    /// Distinct from `Io`, which is a transport that answered with a failure:
    /// this is a transport that did not answer inside the bound its driver
    /// enforces, so the request's outcome is unknown rather than known-bad.
    Timeout,
    /// The media uses a feature outside the selected provider profile.
    Unsupported,
    /// The operation needs the wall clock's instant and no wall time is known.
    ///
    /// Distinct from `Unsupported`, which says the provider records nothing at
    /// all: this is a transient condition an installed clock resolves.
    NotConfigured,
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
            Self::Timeout => f.write_str("filesystem transport timed out"),
            Self::Unsupported => f.write_str("filesystem feature is unsupported"),
            Self::NotConfigured => f.write_str("wall clock is not set"),
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
    /// Whole Unix UTC seconds of the last payload modification, when recorded.
    ///
    /// `None` where the provider stores no timestamp at all, and also where it
    /// stores one that was never stamped: ADR 0058 leaves the fields it would
    /// write exactly as it found them whenever no wall time is known, which for
    /// a new FAT32 entry means zero. A zero is therefore an absent time rather
    /// than 1970, so it is reported as `None` and never as an instant.
    pub modified_unix_seconds: Option<u64>,
    /// Whole Unix UTC seconds of the last metadata change, when recorded.
    ///
    /// Advances whenever the object's record is rewritten, including changes a
    /// modification time does not see, such as a rename. `None` where the
    /// format has no such field: FAT32 has no change time at all, so this is
    /// reported absent rather than substituted from a field that means
    /// something else.
    pub changed_unix_seconds: Option<u64>,
    /// Whole Unix UTC seconds of the object's creation, when recorded.
    ///
    /// Never advances after the object is created. `None` under the same rule
    /// as the other two: a provider that stamps no creation time reports
    /// absence rather than the closest instant it happens to hold.
    pub created_unix_seconds: Option<u64>,
}

/// One bounded page of a provider directory traversal.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProviderListing {
    /// Entries retained within the caller's count and byte ceilings.
    pub entries: Vec<DirEntry>,
    /// Opaque provider cursor for the next page, or `None` at end-of-directory.
    pub next_cursor: Option<u64>,
}

/// Bounded payload accounting reported by a provider that owns a budget.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ProviderUsage {
    /// Retained payload bytes.
    pub used_bytes: u64,
    /// Configured payload ceiling.
    pub limit_bytes: u64,
    /// Greatest retained payload observed since construction.
    pub high_water_bytes: u64,
}

/// Source of Unix UTC seconds for the timestamps providers write.
///
/// The namespace owns one clock and hands the same handle to every provider,
/// so no mount captures an instant: a provider asks the clock again at each
/// mutation and therefore never stamps its own mount time onto a later write.
/// `None` means no wall time is known; a provider that reads it must leave the
/// timestamps it would otherwise write exactly as they were rather than
/// inventing one. A clock that moves backwards is recorded as it reads,
/// because a provider reports the time it was told, not a time of its own.
pub trait WallClock: fmt::Debug {
    /// Current Unix UTC time in whole seconds, or `None` when it is unknown.
    fn unix_seconds(&self) -> Option<u64>;
}

/// Narrow filesystem-provider interface consumed by the VFS.
///
/// Paths are absolute within the provider root and must already satisfy the
/// VFS normalization bounds. Providers independently validate them because a
/// capability client must not be able to bypass the namespace layer.
pub trait FileSystemProvider: fmt::Debug {
    /// Resolve one path without reading file payload data.
    ///
    /// # Errors
    ///
    /// Rejects invalid or missing paths, wrong types, corrupt or unsupported
    /// media, transport failures, and provider resource exhaustion.
    fn metadata(&mut self, path: &str) -> Result<FileMetadata, FsError>;

    /// Report bounded payload accounting, when this provider owns a budget.
    ///
    /// Providers backed by external media retain the default and report
    /// nothing; a provider that charges its own quota returns it here so the
    /// namespace never needs to know which implementation it mounted.
    fn usage(&self) -> Option<ProviderUsage> {
        None
    }
    /// Set one object's modification time, or stamp it from the wall clock.
    ///
    /// `None` requests the namespace clock's current instant, which is what
    /// `touch` with no explicit time asks for. `Some` requests an exact instant.
    ///
    /// Providers that store no timestamp retain this default and refuse, so a
    /// caller learns the time was not recorded instead of receiving success for
    /// a write that could not happen.
    ///
    /// # Errors
    ///
    /// Rejects invalid or missing paths, immutable or unsupported providers, a
    /// request for the clock's instant while no wall time is known, and
    /// persistence failures.
    fn set_modified_time(
        &mut self,
        _path: &str,
        _unix_seconds: Option<u64>,
    ) -> Result<(), FsError> {
        Err(FsError::Unsupported)
    }

    /// Adopt the namespace's wall clock.
    ///
    /// Providers that write no timestamps retain this default. A provider that
    /// does must read the handle at each mutation rather than at mount, and
    /// must leave timestamps untouched whenever the clock reports no time.
    fn set_wall_clock(&mut self, _clock: Rc<dyn WallClock>) {}

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
