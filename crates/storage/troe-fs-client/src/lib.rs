//! Implementation-independent namespace client contract.
//!
//! The shell and the loader used to hold a concrete namespace, which meant
//! every client was bound to the in-process implementation and could not be
//! served across a protection boundary. They now name this trait instead.
//!
//! The contract is deliberately the *client* surface only: resolving, reading,
//! mutating, and listing paths. Composition — constructing a namespace,
//! mounting providers, and projecting generated state — stays with whoever owns
//! the namespace, because a client must not be able to attach a filesystem.
//!
//! One implementation exists today, the in-process namespace itself. A second
//! implementation carrying these calls over IPC is what lets the namespace move
//! into a server without the shell or the loader changing.
#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;

use core::fmt;

use alloc::string::String;
use alloc::vec::Vec;
use troe_core::MemoryStats;
use troe_fs_api::{DirEntry, DirectoryListing, FileMetadata, FsError, ProviderListing};

/// The path, file, and directory operations a namespace client may perform.
///
/// Every path is resolved against `cwd`, so a client never needs to hold or
/// construct an absolute namespace path itself.
pub trait NamespaceClient: fmt::Debug {
    /// Resolve one path, following a final symbolic link.
    ///
    /// # Errors
    ///
    /// Rejects invalid or missing paths, wrong types, and provider failures.
    fn metadata(&mut self, cwd: &str, path: &str) -> Result<FileMetadata, FsError>;

    /// Resolve one path without following its final symbolic link.
    ///
    /// # Errors
    ///
    /// Rejects invalid or missing paths and provider failures.
    fn metadata_no_follow(&mut self, cwd: &str, path: &str) -> Result<FileMetadata, FsError>;

    /// Read at most `destination.len()` bytes at an exact file offset.
    ///
    /// A successful zero return is end of file.
    ///
    /// # Errors
    ///
    /// Rejects invalid or non-file paths, offset arithmetic, and provider
    /// failures.
    fn read_file_at(
        &mut self,
        cwd: &str,
        path: &str,
        offset: u64,
        destination: &mut [u8],
    ) -> Result<usize, FsError>;

    /// Read one complete file no larger than `max_bytes`.
    ///
    /// # Errors
    ///
    /// Rejects files above the ceiling, invalid paths, and provider failures.
    fn read_file_bounded(
        &mut self,
        cwd: &str,
        path: &str,
        max_bytes: usize,
    ) -> Result<Vec<u8>, FsError>;

    /// Read one complete file under the default working-set ceiling.
    ///
    /// # Errors
    ///
    /// Rejects oversized files, invalid paths, and provider failures.
    fn read_file(&mut self, cwd: &str, path: &str) -> Result<Vec<u8>, FsError>;

    /// Truncate an existing writable file or create an empty one.
    ///
    /// # Errors
    ///
    /// Rejects immutable paths, wrong types, missing parents, and quota or
    /// media exhaustion.
    fn truncate_file(&mut self, cwd: &str, path: &str) -> Result<(), FsError>;

    /// Append one chunk to a writable file.
    ///
    /// # Errors
    ///
    /// Rejects immutable paths, wrong types, and quota or media exhaustion.
    fn append_file(&mut self, cwd: &str, path: &str, bytes: &[u8]) -> Result<(), FsError>;

    /// Complete a streamed write and request provider durability.
    ///
    /// # Errors
    ///
    /// Rejects immutable paths, wrong types, and durability failures.
    fn sync_file(&mut self, cwd: &str, path: &str) -> Result<(), FsError>;

    /// Replace one complete file.
    ///
    /// # Errors
    ///
    /// Reports the first truncate, append, or durability failure.
    fn write_file(&mut self, cwd: &str, path: &str, bytes: &[u8]) -> Result<(), FsError>;

    /// Delete one writable file.
    ///
    /// # Errors
    ///
    /// Rejects invalid, missing, immutable, or non-file paths.
    fn remove_file(&mut self, cwd: &str, path: &str) -> Result<(), FsError>;

    /// Create one empty writable directory.
    ///
    /// # Errors
    ///
    /// Rejects immutable paths, missing parents, collisions, and exhaustion.
    fn create_directory(&mut self, cwd: &str, path: &str) -> Result<(), FsError>;

    /// Remove one empty writable directory without crossing a mount boundary.
    ///
    /// # Errors
    ///
    /// Rejects roots, mount points, non-directories, and nonempty directories.
    fn remove_directory(&mut self, cwd: &str, path: &str) -> Result<(), FsError>;

    /// Rename one object within a single writable provider.
    ///
    /// # Errors
    ///
    /// Rejects collisions, immutable objects, and provider crossings.
    fn rename(&mut self, cwd: &str, source: &str, destination: &str) -> Result<(), FsError>;

    /// Return a symbolic link's target without following it.
    ///
    /// # Errors
    ///
    /// Rejects invalid, missing, or non-symbolic-link paths.
    fn read_link(&mut self, cwd: &str, path: &str) -> Result<String, FsError>;

    /// Create one symbolic link.
    ///
    /// # Errors
    ///
    /// Rejects invalid paths, immutable mounts, and unsupported providers.
    fn create_symlink(&mut self, cwd: &str, target: &str, link_path: &str) -> Result<(), FsError>;

    /// Add a hard-link name for an existing file within one provider.
    ///
    /// # Errors
    ///
    /// Rejects cross-provider links, immutable mounts, and unsupported
    /// providers.
    fn create_hard_link(
        &mut self,
        cwd: &str,
        existing: &str,
        new_path: &str,
    ) -> Result<(), FsError>;

    /// List immediate children in lexical order.
    ///
    /// # Errors
    ///
    /// Rejects invalid, missing, or non-directory paths.
    fn list(&mut self, cwd: &str, path: &str) -> Result<Vec<DirEntry>, FsError>;

    /// List one bounded page of immediate children.
    ///
    /// # Errors
    ///
    /// Rejects invalid cursors, missing paths, and non-directories.
    fn list_bounded(
        &mut self,
        cwd: &str,
        path: &str,
        cursor: u64,
        max_entries: usize,
        max_name_bytes: usize,
    ) -> Result<ProviderListing, FsError>;

    /// List matching immediate children within caller-supplied budgets.
    ///
    /// # Errors
    ///
    /// Rejects invalid, missing, or non-directory paths.
    fn list_matching_bounded(
        &mut self,
        cwd: &str,
        path: &str,
        name_prefix: &str,
        directories_only: bool,
        max_entries: usize,
        max_bytes: usize,
    ) -> Result<DirectoryListing, FsError>;

    /// Resolve one existing directory to its canonical absolute path.
    ///
    /// # Errors
    ///
    /// Rejects invalid, missing, or non-directory paths.
    fn resolve_dir(&mut self, cwd: &str, path: &str) -> Result<String, FsError>;

    /// Report bounded writable-filesystem accounting.
    fn memory_stats(&self) -> MemoryStats;

    /// Revision of namespace changes that can alter `/bin` command discovery.
    ///
    /// A client may cache a validated command catalog until this value changes.
    fn command_revision(&self) -> u64;
}
