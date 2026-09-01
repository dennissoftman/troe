//! Small `no_std` POSIX-like helpers over TROE's typed KEX ABI.
//!
//! This layer owns command algorithms and bounded allocation policy. It does
//! not widen kernel authority and is intentionally not a complete libc.
#![no_std]
#![deny(unsafe_code)]

#[cfg(feature = "alloc")]
extern crate alloc;
#[cfg(test)]
extern crate std;

mod ascii;
pub mod environment;
pub mod errno;
#[cfg(feature = "math")]
#[allow(unsafe_code)]
pub mod math;
#[allow(unsafe_code)]
pub mod memory;
pub mod process;
pub mod random;
pub mod time;
pub mod timezone;
pub mod units;

#[cfg(feature = "alloc")]
use alloc::{string::String, vec::Vec};
use troe_kex_sdk::{Error as KexError, FilesystemMutation, ReadOnlyFilesystem, filesystem};
#[cfg(feature = "alloc")]
use troe_kex_sdk::{FILESYSTEM_IO_BUFFER_BYTES, FILESYSTEM_LIST_BUFFER_BYTES};

/// Atomically replace one file with the supplied bytes.
///
/// The pending replacement is aborted if any streamed write fails.
///
/// # Errors
///
/// Reports typed mutation, partial-write, flush, or commit failures.
pub fn replace_bytes(
    mutation: &mut FilesystemMutation,
    path: &str,
    bytes: &[u8],
) -> Result<(), Error> {
    let mut replacement = mutation.begin_replace(path)?;
    if let Err(error) = replacement.write_all(bytes) {
        let _ignored = replacement.abort();
        return Err(error.into());
    }
    replacement.commit().map_err(Into::into)
}

/// Remove one file, symbolic link, or empty directory without following links.
///
/// # Errors
///
/// Reports typed metadata or mutation failures. Nonempty directories remain
/// unchanged.
pub fn remove_path(
    filesystem: &mut ReadOnlyFilesystem,
    mutation: &mut FilesystemMutation,
    path: &str,
) -> Result<(), Error> {
    match filesystem.metadata_no_follow(path)?.kind {
        filesystem::NodeKind::Directory => mutation.remove_directory(path)?,
        filesystem::NodeKind::File | filesystem::NodeKind::Symlink => mutation.remove(path)?,
    }
    Ok(())
}

/// Maximum retained objects in one recursive operation.
pub const MAX_TRAVERSAL_ENTRIES: usize = 4096;
/// Maximum aggregate path bytes retained by one recursive operation.
pub const MAX_TRAVERSAL_METADATA_BYTES: usize = 1024 * 1024;

/// Higher-level filesystem operation failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    /// The typed KEX service rejected or failed an operation.
    Service(KexError),
    /// A path cannot be represented by the KEX filesystem profile.
    InvalidPath,
    /// Fallible traversal metadata growth exceeded memory or policy ceilings.
    MetadataExhausted,
}

impl From<KexError> for Error {
    fn from(error: KexError) -> Self {
        Self::Service(error)
    }
}

impl Error {
    /// Return the underlying service error, when one exists.
    #[must_use]
    pub const fn service_error(self) -> Option<KexError> {
        match self {
            Self::Service(error) => Some(error),
            Self::InvalidPath | Self::MetadataExhausted => None,
        }
    }
}

#[derive(Debug)]
#[cfg(feature = "alloc")]
struct WalkEntry {
    path: String,
    relative: String,
    kind: filesystem::NodeKind,
}

/// Return a path's final lexical component.
#[must_use]
pub fn basename(path: &str) -> Option<&str> {
    path.trim_end_matches('/')
        .rsplit('/')
        .next()
        .filter(|name| !name.is_empty() && !matches!(*name, "." | ".."))
}

/// Join one validated base path and one immediate entry name.
///
/// # Errors
///
/// Rejects invalid names, path-length overflow, or allocation failure.
#[cfg(feature = "alloc")]
pub fn join(base: &str, name: &str) -> Result<String, Error> {
    if base.is_empty()
        || name.is_empty()
        || matches!(name, "." | "..")
        || name.contains('/')
        || name.as_bytes().contains(&0)
    {
        return Err(Error::InvalidPath);
    }
    let slash = usize::from(!base.ends_with('/'));
    let count = base
        .len()
        .checked_add(slash)
        .and_then(|value| value.checked_add(name.len()))
        .ok_or(Error::InvalidPath)?;
    if count > filesystem::MAX_PATH_BYTES {
        return Err(Error::InvalidPath);
    }
    let mut output = String::new();
    output
        .try_reserve_exact(count)
        .map_err(|_| Error::MetadataExhausted)?;
    output.push_str(base);
    if slash != 0 {
        output.push('/');
    }
    output.push_str(name);
    Ok(output)
}

#[cfg(feature = "alloc")]
fn join_relative(base: &str, relative: &str) -> Result<String, Error> {
    let mut output = owned(base)?;
    for component in relative.split('/') {
        output = join(&output, component)?;
    }
    Ok(output)
}

#[cfg(feature = "alloc")]
fn owned(value: &str) -> Result<String, Error> {
    if value.is_empty() || value.len() > filesystem::MAX_PATH_BYTES || value.as_bytes().contains(&0)
    {
        return Err(Error::InvalidPath);
    }
    let mut output = String::new();
    output
        .try_reserve_exact(value.len())
        .map_err(|_| Error::MetadataExhausted)?;
    output.push_str(value);
    Ok(output)
}

#[cfg(feature = "alloc")]
fn destination_for_source(
    filesystem: &mut ReadOnlyFilesystem,
    source: &str,
    destination: &str,
) -> Result<String, Error> {
    match filesystem.metadata(destination) {
        Ok(metadata) if metadata.kind == filesystem::NodeKind::Directory => {
            join(destination, basename(source).ok_or(Error::InvalidPath)?)
        }
        Ok(_) | Err(KexError::NotFound) => owned(destination),
        Err(error) => Err(error.into()),
    }
}

#[cfg(feature = "alloc")]
fn push_walk(
    entries: &mut Vec<WalkEntry>,
    metadata_bytes: &mut usize,
    entry: WalkEntry,
) -> Result<(), Error> {
    if entries.len() >= MAX_TRAVERSAL_ENTRIES {
        return Err(Error::MetadataExhausted);
    }
    *metadata_bytes = metadata_bytes
        .checked_add(entry.path.len())
        .and_then(|bytes| bytes.checked_add(entry.relative.len()))
        .ok_or(Error::MetadataExhausted)?;
    if *metadata_bytes > MAX_TRAVERSAL_METADATA_BYTES {
        return Err(Error::MetadataExhausted);
    }
    entries
        .try_reserve(1)
        .map_err(|_| Error::MetadataExhausted)?;
    entries.push(entry);
    Ok(())
}

#[cfg(feature = "alloc")]
fn walk_no_follow(
    filesystem: &mut ReadOnlyFilesystem,
    root: &str,
) -> Result<Vec<WalkEntry>, Error> {
    let root_metadata = filesystem.metadata_no_follow(root)?;
    let root_path = owned(root)?;
    let mut entries = Vec::new();
    let mut metadata_bytes = 0_usize;
    push_walk(
        &mut entries,
        &mut metadata_bytes,
        WalkEntry {
            path: root_path,
            relative: String::new(),
            kind: root_metadata.kind,
        },
    )?;
    let mut pending = Vec::new();
    if root_metadata.kind == filesystem::NodeKind::Directory {
        pending
            .try_reserve(1)
            .map_err(|_| Error::MetadataExhausted)?;
        pending.push(0_usize);
    }

    while let Some(directory_index) = pending.pop() {
        let mut cursor = 0_u64;
        loop {
            let mut buffer = [0_u8; FILESYSTEM_LIST_BUFFER_BYTES];
            let page = filesystem.list(
                &entries[directory_index].path,
                cursor,
                filesystem::MAX_LIST_ENTRIES,
                filesystem::MAX_LIST_NAME_BYTES,
                &mut buffer,
            )?;
            let next_cursor = page.next_cursor();
            let mut retained = 0_usize;
            for entry in page.entries() {
                retained += 1;
                let path = join(&entries[directory_index].path, entry.name)?;
                let relative = if entries[directory_index].relative.is_empty() {
                    owned(entry.name)?
                } else {
                    join(&entries[directory_index].relative, entry.name)?
                };
                let next_index = entries.len();
                push_walk(
                    &mut entries,
                    &mut metadata_bytes,
                    WalkEntry {
                        path,
                        relative,
                        kind: entry.kind,
                    },
                )?;
                if entry.kind == filesystem::NodeKind::Directory {
                    pending
                        .try_reserve(1)
                        .map_err(|_| Error::MetadataExhausted)?;
                    pending.push(next_index);
                }
            }
            match next_cursor {
                None => break,
                Some(next) if next != cursor && retained != 0 => cursor = next,
                Some(_) => return Err(Error::Service(KexError::Corrupt)),
            }
        }
    }
    Ok(entries)
}

#[cfg(feature = "alloc")]
fn copy_regular_file(
    filesystem: &mut ReadOnlyFilesystem,
    mutation: &mut FilesystemMutation,
    source: &str,
    destination: &str,
) -> Result<(), Error> {
    let destination_is_new = match filesystem.metadata_no_follow(destination) {
        Ok(_) => false,
        Err(KexError::NotFound) => true,
        Err(error) => return Err(error.into()),
    };
    let file = filesystem.open(source)?;
    let mut replacement = match mutation.begin_replace(destination) {
        Ok(replacement) => replacement,
        Err(error) => {
            let _ignored = filesystem.close(file);
            return Err(error.into());
        }
    };
    let mut offset = 0_u64;
    let mut buffer = [0_u8; FILESYSTEM_IO_BUFFER_BYTES];
    loop {
        let count = match filesystem.read(file, offset, &mut buffer) {
            Ok(count) => count,
            Err(error) => {
                let _ignored = replacement.abort();
                let _ignored = filesystem.close(file);
                if destination_is_new {
                    let _ignored = mutation.remove(destination);
                }
                return Err(error.into());
            }
        };
        if count == 0 {
            break;
        }
        if let Err(error) = replacement.write_all(&buffer[..count]) {
            let _ignored = replacement.abort();
            let _ignored = filesystem.close(file);
            if destination_is_new {
                let _ignored = mutation.remove(destination);
            }
            return Err(error.into());
        }
        offset = offset
            .checked_add(u64::try_from(count).map_err(|_| Error::InvalidPath)?)
            .ok_or(Error::InvalidPath)?;
    }
    if let Err(error) = filesystem.close(file) {
        let _ignored = replacement.abort();
        if destination_is_new {
            let _ignored = mutation.remove(destination);
        }
        return Err(error.into());
    }
    if let Err(error) = replacement.commit() {
        if destination_is_new {
            let _ignored = mutation.remove(destination);
        }
        return Err(error.into());
    }
    Ok(())
}

#[cfg(feature = "alloc")]
fn copy_symlink(
    filesystem: &mut ReadOnlyFilesystem,
    mutation: &mut FilesystemMutation,
    source: &str,
    destination: &str,
) -> Result<(), Error> {
    let mut target = [0_u8; filesystem::MAX_LINK_BYTES];
    let target = filesystem.read_link(source, &mut target)?;
    match filesystem.metadata_no_follow(destination) {
        Ok(_) => return Err(Error::Service(KexError::Exists)),
        Err(KexError::NotFound) => {}
        Err(error) => return Err(error.into()),
    }
    mutation.create_symlink(target, destination)?;
    Ok(())
}

#[cfg(feature = "alloc")]
fn copy_node(
    filesystem: &mut ReadOnlyFilesystem,
    mutation: &mut FilesystemMutation,
    source: &str,
    destination: &str,
    kind: filesystem::NodeKind,
) -> Result<(), Error> {
    match kind {
        filesystem::NodeKind::File => copy_regular_file(filesystem, mutation, source, destination),
        filesystem::NodeKind::Symlink => copy_symlink(filesystem, mutation, source, destination),
        filesystem::NodeKind::Directory => Err(Error::Service(KexError::WrongType)),
    }
}

/// Copy one regular file or symbolic link without following the link.
///
/// # Errors
///
/// Rejects directories and reports all typed read, write, allocation, and
/// partial-I/O failures.
#[cfg(feature = "alloc")]
pub fn copy(
    filesystem: &mut ReadOnlyFilesystem,
    mutation: &mut FilesystemMutation,
    source: &str,
    destination: &str,
) -> Result<(), Error> {
    let target = destination_for_source(filesystem, source, destination)?;
    let metadata = filesystem.metadata_no_follow(source)?;
    copy_node(filesystem, mutation, source, &target, metadata.kind)
}

/// Copy a directory tree iteratively, reproducing symbolic links without following them.
///
/// # Errors
///
/// Reports typed filesystem failures, malformed paths, or traversal metadata
/// exhaustion. Already-created destinations can remain after a later I/O error.
#[cfg(feature = "alloc")]
pub fn copy_recursive(
    filesystem: &mut ReadOnlyFilesystem,
    mutation: &mut FilesystemMutation,
    source: &str,
    destination: &str,
) -> Result<(), Error> {
    let target = destination_for_source(filesystem, source, destination)?;
    let source_prefix = source.trim_end_matches('/');
    if target == source_prefix
        || target
            .strip_prefix(source_prefix)
            .is_some_and(|suffix| suffix.starts_with('/'))
    {
        return Err(Error::InvalidPath);
    }
    let entries = walk_no_follow(filesystem, source)?;
    if entries[0].kind != filesystem::NodeKind::Directory {
        return copy_node(filesystem, mutation, source, &target, entries[0].kind);
    }
    match filesystem.metadata_no_follow(&target) {
        Ok(metadata) if metadata.kind == filesystem::NodeKind::Directory => {}
        Ok(_) => return Err(Error::Service(KexError::WrongType)),
        Err(KexError::NotFound) => mutation.create_directory(&target)?,
        Err(error) => return Err(error.into()),
    }
    for entry in entries.iter().skip(1) {
        let destination = join_relative(&target, &entry.relative)?;
        match entry.kind {
            filesystem::NodeKind::Directory => match filesystem.metadata_no_follow(&destination) {
                Ok(metadata) if metadata.kind == filesystem::NodeKind::Directory => {}
                Ok(_) => return Err(Error::Service(KexError::WrongType)),
                Err(KexError::NotFound) => mutation.create_directory(&destination)?,
                Err(error) => return Err(error.into()),
            },
            kind => copy_node(filesystem, mutation, &entry.path, &destination, kind)?,
        }
    }
    Ok(())
}

/// Remove one file, symbolic link, or complete directory tree in post-order.
///
/// # Errors
///
/// Reports typed filesystem failures or traversal metadata exhaustion. Symbolic
/// links are removed as links and are never traversed.
#[cfg(feature = "alloc")]
pub fn remove_recursive(
    filesystem: &mut ReadOnlyFilesystem,
    mutation: &mut FilesystemMutation,
    path: &str,
) -> Result<(), Error> {
    let entries = walk_no_follow(filesystem, path)?;
    for entry in entries.iter().rev() {
        match entry.kind {
            filesystem::NodeKind::Directory => mutation.remove_directory(&entry.path)?,
            filesystem::NodeKind::File | filesystem::NodeKind::Symlink => {
                mutation.remove(&entry.path)?;
            }
        }
    }
    Ok(())
}

/// Move one object using only the kernel's atomic same-provider rename primitive.
///
/// Cross-provider moves fail explicitly with [`KexError::CrossDevice`].
///
/// # Errors
///
/// Reports destination resolution and rename failures.
#[cfg(feature = "alloc")]
pub fn move_path(
    filesystem: &mut ReadOnlyFilesystem,
    mutation: &mut FilesystemMutation,
    source: &str,
    destination: &str,
) -> Result<(), Error> {
    let target = destination_for_source(filesystem, source, destination)?;
    mutation.rename(source, &target)?;
    Ok(())
}

#[cfg(all(test, feature = "alloc"))]
mod tests {
    extern crate std;

    use super::{Error, MAX_TRAVERSAL_ENTRIES, WalkEntry, basename, join, push_walk};
    use alloc::{string::String, vec::Vec};
    use troe_kex_sdk::filesystem;

    #[test]
    fn path_helpers_reject_malformed_and_excessive_names() {
        assert_eq!(basename("/a/b/"), Some("b"));
        assert_eq!(basename("/"), None);
        assert_eq!(join("/a", "b").as_deref(), Ok("/a/b"));
        assert_eq!(join("/a", "../b"), Err(Error::InvalidPath));
        assert_eq!(join("/a", "bad\0name"), Err(Error::InvalidPath));
    }

    #[test]
    fn traversal_metadata_grows_past_legacy_table_sizes_then_hits_its_ceiling() {
        let mut entries = Vec::new();
        let mut bytes = 0;
        for index in 0..MAX_TRAVERSAL_ENTRIES {
            let path = std::format!("/n{index}");
            push_walk(
                &mut entries,
                &mut bytes,
                WalkEntry {
                    path,
                    relative: String::new(),
                    kind: filesystem::NodeKind::File,
                },
            )
            .unwrap_or_else(|_| std::process::abort());
        }
        assert!(entries.len() > 16);
        assert_eq!(
            push_walk(
                &mut entries,
                &mut bytes,
                WalkEntry {
                    path: "/overflow".into(),
                    relative: String::new(),
                    kind: filesystem::NodeKind::File,
                },
            ),
            Err(Error::MetadataExhausted)
        );
    }
}
