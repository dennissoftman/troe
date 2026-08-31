//! Immutable embedded KEFS v1 image reader and filesystem provider.
//!
//! The namespace previously parsed this format itself and copied every entry
//! into its own node map, which is why the embedded root was not a mountable
//! filesystem. The image is now parsed here and served through
//! [`FileSystemProvider`], so the namespace mounts it like any other provider.
//!
//! One image supplies several mounts. [`Kefs::into_mounts`] partitions it by
//! top-level directory and hands each partition its own provider. The caller
//! reserves the directories that later host their own mounts: a reserved
//! subtree is returned as plain directories and files for the namespace to
//! compose, because a provider mounted over such a directory would make every
//! mount beneath it a rejected nested mount.
#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;
#[cfg(test)]
extern crate std;

use alloc::collections::BTreeMap;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::str;
use troe_fs_api::{
    DirEntry, FileMetadata, FileSystemProvider, FsError, NodeKind, ProviderListing, canonicalize,
};

/// Product-name-independent KEFS v1 format identifier.
pub const KEFS_V1_MAGIC: [u8; 8] = *b"KEFSv1\0\0";
const KEFS_HEADER_LEN: usize = 16;

#[derive(Clone, Debug)]
enum Entry {
    Directory,
    File(Vec<u8>),
}

impl Entry {
    const fn kind(&self) -> NodeKind {
        match self {
            Self::Directory => NodeKind::Directory,
            Self::File(_) => NodeKind::File,
        }
    }
}

/// One validated KEFS v1 image.
#[derive(Debug)]
pub struct Kefs {
    entries: BTreeMap<String, Entry>,
}

impl Kefs {
    /// Validate a complete KEFS v1 image.
    ///
    /// # Errors
    ///
    /// Fails atomically if the magic, reserved bytes, declared length, entry
    /// kinds, path encoding, canonical form, strict ordering, or payload
    /// bounds are invalid.
    pub fn parse(image: &[u8]) -> Result<Self, FsError> {
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
        let mut entries = BTreeMap::new();
        for _ in 0..count {
            let kind = match *image.get(offset).ok_or(FsError::Invalid)? {
                1 => NodeKind::File,
                2 => NodeKind::Directory,
                _ => return Err(FsError::Invalid),
            };
            offset = offset.checked_add(1).ok_or(FsError::Overflow)?;
            let path_len = usize::from(read_u16(image, offset)?);
            offset = offset.checked_add(2).ok_or(FsError::Overflow)?;
            let data_len =
                usize::try_from(read_u32(image, offset)?).map_err(|_| FsError::Overflow)?;
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
            let entry = match kind {
                NodeKind::Directory => Entry::Directory,
                NodeKind::File => Entry::File(data.to_vec()),
                NodeKind::Symlink => return Err(FsError::Unsupported),
            };
            entries.insert(path, entry);
            offset = data_end;
        }
        if offset != image.len() {
            return Err(FsError::Invalid);
        }
        Ok(Self { entries })
    }

    /// Partition the image into one provider per top-level directory.
    ///
    /// `reserved` names directories that must stay owned by the namespace
    /// because the caller mounts its own providers beneath them. Every entry at
    /// or below a reserved path is returned for composition instead of being
    /// served by a provider. Files at the image root are always composed,
    /// because a provider attaches at a directory rather than at one file.
    #[must_use]
    pub fn into_mounts(self, reserved: &[&str]) -> EmbeddedRoot {
        let is_reserved = |path: &str| {
            reserved.iter().any(|root| {
                path == *root
                    || path
                        .strip_prefix(*root)
                        .is_some_and(|suffix| suffix.starts_with('/'))
            })
        };
        let mut views: BTreeMap<String, BTreeMap<String, Entry>> = BTreeMap::new();
        let mut directories = Vec::new();
        let mut files = Vec::new();
        for (path, entry) in self.entries {
            let Some(rest) = path.strip_prefix('/') else {
                continue;
            };
            if is_reserved(&path) {
                match entry {
                    Entry::Directory => directories.push(path),
                    Entry::File(bytes) => files.push((path, bytes)),
                }
                continue;
            }
            match rest.split_once('/') {
                None => match entry {
                    Entry::Directory => {
                        views.entry(path).or_default();
                    }
                    Entry::File(bytes) => files.push((path, bytes)),
                },
                Some((head, tail)) => {
                    let mut relative = String::from("/");
                    relative.push_str(tail);
                    let mut root = String::from("/");
                    root.push_str(head);
                    views.entry(root).or_default().insert(relative, entry);
                }
            }
        }
        EmbeddedRoot {
            mounts: views
                .into_iter()
                .map(|(root, entries)| (root, KefsView { entries }))
                .collect(),
            directories,
            files,
        }
    }
}

/// One image decomposed into the pieces a namespace can attach.
///
/// `directories` and `files` are in lexical order, so composing them in order
/// always creates a parent before its children.
#[derive(Debug)]
pub struct EmbeddedRoot {
    /// One provider per top-level directory, in lexical order.
    pub mounts: Vec<(String, KefsView)>,
    /// Directories the namespace owns: reserved mount roots and their subtrees.
    pub directories: Vec<String>,
    /// Files the namespace owns: image-root files and reserved subtree files.
    pub files: Vec<(String, Vec<u8>)>,
}

/// One immutable subtree of a KEFS image, addressed from its own root.
#[derive(Debug)]
pub struct KefsView {
    entries: BTreeMap<String, Entry>,
}

impl KefsView {
    fn entry(&self, path: &str) -> Option<&Entry> {
        if path == "/" {
            return Some(&Entry::Directory);
        }
        self.entries.get(path)
    }
}

impl FileSystemProvider for KefsView {
    fn metadata(&mut self, path: &str) -> Result<FileMetadata, FsError> {
        match self.entry(path) {
            Some(Entry::Directory) => Ok(FileMetadata {
                kind: NodeKind::Directory,
                byte_count: 0,
                modified_unix_seconds: None,
            }),
            Some(Entry::File(bytes)) => Ok(FileMetadata {
                kind: NodeKind::File,
                byte_count: bytes.len() as u64,
                modified_unix_seconds: None,
            }),
            None => Err(FsError::NotFound),
        }
    }

    fn read_file(
        &mut self,
        path: &str,
        offset: u64,
        destination: &mut [u8],
    ) -> Result<usize, FsError> {
        let bytes = match self.entry(path) {
            Some(Entry::File(bytes)) => bytes,
            Some(Entry::Directory) => return Err(FsError::WrongType),
            None => return Err(FsError::NotFound),
        };
        let start = usize::try_from(offset).map_err(|_| FsError::Invalid)?;
        if start >= bytes.len() || destination.is_empty() {
            return Ok(0);
        }
        let available = bytes.len().checked_sub(start).ok_or(FsError::Overflow)?;
        let count = available.min(destination.len());
        destination[..count].copy_from_slice(&bytes[start..start + count]);
        Ok(count)
    }

    fn list(
        &mut self,
        path: &str,
        cursor: u64,
        max_entries: usize,
        max_name_bytes: usize,
    ) -> Result<ProviderListing, FsError> {
        match self.entry(path) {
            Some(Entry::Directory) => {}
            Some(Entry::File(_)) => return Err(FsError::WrongType),
            None => return Err(FsError::NotFound),
        }
        let start = usize::try_from(cursor).map_err(|_| FsError::Invalid)?;
        let prefix = if path == "/" {
            "/".to_string()
        } else {
            let mut prefix = path.to_string();
            prefix.push('/');
            prefix
        };
        let mut entries = Vec::new();
        entries
            .try_reserve_exact(max_entries)
            .map_err(|_| FsError::NoSpace)?;
        let mut child_index = 0_usize;
        let mut retained_bytes = 0_usize;
        for (candidate, entry) in self.entries.range(prefix.clone()..) {
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
                kind: entry.kind(),
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
    use alloc::vec;
    use alloc::vec::Vec;
    use troe_fs_api::{FileSystemProvider, FsError, NodeKind};

    use super::{KEFS_V1_MAGIC, Kefs};

    fn image(entries: &[(u8, &[u8], &[u8])]) -> Vec<u8> {
        let mut image = vec![0_u8; 16];
        image[..8].copy_from_slice(&KEFS_V1_MAGIC);
        image[8..10].copy_from_slice(&u16::try_from(entries.len()).unwrap_or(0).to_le_bytes());
        for (kind, path, data) in entries {
            image.push(*kind);
            image.extend_from_slice(&u16::try_from(path.len()).unwrap_or(0).to_le_bytes());
            image.extend_from_slice(&u32::try_from(data.len()).unwrap_or(0).to_le_bytes());
            image.extend_from_slice(path);
            image.extend_from_slice(data);
        }
        let length = u32::try_from(image.len()).unwrap_or(0);
        image[12..16].copy_from_slice(&length.to_le_bytes());
        image
    }

    #[test]
    fn format_identifier_is_product_name_independent() {
        assert_eq!(KEFS_V1_MAGIC, *b"KEFSv1\0\0");
    }

    #[test]
    fn corrupt_image_is_rejected_whole() {
        let mut truncated = vec![0_u8; 16];
        truncated[..8].copy_from_slice(&KEFS_V1_MAGIC);
        truncated[8..10].copy_from_slice(&1_u16.to_le_bytes());
        truncated[12..16].copy_from_slice(&16_u32.to_le_bytes());
        assert_eq!(Kefs::parse(&truncated).err(), Some(FsError::Invalid));

        let mut wrong_magic = image(&[(2, b"/bin", b"")]);
        wrong_magic[0] = b'X';
        assert_eq!(Kefs::parse(&wrong_magic).err(), Some(FsError::Invalid));

        let unordered = image(&[(2, b"/man", b""), (2, b"/bin", b"")]);
        assert_eq!(Kefs::parse(&unordered).err(), Some(FsError::Invalid));

        let directory_payload = image(&[(2, b"/bin", b"data")]);
        assert_eq!(
            Kefs::parse(&directory_payload).err(),
            Some(FsError::Invalid)
        );
    }

    #[test]
    fn one_image_becomes_one_mount_per_top_level_directory() {
        let bytes = image(&[
            (1, b"/README", b"root file"),
            (2, b"/bin", b""),
            (1, b"/bin/ls", b"ls"),
            (2, b"/vol", b""),
            (2, b"/vol/boot", b""),
        ]);
        let Ok(parsed) = Kefs::parse(&bytes) else {
            unreachable!("the image is well formed")
        };
        let root = parsed.into_mounts(&[]);
        let paths: Vec<&str> = root.mounts.iter().map(|(path, _)| path.as_str()).collect();
        assert_eq!(paths, vec!["/bin", "/vol"]);
        assert_eq!(root.files, vec![("/README".into(), b"root file".to_vec())]);

        let (_, mut bin) = root
            .mounts
            .into_iter()
            .next()
            .unwrap_or_else(|| unreachable!());
        assert_eq!(
            bin.metadata("/").map(|metadata| metadata.kind),
            Ok(NodeKind::Directory)
        );
        let mut buffer = [0_u8; 2];
        assert_eq!(bin.read_file("/ls", 0, &mut buffer), Ok(2));
        assert_eq!(&buffer, b"ls");
        assert_eq!(bin.metadata("/absent").err(), Some(FsError::NotFound));
    }

    #[test]
    fn listing_is_shallow_lexical_and_bounded() {
        let bytes = image(&[
            (2, b"/bin", b""),
            (1, b"/bin/a", b""),
            (2, b"/bin/sub", b""),
            (1, b"/bin/sub/deep", b""),
            (1, b"/bin/z", b""),
        ]);
        let Ok(parsed) = Kefs::parse(&bytes) else {
            unreachable!("the image is well formed")
        };
        let (_, mut bin) = parsed
            .into_mounts(&[])
            .mounts
            .into_iter()
            .next()
            .unwrap_or_else(|| unreachable!());
        let Ok(page) = bin.list("/", 0, 2, 64) else {
            unreachable!("the root is a directory")
        };
        let names: Vec<&str> = page
            .entries
            .iter()
            .map(|entry| entry.name.as_str())
            .collect();
        assert_eq!(names, vec!["a", "sub"]);
        assert_eq!(page.next_cursor, Some(2));
        let Ok(rest) = bin.list("/", 2, 8, 64) else {
            unreachable!("the cursor came from this provider")
        };
        let names: Vec<&str> = rest
            .entries
            .iter()
            .map(|entry| entry.name.as_str())
            .collect();
        assert_eq!(names, vec!["z"]);
        assert_eq!(rest.next_cursor, None);
        assert_eq!(bin.list("/a", 0, 8, 64).err(), Some(FsError::WrongType));
    }

    #[test]
    fn a_reserved_root_is_composed_rather_than_mounted() {
        // /vol ships a file and two empty directories, and the boot manifest
        // mounts volumes beneath it. If it became a provider mount, every one
        // of those volume mounts would be a rejected nested mount.
        let bytes = image(&[
            (2, b"/bin", b""),
            (1, b"/bin/ls", b"ls"),
            (2, b"/vol", b""),
            (1, b"/vol/README", b"readme"),
            (2, b"/vol/boot", b""),
            (2, b"/vol/root", b""),
        ]);
        let Ok(parsed) = Kefs::parse(&bytes) else {
            unreachable!("the image is well formed")
        };
        let root = parsed.into_mounts(&["/vol"]);
        let mounts: Vec<&str> = root.mounts.iter().map(|(path, _)| path.as_str()).collect();
        assert_eq!(mounts, vec!["/bin"]);
        assert_eq!(root.directories, vec!["/vol", "/vol/boot", "/vol/root"]);
        assert_eq!(root.files, vec![("/vol/README".into(), b"readme".to_vec())]);
        // Parents precede their children, so composing in order always works.
        let mut sorted = root.directories.clone();
        sorted.sort();
        assert_eq!(sorted, root.directories);
    }

    #[test]
    fn the_image_is_immutable() {
        let bytes = image(&[(2, b"/bin", b""), (1, b"/bin/ls", b"ls")]);
        let Ok(parsed) = Kefs::parse(&bytes) else {
            unreachable!("the image is well formed")
        };
        let (_, mut bin) = parsed
            .into_mounts(&[])
            .mounts
            .into_iter()
            .next()
            .unwrap_or_else(|| unreachable!());
        assert_eq!(bin.truncate_file("/ls").err(), Some(FsError::ReadOnly));
        assert_eq!(bin.remove_file("/ls").err(), Some(FsError::ReadOnly));
        assert_eq!(bin.create_directory("/new").err(), Some(FsError::ReadOnly));
        assert_eq!(bin.read_link("/ls").err(), Some(FsError::Unsupported));
    }
}
