//! Quota-bound writable in-memory filesystem provider.
//!
//! The namespace previously kept this filesystem inline, sharing one node map
//! with immutable content and telling the two apart with a per-file flag. It is
//! now an ordinary [`FileSystemProvider`] so the namespace holds mounts and
//! nothing else.
//!
//! Paths are absolute within the provider root. The root itself is immutable
//! and is not charged to the node quota, matching the mount point the namespace
//! creates for it.
#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;
#[cfg(test)]
extern crate std;

use alloc::collections::BTreeMap;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use troe_fs_api::{
    DirEntry, FileMetadata, FileSystemProvider, FsError, NodeKind, ProviderListing, ProviderUsage,
};

/// Explicit limits for one writable in-memory filesystem.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RamFsQuota {
    /// Maximum total file payload bytes.
    pub max_bytes: usize,
    /// Maximum writable node count, counting files and directories.
    pub max_nodes: usize,
    /// Maximum payload bytes in one file.
    pub max_file_bytes: usize,
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

#[derive(Clone, Debug)]
enum Node {
    Directory,
    File(Vec<u8>),
}

impl Node {
    const fn kind(&self) -> NodeKind {
        match self {
            Self::Directory => NodeKind::Directory,
            Self::File(_) => NodeKind::File,
        }
    }
}

/// One writable in-memory filesystem bounded by an immutable quota.
#[derive(Debug)]
pub struct RamFs {
    nodes: BTreeMap<String, Node>,
    quota: RamFsQuota,
    bytes: usize,
    charged_nodes: usize,
    high_water: usize,
}

impl RamFs {
    /// Create an empty filesystem containing only its immutable root.
    #[must_use]
    pub fn new(quota: RamFsQuota) -> Self {
        let mut nodes = BTreeMap::new();
        nodes.insert("/".to_string(), Node::Directory);
        Self {
            nodes,
            quota,
            bytes: 0,
            charged_nodes: 0,
            high_water: 0,
        }
    }

    /// The root is immutable, so every mutation rejects it before any lookup.
    fn writable_target(path: &str) -> Result<&str, FsError> {
        if path == "/" {
            return Err(FsError::ReadOnly);
        }
        Ok(path)
    }

    fn parent_is_directory(&self, path: &str) -> Result<(), FsError> {
        let parent = parent_path(path).ok_or(FsError::Invalid)?;
        if matches!(self.nodes.get(parent), Some(Node::Directory)) {
            Ok(())
        } else {
            Err(FsError::NotFound)
        }
    }
}

impl FileSystemProvider for RamFs {
    fn usage(&self) -> Option<ProviderUsage> {
        Some(ProviderUsage {
            used_bytes: self.bytes as u64,
            limit_bytes: self.quota.max_bytes as u64,
            high_water_bytes: self.high_water as u64,
        })
    }

    fn metadata(&mut self, path: &str) -> Result<FileMetadata, FsError> {
        match self.nodes.get(path) {
            Some(Node::Directory) => Ok(FileMetadata {
                kind: NodeKind::Directory,
                byte_count: 0,
                modified_unix_seconds: None,
            }),
            Some(Node::File(bytes)) => Ok(FileMetadata {
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
        let bytes = match self.nodes.get(path) {
            Some(Node::File(bytes)) => bytes,
            Some(Node::Directory) => return Err(FsError::WrongType),
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
        match self.nodes.get(path) {
            Some(Node::Directory) => {}
            Some(Node::File(_)) => return Err(FsError::WrongType),
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

    fn truncate_file(&mut self, path: &str) -> Result<(), FsError> {
        let path = Self::writable_target(path)?;
        self.parent_is_directory(path)?;
        let old_len = match self.nodes.get(path) {
            Some(Node::File(bytes)) => bytes.len(),
            Some(Node::Directory) => return Err(FsError::WrongType),
            None => 0,
        };
        let is_new = !self.nodes.contains_key(path);
        if is_new && self.charged_nodes >= self.quota.max_nodes {
            return Err(FsError::NoSpace);
        }
        let without_old = self.bytes.checked_sub(old_len).ok_or(FsError::Overflow)?;
        self.nodes.insert(path.to_string(), Node::File(Vec::new()));
        self.bytes = without_old;
        if is_new {
            self.charged_nodes += 1;
        }
        Ok(())
    }

    fn append_file(&mut self, path: &str, bytes: &[u8]) -> Result<(), FsError> {
        if bytes.is_empty() {
            return Ok(());
        }
        let path = Self::writable_target(path)?;
        let current_len = match self.nodes.get(path) {
            Some(Node::File(existing)) => existing.len(),
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
            .bytes
            .checked_add(bytes.len())
            .ok_or(FsError::Overflow)?;
        if next_total > self.quota.max_bytes {
            return Err(FsError::NoSpace);
        }
        let Some(Node::File(destination)) = self.nodes.get_mut(path) else {
            return Err(FsError::Corrupt);
        };
        destination
            .try_reserve_exact(bytes.len())
            .map_err(|_| FsError::NoSpace)?;
        destination.extend_from_slice(bytes);
        self.bytes = next_total;
        self.high_water = self.high_water.max(next_total);
        Ok(())
    }

    fn sync_file(&mut self, path: &str) -> Result<(), FsError> {
        match self.nodes.get(path) {
            Some(Node::File(_)) => Ok(()),
            Some(Node::Directory) => Err(FsError::WrongType),
            None => Err(FsError::NotFound),
        }
    }

    fn create_directory(&mut self, path: &str) -> Result<(), FsError> {
        let path = Self::writable_target(path)?;
        if self.nodes.contains_key(path) {
            return Err(FsError::Exists);
        }
        if self.charged_nodes >= self.quota.max_nodes {
            return Err(FsError::NoSpace);
        }
        self.parent_is_directory(path)?;
        self.nodes.insert(path.to_string(), Node::Directory);
        self.charged_nodes = self.charged_nodes.checked_add(1).ok_or(FsError::Overflow)?;
        Ok(())
    }

    fn remove_file(&mut self, path: &str) -> Result<(), FsError> {
        let path = Self::writable_target(path)?;
        match self.nodes.get(path) {
            Some(Node::File(bytes)) => {
                self.bytes = self
                    .bytes
                    .checked_sub(bytes.len())
                    .ok_or(FsError::Overflow)?;
                self.charged_nodes = self.charged_nodes.checked_sub(1).ok_or(FsError::Overflow)?;
            }
            Some(Node::Directory) => return Err(FsError::WrongType),
            None => return Err(FsError::NotFound),
        }
        self.nodes.remove(path);
        Ok(())
    }

    fn remove_directory(&mut self, path: &str) -> Result<(), FsError> {
        let path = Self::writable_target(path)?;
        match self.nodes.get(path) {
            Some(Node::Directory) => {}
            Some(Node::File(_)) => return Err(FsError::WrongType),
            None => return Err(FsError::NotFound),
        }
        let mut prefix = path.to_string();
        prefix.push('/');
        if self
            .nodes
            .range(prefix.clone()..)
            .next()
            .is_some_and(|(candidate, _)| candidate.starts_with(&prefix))
        {
            return Err(FsError::NotEmpty);
        }
        self.nodes.remove(path);
        self.charged_nodes = self.charged_nodes.checked_sub(1).ok_or(FsError::Overflow)?;
        Ok(())
    }

    fn rename(&mut self, source: &str, destination: &str) -> Result<(), FsError> {
        let source = Self::writable_target(source)?;
        let destination = Self::writable_target(destination)?;
        if source == destination {
            return Ok(());
        }
        if !self.nodes.contains_key(source) {
            return Err(FsError::NotFound);
        }
        if self.nodes.contains_key(destination) {
            return Err(FsError::Exists);
        }
        self.parent_is_directory(destination)?;
        let mut descent = source.to_string();
        descent.push('/');
        if destination.starts_with(&descent) {
            return Err(FsError::Invalid);
        }
        let moved: Vec<String> = self
            .nodes
            .range(descent.clone()..)
            .take_while(|(candidate, _)| candidate.starts_with(&descent))
            .map(|(candidate, _)| candidate.clone())
            .collect();
        let node = self.nodes.remove(source).ok_or(FsError::Corrupt)?;
        self.nodes.insert(destination.to_string(), node);
        for candidate in moved {
            let node = self.nodes.remove(&candidate).ok_or(FsError::Corrupt)?;
            let mut renamed = destination.to_string();
            renamed.push_str(&candidate[source.len()..]);
            self.nodes.insert(renamed, node);
        }
        Ok(())
    }

    /// This filesystem has no links, matching the namespace behavior it replaces.
    fn read_link(&mut self, _path: &str) -> Result<String, FsError> {
        Err(FsError::Unsupported)
    }

    /// This filesystem has no links, matching the namespace behavior it replaces.
    fn create_symlink(&mut self, _target: &str, _link_path: &str) -> Result<(), FsError> {
        Err(FsError::Unsupported)
    }

    /// This filesystem has no links, matching the namespace behavior it replaces.
    fn create_hard_link(&mut self, _existing: &str, _new_path: &str) -> Result<(), FsError> {
        Err(FsError::Unsupported)
    }
}

fn parent_path(path: &str) -> Option<&str> {
    let index = path.rfind('/')?;
    Some(if index == 0 { "/" } else { &path[..index] })
}
