//! Portable virtual namespace with immutable and quota-bound writable nodes.
#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;

use alloc::collections::BTreeMap;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::{fmt, str};
use kllm_core::MemoryStats;

/// Maximum encoded path length.
pub const MAX_PATH_BYTES: usize = 256;
/// Maximum single path component length.
pub const MAX_NAME_BYTES: usize = 64;
/// Maximum normalized path depth.
pub const MAX_PATH_DEPTH: usize = 16;
const KEFS_MAGIC: &[u8; 8] = b"KLLMFS1\0";
const KEFS_HEADER_LEN: usize = 16;

/// Node kind visible through the namespace.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NodeKind {
    /// Directory node.
    Directory,
    /// Regular byte file.
    File,
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
        }
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

impl Default for RamFsQuota {
    fn default() -> Self {
        Self {
            max_bytes: 1024 * 1024,
            max_nodes: 128,
            max_file_bytes: 64 * 1024,
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

/// Unified immutable-root and writable-RAM namespace.
#[derive(Clone, Debug)]
pub struct Namespace {
    nodes: BTreeMap<String, Node>,
    quota: RamFsQuota,
    ramfs_bytes: usize,
    ramfs_nodes: usize,
    ramfs_high_water: usize,
}

impl Namespace {
    /// Create the fixed root skeleton.
    #[must_use]
    pub fn new(quota: RamFsQuota) -> Self {
        let mut nodes = BTreeMap::new();
        nodes.insert("/".to_string(), Node::Directory);
        nodes.insert("/tmp".to_string(), Node::Directory);
        nodes.insert("/sys".to_string(), Node::Directory);
        Self {
            nodes,
            quota,
            ramfs_bytes: 0,
            ramfs_nodes: 0,
            ramfs_high_water: 0,
        }
    }

    /// Insert an immutable directory while composing the initial namespace.
    ///
    /// # Errors
    ///
    /// Fails for an invalid, duplicate, root, or parentless path.
    pub fn add_read_only_dir(&mut self, path: &str) -> Result<(), FsError> {
        let path = canonicalize("/", path)?;
        self.insert_composed(path, Node::Directory)
    }

    /// Insert an immutable file while composing the initial namespace.
    ///
    /// # Errors
    ///
    /// Fails for an invalid, duplicate, root, or parentless path.
    pub fn add_read_only_file(&mut self, path: &str, bytes: &[u8]) -> Result<(), FsError> {
        let path = canonicalize("/", path)?;
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
        if !path.starts_with("/sys/") {
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
        if path == "/" || self.nodes.contains_key(&path) {
            return Err(FsError::Exists);
        }
        let parent = parent_path(&path).ok_or(FsError::Invalid)?;
        if !matches!(self.nodes.get(parent), Some(Node::Directory)) {
            return Err(FsError::NotFound);
        }
        self.nodes.insert(path, node);
        Ok(())
    }

    /// Validate and mount a deterministic KEFS v1 image.
    ///
    /// # Errors
    ///
    /// Fails atomically if metadata, bounds, ordering, paths, or parents are invalid.
    pub fn mount_embedded(&mut self, image: &[u8]) -> Result<(), FsError> {
        let parsed = parse_embedded(image)?;
        let mut staged = self.clone();
        for entry in parsed {
            match entry.kind {
                NodeKind::Directory => staged.add_read_only_dir(&entry.path)?,
                NodeKind::File => staged.add_read_only_file(&entry.path, &entry.data)?,
            }
        }
        *self = staged;
        Ok(())
    }

    /// Resolve and read a complete file.
    ///
    /// # Errors
    ///
    /// Fails if the path is invalid, missing, or not a file.
    pub fn read_file<'a>(&'a self, cwd: &str, path: &str) -> Result<&'a [u8], FsError> {
        let path = canonicalize(cwd, path)?;
        match self.nodes.get(&path) {
            Some(Node::File { bytes, .. }) => Ok(bytes),
            Some(Node::Directory) => Err(FsError::WrongType),
            None => Err(FsError::NotFound),
        }
    }

    /// Create or replace a RAMFS file. Each call is atomic with respect to quotas.
    ///
    /// # Errors
    ///
    /// Fails for invalid paths, immutable targets, missing parents, or quota exhaustion.
    pub fn write_file(&mut self, cwd: &str, path: &str, bytes: &[u8]) -> Result<(), FsError> {
        let path = canonicalize(cwd, path)?;
        if !is_under_tmp(&path) {
            return Err(FsError::ReadOnly);
        }
        if bytes.len() > self.quota.max_file_bytes {
            return Err(FsError::NoSpace);
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
        let new_total = without_old
            .checked_add(bytes.len())
            .ok_or(FsError::Overflow)?;
        if new_total > self.quota.max_bytes {
            return Err(FsError::NoSpace);
        }

        self.nodes.insert(
            path,
            Node::File {
                bytes: bytes.to_vec(),
                writable: true,
            },
        );
        self.ramfs_bytes = new_total;
        if is_new {
            self.ramfs_nodes += 1;
        }
        self.ramfs_high_water = self.ramfs_high_water.max(new_total);
        Ok(())
    }

    /// Delete a writable file and release its complete quota charge.
    ///
    /// # Errors
    ///
    /// Fails if the path is invalid, missing, immutable, or not a file.
    pub fn remove_file(&mut self, cwd: &str, path: &str) -> Result<(), FsError> {
        let path = canonicalize(cwd, path)?;
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
        Ok(())
    }

    /// List immediate children in lexical order.
    ///
    /// # Errors
    ///
    /// Fails if the path is invalid, missing, or not a directory.
    pub fn list(&self, cwd: &str, path: &str) -> Result<Vec<DirEntry>, FsError> {
        let path = canonicalize(cwd, path)?;
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

    /// Resolve a path and require it to be a directory.
    ///
    /// # Errors
    ///
    /// Fails if the path is invalid, missing, or not a directory.
    pub fn resolve_dir(&self, cwd: &str, path: &str) -> Result<String, FsError> {
        let path = canonicalize(cwd, path)?;
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

#[derive(Debug)]
struct EmbeddedEntry {
    path: String,
    kind: NodeKind,
    data: Vec<u8>,
}

fn parse_embedded(image: &[u8]) -> Result<Vec<EmbeddedEntry>, FsError> {
    if image.len() < KEFS_HEADER_LEN
        || &image[..8] != KEFS_MAGIC
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
    use super::{FsError, Namespace, NodeKind, RamFsQuota, canonicalize};
    use alloc::vec;

    #[test]
    fn paths_are_bounded_and_cannot_escape_root() {
        assert_eq!(canonicalize("/a/b", "../../../../c"), Ok("/c".into()));
        assert_eq!(canonicalize("/", "//a/./b/../c"), Ok("/a/c".into()));
        assert_eq!(canonicalize("/", "bad\0name"), Err(FsError::Invalid));
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
    fn corrupt_embedded_image_is_rejected_without_partial_mount() {
        let mut image = vec![0_u8; 16];
        image[..8].copy_from_slice(b"KLLMFS1\0");
        image[8..10].copy_from_slice(&1_u16.to_le_bytes());
        image[12..16].copy_from_slice(&16_u32.to_le_bytes());
        let mut fs = Namespace::new(RamFsQuota::default());
        assert_eq!(fs.mount_embedded(&image), Err(FsError::Invalid));
        assert!(fs.list("/", "/").is_ok());
    }
}
