//! Bounded crash-consistent single-file persistent filesystem.
#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;
#[cfg(test)]
extern crate std;

use alloc::string::String;
use alloc::{vec, vec::Vec};
use troe_block::{BlockDevice, BlockRegion};
use troe_persist::{DualSlotStore, PersistError};
use troe_vfs::{DirEntry, FileMetadata, FsError, NodeKind, ProviderListing, ReadOnlyFileSystem};

/// Product-independent state-filesystem image identifier.
pub const STATEFS_MAGIC: [u8; 8] = *b"STFSv1\0\0";
/// The only mutable file exposed by the initial profile.
pub const STATE_PATH: &str = "/state.bin";
const HEADER_BYTES: usize = 32;
const CHECKSUM_OFFSET: usize = 20;
const PRESENT: u16 = 1;

/// One mounted state filesystem owning an exact dual-slot region.
pub struct StateFs<D: BlockDevice> {
    store: DualSlotStore<D>,
    bytes: Option<Vec<u8>>,
    pending: Option<Vec<u8>>,
}

impl<D: BlockDevice> core::fmt::Debug for StateFs<D> {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("StateFs")
            .field("generation", &self.store.generation())
            .field("file_bytes", &self.bytes.as_ref().map(Vec::len))
            .finish_non_exhaustive()
    }
}

impl<D: BlockDevice> StateFs<D> {
    /// Recover a filesystem from the newest fully committed slot.
    ///
    /// # Errors
    ///
    /// Rejects unsuitable authority/geometry, corrupt committed filesystem
    /// images, bounded allocation failure, and block transport failures.
    pub fn mount(region: BlockRegion<D>) -> Result<Self, FsError> {
        let store = DualSlotStore::open(region).map_err(map_persist)?;
        let bytes = store.payload().map(parse_image).transpose()?.flatten();
        Ok(Self {
            store,
            bytes,
            pending: None,
        })
    }

    /// Newest committed filesystem transaction generation.
    #[must_use]
    pub fn generation(&self) -> u64 {
        self.store.generation()
    }

    /// Exact maximum payload for `/state.bin` on this device.
    #[must_use]
    pub fn max_file_bytes(&self) -> usize {
        self.store.max_payload_bytes().saturating_sub(HEADER_BYTES)
    }

    fn commit(&mut self, bytes: Option<&[u8]>) -> Result<(), FsError> {
        if bytes.is_some_and(|value| value.len() > self.max_file_bytes()) {
            return Err(FsError::NoSpace);
        }
        let image = encode_image(bytes)?;
        self.store.commit(&image).map_err(map_persist)?;
        self.bytes = bytes.map(<[u8]>::to_vec);
        Ok(())
    }
}

impl<D: BlockDevice> ReadOnlyFileSystem for StateFs<D> {
    fn metadata(&mut self, path: &str) -> Result<FileMetadata, FsError> {
        match path {
            "/" => Ok(FileMetadata {
                kind: NodeKind::Directory,
                byte_count: 0,
            }),
            STATE_PATH => self.bytes.as_ref().map_or(Err(FsError::NotFound), |bytes| {
                Ok(FileMetadata {
                    kind: NodeKind::File,
                    byte_count: u64::try_from(bytes.len()).map_err(|_| FsError::Overflow)?,
                })
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
        if path != STATE_PATH {
            return Err(if path == "/" {
                FsError::WrongType
            } else {
                FsError::NotFound
            });
        }
        let bytes = self.bytes.as_ref().ok_or(FsError::NotFound)?;
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
        path: &str,
        cursor: u64,
        max_entries: usize,
        max_name_bytes: usize,
    ) -> Result<ProviderListing, FsError> {
        if path != "/" {
            return Err(if path == STATE_PATH {
                FsError::WrongType
            } else {
                FsError::NotFound
            });
        }
        if cursor > 1 {
            return Err(FsError::Invalid);
        }
        if self.bytes.is_none() || cursor == 1 {
            return Ok(ProviderListing {
                entries: Vec::new(),
                next_cursor: None,
            });
        }
        if max_entries == 0 || max_name_bytes < "state.bin".len() {
            return Ok(ProviderListing {
                entries: Vec::new(),
                next_cursor: Some(1),
            });
        }
        Ok(ProviderListing {
            entries: vec![DirEntry {
                name: String::from("state.bin"),
                kind: NodeKind::File,
            }],
            next_cursor: None,
        })
    }

    fn write_file(&mut self, path: &str, bytes: &[u8]) -> Result<(), FsError> {
        if path != STATE_PATH {
            return Err(if path == "/" {
                FsError::WrongType
            } else {
                FsError::ReadOnly
            });
        }
        self.pending = None;
        self.commit(Some(bytes))
    }

    fn truncate_file(&mut self, path: &str) -> Result<(), FsError> {
        if path != STATE_PATH {
            return Err(if path == "/" {
                FsError::WrongType
            } else {
                FsError::ReadOnly
            });
        }
        self.pending = Some(Vec::new());
        Ok(())
    }

    fn append_file(&mut self, path: &str, bytes: &[u8]) -> Result<(), FsError> {
        if path != STATE_PATH {
            return Err(FsError::ReadOnly);
        }
        let maximum = self.max_file_bytes();
        if self.pending.is_none() {
            self.pending = Some(self.bytes.clone().unwrap_or_default());
        }
        let pending = self.pending.as_mut().ok_or(FsError::Invalid)?;
        let next = pending
            .len()
            .checked_add(bytes.len())
            .ok_or(FsError::Overflow)?;
        if next > maximum {
            return Err(FsError::NoSpace);
        }
        pending
            .try_reserve_exact(bytes.len())
            .map_err(|_| FsError::NoSpace)?;
        pending.extend_from_slice(bytes);
        Ok(())
    }

    fn sync_file(&mut self, path: &str) -> Result<(), FsError> {
        if path != STATE_PATH {
            return Err(FsError::ReadOnly);
        }
        let Some(pending) = self.pending.take() else {
            return Ok(());
        };
        self.commit(Some(&pending))
    }

    fn remove_file(&mut self, path: &str) -> Result<(), FsError> {
        if path != STATE_PATH {
            return Err(if path == "/" {
                FsError::WrongType
            } else {
                FsError::ReadOnly
            });
        }
        self.pending = None;
        if self.bytes.is_none() {
            return Err(FsError::NotFound);
        }
        self.commit(None)
    }

    fn remove_directory(&mut self, _path: &str) -> Result<(), FsError> {
        Err(FsError::Unsupported)
    }

    fn rename(&mut self, _source: &str, _destination: &str) -> Result<(), FsError> {
        Err(FsError::Unsupported)
    }
}

fn encode_image(bytes: Option<&[u8]>) -> Result<Vec<u8>, FsError> {
    let length = bytes.map_or(0, <[u8]>::len);
    let total = HEADER_BYTES.checked_add(length).ok_or(FsError::Overflow)?;
    let mut image = Vec::new();
    image
        .try_reserve_exact(total)
        .map_err(|_| FsError::NoSpace)?;
    image.resize(total, 0);
    image[..8].copy_from_slice(&STATEFS_MAGIC);
    image[8..10].copy_from_slice(&1_u16.to_le_bytes());
    image[12..14].copy_from_slice(&32_u16.to_le_bytes());
    if bytes.is_some() {
        image[14..16].copy_from_slice(&PRESENT.to_le_bytes());
    }
    image[16..20].copy_from_slice(
        &u32::try_from(length)
            .map_err(|_| FsError::NoSpace)?
            .to_le_bytes(),
    );
    if let Some(bytes) = bytes {
        image[HEADER_BYTES..].copy_from_slice(bytes);
    }
    let checksum = crc32_zeroed(&image);
    image[CHECKSUM_OFFSET..CHECKSUM_OFFSET + 4].copy_from_slice(&checksum.to_le_bytes());
    Ok(image)
}

fn parse_image(image: &[u8]) -> Result<Option<Vec<u8>>, FsError> {
    if image.len() < HEADER_BYTES
        || image.get(..8) != Some(&STATEFS_MAGIC)
        || read_u16(image, 8)? != 1
        || read_u16(image, 10)? != 0
        || read_u16(image, 12)? != 32
        || image[24..HEADER_BYTES].iter().any(|byte| *byte != 0)
        || crc32_zeroed(image) != read_u32(image, CHECKSUM_OFFSET)?
    {
        return Err(FsError::Corrupt);
    }
    let flags = read_u16(image, 14)?;
    let length = usize::try_from(read_u32(image, 16)?).map_err(|_| FsError::Corrupt)?;
    if flags & !PRESENT != 0
        || HEADER_BYTES.checked_add(length) != Some(image.len())
        || (flags & PRESENT == 0 && length != 0)
    {
        return Err(FsError::Corrupt);
    }
    Ok((flags & PRESENT != 0).then(|| image[HEADER_BYTES..].to_vec()))
}

fn read_u16(bytes: &[u8], offset: usize) -> Result<u16, FsError> {
    let raw = bytes.get(offset..offset + 2).ok_or(FsError::Corrupt)?;
    Ok(u16::from_le_bytes([raw[0], raw[1]]))
}

fn read_u32(bytes: &[u8], offset: usize) -> Result<u32, FsError> {
    let raw = bytes.get(offset..offset + 4).ok_or(FsError::Corrupt)?;
    Ok(u32::from_le_bytes([raw[0], raw[1], raw[2], raw[3]]))
}

fn crc32_zeroed(bytes: &[u8]) -> u32 {
    let mut crc = u32::MAX;
    for (index, byte) in bytes.iter().copied().enumerate() {
        let byte = if (CHECKSUM_OFFSET..CHECKSUM_OFFSET + 4).contains(&index) {
            0
        } else {
            byte
        };
        crc ^= u32::from(byte);
        for _ in 0..8 {
            crc = (crc >> 1) ^ (0xedb8_8320 & 0_u32.wrapping_sub(crc & 1));
        }
    }
    !crc
}

fn map_persist(error: PersistError) -> FsError {
    match error {
        PersistError::PayloadTooLarge | PersistError::MetadataExhausted => FsError::NoSpace,
        PersistError::Corrupt => FsError::Corrupt,
        PersistError::UnsupportedRegion | PersistError::GenerationExhausted => FsError::Unsupported,
        PersistError::Block(_) => FsError::Io,
    }
}

#[cfg(test)]
mod tests {
    use alloc::{boxed::Box, rc::Rc, vec, vec::Vec};
    use core::cell::RefCell;

    use super::{STATE_PATH, StateFs};
    use troe_block::{
        BlockAccess, BlockDevice, BlockError, BlockGeometry, BlockLimits, BlockRegion,
    };
    use troe_persist::DualSlotStore;
    use troe_vfs::{FsError, Namespace, RamFsQuota, ReadOnlyFileSystem};

    #[derive(Clone)]
    struct MemoryDevice(Rc<RefCell<Vec<u8>>>);

    impl MemoryDevice {
        fn new() -> Self {
            Self(Rc::new(RefCell::new(vec![0; 4 * 512])))
        }
    }

    impl BlockDevice for MemoryDevice {
        fn geometry(&self) -> BlockGeometry {
            BlockGeometry::new(512, 4, 1, true, false).unwrap_or_else(|_| std::process::abort())
        }

        fn read_blocks(
            &mut self,
            start_block: u64,
            block_count: u32,
            destination: &mut [u8],
        ) -> Result<(), BlockError> {
            let start = usize::try_from(start_block)
                .ok()
                .and_then(|block| block.checked_mul(512))
                .ok_or(BlockError::OutOfBounds)?;
            let count = usize::try_from(block_count)
                .ok()
                .and_then(|blocks| blocks.checked_mul(512))
                .ok_or(BlockError::OutOfBounds)?;
            let media = self.0.borrow();
            let source = media
                .get(start..start + count)
                .ok_or(BlockError::OutOfBounds)?;
            if source.len() != destination.len() {
                return Err(BlockError::BufferLength);
            }
            destination.copy_from_slice(source);
            Ok(())
        }

        fn write_blocks(
            &mut self,
            start_block: u64,
            _block_count: u32,
            source: &[u8],
            _force_unit_access: bool,
        ) -> Result<(), BlockError> {
            let start = usize::try_from(start_block)
                .ok()
                .and_then(|block| block.checked_mul(512))
                .ok_or(BlockError::OutOfBounds)?;
            self.0.borrow_mut()[start..start + source.len()].copy_from_slice(source);
            Ok(())
        }

        fn flush(&mut self) -> Result<(), BlockError> {
            Ok(())
        }
    }

    fn region(device: MemoryDevice) -> Result<BlockRegion<MemoryDevice>, BlockError> {
        BlockRegion::new(
            device,
            0,
            4,
            BlockAccess::ReadWrite,
            BlockLimits::new(1, 512, 1)?,
        )
    }

    #[test]
    fn vfs_mutation_reopens_and_removes_durably() -> Result<(), FsError> {
        let device = MemoryDevice::new();
        let statefs = StateFs::mount(region(device.clone()).map_err(|_| FsError::Io)?)?;
        let mut namespace = Namespace::new(RamFsQuota::default());
        namespace.mount_writable("/state", Box::new(statefs))?;
        namespace.write_file("/", "/state/state.bin", b"persistent")?;
        assert_eq!(namespace.read_file("/", "/state/state.bin")?, b"persistent");
        drop(namespace);

        let mut reopened = StateFs::mount(region(device.clone()).map_err(|_| FsError::Io)?)?;
        let mut bytes = [0_u8; 16];
        assert_eq!(reopened.read_file(STATE_PATH, 0, &mut bytes)?, 10);
        assert_eq!(&bytes[..10], b"persistent");
        assert_eq!(
            reopened.rename(STATE_PATH, "/renamed.bin"),
            Err(FsError::Unsupported)
        );
        assert_eq!(
            reopened.remove_directory("/directory"),
            Err(FsError::Unsupported)
        );
        reopened.remove_file(STATE_PATH)?;
        drop(reopened);
        let mut empty = StateFs::mount(region(device).map_err(|_| FsError::Io)?)?;
        assert_eq!(empty.metadata(STATE_PATH), Err(FsError::NotFound));
        Ok(())
    }

    #[test]
    fn valid_outer_transaction_rejects_malformed_filesystem_image() -> Result<(), FsError> {
        let device = MemoryDevice::new();
        let mut store = DualSlotStore::open(region(device.clone()).map_err(|_| FsError::Io)?)
            .map_err(|_| FsError::Io)?;
        store.commit(b"not-statefs").map_err(|_| FsError::Io)?;
        drop(store);
        assert!(matches!(
            StateFs::mount(region(device).map_err(|_| FsError::Io)?),
            Err(FsError::Corrupt)
        ));
        Ok(())
    }
}
