//! Deterministic native-volume discovery and read-only mount activation.
#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;
#[cfg(test)]
extern crate std;

use alloc::boxed::Box;
use alloc::rc::Rc;
use alloc::string::String;
use alloc::vec::Vec;
use core::cell::RefCell;

use troe_block::{BlockAccess, BlockDevice, BlockError, BlockGeometry, BlockLimits, BlockRegion};
use troe_ext4::{Ext4, Ext4Limits};
use troe_gpt::{GptLimits, discover};
use troe_mount::{
    AccessMode, BootMountManifest, FilesystemProfile, MAX_DISCOVERED_VOLUMES, MatchState,
    MountEntry, SelectorKind, VolumeSelector,
};
use troe_vfs::{FsError, Namespace, NodeKind, ReadOnlyFileSystem};

/// Hard ceiling for one early-activation file read.
pub const MAX_SELECTED_FILE_BYTES: usize = 4 * 1024 * 1024;

/// Complete parser, request, and filesystem ceilings for one activation pass.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ActivationLimits {
    block: BlockLimits,
    gpt: GptLimits,
    ext4: Ext4Limits,
}

impl ActivationLimits {
    /// Compose already-validated limits for each storage layer.
    #[must_use]
    pub const fn new(block: BlockLimits, gpt: GptLimits, ext4: Ext4Limits) -> Self {
        Self { block, gpt, ext4 }
    }

    /// Limits applied to every whole-device and partition capability.
    #[must_use]
    pub const fn block(self) -> BlockLimits {
        self.block
    }

    /// Limits applied to primary and backup GPT discovery.
    #[must_use]
    pub const fn gpt(self) -> GptLimits {
        self.gpt
    }

    /// Limits applied to every ext4 provider candidate.
    #[must_use]
    pub const fn ext4(self) -> Ext4Limits {
        self.ext4
    }
}

/// One fully validated provider ready to attach below `/vol`.
pub struct PreparedReadOnlyMount {
    path: String,
    provider: Box<dyn ReadOnlyFileSystem>,
}

impl core::fmt::Debug for PreparedReadOnlyMount {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("PreparedReadOnlyMount")
            .field("path", &self.path)
            .finish_non_exhaustive()
    }
}

impl PreparedReadOnlyMount {
    /// Absolute namespace path derived from the canonical manifest name.
    #[must_use]
    pub fn path(&self) -> &str {
        &self.path
    }

    /// Consume this plan and return its validated provider.
    #[must_use]
    pub fn into_provider(self) -> Box<dyn ReadOnlyFileSystem> {
        self.provider
    }

    /// Attach this validated provider at its manifest-derived namespace path.
    ///
    /// # Errors
    ///
    /// Forwards namespace path, collision, and provider-root failures.
    pub fn attach(self, namespace: &mut Namespace) -> Result<(), FsError> {
        namespace.mount_read_only(&self.path, self.provider)
    }
}

/// Deterministic result of one bounded discovery and manifest-resolution pass.
#[derive(Debug)]
pub struct ReadOnlyActivation {
    mounts: Vec<PreparedReadOnlyMount>,
    desired_system_available: bool,
    scanned_devices: u8,
    valid_gpt_disks: u8,
    candidates: u8,
}

impl ReadOnlyActivation {
    /// Validated providers in canonical manifest order.
    #[must_use]
    pub fn mounts(&self) -> &[PreparedReadOnlyMount] {
        &self.mounts
    }

    /// Consume the result and return its provider plans.
    #[must_use]
    pub fn into_mounts(self) -> Vec<PreparedReadOnlyMount> {
        self.mounts
    }

    /// Whether every required selector matched exactly once.
    #[must_use]
    pub const fn desired_system_available(&self) -> bool {
        self.desired_system_available
    }

    /// Number of bounded native devices considered.
    #[must_use]
    pub const fn scanned_devices(&self) -> u8 {
        self.scanned_devices
    }

    /// Number of devices with a complete, primary/backup-consistent GPT.
    #[must_use]
    pub const fn valid_gpt_disks(&self) -> u8 {
        self.valid_gpt_disks
    }

    /// Number of candidates that matched every on-media identity.
    #[must_use]
    pub const fn candidate_count(&self) -> u8 {
        self.candidates
    }
}

/// Activation failures unrelated to expected missing, foreign, or corrupt media.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ActivationError {
    /// Device or validated-candidate input exceeded the hard discovery ceiling.
    DiscoveryLimit,
    /// Bounded metadata allocation failed before any mount was returned.
    MetadataExhausted,
    /// Manifest resolution rejected the bounded candidate set.
    Resolution,
}

/// Stable failure while reading one file from an exactly selected volume.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SelectedFileError {
    /// Role, path, or byte ceiling was invalid or unsupported.
    InvalidRequest,
    /// No clean supported volume reproduced the role's stable identity.
    Unavailable,
    /// More than one volume reproduced the supposedly unique identity.
    Ambiguous,
    /// The selected file exceeds the caller or storage hard ceiling.
    TooLarge,
    /// Bounded output allocation failed.
    MetadataExhausted,
    /// The exact volume matched but the file was absent, corrupt, or unreadable.
    Filesystem,
}

struct Candidate {
    selector: VolumeSelector,
    provider: Option<Box<dyn ReadOnlyFileSystem>>,
}

struct SharedDevice<D: BlockDevice> {
    inner: Rc<RefCell<D>>,
    geometry: BlockGeometry,
}

impl<D: BlockDevice> SharedDevice<D> {
    fn new(device: D) -> Self {
        let geometry = device.geometry();
        Self {
            inner: Rc::new(RefCell::new(device)),
            geometry,
        }
    }
}

impl<D: BlockDevice> Clone for SharedDevice<D> {
    fn clone(&self) -> Self {
        Self {
            inner: Rc::clone(&self.inner),
            geometry: self.geometry,
        }
    }
}

impl<D: BlockDevice> BlockDevice for SharedDevice<D> {
    fn geometry(&self) -> BlockGeometry {
        self.geometry
    }

    fn read_blocks(
        &mut self,
        start_block: u64,
        block_count: u32,
        destination: &mut [u8],
    ) -> Result<(), BlockError> {
        self.inner
            .try_borrow_mut()
            .map_err(|_| BlockError::Device)?
            .read_blocks(start_block, block_count, destination)
    }

    fn write_blocks(
        &mut self,
        start_block: u64,
        block_count: u32,
        source: &[u8],
        force_unit_access: bool,
    ) -> Result<(), BlockError> {
        self.inner
            .try_borrow_mut()
            .map_err(|_| BlockError::Device)?
            .write_blocks(start_block, block_count, source, force_unit_access)
    }

    fn flush(&mut self) -> Result<(), BlockError> {
        self.inner
            .try_borrow_mut()
            .map_err(|_| BlockError::Device)?
            .flush()
    }
}

/// Discover exact BMNT-selected ext4 providers without granting mutation authority.
///
/// Foreign, missing, corrupt, and unsupported media are availability outcomes,
/// not parser-policy errors. No returned provider exists until GPT copies,
/// partition bounds, the ext4 profile, and every stable identifier validate.
///
/// # Errors
///
/// Rejects inputs above hard discovery limits, bounded allocation failure, or
/// an internal manifest-resolution limit failure before returning mount plans.
pub fn prepare_read_only<D: BlockDevice + 'static>(
    manifest: &BootMountManifest,
    devices: Vec<D>,
    limits: ActivationLimits,
) -> Result<ReadOnlyActivation, ActivationError> {
    if devices.len() > MAX_DISCOVERED_VOLUMES {
        return Err(ActivationError::DiscoveryLimit);
    }
    let scanned_devices =
        u8::try_from(devices.len()).map_err(|_| ActivationError::DiscoveryLimit)?;
    let mut candidates = Vec::new();
    candidates
        .try_reserve_exact(manifest.entries().len())
        .map_err(|_| ActivationError::MetadataExhausted)?;
    let mut valid_gpt_disks = 0_u8;

    for device in devices {
        if discover_device(manifest, device, limits, &mut candidates)? {
            valid_gpt_disks = valid_gpt_disks
                .checked_add(1)
                .ok_or(ActivationError::DiscoveryLimit)?;
        }
    }

    let selectors: Vec<_> = candidates
        .iter()
        .map(|candidate| candidate.selector)
        .collect();
    let resolution = manifest
        .resolve(&selectors)
        .map_err(|_| ActivationError::Resolution)?;
    let candidate_count =
        u8::try_from(candidates.len()).map_err(|_| ActivationError::DiscoveryLimit)?;
    let mut mounts = Vec::new();
    mounts
        .try_reserve_exact(manifest.entries().len())
        .map_err(|_| ActivationError::MetadataExhausted)?;
    for (entry, resolved) in manifest.entries().iter().zip(resolution.entries()) {
        let MatchState::Matched { candidate_index } = resolved.state() else {
            continue;
        };
        let candidate = candidates
            .get_mut(usize::from(candidate_index))
            .ok_or(ActivationError::Resolution)?;
        let provider = candidate
            .provider
            .take()
            .ok_or(ActivationError::Resolution)?;
        let mut path = String::from("/vol/");
        path.try_reserve_exact(entry.name().len())
            .map_err(|_| ActivationError::MetadataExhausted)?;
        path.push_str(entry.name());
        mounts.push(PreparedReadOnlyMount { path, provider });
    }
    Ok(ReadOnlyActivation {
        mounts,
        desired_system_available: resolution.desired_system_available(),
        scanned_devices,
        valid_gpt_disks,
        candidates: candidate_count,
    })
}

/// Read one complete bounded file from an exactly BMNT-selected ext4 role.
///
/// Devices are borrowed only for the duration of the read, so later activation
/// may still consume them into namespace providers or a separate writable
/// capability. Missing, foreign, dirty, and corrupt candidate media never
/// provide bytes. Duplicate exact identities fail closed.
///
/// # Errors
///
/// Rejects invalid requests, absent or ambiguous selected media, files above
/// either byte ceiling, bounded allocation failure, and provider failures.
pub fn read_selected_file<D: BlockDevice>(
    manifest: &BootMountManifest,
    devices: &mut [D],
    role: &str,
    path: &str,
    max_bytes: usize,
    limits: ActivationLimits,
) -> Result<Vec<u8>, SelectedFileError> {
    if devices.len() > MAX_DISCOVERED_VOLUMES
        || max_bytes == 0
        || max_bytes > MAX_SELECTED_FILE_BYTES
        || !path.starts_with('/')
    {
        return Err(SelectedFileError::InvalidRequest);
    }
    let mut entries = manifest
        .entries()
        .iter()
        .filter(|entry| entry.name() == role);
    let entry = entries.next().ok_or(SelectedFileError::InvalidRequest)?;
    if entries.next().is_some()
        || entry.access() != AccessMode::ReadOnly
        || entry.filesystem() != FilesystemProfile::Ext4V1
    {
        return Err(SelectedFileError::InvalidRequest);
    }

    let mut selected = None;
    for device in devices {
        let Some(provider) = open_selected_provider(entry, device, limits) else {
            continue;
        };
        if selected.is_some() {
            return Err(SelectedFileError::Ambiguous);
        }
        selected = Some(read_provider_file(provider, path, max_bytes)?);
    }
    selected.ok_or(SelectedFileError::Unavailable)
}

fn open_selected_provider<'a, D: BlockDevice>(
    entry: &MountEntry,
    device: &'a mut D,
    limits: ActivationLimits,
) -> Option<Ext4<&'a mut D>> {
    let selector = entry.selector();
    match selector.kind() {
        SelectorKind::WholeDevice => {
            let region =
                BlockRegion::whole_device(device, BlockAccess::ReadOnly, limits.block()).ok()?;
            let ext4 = Ext4::mount(region, limits.ext4()).ok()?;
            let discovered = VolumeSelector::whole_ext4(ext4.uuid().bytes()).ok()?;
            (discovered == selector).then_some(ext4)
        }
        SelectorKind::GptPartition => {
            let partition = {
                let mut whole =
                    BlockRegion::whole_device(&mut *device, BlockAccess::ReadOnly, limits.block())
                        .ok()?;
                let gpt = discover(&mut whole, limits.gpt()).ok()?;
                if selector
                    .disk_guid()
                    .map(troe_mount::StableIdentifier::bytes)
                    != Some(gpt.disk_guid().disk_bytes())
                {
                    return None;
                }
                let partition_guid = selector.partition_guid()?;
                let partition = gpt.partition_by_unique_guid(
                    troe_gpt::GptGuid::from_disk_bytes(partition_guid.bytes()),
                )?;
                (
                    partition.first_lba(),
                    partition.block_count(),
                    partition.unique_guid().disk_bytes(),
                    gpt.disk_guid().disk_bytes(),
                )
            };
            let region = BlockRegion::new(
                device,
                partition.0,
                partition.1,
                BlockAccess::ReadOnly,
                limits.block(),
            )
            .ok()?;
            let ext4 = Ext4::mount(region, limits.ext4()).ok()?;
            let discovered =
                VolumeSelector::gpt_ext4(partition.3, partition.2, ext4.uuid().bytes()).ok()?;
            (discovered == selector).then_some(ext4)
        }
    }
}

fn read_provider_file<D: BlockDevice>(
    mut provider: Ext4<D>,
    path: &str,
    max_bytes: usize,
) -> Result<Vec<u8>, SelectedFileError> {
    let metadata = provider
        .metadata(path)
        .map_err(|_| SelectedFileError::Filesystem)?;
    if metadata.kind != NodeKind::File {
        return Err(SelectedFileError::Filesystem);
    }
    let byte_count =
        usize::try_from(metadata.byte_count).map_err(|_| SelectedFileError::TooLarge)?;
    if byte_count > max_bytes || byte_count > MAX_SELECTED_FILE_BYTES {
        return Err(SelectedFileError::TooLarge);
    }
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(byte_count)
        .map_err(|_| SelectedFileError::MetadataExhausted)?;
    bytes.resize(byte_count, 0);
    let mut offset = 0_usize;
    while offset < byte_count {
        let end = offset.saturating_add(4096).min(byte_count);
        let read = provider
            .read_file(
                path,
                u64::try_from(offset).map_err(|_| SelectedFileError::TooLarge)?,
                &mut bytes[offset..end],
            )
            .map_err(|_| SelectedFileError::Filesystem)?;
        if read == 0 || read > end - offset {
            return Err(SelectedFileError::Filesystem);
        }
        offset = offset
            .checked_add(read)
            .ok_or(SelectedFileError::TooLarge)?;
    }
    Ok(bytes)
}

fn discover_device<D: BlockDevice + 'static>(
    manifest: &BootMountManifest,
    device: D,
    limits: ActivationLimits,
    candidates: &mut Vec<Candidate>,
) -> Result<bool, ActivationError> {
    let shared = SharedDevice::new(device);
    discover_whole_ext4(manifest, &shared, limits, candidates)?;
    let Ok(mut whole) =
        BlockRegion::whole_device(shared.clone(), BlockAccess::ReadOnly, limits.block())
    else {
        return Ok(false);
    };
    let Ok(gpt) = discover(&mut whole, limits.gpt()) else {
        return Ok(false);
    };
    for entry in manifest.entries() {
        let selector = entry.selector();
        if entry.access() != AccessMode::ReadOnly
            || entry.filesystem() != FilesystemProfile::Ext4V1
            || selector.kind() != SelectorKind::GptPartition
            || selector
                .disk_guid()
                .map(troe_mount::StableIdentifier::bytes)
                != Some(gpt.disk_guid().disk_bytes())
        {
            continue;
        }
        let Some(partition_guid) = selector.partition_guid() else {
            continue;
        };
        let Some(partition) = gpt
            .partition_by_unique_guid(troe_gpt::GptGuid::from_disk_bytes(partition_guid.bytes()))
        else {
            continue;
        };
        let Ok(region) = BlockRegion::new(
            shared.clone(),
            partition.first_lba(),
            partition.block_count(),
            BlockAccess::ReadOnly,
            limits.block(),
        ) else {
            continue;
        };
        let Ok(ext4) = Ext4::mount(region, limits.ext4()) else {
            continue;
        };
        let Ok(discovered) = VolumeSelector::gpt_ext4(
            gpt.disk_guid().disk_bytes(),
            partition.unique_guid().disk_bytes(),
            ext4.uuid().bytes(),
        ) else {
            continue;
        };
        if discovered == selector {
            push_candidate(candidates, discovered, Box::new(ext4))?;
        }
    }
    Ok(true)
}

fn discover_whole_ext4<D: BlockDevice + 'static>(
    manifest: &BootMountManifest,
    device: &SharedDevice<D>,
    limits: ActivationLimits,
    candidates: &mut Vec<Candidate>,
) -> Result<(), ActivationError> {
    for entry in manifest.entries() {
        let selector = entry.selector();
        if entry.access() != AccessMode::ReadOnly
            || entry.filesystem() != FilesystemProfile::Ext4V1
            || selector.kind() != SelectorKind::WholeDevice
        {
            continue;
        }
        let Ok(region) =
            BlockRegion::whole_device(device.clone(), BlockAccess::ReadOnly, limits.block())
        else {
            continue;
        };
        let Ok(ext4) = Ext4::mount(region, limits.ext4()) else {
            continue;
        };
        let Ok(discovered) = VolumeSelector::whole_ext4(ext4.uuid().bytes()) else {
            continue;
        };
        if discovered == selector {
            push_candidate(candidates, discovered, Box::new(ext4))?;
        }
    }
    Ok(())
}

fn push_candidate(
    candidates: &mut Vec<Candidate>,
    selector: VolumeSelector,
    provider: Box<dyn ReadOnlyFileSystem>,
) -> Result<(), ActivationError> {
    if candidates.len() >= MAX_DISCOVERED_VOLUMES {
        return Err(ActivationError::DiscoveryLimit);
    }
    candidates
        .try_reserve(1)
        .map_err(|_| ActivationError::MetadataExhausted)?;
    candidates.push(Candidate {
        selector,
        provider: Some(provider),
    });
    Ok(())
}

#[cfg(test)]
mod tests {
    use alloc::vec;
    use alloc::vec::Vec;

    use super::{ActivationLimits, SharedDevice, prepare_read_only};
    use troe_block::{BlockDevice, BlockError, BlockGeometry, BlockLimits};
    use troe_ext4::Ext4Limits;
    use troe_gpt::GptLimits;
    use troe_mount::parse_manifest;

    const MANIFEST: &[u8] = include_bytes!("../../../assets/boot.bmnt");

    struct MemoryDevice {
        bytes: Vec<u8>,
        geometry: BlockGeometry,
    }

    impl MemoryDevice {
        fn zeroed(blocks: u64) -> Self {
            Self {
                bytes: vec![0; usize::try_from(blocks).unwrap_or(0) * 512],
                geometry: BlockGeometry::new(512, blocks, 1, false, false)
                    .unwrap_or_else(|_| std::process::abort()),
            }
        }
    }

    impl BlockDevice for MemoryDevice {
        fn geometry(&self) -> BlockGeometry {
            self.geometry
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
            let bytes = usize::try_from(block_count)
                .ok()
                .and_then(|blocks| blocks.checked_mul(512))
                .ok_or(BlockError::OutOfBounds)?;
            let source = self
                .bytes
                .get(start..start + bytes)
                .ok_or(BlockError::OutOfBounds)?;
            if destination.len() != source.len() {
                return Err(BlockError::BufferLength);
            }
            destination.copy_from_slice(source);
            Ok(())
        }
    }

    fn limits() -> ActivationLimits {
        ActivationLimits::new(
            BlockLimits::new(8, 4096, 1).unwrap_or_else(|_| std::process::abort()),
            GptLimits::new(128, 16 * 1024, 8).unwrap_or_else(|_| std::process::abort()),
            Ext4Limits::new(8, 32, 64, 1024, 1024 * 1024, 4096, 64)
                .unwrap_or_else(|_| std::process::abort()),
        )
    }

    #[test]
    fn missing_and_foreign_media_preserve_recovery_without_partial_mounts() {
        let manifest = parse_manifest(MANIFEST).unwrap_or_else(|_| std::process::abort());
        let empty = prepare_read_only::<MemoryDevice>(&manifest, Vec::new(), limits())
            .unwrap_or_else(|_| std::process::abort());
        assert!(!empty.desired_system_available());
        assert!(empty.mounts().is_empty());
        assert_eq!(empty.scanned_devices(), 0);

        let foreign = prepare_read_only(&manifest, vec![MemoryDevice::zeroed(64)], limits())
            .unwrap_or_else(|_| std::process::abort());
        assert!(!foreign.desired_system_available());
        assert!(foreign.mounts().is_empty());
        assert_eq!(foreign.scanned_devices(), 1);
        assert_eq!(foreign.valid_gpt_disks(), 0);
        assert_eq!(foreign.candidate_count(), 0);
    }

    #[test]
    fn shared_device_rejects_overlapping_mutable_access() {
        let shared = SharedDevice::new(MemoryDevice::zeroed(8));
        let _borrow = shared.inner.borrow_mut();
        let mut clone = shared.clone();
        let mut block = [0_u8; 512];
        assert_eq!(clone.read_blocks(0, 1, &mut block), Err(BlockError::Device));
    }
}
