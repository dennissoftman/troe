//! Deterministic native-volume discovery and manifest-authorized mount activation.
#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;
#[cfg(test)]
extern crate std;

mod generation;

pub use generation::{
    GenerationValidationError, ValidatedRootActivation, validate_root_activation,
};

use alloc::boxed::Box;
use alloc::rc::Rc;
use alloc::string::String;
use alloc::vec::Vec;
use core::cell::RefCell;
use core::fmt::{self, Write};

use troe_block::{BlockAccess, BlockDevice, BlockError, BlockGeometry, BlockLimits, BlockRegion};
use troe_ext4::{Ext4, Ext4Limits};
use troe_fat::{Fat32, Fat32Limits};
use troe_gpt::{GptError, GptGuid, GptLimits, GptPartition, discover};
use troe_mount::{
    AccessMode, ActivationMode, AvailabilityPolicy, BootMountManifest, FilesystemProfile,
    MAX_DISCOVERED_VOLUMES, MatchState, MountEntry, MountResolution, SelectorKind, VolumeSelector,
};
use troe_vfs::{FsError, Namespace, NodeKind, ReadOnlyFileSystem};

/// Hard ceiling for one early-activation file read.
pub const MAX_SELECTED_FILE_BYTES: usize = 4 * 1024 * 1024;
/// Maximum discovered GPT regions retained for deterministic diagnostics.
pub const MAX_REPORTED_REGIONS: usize = 64;
/// Hard ceiling for the generated `/sys/storage` topology snapshot.
pub const MAX_STORAGE_REPORT_BYTES: usize = 32 * 1024;
/// Space reserved for kernel-owned transaction and `StateFS` region diagnostics.
pub const STORAGE_REPORT_EXTENSION_BYTES: usize = 1024;
const MAX_DISCOVERY_REPORT_BYTES: usize = MAX_STORAGE_REPORT_BYTES - STORAGE_REPORT_EXTENSION_BYTES;

/// Complete parser, request, and filesystem ceilings for one activation pass.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ActivationLimits {
    block: BlockLimits,
    gpt: GptLimits,
    ext4: Ext4Limits,
    fat32: Fat32Limits,
}

impl ActivationLimits {
    /// Compose already-validated limits for each storage layer.
    #[must_use]
    pub const fn new(
        block: BlockLimits,
        gpt: GptLimits,
        ext4: Ext4Limits,
        fat32: Fat32Limits,
    ) -> Self {
        Self {
            block,
            gpt,
            ext4,
            fat32,
        }
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

    /// Limits applied to every FAT32 provider candidate.
    #[must_use]
    pub const fn fat32(self) -> Fat32Limits {
        self.fat32
    }
}

/// One fully validated provider ready to attach below `/vol`.
pub struct PreparedMount {
    path: String,
    provider: Box<dyn ReadOnlyFileSystem>,
    writable: bool,
    activation: ActivationMode,
}

impl core::fmt::Debug for PreparedMount {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("PreparedMount")
            .field("path", &self.path)
            .finish_non_exhaustive()
    }
}

impl PreparedMount {
    /// Absolute namespace path derived from the canonical manifest name.
    #[must_use]
    pub fn path(&self) -> &str {
        &self.path
    }

    /// Whether the validated manifest granted mutation authority.
    #[must_use]
    pub const fn is_writable(&self) -> bool {
        self.writable
    }

    /// Whether this provider should attach at boot or await runtime activation.
    #[must_use]
    pub const fn activation(&self) -> ActivationMode {
        self.activation
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
        if self.writable {
            namespace.mount_writable(&self.path, self.provider)
        } else {
            namespace.mount_read_only(&self.path, self.provider)
        }
    }
}

/// Deterministic result of one bounded discovery and manifest-resolution pass.
#[derive(Debug)]
pub struct StorageActivation {
    mounts: Vec<PreparedMount>,
    desired_system_available: bool,
    scanned_devices: u8,
    valid_gpt_disks: u8,
    candidates: u8,
    report: String,
}

impl StorageActivation {
    /// Validated providers in canonical manifest order.
    #[must_use]
    pub fn mounts(&self) -> &[PreparedMount] {
        &self.mounts
    }

    /// Consume the result and return its provider plans.
    #[must_use]
    pub fn into_mounts(self) -> Vec<PreparedMount> {
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

    /// Number of clean supported volumes retained, including foreign media.
    #[must_use]
    pub const fn candidate_count(&self) -> u8 {
        self.candidates
    }

    /// Deterministic bounded topology, identity, and role-state snapshot.
    ///
    /// The kernel publishes these exact bytes at `/sys/storage` after every
    /// returned provider has attached successfully. Consequently a `matched`
    /// role is observable only in a namespace where that provider is mounted.
    #[must_use]
    pub fn report(&self) -> &str {
        &self.report
    }
}

/// Activation failures unrelated to expected missing, foreign, or corrupt media.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ActivationError {
    /// Device or validated-candidate input exceeded the hard discovery ceiling.
    DiscoveryLimit,
    /// One device simultaneously claimed whole-device and partitioned filesystems.
    ConflictingLayout,
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
    device_index: u8,
    first_block: u64,
    block_count: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ProbeState {
    Valid,
    InvalidGeometry,
    Corrupt,
    Unsupported,
    Io,
    Exhausted,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum GptProbe {
    Valid { disk_guid: GptGuid, partitions: u16 },
    Invalid(GptError),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct DeviceObservation {
    index: u8,
    geometry: BlockGeometry,
    whole_ext4: ProbeState,
    gpt: GptProbe,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct RegionObservation {
    device_index: u8,
    first_block: u64,
    block_count: u64,
    type_guid: GptGuid,
    partition_guid: GptGuid,
    ext4: ProbeState,
    filesystem_uuid: Option<[u8; 16]>,
    fat32: ProbeState,
    fat32_volume_id: Option<u32>,
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

/// Discover exact BMNT-selected ext4 providers with manifest-bounded authority.
///
/// Foreign, missing, corrupt, and unsupported media are availability outcomes,
/// not parser-policy errors. No returned provider exists until GPT copies,
/// partition bounds, the ext4 profile, and every stable identifier validate.
///
/// # Errors
///
/// Rejects inputs above hard discovery limits, bounded allocation failure, or
/// an internal manifest-resolution limit failure before returning mount plans.
pub fn prepare_mounts<D: BlockDevice + 'static>(
    manifest: &BootMountManifest,
    devices: Vec<D>,
    limits: ActivationLimits,
) -> Result<StorageActivation, ActivationError> {
    if devices.len() > MAX_DISCOVERED_VOLUMES {
        return Err(ActivationError::DiscoveryLimit);
    }
    let scanned_devices =
        u8::try_from(devices.len()).map_err(|_| ActivationError::DiscoveryLimit)?;
    let mut candidates = Vec::new();
    candidates
        .try_reserve_exact(MAX_DISCOVERED_VOLUMES.min(manifest.entries().len().max(devices.len())))
        .map_err(|_| ActivationError::MetadataExhausted)?;
    let mut device_observations = Vec::new();
    device_observations
        .try_reserve_exact(devices.len())
        .map_err(|_| ActivationError::MetadataExhausted)?;
    let mut region_observations = Vec::new();
    region_observations
        .try_reserve_exact(MAX_REPORTED_REGIONS.min(devices.len().saturating_mul(2)))
        .map_err(|_| ActivationError::MetadataExhausted)?;
    let mut valid_gpt_disks = 0_u8;

    for (index, device) in devices.into_iter().enumerate() {
        let device_index = u8::try_from(index).map_err(|_| ActivationError::DiscoveryLimit)?;
        if discover_device(
            manifest,
            device_index,
            device,
            limits,
            &mut candidates,
            &mut device_observations,
            &mut region_observations,
        )? {
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
    let report = render_storage_report(
        manifest,
        &resolution,
        &device_observations,
        &region_observations,
        &candidates,
        valid_gpt_disks,
    )?;
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
        mounts.push(PreparedMount {
            path,
            provider,
            writable: entry.access() == AccessMode::ReadWrite,
            activation: entry.activation(),
        });
    }
    Ok(StorageActivation {
        mounts,
        desired_system_available: resolution.desired_system_available(),
        scanned_devices,
        valid_gpt_disks,
        candidates: candidate_count,
        report,
    })
}

/// Prepare only manifests whose entries are all read-only.
///
/// Use [`prepare_mounts`] when the validated manifest deliberately requests a
/// writable provider. This compatibility entry point refuses mutation policy.
///
/// # Errors
///
/// Rejects a manifest containing any read-write role and otherwise forwards
/// [`prepare_mounts`] failures.
pub fn prepare_read_only<D: BlockDevice + 'static>(
    manifest: &BootMountManifest,
    devices: Vec<D>,
    limits: ActivationLimits,
) -> Result<StorageActivation, ActivationError> {
    if manifest
        .entries()
        .iter()
        .any(|entry| entry.access() == AccessMode::ReadWrite)
    {
        return Err(ActivationError::Resolution);
    }
    prepare_mounts(manifest, devices, limits)
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
    if entries.next().is_some() || entry.filesystem() != FilesystemProfile::Ext4V1 {
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
    device_index: u8,
    device: D,
    limits: ActivationLimits,
    candidates: &mut Vec<Candidate>,
    device_observations: &mut Vec<DeviceObservation>,
    region_observations: &mut Vec<RegionObservation>,
) -> Result<bool, ActivationError> {
    let shared = SharedDevice::new(device);
    let geometry = shared.geometry();
    let whole_ext4 = discover_whole_ext4(manifest, device_index, &shared, limits, candidates)?;
    let gpt_result =
        BlockRegion::whole_device(shared.clone(), BlockAccess::ReadOnly, limits.block())
            .map_err(GptError::Block)
            .and_then(|mut whole| discover(&mut whole, limits.gpt()));

    let (gpt_probe, valid_gpt) = match gpt_result {
        Ok(gpt) => {
            if whole_ext4 == ProbeState::Valid {
                return Err(ActivationError::ConflictingLayout);
            }
            let partition_count = u16::try_from(gpt.partitions().len())
                .map_err(|_| ActivationError::DiscoveryLimit)?;
            for partition in gpt.partitions() {
                if region_observations.len() >= MAX_REPORTED_REGIONS {
                    return Err(ActivationError::DiscoveryLimit);
                }
                region_observations
                    .try_reserve(1)
                    .map_err(|_| ActivationError::MetadataExhausted)?;
                let (ext4_state, filesystem_uuid) = probe_partition_ext4(
                    manifest,
                    &shared,
                    geometry,
                    limits,
                    gpt.disk_guid(),
                    partition,
                    device_index,
                    candidates,
                )?;
                let (fat32_state, fat32_volume_id) = probe_partition_fat32(
                    manifest,
                    &shared,
                    geometry,
                    limits,
                    gpt.disk_guid(),
                    partition,
                    device_index,
                    candidates,
                )?;
                if ext4_state == ProbeState::Valid && fat32_state == ProbeState::Valid {
                    return Err(ActivationError::ConflictingLayout);
                }
                region_observations.push(RegionObservation {
                    device_index,
                    first_block: partition.first_lba(),
                    block_count: partition.block_count(),
                    type_guid: partition.type_guid(),
                    partition_guid: partition.unique_guid(),
                    ext4: ext4_state,
                    filesystem_uuid,
                    fat32: fat32_state,
                    fat32_volume_id,
                });
            }
            (
                GptProbe::Valid {
                    disk_guid: gpt.disk_guid(),
                    partitions: partition_count,
                },
                true,
            )
        }
        Err(GptError::MetadataExhausted) => return Err(ActivationError::MetadataExhausted),
        Err(error) => (GptProbe::Invalid(error), false),
    };
    device_observations
        .try_reserve(1)
        .map_err(|_| ActivationError::MetadataExhausted)?;
    device_observations.push(DeviceObservation {
        index: device_index,
        geometry,
        whole_ext4,
        gpt: gpt_probe,
    });
    Ok(valid_gpt)
}

fn discover_whole_ext4<D: BlockDevice + 'static>(
    manifest: &BootMountManifest,
    device_index: u8,
    device: &SharedDevice<D>,
    limits: ActivationLimits,
    candidates: &mut Vec<Candidate>,
) -> Result<ProbeState, ActivationError> {
    let Ok(region) =
        BlockRegion::whole_device(device.clone(), BlockAccess::ReadOnly, limits.block())
    else {
        return Ok(ProbeState::InvalidGeometry);
    };
    let ext4_probe = match Ext4::mount(region, limits.ext4()) {
        Ok(ext4) => ext4,
        Err(error) => return Ok(probe_state(error)),
    };
    let selector = VolumeSelector::whole_ext4(ext4_probe.uuid().bytes())
        .map_err(|_| ActivationError::Resolution)?;
    let access = selected_block_access(manifest, selector, device.geometry)?;
    let provider_region = BlockRegion::whole_device(device.clone(), access, limits.block())
        .map_err(|_| ActivationError::Resolution)?;
    let ext4 =
        Ext4::mount(provider_region, limits.ext4()).map_err(|_| ActivationError::Resolution)?;
    push_candidate(
        candidates,
        selector,
        Box::new(ext4),
        device_index,
        0,
        device.geometry.block_count(),
    )?;
    Ok(ProbeState::Valid)
}

#[allow(clippy::too_many_arguments)]
fn probe_partition_ext4<D: BlockDevice + 'static>(
    manifest: &BootMountManifest,
    device: &SharedDevice<D>,
    geometry: BlockGeometry,
    limits: ActivationLimits,
    disk_guid: GptGuid,
    partition: &GptPartition,
    device_index: u8,
    candidates: &mut Vec<Candidate>,
) -> Result<(ProbeState, Option<[u8; 16]>), ActivationError> {
    let Ok(region) = BlockRegion::new(
        device.clone(),
        partition.first_lba(),
        partition.block_count(),
        BlockAccess::ReadOnly,
        limits.block(),
    ) else {
        return Ok((ProbeState::InvalidGeometry, None));
    };
    let probe = match Ext4::mount(region, limits.ext4()) {
        Ok(probe) => probe,
        Err(error) => return Ok((probe_state(error), None)),
    };
    let filesystem_uuid = probe.uuid().bytes();
    let selector = VolumeSelector::gpt_ext4(
        disk_guid.disk_bytes(),
        partition.unique_guid().disk_bytes(),
        filesystem_uuid,
    )
    .map_err(|_| ActivationError::Resolution)?;
    let access = selected_block_access(manifest, selector, geometry)?;
    let provider_region = BlockRegion::new(
        device.clone(),
        partition.first_lba(),
        partition.block_count(),
        access,
        limits.block(),
    )
    .map_err(|_| ActivationError::Resolution)?;
    let provider =
        Ext4::mount(provider_region, limits.ext4()).map_err(|_| ActivationError::Resolution)?;
    push_candidate(
        candidates,
        selector,
        Box::new(provider),
        device_index,
        partition.first_lba(),
        partition.block_count(),
    )?;
    Ok((ProbeState::Valid, Some(filesystem_uuid)))
}

#[allow(clippy::too_many_arguments)]
fn probe_partition_fat32<D: BlockDevice + 'static>(
    manifest: &BootMountManifest,
    device: &SharedDevice<D>,
    geometry: BlockGeometry,
    limits: ActivationLimits,
    disk_guid: GptGuid,
    partition: &GptPartition,
    device_index: u8,
    candidates: &mut Vec<Candidate>,
) -> Result<(ProbeState, Option<u32>), ActivationError> {
    let Ok(region) = BlockRegion::new(
        device.clone(),
        partition.first_lba(),
        partition.block_count(),
        BlockAccess::ReadOnly,
        limits.block(),
    ) else {
        return Ok((ProbeState::InvalidGeometry, None));
    };
    let probe = match Fat32::mount(region, limits.fat32()) {
        Ok(probe) => probe,
        Err(error) => return Ok((probe_state(error), None)),
    };
    let volume_id = probe.volume_id();
    let Ok(selector) = VolumeSelector::gpt_fat32(
        disk_guid.disk_bytes(),
        partition.unique_guid().disk_bytes(),
        volume_id,
    ) else {
        return Ok((ProbeState::Corrupt, None));
    };
    let access = selected_block_access(manifest, selector, geometry)?;
    let provider_region = BlockRegion::new(
        device.clone(),
        partition.first_lba(),
        partition.block_count(),
        access,
        limits.block(),
    )
    .map_err(|_| ActivationError::Resolution)?;
    let provider =
        Fat32::mount(provider_region, limits.fat32()).map_err(|_| ActivationError::Resolution)?;
    push_candidate(
        candidates,
        selector,
        Box::new(provider),
        device_index,
        partition.first_lba(),
        partition.block_count(),
    )?;
    Ok((ProbeState::Valid, Some(volume_id)))
}

fn selected_block_access(
    manifest: &BootMountManifest,
    selector: VolumeSelector,
    geometry: BlockGeometry,
) -> Result<BlockAccess, ActivationError> {
    let writable = manifest
        .entries()
        .iter()
        .any(|entry| entry.selector() == selector && entry.access() == AccessMode::ReadWrite);
    if writable {
        if !geometry.supports_flush() && !geometry.supports_force_unit_access() {
            return Err(ActivationError::Resolution);
        }
        Ok(BlockAccess::ReadWrite)
    } else {
        Ok(BlockAccess::ReadOnly)
    }
}

fn push_candidate(
    candidates: &mut Vec<Candidate>,
    selector: VolumeSelector,
    provider: Box<dyn ReadOnlyFileSystem>,
    device_index: u8,
    first_block: u64,
    block_count: u64,
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
        device_index,
        first_block,
        block_count,
    });
    Ok(())
}

const fn probe_state(error: FsError) -> ProbeState {
    match error {
        FsError::Unsupported => ProbeState::Unsupported,
        FsError::Io => ProbeState::Io,
        FsError::NoSpace => ProbeState::Exhausted,
        FsError::Invalid
        | FsError::NotFound
        | FsError::WrongType
        | FsError::ReadOnly
        | FsError::Overflow
        | FsError::Exists
        | FsError::Corrupt => ProbeState::Corrupt,
    }
}

struct StorageReport {
    bytes: String,
}

impl StorageReport {
    fn new() -> Result<Self, ActivationError> {
        let mut bytes = String::new();
        bytes
            .try_reserve_exact(MAX_DISCOVERY_REPORT_BYTES)
            .map_err(|_| ActivationError::MetadataExhausted)?;
        Ok(Self { bytes })
    }

    fn finish(self) -> String {
        self.bytes
    }
}

impl Write for StorageReport {
    fn write_str(&mut self, value: &str) -> fmt::Result {
        if self
            .bytes
            .len()
            .checked_add(value.len())
            .is_none_or(|length| length > MAX_DISCOVERY_REPORT_BYTES)
        {
            return Err(fmt::Error);
        }
        self.bytes.push_str(value);
        Ok(())
    }
}

#[derive(Clone, Copy)]
struct HexIdentity([u8; 16]);

impl fmt::Display for HexIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            write!(formatter, "{byte:02x}")?;
        }
        Ok(())
    }
}

fn render_storage_report(
    manifest: &BootMountManifest,
    resolution: &MountResolution,
    devices: &[DeviceObservation],
    regions: &[RegionObservation],
    candidates: &[Candidate],
    valid_gpt_disks: u8,
) -> Result<String, ActivationError> {
    let mut report = StorageReport::new()?;
    writeln!(report, "storage-v1")
        .and_then(|()| writeln!(report, "devices {}", devices.len()))
        .and_then(|()| writeln!(report, "gpt-disks {valid_gpt_disks}"))
        .and_then(|()| writeln!(report, "regions {}", regions.len()))
        .and_then(|()| writeln!(report, "volumes {}", candidates.len()))
        .and_then(|()| {
            writeln!(
                report,
                "required-roles {}",
                if resolution.desired_system_available() {
                    "available"
                } else {
                    "recovery"
                }
            )
        })
        .map_err(|_| ActivationError::DiscoveryLimit)?;

    for device in devices {
        write!(
            report,
            "device {} block-bytes={} blocks={} alignment={} flush={} fua={} whole-ext4={} gpt=",
            device.index,
            device.geometry.logical_block_bytes(),
            device.geometry.block_count(),
            device.geometry.required_alignment_blocks(),
            yes_no(device.geometry.supports_flush()),
            yes_no(device.geometry.supports_force_unit_access()),
            probe_name(device.whole_ext4),
        )
        .map_err(|_| ActivationError::DiscoveryLimit)?;
        match device.gpt {
            GptProbe::Valid {
                disk_guid,
                partitions,
            } => writeln!(
                report,
                "valid disk={} partitions={partitions}",
                HexIdentity(disk_guid.disk_bytes())
            ),
            GptProbe::Invalid(error) => writeln!(report, "{}", gpt_error_name(error)),
        }
        .map_err(|_| ActivationError::DiscoveryLimit)?;
    }

    for region in regions {
        write!(
            report,
            "region device={} first={} blocks={} type={} partition={} ext4={}",
            region.device_index,
            region.first_block,
            region.block_count,
            HexIdentity(region.type_guid.disk_bytes()),
            HexIdentity(region.partition_guid.disk_bytes()),
            probe_name(region.ext4),
        )
        .map_err(|_| ActivationError::DiscoveryLimit)?;
        if let Some(filesystem_uuid) = region.filesystem_uuid {
            write!(report, " uuid={}", HexIdentity(filesystem_uuid))
                .map_err(|_| ActivationError::DiscoveryLimit)?;
        }
        write!(report, " fat32={}", probe_name(region.fat32))
            .map_err(|_| ActivationError::DiscoveryLimit)?;
        if let Some(volume_id) = region.fat32_volume_id {
            write!(report, " volume-id={volume_id:08x}")
                .map_err(|_| ActivationError::DiscoveryLimit)?;
        }
        writeln!(report).map_err(|_| ActivationError::DiscoveryLimit)?;
    }

    for (index, candidate) in candidates.iter().enumerate() {
        write!(
            report,
            "volume {index} device={} first={} blocks={} kind={} filesystem={} uuid={}",
            candidate.device_index,
            candidate.first_block,
            candidate.block_count,
            selector_kind_name(candidate.selector.kind()),
            filesystem_name(candidate.selector.filesystem()),
            HexIdentity(candidate.selector.filesystem_identity().bytes()),
        )
        .map_err(|_| ActivationError::DiscoveryLimit)?;
        if let Some(disk) = candidate.selector.disk_guid() {
            write!(report, " disk={}", HexIdentity(disk.bytes()))
                .map_err(|_| ActivationError::DiscoveryLimit)?;
        }
        if let Some(partition) = candidate.selector.partition_guid() {
            write!(report, " partition={}", HexIdentity(partition.bytes()))
                .map_err(|_| ActivationError::DiscoveryLimit)?;
        }
        writeln!(report).map_err(|_| ActivationError::DiscoveryLimit)?;
    }

    write_role_report(&mut report, manifest, resolution)?;
    Ok(report.finish())
}

fn write_role_report(
    report: &mut StorageReport,
    manifest: &BootMountManifest,
    resolution: &MountResolution,
) -> Result<(), ActivationError> {
    for (entry, resolved) in manifest.entries().iter().zip(resolution.entries()) {
        write!(
            report,
            "role {} path=/vol/{} filesystem={} access={} availability={} activation={} state=",
            entry.name(),
            entry.name(),
            filesystem_name(entry.filesystem()),
            access_name(entry.access()),
            availability_name(entry.availability()),
            activation_name(entry.activation()),
        )
        .map_err(|_| ActivationError::DiscoveryLimit)?;
        match resolved.state() {
            MatchState::Missing => writeln!(report, "missing"),
            MatchState::Ambiguous => writeln!(report, "ambiguous"),
            MatchState::Matched { candidate_index } => {
                writeln!(
                    report,
                    "{} volume={candidate_index}",
                    match entry.activation() {
                        ActivationMode::Auto => "mounted",
                        ActivationMode::Manual => "ready",
                    }
                )
            }
        }
        .map_err(|_| ActivationError::DiscoveryLimit)?;
    }
    Ok(())
}

const fn yes_no(value: bool) -> &'static str {
    if value { "yes" } else { "no" }
}

const fn probe_name(state: ProbeState) -> &'static str {
    match state {
        ProbeState::Valid => "valid",
        ProbeState::InvalidGeometry => "invalid-geometry",
        ProbeState::Corrupt => "corrupt",
        ProbeState::Unsupported => "unsupported",
        ProbeState::Io => "io-error",
        ProbeState::Exhausted => "profile-exhausted",
    }
}

const fn selector_kind_name(kind: SelectorKind) -> &'static str {
    match kind {
        SelectorKind::WholeDevice => "whole-device",
        SelectorKind::GptPartition => "gpt-partition",
    }
}

const fn filesystem_name(filesystem: FilesystemProfile) -> &'static str {
    match filesystem {
        FilesystemProfile::Fat32 => "fat32",
        FilesystemProfile::Ext4V1 => "ext4-v1",
    }
}

const fn access_name(access: AccessMode) -> &'static str {
    match access {
        AccessMode::ReadOnly => "read-only",
        AccessMode::ReadWrite => "read-write",
    }
}

const fn availability_name(availability: AvailabilityPolicy) -> &'static str {
    match availability {
        AvailabilityPolicy::Optional => "optional",
        AvailabilityPolicy::Required => "required",
    }
}

const fn activation_name(activation: ActivationMode) -> &'static str {
    match activation {
        ActivationMode::Auto => "auto",
        ActivationMode::Manual => "manual",
    }
}

const fn gpt_error_name(error: GptError) -> &'static str {
    match error {
        GptError::InvalidLimits => "invalid-limits",
        GptError::UnsupportedGeometry => "unsupported-geometry",
        GptError::InvalidProtectiveMbr => "invalid-protective-mbr",
        GptError::InvalidHeader => "invalid-header",
        GptError::HeaderChecksum => "header-checksum",
        GptError::InvalidEntryLayout => "invalid-entry-layout",
        GptError::EntryChecksum => "entry-checksum",
        GptError::InconsistentCopies => "inconsistent-copies",
        GptError::InvalidPartition => "invalid-partition",
        GptError::OverlappingPartitions => "overlapping-partitions",
        GptError::DuplicateIdentifier => "duplicate-identifier",
        GptError::MetadataExhausted => "metadata-exhausted",
        GptError::Block(error) => block_error_name(error),
    }
}

const fn block_error_name(error: BlockError) -> &'static str {
    match error {
        BlockError::InvalidGeometry => "block-invalid-geometry",
        BlockError::InvalidLimits => "block-invalid-limits",
        BlockError::InvalidRegion => "block-invalid-region",
        BlockError::EmptyTransfer => "block-empty-transfer",
        BlockError::Misaligned => "block-misaligned",
        BlockError::OutOfBounds => "block-out-of-bounds",
        BlockError::TransferTooLarge => "block-transfer-too-large",
        BlockError::BufferLength => "block-buffer-length",
        BlockError::ReadOnly => "block-read-only",
        BlockError::Unsupported => "block-unsupported",
        BlockError::Device => "block-io-error",
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec;
    use alloc::vec::Vec;
    use core::fmt::Write;

    use super::{
        ActivationError, ActivationLimits, Candidate, MAX_DISCOVERY_REPORT_BYTES, SharedDevice,
        StorageReport, prepare_mounts, prepare_read_only, render_storage_report,
    };
    use troe_block::{BlockDevice, BlockError, BlockGeometry, BlockLimits};
    use troe_ext4::Ext4Limits;
    use troe_fat::Fat32Limits;
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
            Fat32Limits::new(4096, 1024, 1024 * 1024, 4096, 64)
                .unwrap_or_else(|_| std::process::abort()),
        )
    }

    #[test]
    fn missing_and_foreign_media_preserve_recovery_without_partial_mounts() {
        let manifest = parse_manifest(MANIFEST).unwrap_or_else(|_| std::process::abort());
        assert!(matches!(
            prepare_read_only::<MemoryDevice>(&manifest, Vec::new(), limits()),
            Err(ActivationError::Resolution)
        ));
        let empty = prepare_mounts::<MemoryDevice>(&manifest, Vec::new(), limits())
            .unwrap_or_else(|_| std::process::abort());
        assert!(!empty.desired_system_available());
        assert!(empty.mounts().is_empty());
        assert_eq!(empty.scanned_devices(), 0);
        assert_eq!(
            empty.report(),
            "storage-v1\n\
             devices 0\n\
             gpt-disks 0\n\
             regions 0\n\
             volumes 0\n\
             required-roles recovery\n\
             role root path=/vol/root filesystem=ext4-v1 access=read-write availability=required activation=auto state=missing\n"
        );

        let foreign = prepare_mounts(&manifest, vec![MemoryDevice::zeroed(64)], limits())
            .unwrap_or_else(|_| std::process::abort());
        assert!(!foreign.desired_system_available());
        assert!(foreign.mounts().is_empty());
        assert_eq!(foreign.scanned_devices(), 1);
        assert_eq!(foreign.valid_gpt_disks(), 0);
        assert_eq!(foreign.candidate_count(), 0);
        assert!(
            foreign.report().contains(
                "device 0 block-bytes=512 blocks=64 alignment=1 flush=no fua=no \
                 whole-ext4=unsupported gpt=invalid-protective-mbr\n"
            ),
            "{}",
            foreign.report()
        );
        assert!(foreign.report().ends_with(
            "role root path=/vol/root filesystem=ext4-v1 access=read-write \
             availability=required activation=auto state=missing\n"
        ));
    }

    #[test]
    fn topology_report_distinguishes_unique_and_ambiguous_stable_identities() {
        let manifest = parse_manifest(MANIFEST).unwrap_or_else(|_| std::process::abort());
        let selector = manifest.entries()[0].selector();
        let candidate = |device_index| Candidate {
            selector,
            provider: None,
            device_index,
            first_block: 0,
            block_count: 128,
        };
        let unique = vec![candidate(7)];
        let unique_resolution = manifest
            .resolve(&[selector])
            .unwrap_or_else(|_| std::process::abort());
        let unique_report =
            render_storage_report(&manifest, &unique_resolution, &[], &[], &unique, 0)
                .unwrap_or_else(|_| std::process::abort());
        assert!(unique_report.contains("required-roles available\n"));
        assert!(unique_report.contains("volume 0 device=7 first=0 blocks=128"));
        assert!(unique_report.ends_with("state=mounted volume=0\n"));

        let ambiguous = vec![candidate(1), candidate(9)];
        let ambiguous_resolution = manifest
            .resolve(&[selector, selector])
            .unwrap_or_else(|_| std::process::abort());
        let ambiguous_report =
            render_storage_report(&manifest, &ambiguous_resolution, &[], &[], &ambiguous, 0)
                .unwrap_or_else(|_| std::process::abort());
        assert!(ambiguous_report.contains("required-roles recovery\n"));
        assert!(ambiguous_report.ends_with("state=ambiguous\n"));
    }

    #[test]
    fn topology_report_ceiling_is_exact_and_atomic_per_write() {
        let mut report = StorageReport::new().unwrap_or_else(|_| std::process::abort());
        let exact = "x".repeat(MAX_DISCOVERY_REPORT_BYTES);
        assert_eq!(report.write_str(&exact), Ok(()));
        assert_eq!(report.write_str("x"), Err(core::fmt::Error));
        assert_eq!(report.finish().len(), MAX_DISCOVERY_REPORT_BYTES);
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
