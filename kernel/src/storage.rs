//! Native block activation, generation recovery, and root selection policy.
//!
//! This module decides which volume the machine boots from: it brings up the
//! virtio block devices, recovers the activation record through the dual-slot
//! transaction store, chooses between the active, predecessor, and recovery
//! generations, mounts the state filesystem, and prepares the manifest-named
//! mounts.
//!
//! ADR 0035 Phase E removes this whole concern from the kernel address space.
//! It is the single largest block of storage policy the privileged image still
//! holds, and it is why the kernel links `troe-fs-ext4`, `troe-fs-fat`,
//! `troe-fs-statefs`, `troe-txslot`, and `troe-volume` at all. What the kernel
//! keeps once they go is the virtio-block device access, handing the storage
//! server exact block regions: the `kernel/src/broker/block.rs` ADR 0035
//! names.

use crate::handoff::write_boot_status;
use crate::limits::{INITIAL_ACTIVATION, PERSISTENCE_SELECTOR, STATEFS_SELECTOR};
use crate::machine::OwnedAccounting;
#[cfg(feature = "acceptance-probes")]
use crate::network::bringup::probe_native_network;
use crate::support::fatal;
use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec::Vec;
use core::fmt::Write as _;
use troe_block::BlockDevice;
use troe_block::{BlockAccess, BlockLimits, BlockRegion};
use troe_core::Output;
use troe_fmt_bmnt::BootMountManifest;
use troe_fmt_cspk::{ContentPack, MAX_PACK_BYTES, ObjectKind};
use troe_fmt_gpt::{GptGuid, GptLimits, discover};
use troe_fmt_prgn::RegionSelector;
use troe_fmt_scfg::{
    ActivationPointer, ActivationRecovery, SystemConfig, parse_config, recover_activation,
};
use troe_fs_api::FileSystemProvider;
use troe_fs_ext4::Ext4Limits;
use troe_fs_fat::Fat32Limits;
#[cfg(feature = "acceptance-probes")]
use troe_fs_statefs::STATE_PATH;
use troe_fs_statefs::StateFs;
use troe_identity::IdentityLimits;
use troe_namespace::Namespace;
use troe_txslot::{DualSlotStore, TRANSACTION_BLOCKS};
use troe_volume::{
    ActivationLimits, MAX_STORAGE_REPORT_BYTES, STORAGE_REPORT_EXTENSION_BYTES, prepare_mounts,
    read_selected_file, validate_root_activation,
};

pub(crate) struct NativeBlockInitialization {
    pub(crate) blocks: Vec<troe_machine::NativeVirtioBlock>,
    pub(crate) statefs: Option<Box<dyn FileSystemProvider>>,
    pub(crate) generation: NativeGenerationState,
    pub(crate) config: Option<SystemConfig>,
}

pub(crate) struct RecoveredNativeGeneration {
    state: NativeGenerationState,
    config: Option<SystemConfig>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum NativeGenerationState {
    Active,
    Predecessor,
    Recovery,
}

impl NativeGenerationState {
    const fn desired_system_available(self) -> bool {
        !matches!(self, Self::Recovery)
    }

    const fn name(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Predecessor => "predecessor",
            Self::Recovery => "recovery",
        }
    }
}

pub(crate) fn initialize_native_blocks(
    boot_mount_manifest: &BootMountManifest,
) -> Result<NativeBlockInitialization, ()> {
    let mut devices = troe_machine::discover_virtio_blocks().map_err(|_| ())?;
    #[cfg(feature = "acceptance-probes")]
    let generation = recover_native_generation(&mut devices, boot_mount_manifest)?;
    #[cfg(not(feature = "acceptance-probes"))]
    let generation = recover_native_generation(&mut devices, boot_mount_manifest);
    #[cfg(feature = "acceptance-probes")]
    let statefs = recover_native_statefs(&mut devices)?;
    #[cfg(not(feature = "acceptance-probes"))]
    let statefs = recover_native_statefs(&mut devices);
    #[cfg(feature = "acceptance-probes")]
    probe_native_network()?;
    Ok(NativeBlockInitialization {
        blocks: devices,
        statefs,
        generation: generation.state,
        config: generation.config,
    })
}

#[cfg(feature = "acceptance-probes")]
pub(crate) fn recover_native_generation(
    devices: &mut Vec<troe_machine::NativeVirtioBlock>,
    boot_mount_manifest: &BootMountManifest,
) -> Result<RecoveredNativeGeneration, ()> {
    recover_native_generation_inner(devices, boot_mount_manifest)
}

#[cfg(not(feature = "acceptance-probes"))]
pub(crate) fn recover_native_generation(
    devices: &mut Vec<troe_machine::NativeVirtioBlock>,
    boot_mount_manifest: &BootMountManifest,
) -> RecoveredNativeGeneration {
    recover_native_generation_inner(devices, boot_mount_manifest).unwrap_or(
        RecoveredNativeGeneration {
            state: NativeGenerationState::Recovery,
            config: None,
        },
    )
}

pub(crate) fn recover_native_generation_inner(
    devices: &mut Vec<troe_machine::NativeVirtioBlock>,
    boot_mount_manifest: &BootMountManifest,
) -> Result<RecoveredNativeGeneration, ()> {
    let activation_limits = native_activation_limits()?;
    let content_bytes = read_selected_file(
        boot_mount_manifest,
        devices.as_mut_slice(),
        "root",
        "/system.cspk",
        MAX_PACK_BYTES,
        activation_limits,
    )
    .map_err(|_| ())?;
    let content = ContentPack::parse(&content_bytes).map_err(|_| ())?;
    let bootstrap = ActivationPointer::parse(INITIAL_ACTIVATION).map_err(|_| ())?;
    let selector = RegionSelector::parse(PERSISTENCE_SELECTOR).map_err(|_| ())?;
    let region = take_transaction_region(devices, selector)?;
    let mut store = DualSlotStore::open(region).map_err(|_| ())?;
    let recovered = match store.payload() {
        Some(payload) => Some(ActivationPointer::parse(payload).map_err(|_| ())?),
        None => None,
    };
    let candidate = recovered.unwrap_or(bootstrap);
    #[allow(unused_mut)]
    let (mut pointer, validated, state) = match recover_activation(candidate, |pointer| {
        validate_root_activation(&content, pointer, IdentityLimits::standard())
    }) {
        ActivationRecovery::Active { pointer, validated } => {
            (pointer, validated, NativeGenerationState::Active)
        }
        ActivationRecovery::Previous { pointer, validated } => {
            (pointer, validated, NativeGenerationState::Predecessor)
        }
        ActivationRecovery::Unavailable => {
            return Ok(RecoveredNativeGeneration {
                state: NativeGenerationState::Recovery,
                config: None,
            });
        }
    };
    let newly_published = recovered.is_none() || state == NativeGenerationState::Predecessor;
    if newly_published {
        store.commit(&pointer.encode()).map_err(|_| ())?;
    }

    #[cfg(feature = "acceptance-probes")]
    let state = {
        let mut selected_state = state;
        if selected_state == NativeGenerationState::Active && validated.health_rollback() {
            let previous = pointer.previous().ok_or(())?;
            let previous_pointer = ActivationPointer::new(previous, None).map_err(|_| ())?;
            let previous_validation =
                validate_root_activation(&content, previous_pointer, IdentityLimits::standard())
                    .map_err(|_| ())?;
            if previous_validation.health_rollback()
                || !troe_machine::write(b"native generation: candidate published\n")
            {
                return Err(());
            }
            store.commit(&previous_pointer.encode()).map_err(|_| ())?;
            pointer = previous_pointer;
            selected_state = NativeGenerationState::Predecessor;
            if !troe_machine::write(b"native generation: health rollback committed\n") {
                return Err(());
            }
        } else if !newly_published {
            // Exercise a complete durable transaction on every acceptance
            // boot without changing the production activation policy.
            store.commit(&pointer.encode()).map_err(|_| ())?;
        }
        if !troe_machine::write(b"native identity: generation snapshot verified\n") {
            return Err(());
        }
        if !troe_machine::write(b"native content: selected ext4 CSPK verified\n") {
            return Err(());
        }
        if !troe_machine::write(b"native persistence: committed and flushed\n") {
            return Err(());
        }
        selected_state
    };
    #[cfg(not(feature = "acceptance-probes"))]
    let _ = validated.health_rollback();
    let config_object = content.get(pointer.active().digest()).ok_or(())?;
    if config_object.kind != ObjectKind::SystemConfig {
        return Err(());
    }
    let selected_config = parse_config(config_object.bytes).map_err(|_| ())?;
    Ok(RecoveredNativeGeneration {
        state,
        config: Some(selected_config),
    })
}

pub(crate) fn mount_native_statefs(
    devices: &mut Vec<troe_machine::NativeVirtioBlock>,
) -> Result<StateFs<troe_machine::NativeVirtioBlock>, ()> {
    let state_selector = RegionSelector::parse(STATEFS_SELECTOR).map_err(|_| ())?;
    let state_region = take_transaction_region(devices, state_selector)?;
    StateFs::mount(state_region).map_err(|_| ())
}

#[cfg(feature = "acceptance-probes")]
pub(crate) fn recover_native_statefs(
    devices: &mut Vec<troe_machine::NativeVirtioBlock>,
) -> Result<Option<Box<dyn FileSystemProvider>>, ()> {
    let statefs = mount_native_statefs(devices)?;
    let mut statefs = statefs;
    probe_native_statefs_mutation(&mut statefs)?;
    Ok(Some(Box::new(statefs)))
}

#[cfg(not(feature = "acceptance-probes"))]
pub(crate) fn recover_native_statefs(
    devices: &mut Vec<troe_machine::NativeVirtioBlock>,
) -> Option<Box<dyn FileSystemProvider>> {
    mount_native_statefs(devices)
        .ok()
        .map(|statefs| Box::new(statefs) as Box<dyn FileSystemProvider>)
}

#[cfg(feature = "acceptance-probes")]
pub(crate) fn probe_native_statefs_mutation(
    statefs: &mut StateFs<troe_machine::NativeVirtioBlock>,
) -> Result<(), ()> {
    let mut prior = [0_u8; 8];
    let next = match statefs.read_file(STATE_PATH, 0, &mut prior) {
        Ok(8) => u64::from_le_bytes(prior).checked_add(1).ok_or(())?,
        Err(troe_fs_api::FsError::NotFound) => 1,
        _ => return Err(()),
    };
    statefs
        .write_file(STATE_PATH, &next.to_le_bytes())
        .map_err(|_| ())?;
    let mut verified = [0_u8; 8];
    if statefs
        .read_file(STATE_PATH, 0, &mut verified)
        .map_err(|_| ())?
        != 8
        || u64::from_le_bytes(verified) != next
    {
        return Err(());
    }
    if !troe_machine::write(b"native statefs: mutation committed and flushed\n") {
        return Err(());
    }
    Ok(())
}

pub(crate) fn take_transaction_region(
    devices: &mut Vec<troe_machine::NativeVirtioBlock>,
    selector: RegionSelector,
) -> Result<BlockRegion<troe_machine::NativeVirtioBlock>, ()> {
    let discovery_limits = BlockLimits::new(32, 16 * 1024, 1).map_err(|_| ())?;
    let gpt_limits = GptLimits::new(128, 16 * 1024, 4).map_err(|_| ())?;
    let mut selected = None;
    for (index, device) in devices.iter_mut().enumerate() {
        let geometry = device.geometry();
        if geometry.logical_block_bytes() != 512
            || !geometry.supports_flush()
            || device.profile().read_only()
        {
            continue;
        }
        let Ok(mut whole) =
            BlockRegion::whole_device(device, BlockAccess::ReadOnly, discovery_limits)
        else {
            continue;
        };
        let Ok(gpt) = discover(&mut whole, gpt_limits) else {
            continue;
        };
        if gpt.disk_guid().disk_bytes() != selector.disk_guid() {
            continue;
        }
        let Some(partition) =
            gpt.partition_by_unique_guid(GptGuid::from_disk_bytes(selector.partition_guid()))
        else {
            continue;
        };
        if partition.type_guid().disk_bytes() != selector.partition_type_guid()
            || partition.block_count() != TRANSACTION_BLOCKS
        {
            continue;
        }
        if selected.replace((index, partition.first_lba())).is_some() {
            return Err(());
        }
    }
    let (index, first_lba) = selected.ok_or(())?;
    let device = devices.remove(index);
    let limits = BlockLimits::new(1, 512, 1).map_err(|_| ())?;
    BlockRegion::new(
        device,
        first_lba,
        TRANSACTION_BLOCKS,
        BlockAccess::ReadWrite,
        limits,
    )
    .map_err(|_| ())
}

pub(crate) fn native_activation_limits() -> Result<ActivationLimits, ()> {
    let block = BlockLimits::new(8, 4096, 1).map_err(|_| ())?;
    let gpt = GptLimits::new(128, 16 * 1024, 16).map_err(|_| ())?;
    let ext4 =
        Ext4Limits::new(8, 64, 256, 4096, u64::from(u32::MAX) * 4096, 4096, 64).map_err(|_| ())?;
    let fat32 = Fat32Limits::new(u32::MAX, 4096, u64::from(u32::MAX), 4096, 64).map_err(|_| ())?;
    Ok(ActivationLimits::new(block, gpt, ext4, fat32))
}

#[derive(Clone, Copy)]
pub(crate) enum NativeRootMode {
    Recovery,
    ReadOnly,
    ReadWrite,
}

impl NativeRootMode {
    pub(crate) const fn summary(self) -> &'static str {
        match self {
            Self::Recovery => "recovery root (read-only)",
            Self::ReadOnly => "/vol/root (read-only)",
            Self::ReadWrite => "/vol/root (read-write)",
        }
    }

    const fn boot_label(self) -> &'static str {
        match self {
            Self::Recovery => "Mounting recovery root read-only",
            Self::ReadOnly => "Mounting /vol/root read-only",
            Self::ReadWrite => "Mounting /vol/root read-write",
        }
    }
}

pub(crate) fn append_internal_storage_report(
    report: &mut String,
    generation: NativeGenerationState,
    statefs_mounted: bool,
) -> Result<(), ()> {
    let activation = RegionSelector::parse(PERSISTENCE_SELECTOR).map_err(|_| ())?;
    let statefs = RegionSelector::parse(STATEFS_SELECTOR).map_err(|_| ())?;
    report.push_str("internal activation disk=");
    write_storage_identity(report, activation.disk_guid())?;
    report.push_str(" partition=");
    write_storage_identity(report, activation.partition_guid())?;
    report.push_str(" type=");
    write_storage_identity(report, activation.partition_type_guid())?;
    writeln!(report, " state={}", generation.name()).map_err(|_| ())?;
    report.push_str("internal statefs disk=");
    write_storage_identity(report, statefs.disk_guid())?;
    report.push_str(" partition=");
    write_storage_identity(report, statefs.partition_guid())?;
    report.push_str(" type=");
    write_storage_identity(report, statefs.partition_type_guid())?;
    writeln!(
        report,
        " state={}",
        if statefs_mounted {
            "mounted"
        } else {
            "missing"
        }
    )
    .map_err(|_| ())?;
    if report.len() > MAX_STORAGE_REPORT_BYTES {
        return Err(());
    }
    Ok(())
}

pub(crate) fn write_storage_identity(report: &mut String, identity: [u8; 16]) -> Result<(), ()> {
    for byte in identity {
        write!(report, "{byte:02x}").map_err(|_| ())?;
    }
    Ok(())
}

pub(crate) fn activate_native_storage(
    accounting: &OwnedAccounting,
    namespace: &mut Namespace,
    console: &mut dyn Output,
) -> NativeRootMode {
    let limits = native_activation_limits()
        .unwrap_or_else(|()| fatal(b"fatal: invalid native storage limits\n"));
    let devices = core::mem::take(&mut *accounting.native_blocks.borrow_mut());
    let activation = prepare_mounts(&accounting.boot_mount_manifest, devices, limits)
        .unwrap_or_else(|_| fatal(b"fatal: native storage activation failed\n"));
    let desired_system_available = activation.desired_system_available();
    let root_mode = activation
        .mounts()
        .iter()
        .find(|mount| mount.path() == "/vol/root")
        .map_or(NativeRootMode::Recovery, |mount| {
            if mount.is_writable() {
                NativeRootMode::ReadWrite
            } else {
                NativeRootMode::ReadOnly
            }
        });
    let root_mounted = !matches!(root_mode, NativeRootMode::Recovery);
    let mut storage_report = String::new();
    let report_capacity = activation
        .report()
        .len()
        .checked_add(STORAGE_REPORT_EXTENSION_BYTES)
        .unwrap_or_else(|| fatal(b"fatal: native storage diagnostic overflow\n"));
    if storage_report.try_reserve_exact(report_capacity).is_err() {
        fatal(b"fatal: cannot retain native storage diagnostic\n");
    }
    storage_report.push_str(activation.report());
    accounting
        .runtime_mounts
        .borrow_mut()
        .configure(
            &accounting.boot_mount_manifest,
            activation.into_mounts(),
            namespace,
        )
        .unwrap_or_else(|()| fatal(b"fatal: cannot configure native mount registry\n"));
    let statefs_mounted = accounting.native_statefs.borrow().is_some();
    if let Some(statefs) = accounting.native_statefs.borrow_mut().take() {
        namespace
            .mount_writable("/vol/state", statefs)
            .unwrap_or_else(|_| fatal(b"fatal: cannot attach native state filesystem\n"));
    }
    append_internal_storage_report(
        &mut storage_report,
        accounting.native_generation,
        statefs_mounted,
    )
    .unwrap_or_else(|()| fatal(b"fatal: cannot extend native storage diagnostic\n"));
    namespace
        .set_system_file("/sys/storage", storage_report.as_bytes())
        .unwrap_or_else(|_| fatal(b"fatal: cannot publish native storage diagnostic\n"));
    if desired_system_available
        && root_mounted
        && accounting.native_generation.desired_system_available()
    {
        if write_boot_status(console, root_mode.boot_label(), true).is_err() {
            fatal(b"fatal: native storage diagnostic failed\n");
        }
        root_mode
    } else {
        let recovery = NativeRootMode::Recovery;
        if write_boot_status(console, recovery.boot_label(), true).is_err() {
            fatal(b"fatal: native storage diagnostic failed\n");
        }
        recovery
    }
}
