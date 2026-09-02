//! The firmware handoff: everything that runs while boot services are alive.
//!
//! `prepare_handoff` reserves the owned arena, captures the framebuffer and an
//! entropy seed, reads the boot mount manifest, and builds the kernel mapping
//! plan. `post_handoff` runs on the owned stack once boot services have exited
//! and `complete_handoff` installs the owned memory map. After that point no
//! UEFI boot service may be called again.

pub(crate) mod reservation;

use crate::console::{FirmwareConsole, NativeConsole};
use crate::handoff::reservation::{
    BootMemory, build_mapping_plan, capture_framebuffer, framebuffer_device_range,
    normalize_final_map, reserve_and_install_heap,
};
use crate::limits::{BOOT_DEVICES_LABEL, BOOT_MEMORY_LABEL, BOOT_STATUS_WIDTH};
use crate::machine::{OwnedAccounting, run_owned};
use crate::mounts::RuntimeMountRegistry;
use crate::service::clock::firmware_unix_seconds;
use crate::storage::initialize_native_blocks;
use crate::support::{fatal, usize_as_u64, write_all};
use alloc::rc::Rc;
use alloc::string::String;
use core::cell::RefCell;
use troe_console::FramebufferDescriptor;
use troe_core::Output;
use troe_driver::InputQueueConfig;
use troe_fmt_bmnt::{BootMountManifest, MAX_MANIFEST_BYTES, parse_manifest};
use troe_fmt_scfg::{MemoryPolicy, SystemConfig};
use troe_memory::{FrameAllocator, PhysicalRange};
use troe_random::{Generator as RandomGenerator, SEED_BYTES as RANDOM_SEED_BYTES};
use uefi::boot;
use uefi::mem::memory_map::MemoryMapOwned;
use uefi::prelude::*;
use uefi::proto::rng::{Rng, RngAlgorithmType};

pub(crate) struct PreparedHandoff {
    image_layout: troe_machine::ImageLayout,
    pub(crate) boot_memory: BootMemory,
    framebuffer: Option<FramebufferDescriptor>,
    firmware_wall_seconds: Option<u64>,
    boot_mount_manifest: Option<BootMountManifest>,
    entropy_seed: [u8; RANDOM_SEED_BYTES],
}

pub(crate) fn prepare_handoff(
    console: &mut FirmwareConsole,
    platform_source: troe_machine::PlatformSource,
) -> Result<PreparedHandoff, ()> {
    write_all(console, b"\x1b[2J\x1b[H")?;
    match platform_source {
        troe_machine::PlatformSource::Acpi => {
            write_all(console, b"platform discovery: ACPI validated\n")?;
        }
        troe_machine::PlatformSource::Fdt => {
            write_all(console, b"platform discovery: FDT validated\n")?;
        }
        troe_machine::PlatformSource::Fixed => {}
    }

    let image_layout = troe_machine::loaded_image_layout().map_err(|_| ())?;
    let framebuffer = capture_framebuffer();
    let boot_memory = reserve_and_install_heap()?;
    let boot_mount_manifest = load_boot_mount_manifest()?;
    troe_machine::initialize_console();
    if !troe_machine::initialize_monotonic_clock() {
        return Err(());
    }
    let firmware_wall_seconds = firmware_unix_seconds();
    let entropy_seed = capture_entropy_seed()?;
    Ok(PreparedHandoff {
        image_layout,
        boot_memory,
        framebuffer,
        firmware_wall_seconds,
        boot_mount_manifest: Some(boot_mount_manifest),
        entropy_seed,
    })
}

pub(crate) fn capture_entropy_seed() -> Result<[u8; RANDOM_SEED_BYTES], ()> {
    let handle = boot::get_handle_for_protocol::<Rng>().map_err(|_| ())?;
    let mut rng = boot::open_protocol_exclusive::<Rng>(handle).map_err(|_| ())?;
    let mut seed = [0_u8; RANDOM_SEED_BYTES];
    if rng
        .get_rng(Some(RngAlgorithmType::ALGORITHM_RAW), &mut seed)
        .is_err()
    {
        rng.get_rng(None, &mut seed).map_err(|_| ())?;
    }
    if seed.iter().all(|byte| *byte == 0) {
        return Err(());
    }
    Ok(seed)
}

pub(crate) fn load_boot_mount_manifest() -> Result<BootMountManifest, ()> {
    let protocol = boot::get_image_file_system(boot::image_handle()).map_err(|_| ())?;
    let mut filesystem = uefi::fs::FileSystem::new(protocol);
    let path = cstr16!("\\EFI\\BOOT\\VOLUMES.BMT");
    let file_bytes =
        usize::try_from(filesystem.metadata(path).map_err(|_| ())?.file_size()).map_err(|_| ())?;
    if file_bytes > MAX_MANIFEST_BYTES {
        return Err(());
    }
    let bytes = filesystem.read(path).map_err(|_| ())?;
    if bytes.len() != file_bytes {
        return Err(());
    }
    parse_manifest(&bytes).map_err(|_| ())
}

pub(crate) fn post_handoff(prepared: &mut PreparedHandoff) -> ! {
    let final_map = troe_machine::exit_boot_services_after_protocols();
    troe_machine::mark_firmware_exited();
    troe_machine::take_interrupt_ownership();
    // Firmware built on Trusted Firmware hands a boot loader EL2, not the
    // EL1 every system register below assumes.
    if troe_machine::descend_to_kernel_execution_level().is_err() {
        fatal(b"fatal: unsupported firmware execution level\n");
    }
    let stack_pointer = usize_as_u64(troe_machine::current_stack_pointer());
    if !prepared.boot_memory.stack.contains(stack_pointer) {
        fatal(b"fatal: active stack is not kernel-owned\n");
    }
    let accounting = complete_handoff(prepared, final_map)
        .unwrap_or_else(|()| fatal(b"fatal: post-handoff initialization failed\n"));
    run_owned(accounting)
}

pub(crate) fn complete_handoff(
    prepared: &mut PreparedHandoff,
    final_map: MemoryMapOwned,
) -> Result<OwnedAccounting, ()> {
    let reservations = [prepared.boot_memory.arena];
    let normalized = normalize_final_map(&final_map, &reservations)?;
    let framebuffer = prepared.framebuffer;
    let mapping_plan = build_mapping_plan(
        &final_map,
        &prepared.image_layout,
        &prepared.boot_memory,
        framebuffer,
    )?;
    // The final-map buffer is LoaderData recorded as reserved in the map.
    // It must remain live because boot services can no longer free it.
    core::mem::forget(final_map);

    let map = normalized.stats();
    let mut frames = FrameAllocator::from_map(&normalized).map_err(|_| ())?;
    let null_page = PhysicalRange::from_pages(0, 1).map_err(|_| ())?;
    frames.reserve_range(null_page).map_err(|_| ())?;
    if let Some(framebuffer) = framebuffer {
        frames
            .reserve_range(framebuffer_device_range(framebuffer)?)
            .map_err(|_| ())?;
    }
    let probe = frames.allocate().map_err(|_| ())?;
    frames.free(probe).map_err(|_| ())?;
    if !troe_machine::probe_allocation_failure() {
        return Err(());
    }
    troe_machine::install_exception_vectors(prepared.boot_memory.exception_stack)
        .map_err(|_| ())?;
    let mmu = troe_machine::install_mmu(&mapping_plan, prepared.boot_memory.page_tables)
        .map_err(|_| ())?;
    if mmu.mapped_pages == 0 || mmu.table_pages == 0 {
        return Err(());
    }
    if !write_machine_boot_status(BOOT_MEMORY_LABEL, true) {
        return Err(());
    }
    let boot_mount_manifest = prepared.boot_mount_manifest.as_ref().ok_or(())?;
    troe_machine::initialize_input_interrupts(InputQueueConfig::standard()).map_err(|_| ())?;
    let native = initialize_native_blocks(boot_mount_manifest)?;
    let boot_mount_manifest = prepared.boot_mount_manifest.take().ok_or(())?;
    if !write_machine_boot_status(BOOT_DEVICES_LABEL, true) {
        return Err(());
    }
    let memory_policy = native
        .config
        .as_ref()
        .map_or_else(MemoryPolicy::standard, SystemConfig::memory);
    let entropy_seed = core::mem::replace(&mut prepared.entropy_seed, [0_u8; RANDOM_SEED_BYTES]);
    let random = Rc::new(RefCell::new(
        RandomGenerator::new(entropy_seed).map_err(|_| ())?,
    ));
    Ok(OwnedAccounting {
        map,
        frames,
        #[cfg(feature = "acceptance-probes")]
        execute_probe_address: usize::try_from(prepared.boot_memory.heap.start())
            .map_err(|_| ())?,
        task_stacks: prepared.boot_memory.task_stacks,
        framebuffer,
        kernel_runtime: prepared.boot_memory.arena,
        kernel_plan: mapping_plan,
        native_blocks: RefCell::new(native.blocks),
        native_statefs: RefCell::new(native.statefs),
        native_generation: native.generation,
        selected_config: native.config,
        memory_policy,
        application_committed_pages: 0,
        private_metadata_bytes: 0,
        random,
        firmware_wall_seconds: prepared.firmware_wall_seconds,
        boot_mount_manifest,
        runtime_mounts: Rc::new(RefCell::new(RuntimeMountRegistry::empty())),
        session_timezone: RefCell::new(None),
    })
}

pub(crate) fn write_boot_status(output: &mut dyn Output, label: &str, ok: bool) -> Result<(), ()> {
    let mut line = String::from(" * ");
    line.push_str(label);
    line.push(' ');
    while line.len() < BOOT_STATUS_WIDTH {
        line.push('.');
    }
    if ok {
        line.push_str(" [ OK ]\n");
    } else {
        line.push_str(" [ ERR ]\n");
    }
    write_all(output, line.as_bytes())
}

pub(crate) fn write_machine_boot_status(label: &str, ok: bool) -> bool {
    write_boot_status(&mut NativeConsole, label, ok).is_ok()
}
