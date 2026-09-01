//! Compile-time limits, embedded images, and the invariants that pin them.
//!
//! Every fixed size the owned machine reserves is named here: the boot arena
//! and heap, the three kernel task stacks, the resident process ceiling, the
//! isolated-task page budget, and the acceptance IPC sample counts. The
//! embedded root filesystem, persistence selectors, and initial activation
//! record are linked in from `assets/`.
//!
//! ADR 0035 Phase E wants `ROOTFS`, `PERSISTENCE_SELECTOR`, `STATEFS_SELECTOR`,
//! and `INITIAL_ACTIVATION` out of the kernel image: they are filesystem and
//! volume-selection content the privileged address space carries only because
//! the kernel still mounts them itself.

use troe_memory::BASE_PAGE_SIZE;

/// Directories the embedded image supplies but does not own, because
/// manifest-selected volumes mount beneath them.
pub(crate) const EMBEDDED_MOUNT_ROOTS: &[&str] = &["/vol"];

#[cfg(target_arch = "x86_64")]
pub(crate) const ROOTFS: &[u8] = include_bytes!("../../assets/root-x86_64.kefs");

#[cfg(target_arch = "aarch64")]
pub(crate) const ROOTFS: &[u8] = include_bytes!("../../assets/root-aarch64.kefs");

pub(crate) const PERSISTENCE_SELECTOR: &[u8] = include_bytes!("../../assets/persist.prgn");

pub(crate) const STATEFS_SELECTOR: &[u8] = include_bytes!("../../assets/state.prgn");

pub(crate) const INITIAL_ACTIVATION: &[u8] = include_bytes!("../../assets/system.sact");

pub(crate) const OWNED_HEAP_BYTES: u64 = 6 * 1024 * 1024;

pub(crate) const PAGE_TABLE_BYTES: u64 = 2 * 1024 * 1024;

pub(crate) const OWNED_STACK_BYTES: u64 = 128 * 1024;

pub(crate) const EXCEPTION_STACK_BYTES: u64 = 16 * 1024;

pub(crate) const TASK_STACK_BYTES: u64 = 64 * 1024;

pub(crate) const SERVER_TASK_STACK_BYTES: u64 = 128 * 1024;

pub(crate) const SHELL_TASK_STACK_BYTES: u64 = 128 * 1024;

pub(crate) const TASK_GUARD_BYTES: u64 = BASE_PAGE_SIZE;

pub(crate) const TASK_STACK_PAGES: u64 = 16;

pub(crate) const SERVER_TASK_STACK_PAGES: u64 = 32;

pub(crate) const SHELL_TASK_STACK_PAGES: u64 = 32;

pub(crate) const TASK_STACK_COUNT: usize = 3;

pub(crate) const SHELL_SCHEDULER_SLOT: u32 = 65_536;

pub(crate) const RESIDENT_PROCESS_FIRST_SLOT: u32 = 3;

pub(crate) const RESIDENT_PROCESS_CAPACITY: usize = troe_task::MAX_TASKS - 3;

pub(crate) const INITIAL_RESIDENT_PROCESS_CAPACITY: usize = 64;

pub(crate) const RESIDENT_PROCESS_LOG_BYTES: usize = 64 * 1024;

// Nested children run on the launching task's kernel stack: pumping a child
// re-enters `ResidentApplication::step`, so nesting costs one frame per
// level. `step` keeps only the pump on that recursive path and leaves its
// message buffers and service handlers in `run_execution_slice`, which is
// never recursive, so a level costs about 1 KiB and the one running slice
// about 53 KiB. Eight levels stay near two thirds of
// SHELL_TASK_STACK_BYTES on both architectures.
pub(crate) const MAX_LAUNCH_DEPTH: u32 = 8;

pub(crate) const RESIDENT_APPLICATION_TIMESLICE_MILLISECONDS: u32 = 10;

pub(crate) const RESIDENT_SERVICE_CALLS_PER_STEP: usize = 4;

pub(crate) const RESIDENT_POLL_MILLISECONDS: u32 = 10;

pub(crate) const ISOLATED_TABLE_PAGES: u64 = PAGE_TABLE_BYTES / BASE_PAGE_SIZE;

pub(crate) const ISOLATED_CODE_PAGES: u64 = 1;

pub(crate) const ISOLATED_DATA_PAGES: u64 = 1;

pub(crate) const ISOLATED_STACK_PAGES: u64 = 4;

pub(crate) const ISOLATED_PRIVATE_PAGES: u64 =
    ISOLATED_CODE_PAGES + ISOLATED_DATA_PAGES + ISOLATED_STACK_PAGES;

pub(crate) const ISOLATED_RESOURCE_PAGES: u64 = ISOLATED_TABLE_PAGES + ISOLATED_PRIVATE_PAGES;

pub(crate) const STAGE6_USER_REGION_LIMIT: usize = 8;

pub(crate) const STAGE6_USER_REGIONS: usize = 3;

pub(crate) const APPLICATION_INTERFACE_ECHO: u32 = 1;

pub(crate) const APPLICATION_TIMESLICE_MILLISECONDS: u32 = 50;

pub(crate) const APPLICATION_DATAGRAM_WAIT_MILLISECONDS: u64 = 4_000;

#[cfg(feature = "acceptance-probes")]
pub(crate) const IPC_BASELINE_WARMUP_CALLS: usize = 64;

#[cfg(feature = "acceptance-probes")]
pub(crate) const IPC_BASELINE_SAMPLES: usize = 256;

#[cfg(feature = "acceptance-probes")]
pub(crate) const IPC_ISOLATED_SERVICE_CALL_LIMIT: u16 = 1536;

#[cfg(feature = "acceptance-probes")]
pub(crate) const DIAGNOSTICS_SERVER_MAX_RETAINED_REQUESTS: usize = 1;

#[cfg(feature = "acceptance-probes")]
pub(crate) const DIAGNOSTICS_SERVER_MAX_CONTEXTS: usize = 1;

pub(crate) const USER_CODE_BASE: u64 = 0x0000_4000_0000_0000;

pub(crate) const USER_DATA_BASE: u64 = USER_CODE_BASE + BASE_PAGE_SIZE;

pub(crate) const USER_STACK_BASE: u64 = USER_CODE_BASE + 0x1_0000;

pub(crate) const USER_UNMAPPED_BASE: u64 = USER_CODE_BASE + 0x1000_0000;

pub(crate) const ISOLATED_MESSAGE: &[u8] = b"stage6 copied request";

pub(crate) const BOOT_ARENA_PAGES: usize = ((OWNED_HEAP_BYTES
    + PAGE_TABLE_BYTES
    + OWNED_STACK_BYTES
    + EXCEPTION_STACK_BYTES
    + TASK_STACK_BYTES
    + SERVER_TASK_STACK_BYTES
    + SHELL_TASK_STACK_BYTES
    + 2 * TASK_GUARD_BYTES * TASK_STACK_COUNT as u64)
    / BASE_PAGE_SIZE) as usize;

pub(crate) const BOOT_STATUS_WIDTH: usize = 54;

pub(crate) const BOOT_MEMORY_LABEL: &str = "Initializing memory and protection";

pub(crate) const BOOT_DEVICES_LABEL: &str = "Starting devices and input";

pub(crate) const BOOT_RUNTIME_LABEL: &str = "Starting task and application runtime";

const _: () = assert!(TASK_STACK_BYTES == TASK_STACK_PAGES * BASE_PAGE_SIZE);

const _: () = assert!(SERVER_TASK_STACK_BYTES == SERVER_TASK_STACK_PAGES * BASE_PAGE_SIZE);

const _: () = assert!(SHELL_TASK_STACK_BYTES == SHELL_TASK_STACK_PAGES * BASE_PAGE_SIZE);

const _: () = assert!(TASK_GUARD_BYTES == BASE_PAGE_SIZE);

const _: () = assert!(TASK_STACK_COUNT == 3);

const _: () = assert!(STAGE6_USER_REGIONS <= STAGE6_USER_REGION_LIMIT);
