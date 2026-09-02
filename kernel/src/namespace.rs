//! Composition of the boot namespace the shell and applications observe.
//!
//! The composition root retains the concrete namespace because mounting
//! providers and projecting generated state are authorities a client of the
//! namespace must not hold.
//!
//! ADR 0035 Phase D removes namespace policy from the kernel. `compose_namespace`
//! is the decision this module makes on the kernel's behalf today: which
//! providers exist, where the embedded image is rooted, and which generated
//! files `/sys` publishes.
//!
//! The composition itself moves to the storage server. What remains here is
//! the kernel reaching a namespace it no longer owns, which is part of the
//! `kernel/src/client.rs` ADR 0035 names.

use crate::limits::{EMBEDDED_MOUNT_ROOTS, ROOTFS};
use crate::machine::OwnedAccounting;
use crate::storage::{NativeRootMode, activate_native_storage};
use crate::support::{architecture, fatal, write_all};
use alloc::boxed::Box;
use alloc::string::String;
use core::fmt::Write as _;
use troe_core::Output;
use troe_fs_kefs::Kefs;
use troe_fs_ramfs::{RamFs, RamFsQuota};
use troe_namespace::Namespace;

/// The architecture name with its trailing newline, for `/sys/arch`.
pub(crate) fn architecture_line() -> String {
    let mut line = String::from(architecture());
    line.push('\n');
    line
}

pub(crate) fn compose_namespace(
    accounting: &OwnedAccounting,
    console: &mut dyn Output,
) -> (Namespace, NativeRootMode) {
    let mut namespace = Namespace::new();
    if namespace
        .mount_writable("/tmp", Box::new(RamFs::new(RamFsQuota::default())))
        .is_err()
    {
        fatal(b"fatal: cannot mount the writable filesystem\n");
    }
    let Ok(embedded) = Kefs::parse(ROOTFS) else {
        fatal(b"fatal: cannot mount embedded root\n");
    };
    let embedded = embedded.into_mounts(EMBEDDED_MOUNT_ROOTS);
    for path in embedded.directories {
        if namespace.add_read_only_dir(&path).is_err() {
            fatal(b"fatal: cannot mount embedded root\n");
        }
    }
    for (path, bytes) in embedded.files {
        if namespace.add_read_only_file(&path, &bytes).is_err() {
            fatal(b"fatal: cannot mount embedded root\n");
        }
    }
    for (path, view) in embedded.mounts {
        if namespace.mount_read_only(&path, Box::new(view)).is_err() {
            fatal(b"fatal: cannot mount embedded root\n");
        }
    }
    let root_mode = activate_native_storage(accounting, &mut namespace, console);
    attach_configuration(&mut namespace, root_mode, console);
    *accounting.session_timezone.borrow_mut() = resolve_session_timezone(&mut namespace, console);
    (namespace, root_mode)
}

/// Subtree of the persistent root holding configuration bytes.
const CONFIGURATION_STORE_PATH: &str = "/vol/root/config";

/// Present configuration at `/config`, backed by the persistent root.
///
/// A path names an access point rather than a place bytes live, so
/// `/config` is where configuration is read and written while the bytes sit
/// on the journalled root volume that ADR 0055 already made durable. The
/// subtree is created on first boot when the root is writable.
///
/// A recovery boot has no root to alias, and a read-only root presents
/// configuration without accepting edits. Both leave a configured value
/// reading as absent, which is the same ordinary case as a machine nobody
/// has configured.
fn attach_configuration(
    namespace: &mut Namespace,
    root_mode: NativeRootMode,
    console: &mut dyn Output,
) {
    if matches!(root_mode, NativeRootMode::Recovery) {
        return;
    }
    if matches!(root_mode, NativeRootMode::ReadWrite)
        && namespace.metadata("/", CONFIGURATION_STORE_PATH).is_err()
    {
        let _ignored = namespace.create_directory("/", CONFIGURATION_STORE_PATH);
    }
    if namespace
        .mount_alias("/config", "/vol/root", "/config")
        .is_err()
    {
        // The root mounted but configuration did not attach, which is not
        // the ordinary absent case and would otherwise look like a machine
        // nobody configured.
        let _ignored = write_all(console, b"/config: not attached; configuration is absent\n");
    }
}

/// Path holding the operator's POSIX zone string, per ADR 0068.
const SESSION_TIMEZONE_PATH: &str = "/config/timezone";

/// Resolve the session's zone entry from desired state.
///
/// Returns the complete `TZ=VALUE` entry to compose, or `None` to keep the
/// conventional `UTC0`. An absent file, an absent `/config` provider, and
/// recovery are the same ordinary case. A file that does not parse is
/// reported and refused: booting into a silently wrong zone would be worse
/// than booting into UTC, and refusing to boot over a typo worse still.
fn resolve_session_timezone(namespace: &mut Namespace, console: &mut dyn Output) -> Option<String> {
    // One trailing newline is allowed, so a file written by a shell
    // redirection is accepted. The grammar and its refusals live in the
    // ABI, where they are tested; the kernel binary has no test harness.
    let bytes = namespace
        .read_file_bounded(
            "/",
            SESSION_TIMEZONE_PATH,
            troe_abi::timezone::MAX_TZ_BYTES + 2,
        )
        .ok()?;
    let text = match troe_abi::timezone::parse_configuration(&bytes) {
        Ok(text) => text,
        Err(error) => {
            let mut report = String::new();
            if writeln!(&mut report, "{SESSION_TIMEZONE_PATH}: {error:?}; using UTC").is_ok() {
                let _ignored = write_all(console, report.as_bytes());
            }
            return None;
        }
    };
    let mut entry = String::new();
    entry
        .try_reserve_exact(troe_abi::command::TIMEZONE_NAME.len() + 1 + text.len())
        .ok()?;
    entry.push_str(troe_abi::command::TIMEZONE_NAME);
    entry.push('=');
    entry.push_str(text);
    Some(entry)
}
