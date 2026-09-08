//! UEFI-bootstrapped owned-machine image with a staged Stage 7 load boundary.
//!
//! This file is the composition root: crate attributes, the module tree, the
//! `#[entry]` point, and the panic handler. Every other authority the kernel
//! holds is named by the module that holds it.
//!
//! `ipc` contains the synthetic ABI 1.3 acceptance composition; `deferred`
//! and `service` retain compatibility service routing. Product supervision,
//! network, storage, and namespace authority are named by their own modules.
#![cfg_attr(target_os = "uefi", no_std)]
#![cfg_attr(target_os = "uefi", no_main)]
#![forbid(unsafe_code)]

#[cfg(not(target_os = "uefi"))]
fn main() {
    println!("build with --target x86_64-unknown-uefi or aarch64-unknown-uefi");
}

#[cfg(target_os = "uefi")]
extern crate alloc;

#[cfg(target_os = "uefi")]
mod artifacts;
#[cfg(all(target_os = "uefi", feature = "acceptance-probes"))]
mod boot_baseline;
#[cfg(target_os = "uefi")]
mod console;
#[cfg(target_os = "uefi")]
mod deferred;
#[cfg(target_os = "uefi")]
mod handles;
#[cfg(target_os = "uefi")]
mod handoff;
#[cfg(target_os = "uefi")]
mod invocation;
#[cfg(all(target_os = "uefi", feature = "acceptance-probes"))]
mod ipc;
#[cfg(target_os = "uefi")]
mod kex;
#[cfg(target_os = "uefi")]
mod limits;
#[cfg(target_os = "uefi")]
mod machine;
#[cfg(target_os = "uefi")]
mod memory;
#[cfg(target_os = "uefi")]
mod mounts;
#[cfg(target_os = "uefi")]
mod namespace;
#[cfg(target_os = "uefi")]
mod nested;
#[cfg(target_os = "uefi")]
mod network;
#[cfg(target_os = "uefi")]
mod probes;
#[cfg(target_os = "uefi")]
mod requirements;
#[cfg(target_os = "uefi")]
mod resident;
#[cfg(target_os = "uefi")]
mod runtime;
#[cfg(target_os = "uefi")]
mod service;
#[cfg(target_os = "uefi")]
mod session;
#[cfg(target_os = "uefi")]
mod shell;
#[cfg(target_os = "uefi")]
mod storage;
#[cfg(target_os = "uefi")]
mod supervision;
#[cfg(target_os = "uefi")]
mod support;

#[cfg(target_os = "uefi")]
use crate::console::FirmwareConsole;
#[cfg(target_os = "uefi")]
use crate::handoff::{post_handoff, prepare_handoff, write_boot_status};
#[cfg(target_os = "uefi")]
use crate::support::{fatal, write_all};
#[cfg(target_os = "uefi")]
use alloc::boxed::Box;
#[cfg(target_os = "uefi")]
use core::panic::PanicInfo;
#[cfg(target_os = "uefi")]
use uefi::prelude::*;

#[cfg(target_os = "uefi")]
#[entry]
fn main() -> Status {
    if uefi::helpers::init().is_err() {
        return Status::DEVICE_ERROR;
    }
    if troe_machine::validate_selected_platform().is_err() {
        let mut firmware_console = FirmwareConsole;
        if let Some(failure) = troe_machine::platform_discovery_failure() {
            let _ignored = write_all(&mut firmware_console, b"platform discovery failed: ");
            let _ignored = write_all(&mut firmware_console, failure.label().as_bytes());
            let _ignored = write_all(&mut firmware_console, b"\n");
        }
        return Status::ABORTED;
    }
    let Ok(platform_source) = troe_machine::selected_platform_source() else {
        return Status::ABORTED;
    };
    let mut firmware_console = FirmwareConsole;
    if let Ok(prepared) = prepare_handoff(&mut firmware_console, platform_source) {
        let stack = prepared.boot_memory.stack;
        let prepared = Box::leak(Box::new(prepared));
        match troe_machine::enter_owned_stack(stack, prepared, post_handoff) {
            Err(_) => Status::ABORTED,
            Ok(never) => match never {},
        }
    } else {
        let _ignored = write_boot_status(&mut firmware_console, "TROE initialization", false);
        Status::ABORTED
    }
}

#[cfg(target_os = "uefi")]
#[panic_handler]
fn panic(_information: &PanicInfo<'_>) -> ! {
    fatal(b"fatal: kernel panic\n")
}
