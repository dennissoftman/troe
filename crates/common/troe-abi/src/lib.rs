//! Stable, allocation-free application service protocols.
#![no_std]
#![forbid(unsafe_code)]

#[cfg(test)]
extern crate std;

use core::str;

/// Application ABI major implemented by the current kernel and SDK.
pub const ABI_MAJOR: u16 = 1;
/// Highest compatible application ABI minor implemented by the current kernel and SDK.
pub const ABI_MINOR: u16 = 2;
/// Maximum complete request or reply crossing the application call gate.
pub const MAX_MESSAGE_BYTES: usize = 4 * 1024;
/// Maximum service payload after the required two-byte opcode.
pub const MAX_SERVICE_PAYLOAD_BYTES: usize = MAX_MESSAGE_BYTES - 2;

pub mod clock_control;
pub mod command;
pub mod datagram;
pub mod diagnostics;
pub mod exit;
pub mod filesystem;
pub mod filesystem_mutation;
pub mod heap_growth;
pub mod icmp_echo;
pub mod interface;
pub mod network_configuration;
pub mod network_observation;
pub mod pipe;
pub mod private_memory;
pub mod process_launch;
pub mod process_observation;
pub mod random;
pub mod reply;
pub mod requirements;
pub mod server;
pub mod shell_script;
pub mod stream;
pub mod tcp_connect;
pub mod timer;
pub mod timezone;
pub mod volume_control;
pub mod wall_clock;
