#![no_std]
#![no_main]

#[path = "../../common.rs"]
mod common;

use core::fmt::Write as _;
use troe_kex_sdk::{CommandContext, INVOCATION_BUFFER_BYTES, entry, exit};

fn main(command: &mut CommandContext) -> u32 {
    let mut invocation_bytes = [0_u8; INVOCATION_BUFFER_BYTES];
    let Ok(invocation) = command.invocation(&mut invocation_bytes) else {
        return exit::FAILURE;
    };
    let Ok(mut network) = command.network_observation() else {
        return exit::DENIED;
    };
    if invocation.len() == 1 {
        let status = match network.status() {
            Ok(status) => status,
            Err(error) => return common::network_failure(&mut command.stderr(), "net", error),
        };
        return if common::write_network_status(&mut command.stdout(), status).is_err() {
            common::stream_failure(&mut command.stderr(), "net")
        } else {
            exit::SUCCESS
        };
    }
    if invocation.len() != 2 || invocation.argument(1) != Some("stats") {
        return common::usage(&mut command.stderr(), "net", b"net | net stats");
    }
    let stats = match network.stats() {
        Ok(stats) => stats,
        Err(error) => return common::network_failure(&mut command.stderr(), "net", error),
    };
    let result = writeln!(
        common::OutputWriter(&mut command.stdout()),
        "rx frames: {}\ntx frames: {}\narp replies: {}\nicmp replies: {}\nudp retained: {}\nudp unbound: {}\nudp dropped: {}\narp entries: {}\nudp ports: {}\ncheckpoints: {}\nerrors: {}",
        stats.received_frames,
        stats.transmitted_frames,
        stats.arp_replies,
        stats.icmp_replies,
        stats.udp_retained,
        stats.udp_unbound,
        stats.udp_dropped,
        stats.arp_entries,
        stats.udp_ports,
        stats.checkpoints,
        stats.errors,
    );
    if result.is_err() {
        common::stream_failure(&mut command.stderr(), "net")
    } else {
        exit::SUCCESS
    }
}

entry!(main);
