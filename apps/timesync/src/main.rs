#![no_std]
#![no_main]

#[path = "../../common.rs"]
mod common;

use troe_app_timesync::{request, unix_transmit_seconds};
use troe_kex_sdk::{CommandContext, DATAGRAM_BUFFER_BYTES, Timer, entry, exit};

const NTP_SERVER: [u8; 4] = [10, 0, 2, 2];
const NTP_PORT: u16 = 123;
const DAY_MILLISECONDS: u64 = 86_400_000;
const RETRY_MILLISECONDS: [u64; 4] = [60_000, 300_000, 1_800_000, 3_600_000];

fn main(command: &mut CommandContext) -> u32 {
    let Ok(mut datagram) = command.datagram() else {
        return exit::DENIED;
    };
    let Ok(mut timer) = command.timer() else {
        return exit::DENIED;
    };
    let Ok(mut clock) = command.clock_control() else {
        return exit::DENIED;
    };

    let mut retry = 0_usize;
    loop {
        let delay = match synchronize(&mut datagram, &mut timer, &mut clock) {
            Ok(()) => {
                common::report(&mut command.stdout(), "timesync", b"clock synchronized");
                retry = 0;
                DAY_MILLISECONDS
            }
            Err(()) => {
                common::report(&mut command.stderr(), "timesync", b"synchronization failed");
                let delay = RETRY_MILLISECONDS[retry];
                retry = retry.saturating_add(1).min(RETRY_MILLISECONDS.len() - 1);
                delay
            }
        };
        let Ok(now) = timer.now() else {
            return exit::FAILURE;
        };
        if timer.sleep_until(now.saturating_add(delay)).is_err() {
            return exit::CANCELLED;
        }
    }
}

fn synchronize(
    datagram: &mut troe_kex_sdk::Datagram,
    timer: &mut Timer,
    clock: &mut troe_kex_sdk::ClockControl,
) -> Result<(), ()> {
    let token = timer.now().map_err(|_| ())?.max(1);
    let request = request(token);
    let local_port = datagram
        .send(None, NTP_SERVER, NTP_PORT, &request)
        .map_err(|_| ())?;
    let mut response = [0_u8; DATAGRAM_BUFFER_BYTES];
    let received = datagram
        .receive(local_port, &mut response)
        .map_err(|_| ())?;
    if received.source != NTP_SERVER || received.source_port != NTP_PORT {
        return Err(());
    }
    let unix_seconds = unix_transmit_seconds(received.payload, token).map_err(|_| ())?;
    clock.set(unix_seconds).map_err(|_| ())
}

entry!(main);
