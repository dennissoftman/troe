#![no_std]
#![no_main]

use core::fmt::{self, Write as _};
use troe_kex_sdk::{
    CommandContext, DATAGRAM_BUFFER_BYTES, Error, INVOCATION_BUFFER_BYTES, StandardOutput, Timer,
    entry, exit, yield_now,
};

const WARMUP: usize = 64;
const SAMPLES: usize = 256;
const UDP_BYTES: usize = 1472;
const TCP_BYTES: usize = 16384;
const HOST: [u8; 4] = [10, 0, 2, 2];

struct Writer(StandardOutput);
impl fmt::Write for Writer {
    fn write_str(&mut self, text: &str) -> fmt::Result {
        self.0.write_all(text.as_bytes()).map_err(|_| fmt::Error)
    }
}

fn elapsed(timer: &mut Timer, start: u64, frequency: u64) -> Result<u64, Error> {
    let end = timer.acceptance_counter()?;
    if end.frequency_hz != frequency {
        return Err(Error::InvalidCall);
    }
    end.ticks
        .checked_sub(start)
        .filter(|ticks| *ticks > 0)
        .ok_or(Error::InvalidCall)
}

fn report(
    command: &CommandContext,
    protocol: &str,
    frequency: u64,
    samples: &[u64; SAMPLES],
) -> Result<(), Error> {
    let mut output = Writer(command.stdout());
    write!(
        output,
        "NETWORK protocol={protocol} frequency_hz={frequency} ticks="
    )
    .map_err(|_| Error::Io)?;
    for (index, ticks) in samples.iter().enumerate() {
        if index != 0 {
            output.write_char(',').map_err(|_| Error::Io)?;
        }
        write!(output, "{ticks}").map_err(|_| Error::Io)?;
    }
    output.write_char('\n').map_err(|_| Error::Io)
}

fn udp(command: &CommandContext, port: u16) -> Result<(), Error> {
    let mut network = command.datagram()?;
    let mut timer = command.timer()?;
    let frequency = timer.acceptance_counter()?.frequency_hz;
    let mut samples = [0; SAMPLES];
    let mut payload = [0x5a; UDP_BYTES];
    let mut buffer = [0; DATAGRAM_BUFFER_BYTES];
    let mut source_port = None;
    for index in 0..WARMUP + SAMPLES {
        payload[..8].copy_from_slice(&(index as u64).to_le_bytes());
        let start = timer.acceptance_counter()?.ticks;
        let selected = network.send(source_port, HOST, port, &payload)?;
        let received = network.receive(selected, &mut buffer)?;
        let ticks = elapsed(&mut timer, start, frequency)?;
        if received.source != HOST || received.source_port != port || received.payload != payload {
            return Err(Error::Io);
        }
        source_port = Some(selected);
        if index >= WARMUP {
            samples[index - WARMUP] = ticks;
        }
        yield_now()?;
    }
    report(command, "udp", frequency, &samples)
}

fn tcp(command: &CommandContext, port: u16) -> Result<(), Error> {
    let mut connection = command.tcp_connect()?.connect(HOST, port)?;
    let mut timer = command.timer()?;
    let frequency = timer.acceptance_counter()?.frequency_hz;
    let mut samples = [0; SAMPLES];
    let mut payload = [0x5a; TCP_BYTES];
    let mut buffer = [0; TCP_BYTES];
    for index in 0..WARMUP + SAMPLES {
        payload[..8].copy_from_slice(&(index as u64).to_le_bytes());
        let start = timer.acceptance_counter()?.ticks;
        connection.write_all(&payload)?;
        let mut count = 0;
        while count < TCP_BYTES {
            let received = connection.read(&mut buffer[count..])?;
            if received == 0 {
                return Err(Error::Io);
            }
            count += received;
        }
        let ticks = elapsed(&mut timer, start, frequency)?;
        if buffer != payload {
            return Err(Error::Io);
        }
        if index >= WARMUP {
            samples[index - WARMUP] = ticks;
        }
        yield_now()?;
    }
    connection.close()?;
    report(command, "tcp", frequency, &samples)
}

fn run(command: &CommandContext) -> Result<(), Error> {
    let mut bytes = [0; INVOCATION_BUFFER_BYTES];
    let invocation = command.invocation(&mut bytes)?;
    if invocation.len() != 3 {
        return Err(Error::InvalidInvocation);
    }
    let udp_port = invocation
        .argument(1)
        .and_then(|value| value.parse::<u16>().ok())
        .filter(|port| *port != 0)
        .ok_or(Error::InvalidInvocation)?;
    let tcp_port = invocation
        .argument(2)
        .and_then(|value| value.parse::<u16>().ok())
        .filter(|port| *port != 0)
        .ok_or(Error::InvalidInvocation)?;
    writeln!(Writer(command.stdout()), "NETWORK-BASELINE version=1 warmup={WARMUP} samples={SAMPLES} udp_bytes={UDP_BYTES} tcp_bytes={TCP_BYTES} payload=5a-with-u64le-index timer=architecture-counter").map_err(|_| Error::Io)?;
    udp(command, udp_port)?;
    tcp(command, tcp_port)?;
    writeln!(Writer(command.stdout()), "END network-baseline").map_err(|_| Error::Io)
}

fn main(command: &mut CommandContext) -> u32 {
    match run(command) {
        Ok(()) => exit::SUCCESS,
        Err(error) => {
            let _ignored = writeln!(
                Writer(command.stderr()),
                "network-baseline failed: {error:?}"
            );
            exit::FAILURE
        }
    }
}
entry!(main);
