#![no_std]
#![no_main]

use core::fmt::{self, Write as _};
use troe_kex_sdk::{CommandContext, Error, StandardOutput, Timer, entry, exit, yield_now};

const CHUNK_BYTES: usize = 4096;
const WARMUP: usize = 64;
const SAMPLES: usize = 256;
const PAYLOAD: [u8; CHUNK_BYTES] = [0x5a; CHUNK_BYTES];

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
    output: &mut Writer,
    volume: &str,
    phase: &str,
    frequency: u64,
    samples: &[u64; SAMPLES],
) -> Result<(), Error> {
    // Formatting and console I/O occur only after all timed operations finish.
    write!(
        output,
        "STORAGE volume={volume} phase={phase} frequency_hz={frequency} ticks="
    )
    .map_err(|_| Error::Io)?;
    for (index, ticks) in samples.iter().enumerate() {
        if index != 0 {
            output.write_str(",").map_err(|_| Error::Io)?;
        }
        write!(output, "{ticks}").map_err(|_| Error::Io)?;
    }
    output.write_char('\n').map_err(|_| Error::Io)
}

fn measure(command: &CommandContext, volume: &str, path: &str) -> Result<(), Error> {
    let mut mutation = command.filesystem_mutation()?;
    let mut filesystem = command.filesystem()?;
    let mut timer = command.timer()?;
    let frequency = timer.acceptance_counter()?.frequency_hz;
    // Start with a fresh empty file. Each append commits exactly one 4 KiB unit,
    // including the provider's declared sync, while preserving sequential offsets.
    mutation.begin_replace(path)?.commit()?;
    let mut samples = [0_u64; SAMPLES];
    let mut payload = PAYLOAD;
    for index in 0..WARMUP + SAMPLES {
        payload[..8].copy_from_slice(&(index as u64).to_le_bytes());
        let start = timer.acceptance_counter()?.ticks;
        let mut file = mutation.begin_append(path)?;
        file.write_all(&payload)?;
        file.commit()?;
        let ticks = elapsed(&mut timer, start, frequency)?;
        if index >= WARMUP {
            samples[index - WARMUP] = ticks;
        }
        // Renew the ordinary execution lease outside the measurement interval.
        yield_now()?;
    }
    let mut output = Writer(command.stdout());
    report(&mut output, volume, "write_sync", frequency, &samples)?;

    let file = filesystem.open(path)?;
    if file.byte_count != ((WARMUP + SAMPLES) * CHUNK_BYTES) as u64 {
        return Err(Error::Io);
    }
    let mut bytes = [0_u8; CHUNK_BYTES];
    for index in 0..WARMUP + SAMPLES {
        let start = timer.acceptance_counter()?.ticks;
        let mut count = 0;
        while count < CHUNK_BYTES {
            let received = filesystem.read(
                file,
                (index * CHUNK_BYTES + count) as u64,
                &mut bytes[count..],
            )?;
            if received == 0 {
                return Err(Error::Io);
            }
            count += received;
        }
        let ticks = elapsed(&mut timer, start, frequency)?;
        // Exact payload verification is outside the timed read interval.
        payload[..8].copy_from_slice(&(index as u64).to_le_bytes());
        if count != CHUNK_BYTES || bytes != payload {
            return Err(Error::Io);
        }
        if index >= WARMUP {
            samples[index - WARMUP] = ticks;
        }
        yield_now()?;
    }
    filesystem.close(file)?;
    report(&mut output, volume, "read", frequency, &samples)?;
    mutation.remove(path)?;
    Ok(())
}

fn run(command: &CommandContext) -> Result<(), Error> {
    let mut output = Writer(command.stdout());
    writeln!(output, "STORAGE-BASELINE version=1 chunk_bytes={CHUNK_BYTES} warmup={WARMUP} samples={SAMPLES} payload=5a-with-u64le-chunk-index timer=architecture-counter sync=per-chunk")
        .map_err(|_| Error::Io)?;
    measure(command, "ext4", "/vol/root/troe-storage-baseline.bin")?;
    measure(command, "fat32", "/vol/shared/troe-storage-baseline.bin")?;
    output
        .write_str("END storage-baseline\n")
        .map_err(|_| Error::Io)
}

fn main(command: &mut CommandContext) -> u32 {
    match run(command) {
        Ok(()) => exit::SUCCESS,
        Err(error) => {
            let _ignored = writeln!(
                Writer(command.stderr()),
                "storage-baseline failed: {error:?}"
            );
            exit::FAILURE
        }
    }
}

entry!(main);
