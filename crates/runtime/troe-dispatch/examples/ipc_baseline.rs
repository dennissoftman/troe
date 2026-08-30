//! Reproducible host-side latency and structural-event baseline for dispatch.

use std::hint::black_box;
use std::process::ExitCode;
use std::time::Instant;
use troe_dispatch::{
    DispatchError, DispatchStats, Dispatcher, ReplyStatus, Request, Rights, Service, ServiceReply,
};

const PAYLOAD_BYTES: [usize; 4] = [0, 64, 256, 4 * 1024];
const DEFAULT_WARMUP: usize = 10_000;
const DEFAULT_SAMPLES: usize = 50_000;

struct EchoService;

impl Service for EchoService {
    fn call(&mut self, request: Request<'_>) -> Result<ServiceReply, DispatchError> {
        ServiceReply::with_payload(ReplyStatus::Success, request.payload())
    }
}

#[derive(Clone, Copy)]
struct Options {
    warmup: usize,
    samples: usize,
}

struct Measurement {
    payload_bytes: usize,
    p50_ns: u128,
    p95_ns: u128,
    p99_ns: u128,
    max_ns: u128,
    stats: DispatchStats,
}

fn main() -> ExitCode {
    let options = match parse_options() {
        Ok(options) => options,
        Err(message) => {
            eprintln!("ipc baseline: {message}");
            return ExitCode::FAILURE;
        }
    };
    println!(
        "path,payload_bytes,warmup,samples,clock,p50,p95,p99,max,completed_calls,request_bytes,request_copies,request_allocations,reply_bytes,reply_copies,reply_allocations,address_space_switches,tlb_invalidations,timer_programs"
    );
    for payload_bytes in PAYLOAD_BYTES {
        let measurement = match measure(payload_bytes, options) {
            Ok(measurement) => measurement,
            Err(message) => {
                eprintln!("ipc baseline: {message}");
                return ExitCode::FAILURE;
            }
        };
        println!(
            "in_process,{},{},{},monotonic_ns,{},{},{},{},{},{},{},{},{},{},{},0,0,0",
            measurement.payload_bytes,
            options.warmup,
            options.samples,
            measurement.p50_ns,
            measurement.p95_ns,
            measurement.p99_ns,
            measurement.max_ns,
            measurement.stats.replies,
            measurement.stats.request_bytes,
            measurement.stats.request_payload_copies,
            measurement.stats.request_payload_allocations,
            measurement.stats.reply_bytes,
            measurement.stats.reply_payload_copies,
            measurement.stats.reply_payload_allocations,
        );
    }
    ExitCode::SUCCESS
}

fn parse_options() -> Result<Options, String> {
    let mut options = Options {
        warmup: DEFAULT_WARMUP,
        samples: DEFAULT_SAMPLES,
    };
    let mut arguments = std::env::args().skip(1);
    while let Some(argument) = arguments.next() {
        let value = arguments
            .next()
            .ok_or_else(|| format!("{argument} requires a positive integer"))?;
        let count = value
            .parse::<usize>()
            .map_err(|_| format!("{argument} requires a positive integer"))?;
        if count == 0 {
            return Err(format!("{argument} requires a positive integer"));
        }
        match argument.as_str() {
            "--warmup" => options.warmup = count,
            "--samples" => options.samples = count,
            _ => return Err(format!("unknown option {argument}")),
        }
    }
    Ok(options)
}

fn measure(payload_bytes: usize, options: Options) -> Result<Measurement, String> {
    let mut dispatcher = Dispatcher::new(1, 1).map_err(dispatch_error)?;
    let (_port, handle) = dispatcher
        .register(Box::new(EchoService), Rights::CALL)
        .map_err(dispatch_error)?;
    let payload = vec![0x5a_u8; payload_bytes];
    for _ in 0..options.warmup {
        let reply = dispatcher
            .call(handle, 1, black_box(&payload))
            .map_err(dispatch_error)?;
        if reply.payload() != payload {
            return Err("warmup echo mismatch".to_owned());
        }
        black_box(reply);
    }
    let baseline = dispatcher.stats();
    let mut durations = Vec::new();
    durations
        .try_reserve_exact(options.samples)
        .map_err(|_| "cannot allocate duration samples".to_owned())?;
    for _ in 0..options.samples {
        let started = Instant::now();
        let reply = dispatcher
            .call(handle, 1, black_box(&payload))
            .map_err(dispatch_error)?;
        let elapsed = started.elapsed().as_nanos();
        if reply.payload() != payload {
            return Err("measured echo mismatch".to_owned());
        }
        black_box(reply);
        durations.push(elapsed);
    }
    durations.sort_unstable();
    let stats = subtract_stats(dispatcher.stats(), baseline)?;
    let expected_calls = u64::try_from(options.samples)
        .map_err(|_| "sample count does not fit event counters".to_owned())?;
    let expected_bytes = expected_calls
        .checked_mul(
            u64::try_from(payload_bytes)
                .map_err(|_| "payload size does not fit event counters".to_owned())?,
        )
        .ok_or_else(|| "payload byte count overflowed".to_owned())?;
    let expected_copies = if payload_bytes == 0 {
        0
    } else {
        expected_calls
    };
    if stats.calls != expected_calls
        || stats.replies != expected_calls
        || stats.request_bytes != expected_bytes
        || stats.reply_bytes != expected_bytes
        || stats.request_payload_copies != 0
        || stats.request_payload_allocations != 0
        || stats.reply_payload_copies != expected_copies
        || stats.reply_payload_allocations != expected_copies
    {
        return Err("structural event counters do not match the measured calls".to_owned());
    }
    Ok(Measurement {
        payload_bytes,
        p50_ns: percentile(&durations, 50),
        p95_ns: percentile(&durations, 95),
        p99_ns: percentile(&durations, 99),
        max_ns: durations.last().copied().unwrap_or_default(),
        stats,
    })
}

fn percentile(sorted: &[u128], percentile: usize) -> u128 {
    let rank = sorted.len().saturating_mul(percentile).saturating_add(99) / 100;
    sorted
        .get(rank.saturating_sub(1).min(sorted.len().saturating_sub(1)))
        .copied()
        .unwrap_or_default()
}

fn subtract_stats(after: DispatchStats, before: DispatchStats) -> Result<DispatchStats, String> {
    Ok(DispatchStats {
        live_ports: after.live_ports,
        live_handles: after.live_handles,
        calls: subtract(after.calls, before.calls)?,
        replies: subtract(after.replies, before.replies)?,
        request_bytes: subtract(after.request_bytes, before.request_bytes)?,
        request_payload_copies: subtract(
            after.request_payload_copies,
            before.request_payload_copies,
        )?,
        request_payload_allocations: subtract(
            after.request_payload_allocations,
            before.request_payload_allocations,
        )?,
        reply_bytes: subtract(after.reply_bytes, before.reply_bytes)?,
        reply_payload_copies: subtract(after.reply_payload_copies, before.reply_payload_copies)?,
        reply_payload_allocations: subtract(
            after.reply_payload_allocations,
            before.reply_payload_allocations,
        )?,
    })
}

fn subtract(after: u64, before: u64) -> Result<u64, String> {
    after
        .checked_sub(before)
        .ok_or_else(|| "event counter moved backwards".to_owned())
}

fn dispatch_error(error: DispatchError) -> String {
    format!("dispatch failed: {error}")
}
