//! Acceptance-only boot interval, sampled before formatting its output record.
use core::sync::atomic::{AtomicU64, Ordering};

static START: AtomicU64 = AtomicU64::new(0);
static IPC: AtomicU64 = AtomicU64::new(0);

pub(crate) fn start() {
    START.store(troe_machine::benchmark_counter_ticks(), Ordering::Relaxed);
}

pub(crate) fn exclude_ipc(start: u64) {
    let elapsed = troe_machine::benchmark_counter_ticks()
        .checked_sub(start)
        .unwrap_or_else(|| crate::support::fatal(b"fatal: boot counter reversed\n"));
    IPC.store(elapsed, Ordering::Relaxed);
}

pub(crate) fn finish() {
    let end = troe_machine::benchmark_counter_ticks();
    let start = START.load(Ordering::Relaxed);
    let excluded = IPC.load(Ordering::Relaxed);
    let ticks = end
        .checked_sub(start)
        .and_then(|value| value.checked_sub(excluded))
        .filter(|value| *value > 0)
        .unwrap_or_else(|| crate::support::fatal(b"fatal: boot counter interval invalid\n"));
    let frequency = troe_machine::benchmark_counter_frequency_hz()
        .unwrap_or_else(|| crate::support::fatal(b"fatal: boot counter unavailable\n"));
    let line = alloc::format!(
        "TROE-BOOT-BASELINE-v1 start_ticks={start} end_ticks={end} excluded_ipc_ticks={excluded} ticks={ticks} counter_hz={frequency}\n"
    );
    if !troe_machine::write(line.as_bytes()) {
        crate::support::fatal(b"fatal: boot counter output failed\n");
    }
}
