//! Time: the runtime wall clock and the timer, wall-clock, and clock-control
//! services.
//!
//! `RuntimeWallClock` is the handle filesystem providers hold, so a volume
//! mounted at boot stamps the current time rather than its mount time. The
//! firmware time is converted once at boot and advanced from the monotonic
//! millisecond counter afterwards.

use crate::handles::{SharedProcessTable, SharedRuntime, SharedTaskIdentity};
use troe_abi::{clock_control, timer, wall_clock};
use troe_dispatch::{ReplyStatus, Request, Service, ServiceReply};
use troe_fs_api::WallClock;
use troe_task::MonotonicMillis;

#[derive(Clone, Copy)]
pub(crate) struct WallClockAnchor {
    pub(crate) unix_seconds: u64,
    pub(crate) monotonic_milliseconds: u64,
}

/// The runtime's wall clock, as filesystem providers read it.
///
/// Providers hold this handle and ask it at each mutation, so a volume
/// mounted at boot stamps the current time rather than its mount time.
pub(crate) struct RuntimeWallClock {
    pub(crate) runtime: SharedRuntime,
}

impl core::fmt::Debug for RuntimeWallClock {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.debug_struct("RuntimeWallClock").finish()
    }
}

impl WallClock for RuntimeWallClock {
    fn unix_seconds(&self) -> Option<u64> {
        // A mutation reached from inside a runtime borrow reports no time
        // rather than panicking; the provider then leaves its timestamps
        // untouched, which is the same contract as having no clock.
        self.runtime.try_borrow().ok()?.wall_seconds()
    }
}

pub(crate) struct ApplicationTimerService {
    pub(crate) runtime: SharedRuntime,
    pub(crate) processes: SharedProcessTable,
    pub(crate) task_id: SharedTaskIdentity,
}

pub(crate) struct ApplicationWallClockService {
    pub(crate) runtime: SharedRuntime,
}

pub(crate) struct ApplicationClockControlService {
    pub(crate) runtime: SharedRuntime,
}

impl Service for ApplicationTimerService {
    fn call(&mut self, request: Request<'_>) -> Result<ServiceReply, troe_dispatch::DispatchError> {
        match request.opcode() {
            timer::NOW if request.payload().is_empty() => {
                let milliseconds = self.runtime.borrow().now().as_millis();
                ServiceReply::with_payload(
                    ReplyStatus::Success,
                    &timer::encode_milliseconds(milliseconds),
                )
            }
            timer::PROCESS_CPU_TIME if request.payload().is_empty() => {
                let task_id = self
                    .task_id
                    .get()
                    .ok_or(troe_dispatch::DispatchError::AccountingOverflow)?;
                let ticks = self
                    .processes
                    .try_borrow()
                    .map_err(|_| troe_dispatch::DispatchError::AccountingOverflow)?
                    .snapshot_for_task(task_id)
                    .map_err(|_| troe_dispatch::DispatchError::AccountingOverflow)?
                    .cpu_ticks();
                let frequency_hz = troe_machine::process_accounting_frequency_hz()
                    .ok_or(troe_dispatch::DispatchError::AccountingOverflow)?;
                let reply = timer::encode_process_cpu_time(timer::ProcessCpuTime {
                    ticks,
                    frequency_hz,
                })
                .map_err(|_| troe_dispatch::DispatchError::AccountingOverflow)?;
                ServiceReply::with_payload(ReplyStatus::Success, &reply)
            }
            timer::SLEEP_UNTIL => {
                let Ok(deadline) = timer::decode_milliseconds(request.payload()) else {
                    return Ok(ServiceReply::empty(ReplyStatus::InvalidRequest));
                };
                let deadline = MonotonicMillis::from_millis(deadline);
                let now = self.runtime.borrow().now();
                if deadline <= now {
                    Ok(ServiceReply::empty(ReplyStatus::Success))
                } else {
                    // Future sleeps are intercepted at the composition
                    // boundary and retained as deferred calls.
                    Ok(ServiceReply::empty(ReplyStatus::Failure))
                }
            }
            _ => Ok(ServiceReply::empty(ReplyStatus::InvalidRequest)),
        }
    }
}

impl Service for ApplicationWallClockService {
    fn call(&mut self, request: Request<'_>) -> Result<ServiceReply, troe_dispatch::DispatchError> {
        if request.opcode() != wall_clock::NOW || !request.payload().is_empty() {
            return Ok(ServiceReply::empty(ReplyStatus::InvalidRequest));
        }
        let Some(seconds) = self.runtime.borrow().wall_seconds() else {
            return Ok(ServiceReply::empty(ReplyStatus::NotConfigured));
        };
        ServiceReply::with_payload(ReplyStatus::Success, &wall_clock::encode_seconds(seconds))
    }
}

impl Service for ApplicationClockControlService {
    fn call(&mut self, request: Request<'_>) -> Result<ServiceReply, troe_dispatch::DispatchError> {
        if request.opcode() != clock_control::SET {
            return Ok(ServiceReply::empty(ReplyStatus::InvalidRequest));
        }
        let Ok(seconds) = clock_control::decode_seconds(request.payload()) else {
            return Ok(ServiceReply::empty(ReplyStatus::InvalidRequest));
        };
        let status = if self.runtime.borrow_mut().set_wall_seconds(seconds).is_ok() {
            ReplyStatus::Success
        } else {
            ReplyStatus::InvalidRequest
        };
        Ok(ServiceReply::empty(status))
    }
}

pub(crate) fn firmware_unix_seconds() -> Option<u64> {
    const MONTH_DAYS: [u64; 12] = [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];

    let time = uefi::runtime::get_time().ok()?;
    if time.year() < 1970 {
        return None;
    }
    let mut days = 0_u64;
    for year in 1970..time.year() {
        days = days.checked_add(if is_leap_year(year) { 366 } else { 365 })?;
    }
    for month in 1..time.month() {
        let mut month_days = *MONTH_DAYS.get(usize::from(month - 1))?;
        if month == 2 && is_leap_year(time.year()) {
            month_days += 1;
        }
        days = days.checked_add(month_days)?;
    }
    days = days.checked_add(u64::from(time.day().checked_sub(1)?))?;
    let local = days
        .checked_mul(86_400)?
        .checked_add(u64::from(time.hour()).checked_mul(3_600)?)?
        .checked_add(u64::from(time.minute()).checked_mul(60)?)?
        .checked_add(u64::from(time.second()))?;
    match time.time_zone() {
        Some(offset) if offset >= 0 => local.checked_sub(u64::from(offset.unsigned_abs()) * 60),
        Some(offset) => local.checked_add(u64::from(offset.unsigned_abs()) * 60),
        None => Some(local),
    }
}

pub(crate) const fn is_leap_year(year: u16) -> bool {
    year.is_multiple_of(4) && (!year.is_multiple_of(100) || year.is_multiple_of(400))
}
