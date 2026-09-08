//! `KernelRuntime`: the per-machine runtime the cooperative scheduler drives.
//!
//! Bundles the network, the wall clock, the random generator, and the runtime
//! mount registry behind one shared handle, and implements the cooperative
//! runtime capability the task layer calls into.
//!
//! Two of those four are subsystems ADR 0035 Phase D and E move out. What is
//! left of this handle afterwards is the kernel's own client of them, which
//! is the `kernel/src/client.rs` that ADR 0035 names.

use crate::handles::{SharedNetwork, SharedRuntime};
use crate::service::clock::WallClockAnchor;
use alloc::collections::VecDeque;
use core::cell::Cell;
use troe_driver::{InputEvent, InputSource};
use troe_task::{Cancelled, CooperativeRuntime, MonotonicMillis};

pub(crate) struct KernelRuntime {
    pub(crate) network: Option<SharedNetwork>,
    wall_clock: Option<WallClockAnchor>,
    deferred_input: VecDeque<InputEvent>,
    control_down: bool,
    last_millis: Cell<u64>,
    last_nanos: Cell<u64>,
}

pub(crate) struct KernelRuntimeCapability {
    pub(crate) runtime: SharedRuntime,
}

pub(crate) enum RuntimeInitError {
    Clock,
    InputMetadata,
}

impl core::fmt::Debug for KernelRuntimeCapability {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("KernelRuntimeCapability")
    }
}

impl KernelRuntime {
    const DEFERRED_INPUT_CAPACITY: usize = 128;
    const INPUT_CHECKPOINT_BUDGET: usize = 32;

    pub(crate) fn new(
        network: Option<SharedNetwork>,
        firmware_wall_seconds: Option<u64>,
    ) -> Result<Self, RuntimeInitError> {
        let initial = troe_machine::monotonic_millis().ok_or(RuntimeInitError::Clock)?;
        let initial_nanos = troe_machine::monotonic_nanos().ok_or(RuntimeInitError::Clock)?;
        let mut deferred_input = VecDeque::new();
        deferred_input
            .try_reserve_exact(Self::DEFERRED_INPUT_CAPACITY)
            .map_err(|_| RuntimeInitError::InputMetadata)?;
        Ok(Self {
            network,
            wall_clock: firmware_wall_seconds.map(|unix_seconds| WallClockAnchor {
                unix_seconds,
                // Firmware reports whole seconds, so the anchor starts on a
                // second boundary and every finer reading is the monotonic
                // delta from it. `clock_control::SET_PRECISE` is what can
                // establish a true sub-second phase later.
                unix_subsec_nanos: 0,
                monotonic_nanos: initial_nanos,
            }),
            deferred_input,
            control_down: false,
            last_millis: Cell::new(initial),
            last_nanos: Cell::new(initial_nanos),
        })
    }

    /// Read the monotonic clock in nanoseconds, never going backwards.
    ///
    /// The same latch `now` uses: a counter that reads lower than the previous
    /// sample reports the previous one, so a caller never observes time
    /// reversing.
    pub(crate) fn now_nanos(&self) -> u64 {
        let previous = self.last_nanos.get();
        let current = troe_machine::monotonic_nanos()
            .unwrap_or(previous)
            .max(previous);
        self.last_nanos.set(current);
        current
    }

    pub(crate) fn now(&self) -> MonotonicMillis {
        let previous = self.last_millis.get();
        let current = troe_machine::monotonic_millis()
            .unwrap_or(previous)
            .max(previous);
        self.last_millis.set(current);
        MonotonicMillis::from_millis(current)
    }

    pub(crate) fn checkpoint(&mut self) -> Result<(), Cancelled> {
        self.service_ambient();
        for _ in 0..Self::INPUT_CHECKPOINT_BUDGET {
            let Some(event) = troe_machine::try_input_event() else {
                break;
            };
            match event.source() {
                InputSource::Serial if event.byte() == 3 => return Err(Cancelled),
                InputSource::Keyboard if event.byte() == 0x1d => {
                    self.control_down = true;
                }
                InputSource::Keyboard if event.byte() == 0x9d => {
                    self.control_down = false;
                }
                InputSource::Keyboard if self.control_down && event.byte() == 0x2e => {
                    return Err(Cancelled);
                }
                _ if self.deferred_input.len() < Self::DEFERRED_INPUT_CAPACITY => {
                    self.deferred_input.push_back(event);
                }
                _ => {}
            }
        }
        Ok(())
    }

    pub(crate) fn service_ambient(&mut self) {
        let interrupted = troe_machine::take_network_interrupt();
        if let Some(network) = &self.network {
            let mut network = network.borrow_mut();
            if interrupted {
                let _bounded_poll = network.poll();
            }
            network.flush_pending(self.now().as_millis());
        }
    }

    /// Wall-clock seconds, derived from the precise reading so the two can
    /// never disagree about which second it is.
    pub(crate) fn wall_seconds(&self) -> Option<u64> {
        Some(self.wall_precise()?.seconds)
    }

    /// The wall clock with its sub-second remainder.
    ///
    /// The anchor is advanced by the monotonic delta rather than re-read, so
    /// the remainder is as accurate as the anchor's own phase. Firmware
    /// supplies whole seconds, so that phase is zero until something calls
    /// `set_wall_precise` with a finer source.
    pub(crate) fn wall_precise(&self) -> Option<troe_abi::wall_clock::WallTime> {
        const NANOS_PER_SECOND: u64 = troe_abi::wall_clock::NANOS_PER_SECOND;
        let anchor = self.wall_clock?;
        let elapsed = self.now_nanos().saturating_sub(anchor.monotonic_nanos);
        let total = anchor.unix_subsec_nanos.saturating_add(elapsed);
        Some(troe_abi::wall_clock::WallTime {
            seconds: anchor.unix_seconds.saturating_add(total / NANOS_PER_SECOND),
            nanoseconds: total % NANOS_PER_SECOND,
        })
    }

    pub(crate) fn set_wall_seconds(&mut self, unix_seconds: u64) -> Result<(), ()> {
        self.set_wall_precise(troe_abi::wall_clock::WallTime {
            seconds: unix_seconds,
            nanoseconds: 0,
        })
    }

    pub(crate) fn set_wall_precise(
        &mut self,
        value: troe_abi::wall_clock::WallTime,
    ) -> Result<(), ()> {
        // The seconds bound is year 9999, which is why the anchor keeps
        // seconds and a remainder rather than one nanosecond count: that far
        // out does not fit in `u64` nanoseconds.
        if value.seconds > 253_402_300_799
            || value.nanoseconds >= troe_abi::wall_clock::NANOS_PER_SECOND
        {
            return Err(());
        }
        self.wall_clock = Some(WallClockAnchor {
            unix_seconds: value.seconds,
            unix_subsec_nanos: value.nanoseconds,
            monotonic_nanos: self.now_nanos(),
        });
        Ok(())
    }

    pub(crate) fn poll_input_event(&mut self) -> Option<InputEvent> {
        let _cancel_at_prompt = self.checkpoint();
        self.take_input_event()
    }

    /// Take one retained event without observing cancellation.
    ///
    /// Foreground callers detect cancellation with their own checkpoint,
    /// so draining here must not consume that observation.
    pub(crate) fn take_input_event(&mut self) -> Option<InputEvent> {
        self.deferred_input.pop_front()
    }
}

impl CooperativeRuntime for KernelRuntimeCapability {
    fn now(&self) -> MonotonicMillis {
        self.runtime.borrow().now()
    }

    fn checkpoint(&mut self) -> Result<(), Cancelled> {
        self.runtime.borrow_mut().checkpoint()
    }
}
