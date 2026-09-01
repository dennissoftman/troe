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
        let mut deferred_input = VecDeque::new();
        deferred_input
            .try_reserve_exact(Self::DEFERRED_INPUT_CAPACITY)
            .map_err(|_| RuntimeInitError::InputMetadata)?;
        Ok(Self {
            network,
            wall_clock: firmware_wall_seconds.map(|unix_seconds| WallClockAnchor {
                unix_seconds,
                monotonic_milliseconds: initial,
            }),
            deferred_input,
            control_down: false,
            last_millis: Cell::new(initial),
        })
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
        if troe_machine::take_network_interrupt()
            && let Some(network) = &self.network
        {
            let _bounded_poll = network.borrow_mut().poll();
        }
    }

    pub(crate) fn wall_seconds(&self) -> Option<u64> {
        let anchor = self.wall_clock?;
        let elapsed = self
            .now()
            .as_millis()
            .saturating_sub(anchor.monotonic_milliseconds)
            / 1_000;
        Some(anchor.unix_seconds.saturating_add(elapsed))
    }

    pub(crate) fn set_wall_seconds(&mut self, unix_seconds: u64) -> Result<(), ()> {
        if unix_seconds > 253_402_300_799 {
            return Err(());
        }
        self.wall_clock = Some(WallClockAnchor {
            unix_seconds,
            monotonic_milliseconds: self.now().as_millis(),
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
