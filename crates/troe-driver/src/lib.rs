//! Bounded portable resource descriptors and raw input event queues.
#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;
#[cfg(test)]
extern crate std;

use alloc::vec::Vec;
use core::fmt;

/// Hard implementation ceiling for one configured raw-input queue.
pub const MAX_INPUT_QUEUE_EVENTS: usize = 4096;
/// Hard implementation ceiling for bytes drained during one device interrupt.
pub const MAX_INPUT_DRAIN_EVENTS: usize = 1024;

/// Invalid portable driver configuration or resource metadata.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConfigError {
    /// A selected capacity or length is zero.
    Empty,
    /// A selected capacity exceeds its explicit implementation ceiling.
    CapacityTooLarge,
    /// Address, port, or range arithmetic overflowed.
    Overflow,
    /// An interrupt vector is outside the architecture-neutral byte range.
    InvalidVector,
}

impl fmt::Display for ConfigError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => formatter.write_str("driver resource or capacity is empty"),
            Self::CapacityTooLarge => formatter.write_str("driver capacity exceeds hard ceiling"),
            Self::Overflow => formatter.write_str("driver resource arithmetic overflowed"),
            Self::InvalidVector => formatter.write_str("interrupt vector is invalid"),
        }
    }
}

/// Selected raw-input retention and interrupt-work policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InputQueueConfig {
    capacity: usize,
    max_drain_per_interrupt: usize,
    interrupt_priority: u8,
}

impl InputQueueConfig {
    /// Construct a bounded input policy.
    ///
    /// # Errors
    ///
    /// Rejects zero values and capacities above the published hard ceilings.
    pub const fn new(
        capacity: usize,
        max_drain_per_interrupt: usize,
        interrupt_priority: u8,
    ) -> Result<Self, ConfigError> {
        if capacity == 0 || max_drain_per_interrupt == 0 {
            return Err(ConfigError::Empty);
        }
        if capacity > MAX_INPUT_QUEUE_EVENTS || max_drain_per_interrupt > MAX_INPUT_DRAIN_EVENTS {
            return Err(ConfigError::CapacityTooLarge);
        }
        Ok(Self {
            capacity,
            max_drain_per_interrupt,
            interrupt_priority,
        })
    }

    /// Default input policy for the `tiny` resource profile.
    #[must_use]
    pub const fn tiny() -> Self {
        Self {
            capacity: 256,
            max_drain_per_interrupt: 32,
            interrupt_priority: 0xa0,
        }
    }

    /// Maximum retained raw input events.
    #[must_use]
    pub const fn capacity(self) -> usize {
        self.capacity
    }

    /// Maximum device bytes inspected during one interrupt.
    #[must_use]
    pub const fn max_drain_per_interrupt(self) -> usize {
        self.max_drain_per_interrupt
    }

    /// Architecture interrupt-controller priority selected by the profile.
    #[must_use]
    pub const fn interrupt_priority(self) -> u8 {
        self.interrupt_priority
    }
}

/// Hardware transport that produced one raw input byte.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InputSource {
    /// Architecture-native serial receive device.
    Serial,
    /// Native keyboard scan-code transport.
    Keyboard,
}

/// One transport byte retained outside interrupt context.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InputEvent {
    source: InputSource,
    byte: u8,
}

impl InputEvent {
    /// Construct one raw event.
    #[must_use]
    pub const fn new(source: InputSource, byte: u8) -> Self {
        Self { source, byte }
    }

    /// Transport that produced the byte.
    #[must_use]
    pub const fn source(self) -> InputSource {
        self.source
    }

    /// Uninterpreted transport byte.
    #[must_use]
    pub const fn byte(self) -> u8 {
        self.byte
    }
}

/// A checked byte-addressed MMIO resource.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MmioResource {
    base_address: u64,
    byte_len: u64,
}

impl MmioResource {
    /// Construct a non-empty checked MMIO resource.
    ///
    /// # Errors
    ///
    /// Rejects zero length and address overflow.
    pub const fn new(base_address: u64, byte_len: u64) -> Result<Self, ConfigError> {
        if byte_len == 0 {
            return Err(ConfigError::Empty);
        }
        if base_address.checked_add(byte_len).is_none() {
            return Err(ConfigError::Overflow);
        }
        Ok(Self {
            base_address,
            byte_len,
        })
    }

    /// First byte in the resource.
    #[must_use]
    pub const fn base_address(self) -> u64 {
        self.base_address
    }

    /// Complete resource length.
    #[must_use]
    pub const fn byte_len(self) -> u64 {
        self.byte_len
    }

    /// First byte after the resource.
    #[must_use]
    pub const fn end_address(self) -> u64 {
        self.base_address + self.byte_len
    }
}

/// A checked contiguous I/O-port resource.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct IoPortResource {
    base_port: u16,
    port_count: u16,
}

impl IoPortResource {
    /// Construct a non-empty port resource.
    ///
    /// # Errors
    ///
    /// Rejects zero ports or a range extending past port `0xffff`.
    pub const fn new(base_port: u16, port_count: u16) -> Result<Self, ConfigError> {
        if port_count == 0 {
            return Err(ConfigError::Empty);
        }
        if base_port.checked_add(port_count - 1).is_none() {
            return Err(ConfigError::Overflow);
        }
        Ok(Self {
            base_port,
            port_count,
        })
    }

    /// First owned port.
    #[must_use]
    pub const fn base_port(self) -> u16 {
        self.base_port
    }

    /// Owned port count.
    #[must_use]
    pub const fn port_count(self) -> u16 {
        self.port_count
    }
}

/// One platform interrupt line and selected CPU vector.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InterruptResource {
    line: u32,
    vector: u8,
}

impl InterruptResource {
    /// Construct an interrupt resource with a non-exception vector.
    ///
    /// # Errors
    ///
    /// Rejects vectors reserved for architecture exceptions.
    pub const fn new(line: u32, vector: u8) -> Result<Self, ConfigError> {
        if vector < 32 {
            return Err(ConfigError::InvalidVector);
        }
        Ok(Self { line, vector })
    }

    /// Platform interrupt line, GSI, or INTID.
    #[must_use]
    pub const fn line(self) -> u32 {
        self.line
    }

    /// CPU-visible interrupt vector selected by the platform profile.
    #[must_use]
    pub const fn vector(self) -> u8 {
        self.vector
    }
}

/// Queue construction failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum QueueError {
    /// Preallocating the complete selected ring failed.
    MetadataExhausted,
}

/// Result of retaining one event under the selected overflow policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PushResult {
    /// The event is retained for a consumer.
    Enqueued,
    /// The queue was full and the newest event was dropped.
    Dropped,
}

/// Observable bounded input-delivery accounting.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct InputQueueStats {
    /// Selected event capacity.
    pub capacity: usize,
    /// Events currently retained.
    pub queued: usize,
    /// Events removed by the consumer.
    pub delivered: u64,
    /// Newest events discarded because the queue was full.
    pub dropped: u64,
    /// Hardware input interrupts handled.
    pub interrupts: u64,
    /// Empty-queue transitions into an architecture idle instruction.
    pub idle_waits: u64,
    /// Returns from an architecture idle instruction.
    pub wakeups: u64,
}

/// Preallocated FIFO with a drop-newest overflow policy.
#[derive(Debug)]
pub struct BoundedInputQueue {
    config: InputQueueConfig,
    slots: Vec<Option<InputEvent>>,
    head: usize,
    len: usize,
    delivered: u64,
    dropped: u64,
    interrupts: u64,
    idle_waits: u64,
    wakeups: u64,
}

impl BoundedInputQueue {
    /// Allocate and initialize every selected queue slot before IRQ enablement.
    ///
    /// # Errors
    ///
    /// Returns a typed failure if metadata allocation cannot be satisfied.
    pub fn try_new(config: InputQueueConfig) -> Result<Self, QueueError> {
        let mut slots = Vec::new();
        slots
            .try_reserve_exact(config.capacity())
            .map_err(|_| QueueError::MetadataExhausted)?;
        slots.resize(config.capacity(), None);
        Ok(Self {
            config,
            slots,
            head: 0,
            len: 0,
            delivered: 0,
            dropped: 0,
            interrupts: 0,
            idle_waits: 0,
            wakeups: 0,
        })
    }

    /// Selected immutable policy.
    #[must_use]
    pub const fn config(&self) -> InputQueueConfig {
        self.config
    }

    /// Retain an event or account a drop without allocating.
    pub fn push(&mut self, event: InputEvent) -> PushResult {
        if self.len == self.slots.len() {
            self.dropped = self.dropped.saturating_add(1);
            return PushResult::Dropped;
        }
        let tail = (self.head + self.len) % self.slots.len();
        self.slots[tail] = Some(event);
        self.len += 1;
        PushResult::Enqueued
    }

    /// Remove the oldest retained event without allocating.
    pub fn pop(&mut self) -> Option<InputEvent> {
        if self.len == 0 {
            return None;
        }
        let event = self.slots[self.head].take();
        self.head = (self.head + 1) % self.slots.len();
        self.len -= 1;
        self.delivered = self.delivered.saturating_add(1);
        event
    }

    /// Account one hardware input interrupt.
    pub const fn record_interrupt(&mut self) {
        self.interrupts = self.interrupts.saturating_add(1);
    }

    /// Account one empty-queue transition into an architecture idle wait.
    pub const fn record_idle_wait(&mut self) {
        self.idle_waits = self.idle_waits.saturating_add(1);
    }

    /// Account one return from an architecture idle wait.
    pub const fn record_wakeup(&mut self) {
        self.wakeups = self.wakeups.saturating_add(1);
    }

    /// Current queue and delivery accounting.
    #[must_use]
    pub const fn stats(&self) -> InputQueueStats {
        InputQueueStats {
            capacity: self.slots.len(),
            queued: self.len,
            delivered: self.delivered,
            dropped: self.dropped,
            interrupts: self.interrupts,
            idle_waits: self.idle_waits,
            wakeups: self.wakeups,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        BoundedInputQueue, ConfigError, InputEvent, InputQueueConfig, InputSource,
        InterruptResource, IoPortResource, MmioResource, PushResult,
    };

    #[test]
    fn queue_policy_is_configurable_and_checked() {
        assert_eq!(InputQueueConfig::new(0, 1, 0xa0), Err(ConfigError::Empty));
        assert_eq!(InputQueueConfig::new(1, 0, 0xa0), Err(ConfigError::Empty));
        let tiny = InputQueueConfig::tiny();
        assert!(tiny.capacity() > 0);
        assert!(tiny.max_drain_per_interrupt() > 0);
        assert_eq!(tiny.interrupt_priority(), 0xa0);
    }

    #[test]
    fn queue_is_fifo_and_drops_newest_at_capacity() {
        let config = InputQueueConfig::new(2, 1, 0x80).unwrap_or_else(|_| InputQueueConfig::tiny());
        let mut queue =
            BoundedInputQueue::try_new(config).unwrap_or_else(|_| std::process::abort());
        let first = InputEvent::new(InputSource::Serial, b'a');
        let second = InputEvent::new(InputSource::Keyboard, 0x1e);
        assert_eq!(queue.push(first), PushResult::Enqueued);
        assert_eq!(queue.push(second), PushResult::Enqueued);
        assert_eq!(
            queue.push(InputEvent::new(InputSource::Serial, b'x')),
            PushResult::Dropped
        );
        queue.record_interrupt();
        assert_eq!(queue.pop(), Some(first));
        assert_eq!(queue.pop(), Some(second));
        assert_eq!(queue.pop(), None);
        let stats = queue.stats();
        assert_eq!(stats.delivered, 2);
        assert_eq!(stats.dropped, 1);
        assert_eq!(stats.interrupts, 1);
    }

    #[test]
    fn resource_descriptors_reject_invalid_ranges_and_vectors() {
        assert_eq!(MmioResource::new(u64::MAX, 2), Err(ConfigError::Overflow));
        assert_eq!(IoPortResource::new(u16::MAX, 2), Err(ConfigError::Overflow));
        assert_eq!(
            InterruptResource::new(1, 31),
            Err(ConfigError::InvalidVector)
        );
        assert!(InterruptResource::new(1, 0x31).is_ok());
    }
}
