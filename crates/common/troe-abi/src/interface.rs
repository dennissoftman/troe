//! Stable interface identifiers carried by startup handle descriptors.

/// One immutable command invocation.
pub const COMMAND: u32 = 1;
/// Standard input byte stream for one command launch.
pub const STANDARD_INPUT: u32 = 2;
/// Standard output byte stream for one command launch.
pub const STANDARD_OUTPUT: u32 = 3;
/// Standard error byte stream for one command launch.
pub const STANDARD_ERROR: u32 = 4;
/// Owned IPv4 datagram endpoint for one application lifetime.
pub const DATAGRAM: u32 = 5;
/// Read-only view of one application namespace.
pub const FILESYSTEM_READ: u32 = 6;
/// Atomic create/replace and remove authority for one application namespace.
pub const FILESYSTEM_MUTATE: u32 = 7;
/// Boot-relative monotonic time and cancellable waiting.
pub const TIMER: u32 = 8;
/// Immutable typed kernel and namespace diagnostics snapshot.
pub const DIAGNOSTICS: u32 = 9;
/// Read-only typed IPv4 configuration, counters, and neighbor state.
pub const NETWORK_OBSERVE: u32 = 10;
/// Bounded DHCP configuration authority.
pub const NETWORK_CONFIGURE: u32 = 11;
/// Bounded ICMP echo authority.
pub const ICMP_ECHO: u32 = 12;
/// One bounded outbound IPv4/TCP byte stream.
pub const TCP_CONNECT: u32 = 13;
/// List and activate manifest-authorized runtime volumes.
pub const VOLUME_CONTROL: u32 = 14;
/// Receive and reply to copied requests for one isolated user service.
pub const SERVER_ENDPOINT: u32 = 15;
/// Submit validated physical command lines to the owning shell session.
pub const SHELL_SCRIPT: u32 = 16;
/// Read the kernel-maintained Unix wall clock.
pub const WALL_CLOCK: u32 = 17;
/// Privileged authority to correct the kernel wall clock.
pub const CLOCK_CONTROL: u32 = 18;
/// Read-only bounded observation of registered application processes.
pub const PROCESS_OBSERVE: u32 = 19;
/// Owner-scoped authority to launch and control child KEX processes.
pub const PROCESS_LAUNCH: u32 = 20;
/// Owner-scoped bounded byte-pipe construction and endpoint I/O.
pub const PIPE: u32 = 21;
/// Caller-private anonymous virtual-memory reservation and mapping.
pub const PRIVATE_MEMORY: u32 = 22;
/// Kernel CSPRNG byte service.
pub const RANDOM: u32 = 23;

// ADR 0035's closed internal registry. These are reachable only from a fixed
// boot-service role, never from an ordinary `/bin` package, and they begin at
// the next free identifier rather than at the 16 that ADR proposed: 16 through
// 23 were assigned to application-facing interfaces after it was written.

/// Immutable wait set observed only through `ipc_reply_wait`.
pub const WAIT_SET: u32 = 24;
/// Bounded whole-frame transmit and receive for one brokered packet device.
pub const PACKET_DEVICE: u32 = 25;
/// Bounded read, write, flush, and derivation for one granted block region.
pub const BLOCK_REGION: u32 = 26;
/// Bounded offset reads of one immutable boot artifact.
pub const BOOT_BLOB: u32 = 27;
/// Supervisor-only initialize and shutdown for one persistent server.
pub const SERVICE_LIFECYCLE: u32 = 28;

/// Highest assigned interface identifier.
pub const HIGHEST: u32 = SERVICE_LIFECYCLE;

/// Rights bit positions shared by every interface, fixed by ADR 0035.
pub mod rights {
    /// Synchronous request/reply calls.
    pub const CALL: u16 = 1 << 0;
    /// Receiving one delivered call.
    pub const RECEIVE: u16 = 1 << 1;
    /// Replying to one delivered call.
    pub const REPLY: u16 = 1 << 2;
    /// Waiting on one immutable wait set.
    pub const WAIT: u16 = 1 << 3;
    /// Reading bytes.
    pub const READ: u16 = 1 << 4;
    /// Writing bytes.
    pub const WRITE: u16 = 1 << 5;
    /// Explicit durability flush.
    pub const FLUSH: u16 = 1 << 6;
    /// Deriving an equal-or-narrower child authority.
    pub const DERIVE: u16 = 1 << 7;
    /// Supervisor device reset.
    pub const RESET: u16 = 1 << 8;
    /// Every bit this ABI assigns a meaning.
    ///
    /// The assignment occupies bits 0 through 8, so rights are stored in 16
    /// bits and widened to the 32-bit field a startup handle descriptor
    /// carries.
    pub const ASSIGNED: u16 = CALL | RECEIVE | REPLY | WAIT | READ | WRITE | FLUSH | DERIVE | RESET;
}

/// Whether one identifier belongs to the closed boot-only internal registry.
///
/// A boot-only interface may be named by a fixed boot-service role and never by
/// an ordinary package requirement.
#[must_use]
pub const fn is_boot_only(interface: u32) -> bool {
    matches!(
        interface,
        WAIT_SET | PACKET_DEVICE | BLOCK_REGION | BOOT_BLOB | SERVICE_LIFECYCLE
    )
}

/// Rights one interface can meaningfully carry.
///
/// An interface rejects every bit outside this mask even when a malformed
/// startup record sets it, so a handle can never be granted authority its
/// interface has no operation for. An unassigned identifier carries none.
#[must_use]
pub const fn allowed_rights(interface: u32) -> u16 {
    match interface {
        // A persistent server owns the receive and reply side of its endpoint;
        // its clients hold the call side of the same interface.
        SERVER_ENDPOINT => rights::CALL | rights::RECEIVE | rights::REPLY,
        WAIT_SET => rights::WAIT,
        PACKET_DEVICE => rights::CALL | rights::READ | rights::WRITE | rights::RESET,
        BLOCK_REGION => {
            rights::CALL | rights::READ | rights::WRITE | rights::FLUSH | rights::DERIVE
        }
        BOOT_BLOB => rights::CALL | rights::READ,
        // The lifecycle interface and every application-facing interface are
        // reached only by calling them. Their operation-level authority is
        // carried by the interface identity itself, not by a rights bit.
        SERVICE_LIFECYCLE | COMMAND..=SERVER_ENDPOINT | SHELL_SCRIPT..=RANDOM => rights::CALL,
        _ => 0,
    }
}

#[cfg(test)]
mod tests {
    use crate::interface;

    #[test]
    fn interface_registry_is_unique_and_nonzero() {
        let interfaces = [
            interface::COMMAND,
            interface::STANDARD_INPUT,
            interface::STANDARD_OUTPUT,
            interface::STANDARD_ERROR,
            interface::DATAGRAM,
            interface::FILESYSTEM_READ,
            interface::FILESYSTEM_MUTATE,
            interface::TIMER,
            interface::DIAGNOSTICS,
            interface::NETWORK_OBSERVE,
            interface::NETWORK_CONFIGURE,
            interface::ICMP_ECHO,
            interface::TCP_CONNECT,
            interface::VOLUME_CONTROL,
            interface::SERVER_ENDPOINT,
            interface::SHELL_SCRIPT,
            interface::WALL_CLOCK,
            interface::CLOCK_CONTROL,
            interface::PROCESS_OBSERVE,
            interface::PROCESS_LAUNCH,
            interface::PIPE,
            interface::PRIVATE_MEMORY,
            interface::RANDOM,
            interface::WAIT_SET,
            interface::PACKET_DEVICE,
            interface::BLOCK_REGION,
            interface::BOOT_BLOB,
            interface::SERVICE_LIFECYCLE,
        ];
        assert!(interfaces.iter().all(|value| *value != 0));
        assert!(
            interfaces
                .iter()
                .enumerate()
                .all(|(index, value)| !interfaces[..index].contains(value))
        );
        assert_eq!(
            interfaces.iter().copied().max(),
            Some(interface::HIGHEST),
            "HIGHEST must name the last assigned identifier"
        );
        assert_eq!(
            interfaces.len(),
            interface::HIGHEST as usize,
            "the registry is dense, so every identifier through HIGHEST is assigned"
        );
    }

    #[test]
    fn only_the_internal_registry_is_boot_only() {
        for interface in 1..=interface::HIGHEST {
            assert_eq!(
                interface::is_boot_only(interface),
                interface >= interface::WAIT_SET,
                "interface {interface} has the wrong boot-only classification"
            );
        }
        assert!(!interface::is_boot_only(0));
        assert!(!interface::is_boot_only(interface::HIGHEST + 1));
    }

    #[test]
    fn every_interface_allows_only_bits_its_operations_need() {
        for interface in 1..=interface::HIGHEST {
            let allowed = interface::allowed_rights(interface);
            assert_ne!(allowed, 0, "interface {interface} carries no right");
            assert_eq!(
                allowed & !interface::rights::ASSIGNED,
                0,
                "interface {interface} allows an unassigned bit"
            );
        }
        // An unassigned identifier carries no authority at all, so a malformed
        // startup record naming one cannot be granted a right.
        assert_eq!(interface::allowed_rights(0), 0);
        assert_eq!(interface::allowed_rights(interface::HIGHEST + 1), 0);
        // Only the block region can derive a narrower child, and only the
        // packet device can be reset by its supervisor.
        for interface in 1..=interface::HIGHEST {
            let allowed = interface::allowed_rights(interface);
            assert_eq!(
                allowed & interface::rights::DERIVE != 0,
                interface == interface::BLOCK_REGION
            );
            assert_eq!(
                allowed & interface::rights::RESET != 0,
                interface == interface::PACKET_DEVICE
            );
            assert_eq!(
                allowed & interface::rights::WAIT != 0,
                interface == interface::WAIT_SET
            );
        }
    }

    #[test]
    fn assigned_rights_are_the_nine_fixed_bits() {
        assert_eq!(interface::rights::ASSIGNED.count_ones(), 9);
        assert_eq!(interface::rights::ASSIGNED, 0b1_1111_1111);
        assert_eq!(interface::rights::CALL, 1);
        assert_eq!(interface::rights::RESET, 1 << 8);
    }
}
