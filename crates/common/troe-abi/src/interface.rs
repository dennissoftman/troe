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
        ];
        assert!(interfaces.iter().all(|value| *value != 0));
        assert!(
            interfaces
                .iter()
                .enumerate()
                .all(|(index, value)| !interfaces[..index].contains(value))
        );
    }
}
