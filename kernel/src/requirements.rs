//! Decoding what an application declares it needs before it is launched.
//!
//! `decode_application_requirements` reads the requirement records out of a
//! parsed package and turns them into the concrete set of services, handles,
//! and capabilities the launch must attach.

use troe_abi::{
    clock_control, datagram, diagnostics, filesystem, filesystem_mutation, icmp_echo,
    network_configuration, network_observation, pipe, private_memory, process_launch,
    process_observation, random, shell_script, tcp_connect, timer, volume_control, wall_clock,
};

#[allow(clippy::struct_excessive_bools)]
#[derive(Clone, Copy)]
pub(crate) struct BackgroundRequirements {
    pub(crate) datagram: bool,
    pub(crate) filesystem: bool,
    pub(crate) filesystem_mutation: bool,
    pub(crate) timer: bool,
    pub(crate) diagnostics: bool,
    pub(crate) process_observation: bool,
    pub(crate) process_launch: bool,
    pub(crate) pipe: bool,
    pub(crate) network_observation: bool,
    pub(crate) network_configuration: bool,
    pub(crate) icmp_echo: bool,
    pub(crate) tcp_connect: bool,
    pub(crate) volume_control: bool,
    pub(crate) wall_clock: bool,
    pub(crate) clock_control: bool,
    pub(crate) private_memory: bool,
    pub(crate) random: bool,
}

impl BackgroundRequirements {
    pub(crate) fn attenuates(self, required: Self, shell_script: bool) -> bool {
        !shell_script
            && !required.clock_control
            && (!required.datagram || self.datagram)
            && (!required.filesystem || self.filesystem)
            && (!required.filesystem_mutation || self.filesystem_mutation)
            && (!required.timer || self.timer)
            && (!required.diagnostics || self.diagnostics)
            && (!required.process_observation || self.process_observation)
            && (!required.process_launch || self.process_launch)
            && (!required.pipe || self.pipe)
            && (!required.network_observation || self.network_observation)
            && (!required.network_configuration || self.network_configuration)
            && (!required.icmp_echo || self.icmp_echo)
            && (!required.tcp_connect || self.tcp_connect)
            && (!required.volume_control || self.volume_control)
            && (!required.wall_clock || self.wall_clock)
            && (!required.private_memory || self.private_memory)
            && (!required.random || self.random)
    }
}

#[allow(clippy::too_many_lines)]
pub(crate) fn decode_application_requirements(
    manifest: troe_abi::requirements::Manifest<'_>,
) -> Result<(BackgroundRequirements, bool), ()> {
    let mut required = BackgroundRequirements {
        datagram: false,
        filesystem: false,
        filesystem_mutation: false,
        timer: false,
        diagnostics: false,
        process_observation: false,
        process_launch: false,
        pipe: false,
        network_observation: false,
        network_configuration: false,
        icmp_echo: false,
        tcp_connect: false,
        volume_control: false,
        wall_clock: false,
        clock_control: false,
        private_memory: false,
        random: false,
    };
    let mut shell_script = false;
    for requirement in manifest.iter() {
        let supported = match requirement.interface {
            troe_abi::interface::DATAGRAM => {
                required.datagram = true;
                requirement.major == datagram::MAJOR && requirement.minor == datagram::MINOR
            }
            troe_abi::interface::FILESYSTEM_READ => {
                required.filesystem = true;
                requirement.major == filesystem::MAJOR && requirement.minor == filesystem::MINOR
            }
            troe_abi::interface::FILESYSTEM_MUTATE => {
                required.filesystem_mutation = true;
                requirement.major == filesystem_mutation::MAJOR
                    && requirement.minor == filesystem_mutation::MINOR
            }
            troe_abi::interface::TIMER => {
                required.timer = true;
                requirement.major == timer::MAJOR && requirement.minor == timer::MINOR
            }
            troe_abi::interface::DIAGNOSTICS => {
                required.diagnostics = true;
                requirement.major == diagnostics::MAJOR && requirement.minor == diagnostics::MINOR
            }
            troe_abi::interface::PROCESS_OBSERVE => {
                required.process_observation = true;
                requirement.major == process_observation::MAJOR
                    && requirement.minor == process_observation::MINOR
            }
            troe_abi::interface::PROCESS_LAUNCH => {
                required.process_launch = true;
                requirement.major == process_launch::MAJOR
                    && requirement.minor == process_launch::MINOR
            }
            troe_abi::interface::PIPE => {
                required.pipe = true;
                requirement.major == pipe::MAJOR && requirement.minor == pipe::MINOR
            }
            troe_abi::interface::NETWORK_OBSERVE => {
                required.network_observation = true;
                requirement.major == network_observation::MAJOR
                    && requirement.minor == network_observation::MINOR
            }
            troe_abi::interface::NETWORK_CONFIGURE => {
                required.network_configuration = true;
                requirement.major == network_configuration::MAJOR
                    && requirement.minor == network_configuration::MINOR
            }
            troe_abi::interface::ICMP_ECHO => {
                required.icmp_echo = true;
                requirement.major == icmp_echo::MAJOR && requirement.minor == icmp_echo::MINOR
            }
            troe_abi::interface::TCP_CONNECT => {
                required.tcp_connect = true;
                requirement.major == tcp_connect::MAJOR && requirement.minor == tcp_connect::MINOR
            }
            troe_abi::interface::VOLUME_CONTROL => {
                required.volume_control = true;
                requirement.major == volume_control::MAJOR
                    && requirement.minor == volume_control::MINOR
            }
            troe_abi::interface::SHELL_SCRIPT => {
                shell_script = true;
                requirement.major == shell_script::MAJOR && requirement.minor == shell_script::MINOR
            }
            troe_abi::interface::WALL_CLOCK => {
                required.wall_clock = true;
                requirement.major == wall_clock::MAJOR && requirement.minor == wall_clock::MINOR
            }
            troe_abi::interface::CLOCK_CONTROL => {
                required.clock_control = true;
                requirement.major == clock_control::MAJOR
                    && requirement.minor == clock_control::MINOR
            }
            troe_abi::interface::PRIVATE_MEMORY => {
                required.private_memory = true;
                requirement.major == private_memory::MAJOR
                    && requirement.minor == private_memory::MINOR
            }
            troe_abi::interface::RANDOM => {
                required.random = true;
                requirement.major == random::MAJOR && requirement.minor == random::MINOR
            }
            _ => false,
        };
        if !supported {
            return Err(());
        }
    }
    Ok((required, shell_script))
}
