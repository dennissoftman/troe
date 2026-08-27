//! Minimal `no_std` runtime for bounded KEX command applications.
#![no_std]

use core::{fmt, slice};

pub use troe_abi::{
    ABI_MAJOR, ABI_MINOR, clock_control, command, datagram, diagnostics, exit, filesystem,
    filesystem_mutation, icmp_echo, interface, network_configuration, network_observation, pipe,
    process_launch, process_observation, reply, server, shell_script, tcp_connect, timer,
    volume_control, wall_clock,
};
use troe_abi::{MAX_MESSAGE_BYTES, MAX_SERVICE_PAYLOAD_BYTES, heap_growth, stream};

const STARTUP_PAGE_BYTES: usize = 4096;
const STARTUP_HEADER_BYTES: usize = 64;
const STARTUP_HANDLE_BYTES: usize = 24;
const CALL_RIGHT: u32 = 1;
const KEX_IMAGE_BASE: u64 = 0x0000_4000_0000_0000;
const KEX_IMAGE_SPAN_BYTES: u64 = 128 * 1024 * 1024;
const KEX_USER_END: u64 = 0x0000_8000_0000_0000;
const KEX_MAXIMUM_STACK_BYTES: u64 = 256 * STARTUP_PAGE_BYTES as u64;
const KEX_MINIMUM_STACK_BYTES: u64 = 4 * STARTUP_PAGE_BYTES as u64;
const KEX_STARTUP_ADDRESS: u64 = KEX_IMAGE_BASE + KEX_IMAGE_SPAN_BYTES;
const KEX_HEAP_ADDRESS: u64 = KEX_STARTUP_ADDRESS + STARTUP_PAGE_BYTES as u64;
const KEX_STACK_TOP: u64 = KEX_USER_END - STARTUP_PAGE_BYTES as u64;
const KEX_LOWER_STACK_GUARD: u64 =
    KEX_STACK_TOP - KEX_MAXIMUM_STACK_BYTES - STARTUP_PAGE_BYTES as u64;
const KEX_HEAP_SLOT_BYTES: u64 = KEX_LOWER_STACK_GUARD - KEX_HEAP_ADDRESS;

/// Maximum stack buffer needed to receive one command invocation.
pub const INVOCATION_BUFFER_BYTES: usize = command::MAX_INVOCATION_BYTES;
/// Maximum stack buffer needed to receive the immutable launch environment.
pub const ENVIRONMENT_BUFFER_BYTES: usize = command::MAX_ENCODED_ENVIRONMENT_BYTES;
/// Maximum stack buffer needed to receive one datagram.
pub const DATAGRAM_BUFFER_BYTES: usize = datagram::MAX_RECEIVE_REPLY_BYTES;
/// Maximum stack buffer needed to receive one directory page.
pub const FILESYSTEM_LIST_BUFFER_BYTES: usize = filesystem::MAX_LIST_REPLY_BYTES;
/// Maximum useful payload buffer for one filesystem range read or append call.
pub const FILESYSTEM_IO_BUFFER_BYTES: usize = MAX_SERVICE_PAYLOAD_BYTES;
/// Smallest accepted file-stream aggregation hint.
pub const MIN_FILE_STREAM_CHUNK_BYTES: usize = stream::MIN_CHUNK_SIZE;
/// Largest accepted file-stream aggregation hint.
pub const MAX_FILE_STREAM_CHUNK_BYTES: usize = stream::MAX_CHUNK_SIZE;
/// Maximum stack buffer needed to receive one isolated-server request.
pub const SERVER_REQUEST_BUFFER_BYTES: usize = MAX_MESSAGE_BYTES;

/// One opaque application handle selected from the immutable startup page.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Handle {
    value: u64,
}

/// Single-owner view of the application's validated, initially zeroed heap.
///
/// The startup page can describe at most one heap. This token is intentionally
/// neither `Copy` nor `Clone`, so a runtime can consume it exactly once when it
/// initializes an allocator.
#[derive(Debug, Eq, PartialEq)]
pub struct HeapRegion {
    address: usize,
    byte_len: usize,
}

impl HeapRegion {
    /// Address of the first writable heap byte.
    #[must_use]
    pub const fn start_address(&self) -> usize {
        self.address
    }

    /// Number of mapped writable heap bytes.
    #[must_use]
    pub const fn byte_len(&self) -> usize {
        self.byte_len
    }

    /// Consume the single-owner token and return its writable address range.
    #[must_use]
    pub const fn into_raw_parts(self) -> (usize, usize) {
        (self.address, self.byte_len)
    }
}

/// Invalid startup page or missing command authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StartupError {
    /// Fixed startup fields, lengths, padding, or memory geometry are invalid.
    InvalidPage,
    /// A handle descriptor is invalid or duplicated.
    InvalidHandle,
    /// A required command interface is missing, duplicated, or incompatible.
    MissingAuthority,
}

/// Application call or service failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    /// Request, reply, pointer, or returned length violated the ABI contract.
    InvalidCall,
    /// Service rejected the opcode or request payload.
    InvalidRequest,
    /// Requested service object was not found.
    NotFound,
    /// Service failed the operation.
    Failure,
    /// A bounded service resource is exhausted.
    Exhausted,
    /// The network has no usable IPv4 configuration.
    NotConfigured,
    /// Cooperative work was cancelled.
    Cancelled,
    /// A bounded service wait expired.
    Timeout,
    /// The requested resource has another owner.
    Conflict,
    /// A service-domain payload ceiling was exceeded.
    TooLarge,
    /// Required startup authority was absent or incompatible.
    MissingAuthority,
    /// Command invocation bytes were malformed.
    InvalidInvocation,
    /// This build target cannot execute the native KEX call gate.
    UnsupportedTarget,
    /// A filesystem path was invalid.
    InvalidPath,
    /// A filesystem object had the wrong type.
    WrongType,
    /// A filesystem mutation targeted immutable content.
    ReadOnly,
    /// A filesystem quota was exhausted.
    NoSpace,
    /// A filesystem object already exists.
    Exists,
    /// Filesystem metadata was corrupt.
    Corrupt,
    /// A filesystem transport failed.
    Io,
    /// A filesystem feature is unsupported.
    Unsupported,
    /// Filesystem arithmetic overflowed.
    Overflow,
    /// A network exchange returned an invalid protocol response.
    NetworkProtocol,
    /// The caller lacks authority for the requested operation.
    Denied,
}

impl fmt::Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidCall => "invalid KEX ABI call",
            Self::InvalidRequest => "service rejected the request",
            Self::NotFound => "service object not found",
            Self::Failure => "service operation failed",
            Self::Exhausted => "bounded service resources exhausted",
            Self::NotConfigured => "network is not configured",
            Self::Cancelled => "operation cancelled",
            Self::Timeout => "operation timed out",
            Self::Conflict => "resource is already owned",
            Self::TooLarge => "service payload is too large",
            Self::MissingAuthority => "required application authority missing",
            Self::InvalidInvocation => "command invocation is invalid",
            Self::UnsupportedTarget => "KEX calls require a freestanding supported target",
            Self::InvalidPath => "invalid path or filesystem image",
            Self::WrongType => "wrong node type",
            Self::ReadOnly => "read-only filesystem",
            Self::NoSpace => "filesystem quota exceeded",
            Self::Exists => "already exists",
            Self::Corrupt => "filesystem metadata is corrupt",
            Self::Io => "filesystem transport failed",
            Self::Unsupported => "filesystem feature is unsupported",
            Self::Overflow => "filesystem size overflow",
            Self::NetworkProtocol => "invalid network response",
            Self::Denied => "operation denied",
        })
    }
}

/// Validated command launch with explicit standard stream handles.
pub struct CommandContext {
    invocation: Handle,
    stdin: Handle,
    stdout: Handle,
    stderr: Handle,
    datagram: Option<Handle>,
    filesystem_read: Option<Handle>,
    filesystem_mutate: Option<Handle>,
    timer: Option<Handle>,
    diagnostics: Option<Handle>,
    process_observation: Option<Handle>,
    process_launch: Option<Handle>,
    pipe: Option<Handle>,
    network_observation: Option<Handle>,
    network_configuration: Option<Handle>,
    icmp_echo: Option<Handle>,
    tcp_connect: Option<Handle>,
    volume_control: Option<Handle>,
    shell_script: Option<Handle>,
    wall_clock: Option<Handle>,
    clock_control: Option<Handle>,
    heap: Option<HeapRegion>,
}

impl CommandContext {
    fn from_startup(startup: &Startup<'_>) -> Result<Self, StartupError> {
        Ok(Self {
            invocation: startup.required_handle(
                interface::COMMAND,
                command::MAJOR,
                command::MINOR,
            )?,
            stdin: startup.required_handle(
                interface::STANDARD_INPUT,
                stream::MAJOR,
                stream::MINOR,
            )?,
            stdout: startup.required_handle(
                interface::STANDARD_OUTPUT,
                stream::MAJOR,
                stream::MINOR,
            )?,
            stderr: startup.required_handle(
                interface::STANDARD_ERROR,
                stream::MAJOR,
                stream::MINOR,
            )?,
            datagram: startup.optional_handle(
                interface::DATAGRAM,
                datagram::MAJOR,
                datagram::MINOR,
            )?,
            filesystem_read: startup.optional_handle(
                interface::FILESYSTEM_READ,
                filesystem::MAJOR,
                filesystem::MINOR,
            )?,
            filesystem_mutate: startup.optional_handle(
                interface::FILESYSTEM_MUTATE,
                filesystem_mutation::MAJOR,
                filesystem_mutation::MINOR,
            )?,
            timer: startup.optional_handle(interface::TIMER, timer::MAJOR, timer::MINOR)?,
            diagnostics: startup.optional_handle(
                interface::DIAGNOSTICS,
                diagnostics::MAJOR,
                diagnostics::MINOR,
            )?,
            process_observation: startup.optional_handle(
                interface::PROCESS_OBSERVE,
                process_observation::MAJOR,
                process_observation::MINOR,
            )?,
            process_launch: startup.optional_handle(
                interface::PROCESS_LAUNCH,
                process_launch::MAJOR,
                process_launch::MINOR,
            )?,
            pipe: startup.optional_handle(interface::PIPE, pipe::MAJOR, pipe::MINOR)?,
            network_observation: startup.optional_handle(
                interface::NETWORK_OBSERVE,
                network_observation::MAJOR,
                network_observation::MINOR,
            )?,
            network_configuration: startup.optional_handle(
                interface::NETWORK_CONFIGURE,
                network_configuration::MAJOR,
                network_configuration::MINOR,
            )?,
            icmp_echo: startup.optional_handle(
                interface::ICMP_ECHO,
                icmp_echo::MAJOR,
                icmp_echo::MINOR,
            )?,
            tcp_connect: startup.optional_handle(
                interface::TCP_CONNECT,
                tcp_connect::MAJOR,
                tcp_connect::MINOR,
            )?,
            volume_control: startup.optional_handle(
                interface::VOLUME_CONTROL,
                volume_control::MAJOR,
                volume_control::MINOR,
            )?,
            shell_script: startup.optional_handle(
                interface::SHELL_SCRIPT,
                shell_script::MAJOR,
                shell_script::MINOR,
            )?,
            wall_clock: startup.optional_handle(
                interface::WALL_CLOCK,
                wall_clock::MAJOR,
                wall_clock::MINOR,
            )?,
            clock_control: startup.optional_handle(
                interface::CLOCK_CONTROL,
                clock_control::MAJOR,
                clock_control::MINOR,
            )?,
            heap: startup.heap_region()?,
        })
    }

    /// Consume the application's validated heap token, if the package
    /// requested a nonzero heap.
    ///
    /// A second call returns `None`. This makes allocator ownership explicit
    /// and prevents two safe runtimes from independently managing the same
    /// bytes.
    pub fn take_heap(&mut self) -> Option<HeapRegion> {
        self.heap.take()
    }

    /// Fetch and validate the one immutable invocation record.
    ///
    /// # Errors
    ///
    /// Reports call, service, authority, or canonical decoding failure.
    pub fn invocation<'buffer>(
        &self,
        buffer: &'buffer mut [u8; INVOCATION_BUFFER_BYTES],
    ) -> Result<command::Invocation<'buffer>, Error> {
        let count = call(self.invocation, command::GET_INVOCATION, &[], buffer)?;
        command::Invocation::parse(&buffer[..count]).map_err(|_| Error::InvalidInvocation)
    }

    /// Fetch and validate the immutable `NAME=VALUE` launch environment.
    ///
    /// # Errors
    ///
    /// Reports call, service, authority, or canonical decoding failure.
    pub fn environment<'buffer>(
        &self,
        buffer: &'buffer mut [u8; ENVIRONMENT_BUFFER_BYTES],
    ) -> Result<command::Environment<'buffer>, Error> {
        let count = call(self.invocation, command::GET_ENVIRONMENT, &[], buffer)?;
        command::Environment::parse(&buffer[..count]).map_err(|_| Error::InvalidInvocation)
    }

    /// Borrow the standard-input client.
    #[must_use]
    pub const fn stdin(&self) -> StandardInput {
        StandardInput { handle: self.stdin }
    }

    /// Borrow the standard-output client.
    #[must_use]
    pub const fn stdout(&self) -> StandardOutput {
        StandardOutput {
            handle: self.stdout,
        }
    }

    /// Borrow the standard-error client.
    #[must_use]
    pub const fn stderr(&self) -> StandardOutput {
        StandardOutput {
            handle: self.stderr,
        }
    }

    /// Borrow the optional owned IPv4 datagram capability.
    ///
    /// # Errors
    ///
    /// Reports that the kernel did not grant a network endpoint to this app.
    pub const fn datagram(&self) -> Result<Datagram, Error> {
        match self.datagram {
            Some(handle) => Ok(Datagram { handle }),
            None => Err(Error::MissingAuthority),
        }
    }

    /// Borrow the optional read-only filesystem capability.
    ///
    /// # Errors
    ///
    /// Reports that the package did not request or receive namespace authority.
    pub const fn filesystem(&self) -> Result<ReadOnlyFilesystem, Error> {
        match self.filesystem_read {
            Some(handle) => Ok(ReadOnlyFilesystem { handle }),
            None => Err(Error::MissingAuthority),
        }
    }

    /// Borrow the optional streamed filesystem-mutation capability.
    ///
    /// # Errors
    ///
    /// Reports that the package did not request or receive mutation authority.
    pub const fn filesystem_mutation(&self) -> Result<FilesystemMutation, Error> {
        match self.filesystem_mutate {
            Some(handle) => Ok(FilesystemMutation { handle }),
            None => Err(Error::MissingAuthority),
        }
    }

    /// Borrow the optional boot-relative monotonic timer capability.
    ///
    /// # Errors
    ///
    /// Reports that the package did not request or receive timer authority.
    pub const fn timer(&self) -> Result<Timer, Error> {
        match self.timer {
            Some(handle) => Ok(Timer { handle }),
            None => Err(Error::MissingAuthority),
        }
    }

    /// Borrow the optional read-only wall-clock capability.
    ///
    /// # Errors
    ///
    /// Reports that the package did not request or receive wall-clock access.
    pub const fn wall_clock(&self) -> Result<WallClock, Error> {
        match self.wall_clock {
            Some(handle) => Ok(WallClock { handle }),
            None => Err(Error::MissingAuthority),
        }
    }

    /// Borrow the optional privileged wall-clock correction capability.
    ///
    /// # Errors
    ///
    /// Reports that the package did not request or receive clock authority.
    pub const fn clock_control(&self) -> Result<ClockControl, Error> {
        match self.clock_control {
            Some(handle) => Ok(ClockControl { handle }),
            None => Err(Error::MissingAuthority),
        }
    }

    /// Borrow the optional immutable diagnostics capability.
    ///
    /// # Errors
    ///
    /// Reports that the package did not request or receive diagnostics.
    pub const fn diagnostics(&self) -> Result<Diagnostics, Error> {
        match self.diagnostics {
            Some(handle) => Ok(Diagnostics { handle }),
            None => Err(Error::MissingAuthority),
        }
    }

    /// Borrow the optional current-process observation capability.
    ///
    /// # Errors
    ///
    /// Reports that the package did not request or receive observation authority.
    pub const fn process_observation(&self) -> Result<ProcessObservation, Error> {
        match self.process_observation {
            Some(handle) => Ok(ProcessObservation { handle }),
            None => Err(Error::MissingAuthority),
        }
    }

    /// Borrow the optional owner-scoped child-process capability.
    ///
    /// # Errors
    ///
    /// Reports that the package did not request or receive launch authority.
    pub const fn process_launcher(&self) -> Result<ProcessLauncher, Error> {
        match self.process_launch {
            Some(handle) => Ok(ProcessLauncher { handle }),
            None => Err(Error::MissingAuthority),
        }
    }

    /// Borrow the optional owner-scoped bounded-pipe capability.
    ///
    /// # Errors
    ///
    /// Reports that the package did not request or receive pipe authority.
    pub const fn pipes(&self) -> Result<Pipes, Error> {
        match self.pipe {
            Some(handle) => Ok(Pipes { handle }),
            None => Err(Error::MissingAuthority),
        }
    }

    /// Borrow the optional read-only typed network-observation capability.
    ///
    /// # Errors
    ///
    /// Reports that the package did not request or receive observation.
    pub const fn network_observation(&self) -> Result<NetworkObservation, Error> {
        match self.network_observation {
            Some(handle) => Ok(NetworkObservation { handle }),
            None => Err(Error::MissingAuthority),
        }
    }

    /// Borrow the optional bounded network-configuration capability.
    ///
    /// # Errors
    ///
    /// Reports that the package did not request or receive configuration.
    pub const fn network_configuration(&self) -> Result<NetworkConfiguration, Error> {
        match self.network_configuration {
            Some(handle) => Ok(NetworkConfiguration { handle }),
            None => Err(Error::MissingAuthority),
        }
    }

    /// Borrow the optional bounded ICMP echo capability.
    ///
    /// # Errors
    ///
    /// Reports that the package did not request or receive echo authority.
    pub const fn icmp_echo(&self) -> Result<IcmpEcho, Error> {
        match self.icmp_echo {
            Some(handle) => Ok(IcmpEcho { handle }),
            None => Err(Error::MissingAuthority),
        }
    }

    /// Borrow the optional one-shot outbound TCP connect authority.
    ///
    /// # Errors
    ///
    /// Reports that the package did not request or receive TCP authority.
    pub const fn tcp_connect(&self) -> Result<TcpConnect, Error> {
        match self.tcp_connect {
            Some(handle) => Ok(TcpConnect { handle }),
            None => Err(Error::MissingAuthority),
        }
    }

    /// Borrow the optional manifest-authorized volume-control capability.
    ///
    /// # Errors
    ///
    /// Reports that the package did not request or receive mount authority.
    pub const fn volume_control(&self) -> Result<VolumeControl, Error> {
        match self.volume_control {
            Some(handle) => Ok(VolumeControl { handle }),
            None => Err(Error::MissingAuthority),
        }
    }

    /// Borrow the optional bounded shell-script submission capability.
    ///
    /// # Errors
    ///
    /// Reports that the package did not request or receive authority to submit
    /// command lines to its owning shell session.
    pub const fn shell_script(&self) -> Result<ShellScript, Error> {
        match self.shell_script {
            Some(handle) => Ok(ShellScript { handle }),
            None => Err(Error::MissingAuthority),
        }
    }

    /// Yield cooperatively and resume only after kernel reselection.
    ///
    /// # Errors
    ///
    /// Reports an invalid kernel completion or a non-freestanding host build.
    pub fn yield_now(&mut self) -> Result<(), Error> {
        yield_now()
    }
}

/// Validated startup authority for one isolated user service.
pub struct ServerContext {
    endpoint: Handle,
    heap: Option<HeapRegion>,
}

impl ServerContext {
    fn from_startup(startup: &Startup<'_>) -> Result<Self, StartupError> {
        Ok(Self {
            endpoint: startup.required_handle(
                interface::SERVER_ENDPOINT,
                server::MAJOR,
                server::MINOR,
            )?,
            heap: startup.heap_region()?,
        })
    }

    /// Consume the server's validated heap token, if one was configured.
    pub fn take_heap(&mut self) -> Option<HeapRegion> {
        self.heap.take()
    }

    /// Receive the copied request assigned to this server invocation.
    ///
    /// The returned request and payload borrow `buffer`. The opaque token must
    /// be supplied unchanged to [`Self::reply`].
    ///
    /// # Errors
    ///
    /// Reports call-gate, service-fate, or canonical decoding failure.
    pub fn receive<'buffer>(
        &self,
        buffer: &'buffer mut [u8; SERVER_REQUEST_BUFFER_BYTES],
    ) -> Result<server::ReceivedRequest<'buffer>, Error> {
        let count = call(self.endpoint, server::RECEIVE, &[], buffer)?;
        server::decode_received_request(&buffer[..count]).map_err(|_| Error::InvalidCall)
    }

    /// Complete one received request exactly once with copied reply bytes.
    ///
    /// # Errors
    ///
    /// Reports an invalid token/status/payload, duplicate completion, peer
    /// fate, or call-gate failure.
    pub fn reply(&self, token: u64, status: u32, payload: &[u8]) -> Result<(), Error> {
        let mut request = [0_u8; MAX_SERVICE_PAYLOAD_BYTES];
        let count = server::encode_reply_request(token, status, payload, &mut request)
            .map_err(|_| Error::InvalidCall)?;
        let mut response = [0_u8; 0];
        let count = call(
            self.endpoint,
            server::REPLY,
            &request[..count],
            &mut response,
        )?;
        if count == 0 {
            Ok(())
        } else {
            Err(Error::InvalidCall)
        }
    }
}

/// Yield cooperatively and resume only after kernel reselection.
///
/// This free function is useful to language-runtime callbacks that cannot
/// retain a mutable borrow of [`CommandContext`].
///
/// # Errors
///
/// Reports an invalid kernel completion or a non-freestanding host build.
pub fn yield_now() -> Result<(), Error> {
    native_yield()
}

/// Commit at least `minimum_additional_pages` after the currently mapped heap.
///
/// The operation is grow-only. Successful pages are zeroed by the kernel and
/// the returned value is the complete current mapped heap length in bytes.
/// This primitive is runtime-neutral; allocators and a future libc can build
/// `sbrk`-like policy on it without exposing physical-memory layout.
///
/// # Safety
///
/// The caller must exclusively own the startup [`HeapRegion`], serialize all
/// heap access, and incorporate every successful extension into the same
/// allocator before requesting another one.
///
/// # Errors
///
/// Returns [`Error::Exhausted`] when system frames, commit metadata, or the
/// remaining user virtual range are unavailable. Other failures indicate an
/// invalid ABI completion or an unsupported hosted target.
pub unsafe fn grow_heap(minimum_additional_pages: usize) -> Result<usize, Error> {
    if minimum_additional_pages == 0 {
        return Err(Error::InvalidCall);
    }
    let pages = u64::try_from(minimum_additional_pages).map_err(|_| Error::InvalidCall)?;
    let (status, mapped_bytes) = native_grow_heap(pages)?;
    match status {
        heap_growth::SUCCESS
            if mapped_bytes != 0
                && u64::try_from(mapped_bytes).is_ok_and(|bytes| bytes <= KEX_HEAP_SLOT_BYTES)
                && mapped_bytes.is_multiple_of(STARTUP_PAGE_BYTES) =>
        {
            Ok(mapped_bytes)
        }
        heap_growth::EXHAUSTED if mapped_bytes == 0 => Err(Error::Exhausted),
        _ => Err(Error::InvalidCall),
    }
}

/// Read-only standard-input client.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StandardInput {
    handle: Handle,
}

impl StandardInput {
    /// Read up to `destination.len()` bytes; zero is end-of-input.
    ///
    /// # Errors
    ///
    /// Reports service, call-gate, or invalid-buffer failure.
    pub fn read(&mut self, destination: &mut [u8]) -> Result<usize, Error> {
        if destination.is_empty() {
            return Ok(0);
        }
        let requested = destination.len().min(MAX_SERVICE_PAYLOAD_BYTES);
        let request = stream::encode_read_request(requested).map_err(|_| Error::InvalidCall)?;
        call(
            self.handle,
            stream::READ,
            &request,
            &mut destination[..requested],
        )
    }
}

/// Write-only standard-output or standard-error client.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StandardOutput {
    handle: Handle,
}

impl StandardOutput {
    /// Select a bounded downstream aggregation size.
    ///
    /// File-backed redirection accepts power-of-two values from 4 KiB through
    /// 1 MiB. Other sinks may report `Unsupported`.
    ///
    /// # Errors
    ///
    /// Reports an invalid size, unsupported sink, service, or call-gate failure.
    pub fn set_chunk_size(&mut self, bytes: usize) -> Result<(), Error> {
        let request = stream::encode_chunk_size(bytes).map_err(|_| Error::InvalidCall)?;
        let mut reply = [];
        let count = call(self.handle, stream::SET_CHUNK_SIZE, &request, &mut reply)?;
        if count == 0 {
            Ok(())
        } else {
            Err(Error::InvalidCall)
        }
    }

    /// Write the complete byte slice using bounded copied calls.
    ///
    /// # Errors
    ///
    /// Reports the first service or call-gate failure.
    pub fn write_all(&mut self, mut bytes: &[u8]) -> Result<(), Error> {
        let mut reply_buffer = [];
        while !bytes.is_empty() {
            let count = bytes.len().min(MAX_SERVICE_PAYLOAD_BYTES);
            let reply_bytes = call(
                self.handle,
                stream::WRITE,
                &bytes[..count],
                &mut reply_buffer,
            )?;
            if reply_bytes != 0 {
                return Err(Error::InvalidCall);
            }
            bytes = &bytes[count..];
        }
        Ok(())
    }
}

/// Owned IPv4/UDP datagram client scoped to one application lifetime.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Datagram {
    handle: Handle,
}

/// Read-only namespace client scoped to one application lifetime.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReadOnlyFilesystem {
    handle: Handle,
}

/// Streamed file-mutation and link client scoped to one application lifetime.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FilesystemMutation {
    handle: Handle,
}

/// Boot-relative monotonic timer client scoped to one application lifetime.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Timer {
    handle: Handle,
}

/// Read-only kernel wall-clock client.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WallClock {
    handle: Handle,
}

/// Privileged kernel wall-clock correction client.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ClockControl {
    handle: Handle,
}

/// Immutable diagnostics client scoped to one application lifetime.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Diagnostics {
    handle: Handle,
}

/// Read-only current-process observation client.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProcessObservation {
    handle: Handle,
}

/// Owner-scoped child-process launch and lifecycle client.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProcessLauncher {
    handle: Handle,
}

/// Owner-scoped bounded byte-pipe client.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Pipes {
    handle: Handle,
}

/// Read-only typed network-observation client.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NetworkObservation {
    handle: Handle,
}

/// Bounded network-configuration client.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NetworkConfiguration {
    handle: Handle,
}

/// Bounded ICMP echo client.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct IcmpEcho {
    handle: Handle,
}

/// One-shot literal-IPv4 outbound TCP connect authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TcpConnect {
    handle: Handle,
}

/// Manifest-authorized runtime volume activation client.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VolumeControl {
    handle: Handle,
}

/// Bounded command-line submission client for a shell interpreter.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ShellScript {
    handle: Handle,
}

/// One connected bounded TCP byte stream.
#[derive(Debug, Eq, PartialEq)]
pub struct TcpConnection {
    handle: Handle,
    local_port: u16,
}

/// One pending sequential file replacement.
pub struct FileReplacement {
    handle: Handle,
    token: u32,
    offset: u64,
}

impl ReadOnlyFilesystem {
    /// Resolve and open one regular file.
    ///
    /// # Errors
    ///
    /// Reports invalid/missing paths, wrong types, resource exhaustion, or a
    /// service/call-gate failure.
    pub fn open(&mut self, path: &str) -> Result<filesystem::OpenFile, Error> {
        let mut request = [0_u8; filesystem::MAX_PATH_BYTES];
        let count =
            filesystem::encode_path_request(path, &mut request).map_err(|_| Error::InvalidCall)?;
        let mut reply = [0_u8; filesystem::OPEN_REPLY_BYTES];
        let count = call(self.handle, filesystem::OPEN, &request[..count], &mut reply)?;
        filesystem::decode_open_reply(&reply[..count]).map_err(|_| Error::InvalidCall)
    }

    /// Read a bounded range through an open-file token; zero is EOF.
    ///
    /// # Errors
    ///
    /// Reports stale tokens, invalid offsets, filesystem failures, or a
    /// service/call-gate failure.
    pub fn read(
        &mut self,
        file: filesystem::OpenFile,
        offset: u64,
        destination: &mut [u8],
    ) -> Result<usize, Error> {
        if destination.is_empty() {
            return Ok(0);
        }
        let requested = destination.len().min(MAX_SERVICE_PAYLOAD_BYTES);
        let request = filesystem::encode_read_request(file, offset, requested)
            .map_err(|_| Error::InvalidCall)?;
        call(
            self.handle,
            filesystem::READ,
            &request,
            &mut destination[..requested],
        )
    }

    /// Release one open-file token.
    ///
    /// # Errors
    ///
    /// Reports a stale token or service/call-gate failure.
    pub fn close(&mut self, file: filesystem::OpenFile) -> Result<(), Error> {
        let request = filesystem::encode_close_request(file);
        let mut reply = [];
        let count = call(self.handle, filesystem::CLOSE, &request, &mut reply)?;
        if count == 0 {
            Ok(())
        } else {
            Err(Error::InvalidCall)
        }
    }

    /// Return metadata for one file or directory without opening it.
    ///
    /// # Errors
    ///
    /// Reports path, namespace, service, or call-gate failures.
    pub fn metadata(&mut self, path: &str) -> Result<filesystem::Metadata, Error> {
        let mut request = [0_u8; filesystem::MAX_PATH_BYTES];
        let count =
            filesystem::encode_path_request(path, &mut request).map_err(|_| Error::InvalidCall)?;
        let mut reply = [0_u8; filesystem::METADATA_REPLY_BYTES];
        let count = call(
            self.handle,
            filesystem::METADATA,
            &request[..count],
            &mut reply,
        )?;
        filesystem::decode_metadata_reply(&reply[..count]).map_err(|_| Error::InvalidCall)
    }

    /// Return one bounded lexical directory page.
    ///
    /// The reply borrows `buffer`; pass the returned cursor to the next call.
    ///
    /// # Errors
    ///
    /// Reports path/cursor/budget, namespace, service, or call-gate failures.
    pub fn list<'buffer>(
        &mut self,
        path: &str,
        cursor: u64,
        max_entries: usize,
        max_name_bytes: usize,
        buffer: &'buffer mut [u8; FILESYSTEM_LIST_BUFFER_BYTES],
    ) -> Result<filesystem::DirectoryPage<'buffer>, Error> {
        let mut request = [0_u8; filesystem::MAX_LIST_REQUEST_BYTES];
        let count = filesystem::encode_list_request(
            cursor,
            max_entries,
            max_name_bytes,
            path,
            &mut request,
        )
        .map_err(|_| Error::InvalidCall)?;
        let count = call(self.handle, filesystem::LIST, &request[..count], buffer)?;
        filesystem::DirectoryPage::parse(&buffer[..count]).map_err(|_| Error::InvalidCall)
    }

    /// Read the exact UTF-8 target of one symbolic link without following it.
    ///
    /// The returned string borrows `buffer`.
    ///
    /// # Errors
    ///
    /// Reports invalid paths, wrong object kinds, unsupported providers,
    /// filesystem failures, or a malformed service reply.
    pub fn read_link<'buffer>(
        &mut self,
        path: &str,
        buffer: &'buffer mut [u8; filesystem::MAX_LINK_BYTES],
    ) -> Result<&'buffer str, Error> {
        let mut request = [0_u8; filesystem::MAX_PATH_BYTES];
        let count =
            filesystem::encode_path_request(path, &mut request).map_err(|_| Error::InvalidCall)?;
        let count = call(
            self.handle,
            filesystem::READ_LINK,
            &request[..count],
            buffer,
        )?;
        filesystem::decode_link_reply(&buffer[..count]).map_err(|_| Error::InvalidCall)
    }
}

impl FilesystemMutation {
    /// Truncate or create one regular file and begin streaming its replacement.
    ///
    /// Only one replacement may be pending on this capability. Bytes can reach
    /// storage before `commit`; failure or teardown can therefore leave a
    /// truncated file or a written prefix, like an ordinary write loop.
    ///
    /// # Errors
    ///
    /// Reports invalid paths, conflicting pending work, exhaustion, or a
    /// service/call-gate failure.
    pub fn begin_replace(&mut self, path: &str) -> Result<FileReplacement, Error> {
        let mut request = [0_u8; filesystem::MAX_PATH_BYTES];
        let count = filesystem_mutation::encode_path_request(path, &mut request)
            .map_err(|_| Error::InvalidCall)?;
        let mut reply = [0_u8; filesystem_mutation::TOKEN_BYTES];
        let count = call(
            self.handle,
            filesystem_mutation::BEGIN_REPLACE,
            &request[..count],
            &mut reply,
        )?;
        let token =
            filesystem_mutation::decode_token(&reply[..count]).map_err(|_| Error::InvalidCall)?;
        Ok(FileReplacement {
            handle: self.handle,
            token,
            offset: 0,
        })
    }

    /// Atomically remove one regular file or symbolic link.
    ///
    /// # Errors
    ///
    /// Reports invalid/missing paths, immutable targets, a conflicting pending
    /// replacement, filesystem failures, or call-gate failure.
    pub fn remove(&mut self, path: &str) -> Result<(), Error> {
        let mut request = [0_u8; filesystem::MAX_PATH_BYTES];
        let count = filesystem_mutation::encode_path_request(path, &mut request)
            .map_err(|_| Error::InvalidCall)?;
        let mut reply = [];
        let count = call(
            self.handle,
            filesystem_mutation::REMOVE,
            &request[..count],
            &mut reply,
        )?;
        if count == 0 {
            Ok(())
        } else {
            Err(Error::InvalidCall)
        }
    }

    /// Create one empty directory without replacing an existing entry.
    ///
    /// # Errors
    ///
    /// Reports invalid or missing parents, collisions, immutable or
    /// unsupported providers, persistence failures, or call-gate failure.
    pub fn create_directory(&mut self, path: &str) -> Result<(), Error> {
        let mut request = [0_u8; filesystem::MAX_PATH_BYTES];
        let count = filesystem_mutation::encode_path_request(path, &mut request)
            .map_err(|_| Error::InvalidCall)?;
        let mut reply = [];
        let count = call(
            self.handle,
            filesystem_mutation::CREATE_DIRECTORY,
            &request[..count],
            &mut reply,
        )?;
        if count == 0 {
            Ok(())
        } else {
            Err(Error::InvalidCall)
        }
    }

    /// Create one symbolic link.
    ///
    /// The target is stored as supplied. Absolute targets are interpreted by
    /// the mounted provider, and relative targets are relative to the link's
    /// parent directory.
    ///
    /// # Errors
    ///
    /// Reports invalid or existing paths, immutable or unsupported providers,
    /// a conflicting pending replacement, filesystem failures, or call-gate
    /// failure.
    pub fn create_symlink(&mut self, target: &str, link_path: &str) -> Result<(), Error> {
        self.create_link(filesystem_mutation::CREATE_SYMLINK, target, link_path)
    }

    /// Create one same-provider hard link to an existing regular file.
    ///
    /// # Errors
    ///
    /// Reports invalid, missing, cross-provider, wrong-type, or existing paths,
    /// immutable or unsupported providers, a conflicting pending replacement,
    /// filesystem failures, or call-gate failure.
    pub fn create_hard_link(&mut self, existing: &str, new_path: &str) -> Result<(), Error> {
        self.create_link(filesystem_mutation::CREATE_HARD_LINK, existing, new_path)
    }

    fn create_link(&mut self, opcode: u16, target: &str, link_path: &str) -> Result<(), Error> {
        let mut request = [0_u8; filesystem_mutation::MAX_LINK_REQUEST_BYTES];
        let count = filesystem_mutation::encode_link_request(target, link_path, &mut request)
            .map_err(|_| Error::InvalidCall)?;
        let mut reply = [];
        let count = call(self.handle, opcode, &request[..count], &mut reply)?;
        if count == 0 {
            Ok(())
        } else {
            Err(Error::InvalidCall)
        }
    }
}

impl FileReplacement {
    /// Select the kernel aggregation size for this streamed replacement.
    ///
    /// Values are power-of-two sizes from 4 KiB through 1 MiB. Configure the
    /// writer before sending payload bytes.
    ///
    /// # Errors
    ///
    /// Reports invalid policy, stale tokens, service, or call-gate failures.
    pub fn set_chunk_size(&mut self, bytes: usize) -> Result<(), Error> {
        if self.offset != 0 {
            return Err(Error::InvalidCall);
        }
        let request = filesystem_mutation::encode_chunk_size_request(self.token, bytes)
            .map_err(|_| Error::InvalidCall)?;
        let mut reply = [];
        let count = call(
            self.handle,
            filesystem_mutation::SET_CHUNK_SIZE,
            &request,
            &mut reply,
        )?;
        if count == 0 {
            Ok(())
        } else {
            Err(Error::InvalidCall)
        }
    }

    /// Append all bytes sequentially using bounded copied calls.
    ///
    /// # Errors
    ///
    /// Reports the first size, buffering, service, or call-gate failure.
    pub fn write_all(&mut self, mut bytes: &[u8]) -> Result<(), Error> {
        while !bytes.is_empty() {
            let chunk_bytes = bytes.len().min(filesystem_mutation::MAX_APPEND_BYTES);
            let mut request = [0_u8; MAX_SERVICE_PAYLOAD_BYTES];
            let count = filesystem_mutation::encode_append_request(
                self.token,
                self.offset,
                &bytes[..chunk_bytes],
                &mut request,
            )
            .map_err(|_| Error::TooLarge)?;
            let mut reply = [];
            let reply_bytes = call(
                self.handle,
                filesystem_mutation::APPEND,
                &request[..count],
                &mut reply,
            )?;
            if reply_bytes != 0 {
                return Err(Error::InvalidCall);
            }
            self.offset = self
                .offset
                .checked_add(u64::try_from(chunk_bytes).map_err(|_| Error::Overflow)?)
                .ok_or(Error::Overflow)?;
            bytes = &bytes[chunk_bytes..];
        }
        Ok(())
    }

    /// Flush and durably order the streamed bytes, then consume this token.
    ///
    /// # Errors
    ///
    /// Reports immutable targets, quotas, filesystem failures, or call-gate
    /// failure.
    pub fn commit(self) -> Result<(), Error> {
        self.finish(filesystem_mutation::COMMIT_REPLACE)
    }

    /// Consume this token without flushing its final buffered chunk.
    ///
    /// Previously flushed bytes and the initial truncation remain visible.
    ///
    /// # Errors
    ///
    /// Reports a stale token or call-gate failure.
    pub fn abort(self) -> Result<(), Error> {
        self.finish(filesystem_mutation::ABORT_REPLACE)
    }

    fn finish(self, opcode: u16) -> Result<(), Error> {
        let request =
            filesystem_mutation::encode_token(self.token).map_err(|_| Error::InvalidCall)?;
        let mut reply = [];
        let count = call(self.handle, opcode, &request, &mut reply)?;
        if count == 0 {
            Ok(())
        } else {
            Err(Error::InvalidCall)
        }
    }
}

impl Timer {
    /// Read the current boot-relative monotonic millisecond count.
    ///
    /// # Errors
    ///
    /// Reports service, decoding, or call-gate failure.
    pub fn now(&mut self) -> Result<u64, Error> {
        let mut reply = [0_u8; timer::MILLISECONDS_BYTES];
        let count = call(self.handle, timer::NOW, &[], &mut reply)?;
        timer::decode_milliseconds(&reply[..count]).map_err(|_| Error::InvalidCall)
    }

    /// Read CPU time charged to the calling process.
    ///
    /// The returned frequency converts `ticks` into seconds. Kernel service,
    /// waiting, and descheduled time are not charged to this counter.
    ///
    /// # Errors
    ///
    /// Reports service, decoding, or call-gate failure.
    pub fn process_cpu_time(&mut self) -> Result<timer::ProcessCpuTime, Error> {
        let mut reply = [0_u8; timer::PROCESS_CPU_TIME_BYTES];
        let count = call(self.handle, timer::PROCESS_CPU_TIME, &[], &mut reply)?;
        timer::decode_process_cpu_time(&reply[..count]).map_err(|_| Error::InvalidCall)
    }

    /// Cooperatively wait until one boot-relative monotonic deadline.
    ///
    /// # Errors
    ///
    /// Reports cancellation, service, decoding, or call-gate failure.
    pub fn sleep_until(&mut self, deadline_milliseconds: u64) -> Result<(), Error> {
        let request = timer::encode_milliseconds(deadline_milliseconds);
        let mut reply = [];
        let count = call(self.handle, timer::SLEEP_UNTIL, &request, &mut reply)?;
        if count == 0 {
            Ok(())
        } else {
            Err(Error::InvalidCall)
        }
    }
}

impl WallClock {
    /// Read whole Unix seconds from the kernel's monotonic wall-clock anchor.
    ///
    /// # Errors
    ///
    /// Reports service, decoding, or call-gate failure.
    pub fn now(&mut self) -> Result<u64, Error> {
        let mut reply = [0_u8; wall_clock::SECONDS_BYTES];
        let count = call(self.handle, wall_clock::NOW, &[], &mut reply)?;
        wall_clock::decode_seconds(&reply[..count]).map_err(|_| Error::InvalidCall)
    }
}

impl ClockControl {
    /// Correct the kernel wall clock at the current monotonic instant.
    ///
    /// # Errors
    ///
    /// Reports an invalid timestamp, denied service, or call-gate failure.
    pub fn set(&mut self, unix_seconds: u64) -> Result<(), Error> {
        let request = clock_control::encode_seconds(unix_seconds);
        let mut reply = [];
        let count = call(self.handle, clock_control::SET, &request, &mut reply)?;
        if count == 0 {
            Ok(())
        } else {
            Err(Error::InvalidCall)
        }
    }
}

impl VolumeControl {
    /// List every configured volume and its current runtime state.
    ///
    /// The reply borrows `buffer`.
    ///
    /// # Errors
    ///
    /// Reports service, decoding, or call-gate failure.
    pub fn list<'buffer>(
        &mut self,
        buffer: &'buffer mut [u8; volume_control::MAX_LIST_REPLY_BYTES],
    ) -> Result<volume_control::VolumeList<'buffer>, Error> {
        let count = call(self.handle, volume_control::LIST, &[], buffer)?;
        volume_control::decode_list(&buffer[..count]).map_err(|_| Error::InvalidCall)
    }

    /// Activate one prepared manual volume by its manifest name.
    ///
    /// Already-mounted volumes succeed idempotently.
    ///
    /// # Errors
    ///
    /// Reports invalid/unconfigured names, unavailable media, attachment
    /// failure, service rejection, or call-gate failure.
    pub fn activate(&mut self, name: &str) -> Result<(), Error> {
        let mut request = [0_u8; volume_control::MAX_ACTIVATE_REQUEST_BYTES];
        let count = volume_control::encode_activate_request(name, &mut request)
            .map_err(|_| Error::InvalidCall)?;
        let mut reply = [];
        let reply_bytes = call(
            self.handle,
            volume_control::ACTIVATE,
            &request[..count],
            &mut reply,
        )?;
        if reply_bytes == 0 {
            Ok(())
        } else {
            Err(Error::InvalidCall)
        }
    }
}

impl ShellScript {
    /// Submit one nonempty physical source line for later execution by the
    /// owning shell session.
    ///
    /// Submission validates and stages the line only. The owning shell begins
    /// executing the complete staged batch after the interpreter exits
    /// successfully; a failed or faulted interpreter discards the batch.
    ///
    /// # Errors
    ///
    /// Reports invalid source, syntax rejection, batch exhaustion, service
    /// failure, or call-gate failure.
    pub fn submit_line(&mut self, number: u32, source: &str) -> Result<(), Error> {
        let mut request = [0_u8; shell_script::MAX_REQUEST_BYTES];
        let count = shell_script::encode_submit_line(number, source, &mut request)
            .map_err(|_| Error::InvalidCall)?;
        let mut reply = [];
        let reply_bytes = call(
            self.handle,
            shell_script::SUBMIT_LINE,
            &request[..count],
            &mut reply,
        )?;
        if reply_bytes == 0 {
            Ok(())
        } else {
            Err(Error::InvalidCall)
        }
    }
}

impl Diagnostics {
    /// Read the immutable typed snapshot captured for this launch.
    ///
    /// # Errors
    ///
    /// Reports service, decoding, or call-gate failure.
    pub fn snapshot(&mut self) -> Result<diagnostics::Snapshot, Error> {
        let mut reply = [0_u8; diagnostics::SNAPSHOT_BYTES];
        let count = call(self.handle, diagnostics::GET_SNAPSHOT, &[], &mut reply)?;
        diagnostics::decode_snapshot(&reply[..count]).map_err(|_| Error::InvalidCall)
    }
}

impl ProcessObservation {
    /// Read one current bounded snapshot of registered application processes.
    ///
    /// # Errors
    ///
    /// Reports service, decoding, or call-gate failure.
    pub fn snapshot(&mut self) -> Result<process_observation::Snapshot, Error> {
        let mut reply = [0_u8; process_observation::SNAPSHOT_BYTES];
        let count = call(
            self.handle,
            process_observation::GET_SNAPSHOT,
            &[],
            &mut reply,
        )?;
        process_observation::decode_snapshot(&reply[..count]).map_err(|_| Error::InvalidCall)
    }

    /// Read one stable-ID-cursor page of current process records.
    ///
    /// Pass zero to begin a scan, then pass each nonzero `next_cursor()` until
    /// the returned cursor is zero.
    ///
    /// # Errors
    ///
    /// Reports service, decoding, or call-gate failure.
    pub fn page(&mut self, after_process_id: u64) -> Result<process_observation::Page, Error> {
        let request = process_observation::encode_page_request(after_process_id);
        let mut reply = [0_u8; process_observation::PAGE_BYTES];
        let count = call(
            self.handle,
            process_observation::GET_PAGE,
            &request,
            &mut reply,
        )?;
        process_observation::decode_page(&reply[..count]).map_err(|_| Error::InvalidCall)
    }
}

impl ProcessLauncher {
    /// Admit one child KEX application through package resolution.
    ///
    /// `args` includes argument zero. Environment entries must use canonical
    /// `NAME=VALUE` form. The returned token, unlike the observable process ID,
    /// is the authority required by all lifecycle operations.
    ///
    /// # Errors
    ///
    /// Reports malformed launch data, missing packages or capabilities,
    /// exhausted bounded resources, invalid pipe ownership, or call failure.
    pub fn spawn<T: AsRef<str>>(
        &mut self,
        cwd: &str,
        args: &[T],
        environment: &[&str],
        stdin: process_launch::StreamSpec,
        stdout: process_launch::StreamSpec,
        stderr: process_launch::StreamSpec,
    ) -> Result<process_launch::SpawnedChild, Error> {
        let mut invocation = [0_u8; command::MAX_INVOCATION_BYTES];
        let invocation_bytes =
            command::encode(cwd, args, &mut invocation).map_err(|_| Error::InvalidInvocation)?;
        let mut request = [0_u8; process_launch::MAX_SPAWN_BYTES];
        let request_bytes = process_launch::encode_spawn(
            &invocation[..invocation_bytes],
            environment,
            stdin,
            stdout,
            stderr,
            &mut request,
        )
        .map_err(|_| Error::InvalidCall)?;
        let mut reply = [0_u8; process_launch::SPAWN_REPLY_BYTES];
        let count = call(
            self.handle,
            process_launch::SPAWN,
            &request[..request_bytes],
            &mut reply,
        )?;
        process_launch::decode_spawned(&reply[..count]).map_err(|_| Error::InvalidCall)
    }

    /// Return the current state of one owned child without waiting.
    ///
    /// # Errors
    ///
    /// Reports an invalid or foreign token, service failure, or invalid reply.
    pub fn poll(
        &mut self,
        token: process_launch::ChildToken,
    ) -> Result<process_launch::ChildStatus, Error> {
        self.status_call(process_launch::POLL, token)
    }

    /// Wait cooperatively until one owned child reaches a terminal state.
    ///
    /// # Errors
    ///
    /// Reports an invalid or foreign token, cancellation, service failure, or
    /// invalid reply.
    pub fn wait(
        &mut self,
        token: process_launch::ChildToken,
    ) -> Result<process_launch::ChildStatus, Error> {
        self.status_call(process_launch::WAIT, token)
    }

    /// Request cancellation of one running owned child.
    ///
    /// Cancellation is cooperative with kernel scheduling. Use [`Self::wait`]
    /// to observe its terminal state before reaping the token.
    ///
    /// # Errors
    ///
    /// Reports an invalid or foreign token, service failure, or invalid reply.
    pub fn cancel(
        &mut self,
        token: process_launch::ChildToken,
    ) -> Result<process_launch::ChildStatus, Error> {
        self.status_call(process_launch::CANCEL, token)
    }

    /// Revoke one terminal child token and release its retained metadata.
    ///
    /// # Errors
    ///
    /// Reports an invalid, foreign, or still-running token or service failure.
    pub fn reap(&mut self, token: process_launch::ChildToken) -> Result<(), Error> {
        let request = process_launch::encode_token(token);
        let mut reply = [];
        let count = call(self.handle, process_launch::REAP, &request, &mut reply)?;
        if count == 0 {
            Ok(())
        } else {
            Err(Error::InvalidCall)
        }
    }

    fn status_call(
        &mut self,
        opcode: u16,
        token: process_launch::ChildToken,
    ) -> Result<process_launch::ChildStatus, Error> {
        let request = process_launch::encode_token(token);
        let mut reply = [0_u8; process_launch::STATUS_BYTES];
        let count = call(self.handle, opcode, &request, &mut reply)?;
        process_launch::decode_status(&reply[..count]).map_err(|_| Error::InvalidCall)
    }
}

impl Pipes {
    /// Create one owner-scoped pipe with a fixed byte capacity.
    ///
    /// # Errors
    ///
    /// Reports an out-of-policy size, exhausted owner quota, or call failure.
    pub fn create(&mut self, capacity: usize) -> Result<pipe::PipeToken, Error> {
        let request = pipe::encode_create(capacity).map_err(|_| Error::InvalidCall)?;
        let mut reply = [0_u8; pipe::TOKEN_BYTES];
        let count = call(self.handle, pipe::CREATE, &request, &mut reply)?;
        pipe::decode_token(&reply[..count]).map_err(|_| Error::InvalidCall)
    }

    /// Read up to `destination.len()` bytes; zero means writer-side EOF.
    ///
    /// The kernel suspends an empty read while a writer remains attached.
    ///
    /// # Errors
    ///
    /// Reports an invalid or foreign token, closed reader, or call failure.
    pub fn read(&mut self, token: pipe::PipeToken, destination: &mut [u8]) -> Result<usize, Error> {
        if destination.is_empty() {
            return Ok(0);
        }
        let maximum = destination.len().min(pipe::MAX_IO_BYTES);
        let request = pipe::encode_read(token, maximum).map_err(|_| Error::InvalidCall)?;
        call(
            self.handle,
            pipe::READ,
            &request,
            &mut destination[..maximum],
        )
    }

    /// Write the complete byte slice with bounded copied calls.
    ///
    /// The kernel suspends each chunk until enough pipe capacity is available.
    ///
    /// # Errors
    ///
    /// Reports an invalid or foreign token, reader-side EOF, or call failure.
    pub fn write_all(&mut self, token: pipe::PipeToken, mut bytes: &[u8]) -> Result<(), Error> {
        let mut request = [0_u8; MAX_SERVICE_PAYLOAD_BYTES];
        let mut reply = [];
        while !bytes.is_empty() {
            let chunk = bytes.len().min(pipe::MAX_IO_BYTES);
            let request_bytes = pipe::encode_write(token, &bytes[..chunk], &mut request)
                .map_err(|_| Error::InvalidCall)?;
            let count = call(
                self.handle,
                pipe::WRITE,
                &request[..request_bytes],
                &mut reply,
            )?;
            if count != 0 {
                return Err(Error::InvalidCall);
            }
            bytes = &bytes[chunk..];
        }
        Ok(())
    }

    /// Close the owner's writer endpoint. Readers see EOF after draining data.
    ///
    /// # Errors
    ///
    /// Reports an invalid, foreign, or already closed endpoint or call failure.
    pub fn close_writer(&mut self, token: pipe::PipeToken) -> Result<(), Error> {
        self.close(pipe::CLOSE_WRITER, token)
    }

    /// Close the owner's reader endpoint. Subsequent writes fail.
    ///
    /// # Errors
    ///
    /// Reports an invalid, foreign, or already closed endpoint or call failure.
    pub fn close_reader(&mut self, token: pipe::PipeToken) -> Result<(), Error> {
        self.close(pipe::CLOSE_READER, token)
    }

    fn close(&mut self, opcode: u16, token: pipe::PipeToken) -> Result<(), Error> {
        let request = pipe::encode_token(token);
        let mut reply = [];
        let count = call(self.handle, opcode, &request, &mut reply)?;
        if count == 0 {
            Ok(())
        } else {
            Err(Error::InvalidCall)
        }
    }
}

impl NetworkObservation {
    /// Read current link and optional IPv4 configuration.
    ///
    /// # Errors
    ///
    /// Reports device absence, service, decoding, or call-gate failure.
    pub fn status(&mut self) -> Result<network_observation::Status, Error> {
        let mut reply = [0_u8; network_observation::STATUS_BYTES];
        let count = call(
            self.handle,
            network_observation::GET_STATUS,
            &[],
            &mut reply,
        )?;
        network_observation::decode_status(&reply[..count]).map_err(|_| Error::InvalidCall)
    }

    /// Read current ambient counters and bounded resource use.
    ///
    /// # Errors
    ///
    /// Reports device absence, service, decoding, or call-gate failure.
    pub fn stats(&mut self) -> Result<network_observation::Stats, Error> {
        let mut reply = [0_u8; network_observation::STATS_BYTES];
        let count = call(self.handle, network_observation::GET_STATS, &[], &mut reply)?;
        network_observation::decode_stats(&reply[..count]).map_err(|_| Error::InvalidCall)
    }

    /// Read the complete bounded neighbor cache.
    ///
    /// # Errors
    ///
    /// Reports device absence, service, decoding, or call-gate failure.
    pub fn neighbors(&mut self) -> Result<network_observation::Neighbors, Error> {
        let mut reply = [0_u8; network_observation::MAX_NEIGHBOR_REPLY_BYTES];
        let count = call(
            self.handle,
            network_observation::GET_NEIGHBORS,
            &[],
            &mut reply,
        )?;
        network_observation::decode_neighbors(&reply[..count]).map_err(|_| Error::InvalidCall)
    }
}

impl NetworkConfiguration {
    /// Perform one bounded cancellable DHCP exchange.
    ///
    /// # Errors
    ///
    /// Reports device absence, cancellation, timeout, protocol, service,
    /// decoding, or call-gate failure.
    pub fn dhcp(&mut self) -> Result<network_observation::Status, Error> {
        let mut reply = [0_u8; network_observation::STATUS_BYTES];
        let count = call(self.handle, network_configuration::DHCP, &[], &mut reply)?;
        network_observation::decode_status(&reply[..count]).map_err(|_| Error::InvalidCall)
    }
}

impl IcmpEcho {
    /// Send one bounded echo request and wait for its matching reply.
    ///
    /// # Errors
    ///
    /// Reports device/configuration absence, cancellation, timeout, protocol,
    /// service, decoding, or call-gate failure.
    pub fn echo(&mut self, destination: [u8; 4]) -> Result<icmp_echo::Reply, Error> {
        let request = icmp_echo::encode_request(destination);
        let mut reply = [0_u8; icmp_echo::REPLY_BYTES];
        let count = call(self.handle, icmp_echo::ECHO, &request, &mut reply)?;
        icmp_echo::decode_reply(&reply[..count]).map_err(|_| Error::InvalidCall)
    }
}

impl TcpConnect {
    /// Consume this authority to attempt one literal IPv4 connection.
    ///
    /// # Errors
    ///
    /// Reports invalid endpoints, device/configuration absence, cancellation,
    /// timeout, reset, resource conflict/exhaustion, or call-gate failure.
    pub fn connect(
        self,
        destination: [u8; 4],
        destination_port: u16,
    ) -> Result<TcpConnection, Error> {
        let request = tcp_connect::encode_connect_request(destination, destination_port)
            .map_err(|_| Error::InvalidCall)?;
        let mut reply = [0_u8; tcp_connect::CONNECT_REPLY_BYTES];
        let count = call(self.handle, tcp_connect::CONNECT, &request, &mut reply)?;
        let local_port =
            tcp_connect::decode_connect_reply(&reply[..count]).map_err(|_| Error::InvalidCall)?;
        Ok(TcpConnection {
            handle: self.handle,
            local_port,
        })
    }
}

impl TcpConnection {
    /// Kernel-selected nonzero local port for this connection.
    #[must_use]
    pub const fn local_port(&self) -> u16 {
        self.local_port
    }

    /// Write the complete byte slice through acknowledged, at-most-MTU calls.
    ///
    /// # Errors
    ///
    /// Reports the first cancellation, timeout, reset, close, service, or
    /// call-gate failure. An empty slice succeeds without a service call.
    pub fn write_all(&mut self, mut bytes: &[u8]) -> Result<(), Error> {
        let mut reply = [];
        while !bytes.is_empty() {
            let count = bytes.len().min(tcp_connect::MAX_WRITE_BYTES);
            let reply_bytes = call(self.handle, tcp_connect::WRITE, &bytes[..count], &mut reply)?;
            if reply_bytes != 0 {
                return Err(Error::InvalidCall);
            }
            bytes = &bytes[count..];
        }
        Ok(())
    }

    /// Read up to `destination.len()` bytes; zero is orderly peer EOF.
    ///
    /// # Errors
    ///
    /// Reports cancellation, timeout, reset, service, or call-gate failure.
    pub fn read(&mut self, destination: &mut [u8]) -> Result<usize, Error> {
        if destination.is_empty() {
            return Ok(0);
        }
        let requested = destination.len().min(tcp_connect::MAX_READ_BYTES);
        let request =
            tcp_connect::encode_read_request(requested).map_err(|_| Error::InvalidCall)?;
        call(
            self.handle,
            tcp_connect::READ,
            &request,
            &mut destination[..requested],
        )
    }

    /// Gracefully close the connection and consume the typed stream.
    ///
    /// # Errors
    ///
    /// Reports cancellation, timeout, reset, service, or call-gate failure.
    /// Application teardown aborts the connection after any failure.
    pub fn close(self) -> Result<(), Error> {
        let mut reply = [];
        let count = call(self.handle, tcp_connect::CLOSE, &[], &mut reply)?;
        if count == 0 {
            Ok(())
        } else {
            Err(Error::InvalidCall)
        }
    }
}

impl Datagram {
    /// Send one bounded datagram and return the owned source port.
    ///
    /// A missing source port requests a kernel-selected ephemeral port. The
    /// selected or explicit port remains owned until the application exits.
    ///
    /// # Errors
    ///
    /// Reports invalid arguments, absent authority, resource conflicts,
    /// configuration failure, cancellation, or call-gate failure.
    pub fn send(
        &mut self,
        source_port: Option<u16>,
        destination: [u8; 4],
        destination_port: u16,
        payload: &[u8],
    ) -> Result<u16, Error> {
        let mut request = [0_u8; datagram::MAX_SEND_REQUEST_BYTES];
        let count = datagram::encode_send_request(
            source_port,
            destination,
            destination_port,
            payload,
            &mut request,
        )
        .map_err(|_| Error::InvalidCall)?;
        let mut reply = [0_u8; 2];
        let count = call(self.handle, datagram::SEND, &request[..count], &mut reply)?;
        datagram::decode_send_reply(&reply[..count]).map_err(|_| Error::InvalidCall)
    }

    /// Wait cooperatively for one datagram on an owned local port.
    ///
    /// Ctrl-C is reported as [`Error::Cancelled`]. The reply borrows the
    /// caller-owned fixed buffer and never allocates.
    ///
    /// # Errors
    ///
    /// Reports an invalid port, absent authority, resource conflict,
    /// cancellation, configuration failure, or call-gate failure.
    pub fn receive<'buffer>(
        &mut self,
        local_port: u16,
        buffer: &'buffer mut [u8; DATAGRAM_BUFFER_BYTES],
    ) -> Result<datagram::ReceivedDatagram<'buffer>, Error> {
        let request =
            datagram::encode_receive_request(local_port).map_err(|_| Error::InvalidCall)?;
        let count = call(self.handle, datagram::RECEIVE, &request, buffer)?;
        datagram::decode_receive_reply(&buffer[..count]).map_err(|_| Error::InvalidCall)
    }
}

#[derive(Clone, Copy)]
struct Descriptor {
    value: u64,
    rights: u32,
    interface: u32,
    major: u16,
    minor: u16,
}

struct Startup<'a> {
    bytes: &'a [u8],
    handle_count: usize,
}

impl<'a> Startup<'a> {
    fn parse(bytes: &'a [u8]) -> Result<Self, StartupError> {
        if bytes.len() != STARTUP_PAGE_BYTES
            || read_u32(bytes, 0)? as usize
                != STARTUP_HEADER_BYTES
                    .checked_add(
                        usize::from(read_u16(bytes, 14)?)
                            .checked_mul(STARTUP_HANDLE_BYTES)
                            .ok_or(StartupError::InvalidPage)?,
                    )
                    .ok_or(StartupError::InvalidPage)?
            || read_u16(bytes, 4)? != ABI_MAJOR
            || read_u16(bytes, 6)? != ABI_MINOR
            || read_u32(bytes, 8)? != 4096
            || read_u16(bytes, 12)? != 0
        {
            return Err(StartupError::InvalidPage);
        }
        let handle_count = usize::from(read_u16(bytes, 14)?);
        let encoded_bytes = STARTUP_HEADER_BYTES + handle_count * STARTUP_HANDLE_BYTES;
        let heap_address = read_u64(bytes, 24)?;
        let heap_bytes = read_u64(bytes, 32)?;
        let stack_bottom = read_u64(bytes, 40)?;
        let stack_top = read_u64(bytes, 48)?;
        if handle_count > 32
            || encoded_bytes > bytes.len()
            || bytes[encoded_bytes..].iter().any(|byte| *byte != 0)
            || read_u64(bytes, 16)? != KEX_IMAGE_BASE
            || heap_address != KEX_HEAP_ADDRESS
            || heap_bytes > KEX_HEAP_SLOT_BYTES
            || !heap_bytes.is_multiple_of(STARTUP_PAGE_BYTES as u64)
            || read_u64(bytes, 56)? == 0
            || !stack_bottom.is_multiple_of(STARTUP_PAGE_BYTES as u64)
            || stack_top != KEX_STACK_TOP
            || stack_bottom >= stack_top
            || stack_bottom < stack_top - KEX_MAXIMUM_STACK_BYTES
            || stack_bottom > stack_top - KEX_MINIMUM_STACK_BYTES
        {
            return Err(StartupError::InvalidPage);
        }
        let startup = Self {
            bytes,
            handle_count,
        };
        for index in 0..handle_count {
            let descriptor = startup.descriptor(index)?;
            if descriptor.value == 0
                || descriptor.rights & !CALL_RIGHT != 0
                || descriptor.rights & CALL_RIGHT == 0
                || startup
                    .descriptors_before(index)
                    .any(|prior| prior.is_ok_and(|prior| prior.value == descriptor.value))
            {
                return Err(StartupError::InvalidHandle);
            }
        }
        Ok(startup)
    }

    fn heap_region(&self) -> Result<Option<HeapRegion>, StartupError> {
        let byte_len =
            usize::try_from(read_u64(self.bytes, 32)?).map_err(|_| StartupError::InvalidPage)?;
        if byte_len == 0 {
            return Ok(None);
        }
        let address =
            usize::try_from(read_u64(self.bytes, 24)?).map_err(|_| StartupError::InvalidPage)?;
        Ok(Some(HeapRegion { address, byte_len }))
    }

    fn required_handle(&self, wanted: u32, major: u16, minor: u16) -> Result<Handle, StartupError> {
        self.optional_handle(wanted, major, minor)?
            .ok_or(StartupError::MissingAuthority)
    }

    fn optional_handle(
        &self,
        wanted: u32,
        major: u16,
        minor: u16,
    ) -> Result<Option<Handle>, StartupError> {
        let mut found = None;
        for index in 0..self.handle_count {
            let descriptor = self.descriptor(index)?;
            if descriptor.interface == wanted {
                if descriptor.major != major || descriptor.minor != minor || found.is_some() {
                    return Err(StartupError::MissingAuthority);
                }
                found = Some(Handle {
                    value: descriptor.value,
                });
            }
        }
        Ok(found)
    }

    fn descriptor(&self, index: usize) -> Result<Descriptor, StartupError> {
        if index >= self.handle_count {
            return Err(StartupError::InvalidHandle);
        }
        let offset = STARTUP_HEADER_BYTES + index * STARTUP_HANDLE_BYTES;
        if self.bytes[offset + 20..offset + 24]
            .iter()
            .any(|byte| *byte != 0)
        {
            return Err(StartupError::InvalidHandle);
        }
        Ok(Descriptor {
            value: read_u64(self.bytes, offset)?,
            rights: read_u32(self.bytes, offset + 8)?,
            interface: read_u32(self.bytes, offset + 12)?,
            major: read_u16(self.bytes, offset + 16)?,
            minor: read_u16(self.bytes, offset + 18)?,
        })
    }

    fn descriptors_before(
        &self,
        end: usize,
    ) -> impl Iterator<Item = Result<Descriptor, StartupError>> + '_ {
        (0..end).map(|index| self.descriptor(index))
    }
}

fn call(
    handle: Handle,
    opcode: u16,
    payload: &[u8],
    reply_bytes: &mut [u8],
) -> Result<usize, Error> {
    if payload.len() > MAX_SERVICE_PAYLOAD_BYTES || reply_bytes.len() > MAX_MESSAGE_BYTES {
        return Err(Error::InvalidCall);
    }
    let mut request = [0_u8; MAX_MESSAGE_BYTES];
    request[..2].copy_from_slice(&opcode.to_le_bytes());
    request[2..2 + payload.len()].copy_from_slice(payload);
    let (status, count) =
        native_handle_call(handle.value, &request[..2 + payload.len()], reply_bytes)?;
    if count > reply_bytes.len() {
        return Err(Error::InvalidCall);
    }
    match status {
        reply::SUCCESS => Ok(count),
        reply::INVALID_REQUEST => Err(Error::InvalidRequest),
        reply::NOT_FOUND => Err(Error::NotFound),
        reply::FAILURE => Err(Error::Failure),
        reply::EXHAUSTED => Err(Error::Exhausted),
        reply::NOT_CONFIGURED => Err(Error::NotConfigured),
        reply::CANCELLED => Err(Error::Cancelled),
        reply::TIMEOUT => Err(Error::Timeout),
        reply::CONFLICT => Err(Error::Conflict),
        reply::TOO_LARGE => Err(Error::TooLarge),
        reply::INVALID_PATH => Err(Error::InvalidPath),
        reply::WRONG_TYPE => Err(Error::WrongType),
        reply::READ_ONLY => Err(Error::ReadOnly),
        reply::NO_SPACE => Err(Error::NoSpace),
        reply::EXISTS => Err(Error::Exists),
        reply::CORRUPT => Err(Error::Corrupt),
        reply::IO => Err(Error::Io),
        reply::UNSUPPORTED => Err(Error::Unsupported),
        reply::OVERFLOW => Err(Error::Overflow),
        reply::NETWORK_PROTOCOL => Err(Error::NetworkProtocol),
        reply::DENIED => Err(Error::Denied),
        _ => Err(Error::InvalidCall),
    }
}

/// Terminate the application with one stable command status.
pub fn terminate(status: u32) -> ! {
    native_exit(status)
}

/// Run one SDK entry function from the raw kernel startup pair.
///
/// # Safety
///
/// `startup_address` must identify the immutable mapped startup page supplied
/// by the KEX loader for the complete duration of this non-returning call.
#[doc(hidden)]
pub unsafe fn __run(
    startup_address: *const u8,
    startup_bytes: usize,
    main: fn(&mut CommandContext) -> u32,
) -> ! {
    if startup_address.is_null() || startup_bytes != STARTUP_PAGE_BYTES {
        terminate(exit::FAILURE);
    }
    // SAFETY: The raw KEX entry contract supplies one immutable mapped startup
    // page. Startup parsing validates every byte before exposing authority.
    let bytes = unsafe { slice::from_raw_parts(startup_address, startup_bytes) };
    let Ok(startup) = Startup::parse(bytes) else {
        terminate(exit::FAILURE);
    };
    let Ok(mut command) = CommandContext::from_startup(&startup) else {
        terminate(exit::DENIED);
    };
    terminate(main(&mut command));
}

/// Run one isolated service entry function from the raw kernel startup pair.
///
/// # Safety
///
/// `startup_address` must identify the immutable mapped startup page supplied
/// by the KEX loader for the complete duration of this non-returning call.
#[doc(hidden)]
pub unsafe fn __run_server(
    startup_address: *const u8,
    startup_bytes: usize,
    main: fn(&mut ServerContext) -> u32,
) -> ! {
    if startup_address.is_null() || startup_bytes != STARTUP_PAGE_BYTES {
        terminate(exit::FAILURE);
    }
    // SAFETY: The raw KEX entry contract supplies one immutable mapped startup
    // page. Startup parsing validates every byte before exposing authority.
    let bytes = unsafe { slice::from_raw_parts(startup_address, startup_bytes) };
    let Ok(startup) = Startup::parse(bytes) else {
        terminate(exit::FAILURE);
    };
    let Ok(mut server) = ServerContext::from_startup(&startup) else {
        terminate(exit::DENIED);
    };
    terminate(main(&mut server));
}

/// Define `_start` and a fail-closed panic handler for one KEX command app.
#[macro_export]
macro_rules! entry {
    ($main:path) => {
        #[allow(clippy::not_unsafe_ptr_arg_deref)]
        #[unsafe(no_mangle)]
        pub extern "C" fn _start(startup_address: *const u8, startup_bytes: usize) -> ! {
            // SAFETY: Only the kernel KEX loader enters this exported symbol.
            unsafe { $crate::__run(startup_address, startup_bytes, $main) }
        }

        #[panic_handler]
        fn panic(_information: &core::panic::PanicInfo<'_>) -> ! {
            $crate::terminate($crate::exit::FAILURE)
        }
    };
}

/// Define `_start` and a fail-closed panic handler for one isolated KEX server.
#[macro_export]
macro_rules! server_entry {
    ($main:path) => {
        #[allow(clippy::not_unsafe_ptr_arg_deref)]
        #[unsafe(no_mangle)]
        pub extern "C" fn _start(startup_address: *const u8, startup_bytes: usize) -> ! {
            // SAFETY: Only the kernel KEX loader enters this exported symbol.
            unsafe { $crate::__run_server(startup_address, startup_bytes, $main) }
        }

        #[panic_handler]
        fn panic(_information: &core::panic::PanicInfo<'_>) -> ! {
            $crate::terminate($crate::exit::FAILURE)
        }
    };
}

#[cfg(all(target_os = "none", target_arch = "x86_64"))]
fn native_handle_call(
    handle: u64,
    request: &[u8],
    reply: &mut [u8],
) -> Result<(u32, usize), Error> {
    let mut status = 2_u64;
    let mut secondary = request.len() as u64;
    // SAFETY: The ABI gate validates the complete mapped request/reply ranges,
    // copies requests before dispatch, and writes replies only after success.
    unsafe {
        core::arch::asm!(
            "int 0x80",
            inlateout("rax") status,
            in("rdi") handle,
            in("rsi") request.as_ptr(),
            inlateout("rdx") secondary,
            in("r10") reply.as_mut_ptr(),
            in("r8") reply.len(),
            options(nostack),
        );
    }
    Ok((status as u32, secondary as usize))
}

#[cfg(all(target_os = "none", target_arch = "aarch64"))]
fn native_handle_call(
    handle: u64,
    request: &[u8],
    reply: &mut [u8],
) -> Result<(u32, usize), Error> {
    let mut status = handle;
    let mut secondary = request.as_ptr() as u64;
    // SAFETY: The ABI gate validates the complete mapped request/reply ranges,
    // copies requests before dispatch, and writes replies only after success.
    unsafe {
        core::arch::asm!(
            "svc #0",
            in("x8") 2_u64,
            inlateout("x0") status,
            inlateout("x1") secondary,
            in("x2") request.len(),
            in("x3") reply.as_mut_ptr(),
            in("x4") reply.len(),
            options(nostack),
        );
    }
    Ok((status as u32, secondary as usize))
}

#[cfg(not(target_os = "none"))]
fn native_handle_call(
    _handle: u64,
    _request: &[u8],
    _reply: &mut [u8],
) -> Result<(u32, usize), Error> {
    Err(Error::UnsupportedTarget)
}

#[cfg(all(target_os = "none", target_arch = "x86_64"))]
fn native_yield() -> Result<(), Error> {
    let mut status = 1_u64;
    let mut secondary: u64;
    // SAFETY: Call 1 has no pointer arguments and returns only after kernel
    // scheduler reselection under a fresh execution lease.
    unsafe {
        core::arch::asm!(
            "int 0x80",
            inlateout("rax") status,
            lateout("rdx") secondary,
            options(nostack),
        );
    }
    if status == 0 && secondary == 0 {
        Ok(())
    } else {
        Err(Error::InvalidCall)
    }
}

#[cfg(all(target_os = "none", target_arch = "aarch64"))]
fn native_yield() -> Result<(), Error> {
    let mut status: u64;
    let mut secondary: u64;
    // SAFETY: Call 1 has no pointer arguments and returns only after kernel
    // scheduler reselection under a fresh execution lease.
    unsafe {
        core::arch::asm!(
            "svc #0",
            in("x8") 1_u64,
            lateout("x0") status,
            lateout("x1") secondary,
            options(nostack),
        );
    }
    if status == 0 && secondary == 0 {
        Ok(())
    } else {
        Err(Error::InvalidCall)
    }
}

#[cfg(not(target_os = "none"))]
fn native_yield() -> Result<(), Error> {
    Err(Error::UnsupportedTarget)
}

#[cfg(all(target_os = "none", target_arch = "x86_64"))]
fn native_grow_heap(minimum_pages: u64) -> Result<(u32, usize), Error> {
    let mut status = 3_u64;
    let mut mapped_bytes = 0_u64;
    // SAFETY: Call 3 carries only scalar arguments. The kernel commits zeroed
    // pages before returning the new mapped length under a fresh lease.
    unsafe {
        core::arch::asm!(
            "int 0x80",
            inlateout("rax") status,
            in("rdi") minimum_pages,
            in("rsi") 0_u64,
            inlateout("rdx") mapped_bytes,
            in("r10") 0_u64,
            in("r8") 0_u64,
            options(nostack),
        );
    }
    Ok((status as u32, mapped_bytes as usize))
}

#[cfg(all(target_os = "none", target_arch = "aarch64"))]
fn native_grow_heap(minimum_pages: u64) -> Result<(u32, usize), Error> {
    let mut status = minimum_pages;
    let mut mapped_bytes = 0_u64;
    // SAFETY: Call 3 carries only scalar arguments. The kernel commits zeroed
    // pages before returning the new mapped length under a fresh lease.
    unsafe {
        core::arch::asm!(
            "svc #0",
            in("x8") 3_u64,
            inlateout("x0") status,
            inlateout("x1") mapped_bytes,
            in("x2") 0_u64,
            in("x3") 0_u64,
            in("x4") 0_u64,
            options(nostack),
        );
    }
    Ok((status as u32, mapped_bytes as usize))
}

#[cfg(not(target_os = "none"))]
fn native_grow_heap(_minimum_pages: u64) -> Result<(u32, usize), Error> {
    Err(Error::UnsupportedTarget)
}

#[cfg(all(target_os = "none", target_arch = "x86_64"))]
fn native_exit(status: u32) -> ! {
    // SAFETY: Call 0 consumes only the scalar status and never resumes.
    unsafe {
        core::arch::asm!(
            "int 0x80",
            in("rax") 0_u64,
            in("rdi") u64::from(status),
            options(noreturn, nostack),
        )
    }
}

#[cfg(all(target_os = "none", target_arch = "aarch64"))]
fn native_exit(status: u32) -> ! {
    // SAFETY: Call 0 consumes only the scalar status and never resumes.
    unsafe {
        core::arch::asm!(
            "svc #0",
            in("x8") 0_u64,
            in("x0") u64::from(status),
            options(noreturn, nostack),
        )
    }
}

#[cfg(not(target_os = "none"))]
fn native_exit(_status: u32) -> ! {
    loop {
        core::hint::spin_loop();
    }
}

fn read_u16(bytes: &[u8], offset: usize) -> Result<u16, StartupError> {
    let raw = bytes
        .get(offset..offset + 2)
        .ok_or(StartupError::InvalidPage)?;
    Ok(u16::from_le_bytes([raw[0], raw[1]]))
}

fn read_u32(bytes: &[u8], offset: usize) -> Result<u32, StartupError> {
    let raw = bytes
        .get(offset..offset + 4)
        .ok_or(StartupError::InvalidPage)?;
    Ok(u32::from_le_bytes([raw[0], raw[1], raw[2], raw[3]]))
}

fn read_u64(bytes: &[u8], offset: usize) -> Result<u64, StartupError> {
    let raw = bytes
        .get(offset..offset + 8)
        .ok_or(StartupError::InvalidPage)?;
    Ok(u64::from_le_bytes([
        raw[0], raw[1], raw[2], raw[3], raw[4], raw[5], raw[6], raw[7],
    ]))
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::{
        ABI_MAJOR, ABI_MINOR, CommandContext, HeapRegion, KEX_HEAP_ADDRESS, KEX_STACK_TOP,
        STARTUP_HANDLE_BYTES, STARTUP_HEADER_BYTES, STARTUP_PAGE_BYTES, ServerContext, Startup,
        StartupError, command, interface, pipe, process_launch, stream, timer,
    };

    fn startup_page(interfaces: &[u32]) -> [u8; STARTUP_PAGE_BYTES] {
        let mut page = [0_u8; STARTUP_PAGE_BYTES];
        let encoded = STARTUP_HEADER_BYTES + interfaces.len() * STARTUP_HANDLE_BYTES;
        page[0..4].copy_from_slice(&u32::try_from(encoded).unwrap_or(u32::MAX).to_le_bytes());
        page[4..6].copy_from_slice(&ABI_MAJOR.to_le_bytes());
        page[6..8].copy_from_slice(&ABI_MINOR.to_le_bytes());
        page[8..12].copy_from_slice(&4096_u32.to_le_bytes());
        page[14..16].copy_from_slice(
            &u16::try_from(interfaces.len())
                .unwrap_or(u16::MAX)
                .to_le_bytes(),
        );
        page[16..24].copy_from_slice(&0x0000_4000_0000_0000_u64.to_le_bytes());
        page[24..32].copy_from_slice(&KEX_HEAP_ADDRESS.to_le_bytes());
        page[32..40].copy_from_slice(&(8 * STARTUP_PAGE_BYTES as u64).to_le_bytes());
        page[40..48]
            .copy_from_slice(&(KEX_STACK_TOP - 4 * STARTUP_PAGE_BYTES as u64).to_le_bytes());
        page[48..56].copy_from_slice(&KEX_STACK_TOP.to_le_bytes());
        page[56..64].copy_from_slice(&7_u64.to_le_bytes());
        for (index, interface) in interfaces.iter().copied().enumerate() {
            let offset = STARTUP_HEADER_BYTES + index * STARTUP_HANDLE_BYTES;
            page[offset..offset + 8].copy_from_slice(&(0x1_0001_u64 + index as u64).to_le_bytes());
            page[offset + 8..offset + 12].copy_from_slice(&1_u32.to_le_bytes());
            page[offset + 12..offset + 16].copy_from_slice(&interface.to_le_bytes());
            page[offset + 16..offset + 18].copy_from_slice(&1_u16.to_le_bytes());
            let minor = match interface {
                interface::COMMAND => command::MINOR,
                interface::STANDARD_INPUT
                | interface::STANDARD_OUTPUT
                | interface::STANDARD_ERROR => stream::MINOR,
                interface::TIMER => timer::MINOR,
                interface::PROCESS_LAUNCH => process_launch::MINOR,
                interface::PIPE => pipe::MINOR,
                _ => 0,
            };
            page[offset + 18..offset + 20].copy_from_slice(&minor.to_le_bytes());
        }
        page
    }

    #[test]
    fn startup_requires_exact_command_authority() {
        let page = startup_page(&[
            interface::COMMAND,
            interface::STANDARD_INPUT,
            interface::STANDARD_OUTPUT,
            interface::STANDARD_ERROR,
            interface::DATAGRAM,
            interface::TIMER,
            interface::DIAGNOSTICS,
            interface::PROCESS_LAUNCH,
            interface::PIPE,
            interface::NETWORK_OBSERVE,
            interface::NETWORK_CONFIGURE,
            interface::ICMP_ECHO,
            interface::TCP_CONNECT,
            interface::VOLUME_CONTROL,
            interface::SHELL_SCRIPT,
            interface::WALL_CLOCK,
            interface::CLOCK_CONTROL,
        ]);
        let startup = Startup::parse(&page);
        assert!(startup.is_ok());
        if let Ok(startup) = startup {
            let command = CommandContext::from_startup(&startup);
            assert!(command.is_ok());
            if let Ok(mut command) = command {
                assert!(command.datagram().is_ok());
                assert!(command.timer().is_ok());
                assert!(command.diagnostics().is_ok());
                assert!(command.process_launcher().is_ok());
                assert!(command.pipes().is_ok());
                assert!(command.network_observation().is_ok());
                assert!(command.network_configuration().is_ok());
                assert!(command.icmp_echo().is_ok());
                assert!(command.tcp_connect().is_ok());
                assert!(command.volume_control().is_ok());
                assert!(command.wall_clock().is_ok());
                assert!(command.clock_control().is_ok());
                assert!(command.shell_script().is_ok());
                let heap = command.take_heap();
                assert_eq!(
                    heap.as_ref().map(HeapRegion::start_address),
                    usize::try_from(KEX_HEAP_ADDRESS).ok()
                );
                assert_eq!(
                    heap.as_ref().map(HeapRegion::byte_len),
                    Some(8 * STARTUP_PAGE_BYTES)
                );
                assert!(command.take_heap().is_none());
            }
        }
    }

    #[test]
    fn server_startup_requires_only_the_typed_endpoint() {
        let page = startup_page(&[interface::SERVER_ENDPOINT]);
        let startup = Startup::parse(&page).unwrap_or_else(|_| std::process::abort());
        let mut server =
            ServerContext::from_startup(&startup).unwrap_or_else(|_| std::process::abort());
        assert_eq!(
            server.take_heap().as_ref().map(HeapRegion::byte_len),
            Some(8 * STARTUP_PAGE_BYTES)
        );
        assert!(server.take_heap().is_none());

        let missing = startup_page(&[interface::DIAGNOSTICS]);
        let startup = Startup::parse(&missing).unwrap_or_else(|_| std::process::abort());
        assert!(matches!(
            ServerContext::from_startup(&startup),
            Err(StartupError::MissingAuthority)
        ));
    }

    #[test]
    fn startup_rejects_noncanonical_memory_geometry() {
        let interfaces = [
            interface::COMMAND,
            interface::STANDARD_INPUT,
            interface::STANDARD_OUTPUT,
            interface::STANDARD_ERROR,
        ];
        let mut page = startup_page(&interfaces);
        page[24..32].copy_from_slice(&(KEX_HEAP_ADDRESS + STARTUP_PAGE_BYTES as u64).to_le_bytes());
        assert!(matches!(
            Startup::parse(&page),
            Err(StartupError::InvalidPage)
        ));

        let mut page = startup_page(&interfaces);
        page[32..40].copy_from_slice(&1_u64.to_le_bytes());
        assert!(matches!(
            Startup::parse(&page),
            Err(StartupError::InvalidPage)
        ));

        let mut page = startup_page(&interfaces);
        page[48..56].copy_from_slice(&(KEX_STACK_TOP - 16).to_le_bytes());
        assert!(matches!(
            Startup::parse(&page),
            Err(StartupError::InvalidPage)
        ));
    }

    #[test]
    fn startup_rejects_truncation_padding_and_duplicate_interfaces() {
        let mut old_stream = startup_page(&[
            interface::COMMAND,
            interface::STANDARD_INPUT,
            interface::STANDARD_OUTPUT,
            interface::STANDARD_ERROR,
        ]);
        let output_descriptor = STARTUP_HEADER_BYTES + 2 * STARTUP_HANDLE_BYTES;
        old_stream[output_descriptor + 18..output_descriptor + 20].fill(0);
        let startup = Startup::parse(&old_stream);
        assert!(startup.is_ok());
        if let Ok(startup) = startup {
            assert!(matches!(
                CommandContext::from_startup(&startup),
                Err(StartupError::MissingAuthority)
            ));
        }

        let mut page = startup_page(&[
            interface::COMMAND,
            interface::COMMAND,
            interface::STANDARD_INPUT,
            interface::STANDARD_OUTPUT,
            interface::STANDARD_ERROR,
        ]);
        let startup = Startup::parse(&page);
        assert!(startup.is_ok());
        if let Ok(startup) = startup {
            assert!(matches!(
                CommandContext::from_startup(&startup),
                Err(StartupError::MissingAuthority)
            ));
        }
        page[STARTUP_PAGE_BYTES - 1] = 1;
        assert!(matches!(
            Startup::parse(&page),
            Err(StartupError::InvalidPage)
        ));
        assert!(matches!(
            Startup::parse(&page[..STARTUP_PAGE_BYTES - 1]),
            Err(StartupError::InvalidPage)
        ));
    }
}
