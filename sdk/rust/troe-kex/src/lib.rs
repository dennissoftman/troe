//! Minimal `no_std` runtime for bounded KEX command applications.
#![no_std]

use core::{fmt, slice};

pub use troe_abi::{
    ABI_MAJOR, ABI_MINOR, command, datagram, exit, filesystem, filesystem_mutation,
};
use troe_abi::{MAX_MESSAGE_BYTES, MAX_SERVICE_PAYLOAD_BYTES, interface, reply, stream};

const STARTUP_PAGE_BYTES: usize = 4096;
const STARTUP_HEADER_BYTES: usize = 64;
const STARTUP_HANDLE_BYTES: usize = 24;
const CALL_RIGHT: u32 = 1;

/// Maximum stack buffer needed to receive one command invocation.
pub const INVOCATION_BUFFER_BYTES: usize = command::MAX_INVOCATION_BYTES;
/// Maximum stack buffer needed to receive one datagram.
pub const DATAGRAM_BUFFER_BYTES: usize = datagram::MAX_RECEIVE_REPLY_BYTES;
/// Maximum stack buffer needed to receive one directory page.
pub const FILESYSTEM_LIST_BUFFER_BYTES: usize = filesystem::MAX_LIST_REPLY_BYTES;

/// One opaque application handle selected from the immutable startup page.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Handle {
    value: u64,
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
}

impl CommandContext {
    fn from_startup(startup: &Startup<'_>) -> Result<Self, StartupError> {
        Ok(Self {
            invocation: startup.required_handle(interface::COMMAND)?,
            stdin: startup.required_handle(interface::STANDARD_INPUT)?,
            stdout: startup.required_handle(interface::STANDARD_OUTPUT)?,
            stderr: startup.required_handle(interface::STANDARD_ERROR)?,
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
        })
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

    /// Borrow the optional atomic filesystem-mutation capability.
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

    /// Yield cooperatively and resume only after kernel reselection.
    ///
    /// # Errors
    ///
    /// Reports an invalid kernel completion or a non-freestanding host build.
    pub fn yield_now(&mut self) -> Result<(), Error> {
        native_yield()
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

/// Atomic create/replace and remove client scoped to one application lifetime.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FilesystemMutation {
    handle: Handle,
}

/// One pending complete-file replacement.
pub struct FileReplacement {
    handle: Handle,
    token: u32,
    offset: usize,
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
}

impl FilesystemMutation {
    /// Begin staging one complete regular-file replacement.
    ///
    /// Only one replacement may be pending on this capability. Application
    /// teardown implicitly discards an uncommitted replacement.
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

    /// Atomically remove one regular file.
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
}

impl FileReplacement {
    /// Append all bytes sequentially using bounded copied calls.
    ///
    /// # Errors
    ///
    /// Reports the first size, staging, service, or call-gate failure.
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
                .checked_add(chunk_bytes)
                .ok_or(Error::Overflow)?;
            bytes = &bytes[chunk_bytes..];
        }
        Ok(())
    }

    /// Atomically publish the complete staged bytes and consume this token.
    ///
    /// The service discards the staging transaction whether commit succeeds or
    /// returns a filesystem failure.
    ///
    /// # Errors
    ///
    /// Reports immutable targets, quotas, filesystem failures, or call-gate
    /// failure.
    pub fn commit(self) -> Result<(), Error> {
        self.finish(filesystem_mutation::COMMIT_REPLACE)
    }

    /// Discard the staged bytes and consume this token.
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
        if handle_count > 32
            || encoded_bytes > bytes.len()
            || bytes[encoded_bytes..].iter().any(|byte| *byte != 0)
            || read_u64(bytes, 16)? != 0x0000_4000_0000_0000
            || read_u64(bytes, 56)? == 0
            || !read_u64(bytes, 40)?.is_multiple_of(STARTUP_PAGE_BYTES as u64)
            || !read_u64(bytes, 48)?.is_multiple_of(16)
            || read_u64(bytes, 40)? >= read_u64(bytes, 48)?
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

    fn required_handle(&self, wanted: u32) -> Result<Handle, StartupError> {
        self.optional_handle(wanted, 1, 0)?
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
        ABI_MAJOR, CommandContext, STARTUP_HANDLE_BYTES, STARTUP_HEADER_BYTES, STARTUP_PAGE_BYTES,
        Startup, StartupError, interface,
    };

    fn startup_page(interfaces: &[u32]) -> [u8; STARTUP_PAGE_BYTES] {
        let mut page = [0_u8; STARTUP_PAGE_BYTES];
        let encoded = STARTUP_HEADER_BYTES + interfaces.len() * STARTUP_HANDLE_BYTES;
        page[0..4].copy_from_slice(&u32::try_from(encoded).unwrap_or(u32::MAX).to_le_bytes());
        page[4..6].copy_from_slice(&ABI_MAJOR.to_le_bytes());
        page[8..12].copy_from_slice(&4096_u32.to_le_bytes());
        page[14..16].copy_from_slice(
            &u16::try_from(interfaces.len())
                .unwrap_or(u16::MAX)
                .to_le_bytes(),
        );
        page[16..24].copy_from_slice(&0x0000_4000_0000_0000_u64.to_le_bytes());
        page[40..48].copy_from_slice(&0x5000_u64.to_le_bytes());
        page[48..56].copy_from_slice(&0x9000_u64.to_le_bytes());
        page[56..64].copy_from_slice(&7_u64.to_le_bytes());
        for (index, interface) in interfaces.iter().copied().enumerate() {
            let offset = STARTUP_HEADER_BYTES + index * STARTUP_HANDLE_BYTES;
            page[offset..offset + 8].copy_from_slice(&(0x1_0001_u64 + index as u64).to_le_bytes());
            page[offset + 8..offset + 12].copy_from_slice(&1_u32.to_le_bytes());
            page[offset + 12..offset + 16].copy_from_slice(&interface.to_le_bytes());
            page[offset + 16..offset + 18].copy_from_slice(&1_u16.to_le_bytes());
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
        ]);
        let startup = Startup::parse(&page);
        assert!(startup.is_ok());
        if let Ok(startup) = startup {
            let command = CommandContext::from_startup(&startup);
            assert!(command.is_ok());
            if let Ok(command) = command {
                assert!(command.datagram().is_ok());
            }
        }
    }

    #[test]
    fn startup_rejects_truncation_padding_and_duplicate_interfaces() {
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
