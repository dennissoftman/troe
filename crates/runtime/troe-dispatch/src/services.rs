//! Built-in services for command invocation, byte streams, and the console.

use crate::{
    DispatchError, Dispatcher, Handle, MAX_MESSAGE_BYTES, ReplyStatus, Request, Service,
    ServiceReply,
};
use alloc::rc::Rc;
use alloc::vec::Vec;
use core::cell::RefCell;
use core::str;
use troe_abi::{MAX_SERVICE_PAYLOAD_BYTES, command, stream};
use troe_core::{BoundedOutput, Output, StreamError, write_all};

/// Immutable command-invocation service for one application launch.
///
/// Arguments are retained once as a flat UTF-8 table with a parallel length
/// table. That representation serves both the single-message record of
/// interface 1.1 and the paged reads of 1.2 without a second copy, and without
/// one owned `String` allocation per argument.
pub struct CommandInvocationService {
    invocation: Option<Vec<u8>>,
    environment: Vec<u8>,
    argument_bytes: Vec<u8>,
    argument_lengths: Vec<u16>,
}

impl CommandInvocationService {
    /// Encode one canonical current-directory and argument record.
    ///
    /// # Errors
    ///
    /// Rejects invocation-policy excess or bounded allocation failure.
    pub fn new<T: AsRef<str>>(cwd: &str, arguments: &[T]) -> Result<Self, DispatchError> {
        Self::new_with_environment(cwd, arguments, &[])
    }

    /// Encode one invocation and its immutable `NAME=VALUE` environment.
    ///
    /// An argument vector that exceeds the single-message bounds of interface
    /// 1.1 is still accepted and is readable only page by page. `GET_INVOCATION`
    /// then fails closed rather than returning a prefix of the operands.
    ///
    /// # Errors
    ///
    /// Rejects invocation/environment policy excess or bounded allocation failure.
    pub fn new_with_environment<T: AsRef<str>>(
        cwd: &str,
        arguments: &[T],
        environment: &[&str],
    ) -> Result<Self, DispatchError> {
        if !(1..=command::MAX_PAGED_ARGUMENTS).contains(&arguments.len()) {
            return Err(DispatchError::MessageTooLarge);
        }
        let mut argument_bytes = Vec::new();
        let mut argument_lengths = Vec::new();
        argument_lengths
            .try_reserve_exact(arguments.len())
            .map_err(|_| DispatchError::MetadataExhausted)?;
        let mut aggregate = 0_usize;
        for (index, argument) in arguments.iter().enumerate() {
            let value = argument.as_ref();
            if value.len() > command::MAX_SINGLE_ARGUMENT_BYTES || (index == 0 && value.is_empty())
            {
                return Err(DispatchError::MessageTooLarge);
            }
            aggregate = aggregate
                .checked_add(value.len())
                .ok_or(DispatchError::MessageTooLarge)?;
            if aggregate > command::MAX_PAGED_ARGUMENT_BYTES {
                return Err(DispatchError::MessageTooLarge);
            }
            argument_bytes
                .try_reserve(value.len())
                .map_err(|_| DispatchError::MetadataExhausted)?;
            argument_bytes.extend_from_slice(value.as_bytes());
            argument_lengths
                .push(u16::try_from(value.len()).map_err(|_| DispatchError::MessageTooLarge)?);
        }

        let mut encoded = [0_u8; command::MAX_INVOCATION_BYTES];
        let invocation = match command::encode(cwd, arguments, &mut encoded) {
            Ok(count) => {
                let mut owned = Vec::new();
                owned
                    .try_reserve_exact(count)
                    .map_err(|_| DispatchError::MetadataExhausted)?;
                owned.extend_from_slice(&encoded[..count]);
                Some(owned)
            }
            Err(command::EncodeError::LimitExceeded)
                if arguments.len() > command::MAX_ARGUMENTS =>
            {
                None
            }
            Err(command::EncodeError::LimitExceeded) if aggregate > command::MAX_ARGUMENT_BYTES => {
                None
            }
            Err(_) => return Err(DispatchError::MessageTooLarge),
        };

        let mut encoded_environment = [0_u8; command::MAX_ENCODED_ENVIRONMENT_BYTES];
        let environment_count = command::encode_environment(environment, &mut encoded_environment)
            .map_err(|_| DispatchError::MessageTooLarge)?;
        let mut owned_environment = Vec::new();
        owned_environment
            .try_reserve_exact(environment_count)
            .map_err(|_| DispatchError::MetadataExhausted)?;
        owned_environment.extend_from_slice(&encoded_environment[..environment_count]);
        Ok(Self {
            invocation,
            environment: owned_environment,
            argument_bytes,
            argument_lengths,
        })
    }

    /// Borrow one retained argument by its absolute index.
    fn argument(&self, wanted: usize) -> Option<&str> {
        let mut cursor = 0_usize;
        for (index, length) in self.argument_lengths.iter().enumerate() {
            let end = cursor.checked_add(usize::from(*length))?;
            if index == wanted {
                return str::from_utf8(self.argument_bytes.get(cursor..end)?).ok();
            }
            cursor = end;
        }
        None
    }
}

impl Service for CommandInvocationService {
    fn call(&mut self, request: Request<'_>) -> Result<ServiceReply, DispatchError> {
        match request.opcode() {
            command::GET_INVOCATION if request.payload().is_empty() => match &self.invocation {
                Some(invocation) => ServiceReply::with_payload(ReplyStatus::Success, invocation),
                None => Ok(ServiceReply::empty(ReplyStatus::TooLarge)),
            },
            command::GET_ENVIRONMENT if request.payload().is_empty() => {
                ServiceReply::with_payload(ReplyStatus::Success, &self.environment)
            }
            command::GET_ARGUMENT_PAGE => {
                let Ok(start) = command::decode_argument_page_request(request.payload()) else {
                    return Ok(ServiceReply::empty(ReplyStatus::InvalidRequest));
                };
                if start > self.argument_lengths.len() {
                    return Ok(ServiceReply::empty(ReplyStatus::InvalidRequest));
                }
                let mut page = [0_u8; command::MAX_ARGUMENT_PAGE_REPLY_BYTES];
                let count = command::encode_argument_page_with(
                    self.argument_lengths.len(),
                    start,
                    |index| self.argument(index),
                    &mut page,
                )
                .map_err(|_| DispatchError::MessageTooLarge)?;
                ServiceReply::with_payload(ReplyStatus::Success, &page[..count])
            }
            _ => Ok(ServiceReply::empty(ReplyStatus::InvalidRequest)),
        }
    }
}

/// Read-only byte service backed by one owned, bounded input snapshot.
pub struct ByteInputService {
    bytes: Vec<u8>,
    offset: usize,
}

impl ByteInputService {
    /// Own the complete input made available to one application.
    #[must_use]
    pub const fn new(bytes: Vec<u8>) -> Self {
        Self { bytes, offset: 0 }
    }
}

impl Service for ByteInputService {
    fn call(&mut self, request: Request<'_>) -> Result<ServiceReply, DispatchError> {
        if request.opcode() != stream::READ {
            return Ok(ServiceReply::empty(ReplyStatus::InvalidRequest));
        }
        let Ok(requested) = stream::decode_read_request(request.payload()) else {
            return Ok(ServiceReply::empty(ReplyStatus::InvalidRequest));
        };
        let available = self.bytes.len().saturating_sub(self.offset);
        let count = requested.min(available).min(MAX_SERVICE_PAYLOAD_BYTES);
        let end = self
            .offset
            .checked_add(count)
            .ok_or(DispatchError::AccountingOverflow)?;
        let reply =
            ServiceReply::with_payload(ReplyStatus::Success, &self.bytes[self.offset..end])?;
        self.offset = end;
        Ok(reply)
    }
}

/// Shared bounded bytes retained after an output service is registered.
#[derive(Clone)]
pub struct SharedOutput {
    output: Rc<RefCell<BoundedOutput>>,
}

impl SharedOutput {
    /// Construct an empty output with one hard aggregate byte ceiling.
    #[must_use]
    pub fn new(limit: usize) -> Self {
        Self {
            output: Rc::new(RefCell::new(BoundedOutput::new(limit))),
        }
    }

    /// Copy all retained bytes to a caller-supplied output.
    ///
    /// # Errors
    ///
    /// Reports a conflicting service borrow or destination stream failure.
    pub fn copy_to(&self, destination: &mut dyn Output) -> Result<(), StreamError> {
        let retained = self.output.try_borrow().map_err(|_| StreamError::Device)?;
        write_all(destination, retained.as_slice())
    }

    /// Number of retained bytes.
    #[must_use]
    pub fn len(&self) -> usize {
        self.output
            .try_borrow()
            .map_or(0, |output| output.as_slice().len())
    }

    /// Whether no bytes were retained.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// Write-only byte-stream service retaining output in [`SharedOutput`].
pub struct ByteOutputService {
    output: SharedOutput,
}

impl ByteOutputService {
    /// Bind a service to shared retained output.
    #[must_use]
    pub const fn new(output: SharedOutput) -> Self {
        Self { output }
    }
}

impl Service for ByteOutputService {
    fn call(&mut self, request: Request<'_>) -> Result<ServiceReply, DispatchError> {
        if request.opcode() != stream::WRITE
            || request.payload().is_empty()
            || request.payload().len() > MAX_SERVICE_PAYLOAD_BYTES
        {
            return Ok(ServiceReply::empty(ReplyStatus::InvalidRequest));
        }
        let Ok(mut output) = self.output.output.try_borrow_mut() else {
            return Ok(ServiceReply::empty(ReplyStatus::Failure));
        };
        let status = if write_all(&mut *output, request.payload()).is_ok() {
            ReplyStatus::Success
        } else {
            ReplyStatus::Failure
        };
        Ok(ServiceReply::empty(status))
    }
}

/// Console-service opcode accepting raw bytes as the request payload.
pub const CONSOLE_WRITE: u16 = 1;

/// Service adapter exposing any [`Output`] implementation through dispatch.
pub struct ConsoleService<O> {
    output: O,
}

impl<O> ConsoleService<O> {
    /// Wrap a direct output implementation as a message-shaped service.
    #[must_use]
    pub const fn new(output: O) -> Self {
        Self { output }
    }
}

impl<O: Output> Service for ConsoleService<O> {
    fn call(&mut self, request: Request<'_>) -> Result<ServiceReply, DispatchError> {
        if request.opcode() != CONSOLE_WRITE {
            return Ok(ServiceReply::empty(ReplyStatus::InvalidRequest));
        }
        let status = if write_all(&mut self.output, request.payload()).is_ok() {
            ReplyStatus::Success
        } else {
            ReplyStatus::Failure
        };
        Ok(ServiceReply::empty(status))
    }
}

/// Client adapter preserving the ordinary [`Output`] interface over dispatch.
pub struct DispatchedOutput<'dispatcher, 'service> {
    dispatcher: &'dispatcher mut Dispatcher<'service>,
    handle: Handle,
}

impl<'dispatcher, 'service> DispatchedOutput<'dispatcher, 'service> {
    /// Bind an output client to one explicitly supplied handle.
    #[must_use]
    pub const fn new(dispatcher: &'dispatcher mut Dispatcher<'service>, handle: Handle) -> Self {
        Self { dispatcher, handle }
    }
}

impl Output for DispatchedOutput<'_, '_> {
    fn write(&mut self, bytes: &[u8]) -> Result<usize, StreamError> {
        if bytes.is_empty() {
            return Ok(0);
        }
        let count = bytes.len().min(MAX_MESSAGE_BYTES);
        let reply = self
            .dispatcher
            .call(self.handle, CONSOLE_WRITE, &bytes[..count])
            .map_err(|_| StreamError::Device)?;
        if reply.status() != ReplyStatus::Success || !reply.payload().is_empty() {
            return Err(StreamError::Device);
        }
        Ok(count)
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        ByteInputService, ByteOutputService, CommandInvocationService, ConsoleService,
        DispatchError, DispatchedOutput, Dispatcher, MAX_MESSAGE_BYTES, ReplyStatus, Rights,
        SharedOutput as RetainedOutput,
    };
    use alloc::boxed::Box;
    use alloc::rc::Rc;
    use alloc::vec;
    use alloc::vec::Vec;
    use core::cell::RefCell;
    use troe_abi::{command, stream};
    use troe_core::{BoundedOutput, Output, StreamError, write_all};

    #[derive(Clone)]
    struct SharedOutput(Rc<RefCell<Vec<u8>>>);

    impl Output for SharedOutput {
        fn write(&mut self, bytes: &[u8]) -> Result<usize, StreamError> {
            self.0.borrow_mut().extend_from_slice(bytes);
            Ok(bytes.len())
        }
    }
    #[test]
    fn an_oversized_argument_record_is_paged_and_never_returned_in_part() {
        // An operand list far larger than one single-message record.
        let mut arguments = alloc::vec::Vec::new();
        arguments.push(alloc::string::String::from("rm"));
        for index in 0..1000 {
            arguments.push(alloc::format!("operand-{index:04}.txt"));
        }
        let mut dispatcher = Dispatcher::new(4, 4).unwrap_or_else(|_| std::process::abort());
        let (_port, handle) = dispatcher
            .register(
                Box::new(
                    CommandInvocationService::new("/work", &arguments)
                        .unwrap_or_else(|_| std::process::abort()),
                ),
                Rights::CALL,
            )
            .unwrap_or_else(|_| std::process::abort());

        // The single-message operation fails closed rather than truncating.
        assert_eq!(
            dispatcher
                .call(handle, command::GET_INVOCATION, &[])
                .unwrap_or_else(|_| std::process::abort())
                .status(),
            ReplyStatus::TooLarge
        );

        let mut seen = Vec::new();
        let mut start = 0_usize;
        loop {
            let mut request = [0_u8; command::ARGUMENT_PAGE_REQUEST_BYTES];
            let count = command::encode_argument_page_request(start, &mut request)
                .unwrap_or_else(|_| std::process::abort());
            let reply = dispatcher
                .call(handle, command::GET_ARGUMENT_PAGE, &request[..count])
                .unwrap_or_else(|_| std::process::abort());
            assert_eq!(reply.status(), ReplyStatus::Success);
            let page = command::ArgumentPage::parse(reply.payload())
                .unwrap_or_else(|_| std::process::abort());
            assert_eq!(page.total(), arguments.len());
            if page.is_empty() {
                break;
            }
            seen.extend(page.iter().map(alloc::string::ToString::to_string));
            start = page.next_start();
        }
        assert_eq!(seen, arguments);

        // A malformed or out-of-range page request is refused, not clamped.
        assert_eq!(
            dispatcher
                .call(handle, command::GET_ARGUMENT_PAGE, &[0])
                .unwrap_or_else(|_| std::process::abort())
                .status(),
            ReplyStatus::InvalidRequest
        );
        let mut past = [0_u8; command::ARGUMENT_PAGE_REQUEST_BYTES];
        let count = command::encode_argument_page_request(arguments.len() + 1, &mut past)
            .unwrap_or_else(|_| std::process::abort());
        assert_eq!(
            dispatcher
                .call(handle, command::GET_ARGUMENT_PAGE, &past[..count])
                .unwrap_or_else(|_| std::process::abort())
                .status(),
            ReplyStatus::InvalidRequest
        );
    }

    #[test]
    fn a_record_within_the_single_message_bounds_serves_both_operations() {
        let mut dispatcher = Dispatcher::new(4, 4).unwrap_or_else(|_| std::process::abort());
        let (_port, handle) = dispatcher
            .register(
                Box::new(
                    CommandInvocationService::new("/work", &["cat", "alpha.txt"])
                        .unwrap_or_else(|_| std::process::abort()),
                ),
                Rights::CALL,
            )
            .unwrap_or_else(|_| std::process::abort());
        let reply = dispatcher
            .call(handle, command::GET_INVOCATION, &[])
            .unwrap_or_else(|_| std::process::abort());
        assert_eq!(reply.status(), ReplyStatus::Success);
        let mut request = [0_u8; command::ARGUMENT_PAGE_REQUEST_BYTES];
        let count = command::encode_argument_page_request(0, &mut request)
            .unwrap_or_else(|_| std::process::abort());
        let reply = dispatcher
            .call(handle, command::GET_ARGUMENT_PAGE, &request[..count])
            .unwrap_or_else(|_| std::process::abort());
        let page =
            command::ArgumentPage::parse(reply.payload()).unwrap_or_else(|_| std::process::abort());
        assert_eq!(
            page.iter().collect::<Vec<_>>(),
            alloc::vec!["cat", "alpha.txt"]
        );
    }

    #[test]
    fn command_and_standard_stream_services_enforce_exact_protocols() {
        let mut dispatcher = Dispatcher::new(4, 4).unwrap_or_else(|_| std::process::abort());
        let (_command_port, command_handle) = dispatcher
            .register(
                Box::new(
                    CommandInvocationService::new("/work", &["echo", "ready"])
                        .unwrap_or_else(|_| std::process::abort()),
                ),
                Rights::CALL,
            )
            .unwrap_or_else(|_| std::process::abort());
        let reply = dispatcher
            .call(command_handle, command::GET_INVOCATION, &[])
            .unwrap_or_else(|_| std::process::abort());
        let invocation =
            command::Invocation::parse(reply.payload()).unwrap_or_else(|_| std::process::abort());
        assert_eq!(invocation.cwd(), "/work");
        assert_eq!(invocation.argument(1), Some("ready"));
        assert_eq!(
            dispatcher
                .call(command_handle, command::GET_INVOCATION, &[0])
                .unwrap_or_else(|_| std::process::abort())
                .status(),
            ReplyStatus::InvalidRequest
        );

        let (_input_port, input_handle) = dispatcher
            .register(
                Box::new(ByteInputService::new(b"abcdef".to_vec())),
                Rights::CALL,
            )
            .unwrap_or_else(|_| std::process::abort());
        let four = stream::encode_read_request(4).unwrap_or_else(|_| std::process::abort());
        assert_eq!(
            dispatcher
                .call(input_handle, stream::READ, &four)
                .unwrap_or_else(|_| std::process::abort())
                .payload(),
            b"abcd"
        );
        assert_eq!(
            dispatcher
                .call(input_handle, stream::READ, &four)
                .unwrap_or_else(|_| std::process::abort())
                .payload(),
            b"ef"
        );

        let retained = RetainedOutput::new(5);
        let (_output_port, output_handle) = dispatcher
            .register(
                Box::new(ByteOutputService::new(retained.clone())),
                Rights::CALL,
            )
            .unwrap_or_else(|_| std::process::abort());
        assert_eq!(
            dispatcher
                .call(output_handle, stream::WRITE, b"hello")
                .unwrap_or_else(|_| std::process::abort())
                .status(),
            ReplyStatus::Success
        );
        assert_eq!(
            dispatcher
                .call(output_handle, stream::WRITE, b"!")
                .unwrap_or_else(|_| std::process::abort())
                .status(),
            ReplyStatus::Failure
        );
        let mut copied = BoundedOutput::new(5);
        retained
            .copy_to(&mut copied)
            .unwrap_or_else(|_| std::process::abort());
        assert_eq!(copied.as_slice(), b"hello");
    }
    #[test]
    fn console_can_switch_between_direct_and_dispatched_output() -> Result<(), DispatchError> {
        let direct_bytes = Rc::new(RefCell::new(Vec::new()));
        let dispatched_bytes = Rc::new(RefCell::new(Vec::new()));
        let payload = vec![b'x'; MAX_MESSAGE_BYTES + 17];

        let mut direct = SharedOutput(Rc::clone(&direct_bytes));
        if write_all(&mut direct, &payload).is_err() {
            return Err(DispatchError::MetadataExhausted);
        }

        let mut dispatcher = Dispatcher::new(1, 1)?;
        let (_port, handle) = dispatcher.register(
            Box::new(ConsoleService::new(SharedOutput(Rc::clone(
                &dispatched_bytes,
            )))),
            Rights::CALL,
        )?;
        let mut output = DispatchedOutput::new(&mut dispatcher, handle);
        if write_all(&mut output, &payload).is_err() {
            return Err(DispatchError::MetadataExhausted);
        }

        assert_eq!(*direct_bytes.borrow(), *dispatched_bytes.borrow());
        assert_eq!(dispatcher.stats().calls, 2);
        Ok(())
    }
}
