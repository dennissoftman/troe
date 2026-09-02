//! Dispatcher service endpoints for the application ABI.
//!
//! This module holds the endpoints with no other home — standard input and
//! output, the discard and empty stdio pair, pipe endpoints, the resident log,
//! the random source, the private-memory registration marker, and shell script
//! submission. The filesystem, process, clock, and diagnostics families live
//! in the children.
//!
//! The dispatcher wiring here — registering an endpoint and routing a call to
//! it — is the other half of the `kernel/src/ipc.rs` ADR 0035 names. The
//! endpoints themselves belong to whichever subsystem answers them, so the
//! filesystem and network families leave with their servers while these stay.

pub(crate) mod clock;
pub(crate) mod diagnostics;
pub(crate) mod filesystem;
pub(crate) mod process;

use crate::handles::{SharedRandom, SharedResidentLog};
use crate::service::process::{
    ApplicationPipeInputService, ApplicationPipeOutputService, child_process_status,
};
use alloc::rc::Rc;
use alloc::string::String;
use alloc::vec::Vec;
use core::cell::RefCell;
use troe_abi::{random, shell_script, stream};
use troe_core::{Input, Output};
use troe_dispatch::{ReplyStatus, Request, Service, ServiceReply};
use troe_shell::parse_command_list;

pub(crate) struct ApplicationEmptyInputService;

pub(crate) struct ApplicationDiscardOutputService;

/// Registration marker. Calls are intercepted while the application is
/// suspended so the dispatcher never receives memory-management state.
pub(crate) struct ApplicationPrivateMemoryService;

pub(crate) struct ApplicationRandomService {
    pub(crate) random: SharedRandom,
}

pub(crate) struct ApplicationLogService {
    pub(crate) log: SharedResidentLog,
}

pub(crate) struct ApplicationInputService<'stream> {
    pub(crate) input: Rc<RefCell<&'stream mut dyn Input>>,
}

pub(crate) struct ApplicationOutputService<'stream> {
    pub(crate) output: Rc<RefCell<&'stream mut dyn Output>>,
}

#[derive(Default)]
pub(crate) struct SubmittedShellScript {
    pub(crate) lines: Vec<String>,
    source_bytes: usize,
}

pub(crate) struct ApplicationShellScriptService {
    pub(crate) script: Rc<RefCell<SubmittedShellScript>>,
}

impl Service for ApplicationInputService<'_> {
    fn call(&mut self, request: Request<'_>) -> Result<ServiceReply, troe_dispatch::DispatchError> {
        if request.opcode() != stream::READ {
            return Ok(ServiceReply::empty(ReplyStatus::InvalidRequest));
        }
        let Ok(requested) = stream::decode_read_request(request.payload()) else {
            return Ok(ServiceReply::empty(ReplyStatus::InvalidRequest));
        };
        let mut bytes = [0_u8; troe_abi::MAX_SERVICE_PAYLOAD_BYTES];
        let Ok(mut input) = self.input.try_borrow_mut() else {
            return Ok(ServiceReply::empty(ReplyStatus::Conflict));
        };
        match input.read(&mut bytes[..requested]) {
            Ok(count) if count <= requested => {
                ServiceReply::with_payload(ReplyStatus::Success, &bytes[..count])
            }
            Ok(_) => Ok(ServiceReply::empty(ReplyStatus::Corrupt)),
            Err(_) => Ok(ServiceReply::empty(ReplyStatus::Failure)),
        }
    }
}

impl Service for ApplicationEmptyInputService {
    fn call(&mut self, request: Request<'_>) -> Result<ServiceReply, troe_dispatch::DispatchError> {
        if request.opcode() != stream::READ
            || stream::decode_read_request(request.payload()).is_err()
        {
            return Ok(ServiceReply::empty(ReplyStatus::InvalidRequest));
        }
        Ok(ServiceReply::empty(ReplyStatus::Success))
    }
}

impl Service for ApplicationDiscardOutputService {
    fn call(&mut self, request: Request<'_>) -> Result<ServiceReply, troe_dispatch::DispatchError> {
        match request.opcode() {
            stream::WRITE if !request.payload().is_empty() => {
                Ok(ServiceReply::empty(ReplyStatus::Success))
            }
            stream::SET_CHUNK_SIZE if stream::decode_chunk_size(request.payload()).is_ok() => {
                Ok(ServiceReply::empty(ReplyStatus::Success))
            }
            _ => Ok(ServiceReply::empty(ReplyStatus::InvalidRequest)),
        }
    }
}

impl Service for ApplicationPrivateMemoryService {
    fn call(
        &mut self,
        _request: Request<'_>,
    ) -> Result<ServiceReply, troe_dispatch::DispatchError> {
        Ok(ServiceReply::empty(ReplyStatus::InvalidRequest))
    }
}

impl Service for ApplicationRandomService {
    fn call(&mut self, request: Request<'_>) -> Result<ServiceReply, troe_dispatch::DispatchError> {
        if request.opcode() != random::GET {
            return Ok(ServiceReply::empty(ReplyStatus::InvalidRequest));
        }
        let Ok(byte_count) = random::decode_request(request.payload()) else {
            return Ok(ServiceReply::empty(ReplyStatus::InvalidRequest));
        };
        let Ok(byte_count) = usize::try_from(byte_count) else {
            return Ok(ServiceReply::empty(ReplyStatus::InvalidRequest));
        };
        let mut bytes = Vec::new();
        if bytes.try_reserve_exact(byte_count).is_err() {
            return Ok(ServiceReply::empty(ReplyStatus::Exhausted));
        }
        bytes.resize(byte_count, 0);
        let Ok(mut generator) = self.random.try_borrow_mut() else {
            return Ok(ServiceReply::empty(ReplyStatus::Conflict));
        };
        if generator.fill(&mut bytes).is_err() {
            return Ok(ServiceReply::empty(ReplyStatus::Failure));
        }
        ServiceReply::with_payload(ReplyStatus::Success, &bytes)
    }
}

impl Service for ApplicationPipeInputService {
    fn call(&mut self, request: Request<'_>) -> Result<ServiceReply, troe_dispatch::DispatchError> {
        if request.opcode() != stream::READ {
            return Ok(ServiceReply::empty(ReplyStatus::InvalidRequest));
        }
        let Ok(maximum) = stream::decode_read_request(request.payload()) else {
            return Ok(ServiceReply::empty(ReplyStatus::InvalidRequest));
        };
        let mut bytes = [0_u8; troe_abi::MAX_SERVICE_PAYLOAD_BYTES];
        match self
            .pipes
            .try_borrow_mut()
            .map_err(|_| troe_dispatch::DispatchError::AccountingOverflow)?
            .read_endpoint(self.endpoint, &mut bytes[..maximum])
        {
            Ok(count) => ServiceReply::with_payload(ReplyStatus::Success, &bytes[..count]),
            Err(error) => Ok(ServiceReply::empty(child_process_status(error))),
        }
    }
}

impl Drop for ApplicationPipeInputService {
    fn drop(&mut self) {
        if let Ok(mut pipes) = self.pipes.try_borrow_mut() {
            let _detached = pipes.detach(self.endpoint);
        }
    }
}

impl Service for ApplicationPipeOutputService {
    fn call(&mut self, request: Request<'_>) -> Result<ServiceReply, troe_dispatch::DispatchError> {
        match request.opcode() {
            stream::WRITE if !request.payload().is_empty() => match self
                .pipes
                .try_borrow_mut()
                .map_err(|_| troe_dispatch::DispatchError::AccountingOverflow)?
                .write_endpoint(self.endpoint, request.payload())
            {
                Ok(count) if count == request.payload().len() => {
                    Ok(ServiceReply::empty(ReplyStatus::Success))
                }
                Ok(_) => Ok(ServiceReply::empty(ReplyStatus::Failure)),
                Err(error) => Ok(ServiceReply::empty(child_process_status(error))),
            },
            stream::SET_CHUNK_SIZE if stream::decode_chunk_size(request.payload()).is_ok() => {
                Ok(ServiceReply::empty(ReplyStatus::Success))
            }
            _ => Ok(ServiceReply::empty(ReplyStatus::InvalidRequest)),
        }
    }
}

impl Drop for ApplicationPipeOutputService {
    fn drop(&mut self) {
        if let Ok(mut pipes) = self.pipes.try_borrow_mut() {
            let _detached = pipes.detach(self.endpoint);
        }
    }
}

impl Service for ApplicationLogService {
    fn call(&mut self, request: Request<'_>) -> Result<ServiceReply, troe_dispatch::DispatchError> {
        match request.opcode() {
            stream::WRITE
                if !request.payload().is_empty()
                    && request.payload().len() <= troe_abi::MAX_SERVICE_PAYLOAD_BYTES =>
            {
                let Ok(mut log) = self.log.try_borrow_mut() else {
                    return Ok(ServiceReply::empty(ReplyStatus::Conflict));
                };
                log.append(request.payload());
                Ok(ServiceReply::empty(ReplyStatus::Success))
            }
            stream::SET_CHUNK_SIZE => {
                let Ok(bytes) = stream::decode_chunk_size(request.payload()) else {
                    return Ok(ServiceReply::empty(ReplyStatus::InvalidRequest));
                };
                let status = if bytes == 0 {
                    ReplyStatus::InvalidRequest
                } else {
                    ReplyStatus::Success
                };
                Ok(ServiceReply::empty(status))
            }
            _ => Ok(ServiceReply::empty(ReplyStatus::InvalidRequest)),
        }
    }
}

impl Service for ApplicationOutputService<'_> {
    fn call(&mut self, request: Request<'_>) -> Result<ServiceReply, troe_dispatch::DispatchError> {
        let Ok(mut output) = self.output.try_borrow_mut() else {
            return Ok(ServiceReply::empty(ReplyStatus::Conflict));
        };
        match request.opcode() {
            stream::WRITE
                if !request.payload().is_empty()
                    && request.payload().len() <= troe_abi::MAX_SERVICE_PAYLOAD_BYTES =>
            {
                let status = if troe_core::write_all(&mut **output, request.payload()).is_ok() {
                    ReplyStatus::Success
                } else {
                    ReplyStatus::Failure
                };
                Ok(ServiceReply::empty(status))
            }
            stream::SET_CHUNK_SIZE => {
                let Ok(bytes) = stream::decode_chunk_size(request.payload()) else {
                    return Ok(ServiceReply::empty(ReplyStatus::InvalidRequest));
                };
                let status = if output.set_chunk_size(bytes).is_ok() {
                    ReplyStatus::Success
                } else {
                    ReplyStatus::Unsupported
                };
                Ok(ServiceReply::empty(status))
            }
            _ => Ok(ServiceReply::empty(ReplyStatus::InvalidRequest)),
        }
    }
}

impl Service for ApplicationShellScriptService {
    fn call(&mut self, request: Request<'_>) -> Result<ServiceReply, troe_dispatch::DispatchError> {
        if request.opcode() != shell_script::SUBMIT_LINE {
            return Ok(ServiceReply::empty(ReplyStatus::InvalidRequest));
        }
        let Ok(line) = shell_script::decode_submit_line(request.payload()) else {
            return Ok(ServiceReply::empty(ReplyStatus::InvalidRequest));
        };
        if parse_command_list(line.source()).is_err() {
            return Ok(ServiceReply::empty(ReplyStatus::InvalidRequest));
        }
        let Ok(mut script) = self.script.try_borrow_mut() else {
            return Ok(ServiceReply::empty(ReplyStatus::Conflict));
        };
        let Some(source_bytes) = script.source_bytes.checked_add(line.source().len()) else {
            return Ok(ServiceReply::empty(ReplyStatus::Exhausted));
        };
        if script.lines.len() >= shell_script::MAX_LINES
            || source_bytes > shell_script::MAX_SCRIPT_BYTES
        {
            return Ok(ServiceReply::empty(ReplyStatus::Exhausted));
        }
        let mut source = String::new();
        if source.try_reserve_exact(line.source().len()).is_err()
            || script.lines.try_reserve(1).is_err()
        {
            return Ok(ServiceReply::empty(ReplyStatus::Exhausted));
        }
        source.push_str(line.source());
        script.lines.push(source);
        script.source_bytes = source_bytes;
        Ok(ServiceReply::empty(ReplyStatus::Success))
    }
}
