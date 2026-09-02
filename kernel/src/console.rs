//! Output sinks the kernel owns: firmware, machine port, and shell console.
//!
//! `FirmwareConsole` writes through UEFI boot services and is valid only
//! before the handoff. `NativeConsole` writes through the machine port and is
//! valid after it. `NativeShellConsole` fans one write out to the serial port
//! and the framebuffer text console together, which is why the session
//! terminal and the dispatched console service can share a single sink.

use crate::handoff::write_boot_status;
use crate::limits::{BOOT_DEVICES_LABEL, BOOT_MEMORY_LABEL, BOOT_RUNTIME_LABEL};
use alloc::rc::Rc;
use alloc::string::String;
use core::cell::RefCell;
use core::fmt::Write as _;
use troe_console::{FramebufferDescriptor, TextConsole, TextConsoleConfig};
use troe_core::{Input, Output, StreamError};

pub(crate) struct FirmwareConsole;

impl Output for FirmwareConsole {
    fn write(&mut self, bytes: &[u8]) -> Result<usize, StreamError> {
        let succeeded = uefi::system::with_stdout(|stdout| {
            if bytes == b"\x1b[2J\x1b[H" {
                stdout.clear().is_ok()
            } else {
                let text = String::from_utf8_lossy(bytes);
                stdout.write_str(text.as_ref()).is_ok()
            }
        });
        if succeeded {
            Ok(bytes.len())
        } else {
            Err(StreamError::Device)
        }
    }
}

pub(crate) struct NativeConsole;

impl Output for NativeConsole {
    fn write(&mut self, bytes: &[u8]) -> Result<usize, StreamError> {
        if troe_machine::write(bytes) {
            Ok(bytes.len())
        } else {
            Err(StreamError::Device)
        }
    }
}

pub(crate) enum NativeShellConsole {
    Serial(NativeConsole),
    Mirrored {
        serial: NativeConsole,
        framebuffer: TextConsole<troe_machine::OwnedFramebuffer>,
    },
}

impl NativeShellConsole {
    pub(crate) fn new(framebuffer: Option<FramebufferDescriptor>) -> Self {
        let Some(framebuffer) = framebuffer else {
            return Self::Serial(NativeConsole);
        };
        let Ok(surface) = troe_machine::OwnedFramebuffer::new(framebuffer) else {
            return Self::Serial(NativeConsole);
        };
        let Ok(framebuffer) = TextConsole::new(surface, TextConsoleConfig::standard()) else {
            return Self::Serial(NativeConsole);
        };
        Self::Mirrored {
            serial: NativeConsole,
            framebuffer,
        }
    }

    pub(crate) const fn has_framebuffer(&self) -> bool {
        matches!(self, Self::Mirrored { .. })
    }

    pub(crate) fn replay_completed_boot(&mut self) -> Result<(), StreamError> {
        let Self::Mirrored { framebuffer, .. } = self else {
            return Ok(());
        };
        write_boot_status(framebuffer, BOOT_MEMORY_LABEL, true)
            .map_err(|()| StreamError::Device)?;
        write_boot_status(framebuffer, BOOT_DEVICES_LABEL, true)
            .map_err(|()| StreamError::Device)?;
        write_boot_status(framebuffer, BOOT_RUNTIME_LABEL, true).map_err(|()| StreamError::Device)
    }
}

impl Output for NativeShellConsole {
    fn write(&mut self, bytes: &[u8]) -> Result<usize, StreamError> {
        match self {
            Self::Serial(serial) => serial.write(bytes),
            Self::Mirrored {
                serial,
                framebuffer,
            } => {
                let count = serial.write(bytes)?;
                let _mirrored = framebuffer.write(&bytes[..count]);
                Ok(count)
            }
        }
    }
}

pub(crate) struct EmptyInput;

pub(crate) struct DiscardOutput;

impl Input for EmptyInput {
    fn read(&mut self, _destination: &mut [u8]) -> Result<usize, StreamError> {
        Ok(0)
    }
}

pub(crate) type SharedShellConsole = Rc<RefCell<NativeShellConsole>>;

/// Client for the single owned shell console.
///
/// The dispatched console service and session terminal echo both write
/// through this handle, so serial and framebuffer output stay mirrored
/// regardless of which one produced the bytes.
pub(crate) struct SharedConsoleOutput {
    console: SharedShellConsole,
}

impl SharedConsoleOutput {
    pub(crate) const fn new(console: SharedShellConsole) -> Self {
        Self { console }
    }
}

impl Output for SharedConsoleOutput {
    fn write(&mut self, bytes: &[u8]) -> Result<usize, StreamError> {
        self.console
            .try_borrow_mut()
            .map_err(|_| StreamError::Device)?
            .write(bytes)
    }
}

impl Output for DiscardOutput {
    fn write(&mut self, bytes: &[u8]) -> Result<usize, StreamError> {
        Ok(bytes.len())
    }
}
