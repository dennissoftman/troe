//! Configurable bounded text console rendered onto a linear framebuffer.
#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;
#[cfg(test)]
extern crate std;

mod framebuffer;
#[cfg(test)]
mod tests;
mod text;

pub use crate::framebuffer::{
    Color, EncodedFramebufferPixel, FRAMEBUFFER_BYTES_PER_PIXEL, FramebufferDescriptor,
    FramebufferDescriptorError, FramebufferPixelFormat, PixelSurface, SurfaceError,
};
pub use crate::text::{TextConsole, TextConsoleConfig, TextConsoleError};

/// Invalid text-console resource policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConfigError {
    /// An escape sequence must allow at least its introducer and final byte.
    EscapeCapacityTooSmall,
    /// Text-grid retention must accept at least one cell.
    EmptyCellCapacity,
    /// Tab stops must contain at least one column.
    EmptyTabWidth,
}
