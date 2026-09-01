//! The canonical startup page handed to a launching application.

use crate::bytes::{write_u16, write_u32, write_u64};
use crate::{
    ABI_MAJOR, ApplicationLayout, ApplicationLimits, PAGE_BYTES, STARTUP_FIXED_BYTES,
    STARTUP_HANDLE_BYTES,
};

/// One explicit initial authority descriptor encoded into the startup page.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InitialHandle {
    /// Opaque generation-checked handle value.
    pub value: u64,
    /// ABI-defined rights bits.
    pub rights: u32,
    /// ABI-defined service interface identifier.
    pub interface: u32,
    /// Required interface major version.
    pub major: u16,
    /// Required interface minor version.
    pub minor: u16,
}

/// Values placed in the immutable ABI 1.x startup page.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StartupInfo<'handles> {
    /// Monotonic nonzero task identity selected by the kernel.
    pub task_id: u64,
    /// Initial handles after loader-policy and launcher-authority intersection.
    pub handles: &'handles [InitialHandle],
}

/// Failure to encode a canonical ABI startup page.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StartupPageError {
    /// The task identity is the reserved zero value.
    InvalidTaskId,
    /// More initial handles were supplied than the standard policy permits.
    TooManyHandles,
    /// A descriptor used the reserved zero opaque-handle value.
    InvalidHandle,
    /// Two descriptors expose the same opaque handle value.
    DuplicateHandle,
}
pub(crate) fn encode_startup_page(
    abi_minor: u16,
    image_base: u64,
    layout: ApplicationLayout,
    info: StartupInfo<'_>,
    destination: &mut [u8; PAGE_BYTES],
) -> Result<(), StartupPageError> {
    if info.task_id == 0 {
        return Err(StartupPageError::InvalidTaskId);
    }
    let limits = ApplicationLimits::standard();
    if info.handles.len() > usize::from(limits.initial_handles) {
        return Err(StartupPageError::TooManyHandles);
    }
    for (index, handle) in info.handles.iter().enumerate() {
        if handle.value == 0 {
            return Err(StartupPageError::InvalidHandle);
        }
        if info.handles[..index]
            .iter()
            .any(|existing| existing.value == handle.value)
        {
            return Err(StartupPageError::DuplicateHandle);
        }
    }

    destination.fill(0);
    let encoded_bytes = STARTUP_FIXED_BYTES + info.handles.len() * STARTUP_HANDLE_BYTES;
    let encoded_bytes =
        u32::try_from(encoded_bytes).map_err(|_| StartupPageError::TooManyHandles)?;
    let handle_count =
        u16::try_from(info.handles.len()).map_err(|_| StartupPageError::TooManyHandles)?;
    write_u32(destination, 0, encoded_bytes);
    write_u16(destination, 4, ABI_MAJOR);
    write_u16(destination, 6, abi_minor);
    write_u32(destination, 8, 4096);
    write_u16(destination, 12, 0);
    write_u16(destination, 14, handle_count);
    write_u64(destination, 16, image_base);
    write_u64(destination, 24, layout.heap_address);
    write_u64(destination, 32, layout.heap_bytes);
    write_u64(destination, 40, layout.stack_bottom);
    write_u64(destination, 48, layout.stack_top);
    write_u64(destination, 56, info.task_id);
    for (index, handle) in info.handles.iter().enumerate() {
        let offset = STARTUP_FIXED_BYTES + index * STARTUP_HANDLE_BYTES;
        write_u64(destination, offset, handle.value);
        write_u32(destination, offset + 8, handle.rights);
        write_u32(destination, offset + 12, handle.interface);
        write_u16(destination, offset + 16, handle.major);
        write_u16(destination, offset + 18, handle.minor);
    }
    Ok(())
}
