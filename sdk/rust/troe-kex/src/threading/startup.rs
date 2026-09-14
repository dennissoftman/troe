//! Explicit profile validation; ordinary `Startup::parse` still rejects ABI 1.4.

use super::wire::{StartupDescriptor, StartupReference};
use crate::{
    ABI_MAJOR, KEX_IMAGE_ALIGNMENT, KEX_MAX_IMAGE_SPAN_BYTES, KEX_MIN_IMAGE_BASE, KEX_USER_END,
    STARTUP_HANDLE_BYTES, STARTUP_PAGE_BYTES, Startup, StartupError, interface, read_u16, read_u32,
    read_u64,
};

fn range(start: u64, bytes: u64) -> Result<(u64, u64), StartupError> {
    let end = start.checked_add(bytes).ok_or(StartupError::InvalidPage)?;
    if start < STARTUP_PAGE_BYTES as u64
        || end > KEX_USER_END
        || !start.is_multiple_of(STARTUP_PAGE_BYTES as u64)
        || !bytes.is_multiple_of(STARTUP_PAGE_BYTES as u64)
    {
        return Err(StartupError::InvalidPage);
    }
    Ok((start, end))
}

fn overlaps(a: (u64, u64), b: (u64, u64)) -> bool {
    a.0 < a.1 && b.0 < b.1 && a.0 < b.1 && b.0 < a.1
}

pub(super) fn parse(
    bytes: &[u8],
    address: u64,
    descriptor: StartupDescriptor,
) -> Result<Startup<'_>, StartupError> {
    descriptor.encode().map_err(|_| StartupError::InvalidPage)?;
    if bytes.len() != STARTUP_PAGE_BYTES
        || address != descriptor.process_startup
        || read_u16(bytes, 4)? != ABI_MAJOR
        || read_u16(bytes, 6)? != troe_abi::startup::THREAD_ABI_MINOR
        || read_u32(bytes, 8)? != 4096
        || read_u16(bytes, 12)? != 0
        || read_u64(bytes, 56)? == 0
    {
        return Err(StartupError::InvalidPage);
    }
    let header_bytes = troe_abi::startup::THREAD_HEADER_BYTES;
    let handle_count = usize::from(read_u16(bytes, 14)?);
    let encoded = header_bytes + handle_count * STARTUP_HANDLE_BYTES;
    if encoded > bytes.len()
        || read_u32(bytes, 0)? as usize != encoded
        || bytes[encoded..].iter().any(|&byte| byte != 0)
    {
        return Err(StartupError::InvalidPage);
    }
    let image = read_u64(bytes, 16)?;
    let span = address
        .checked_sub(image)
        .ok_or(StartupError::InvalidPage)?;
    let heap = range(read_u64(bytes, 24)?, read_u64(bytes, 32)?)?;
    if image < KEX_MIN_IMAGE_BASE
        || !image.is_multiple_of(KEX_IMAGE_ALIGNMENT)
        || span == 0
        || span > KEX_MAX_IMAGE_SPAN_BYTES
        || !span.is_multiple_of(KEX_IMAGE_ALIGNMENT)
        || heap.0 != address + STARTUP_PAGE_BYTES as u64
        || (!descriptor.initial && !(image..address).contains(&descriptor.entry))
    {
        return Err(StartupError::InvalidPage);
    }
    let stack_bottom = read_u64(bytes, 40)?;
    let stack_top = read_u64(bytes, 48)?;
    let stack_bytes = stack_top
        .checked_sub(stack_bottom)
        .filter(|&bytes| bytes != 0)
        .ok_or(StartupError::InvalidPage)?;
    let initial_stack = range(
        stack_bottom
            .checked_sub(4096)
            .ok_or(StartupError::InvalidPage)?,
        stack_bytes
            .checked_add(8192)
            .ok_or(StartupError::InvalidPage)?,
    )?;
    let tx = read_u64(bytes, 64)?;
    let initial_ipc = range(tx, 8192)?;
    let reference =
        StartupReference::decode(&bytes[80..96]).map_err(|_| StartupError::InvalidPage)?;
    if read_u64(bytes, 72)? != tx + 4096
        || (descriptor.initial
            && (stack_bottom != descriptor.stack_bottom
                || stack_top != descriptor.stack_top
                || tx != descriptor.ipc_tx
                || reference.address != descriptor.address))
    {
        return Err(StartupError::InvalidPage);
    }
    // These are numerical header checks only. A worker must never dereference
    // the initial descriptor/stack: its owner may already have been retired.
    let initial_ranges = [
        (image, heap.1),
        initial_stack,
        initial_ipc,
        range(reference.address, 4096)?,
    ];
    for (index, &region) in initial_ranges.iter().enumerate() {
        if initial_ranges[..index]
            .iter()
            .any(|&prior| overlaps(region, prior))
        {
            return Err(StartupError::InvalidPage);
        }
    }
    let shared = (image, heap.1);
    for region in [
        (descriptor.stack_bottom - 4096, descriptor.stack_top + 4096),
        (
            descriptor.tls_base,
            descriptor.tls_base + descriptor.tls_bytes,
        ),
        (descriptor.ipc_tx, descriptor.ipc_tx + 8192),
        (descriptor.address, descriptor.address + 4096),
    ] {
        if overlaps(shared, region) {
            return Err(StartupError::InvalidPage);
        }
    }
    let startup = Startup {
        bytes,
        handle_count,
        header_bytes,
    };
    validate_handles(&startup)?;
    Ok(startup)
}

fn validate_handles(startup: &Startup<'_>) -> Result<(), StartupError> {
    for index in 0..startup.handle_count {
        let handle = startup.descriptor(index)?;
        if handle.value == 0
            || handle.rights == 0
            || handle.rights & !u32::from(interface::allowed_rights(handle.interface)) != 0
            || startup
                .descriptors_before(index)
                .any(|prior| prior.is_ok_and(|prior| prior.value == handle.value))
        {
            return Err(StartupError::InvalidHandle);
        }
    }
    Ok(())
}
