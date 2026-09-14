#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use super::*;

const IMAGE: u64 = 0x4000_0000_0000;
const PAGE: u64 = IMAGE + 2 * 1024 * 1024;

fn put(page: &mut [u8], offset: usize, value: u64) {
    page[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

fn fixture() -> ([u8; 4096], wire::StartupDescriptor) {
    let descriptor = wire::StartupDescriptor {
        thread: wire::Token::new(wire::Kind::Thread, 0, 1).unwrap(),
        process_startup: PAGE,
        stack_bottom: 0x6000_0000_1000,
        stack_top: 0x6000_0000_5000,
        tls_base: 0x6000_0000_6000,
        tls_bytes: 4096,
        thread_pointer: 0x6000_0000_6080,
        ipc_tx: 0x6000_0000_7000,
        address: 0x6000_0000_9000,
        entry: 0,
        argument: 0,
        initial: true,
    };
    let interfaces = [
        interface::COMMAND,
        interface::STANDARD_INPUT,
        interface::STANDARD_OUTPUT,
        interface::STANDARD_ERROR,
        interface::THREAD_CONTROL,
        interface::THREAD_SYNC,
    ];
    let mut page = [0_u8; 4096];
    page[..4]
        .copy_from_slice(&(96_u32 + 24 * u32::try_from(interfaces.len()).unwrap()).to_le_bytes());
    page[4..6].copy_from_slice(&1_u16.to_le_bytes());
    page[6..8].copy_from_slice(&4_u16.to_le_bytes());
    page[8..12].copy_from_slice(&4096_u32.to_le_bytes());
    page[14..16].copy_from_slice(&(u16::try_from(interfaces.len()).unwrap()).to_le_bytes());
    for (offset, value) in [
        (16, IMAGE),
        (24, PAGE + 4096),
        (32, 8192),
        (40, descriptor.stack_bottom),
        (48, descriptor.stack_top),
        (56, 123),
        (64, descriptor.ipc_tx),
        (72, descriptor.ipc_tx + 4096),
        (80, descriptor.address),
        (88, 128),
    ] {
        put(&mut page, offset, value);
    }
    for (index, interface) in interfaces.into_iter().enumerate() {
        let offset = 96 + 24 * index;
        put(&mut page, offset, index as u64 + 1);
        page[offset + 8..offset + 12].copy_from_slice(&1_u32.to_le_bytes());
        page[offset + 12..offset + 16].copy_from_slice(&interface.to_le_bytes());
        page[offset + 16..offset + 18].copy_from_slice(&1_u16.to_le_bytes());
        let minor = match interface {
            interface::COMMAND => crate::command::MINOR,
            interface::STANDARD_INPUT | interface::STANDARD_OUTPUT | interface::STANDARD_ERROR => {
                troe_abi::stream::MINOR
            }
            _ => 0,
        };
        page[offset + 18..offset + 20].copy_from_slice(&minor.to_le_bytes());
    }
    (page, descriptor)
}

#[test]
fn explicit_profile_owns_no_second_ipc_token_and_legacy_still_rejects_it() {
    let (page, descriptor) = fixture();
    assert!(Startup::parse(&page).is_err());
    let startup = startup::parse(&page, PAGE, descriptor).unwrap();
    assert!(startup.ipc_pages().unwrap().is_none());
    let mut command = CommandContext::from_startup(&startup).unwrap();
    assert!(command.take_ipc().is_none());
    let heap = command.take_heap().unwrap();
    assert_eq!(heap.start_address(), usize::try_from(PAGE + 4096).unwrap());
    assert_eq!(heap.byte_len(), 8192);
    assert!(command.take_heap().is_none());
}

#[test]
fn workers_validate_without_reading_a_retired_initial_descriptor_or_stack() {
    let (page, initial) = fixture();
    let mut worker = initial;
    worker.initial = false;
    worker.thread = wire::Token::new(wire::Kind::Thread, 1, 1).unwrap();
    worker.entry = IMAGE + 64;
    worker.argument = 99;
    for address in [
        &mut worker.stack_bottom,
        &mut worker.stack_top,
        &mut worker.tls_base,
        &mut worker.thread_pointer,
        &mut worker.ipc_tx,
        &mut worker.address,
    ] {
        *address += 0x10_0000;
    }
    // None of these numerical user addresses are mapped in this host test.
    assert!(startup::parse(&page, PAGE, worker).is_ok());
    // Reusing the former initial window with a new token is not a new initial
    // thread, and a stale header reference must not prohibit that reuse.
    let reused = wire::StartupDescriptor {
        initial: false,
        entry: IMAGE + 64,
        thread: wire::Token::new(wire::Kind::Thread, 0, 2).unwrap(),
        ..initial
    };
    assert!(startup::parse(&page, PAGE, reused).is_ok());
    worker.process_startup += 4096;
    assert!(startup::parse(&page, PAGE, worker).is_err());
}

#[test]
fn malformed_profiles_geometry_and_handle_incarnations_are_rejected() {
    let (page, descriptor) = fixture();
    for offset in [4, 6, 8, 12, 15, 4095, 96 + 20] {
        let mut bad = page;
        bad[offset] ^= 0xff;
        assert!(
            startup::parse(&bad, PAGE, descriptor).is_err(),
            "offset {offset}"
        );
    }
    for (offset, value) in [
        (16, 0),
        (24, PAGE + 12288),
        (32, u64::MAX),
        (40, 0),
        (48, descriptor.stack_bottom),
        (56, 0),
        (64, PAGE),
        (72, descriptor.ipc_tx),
        (80, 0),
        (88, 4096),
        (96, 0),
        (96 + 24, 1),
    ] {
        let mut bad = page;
        put(&mut bad, offset, value);
        assert!(
            startup::parse(&bad, PAGE, descriptor).is_err(),
            "offset {offset}"
        );
    }
    let mut bad = descriptor;
    bad.tls_base = IMAGE + 4096;
    bad.thread_pointer = bad.tls_base + 128;
    assert!(startup::parse(&page, PAGE, bad).is_err());
    let mut bad = page;
    bad[96 + 8..96 + 12].copy_from_slice(&0x8000_0001_u32.to_le_bytes());
    assert!(startup::parse(&bad, PAGE, descriptor).is_err());
}
