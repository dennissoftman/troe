use super::*;
use crate::{interface, startup};

fn id(kind: Kind) -> Token {
    Token::new(kind, 7, 3).unwrap_or_else(|_| unreachable!())
}
fn encoded(request: Request) -> [u8; REQUEST_BYTES] {
    request.encode().unwrap_or_else(|_| unreachable!())
}
fn descriptor() -> StartupDescriptor {
    StartupDescriptor {
        thread: id(Kind::Thread),
        process_startup: 0x1000,
        stack_bottom: 0x4000,
        stack_top: 0x8000,
        tls_base: 0x9000,
        tls_bytes: 0x1000,
        thread_pointer: 0x9000,
        ipc_tx: 0xa000,
        entry: 0x10000,
        argument: u64::MAX,
        initial: false,
        address: 0xc000,
    }
}
fn requests() -> [Request; 22] {
    let t = id(Kind::Thread);
    let m = id(Kind::Mutex);
    let c = id(Kind::Condition);
    let p = id(Kind::Permit);
    let wait = Wait {
        deadline: Some(u64::MAX),
        observe_stop: true,
    };
    [
        Request::Prepare {
            entry_offset: 0,
            argument: u64::MAX,
            stack_pages: 1 << 32,
        },
        Request::Start(t),
        Request::Abort(t),
        Request::Join {
            thread: t,
            wait: WaitMode::Wait(wait),
        },
        Request::Detach(t),
        Request::RequestStop(t),
        Request::Observe(t),
        Request::Current,
        Request::Exit(u64::MAX),
        Request::Sleep(wait),
        Request::CreateMutex(OwnerDeath::FailProcess),
        Request::CreateCondition,
        Request::CreatePermit {
            count: u32::MAX,
            maximum: u32::MAX,
        },
        Request::Lock {
            mutex: m,
            wait: WaitMode::Try,
        },
        Request::Unlock(m),
        Request::ConditionWait {
            condition: c,
            mutex: m,
            wait,
        },
        Request::Notify {
            condition: c,
            all: true,
        },
        Request::AcquirePermit {
            permit: p,
            wait: WaitMode::Wait(Wait::default()),
        },
        Request::ReleasePermit {
            permit: p,
            count: 1,
        },
        Request::DestroyMutex(m),
        Request::DestroyCondition(c),
        Request::DestroyPermit(p),
    ]
}

#[test]
fn token_boundaries_are_typed_and_do_not_truncate() {
    for kind in [Kind::Thread, Kind::Mutex, Kind::Condition, Kind::Permit] {
        for slot in [0, 7, 0x00ff_fffe] {
            for generation in [1, 3, u32::MAX] {
                let t = Token::new(kind, slot, generation).unwrap_or_else(|_| unreachable!());
                assert_eq!(Token::decode(t.bits()), Ok(t));
                assert_eq!(
                    (t.kind(), t.slot(), t.generation()),
                    (kind, slot, generation)
                );
            }
        }
        assert!(Token::new(kind, 0x00ff_ffff, 1).is_err());
        assert!(Token::new(kind, u32::MAX, 1).is_err());
        assert!(Token::new(kind, 0, 0).is_err());
    }
    for invalid in [0, 1, 0x1_0100_0000, 0x1_0000_0001, 0x1_0500_0001, u64::MAX] {
        assert!(Token::decode(invalid).is_err());
    }
    assert_eq!(id(Kind::Mutex).bits(), 0x0000_0003_0200_0008);
}

#[test]
fn call_frame_rejects_extra_registers_and_size_truncation() {
    for completion in [Completion::Response, Completion::Rejected] {
        assert_eq!(Completion::decode(completion.encode()), Some(completion));
    }
    for words in [[0, 0], [1, 32], [2, 0], [1 << 32, 32], [0, 32 + (1 << 32)]] {
        assert_eq!(Completion::decode(words), None);
    }
    let call = Call { handle: u64::MAX };
    let words = call.encode().unwrap_or_else(|_| unreachable!());
    assert_eq!(words, [u64::MAX, 64, 32, 0, 0, 0]);
    assert_eq!(Call::decode(words), Some(call));
    for index in 0..6 {
        let mut bad = words;
        bad[index] = if index == 0 {
            0
        } else {
            words[index] + (1 << 32)
        };
        assert_eq!(Call::decode(bad), None);
    }
    assert!(Call { handle: 0 }.encode().is_err());
}

#[test]
fn wire_golden_vector_has_no_native_layout_or_host_endianness() {
    let request = Request::Join {
        thread: id(Kind::Thread),
        wait: WaitMode::Wait(Wait {
            deadline: Some(0),
            observe_stop: true,
        }),
    };
    let bytes = encoded(request);
    assert_eq!(
        &bytes[..16],
        &[1, 0, 4, 0, 30, 0, 0, 0, 8, 0, 0, 1, 3, 0, 0, 0]
    );
    assert_eq!(&bytes[16..24], &[2, 1, 0, 0, 0, 0, 0, 0]);
    assert_eq!(&bytes[24..], &[0; 40]);
    assert_eq!(
        Request::decode(interface::THREAD_CONTROL, &bytes),
        Ok(request)
    );
    assert!(Request::decode(interface::THREAD_SYNC, &bytes).is_err());
}

#[test]
fn wait_flags_do_not_alias_try_infinite_zero_or_maximum_deadlines() {
    for stop in [false, true] {
        for deadline in [None, Some(0), Some(1), Some(u64::MAX)] {
            let wait = WaitMode::Wait(Wait {
                deadline,
                observe_stop: stop,
            });
            let (flags, value) = wait.words();
            assert_eq!(WaitMode::decode(flags, value), Ok(wait));
        }
    }
    for (flags, deadline) in [(0, 1), (0x100, 0), (1, 1), (3, 0), (0x103, 0), (1 << 32, 0)] {
        assert!(WaitMode::decode(flags, deadline).is_err());
    }
    let mut condition = encoded(requests()[15]);
    condition[24..40].fill(0);
    assert!(Request::decode(interface::THREAD_SYNC, &condition).is_err());
}

#[test]
fn every_operation_enforces_closed_header_tail_and_token_kinds() {
    for request in requests() {
        let bytes = encoded(request);
        assert_eq!(Request::decode(request.interface(), &bytes), Ok(request));
        for length in 0..REQUEST_BYTES {
            assert!(Request::decode(request.interface(), &bytes[..length]).is_err());
        }
        let mut oversized = [0; REQUEST_BYTES + 1];
        oversized[..REQUEST_BYTES].copy_from_slice(&bytes);
        assert!(Request::decode(request.interface(), &oversized).is_err());
        for offset in [0, 1, 3, 4, 5, 6, 7, 40, 48, 56, 63] {
            let mut bad = bytes;
            bad[offset] ^= 0x80;
            assert!(
                Request::decode(request.interface(), &bad).is_err(),
                "{request:?} offset {offset}"
            );
        }
        assert_eq!(
            request.required_rights() & !interface::allowed_rights(request.interface()),
            0
        );
    }
    assert!(
        Request::Lock {
            mutex: id(Kind::Permit),
            wait: WaitMode::Try
        }
        .encode()
        .is_err()
    );
    assert!(
        Request::Join {
            thread: id(Kind::Mutex),
            wait: WaitMode::Try
        }
        .encode()
        .is_err()
    );
    for (count, maximum) in [(0, 0), (2, 1)] {
        assert!(Request::CreatePermit { count, maximum }.encode().is_err());
    }
    for (entry_offset, stack_pages) in [(1 << 30, 1), (0, 0), (0, (1 << 32) + 1)] {
        assert!(
            Request::Prepare {
                entry_offset,
                argument: 0,
                stack_pages
            }
            .encode()
            .is_err()
        );
    }
    let mut permit = encoded(Request::CreatePermit {
        count: 0,
        maximum: 1,
    });
    permit[20] = 1; // high half of maximum, never truncated to u32
    assert!(Request::decode(interface::THREAD_SYNC, &permit).is_err());
}

#[test]
fn response_correlation_and_wait_outcomes_preserve_ownership_contract() {
    let condition = requests()[15];
    for outcome in [
        Outcome::Success,
        Outcome::TimedOut,
        Outcome::Stopped,
        Outcome::Poisoned,
    ] {
        let response = Response {
            outcome,
            value: 0,
            snapshot: None,
        };
        let bytes = response
            .encode(condition)
            .unwrap_or_else(|_| unreachable!());
        assert_eq!(Response::decode(condition, &bytes), Ok(response));
        assert!(Response::decode(requests()[13], &bytes).is_err());
        for offset in [0, 4, 6, 9, 10, 11, 12, 15, 16, 24, 31] {
            let mut bad = bytes;
            bad[offset] ^= 0x80;
            assert!(Response::decode(condition, &bad).is_err());
        }
        for length in 0..RESPONSE_BYTES {
            assert!(Response::decode(condition, &bytes[..length]).is_err());
        }
    }
    let make = |outcome| Response {
        outcome,
        value: 0,
        snapshot: None,
    };
    assert!(make(Outcome::WouldBlock).encode(condition).is_err());
    assert!(make(Outcome::TimedOut).encode(requests()[13]).is_err());
    assert!(make(Outcome::Stopped).encode(requests()[17]).is_err());
    assert!(make(Outcome::Poisoned).encode(requests()[17]).is_err());
    assert!(make(Outcome::Success).encode(Request::Exit(0)).is_err());
    assert!(make(Outcome::NotOwner).encode(Request::Current).is_err());
    assert!(make(Outcome::Overflow).encode(condition).is_err());
    let joined = Response {
        outcome: Outcome::Success,
        value: u64::MAX,
        snapshot: None,
    };
    assert!(joined.encode(requests()[3]).is_ok());
    assert!(
        Response {
            outcome: Outcome::TimedOut,
            ..joined
        }
        .encode(requests()[3])
        .is_err()
    );
}

#[test]
fn successful_creation_and_observation_cannot_forge_payload_shape() {
    for (request, kind) in [
        (Request::Current, Kind::Thread),
        (requests()[0], Kind::Thread),
        (requests()[10], Kind::Mutex),
        (Request::CreateCondition, Kind::Condition),
        (requests()[12], Kind::Permit),
    ] {
        for candidate in [Kind::Thread, Kind::Mutex, Kind::Condition, Kind::Permit] {
            let response = Response {
                outcome: Outcome::Success,
                value: id(candidate).bits(),
                snapshot: None,
            };
            assert_eq!(response.encode(request).is_ok(), candidate == kind);
        }
    }
    let snapshot = Snapshot {
        state: State::Completed,
        stop_requested: true,
        detached: false,
        resources_released: true,
    };
    let response = Response {
        outcome: Outcome::Success,
        value: 0,
        snapshot: Some(snapshot),
    };
    let observe = Request::Observe(id(Kind::Thread));
    let bytes = response.encode(observe).unwrap_or_else(|_| unreachable!());
    assert_eq!(Response::decode(observe, &bytes), Ok(response));
    assert!(response.encode(Request::Current).is_err());
    assert!(
        Response {
            snapshot: None,
            ..response
        }
        .encode(observe)
        .is_err()
    );
    assert!(
        Response {
            snapshot: Some(Snapshot {
                state: State::Running,
                ..snapshot
            }),
            ..response
        }
        .encode(observe)
        .is_err()
    );
}

#[test]
fn startup_is_versioned_and_old_active_abi_does_not_move() {
    assert_eq!(crate::ABI_MINOR, 3);
    for (minor, bytes, capacity) in [
        (0, 64, 168),
        (1, 64, 168),
        (2, 64, 168),
        (3, 80, 167),
        (4, 96, 166),
    ] {
        assert_eq!(startup::header_bytes(minor), bytes);
        assert_eq!(startup::max_initial_handles(minor), capacity);
    }
    let reference = StartupReference { address: 0xc000 };
    let bytes = reference.encode().unwrap_or_else(|_| unreachable!());
    assert_eq!(&bytes[..8], &[0, 0xc0, 0, 0, 0, 0, 0, 0]);
    assert_eq!(&bytes[8..], &[128, 0, 0, 0, 0, 0, 0, 0]);
    assert_eq!(StartupReference::decode(&bytes), Ok(reference));
    for address in [0, 1, USER_END, u64::MAX] {
        assert!(StartupReference { address }.encode().is_err());
    }
}

#[test]
fn startup_rejects_aliases_guards_wraparound_and_nonzero_slack() {
    let description = descriptor();
    let bytes = description.encode().unwrap_or_else(|_| unreachable!());
    assert_eq!(StartupDescriptor::decode(&bytes), Ok(description));
    let mut page = [0; 4096];
    page[..STARTUP_BYTES].copy_from_slice(&bytes);
    assert_eq!(StartupDescriptor::decode_page(&page), Ok(description));
    for offset in [STARTUP_BYTES, 4095] {
        page[offset] = 1;
        assert!(StartupDescriptor::decode_page(&page).is_err());
        page[offset] = 0;
    }
    for length in 0..STARTUP_BYTES {
        assert!(StartupDescriptor::decode(&bytes[..length]).is_err());
    }
    for offset in [0, 8, 10, 12, 32, 88, 112, 116] {
        let mut bad = bytes;
        bad[offset] ^= 0x80;
        assert!(StartupDescriptor::decode(&bad).is_err());
    }
    for address in [
        0,
        1,
        0x1000,
        0x3000,
        0x4000,
        0x8000,
        0x9000,
        0xa000,
        0xb000,
        USER_END,
        u64::MAX,
    ] {
        assert!(
            StartupDescriptor {
                address,
                ..description
            }
            .encode()
            .is_err(),
            "{address:x}"
        );
    }
    for bad in [
        StartupDescriptor {
            stack_top: 0,
            ..description
        },
        StartupDescriptor {
            tls_bytes: u64::MAX,
            ..description
        },
        StartupDescriptor {
            thread_pointer: 0xa000,
            ..description
        },
        StartupDescriptor {
            thread_pointer: 0x9001,
            ..description
        },
        StartupDescriptor {
            initial: true,
            ..description
        },
        StartupDescriptor {
            entry: 0xa000,
            ..description
        },
    ] {
        assert!(bad.encode().is_err());
    }
    let initial = StartupDescriptor {
        initial: true,
        entry: 0,
        argument: 0,
        ..description
    };
    assert!(initial.encode().is_ok());
}

#[test]
fn adversarial_bit_mutations_are_rejected_or_canonical_without_panics() {
    for request in requests() {
        let bytes = encoded(request);
        for bit in 0..REQUEST_BYTES * 8 {
            let mut changed = bytes;
            changed[bit / 8] ^= 1 << (bit % 8);
            if let Ok(decoded) = Request::decode(request.interface(), &changed) {
                assert_eq!(decoded.encode(), Ok(changed));
            }
        }
    }
    let bytes = descriptor().encode().unwrap_or_else(|_| unreachable!());
    for bit in 0..STARTUP_BYTES * 8 {
        let mut changed = bytes;
        changed[bit / 8] ^= 1 << (bit % 8);
        if let Ok(decoded) = StartupDescriptor::decode(&changed) {
            assert_eq!(decoded.encode(), Ok(changed));
        }
    }
}
