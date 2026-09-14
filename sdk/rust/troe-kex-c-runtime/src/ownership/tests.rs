#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

extern crate std;

use super::*;
use std::{sync::Arc, thread, vec::Vec};

#[test]
fn blocked_operations_release_metadata_but_exclude_same_resource_and_reuse() {
    let table = Slots::<u64, 2>::new();
    let mut first = table.reserve().unwrap();
    let first_token = first.token();
    first.value = Some(17);
    assert_eq!(table.acquire(first_token).err(), Some(errno::EBUSY));

    // Model another callback while the first open is waiting in a service.
    let mut second = table.reserve().unwrap();
    let second_token = second.token();
    second.value = Some(29);
    assert_eq!(table.reserve().err(), Some(errno::ENOMEM));
    drop(second);
    let mut second = table.acquire(second_token).unwrap();
    second.value = Some(31);
    drop(second);
    drop(first);

    let mut read = table.acquire(first_token).unwrap();
    assert_eq!(read.value, Some(17));
    assert_eq!(table.acquire(first_token).err(), Some(errno::EBUSY));
    assert_eq!(table.acquire(second_token).unwrap().value, Some(31));

    // A close moves the resource into its service request, but still reserves
    // the slot until that request returns. A new open cannot reuse it early.
    assert_eq!(read.value.take(), Some(17));
    assert_eq!(table.reserve().err(), Some(errno::ENOMEM));
    drop(read);
    assert_eq!(table.acquire(first_token).err(), Some(errno::EINVAL));
    let mut reopened = table.reserve().unwrap();
    assert_ne!(reopened.token(), first_token);
    assert_eq!(table.acquire(first_token).err(), Some(errno::EINVAL));
    reopened.value = Some(53);
}

#[test]
fn failed_open_spends_generation_and_failed_operation_retains_owned_progress() {
    let table = Slots::<u64, 1>::new();
    let failed = table.reserve().unwrap();
    let failed_token = failed.token();
    drop(failed);
    let mut opened = table.reserve().unwrap();
    let token = opened.token();
    assert_ne!(token, failed_token);
    opened.value = Some(0);
    drop(opened);

    let failure = (|| -> Result<(), i32> {
        let mut append = table.acquire(token)?;
        // One completed chunk, then an error: the original owner and its
        // completed progress must survive the early return.
        append.value = Some(4096);
        Err(errno::EIO)
    })();
    assert_eq!(failure, Err(errno::EIO));
    assert_eq!(table.acquire(token).unwrap().value, Some(4096));
    assert_eq!(table.acquire(failed_token).err(), Some(errno::EINVAL));
}

#[test]
fn malformed_tokens_and_generation_exhaustion_never_alias_live_resources() {
    let table = Slots::<u64, 1>::new();
    for token in [0, 1, 31, 33, u32::MAX] {
        assert_eq!(table.acquire(token).err(), Some(errno::EINVAL));
    }
    table
        .slots
        .with(|slots| slots[0].generation = MAX_GENERATION - 1);
    let mut final_lifetime = table.reserve().unwrap();
    let token = final_lifetime.token();
    assert_eq!(token >> INDEX_BITS, MAX_GENERATION);
    final_lifetime.value = Some(7);
    drop(final_lifetime);
    let mut close = table.acquire(token).unwrap();
    assert_eq!(close.value.take(), Some(7));
    drop(close);
    assert_eq!(table.reserve().err(), Some(errno::ENOMEM));
    assert_eq!(table.acquire(token).err(), Some(errno::EINVAL));
}

#[test]
fn simultaneous_callbacks_keep_values_and_tokens_independent() {
    let table = Arc::new(Slots::<u64, 32>::new());
    let mut tokens = Vec::new();
    for initial in 0..8 {
        let mut opened = table.reserve().unwrap();
        tokens.push(opened.token());
        opened.value = Some(initial);
    }
    let barrier = Arc::new(std::sync::Barrier::new(tokens.len()));
    let workers: Vec<_> = tokens
        .iter()
        .map(|&token| {
            let table = table.clone();
            let barrier = barrier.clone();
            thread::spawn(move || {
                let mut operation = table.acquire(token).unwrap();
                // Every worker must acquire its own resource before any returns.
                // A lock retained across the operation would deadlock here.
                barrier.wait();
                *operation.value.as_mut().unwrap() += 100;
                drop(operation);
                for _ in 0..1000 {
                    let mut operation = table.acquire(token).unwrap();
                    *operation.value.as_mut().unwrap() += 1;
                    thread::yield_now();
                }
            })
        })
        .collect();
    for worker in workers {
        worker.join().unwrap();
    }
    for (initial, token) in tokens.into_iter().enumerate() {
        assert_eq!(
            table.acquire(token).unwrap().value,
            Some(initial as u64 + 1100)
        );
    }
}

#[test]
fn mutable_state_loans_are_exclusive_across_host_threads() {
    let state = Arc::new(Locked::new(0_u64));
    let workers: Vec<_> = (0..8)
        .map(|_| {
            let state = state.clone();
            thread::spawn(move || {
                for _ in 0..1000 {
                    state.with(|value| *value += 1);
                }
            })
        })
        .collect();
    for worker in workers {
        worker.join().unwrap();
    }
    assert_eq!(state.with(|value| *value), 8000);
}
