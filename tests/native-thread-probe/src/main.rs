#![no_std]
#![no_main]

use core::sync::atomic::{AtomicU64, Ordering};
use troe_kex_sdk::{
    self as sdk, threaded_entry,
    threading::{self, Initial, wire},
};

static TIMER: AtomicU64 = AtomicU64::new(0);
static PIPE: AtomicU64 = AtomicU64::new(0);
static PIPE_TOKEN: AtomicU64 = AtomicU64::new(0);
static CONSUMED: AtomicU64 = AtomicU64::new(0);

unsafe extern "C" {
    fn troe_native_canary(advance: i32) -> i32;
}

macro_rules! check {
    ($condition:expr) => {
        if !$condition {
            sdk::terminate(line!());
        }
    };
}

fn operation(request: wire::Request, expected: wire::Outcome) -> u64 {
    // SAFETY: Prepared entries below use worker's declared ABI and scalar args.
    // No operation exits while holding user resources or a runtime loan.
    let Ok(response) = (unsafe { threading::call(request) }) else {
        sdk::terminate(line!());
    };
    check!(response.outcome == expected);
    response.value
}

fn success(request: wire::Request) -> u64 {
    operation(request, wire::Outcome::Success)
}

fn token(bits: u64) -> wire::Token {
    wire::Token::decode(bits).unwrap_or_else(|_| sdk::terminate(line!()))
}

fn service(handle: u64, opcode: u16, payload: &[u8], expected: usize) -> u64 {
    let mut reply = [0xa5; 32];
    let capacity = if expected == 0 { 0 } else { reply.len() };
    // SAFETY: Only the timer/pipe operations below are sent; their scalar
    // requests carry no user-memory or executable ownership.
    let Ok(count) =
        (unsafe { threading::service_call(handle, opcode, payload, &mut reply[..capacity]) })
    else {
        sdk::terminate(line!());
    };
    check!(count == expected && reply[count..].iter().all(|&byte| byte == 0xa5));
    let mut value = [0_u8; 8];
    value[..count.min(8)].copy_from_slice(&reply[..count.min(8)]);
    u64::from_le_bytes(value)
}

fn sleep(milliseconds: u64) {
    let timer = TIMER.load(Ordering::Acquire);
    let deadline = service(timer, sdk::timer::NOW, &[], 8) + milliseconds;
    service(timer, sdk::timer::SLEEP_UNTIL, &deadline.to_le_bytes(), 0);
    check!(service(timer, sdk::timer::NOW, &[], 8) >= deadline);
}

unsafe extern "C" fn worker(argument: u64) -> u64 {
    check!(argument == 0x55 || argument == 0x56);
    // SAFETY: The separately compiled canary owns only this thread's C TLS.
    check!(unsafe { troe_native_canary(1) } == 0);
    let current = success(wire::Request::Current);
    check!(sdk::yield_now().is_ok());
    check!(success(wire::Request::Current) == current);
    sleep(5);
    let mut read = [0_u8; 16];
    read[..8].copy_from_slice(&PIPE_TOKEN.load(Ordering::Acquire).to_le_bytes());
    read[8..].copy_from_slice(&1_u64.to_le_bytes());
    let byte = service(PIPE.load(Ordering::Acquire), sdk::pipe::READ, &read, 1);
    check!(byte == 0xa1 || byte == 0xa2);
    let bit = 1 << (byte - 0xa1);
    check!(CONSUMED.fetch_or(bit, Ordering::AcqRel) & bit == 0);
    // SAFETY: The canary checks its own unchanged TLS after sibling execution.
    check!(unsafe { troe_native_canary(0) } == 0);
    0x7788 + argument - 0x55
}

fn main(initial: Initial) -> u32 {
    TIMER.store(
        initial
            .handle(sdk::interface::TIMER, 1, 1)
            .unwrap_or_else(|_| sdk::terminate(line!())),
        Ordering::Release,
    );
    PIPE.store(
        initial
            .handle(sdk::interface::PIPE, 1, 0)
            .unwrap_or_else(|_| sdk::terminate(line!())),
        Ordering::Release,
    );
    // SAFETY: The canary accesses only this initial thread's compiler TLS.
    check!(unsafe { troe_native_canary(1) } == 0);
    let caller = success(wire::Request::Current);
    let entry = (worker as *const () as u64)
        .checked_sub(initial.image_base())
        .unwrap_or_else(|| sdk::terminate(line!()));
    let prepared = |argument| {
        token(success(wire::Request::Prepare {
            entry_offset: entry,
            argument,
            stack_pages: 8,
        }))
    };
    let aborted = prepared(0x55);
    success(wire::Request::Abort(aborted));
    let child = prepared(0x55);
    let sibling = prepared(0x56);
    check!(child != aborted);
    let pipe = service(
        PIPE.load(Ordering::Acquire),
        sdk::pipe::CREATE,
        &4096_u32.to_le_bytes(),
        8,
    );
    PIPE_TOKEN.store(pipe, Ordering::Release);
    success(wire::Request::Start(child));
    success(wire::Request::Start(sibling));
    sleep(50);
    check!(CONSUMED.load(Ordering::Acquire) == 0);
    let mut write = [0_u8; 9];
    write[..8].copy_from_slice(&pipe.to_le_bytes());
    write[8] = 0xa1;
    service(PIPE.load(Ordering::Acquire), sdk::pipe::WRITE, &write, 0);
    sleep(50);
    check!(CONSUMED.load(Ordering::Acquire) == 1);
    write[8] = 0xa2;
    service(PIPE.load(Ordering::Acquire), sdk::pipe::WRITE, &write, 0);
    let wait = wire::WaitMode::Wait(wire::Wait::default());
    check!(
        success(wire::Request::Join {
            thread: child,
            wait
        }) == 0x7788
    );
    check!(
        success(wire::Request::Join {
            thread: sibling,
            wait
        }) == 0x7789
    );
    service(
        PIPE.load(Ordering::Acquire),
        sdk::pipe::CLOSE_READER,
        &pipe.to_le_bytes(),
        0,
    );
    service(
        PIPE.load(Ordering::Acquire),
        sdk::pipe::CLOSE_WRITER,
        &pipe.to_le_bytes(),
        0,
    );
    check!(CONSUMED.load(Ordering::Acquire) == 3 && success(wire::Request::Current) == caller);
    // SAFETY: The initial thread retains its own live compiler-TLS canary.
    check!(unsafe { troe_native_canary(0) } == 0);
    let mutex = token(success(wire::Request::CreateMutex(
        wire::OwnerDeath::Poison,
    )));
    success(wire::Request::Lock { mutex, wait });
    success(wire::Request::Unlock(mutex));
    success(wire::Request::DestroyMutex(mutex));
    let mut unchanged = [0xa5_u8; 8];
    // SAFETY: A zero handle has no authority and cannot execute a service.
    check!(unsafe { threading::service_call(0, 0, &[], &mut unchanged) }.is_err());
    check!(unchanged == [0xa5; 8]);
    0
}

threaded_entry!(main);
