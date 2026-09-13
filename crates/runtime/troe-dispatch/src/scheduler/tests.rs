use super::SchedulerInterface;
use crate::{DispatchError, Dispatcher, HandleOwner, ReplyStatus, Rights, Service, ServiceReply};
use alloc::{boxed::Box, rc::Rc};
use core::cell::Cell;
use troe_abi::{
    interface,
    threading::{Kind, OwnerDeath, Request, Token, Wait, WaitMode},
};

const OWNER: HandleOwner = HandleOwner::IsolatedTask(7);
const FOREIGN: HandleOwner = HandleOwner::IsolatedTask(8);

struct Counter(Rc<Cell<u32>>);
impl Service for Counter {
    fn call(&mut self, _: crate::Request<'_>) -> Result<ServiceReply, DispatchError> {
        self.0.set(self.0.get() + 1);
        Ok(ServiceReply::empty(ReplyStatus::Success))
    }
}

fn encode(request: Request) -> [u8; 64] {
    request.encode().unwrap_or_else(|_| unreachable!())
}

fn operations() -> [(Request, Rights); 22] {
    let token = |kind| Token::new(kind, 0, 1).unwrap_or_else(|_| unreachable!());
    let thread = token(Kind::Thread);
    let mutex = token(Kind::Mutex);
    let condition = token(Kind::Condition);
    let permit = token(Kind::Permit);
    let wait = Wait {
        deadline: Some(17),
        observe_stop: true,
    };
    [
        (
            Request::Prepare {
                entry_offset: 16,
                argument: u64::MAX,
                stack_pages: 4,
            },
            Rights::THREAD_CREATE,
        ),
        (Request::Start(thread), Rights::THREAD_START),
        (Request::Abort(thread), Rights::THREAD_START),
        (
            Request::Join {
                thread,
                wait: WaitMode::Wait(wait),
            },
            Rights::THREAD_JOIN,
        ),
        (Request::Detach(thread), Rights::THREAD_DETACH),
        (Request::RequestStop(thread), Rights::THREAD_STOP),
        (Request::Observe(thread), Rights::THREAD_OBSERVE),
        (Request::Current, Rights::THREAD_OBSERVE),
        (Request::Exit(19), Rights::NONE),
        (Request::Sleep(wait), Rights::NONE),
        (Request::CreateMutex(OwnerDeath::FailProcess), Rights::NONE),
        (Request::CreateCondition, Rights::NONE),
        (
            Request::CreatePermit {
                count: 0,
                maximum: 2,
            },
            Rights::NONE,
        ),
        (
            Request::Lock {
                mutex,
                wait: WaitMode::Try,
            },
            Rights::NONE,
        ),
        (Request::Unlock(mutex), Rights::NONE),
        (
            Request::ConditionWait {
                condition,
                mutex,
                wait,
            },
            Rights::NONE,
        ),
        (
            Request::Notify {
                condition,
                all: true,
            },
            Rights::NONE,
        ),
        (
            Request::AcquirePermit {
                permit,
                wait: WaitMode::Wait(wait),
            },
            Rights::NONE,
        ),
        (Request::ReleasePermit { permit, count: 1 }, Rights::NONE),
        (Request::DestroyMutex(mutex), Rights::NONE),
        (Request::DestroyCondition(condition), Rights::NONE),
        (Request::DestroyPermit(permit), Rights::NONE),
    ]
}

#[test]
fn every_operation_requires_call_and_its_independent_authority() -> Result<(), DispatchError> {
    for (request, operation_right) in operations() {
        let interface = if request.interface() == interface::THREAD_CONTROL {
            SchedulerInterface::ControlV1
        } else {
            SchedulerInterface::SyncV1
        };
        assert_eq!(interface.version(), (1, 0));
        let required = Rights::CALL.union(operation_right);
        let mut dispatcher = Dispatcher::new(1, 1)?;
        let handle = dispatcher.open_scheduler_owned(interface, required, OWNER)?;
        let before = dispatcher.stats();
        let admitted = dispatcher.authorize_scheduler_owned_abi(
            OWNER,
            handle.abi_value(),
            &encode(request),
        )?;
        assert_eq!((admitted.owner(), admitted.request()), (OWNER, request));
        assert_eq!(dispatcher.stats(), before);
        dispatcher.close(handle)?;

        for bit in 0..16 {
            let omitted = 1 << bit;
            if required.bits() & omitted == 0 {
                continue;
            }
            let rights = Rights::from_bits(required.bits() & !omitted)?;
            let limited = dispatcher.open_scheduler_owned(interface, rights, OWNER)?;
            let before = dispatcher.stats();
            assert_eq!(
                dispatcher.authorize_scheduler_owned_abi(
                    OWNER,
                    limited.abi_value(),
                    &encode(request)
                ),
                Err(DispatchError::PermissionDenied),
                "{request:?} missing {omitted:#x}"
            );
            assert_eq!(dispatcher.stats(), before);
            dispatcher.close(limited)?;
        }
    }
    Ok(())
}

#[test]
fn scheduler_and_service_targets_cannot_be_confused() -> Result<(), DispatchError> {
    let calls = Rc::new(Cell::new(0));
    let mut dispatcher = Dispatcher::new(1, 4)?;
    let (port, _) = dispatcher.register(Box::new(Counter(Rc::clone(&calls))), Rights::CALL)?;
    let service = dispatcher.open_owned(port, Rights::CALL.union(Rights::THREAD_OBSERVE), OWNER)?;
    for (interface, request) in [
        (SchedulerInterface::ControlV1, Request::Current),
        (SchedulerInterface::SyncV1, Request::CreateCondition),
    ] {
        let rights = Rights::from_bits(u32::from(interface::allowed_rights(interface.id())))?;
        let scheduler = dispatcher.open_scheduler_owned(interface, rights, OWNER)?;
        let before = dispatcher.stats();
        let bytes = encode(request);
        assert_eq!(
            dispatcher.authorize_scheduler_owned_abi(OWNER, service.abi_value(), &bytes),
            Err(DispatchError::InvalidHandle)
        );
        let mut destination = [0xa5; 64];
        assert_eq!(
            dispatcher.call_owned_abi(OWNER, scheduler.abi_value(), request.opcode(), &bytes),
            Err(DispatchError::InvalidHandle)
        );
        assert_eq!(
            dispatcher.call_owned_abi_into(
                OWNER,
                scheduler.abi_value(),
                request.opcode(),
                &bytes,
                &mut destination
            ),
            Err(DispatchError::InvalidHandle)
        );
        assert_eq!(destination, [0xa5; 64]);
        assert_eq!(dispatcher.stats(), before);
        assert_eq!(calls.get(), 0);
        dispatcher.close(scheduler)?;
    }
    assert_eq!(
        dispatcher
            .call_owned_abi(OWNER, service.abi_value(), 1, &[])?
            .request_id(),
        1
    );
    assert_eq!(calls.get(), 1);
    Ok(())
}

#[test]
fn owner_and_interface_checks_precede_admission_without_side_effects() -> Result<(), DispatchError>
{
    let mut dispatcher = Dispatcher::new(1, 1)?;
    let rights = Rights::CALL.union(Rights::THREAD_OBSERVE);
    for owner in [HandleOwner::Kernel, HandleOwner::IsolatedTask(0)] {
        assert_eq!(
            dispatcher.open_scheduler_owned(SchedulerInterface::ControlV1, rights, owner),
            Err(DispatchError::InvalidOwner)
        );
    }
    for (interface, invalid) in [
        (SchedulerInterface::ControlV1, Rights::READ),
        (SchedulerInterface::SyncV1, Rights::THREAD_CREATE),
    ] {
        assert_eq!(
            dispatcher.open_scheduler_owned(interface, invalid, OWNER),
            Err(DispatchError::InvalidRights)
        );
    }
    assert_eq!(dispatcher.stats().live_handles, 0);
    let handle = dispatcher.open_scheduler_owned(SchedulerInterface::ControlV1, rights, OWNER)?;
    let before = dispatcher.stats();
    let bytes = encode(Request::Current);
    for owner in [HandleOwner::Kernel, HandleOwner::IsolatedTask(0)] {
        assert_eq!(
            dispatcher.authorize_scheduler_owned_abi(owner, handle.abi_value(), &bytes),
            Err(DispatchError::InvalidOwner)
        );
    }
    assert_eq!(
        dispatcher.authorize_scheduler_owned_abi(FOREIGN, handle.abi_value(), &bytes),
        Err(DispatchError::InvalidHandle)
    );
    for value in [0, 1, 1 << 32, u64::MAX, handle.abi_value() ^ (1 << 63)] {
        assert_eq!(
            dispatcher.authorize_scheduler_owned_abi(OWNER, value, &bytes),
            Err(DispatchError::InvalidHandle)
        );
    }
    assert_eq!(
        dispatcher.authorize_scheduler_owned_abi(
            OWNER,
            handle.abi_value(),
            &encode(Request::CreateCondition)
        ),
        Err(DispatchError::InvalidCall)
    );
    for offset in [0, 1, 2, 3, 4, 5, 6, 7, 8, 16, 24, 32, 40, 48, 56, 63] {
        let mut malformed = bytes;
        malformed[offset] ^= 0x80;
        assert_eq!(
            dispatcher.authorize_scheduler_owned_abi(OWNER, handle.abi_value(), &malformed),
            Err(DispatchError::InvalidCall)
        );
    }
    for length in 0..64 {
        assert_eq!(
            dispatcher.authorize_scheduler_owned_abi(OWNER, handle.abi_value(), &bytes[..length]),
            Err(DispatchError::InvalidCall)
        );
    }
    let mut oversized = [0; 65];
    oversized[..64].copy_from_slice(&bytes);
    assert_eq!(
        dispatcher.authorize_scheduler_owned_abi(OWNER, handle.abi_value(), &oversized),
        Err(DispatchError::InvalidCall)
    );
    assert_eq!(dispatcher.stats(), before);
    Ok(())
}

#[test]
fn mixed_targets_share_capacity_generations_and_owner_revocation() -> Result<(), DispatchError> {
    let mut dispatcher = Dispatcher::new(1, 3)?;
    let rights = Rights::CALL.union(Rights::THREAD_OBSERVE);
    let (port, service) =
        dispatcher.register(Box::new(Counter(Rc::new(Cell::new(0)))), Rights::CALL)?;
    let scheduler =
        dispatcher.open_scheduler_owned(SchedulerInterface::ControlV1, rights, OWNER)?;
    let foreign =
        dispatcher.open_scheduler_owned(SchedulerInterface::SyncV1, Rights::CALL, FOREIGN)?;
    assert_eq!(
        dispatcher.open_scheduler_owned(SchedulerInterface::SyncV1, Rights::CALL, OWNER),
        Err(DispatchError::HandleCapacityExhausted)
    );
    assert_eq!(
        dispatcher.open_owned(port, Rights::CALL, OWNER),
        Err(DispatchError::HandleCapacityExhausted)
    );
    dispatcher.close(scheduler)?;
    let reused = dispatcher.open_owned(port, Rights::CALL, OWNER)?;
    assert_ne!(scheduler.abi_value(), reused.abi_value());
    assert_eq!(
        scheduler.abi_value() & u64::from(u32::MAX),
        reused.abi_value() & u64::from(u32::MAX)
    );
    assert_eq!(
        dispatcher.authorize_scheduler_owned_abi(
            OWNER,
            scheduler.abi_value(),
            &encode(Request::Current)
        ),
        Err(DispatchError::InvalidHandle)
    );
    dispatcher.close(reused)?;
    let replacement =
        dispatcher.open_scheduler_owned(SchedulerInterface::ControlV1, rights, OWNER)?;
    dispatcher.close_port(port)?;
    assert_eq!(dispatcher.stats().live_handles, 2);
    assert_eq!(
        dispatcher.call(service, 1, &[]),
        Err(DispatchError::InvalidHandle)
    );
    assert_eq!(
        dispatcher
            .authorize_scheduler_owned_abi(
                OWNER,
                replacement.abi_value(),
                &encode(Request::Current)
            )?
            .request(),
        Request::Current
    );
    assert_eq!(dispatcher.close_owner(OWNER)?, 1);
    assert_eq!(
        dispatcher.authorize_scheduler_owned_abi(
            OWNER,
            replacement.abi_value(),
            &encode(Request::Current)
        ),
        Err(DispatchError::InvalidHandle)
    );
    assert_eq!(
        dispatcher
            .authorize_scheduler_owned_abi(
                FOREIGN,
                foreign.abi_value(),
                &encode(Request::CreateCondition)
            )?
            .owner(),
        FOREIGN
    );
    assert_eq!(dispatcher.close_owner(FOREIGN)?, 1);
    assert_eq!(
        (
            dispatcher.stats().live_ports,
            dispatcher.stats().live_handles
        ),
        (0, 0)
    );
    Ok(())
}

#[test]
fn admitted_request_is_owned_and_does_not_borrow_revocable_tables() -> Result<(), DispatchError> {
    let mut dispatcher = Dispatcher::new(1, 1)?;
    let handle =
        dispatcher.open_scheduler_owned(SchedulerInterface::SyncV1, Rights::CALL, OWNER)?;
    let mut bytes = encode(Request::CreateCondition);
    let admitted = dispatcher.authorize_scheduler_owned_abi(OWNER, handle.abi_value(), &bytes)?;
    bytes.fill(0);
    dispatcher.close(handle)?;
    // Revocation prevents another admission; the caller owns the existing one.
    assert_eq!(
        dispatcher.authorize_scheduler_owned_abi(
            OWNER,
            handle.abi_value(),
            &encode(Request::CreateCondition)
        ),
        Err(DispatchError::InvalidHandle)
    );
    drop(dispatcher);
    assert_eq!(admitted.request(), Request::CreateCondition);
    Ok(())
}
