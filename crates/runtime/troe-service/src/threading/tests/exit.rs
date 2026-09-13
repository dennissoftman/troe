use super::*;

fn retire(h: &mut Harness, index: usize, result: u64) -> Result<Retiring, ()> {
    let Progress::Retiring(action) = h.run(index, Request::Exit(result))? else {
        return Err(());
    };
    assert_eq!(action.caller(), h.ids[index]);
    assert_eq!(action.request(), Request::Exit(result));
    Ok(action)
}

#[test]
fn exit_of_initial_worker_or_last_thread_retains_charges_and_leaves_other_execution_live()
-> Result<(), ()> {
    for index in [0, 1, 3] {
        let mut h = Harness::new()?;
        h.select(index)?;
        let caller = h.ids[index];
        let owner = caller.process();
        let pages = h.threads.committed_pages();
        let action = retire(&mut h, index, u64::MAX)?;
        assert_eq!(action.disposition(), sync::ExitEffect::ThreadExiting);
        let snapshot = h.threads.snapshot(owner, caller).map_err(|_| ())?;
        assert_eq!(snapshot.state, ThreadState::Exiting);
        assert!(!snapshot.resources_released);
        assert_eq!(snapshot.detached, index != 1);
        assert_eq!(h.threads.committed_pages(), pages);
        assert!(h.threads.dispatch(owner, caller).is_err());
        h.response(index, Request::Exit(0), Outcome::InvalidState)?;
        let sibling = usize::from(index == 0);
        h.select(sibling)?;
        h.response(sibling, Request::Current, Outcome::Success)?;
        action.complete_thread(&mut h.threads).map_err(|_| ())?;
        assert_eq!(h.threads.committed_pages(), pages);
        assert_eq!(
            h.threads.snapshot(owner, caller).map_err(|_| ())?.state,
            ThreadState::Completed
        );
        if index == 1 {
            let token = Token::new(
                Kind::Thread,
                u32::try_from(caller.slot()).map_err(|_| ())?,
                caller.generation(),
            )
            .map_err(|_| ())?;
            let join = Request::Join {
                thread: token,
                wait: TRY,
            };
            h.response(0, join, Outcome::WouldBlock)?;
            h.threads.release_resources(owner, caller).map_err(|_| ())?;
            assert_eq!(h.response(0, join, Outcome::Success)?.value, u64::MAX);
        }
    }
    Ok(())
}

#[test]
fn stop_during_retirement_rejects_completion_without_losing_the_action() -> Result<(), ()> {
    let mut h = Harness::new()?;
    let action = retire(&mut h, 0, 42)?;
    let caller = action.caller();
    let pages = h.threads.committed_pages();
    h.sync
        .stop_process(&mut h.threads, caller.process())
        .map_err(|_| ())?;
    let (error, action) = action.complete_thread(&mut h.threads).err().ok_or(())?;
    assert_eq!(error, Error::Thread(ThreadError::InvalidState));
    assert_eq!(action.caller(), caller);
    assert_eq!(action.request(), Request::Exit(42));
    assert_eq!(h.threads.committed_pages(), pages);
    assert_eq!(
        h.threads
            .snapshot(caller.process(), caller)
            .map_err(|_| ())?
            .state,
        ThreadState::Revoked
    );
    h.threads
        .release_resources(caller.process(), caller)
        .map_err(|_| ())?;
    h.threads.reap(caller.process(), caller).map_err(|_| ())?;
    assert_eq!(
        action.complete_thread(&mut h.threads).err().ok_or(())?.0,
        Error::Thread(ThreadError::Stale)
    );
    Ok(())
}

#[test]
fn creator_exit_revokes_prepared_children_without_refunding_their_backing() -> Result<(), ()> {
    let mut h = Harness::new()?;
    h.select(2)?;
    retire(&mut h, 2, 0)?
        .complete_thread(&mut h.threads)
        .map_err(|_| ())?;
    let owner = h.ids[2].process();
    h.threads.detach(owner, h.ids[2]).map_err(|_| ())?;
    h.threads
        .release_resources(owner, h.ids[2])
        .map_err(|_| ())?;
    h.threads.reap(owner, h.ids[2]).map_err(|_| ())?;
    h.threads.dispatch(owner, h.ids[1]).map_err(|_| ())?;
    h.ids[2] = h
        .threads
        .prepare_worker(
            owner,
            h.ids[1],
            ThreadResources {
                reservation: 99,
                pages: 3,
            },
        )
        .map_err(|_| ())?;
    let pages = h.threads.committed_pages();
    let action = retire(&mut h, 1, 0)?;
    let child = h.threads.snapshot(owner, h.ids[2]).map_err(|_| ())?;
    assert_eq!(child.state, ThreadState::Revoked);
    assert!(!child.resources_released);
    assert_eq!(h.threads.committed_pages(), pages);
    action.complete_thread(&mut h.threads).map_err(|_| ())?;
    assert_eq!(h.threads.committed_pages(), pages);
    assert!(h.threads.start(owner, h.ids[2]).is_err());
    assert!(h.threads.reap(owner, h.ids[2]).is_err());
    h.select(0)?;
    h.response(0, Request::Current, Outcome::Success)?;
    Ok(())
}

#[test]
fn exit_clock_regression_fails_before_lifecycle_or_owner_death_changes() -> Result<(), ()> {
    let mut h = Harness::new()?;
    let mutex = h.create(0, Request::CreateMutex(wire::OwnerDeath::FailProcess))?;
    h.now = 10;
    h.response(0, Request::Lock { mutex, wait: TRY }, Outcome::Success)?;
    let caller = h.ids[0];
    let before = h
        .threads
        .snapshot(caller.process(), caller)
        .map_err(|_| ())?;
    assert_eq!(
        h.operation(0, Request::Exit(0))?.execute(
            &mut h.threads,
            &mut h.sync,
            MonotonicMillis::from_millis(9)
        ),
        Err(Error::Sync(sync::SyncError::ClockRegressed))
    );
    assert_eq!(
        h.threads
            .snapshot(caller.process(), caller)
            .map_err(|_| ())?,
        before
    );
    h.response(0, Request::Unlock(mutex), Outcome::Success)?;
    assert_eq!(
        retire(&mut h, 0, 0)?.disposition(),
        sync::ExitEffect::ThreadExiting
    );
    Ok(())
}

#[test]
fn pending_completion_prevents_exit_until_its_owned_wait_is_consumed() -> Result<(), ()> {
    let mut h = Harness::new()?;
    let permit = h.create(
        0,
        Request::CreatePermit {
            count: 0,
            maximum: 1,
        },
    )?;
    let wait = h.wait(
        0,
        Request::AcquirePermit {
            permit,
            wait: BLOCK,
        },
    )?;
    h.select(1)?;
    h.response(
        1,
        Request::ReleasePermit { permit, count: 1 },
        Outcome::Success,
    )?;
    h.select(0)?;
    h.response(0, Request::Exit(42), Outcome::Busy)?;
    let pages = h.threads.committed_pages();
    let completion = wait.finish(&mut h.threads, &mut h.sync).map_err(|_| ())?;
    assert_eq!(completion.response().outcome, Outcome::Success);
    let action = retire(&mut h, 0, 42)?;
    action.complete_thread(&mut h.threads).map_err(|_| ())?;
    assert_eq!(h.threads.committed_pages(), pages);
    Ok(())
}

#[test]
fn revoking_the_handle_does_not_replay_or_cancel_an_owned_exit() -> Result<(), ()> {
    let mut h = Harness::new()?;
    let operation = h.operation(0, Request::Exit(42))?;
    h.dispatcher.close(h.handles[0][0]).map_err(|_| ())?;
    assert!(h.authorize(0, Request::Exit(0)).is_err());
    let Progress::Retiring(action) = operation
        .execute(&mut h.threads, &mut h.sync, MonotonicMillis::from_millis(0))
        .map_err(|_| ())?
    else {
        return Err(());
    };
    let caller = action.caller();
    // A conflicting trusted completion cannot be overwritten by the retained action.
    h.threads
        .complete(caller.process(), caller, 7)
        .map_err(|_| ())?;
    let (error, retained) = action.complete_thread(&mut h.threads).err().ok_or(())?;
    assert_eq!(error, Error::Thread(ThreadError::InvalidState));
    assert_eq!(retained.request(), Request::Exit(42));
    Ok(())
}
