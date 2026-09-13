use super::*;

const PREPARE: Request = Request::Prepare {
    entry_offset: 0x40,
    argument: u64::MAX,
    stack_pages: 2,
};
const RESOURCE: ThreadResources = ThreadResources {
    reservation: 100,
    pages: 3,
};

fn vacant(h: &mut Harness) -> Result<(), ()> {
    h.select(2)?;
    let Progress::Retiring(exit) = h.run(2, Request::Exit(0))? else {
        return Err(());
    };
    exit.complete_thread(&mut h.threads).map_err(|_| ())?;
    let target = h.ids[2];
    h.threads.detach(target.process(), target).map_err(|_| ())?;
    h.threads
        .release_resources(target.process(), target)
        .map_err(|_| ())?;
    h.threads.reap(target.process(), target).map_err(|_| ())?;
    h.threads
        .dispatch(h.ids[0].process(), h.ids[0])
        .map_err(|_| ())
}
fn preparing(h: &mut Harness) -> Result<Preparing, ()> {
    let Progress::Preparing(action) = h.run(0, PREPARE)? else {
        return Err(());
    };
    assert_eq!(action.caller(), h.ids[0]);
    assert_eq!(action.request(), PREPARE);
    assert_eq!(action.target(), None);
    assert_eq!(action.resources(), None);
    Ok(action)
}
fn reserve(h: &mut Harness) -> Result<Preparing, ()> {
    vacant(h)?;
    let mut action = preparing(h)?;
    h.ids[2] = action.reserve(&mut h.threads, RESOURCE).map_err(|_| ())?;
    Ok(action)
}
fn token(id: ThreadId) -> Result<Token, ()> {
    Token::new(
        Kind::Thread,
        u32::try_from(id.slot()).map_err(|_| ())?,
        id.generation(),
    )
    .map_err(|_| ())
}
fn starting(h: &mut Harness, target: ThreadId) -> Result<Starting, ()> {
    let Progress::Starting(action) = h.run(0, Request::Start(token(target)?))? else {
        return Err(());
    };
    assert_eq!(action.caller(), h.ids[0]);
    assert_eq!(action.target(), target);
    Ok(action)
}

#[test]
fn preparation_retains_request_and_charge_without_implicitly_starting() -> Result<(), ()> {
    let mut h = Harness::new()?;
    let mut action = reserve(&mut h)?;
    let target = h.ids[2];
    let pages = h.threads.committed_pages();
    assert_eq!(action.resources(), Some(RESOURCE));
    assert_eq!(action.target(), Some(target));
    assert_eq!(
        action.reserve(&mut h.threads, RESOURCE),
        Err(Error::Thread(ThreadError::InvalidState))
    );
    assert_eq!(h.threads.committed_pages(), pages);
    h.select(1)?;
    let (error, action) = action.finish(&h.threads).err().ok_or(())?;
    assert_eq!(error, Error::Thread(ThreadError::InvalidState));
    h.select(0)?;
    let completion = action.finish(&h.threads).map_err(|_| ())?;
    assert_eq!(completion.caller(), h.ids[0]);
    assert_eq!(completion.request(), PREPARE);
    assert_eq!(
        completion.response(),
        reply(Outcome::Success, token(target)?.bits())
    );
    assert_eq!(
        h.threads
            .snapshot(target.process(), target)
            .map_err(|_| ())?
            .state,
        ThreadState::Prepared
    );
    assert!(h.threads.dispatch(target.process(), target).is_err());
    let start = starting(&mut h, target)?;
    assert_eq!(
        h.threads
            .snapshot(target.process(), target)
            .map_err(|_| ())?
            .state,
        ThreadState::Prepared
    );
    let completion = start.finish(&mut h.threads).map_err(|_| ())?;
    assert_eq!(completion.response(), reply(Outcome::Success, 0));
    assert_eq!(
        h.threads
            .snapshot(target.process(), target)
            .map_err(|_| ())?
            .state,
        ThreadState::Ready
    );
    h.response(0, Request::Start(token(target)?), Outcome::InvalidState)?;
    h.response(0, Request::Abort(token(target)?), Outcome::InvalidState)?;
    h.select(2)?;
    h.response(2, Request::Current, Outcome::Success)?;
    Ok(())
}

#[test]
fn pre_reservation_failure_has_no_target_or_resource_effect() -> Result<(), ()> {
    let mut h = Harness::new()?;
    let before = h.threads.committed_pages();
    let mut action = preparing(&mut h)?;
    assert_eq!(
        action.reserve(&mut h.threads, RESOURCE),
        Err(Error::Thread(ThreadError::Exhausted))
    );
    assert_eq!(action.target(), None);
    let completion = action
        .reject(&h.threads, PrepareFailure::Exhausted)
        .map_err(|_| ())?;
    assert_eq!(completion.response(), reply(Outcome::Exhausted, 0));
    assert_eq!(h.threads.committed_pages(), before);
    for failure in [PrepareFailure::InvalidRequest, PrepareFailure::Unsupported] {
        let action = preparing(&mut h)?;
        let completion = action.reject(&h.threads, failure).map_err(|_| ())?;
        assert_ne!(completion.response().outcome, Outcome::Success);
        assert_eq!(completion.response().value, 0);
    }
    let action = preparing(&mut h)?;
    let (error, action) = action.finish(&h.threads).err().ok_or(())?;
    assert_eq!(error, Error::Thread(ThreadError::InvalidState));
    assert!(
        action
            .revoke(&mut h.threads, PrepareFailure::Exhausted)
            .is_err()
    );
    Ok(())
}

#[test]
fn rollback_requires_reclamation_and_exact_reap_before_failure_reply() -> Result<(), ()> {
    let mut h = Harness::new()?;
    let action = reserve(&mut h)?;
    let target = h.ids[2];
    let owner = target.process();
    let before = h.threads.committed_pages();
    let (error, action) = action
        .reject(&h.threads, PrepareFailure::Exhausted)
        .err()
        .ok_or(())?;
    assert_eq!(error, Error::Thread(ThreadError::Busy));
    let rollback = action
        .revoke(&mut h.threads, PrepareFailure::Exhausted)
        .map_err(|_| ())?;
    assert_eq!(rollback.request(), PREPARE);
    assert_eq!(rollback.target(), target);
    assert_eq!(rollback.caller(), h.ids[0]);
    assert_eq!(h.threads.committed_pages(), before);
    assert_eq!(
        h.threads.snapshot(owner, target).map_err(|_| ())?.state,
        ThreadState::Revoked
    );
    let (error, rollback) = rollback.finish(&mut h.threads).err().ok_or(())?;
    assert_eq!(error, Error::Thread(ThreadError::Busy));
    assert!(h.threads.reap(owner, target).is_err());
    h.threads.release_resources(owner, target).map_err(|_| ())?;
    h.select(1)?;
    let (error, rollback) = rollback.finish(&mut h.threads).err().ok_or(())?;
    assert_eq!(error, Error::Thread(ThreadError::InvalidState));
    h.select(0)?;
    let completion = rollback.finish(&mut h.threads).map_err(|_| ())?;
    assert_eq!(completion.response(), reply(Outcome::Exhausted, 0));
    assert!(h.threads.snapshot(owner, target).is_err());
    assert_eq!(h.threads.committed_pages(), before - RESOURCE.pages);
    let mut next = preparing(&mut h)?;
    let fresh = next.reserve(&mut h.threads, RESOURCE).map_err(|_| ())?;
    assert_eq!(fresh.slot(), target.slot());
    assert_ne!(fresh.generation(), target.generation());
    Ok(())
}

#[test]
fn sibling_cannot_start_or_abort_another_creators_preparation() -> Result<(), ()> {
    let mut h = Harness::new()?;
    let action = reserve(&mut h)?;
    let target = h.ids[2];
    let before = h
        .threads
        .snapshot(target.process(), target)
        .map_err(|_| ())?;
    let pages = h.threads.committed_pages();
    h.select(1)?;
    for request in [
        Request::Start(token(target)?),
        Request::Abort(token(target)?),
    ] {
        h.response(1, request, Outcome::InvalidState)?;
    }
    h.select(3)?;
    h.response(3, Request::Start(token(target)?), Outcome::Stale)?;
    h.response(3, Request::Abort(token(target)?), Outcome::Stale)?;
    assert_eq!(
        h.threads
            .snapshot(target.process(), target)
            .map_err(|_| ())?,
        before
    );
    assert_eq!(h.threads.committed_pages(), pages);
    h.select(0)?;
    assert_eq!(
        action.finish(&h.threads).map_err(|_| ())?.response().value,
        token(target)?.bits()
    );
    let Progress::Aborting(abort) = h.run(0, Request::Abort(token(target)?))? else {
        return Err(());
    };
    assert_eq!(abort.target(), target);
    Ok(())
}

#[test]
fn abort_or_creator_exit_wins_over_retained_start_without_late_ready() -> Result<(), ()> {
    for exit in [false, true] {
        let mut h = Harness::new()?;
        let preparation = reserve(&mut h)?;
        let target = h.ids[2];
        assert_eq!(
            preparation
                .finish(&h.threads)
                .map_err(|_| ())?
                .response()
                .value,
            token(target)?.bits()
        );
        let start = starting(&mut h, target)?;
        let request = if exit {
            Request::Exit(0)
        } else {
            Request::Abort(token(target)?)
        };
        match (exit, h.run(0, request)?) {
            (true, Progress::Retiring(_)) | (false, Progress::Aborting(_)) => {}
            _ => return Err(()),
        }
        assert!(start.finish(&mut h.threads).is_err());
        assert_eq!(
            h.threads
                .snapshot(target.process(), target)
                .map_err(|_| ())?
                .state,
            ThreadState::Revoked
        );
        assert!(
            !h.threads
                .snapshot(target.process(), target)
                .map_err(|_| ())?
                .resources_released
        );
    }
    Ok(())
}

#[test]
fn stopped_preparation_and_rollback_never_publish_late_completion() -> Result<(), ()> {
    for rollback in [false, true] {
        let mut h = Harness::new()?;
        let action = reserve(&mut h)?;
        let target = h.ids[2];
        if rollback {
            let action = action
                .revoke(&mut h.threads, PrepareFailure::Exhausted)
                .map_err(|_| ())?;
            h.threads
                .release_resources(target.process(), target)
                .map_err(|_| ())?;
            h.sync
                .stop_process(&mut h.threads, target.process())
                .map_err(|_| ())?;
            assert!(action.finish(&mut h.threads).is_err());
        } else {
            h.sync
                .stop_process(&mut h.threads, target.process())
                .map_err(|_| ())?;
            assert!(action.finish(&h.threads).is_err());
        }
        assert_eq!(
            h.threads
                .snapshot(target.process(), target)
                .map_err(|_| ())?
                .state,
            ThreadState::Revoked
        );
    }
    Ok(())
}

#[test]
fn retained_preparation_cannot_complete_against_a_reused_slot() -> Result<(), ()> {
    let mut h = Harness::new()?;
    let action = reserve(&mut h)?;
    let old = h.ids[2];
    h.threads
        .abort_worker(old.process(), h.ids[0], old)
        .map_err(|_| ())?;
    h.threads
        .release_resources(old.process(), old)
        .map_err(|_| ())?;
    h.threads.reap(old.process(), old).map_err(|_| ())?;
    h.ids[2] = h
        .threads
        .prepare_worker(old.process(), h.ids[0], RESOURCE)
        .map_err(|_| ())?;
    assert_eq!(old.slot(), h.ids[2].slot());
    assert_ne!(old.generation(), h.ids[2].generation());
    let (error, _) = action.finish(&h.threads).err().ok_or(())?;
    assert_eq!(error, Error::Thread(ThreadError::Stale));
    Ok(())
}
