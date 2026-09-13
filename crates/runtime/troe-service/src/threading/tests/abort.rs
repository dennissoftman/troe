use super::*;

fn prepared(h: &mut Harness) -> Result<Token, ()> {
    h.select(2)?;
    let Progress::Retiring(exit) = h.run(2, Request::Exit(0))? else {
        return Err(());
    };
    exit.complete_thread(&mut h.threads).map_err(|_| ())?;
    let owner = h.ids[2].process();
    h.threads.detach(owner, h.ids[2]).map_err(|_| ())?;
    h.threads
        .release_resources(owner, h.ids[2])
        .map_err(|_| ())?;
    h.threads.reap(owner, h.ids[2]).map_err(|_| ())?;
    h.threads.dispatch(owner, h.ids[0]).map_err(|_| ())?;
    h.ids[2] = h
        .threads
        .prepare_worker(
            owner,
            h.ids[0],
            ThreadResources {
                reservation: 100,
                pages: 3,
            },
        )
        .map_err(|_| ())?;
    Token::new(
        Kind::Thread,
        u32::try_from(h.ids[2].slot()).map_err(|_| ())?,
        h.ids[2].generation(),
    )
    .map_err(|_| ())
}

fn abort(h: &mut Harness, token: Token) -> Result<Aborting, ()> {
    let Progress::Aborting(action) = h.run(0, Request::Abort(token))? else {
        return Err(());
    };
    assert_eq!(action.caller(), h.ids[0]);
    assert_eq!(action.target(), h.ids[2]);
    assert_eq!(action.request(), Request::Abort(token));
    Ok(action)
}

#[test]
fn abort_retains_its_target_and_charges_until_reclamation_before_reply() -> Result<(), ()> {
    let mut h = Harness::new()?;
    let token = prepared(&mut h)?;
    let pages = h.threads.committed_pages();
    let action = abort(&mut h, token)?;
    let target = action.target();
    let owner = target.process();
    let snapshot = h.threads.snapshot(owner, target).map_err(|_| ())?;
    assert_eq!(snapshot.state, ThreadState::Revoked);
    assert!(!snapshot.resources_released);
    assert_eq!(h.threads.committed_pages(), pages);
    h.response(0, Request::Abort(token), Outcome::InvalidState)?;
    let (error, action) = action.finish(&mut h.threads).err().ok_or(())?;
    assert_eq!(error, Error::Thread(ThreadError::Busy));
    assert!(h.threads.reap(owner, target).is_err());
    h.threads.release_resources(owner, target).map_err(|_| ())?;
    h.select(1)?;
    let (error, action) = action.finish(&mut h.threads).err().ok_or(())?;
    assert_eq!(error, Error::Thread(ThreadError::InvalidState));
    assert!(h.threads.snapshot(owner, target).is_ok());
    h.select(0)?;
    let completion = action.finish(&mut h.threads).map_err(|_| ())?;
    assert_eq!(completion.caller(), h.ids[0]);
    assert_eq!(completion.request(), Request::Abort(token));
    assert_eq!(completion.response(), reply(Outcome::Success, 0));
    assert_eq!(h.threads.committed_pages(), pages - 3);
    assert!(h.threads.snapshot(owner, target).is_err());
    Ok(())
}

#[test]
fn start_winning_before_first_execution_rejects_abort_without_reclaiming() -> Result<(), ()> {
    let mut h = Harness::new()?;
    let token = prepared(&mut h)?;
    let target = h.ids[2];
    h.threads.start(target.process(), target).map_err(|_| ())?;
    let before = h
        .threads
        .snapshot(target.process(), target)
        .map_err(|_| ())?;
    let pages = h.threads.committed_pages();
    h.response(0, Request::Abort(token), Outcome::InvalidState)?;
    assert_eq!(
        h.threads
            .snapshot(target.process(), target)
            .map_err(|_| ())?,
        before
    );
    assert_eq!(h.threads.committed_pages(), pages);
    h.select(2)?;
    h.response(2, Request::Current, Outcome::Success)?;
    Ok(())
}

#[test]
fn stopping_prevents_late_abort_success_even_after_target_resources_are_released() -> Result<(), ()>
{
    let mut h = Harness::new()?;
    let token = prepared(&mut h)?;
    let action = abort(&mut h, token)?;
    let target = action.target();
    h.threads
        .release_resources(target.process(), target)
        .map_err(|_| ())?;
    h.sync
        .stop_process(&mut h.threads, target.process())
        .map_err(|_| ())?;
    let (error, action) = action.finish(&mut h.threads).err().ok_or(())?;
    assert_eq!(error, Error::Thread(ThreadError::Stopping));
    assert_eq!(action.target(), target);
    assert!(h.threads.snapshot(target.process(), target).is_ok());
    Ok(())
}

#[test]
fn premature_reaping_cannot_complete_against_a_reused_target_slot() -> Result<(), ()> {
    let mut h = Harness::new()?;
    let token = prepared(&mut h)?;
    let action = abort(&mut h, token)?;
    let target = action.target();
    let owner = target.process();
    h.threads.release_resources(owner, target).map_err(|_| ())?;
    h.threads.reap(owner, target).map_err(|_| ())?;
    h.ids[2] = h
        .threads
        .prepare_worker(
            owner,
            h.ids[0],
            ThreadResources {
                reservation: 101,
                pages: 3,
            },
        )
        .map_err(|_| ())?;
    assert_eq!(h.ids[2].slot(), target.slot());
    assert_ne!(h.ids[2].generation(), target.generation());
    let before = h.threads.snapshot(owner, h.ids[2]).map_err(|_| ())?;
    let (error, action) = action.finish(&mut h.threads).err().ok_or(())?;
    assert_eq!(error, Error::Thread(ThreadError::Stale));
    assert_eq!(action.target(), target);
    assert_eq!(h.threads.snapshot(owner, h.ids[2]).map_err(|_| ())?, before);
    Ok(())
}

#[test]
fn foreign_and_busy_callers_cannot_abort_a_preparation() -> Result<(), ()> {
    let mut h = Harness::new()?;
    let token = prepared(&mut h)?;
    let target = h.ids[2];
    let before = h
        .threads
        .snapshot(target.process(), target)
        .map_err(|_| ())?;
    h.select(3)?;
    h.response(3, Request::Abort(token), Outcome::Stale)?;
    h.select(0)?;
    let wait = h.wait(0, Request::Sleep(WAIT))?;
    h.response(0, Request::Abort(token), Outcome::Busy)?;
    assert_eq!(
        h.threads
            .snapshot(target.process(), target)
            .map_err(|_| ())?,
        before
    );
    drop(wait);
    h.sync
        .stop_process(&mut h.threads, target.process())
        .map_err(|_| ())?;
    Ok(())
}
