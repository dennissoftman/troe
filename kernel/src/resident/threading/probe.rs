//! Execute converted static-TLS KEX images through the resident loader and loop.

use super::{NativeThreads, PROCESS_THREADS};
use crate::{
    invocation::CommandApplicationOutcome,
    machine::OwnedAccounting,
    memory::native::NativeLoadLimits,
    resident::{ResidentApplication, launch::prepare_threaded_resident_application},
};
use alloc::rc::Rc;
use core::cell::RefCell;
use troe_application::{
    LoadPlacement, encode_kex_package, parse_streamed_threaded_kex_package,
    process_memory::{ProcessMemoryBudget, ProcessMemoryPlacement},
};
use troe_dispatch::{Dispatcher, Rights, SchedulerInterface};
use troe_task::{ProcessOrigin, ProcessTable, Scheduler};

#[cfg(target_arch = "x86_64")]
const PROGRAM: &[u8] = include_bytes!("probe/program-x86_64.kex");
#[cfg(target_arch = "aarch64")]
const PROGRAM: &[u8] = include_bytes!("probe/program-aarch64.kex");

#[allow(clippy::too_many_lines)] // Keep failure cleanup beside both loaded residents.
pub(crate) fn verify(accounting: &mut OwnedAccounting) -> Result<(), ()> {
    let policy = NativeThreads::shared(accounting)?;
    let metadata = accounting.private_metadata_bytes;
    let committed = accounting.application_committed_pages;
    let free = accounting.frames.free_frames();
    let tls = accounting.thread_tls_backing.usage();
    let package = encode_kex_package(PROGRAM, &[]).map_err(|_| ())?;
    let processes = Rc::new(RefCell::new(ProcessTable::new(2).map_err(|_| ())?));
    let mut scheduler = Scheduler::new(2).map_err(|_| ())?;
    let mut residents: [Option<ResidentApplication<'static>>; 2] = [None, None];
    let result = (|| {
        for (index, resident) in residents.iter_mut().enumerate() {
            let placement = LoadPlacement::new(
                0x4000_0000_0000 + index as u64 * 0x400_0000,
                0x7000_0000_0000,
            );
            let parsed = parse_streamed_threaded_kex_package(
                package.len() as u64,
                read(&package),
                crate::artifacts::native_application_target(),
                placement,
            )
            .map_err(|_| ())?;
            *resident = Some(prepare_threaded_resident_application(
                &mut scheduler,
                accounting,
                Dispatcher::new(1, 2).map_err(|_| ())?,
                &[],
                &[
                    (
                        SchedulerInterface::ControlV1,
                        Rights::CALL
                            .union(Rights::THREAD_CREATE)
                            .union(Rights::THREAD_START)
                            .union(Rights::THREAD_JOIN)
                            .union(Rights::THREAD_OBSERVE),
                    ),
                    (SchedulerInterface::SyncV1, Rights::CALL),
                ],
                &parsed,
                ProcessMemoryPlacement {
                    image_base: placement.image_base(),
                    heap_capacity_pages: 16,
                    initial_thread_base: 0x6000_0000_0000 + index as u64 * 0x400_0000,
                },
                NativeLoadLimits {
                    memory: ProcessMemoryBudget {
                        mapped_pages: 4096,
                        resident_pages: 8192,
                        reserved_pages: 1 << 28,
                        ordinary_frames: 8192,
                        ipc_pairs: 8,
                        tls_pages: 32,
                        template_pages: 16,
                        staging_bytes: 64 * 1024,
                    },
                    contexts: PROCESS_THREADS,
                    metadata_bytes: 512 * 1024,
                    extra_table_pages: 64,
                },
                read(&package),
                u32::try_from(240 + index).map_err(|_| ())?,
                "resident-tls-probe",
                ProcessOrigin::Foreground,
                0,
                Rc::clone(&processes),
            )?);
        }
        for _ in 0..256 {
            for resident in &mut residents {
                let Some(application) = resident else {
                    continue;
                };
                if let Some(outcome) = application.step(&mut scheduler, accounting)? {
                    let result = resident.take().ok_or(())?.teardown(
                        &mut scheduler,
                        accounting,
                        outcome,
                        false,
                    )?;
                    if result != CommandApplicationOutcome::Exited(0) {
                        let _ = troe_machine::write(
                            alloc::format!("resident TLS consumer failed: {result:?}\n").as_bytes(),
                        );
                        return Err(());
                    }
                }
            }
            if residents.iter().all(Option::is_none) {
                return Ok(());
            }
        }
        Err(())
    })();
    // Test failure also retires every live root before its backing is reclaimed.
    for resident in residents.into_iter().flatten() {
        resident.teardown(
            &mut scheduler,
            accounting,
            CommandApplicationOutcome::Exited(troe_abi::exit::CANCELLED),
            true,
        )?;
    }
    result?;
    if accounting.frames.free_frames() != free
        || accounting.application_committed_pages != committed
        || accounting.private_metadata_bytes != metadata
        || accounting.thread_tls_backing.usage() != tls
        || policy
            .try_borrow()
            .map_err(|_| ())?
            .threads
            .committed_pages()
            != 0
        || processes.try_borrow().map_err(|_| ())?.snapshots().len() != 0
    {
        return Err(());
    }
    if !troe_machine::write(b"resident TLS KEX: two processes, private compiler TLS, create/start/abort/join, sync and empty heap passed\n") { return Err(()); }
    Ok(())
}

fn read(bytes: &[u8]) -> impl FnMut(u64, &mut [u8]) -> Result<usize, ()> + '_ {
    move |offset, destination| {
        let source = bytes
            .get(usize::try_from(offset).map_err(|_| ())?..)
            .ok_or(())?;
        let count = source.len().min(destination.len()).min(137);
        destination[..count].copy_from_slice(&source[..count]);
        Ok(count)
    }
}
