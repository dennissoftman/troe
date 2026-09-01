//! Isolated-task memory and the program the isolation probe runs.
//!
//! The isolated task is a minimal user-privilege program emitted here as
//! machine code, mapped into its own tables, and used to demonstrate that a
//! user-mode fault is contained.

use crate::limits::{
    ISOLATED_CODE_PAGES, ISOLATED_DATA_PAGES, ISOLATED_MESSAGE, ISOLATED_RESOURCE_PAGES,
    ISOLATED_STACK_PAGES, ISOLATED_TABLE_PAGES, STAGE6_USER_REGIONS, USER_CODE_BASE,
    USER_DATA_BASE, USER_STACK_BASE, USER_UNMAPPED_BASE,
};
use crate::memory::IsolatedAllocation;
use crate::memory::launch::terminate_revoke_and_reap_task;
use crate::probes::IsolationProbe;
use alloc::vec::Vec;
use troe_dispatch::{Dispatcher, HandleOwner};
use troe_memory::{
    BASE_PAGE_SIZE, FrameAllocator, Mapping, MappingLifetime, MappingOwner, MappingPermissions,
    MappingPlan, PhysicalRange, VirtualRange,
};
use troe_task::{Scheduler, TaskId};

pub(crate) fn rollback_isolated_task(
    scheduler: &mut Scheduler,
    task_id: TaskId,
    dispatcher: &mut Dispatcher<'_>,
    owner: Option<HandleOwner>,
    frames: &mut FrameAllocator,
    allocation: IsolatedAllocation,
) -> Result<(), ()> {
    terminate_revoke_and_reap_task(scheduler, task_id, dispatcher, owner)?;
    reclaim_isolated(frames, allocation)
}

pub(crate) fn allocate_isolated(frames: &mut FrameAllocator) -> Result<IsolatedAllocation, ()> {
    let complete = frames
        .allocate_contiguous(ISOLATED_RESOURCE_PAGES, 1)
        .map_err(|_| ())?;
    let derived = (|| {
        let tables =
            PhysicalRange::from_pages(complete.start(), ISOLATED_TABLE_PAGES).map_err(|_| ())?;
        let code = PhysicalRange::from_pages(tables.end(), ISOLATED_CODE_PAGES).map_err(|_| ())?;
        let data = PhysicalRange::from_pages(code.end(), ISOLATED_DATA_PAGES).map_err(|_| ())?;
        let stack = PhysicalRange::from_pages(data.end(), ISOLATED_STACK_PAGES).map_err(|_| ())?;
        if stack.end() != complete.end() {
            return Err(());
        }
        Ok(IsolatedAllocation {
            complete,
            tables,
            code,
            data,
            stack,
        })
    })();
    if derived.is_err() {
        frames.free_range(complete).map_err(|_| ())?;
    }
    derived
}

pub(crate) fn prepare_isolated_memory(
    allocation: &IsolatedAllocation,
    probe: IsolationProbe,
) -> Result<(), ()> {
    troe_machine::zero_physical_range(allocation.complete).map_err(|_| ())?;
    let code = isolated_program(probe)?;
    troe_machine::copy_to_physical(allocation.code, 0, &code).map_err(|_| ())?;
    if matches!(
        probe,
        IsolationProbe::Success
            | IsolationProbe::InvalidOpcode
            | IsolationProbe::InvalidCallEncoding
            | IsolationProbe::InvalidPointer
            | IsolationProbe::OversizeMessage
            | IsolationProbe::InvalidStatus
    ) {
        troe_machine::copy_to_physical(allocation.data, 0, ISOLATED_MESSAGE).map_err(|_| ())?;
    }
    Ok(())
}

#[allow(clippy::needless_pass_by_value)] // Consuming the token prevents double teardown.
pub(crate) fn reclaim_isolated(
    frames: &mut FrameAllocator,
    allocation: IsolatedAllocation,
) -> Result<(), ()> {
    troe_machine::zero_physical_range(allocation.complete).map_err(|_| ())?;
    frames.free_range(allocation.complete).map_err(|_| ())
}

pub(crate) fn build_isolated_plan(
    kernel: &MappingPlan,
    allocation: &IsolatedAllocation,
) -> Result<MappingPlan, ()> {
    let mut plan = MappingPlan::new();
    let mut protected_code = false;
    for mapping in kernel.mappings() {
        let physical = mapping.physical_range();
        if allocation.code.start() < physical.end() && physical.start() < allocation.code.end() {
            if protected_code
                || allocation.code.start() < physical.start()
                || allocation.code.end() > physical.end()
                || mapping.virtual_range().start() != physical.start()
                || mapping.virtual_range().end() != physical.end()
                || mapping.permissions() != MappingPermissions::READ_WRITE
            {
                return Err(());
            }
            insert_identity_segment(
                &mut plan,
                *mapping,
                physical.start(),
                allocation.code.start(),
            )?;
            insert_identity_segment_with_permissions(
                &mut plan,
                *mapping,
                allocation.code.start(),
                allocation.code.end(),
                MappingPermissions::READ_ONLY,
            )?;
            insert_identity_segment(&mut plan, *mapping, allocation.code.end(), physical.end())?;
            protected_code = true;
        } else {
            plan.insert(*mapping).map_err(|_| ())?;
        }
    }
    if !protected_code {
        return Err(());
    }
    let user_mappings: [(u64, PhysicalRange, MappingPermissions); STAGE6_USER_REGIONS] = [
        (
            USER_CODE_BASE,
            allocation.code,
            MappingPermissions::READ_EXECUTE,
        ),
        (
            USER_DATA_BASE,
            allocation.data,
            MappingPermissions::READ_WRITE,
        ),
        (
            USER_STACK_BASE,
            allocation.stack,
            MappingPermissions::READ_WRITE,
        ),
    ];
    for (virtual_start, physical, permissions) in user_mappings {
        let virtual_range =
            VirtualRange::from_pages(virtual_start, physical.page_count()).map_err(|_| ())?;
        let mapping = Mapping::user(
            virtual_range,
            physical,
            permissions,
            MappingOwner::IsolatedTask,
            MappingLifetime::Task,
        )
        .map_err(|_| ())?;
        plan.insert(mapping).map_err(|_| ())?;
    }
    if !plan.enforces_global_w_xor_x() {
        return Err(());
    }
    Ok(plan)
}

pub(crate) fn insert_identity_segment(
    plan: &mut MappingPlan,
    template: Mapping,
    start: u64,
    end: u64,
) -> Result<(), ()> {
    insert_identity_segment_with_permissions(plan, template, start, end, template.permissions())
}

pub(crate) fn insert_identity_segment_with_permissions(
    plan: &mut MappingPlan,
    template: Mapping,
    start: u64,
    end: u64,
    permissions: MappingPermissions,
) -> Result<(), ()> {
    if start == end {
        return Ok(());
    }
    let pages = end.checked_sub(start).ok_or(())? / BASE_PAGE_SIZE;
    let range = PhysicalRange::from_pages(start, pages).map_err(|_| ())?;
    let mapping = Mapping::identity(
        range,
        permissions,
        template.memory_type(),
        template.owner(),
        template.lifetime(),
        template.remappable(),
    )
    .map_err(|_| ())?;
    plan.insert(mapping).map_err(|_| ())
}

pub(crate) fn isolated_program(probe: IsolationProbe) -> Result<Vec<u8>, ()> {
    #[cfg(target_arch = "x86_64")]
    {
        let mut code = Vec::new();
        match probe {
            IsolationProbe::Translation => {
                x86_mov_rax(&mut code, USER_UNMAPPED_BASE);
                code.extend_from_slice(&[0x48, 0x8b, 0x00]);
            }
            IsolationProbe::WritePermission => {
                x86_mov_rax(&mut code, USER_CODE_BASE);
                code.extend_from_slice(&[0xc6, 0x00, 0x00]);
            }
            IsolationProbe::ExecutePermission => {
                x86_mov_rax(&mut code, USER_DATA_BASE);
                code.extend_from_slice(&[0xff, 0xe0]);
            }
            IsolationProbe::IllegalInstruction => code.extend_from_slice(&[0x0f, 0x0b]),
            IsolationProbe::UnexpectedEntry => code.extend_from_slice(&[0x0f, 0x05]),
            IsolationProbe::Success
            | IsolationProbe::InvalidOpcode
            | IsolationProbe::InvalidCallEncoding
            | IsolationProbe::InvalidPointer
            | IsolationProbe::OversizeMessage
            | IsolationProbe::InvalidStatus => {
                let (opcode, address, length, status) = exit_call_parameters(probe)?;
                if matches!(
                    probe,
                    IsolationProbe::Success | IsolationProbe::InvalidOpcode
                ) {
                    // Enter with hostile user-controlled flags. The native
                    // gate must clear DF for Rust and AC before SMAP-aware
                    // validation/copying, then restore kernel RFLAGS.
                    code.push(0xfd);
                    code.extend_from_slice(&[0x9c, 0x81, 0x0c, 0x24, 0x00, 0x00, 0x04, 0x00, 0x9d]);
                }
                code.push(0xb8);
                code.extend_from_slice(&opcode.to_le_bytes());
                code.extend_from_slice(&[0x48, 0xbf]);
                code.extend_from_slice(&address.to_le_bytes());
                code.push(0xbe);
                code.extend_from_slice(&length.to_le_bytes());
                code.push(0xba);
                code.extend_from_slice(&status.to_le_bytes());
                code.extend_from_slice(&[0xcd, 0x80]);
            }
        }
        code.extend_from_slice(&[0x0f, 0x0b]);
        Ok(code)
    }
    #[cfg(target_arch = "aarch64")]
    {
        let mut words = Vec::new();
        match probe {
            IsolationProbe::Translation => {
                emit_aarch64_immediate(&mut words, 1, USER_UNMAPPED_BASE);
                words.push(0xf940_0020);
            }
            IsolationProbe::WritePermission => {
                emit_aarch64_immediate(&mut words, 1, USER_CODE_BASE);
                words.push(0xf900_003f);
            }
            IsolationProbe::ExecutePermission => {
                emit_aarch64_immediate(&mut words, 1, USER_DATA_BASE);
                words.push(0xd61f_0020);
            }
            IsolationProbe::IllegalInstruction => words.push(0xd420_0000),
            IsolationProbe::UnexpectedEntry => words.push(0xd400_0002),
            IsolationProbe::Success
            | IsolationProbe::InvalidOpcode
            | IsolationProbe::InvalidCallEncoding
            | IsolationProbe::InvalidPointer
            | IsolationProbe::OversizeMessage
            | IsolationProbe::InvalidStatus => {
                let (opcode, address, length, status) = exit_call_parameters(probe)?;
                emit_aarch64_immediate(&mut words, 0, u64::from(opcode));
                emit_aarch64_immediate(&mut words, 1, address);
                emit_aarch64_immediate(&mut words, 2, u64::from(length));
                emit_aarch64_immediate(&mut words, 3, u64::from(status));
                words.push(if probe == IsolationProbe::InvalidCallEncoding {
                    0xd400_0021
                } else {
                    0xd400_0001
                });
            }
        }
        words.push(0xd420_0000);
        let mut code = Vec::new();
        code.try_reserve_exact(words.len() * 4).map_err(|_| ())?;
        for word in words {
            code.extend_from_slice(&word.to_le_bytes());
        }
        Ok(code)
    }
}

pub(crate) fn exit_call_parameters(probe: IsolationProbe) -> Result<(u32, u64, u32, u32), ()> {
    let message_len = u32::try_from(ISOLATED_MESSAGE.len()).map_err(|_| ())?;
    Ok(match probe {
        IsolationProbe::Success => (1, USER_DATA_BASE, message_len, 0),
        IsolationProbe::InvalidOpcode => (99, USER_DATA_BASE, message_len, 0),
        IsolationProbe::InvalidCallEncoding => {
            #[cfg(target_arch = "x86_64")]
            {
                (99, USER_DATA_BASE, message_len, 0)
            }
            #[cfg(target_arch = "aarch64")]
            {
                (1, USER_DATA_BASE, message_len, 0)
            }
        }
        IsolationProbe::InvalidPointer => (1, USER_UNMAPPED_BASE, message_len, 0),
        IsolationProbe::OversizeMessage => (
            1,
            USER_DATA_BASE,
            u32::try_from(troe_dispatch::MAX_MESSAGE_BYTES + 1).map_err(|_| ())?,
            0,
        ),
        IsolationProbe::InvalidStatus => (1, USER_DATA_BASE, message_len, 256),
        IsolationProbe::Translation
        | IsolationProbe::WritePermission
        | IsolationProbe::ExecutePermission
        | IsolationProbe::IllegalInstruction
        | IsolationProbe::UnexpectedEntry => return Err(()),
    })
}

#[cfg(target_arch = "x86_64")]
pub(crate) fn x86_mov_rax(code: &mut Vec<u8>, value: u64) {
    code.extend_from_slice(&[0x48, 0xb8]);
    code.extend_from_slice(&value.to_le_bytes());
}

#[cfg(target_arch = "aarch64")]
pub(crate) fn emit_aarch64_immediate(words: &mut Vec<u32>, register: u8, value: u64) {
    let low = (value & 0xffff) as u32;
    words.push(0xd280_0000 | (low << 5) | u32::from(register));
    for halfword in 1..4_u32 {
        let immediate = ((value >> (halfword * 16)) & 0xffff) as u32;
        words.push(0xf280_0000 | (halfword << 21) | (immediate << 5) | u32::from(register));
    }
}
