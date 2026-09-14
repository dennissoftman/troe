//! Captured ordinary service calls with immutable requests and owned completion.

use super::{NativeProcessBacking, NativeProcessContext, ThreadContext};
use crate::mmu::{self, ApplicationCall, ApplicationPending, MmuError};
use troe_task::thread::ThreadId;

/// Native capture identity; capability authentication remains a composition duty.
///
/// The request belongs to the retained context, never to mutable user memory.
/// This descriptor carries no right to execute the requested service operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NativeHandleCall {
    caller: ThreadId,
    sequence: u64,
    pair_slot: usize,
    pair_generation: u64,
    call: ApplicationCall,
}
impl NativeHandleCall {
    /// Captured process-scoped caller incarnation.
    #[must_use]
    pub const fn caller(self) -> ThreadId {
        self.caller
    }

    /// Unauthenticated handle token to resolve against the process's live grants.
    #[must_use]
    pub const fn handle(self) -> u64 {
        self.call.handle()
    }

    /// Exact immutable request length, including its two-byte opcode.
    #[must_use]
    pub const fn request_bytes(self) -> usize {
        self.call.request_bytes()
    }

    /// Original caller's bounded RX prefix capacity.
    #[must_use]
    pub const fn reply_capacity(self) -> usize {
        self.call.reply_capacity()
    }
}

/// One claimed service execution or retained wait, without a borrow or user pointer.
///
/// Claim after trusted capability authentication. Dropping this value does not
/// make the call executable again; its process must be stopped if it is abandoned.
#[derive(Debug, Eq, PartialEq)]
#[must_use = "Complete the owned call or stop its process"]
pub struct NativeHandleExecution {
    operation: NativeHandleCall,
}
impl NativeHandleExecution {
    /// Original capture, for immutable request access and trusted wait correlation.
    #[must_use]
    pub const fn operation(&self) -> NativeHandleCall {
        self.operation
    }
}

pub(super) struct PendingHandleCall {
    pub(super) operation: NativeHandleCall,
    claimed: bool,
}

/// Copy before releasing the native owner to any sibling entry.
pub(super) fn capture(
    backing: &NativeProcessBacking,
    context: &mut ThreadContext,
    sequence: u64,
    call: ApplicationCall,
) -> Result<NativeHandleCall, MmuError> {
    let ipc = context.ipc.ok_or(MmuError::InvalidUserContext)?;
    let pair = backing
        .pairs
        .get(ipc.index)
        .filter(|pair| pair.is_live())
        .ok_or(MmuError::InvalidUserContext)?;
    if context.handle_operation.is_some()
        || context.scheduler_operation.is_some()
        || call.request_address != ipc.tx
        || call.reply_address != ipc.tx + 4096
        || !(2..=troe_abi::MAX_MESSAGE_BYTES).contains(&call.request_bytes)
        || call.reply_capacity > troe_abi::MAX_MESSAGE_BYTES
        || mmu::architecture_translate_page(backing.address_space.root, ipc.tx)?
            != pair.range().start()
        || mmu::architecture_translate_page(backing.address_space.root, ipc.tx + 4096)?
            != pair.range().start() + 4096
    {
        return Err(MmuError::InvalidUserContext);
    }
    context.clear_handle_request();
    mmu::copy_user_from_physical(
        backing.address_space.root,
        &backing.address_space.regions,
        ipc.tx,
        &mut context.handle_request[..call.request_bytes],
    )?;
    let operation = NativeHandleCall {
        caller: context.id,
        sequence,
        pair_slot: pair.slot(),
        pair_generation: pair.generation(),
        call,
    };
    context.handle_operation = Some(PendingHandleCall {
        operation,
        claimed: false,
    });
    Ok(operation)
}

impl NativeProcessContext {
    /// Borrow the original kernel capture without rereading the caller's TX page.
    ///
    /// The immutable native-owner borrow cannot cross a sibling entry or mutable
    /// completion. A retained service wait owns its execution separately.
    ///
    /// # Errors
    /// Rejects stopped, stale, foreign, completed or mismatched call/pair identities.
    pub fn handle_request(&self, operation: NativeHandleCall) -> Result<&[u8], MmuError> {
        let index = self.handle_index(operation, None)?;
        Ok(&self.contexts[index].handle_request[..operation.request_bytes()])
    }

    /// Claim one capture for execution after trusted capability authentication.
    ///
    /// # Errors
    /// Rejects duplicate, stale, stopped or foreign claims without writes.
    pub fn claim_handle(
        &mut self,
        operation: NativeHandleCall,
    ) -> Result<NativeHandleExecution, MmuError> {
        let index = self.handle_index(operation, Some(false))?;
        self.contexts[index]
            .handle_operation
            .as_mut()
            .ok_or(MmuError::InvalidUserContext)?
            .claimed = true;
        Ok(NativeHandleExecution { operation })
    }

    /// Complete an unclaimed capture, including a capability rejection.
    ///
    /// Claimed executions must use the owned completion path. No user code runs
    /// and no timer is armed. Service authority remains a composition obligation.
    ///
    /// # Errors
    /// Rejects invalid identity, status or reply length before writes; native
    /// publication failure stops every continuation in the process.
    pub fn complete_handle(
        &mut self,
        operation: NativeHandleCall,
        status: u32,
        reply: &[u8],
    ) -> Result<(), MmuError> {
        self.complete_handle_inner(operation, status, reply, false)
    }

    /// Consume this exact execution and publish its original caller's reply.
    ///
    /// Completion clears the whole RX page before publishing the bounded prefix,
    /// updates the retained ABI results and makes native state resumable under a
    /// separately selected process turn. It neither enters userspace nor wakes
    /// policy state; composition must consume its matching policy wait first.
    ///
    /// # Errors
    /// Returns ownership on preflight failure without writes. Publication failure
    /// stops the process and also returns the now-revoked execution for retirement.
    #[allow(clippy::result_large_err)]
    pub fn complete_handle_execution(
        &mut self,
        execution: NativeHandleExecution,
        status: u32,
        reply: &[u8],
    ) -> Result<(), (MmuError, NativeHandleExecution)> {
        self.complete_handle_inner(execution.operation, status, reply, true)
            .map_err(|error| (error, execution))
    }

    fn handle_index(
        &self,
        operation: NativeHandleCall,
        claimed: Option<bool>,
    ) -> Result<usize, MmuError> {
        let (ipc, pair) = self.bound_ipc(operation.caller)?;
        if pair.slot() != operation.pair_slot
            || pair.generation() != operation.pair_generation
            || ipc.tx != operation.call.request_address
            || ipc.tx + 4096 != operation.call.reply_address
            || mmu::architecture_translate_page(self.backing.address_space.root, ipc.tx)?
                != pair.range().start()
            || mmu::architecture_translate_page(self.backing.address_space.root, ipc.tx + 4096)?
                != pair.range().start() + 4096
        {
            return Err(MmuError::InvalidUserContext);
        }
        self.contexts
            .iter()
            .position(|context| {
                context.id == operation.caller
                    && context.pending == ApplicationPending::HandleCall(operation.call)
                    && context.handle_operation.as_ref().is_some_and(|pending| {
                        pending.operation == operation
                            && claimed.is_none_or(|claimed| pending.claimed == claimed)
                    })
            })
            .ok_or(MmuError::InvalidUserContext)
    }

    fn complete_handle_inner(
        &mut self,
        operation: NativeHandleCall,
        status: u32,
        reply: &[u8],
        claimed: bool,
    ) -> Result<(), MmuError> {
        let index = self.handle_index(operation, Some(claimed))?;
        if !troe_abi::reply::is_known(status) || reply.len() > operation.reply_capacity() {
            return Err(MmuError::InvalidUserContext);
        }
        let bytes = u64::try_from(reply.len()).map_err(|_| MmuError::InvalidUserContext)?;
        self.publish_thread_rx(operation.caller, reply)?;
        let context = &mut self.contexts[index];
        mmu::application_context_set_results(&mut context.registers, status, bytes);
        context.pending = ApplicationPending::Timeslice;
        context.handle_operation = None;
        context.clear_handle_request();
        Ok(())
    }
}
