//! Short metadata loans and owned service operations. No table lock crosses I/O.

use core::{
    cell::UnsafeCell,
    sync::atomic::{AtomicBool, Ordering},
};

use troe_kex_runtime::errno;

/// Internal exclusion for callback-free state transitions. The allocator uses
/// its own instance and may invoke only backing operations independent of
/// sibling progress. Neither use may run user code or voluntarily exit a thread.
pub(super) struct Locked<T> {
    locked: AtomicBool,
    value: UnsafeCell<T>,
}

impl<T> Locked<T> {
    pub(super) const fn new(value: T) -> Self {
        Self {
            locked: AtomicBool::new(false),
            value: UnsafeCell::new(value),
        }
    }

    pub(super) fn with<R>(&self, operation: impl FnOnce(&mut T) -> R) -> R {
        while self
            .locked
            .compare_exchange_weak(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            core::hint::spin_loop();
        }
        let _release = Release(&self.locked);
        // SAFETY: The acquired flag excludes all other loans. The closure's
        // result cannot retain a reference to the temporary mutable loan.
        operation(unsafe { &mut *self.value.get() })
    }
}

// SAFETY: Every value access is serialized; ownership can cross threads only
// when T itself permits that transfer. This does not make Runtime Sync.
unsafe impl<T: Send> Sync for Locked<T> {}

struct Release<'a>(&'a AtomicBool);

impl Drop for Release<'_> {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Release);
    }
}

const INDEX_BITS: u32 = 5;
const INDEX_MASK: u32 = (1 << INDEX_BITS) - 1;
const MAX_GENERATION: u32 = u32::MAX >> INDEX_BITS;

enum State<T> {
    Vacant,
    Ready(T),
    Busy,
}

struct Slot<T> {
    generation: u32,
    state: State<T>,
}

impl<T> Slot<T> {
    const fn new() -> Self {
        Self {
            generation: 0,
            state: State::Vacant,
        }
    }
}

/// A fixed table of generation-qualified resources. A lease moves its value
/// out of the table, retaining only a Busy marker while a service can block.
pub(super) struct Slots<T, const N: usize> {
    slots: Locked<[Slot<T>; N]>,
}

impl<T, const N: usize> Slots<T, N> {
    pub(super) const fn new() -> Self {
        assert!(N > 0 && N <= 32);
        Self {
            slots: Locked::new([const { Slot::new() }; N]),
        }
    }

    /// Reserve before invoking an open/begin service. Failed opens still spend
    /// their generation; an exhausted slot can never alias an old token.
    pub(super) fn reserve(&self) -> Result<Lease<'_, T, N>, i32> {
        self.slots.with(|slots| {
            for (index, slot) in slots.iter_mut().enumerate() {
                if !matches!(slot.state, State::Vacant) || slot.generation == MAX_GENERATION {
                    continue;
                }
                slot.generation += 1;
                slot.state = State::Busy;
                let token =
                    (slot.generation << INDEX_BITS) | u32::try_from(index).unwrap_or(INDEX_MASK);
                return Ok(Lease {
                    table: self,
                    index,
                    token,
                    value: None,
                });
            }
            Err(errno::ENOMEM)
        })
    }

    /// Move one exact live resource into an operation. A competing operation
    /// gets EBUSY; a malformed, closed or superseded token gets EINVAL.
    pub(super) fn acquire(&self, token: u32) -> Result<Lease<'_, T, N>, i32> {
        let generation = token >> INDEX_BITS;
        let index = usize::try_from(token & INDEX_MASK).map_err(|_| errno::EINVAL)?;
        if generation == 0 || index >= N {
            return Err(errno::EINVAL);
        }
        self.slots.with(|slots| {
            let slot = &mut slots[index];
            if slot.generation != generation {
                return Err(errno::EINVAL);
            }
            match slot.state {
                State::Vacant => return Err(errno::EINVAL),
                State::Busy => return Err(errno::EBUSY),
                State::Ready(_) => {}
            }
            let State::Ready(value) = core::mem::replace(&mut slot.state, State::Busy) else {
                unreachable!();
            };
            Ok(Lease {
                table: self,
                index,
                token,
                value: Some(value),
            })
        })
    }
}

pub(super) struct Lease<'a, T, const N: usize> {
    table: &'a Slots<T, N>,
    index: usize,
    token: u32,
    pub(super) value: Option<T>,
}

impl<T, const N: usize> Lease<'_, T, N> {
    pub(super) const fn token(&self) -> u32 {
        self.token
    }
}

impl<T, const N: usize> Drop for Lease<'_, T, N> {
    fn drop(&mut self) {
        // The private lease is unique. Its slot stays Busy until this point,
        // including across close/finish calls after value has been consumed.
        let state = self.value.take().map_or(State::Vacant, State::Ready);
        self.table
            .slots
            .with(|slots| slots[self.index].state = state);
    }
}

#[cfg(test)]
mod tests;
