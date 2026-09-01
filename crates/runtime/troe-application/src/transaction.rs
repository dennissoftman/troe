//! Ordered loader resource ownership with atomic release on failure.

/// One provisional resource class acquired by the native loader transaction.
///
/// The order is part of the loader contract: bounded staging precedes frames,
/// inactive tables, the scheduler task record, and the initial handle owner.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum LoaderResource {
    /// Bounded kernel-owned format-verifier scratch storage.
    Staging = 0,
    /// Zeroable private-frame allocation, including the table reservation.
    Frames = 1,
    /// Constructed but not yet active application page-table root.
    Tables = 2,
    /// Provisional scheduler task and its resource accounting record.
    Task = 3,
    /// Initial owner-scoped handle set.
    Handles = 4,
}

impl LoaderResource {
    const ALL: [Self; 5] = [
        Self::Staging,
        Self::Frames,
        Self::Tables,
        Self::Task,
        Self::Handles,
    ];

    const REVERSE: [Self; 5] = [
        Self::Handles,
        Self::Task,
        Self::Tables,
        Self::Frames,
        Self::Staging,
    ];

    const fn bit(self) -> u8 {
        1 << self as u8
    }
}

/// Invalid transition in the provisional native loader transaction.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LoaderTransactionError {
    /// A resource was recorded other than in the fixed acquisition order.
    OutOfOrder,
    /// Commit was attempted before every provisional resource was acquired.
    Incomplete,
    /// A transition was attempted after the transaction committed.
    AlreadyCommitted,
}

/// Allocation-free ownership ledger for the native loader's pre-entry phase.
///
/// Native code performs each real acquisition, then records it here. Before
/// commit, rollback visits every recorded resource in strict reverse order.
/// Commit is possible only after the complete staging/frame/table/task/handle
/// sequence, and is the sole transition that marks the root eligible for
/// activation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LoaderTransaction {
    owned: u8,
    next: u8,
    committed: bool,
}

impl LoaderTransaction {
    const ALL_OWNED: u8 = (1 << LoaderResource::ALL.len()) - 1;

    /// Begin an empty transaction whose application root is inactive.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            owned: 0,
            next: 0,
            committed: false,
        }
    }

    /// Record one successfully acquired provisional resource.
    ///
    /// # Errors
    ///
    /// Returns an error after commit or when `resource` is not the next member
    /// of the fixed acquisition sequence.
    pub fn acquire(&mut self, resource: LoaderResource) -> Result<(), LoaderTransactionError> {
        if self.committed {
            return Err(LoaderTransactionError::AlreadyCommitted);
        }
        if usize::from(self.next) >= LoaderResource::ALL.len()
            || LoaderResource::ALL[usize::from(self.next)] != resource
        {
            return Err(LoaderTransactionError::OutOfOrder);
        }
        self.owned |= resource.bit();
        self.next += 1;
        Ok(())
    }

    /// Release every provisional resource in reverse acquisition order.
    ///
    /// The callback performs or observes the concrete cleanup. This method
    /// clears a bit only after its callback returns, making exhaustive hosted
    /// failpoint tests use the same state machine as native loading.
    pub fn rollback(&mut self, mut release: impl FnMut(LoaderResource)) {
        if self.committed {
            return;
        }
        for resource in LoaderResource::REVERSE {
            if self.owned & resource.bit() != 0 {
                release(resource);
                self.owned &= !resource.bit();
            }
        }
        self.next = 0;
    }

    /// Transfer all provisional resources to the runnable task atomically.
    ///
    /// # Errors
    ///
    /// Returns an error if the transaction already committed or if any
    /// acquisition phase is missing.
    pub fn commit(&mut self) -> Result<(), LoaderTransactionError> {
        if self.committed {
            return Err(LoaderTransactionError::AlreadyCommitted);
        }
        if self.owned != Self::ALL_OWNED {
            return Err(LoaderTransactionError::Incomplete);
        }
        self.owned = 0;
        self.committed = true;
        Ok(())
    }

    /// Number of provisional resource classes still retained by this ledger.
    #[must_use]
    pub const fn provisional_resources(self) -> u32 {
        self.owned.count_ones()
    }

    /// Whether commit has made the constructed root eligible for activation.
    #[must_use]
    pub const fn mapping_active(self) -> bool {
        self.committed
    }
}

impl Default for LoaderTransaction {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec::Vec;

    #[test]
    fn loader_transaction_failpoints_release_every_provisional_owner() {
        for failed_index in 0..LoaderResource::ALL.len() {
            let mut transaction = LoaderTransaction::new();
            let mut live = [false; LoaderResource::ALL.len()];
            for (index, resource) in LoaderResource::ALL.iter().copied().enumerate() {
                if index == failed_index {
                    break;
                }
                live[index] = true;
                assert_eq!(transaction.acquire(resource), Ok(()));
            }
            assert!(!transaction.mapping_active());
            let mut released = [None; LoaderResource::ALL.len()];
            let mut release_count = 0;
            transaction.rollback(|resource| {
                let index = resource as usize;
                assert!(live[index]);
                live[index] = false;
                released[release_count] = Some(resource);
                release_count += 1;
            });
            assert!(live.iter().all(|owned| !owned));
            assert_eq!(transaction.provisional_resources(), 0);
            assert!(!transaction.mapping_active());
            let expected = LoaderResource::ALL[..failed_index]
                .iter()
                .rev()
                .copied()
                .collect::<Vec<_>>();
            let actual = released[..release_count]
                .iter()
                .flatten()
                .copied()
                .collect::<Vec<_>>();
            assert_eq!(actual, expected);
        }
    }

    #[test]
    fn loader_transaction_requires_complete_ordered_commit() {
        let mut transaction = LoaderTransaction::new();
        assert_eq!(
            transaction.acquire(LoaderResource::Frames),
            Err(LoaderTransactionError::OutOfOrder)
        );
        assert_eq!(
            transaction.commit(),
            Err(LoaderTransactionError::Incomplete)
        );
        for resource in LoaderResource::ALL {
            assert_eq!(transaction.acquire(resource), Ok(()));
        }
        assert_eq!(transaction.commit(), Ok(()));
        assert!(transaction.mapping_active());
        assert_eq!(transaction.provisional_resources(), 0);
        assert_eq!(
            transaction.acquire(LoaderResource::Staging),
            Err(LoaderTransactionError::AlreadyCommitted)
        );
        assert_eq!(
            transaction.commit(),
            Err(LoaderTransactionError::AlreadyCommitted)
        );
    }
}
