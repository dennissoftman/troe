//! Retained PCID/ASID ownership and synchronous invalidation proofs.

#[cfg(target_arch = "x86_64")]
use super::KERNEL_ROOT;
use super::MmuError;
use core::sync::atomic::{AtomicU8, AtomicU64, Ordering};

static MODE: AtomicU8 = AtomicU8::new(0);
static OWNERS: [AtomicU64; 16] = [const { AtomicU64::new(0) }; 16];
static ROOTS: [AtomicU64; 16] = [const { AtomicU64::new(0) }; 16];
static INCARNATIONS: [AtomicU64; 16] = [const { AtomicU64::new(0) }; 16];
static HITS: AtomicU64 = AtomicU64::new(0);
static WRITES: AtomicU64 = AtomicU64::new(0);
static TARGETED: AtomicU64 = AtomicU64::new(0);
static FULL: AtomicU64 = AtomicU64::new(0);
static REUSES: AtomicU64 = AtomicU64::new(0);

/// Native translation counters, independent of compatibility-boundary counters.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct TagStats {
    /// Hardware tagging is enabled; false identifies the correctness fallback.
    pub supported: bool,
    /// No-flush task-root activations.
    pub hits: u64,
    /// Direct task-root writes.
    pub root_writes: u64,
    /// Completed tag or address-and-tag invalidations.
    pub targeted_invalidations: u64,
    /// Full invalidations required by fallback activations.
    pub full_invalidations: u64,
    /// Published noninitial task-slot incarnations.
    pub reuse: u64,
}

fn count(counter: &AtomicU64) {
    let _ = counter.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
        Some(value.saturating_add(1))
    });
}

/// Snapshot native retained-tag counters.
#[must_use]
pub fn tag_stats() -> TagStats {
    TagStats {
        supported: MODE.load(Ordering::Acquire) == 2,
        hits: HITS.load(Ordering::Relaxed),
        root_writes: WRITES.load(Ordering::Relaxed),
        targeted_invalidations: TARGETED.load(Ordering::Relaxed),
        full_invalidations: FULL.load(Ordering::Relaxed),
        reuse: REUSES.load(Ordering::Relaxed),
    }
}

/// Non-owning incarnation used to verify stale-tag rejection.
#[cfg(feature = "acceptance-probes")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TagIdentity {
    slot: usize,
    generation: u64,
    root: u64,
}

#[cfg(feature = "acceptance-probes")]
impl TagIdentity {
    /// Use exactly the ownership check required before a native activation.
    #[must_use]
    pub fn is_live(self) -> bool {
        live(self.slot, self.generation, self.root)
    }
}

fn live(slot: usize, generation: u64, root: u64) -> bool {
    OWNERS[slot].load(Ordering::Acquire) == generation
        && ROOTS[slot].load(Ordering::Acquire) == root
}

#[derive(Debug, Eq, PartialEq)]
pub(super) struct TagLease {
    slot: usize,
    generation: u64,
    root: u64,
}

impl TagLease {
    pub(super) fn bind(slot: usize, generation: u64, root: u64) -> Result<Self, MmuError> {
        if slot >= 16 || generation == 0 || root == 0 || root & 4095 != 0 {
            return Err(MmuError::InvalidUserContext);
        }
        if MODE.load(Ordering::Acquire) == 0 {
            MODE.store(if initialize()? { 2 } else { 1 }, Ordering::Release);
        }
        let previous = INCARNATIONS[slot].load(Ordering::Acquire);
        if generation <= previous {
            return Err(MmuError::InvalidUserContext);
        }
        if OWNERS[slot]
            .compare_exchange(0, generation, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return Err(MmuError::InvalidUserContext);
        }
        let tag = Self {
            slot,
            generation,
            root,
        };
        // Flush before the first possible activation as well as before reuse.
        tag.invalidate(None);
        INCARNATIONS[slot].store(generation, Ordering::Release);
        ROOTS[slot].store(root, Ordering::Release);
        if previous != 0 {
            count(&REUSES);
        }
        Ok(tag)
    }

    pub(super) fn live(&self) -> bool {
        live(self.slot, self.generation, self.root)
    }

    #[cfg(feature = "acceptance-probes")]
    pub(super) const fn identity(&self) -> TagIdentity {
        TagIdentity {
            slot: self.slot,
            generation: self.generation,
            root: self.root,
        }
    }

    pub(super) fn activate(&self) -> Result<(), MmuError> {
        if !self.live() {
            return Err(MmuError::InvalidUserContext);
        }
        activate(self.root, self.slot as u64 + 1);
        count(&WRITES);
        if MODE.load(Ordering::Acquire) == 2 {
            count(&HITS);
        } else {
            count(&FULL);
        }
        Ok(())
    }

    pub(super) fn invalidate_range(&self, start: u64, pages: u64) -> Result<(), MmuError> {
        if !self.live() {
            return Err(MmuError::InvalidUserContext);
        }
        for page in 0..pages {
            let address = page
                .checked_mul(4096)
                .and_then(|offset| start.checked_add(offset))
                .ok_or(MmuError::AddressUnsupported)?;
            self.invalidate(Some(address));
        }
        Ok(())
    }

    fn invalidate(&self, address: Option<u64>) {
        if MODE.load(Ordering::Acquire) == 2 {
            invalidate(self.slot as u64 + 1, address);
            count(&TARGETED);
        }
        // Fallback roots always flush on activation and never retain a tag.
    }
}

impl Drop for TagLease {
    fn drop(&mut self) {
        // The owning root is already inactive when its retained lease drops.
        // Invalidation completes before either root frames or slot can be reused.
        self.invalidate(None);
        ROOTS[self.slot].store(0, Ordering::Release);
        OWNERS[self.slot].store(0, Ordering::Release);
    }
}

#[cfg(target_arch = "x86_64")]
fn initialize() -> Result<bool, MmuError> {
    // SAFETY: CPUID is read-only and the kernel runs at CPL0 with its owned,
    // page-aligned PCID-zero root installed before any task is published.
    unsafe {
        use core::arch::x86_64::{__cpuid, __cpuid_count};
        if __cpuid(0).eax < 7
            || __cpuid(1).ecx & (1 << 17) == 0
            || __cpuid_count(7, 0).ebx & (1 << 10) == 0
        {
            return Ok(false);
        }
        let root: u64;
        let mut cr4: u64;
        core::arch::asm!("mov {}, cr3", out(reg) root, options(nomem, nostack));
        if root != KERNEL_ROOT.load(Ordering::Acquire) || root & 4095 != 0 {
            return Err(MmuError::InvalidPlan);
        }
        core::arch::asm!("mov {}, cr4", out(reg) cr4, options(nomem, nostack));
        cr4 |= 1 << 17;
        core::arch::asm!("mov cr4, {}", in(reg) cr4, options(nostack));
    }
    Ok(true)
}

#[cfg(target_arch = "aarch64")]
fn initialize() -> Result<bool, MmuError> {
    let features: u64;
    let tcr: u64;
    // SAFETY: These read-only registers describe the already owned EL1 regime.
    unsafe {
        core::arch::asm!("mrs {}, id_aa64mmfr0_el1", out(reg) features, options(nomem, nostack));
        core::arch::asm!("mrs {}, tcr_el1", out(reg) tcr, options(nomem, nostack));
    }
    // ASIDBits is 0 for eight bits and 2 for sixteen. Use the low eight bits
    // in either case, with A1=0 and AS=0 as installed by architecture_activate.
    if !matches!((features >> 4) & 15, 0 | 2) || tcr & ((1 << 22) | (1 << 36)) != 0 {
        return Err(MmuError::UnsupportedCpu);
    }
    Ok(true)
}

#[cfg(target_arch = "x86_64")]
fn invalidate(tag: u64, address: Option<u64>) {
    let descriptor = [tag, address.unwrap_or(0)];
    let kind: u64 = if address.is_some() { 0 } else { 1 };
    // SAFETY: PCID and INVPCID were both detected. This 128-bit descriptor
    // has no reserved bits; type 0 targets one address, type 1 one context.
    unsafe {
        core::arch::asm!("invpcid {kind}, [{descriptor}]", kind = in(reg) kind,
        descriptor = in(reg) descriptor.as_ptr(), options(nostack));
    }
}

#[cfg(target_arch = "aarch64")]
fn invalidate(tag: u64, address: Option<u64>) {
    let operand = (tag << 48) | address.map_or(0, |address| address >> 12);
    // SAFETY: User leaves are non-global and carry this TTBR0 ASID. DSB
    // orders page-table writes and waits for completion before frame reuse.
    unsafe {
        core::arch::asm!("dsb ishst", options(nostack));
        if address.is_some() {
            core::arch::asm!("tlbi vae1, {}", in(reg) operand, options(nostack));
        } else {
            core::arch::asm!("tlbi aside1, {}", in(reg) operand, options(nostack));
        }
        core::arch::asm!("dsb ish", "isb", options(nostack));
    }
}

#[cfg(target_arch = "x86_64")]
fn activate(root: u64, tag: u64) {
    let root = if MODE.load(Ordering::Acquire) == 2 {
        root | tag | (1 << 63)
    } else {
        root
    };
    // SAFETY: The root/tag owner was validated and kernel mappings are shared.
    unsafe {
        core::arch::asm!("mov cr3, {}", in(reg) root, options(nostack));
    }
}

#[cfg(target_arch = "aarch64")]
fn activate(root: u64, tag: u64) {
    // SAFETY: Validated retained ASID and identical supervisor mappings. No
    // user translation is global, so switching TTBR requires no invalidation.
    unsafe {
        core::arch::asm!("msr ttbr0_el1, {}", "isb", in(reg) (root | tag << 48), options(nostack));
    }
}
