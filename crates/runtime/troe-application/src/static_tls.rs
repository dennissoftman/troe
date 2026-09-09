//! Allocation-free layout and initialization of one local-exec static TLS block.
//!
//! This is a portable policy component, not an admitted KEX encoding. KEX loaders
//! and converters still reject TLS. The input describes a single linked template
//! with zero alignment residue; ELF alignment zero must first be normalized to
//! one. There is no dynamic TLS, DTV, libc-private TCB, or destructor registry.

use core::fmt;

use crate::{KEX_V1_USER_END, PAGE_SIZE, Target};

/// Size of the common local-exec displacement window (16 MiB).
///
/// This fits `AArch64`'s default 24-bit local-exec relocations and the signed
/// 32-bit x86-64 displacements. It is an encoding bound, not a resource grant.
pub const LOCAL_EXEC_BYTES: u64 = 1 << 24;

/// A rejected TLS description, placement, or initialization request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StaticTlsError {
    /// Alignment must be a nonzero power of two.
    InvalidAlignment,
    /// The initialized prefix is larger than the complete TLS template.
    InvalidTemplateSize,
    /// Size or alignment arithmetic overflowed.
    ArithmeticOverflow,
    /// The TLS displacement exceeds the common local-exec profile.
    OffsetLimit,
    /// The complete page-rounded allocation exceeds its caller's budget.
    PageBudget,
    /// The mapping is misaligned, includes page zero, or leaves the user range.
    InvalidMapping,
    /// The supplied template or destination has a different length from the plan.
    InvalidBufferSize,
}

impl fmt::Display for StaticTlsError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidAlignment => "TLS alignment must be a nonzero power of two",
            Self::InvalidTemplateSize => "TLS initialized bytes exceed memory bytes",
            Self::ArithmeticOverflow => "TLS size arithmetic overflow",
            Self::OffsetLimit => "TLS exceeds the 16 MiB local-exec displacement profile",
            Self::PageBudget => "TLS mapping exceeds its page budget",
            Self::InvalidMapping => "TLS mapping is outside the aligned user range",
            Self::InvalidBufferSize => "TLS buffers do not match the layout",
        })
    }
}

/// Checked geometry for a separately allocated per-thread TLS mapping.
///
/// x86-64 places its template before FS base and stores the linear thread pointer
/// at FS:0. `AArch64` places its template after the 16-byte TCB at `TPIDR_EL0`, rounded
/// up to the template alignment. The control bytes have no libc-private meaning.
/// Padding, control bytes and the final partial page are charged and initialized.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StaticTlsLayout {
    target: Target,
    file_bytes: u64,
    memory_bytes: u64,
    alignment: u64,
    template_offset: u64,
    thread_pointer_offset: u64,
    mapped_bytes: u64,
}

fn round_up(value: u64, alignment: u64) -> Result<u64, StaticTlsError> {
    value
        .checked_add(alignment - 1)
        .map(|value| value & !(alignment - 1))
        .ok_or(StaticTlsError::ArithmeticOverflow)
}

impl StaticTlsLayout {
    /// Plan one canonical template, including a control block for empty TLS.
    ///
    /// `max_pages` bounds the entire mapping, including all padding. It excludes
    /// page tables, guard reservations, stacks, IPC buffers and runtime metadata;
    /// this helper cannot establish complete thread admission on its own.
    ///
    /// # Errors
    /// Rejects invalid lengths/alignment, overflow, an unrepresentable local-exec
    /// offset, or a mapping larger than `max_pages`.
    pub fn new(
        target: Target,
        file_bytes: u64,
        memory_bytes: u64,
        alignment: u64,
        max_pages: u64,
    ) -> Result<Self, StaticTlsError> {
        if !alignment.is_power_of_two() {
            return Err(StaticTlsError::InvalidAlignment);
        }
        if file_bytes > memory_bytes {
            return Err(StaticTlsError::InvalidTemplateSize);
        }
        let (template_offset, thread_pointer_offset, end) = match target {
            Target::X86_64 => {
                let span = round_up(memory_bytes, alignment)?;
                if span > LOCAL_EXEC_BYTES {
                    return Err(StaticTlsError::OffsetLimit);
                }
                // Preserve the linker's negative displacement even when its
                // template alignment is smaller than the self-pointer word.
                let pointer = round_up(span, 8)?;
                let end = pointer
                    .checked_add(8)
                    .ok_or(StaticTlsError::ArithmeticOverflow)?;
                (pointer - span, pointer, end)
            }
            Target::Aarch64 => {
                let template = round_up(16, alignment)?;
                let end = template
                    .checked_add(memory_bytes)
                    .ok_or(StaticTlsError::ArithmeticOverflow)?;
                if end > LOCAL_EXEC_BYTES {
                    return Err(StaticTlsError::OffsetLimit);
                }
                (template, 0, end)
            }
        };
        // Bound alignment independently of memsz: empty x86 TLS must not be
        // able to demand an arbitrarily large address-alignment reservation.
        if alignment > LOCAL_EXEC_BYTES {
            return Err(StaticTlsError::OffsetLimit);
        }
        let mapped_bytes = round_up(end, PAGE_SIZE)?;
        if mapped_bytes / PAGE_SIZE > max_pages {
            return Err(StaticTlsError::PageBudget);
        }
        Ok(Self {
            target,
            file_bytes,
            memory_bytes,
            alignment,
            template_offset,
            thread_pointer_offset,
            mapped_bytes,
        })
    }

    /// Initialized bytes copied from the single linked template.
    #[must_use]
    pub const fn file_bytes(self) -> u64 {
        self.file_bytes
    }

    /// Template size including zero-filled TLS, but excluding the control block.
    #[must_use]
    pub const fn memory_bytes(self) -> u64 {
        self.memory_bytes
    }

    /// Required alignment of the mapping's virtual base.
    #[must_use]
    pub const fn mapping_alignment(self) -> u64 {
        if self.alignment > PAGE_SIZE {
            self.alignment
        } else {
            PAGE_SIZE
        }
    }

    /// Template offset from the mapping base, not from the thread pointer.
    #[must_use]
    pub const fn template_offset(self) -> u64 {
        self.template_offset
    }

    /// FS base or `TPIDR_EL0` offset from the mapping base.
    #[must_use]
    pub const fn thread_pointer_offset(self) -> u64 {
        self.thread_pointer_offset
    }

    /// Complete page-rounded size which must be charged before allocation.
    #[must_use]
    pub const fn mapped_bytes(self) -> u64 {
        self.mapped_bytes
    }

    /// Physical data pages required for the complete TLS mapping.
    #[must_use]
    pub const fn pages(self) -> u64 {
        self.mapped_bytes / PAGE_SIZE
    }

    /// Initialize every mapped byte and return the application thread pointer.
    ///
    /// The caller supplies the final virtual base and exact initialized template
    /// bytes, including any already-resolved image-relative initializers. This
    /// function neither authenticates the template nor maps or publishes memory.
    /// The caller must own a quiescent destination and establish writable,
    /// non-executable mappings without exposing stale bytes during initialization.
    /// TLS is process-private; it is not secret from sibling threads.
    ///
    /// # Errors
    /// Checks all lengths and virtual geometry before writing. On any error the
    /// destination remains unchanged. On success even padding is overwritten.
    pub fn initialize(
        self,
        virtual_base: u64,
        template: &[u8],
        destination: &mut [u8],
    ) -> Result<u64, StaticTlsError> {
        if virtual_base < PAGE_SIZE
            || !virtual_base.is_multiple_of(self.mapping_alignment())
            || virtual_base
                .checked_add(self.mapped_bytes)
                .is_none_or(|end| end > KEX_V1_USER_END)
        {
            return Err(StaticTlsError::InvalidMapping);
        }
        if u64::try_from(template.len()) != Ok(self.file_bytes)
            || u64::try_from(destination.len()) != Ok(self.mapped_bytes)
        {
            return Err(StaticTlsError::InvalidBufferSize);
        }
        let template_start = usize::try_from(self.template_offset)
            .map_err(|_| StaticTlsError::ArithmeticOverflow)?;
        let pointer_start = usize::try_from(self.thread_pointer_offset)
            .map_err(|_| StaticTlsError::ArithmeticOverflow)?;
        // Private fields and successful construction bound all ranges below by
        // mapped_bytes. The checked mapping bounds this addition by USER_END.
        let pointer = virtual_base + self.thread_pointer_offset;
        destination.fill(0);
        destination[template_start..template_start + template.len()].copy_from_slice(template);
        if self.target == Target::X86_64 {
            destination[pointer_start..pointer_start + 8].copy_from_slice(&pointer.to_le_bytes());
        }
        Ok(pointer)
    }
}

#[cfg(test)]
mod tests;
