//! Compiled storage requests for fixed-capacity portable tables.

use core::alloc::Layout;

/// Inline table layout and its independently allocated backing arrays.
///
/// Layouts come from the actual Rust record types for the current compilation;
/// they are not a wire ABI or hard-coded estimates. The total counts requested
/// storage, including record padding and unused capacity. Allocator bookkeeping,
/// allocation rounding/fragmentation and native context/runtime storage are
/// separate physical costs. A byte budget does not guarantee allocation success.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TableMetadata<const N: usize> {
    inline: Layout,
    buffers: [Layout; N],
    bytes: usize,
}

impl<const N: usize> TableMetadata<N> {
    pub(super) fn new<T>(buffers: [Layout; N]) -> Option<Self> {
        let inline = Layout::new::<T>();
        let bytes = buffers.iter().try_fold(inline.size(), |total, buffer| {
            total.checked_add(buffer.size())
        })?;
        Some(Self {
            inline,
            buffers,
            bytes,
        })
    }

    /// Layout of the inline owner, including its vector descriptors.
    #[must_use]
    pub const fn inline(self) -> Layout {
        self.inline
    }

    /// Separate backing allocation requests in constructor order.
    #[must_use]
    pub const fn buffers(self) -> [Layout; N] {
        self.buffers
    }

    /// Sum of inline bytes and all requested backing bytes, without wrapping.
    #[must_use]
    pub const fn bytes(self) -> usize {
        self.bytes
    }
}
