//! Explicit ceilings and page-table budgets applied to one application.

use crate::{
    KEX_V1_IMAGE_ALIGNMENT, LAUNCH_REGIONS, MAX_IMAGE_SPAN_BYTES, MAX_IMAGE_SPAN_USIZE,
    MAX_INITIAL_HEAP_PAGES, MAX_INITIAL_STACK_PAGES, MAX_PRIVATE_PAGES, TABLE_ENTRIES,
    TABLE_LEVELS_BELOW_ROOT,
};

/// Canonical declared span for one image that ends at `image_end`.
///
/// The span is the image end rounded up to [`KEX_V1_IMAGE_ALIGNMENT`]. It is
/// exact rather than an upper bound, so an artifact cannot reserve image
/// address space it never maps, and the startup page always sits directly
/// above the image.
///
/// Returns [`None`] when the rounded span is not representable.
#[must_use]
pub const fn canonical_image_span_bytes(image_end: u64) -> Option<u64> {
    let Some(rounded) = image_end.checked_add(KEX_V1_IMAGE_ALIGNMENT - 1) else {
        return None;
    };
    Some(rounded / KEX_V1_IMAGE_ALIGNMENT * KEX_V1_IMAGE_ALIGNMENT)
}

/// Upper bound on the page-table pages needed to map `mapped_pages`.
///
/// One page-table page describes [`TABLE_ENTRIES`] entries, so each of the
/// three levels below the root costs at most one page per that level's
/// coverage, rounded up, plus one page per launch region for a run that does
/// not begin on that level's boundary. The root is shared.
///
/// The kernel charges the exact requirement computed from the built mapping
/// plan, so this bound only has to hold beforehand, while admission is still
/// deciding whether to reserve anything at all. It must nonetheless be a true
/// upper bound: an optimistic estimate would admit a launch that then fails at
/// the exact reservation.
///
/// Returns [`None`] when the count is not representable.
#[must_use]
pub const fn maximum_table_pages(mapped_pages: u64) -> Option<u64> {
    let mut total = 1_u64;
    let mut coverage = TABLE_ENTRIES;
    let mut level = 0_u32;
    while level < TABLE_LEVELS_BELOW_ROOT {
        let Some(rounded) = mapped_pages.checked_add(coverage - 1) else {
            return None;
        };
        let Some(with_level) = total.checked_add(rounded / coverage) else {
            return None;
        };
        let Some(with_regions) = with_level.checked_add(LAUNCH_REGIONS) else {
            return None;
        };
        total = with_regions;
        let Some(wider) = coverage.checked_mul(TABLE_ENTRIES) else {
            return None;
        };
        coverage = wider;
        level += 1;
    }
    Some(total)
}

/// Absolute application limits enforced by the standard policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ApplicationLimits {
    pub(crate) encoded_bytes: usize,
    pub(crate) load_records: usize,
    pub(crate) maximum_image_span_bytes: u64,
    pub(crate) minimum_stack_pages: u64,
    pub(crate) maximum_stack_pages: u64,
    pub(crate) heap_pages: u64,
    pub(crate) resident_pages: u64,
    pub(crate) initial_handles: u16,
}

impl ApplicationLimits {
    pub(crate) const STANDARD: Self = Self {
        // Payload bytes cannot exceed the mapped span, which the segment
        // parser enforces exactly. The remaining allowance bounds the
        // canonical header, load records, and relative-relocation table.
        encoded_bytes: 2 * MAX_IMAGE_SPAN_USIZE,
        load_records: 16,
        maximum_image_span_bytes: MAX_IMAGE_SPAN_BYTES,
        minimum_stack_pages: 4,
        maximum_stack_pages: MAX_INITIAL_STACK_PAGES,
        heap_pages: MAX_INITIAL_HEAP_PAGES,
        resident_pages: match maximum_table_pages(MAX_PRIVATE_PAGES) {
            Some(tables) => MAX_PRIVATE_PAGES + tables,
            None => panic!("maximum private pages must have a table bound"),
        },
        initial_handles: 32,
    };

    /// Limits fixed by the standard application policy.
    #[must_use]
    pub const fn standard() -> Self {
        Self::STANDARD
    }

    /// Maximum encoded KEX bytes accepted by the standard policy.
    #[must_use]
    pub const fn encoded_bytes(self) -> usize {
        self.encoded_bytes
    }

    /// Maximum load records.
    #[must_use]
    pub const fn load_records(self) -> usize {
        self.load_records
    }

    /// Largest image span one artifact may declare.
    #[must_use]
    pub const fn maximum_image_span_bytes(self) -> u64 {
        self.maximum_image_span_bytes
    }

    /// Inclusive permitted stack-page range.
    #[must_use]
    pub const fn stack_pages(self) -> (u64, u64) {
        (self.minimum_stack_pages, self.maximum_stack_pages)
    }

    /// Maximum initially mapped heap pages.
    #[must_use]
    pub const fn heap_pages(self) -> u64 {
        self.heap_pages
    }

    /// Maximum total resident pages including page tables.
    #[must_use]
    pub const fn resident_pages(self) -> u64 {
        self.resident_pages
    }

    /// Maximum initially granted handles.
    #[must_use]
    pub const fn initial_handles(self) -> u16 {
        self.initial_handles
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::MAX_IMAGE_SPAN_PAGES;

    #[test]
    fn standard_limits_match_current_policy() {
        let standard = ApplicationLimits::standard();

        assert_eq!(standard.encoded_bytes(), 2 * 1024 * 1024 * 1024);
        assert_eq!(standard.load_records(), 16);
        assert_eq!(standard.maximum_image_span_bytes(), 1024 * 1024 * 1024);
        assert_eq!(standard.stack_pages(), (4, 1 << 32));
        assert_eq!(standard.heap_pages(), 1 << 32);
        let maximum_private = 2 * (1 << 32) + MAX_IMAGE_SPAN_PAGES + 1;
        assert_eq!(
            standard.resident_pages(),
            maximum_private
                + maximum_table_pages(maximum_private).unwrap_or_else(|| unreachable!())
        );
        assert_eq!(standard.initial_handles(), 32);
    }
}
