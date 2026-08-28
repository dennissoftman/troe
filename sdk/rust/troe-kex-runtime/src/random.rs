//! Non-cryptographic seed mixing from capability-provided observations.
#![allow(unsafe_code)]

/// Mix address, wall-clock, and process-clock observations into a seed.
///
/// This is suitable for language hash-table and pseudo-random initialization;
/// it does not claim cryptographic entropy.
#[must_use]
pub const fn seed(address: u64, wall_seconds: u64, ticks: u64, frequency_hz: u64) -> u32 {
    let mut mixed = address ^ address.rotate_left(17);
    mixed ^= wall_seconds.wrapping_add(0x9e37_79b9_7f4a_7c15);
    mixed ^= ticks.wrapping_add(frequency_hz.wrapping_shl(23));
    mixed ^= mixed >> 30;
    mixed = mixed.wrapping_mul(0xbf58_476d_1ce4_e5b9);
    mixed ^= mixed >> 27;
    mixed = mixed.wrapping_mul(0x94d0_49bb_1331_11eb);
    mixed ^= mixed >> 31;
    let folded = (mixed ^ (mixed >> 32)).to_le_bytes();
    u32::from_le_bytes([folded[0], folded[1], folded[2], folded[3]])
}

/// Pointer-free C ABI bridge for [`seed`].
#[unsafe(no_mangle)]
#[must_use]
pub extern "C" fn troe_runtime_mix_seed(
    address: u64,
    wall_seconds: u64,
    ticks: u64,
    frequency_hz: u64,
) -> u32 {
    seed(address, wall_seconds, ticks, frequency_hz)
}

#[cfg(test)]
mod tests {
    use super::seed;

    #[test]
    fn observations_are_mixed_deterministically() {
        let first = seed(0x1000, 1_700_000_000, 42, 1_000);
        assert_eq!(first, seed(0x1000, 1_700_000_000, 42, 1_000));
        assert_ne!(first, seed(0x2000, 1_700_000_000, 42, 1_000));
        assert_ne!(first, seed(0x1000, 1_700_000_001, 42, 1_000));
    }
}
