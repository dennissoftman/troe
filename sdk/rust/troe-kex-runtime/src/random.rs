//! POSIX-like helpers over TROE's typed random-byte capability.

use troe_kex_sdk::{Error, Random};

/// Fill the complete destination with cryptographically secure random bytes.
///
/// This is the capability-scoped equivalent of a blocking `getrandom(2)` call.
/// The kernel seeds its generator before admitting applications, so there is
/// no weak or partially initialized success mode.
///
/// # Errors
///
/// Reports a missing/failing entropy service or malformed ABI completion.
pub fn getrandom(random: &mut Random, destination: &mut [u8]) -> Result<(), Error> {
    random.fill(destination)
}

/// Read one cryptographically secure 32-bit value.
///
/// # Errors
///
/// Reports a missing/failing entropy service or malformed ABI completion.
pub fn next_u32(random: &mut Random) -> Result<u32, Error> {
    let mut bytes = [0_u8; 4];
    getrandom(random, &mut bytes)?;
    Ok(u32::from_le_bytes(bytes))
}

/// Read one cryptographically secure 64-bit value.
///
/// # Errors
///
/// Reports a missing/failing entropy service or malformed ABI completion.
pub fn next_u64(random: &mut Random) -> Result<u64, Error> {
    random.next_u64()
}
