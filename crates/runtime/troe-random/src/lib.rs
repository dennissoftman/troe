//! Kernel-owned cryptographic random generator core.
#![no_std]
#![forbid(unsafe_code)]

/// Exact seed bytes: one 256-bit key and one 64-bit nonce.
pub const SEED_BYTES: usize = 40;

const BLOCK_BYTES: usize = 64;
const CONSTANTS: [u32; 4] = [0x6170_7865, 0x3320_646e, 0x7962_2d32, 0x6b20_6574];

/// Invalid all-zero seed or exhausted generator state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    /// The seed failed the mandatory catastrophic-source check.
    InvalidSeed,
    /// A bounded draw requested an empty range.
    InvalidBound,
    /// The 64-bit block counter was exhausted.
    Exhausted,
}

/// `ChaCha20` CSPRNG with fast key erasure after every public read.
///
/// The seed is obtained outside this crate from an approved platform entropy
/// source. Generator state is intentionally neither cloneable nor printable.
pub struct Generator {
    key: [u32; 8],
    nonce: [u32; 2],
    counter: u64,
    generated_bytes: u64,
    requests: u64,
}

impl Generator {
    /// Initialize one generator from exactly 320 entropy bits.
    ///
    /// # Errors
    ///
    /// Rejects an all-zero seed as a catastrophic entropy-source failure.
    pub fn new(seed: [u8; SEED_BYTES]) -> Result<Self, Error> {
        if seed.iter().all(|byte| *byte == 0) {
            return Err(Error::InvalidSeed);
        }
        let mut key = [0_u32; 8];
        for (word, bytes) in key.iter_mut().zip(seed[..32].chunks_exact(4)) {
            *word = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        }
        let nonce = [
            u32::from_le_bytes([seed[32], seed[33], seed[34], seed[35]]),
            u32::from_le_bytes([seed[36], seed[37], seed[38], seed[39]]),
        ];
        Ok(Self {
            key,
            nonce,
            counter: 0,
            generated_bytes: 0,
            requests: 0,
        })
    }

    /// Fill a caller-owned buffer and erase the key used for its output.
    ///
    /// Empty reads are valid and do not advance state.
    ///
    /// # Errors
    ///
    /// Reports only the practically unreachable 64-bit block-counter limit.
    pub fn fill(&mut self, destination: &mut [u8]) -> Result<(), Error> {
        if destination.is_empty() {
            return Ok(());
        }
        let mut written = 0_usize;
        while written < destination.len() {
            let block = self.block()?;
            let count = (destination.len() - written).min(BLOCK_BYTES);
            destination[written..written + count].copy_from_slice(&block[..count]);
            written += count;
        }
        let replacement = self.block()?;
        for (word, bytes) in self.key.iter_mut().zip(replacement[..32].chunks_exact(4)) {
            *word = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        }
        self.requests = self.requests.checked_add(1).ok_or(Error::Exhausted)?;
        self.generated_bytes = self
            .generated_bytes
            .checked_add(u64::try_from(destination.len()).map_err(|_| Error::Exhausted)?)
            .ok_or(Error::Exhausted)?;
        Ok(())
    }

    /// Draw one full-width value for kernel placement decisions.
    ///
    /// # Errors
    ///
    /// Reports generator exhaustion.
    pub fn next_u64(&mut self) -> Result<u64, Error> {
        let mut bytes = [0_u8; 8];
        self.fill(&mut bytes)?;
        Ok(u64::from_le_bytes(bytes))
    }

    /// Draw uniformly from `0..upper_exclusive` without modulo bias.
    ///
    /// # Errors
    ///
    /// Rejects zero and reports generator exhaustion.
    pub fn uniform_u64(&mut self, upper_exclusive: u64) -> Result<u64, Error> {
        if upper_exclusive == 0 {
            return Err(Error::InvalidBound);
        }
        let threshold = upper_exclusive.wrapping_neg() % upper_exclusive;
        loop {
            let value = self.next_u64()?;
            if value >= threshold {
                return Ok(value % upper_exclusive);
            }
        }
    }

    /// Number of application-visible bytes emitted since seeding.
    #[must_use]
    pub const fn generated_bytes(&self) -> u64 {
        self.generated_bytes
    }

    /// Number of nonempty public reads since seeding.
    #[must_use]
    pub const fn requests(&self) -> u64 {
        self.requests
    }

    fn block(&mut self) -> Result<[u8; BLOCK_BYTES], Error> {
        let counter = self.counter.to_le_bytes();
        let state = [
            CONSTANTS[0],
            CONSTANTS[1],
            CONSTANTS[2],
            CONSTANTS[3],
            self.key[0],
            self.key[1],
            self.key[2],
            self.key[3],
            self.key[4],
            self.key[5],
            self.key[6],
            self.key[7],
            u32::from_le_bytes([counter[0], counter[1], counter[2], counter[3]]),
            u32::from_le_bytes([counter[4], counter[5], counter[6], counter[7]]),
            self.nonce[0],
            self.nonce[1],
        ];
        let mut working = state;
        for _ in 0..10 {
            quarter_round(&mut working, 0, 4, 8, 12);
            quarter_round(&mut working, 1, 5, 9, 13);
            quarter_round(&mut working, 2, 6, 10, 14);
            quarter_round(&mut working, 3, 7, 11, 15);
            quarter_round(&mut working, 0, 5, 10, 15);
            quarter_round(&mut working, 1, 6, 11, 12);
            quarter_round(&mut working, 2, 7, 8, 13);
            quarter_round(&mut working, 3, 4, 9, 14);
        }
        let mut output = [0_u8; BLOCK_BYTES];
        for (index, (value, initial)) in working.into_iter().zip(state).enumerate() {
            output[index * 4..index * 4 + 4]
                .copy_from_slice(&value.wrapping_add(initial).to_le_bytes());
        }
        self.counter = self.counter.checked_add(1).ok_or(Error::Exhausted)?;
        Ok(output)
    }
}

fn quarter_round(state: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
    state[a] = state[a].wrapping_add(state[b]);
    state[d] ^= state[a];
    state[d] = state[d].rotate_left(16);
    state[c] = state[c].wrapping_add(state[d]);
    state[b] ^= state[c];
    state[b] = state[b].rotate_left(12);
    state[a] = state[a].wrapping_add(state[b]);
    state[d] ^= state[a];
    state[d] = state[d].rotate_left(8);
    state[c] = state[c].wrapping_add(state[d]);
    state[b] ^= state[c];
    state[b] = state[b].rotate_left(7);
}

#[cfg(test)]
mod tests {
    use super::{Error, Generator, SEED_BYTES, quarter_round};

    #[test]
    fn quarter_round_matches_rfc_8439() {
        let mut state = [0_u32; 16];
        state[0] = 0x1111_1111;
        state[1] = 0x0102_0304;
        state[2] = 0x9b8d_6f43;
        state[3] = 0x0123_4567;
        quarter_round(&mut state, 0, 1, 2, 3);
        assert_eq!(
            state[..4],
            [0xea2a_92f4, 0xcb1c_f8ce, 0x4581_472e, 0x5881_c4bb]
        );
    }

    #[test]
    fn generator_rejects_zero_and_rekeys_every_read() {
        assert!(matches!(
            Generator::new([0; SEED_BYTES]),
            Err(Error::InvalidSeed)
        ));
        let mut seed = [0_u8; SEED_BYTES];
        for (index, byte) in seed.iter_mut().enumerate() {
            *byte = u8::try_from(index + 1).unwrap_or(1);
        }
        let mut first = Generator::new(seed).unwrap_or_else(|_| unreachable!());
        let mut second = Generator::new(seed).unwrap_or_else(|_| unreachable!());
        let mut one = [0_u8; 96];
        let mut two = [0_u8; 96];
        first.fill(&mut one).unwrap_or_else(|_| unreachable!());
        second.fill(&mut two).unwrap_or_else(|_| unreachable!());
        assert_eq!(one, two);
        assert!(one.iter().any(|byte| *byte != 0));
        let mut later = [0_u8; 96];
        first.fill(&mut later).unwrap_or_else(|_| unreachable!());
        assert_ne!(one, later);
        assert_eq!(first.generated_bytes(), 192);
        assert_eq!(first.requests(), 2);
        assert_eq!(first.uniform_u64(0), Err(Error::InvalidBound));
        for _ in 0..128 {
            assert!(first.uniform_u64(17).is_ok_and(|value| value < 17));
        }
    }
}
