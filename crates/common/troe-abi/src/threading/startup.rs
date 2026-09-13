use super::{
    EncodingError, Kind, PAGE_BYTES, STARTUP_BYTES, STARTUP_MAPPING_BYTES, Token, USER_END, read,
    token, user_range,
};

const MAGIC: [u8; 8] = *b"TTHRv1\0\0";
const PREFIX_BYTES: u32 = 128;
const _: () = assert!(PREFIX_BYTES as usize == STARTUP_BYTES);

/// ABI 1.4 process-header extension at bytes 80..96.
///
/// The active ABI remains 1.3: this standalone codec does not enable admission.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StartupReference {
    /// Page-aligned address of the initial thread's immutable descriptor.
    pub address: u64,
}

impl StartupReference {
    /// Decode the exact 16-byte extension; its encoded prefix size must be 128.
    ///
    /// # Errors
    /// Rejects invalid length, address, range or descriptor size.
    pub fn decode(bytes: &[u8]) -> Result<Self, EncodingError> {
        if bytes.len() != 16 || u64::from_le_bytes(read(bytes, 8)?) != STARTUP_BYTES as u64 {
            return Err(EncodingError);
        }
        let address = u64::from_le_bytes(read(bytes, 0)?);
        user_range(address, STARTUP_MAPPING_BYTES)?;
        Ok(Self { address })
    }

    /// Produce the canonical extension without partial output.
    ///
    /// # Errors
    /// Rejects an invalid descriptor mapping address.
    pub fn encode(self) -> Result<[u8; 16], EncodingError> {
        user_range(self.address, STARTUP_MAPPING_BYTES)?;
        let mut bytes = [0; 16];
        bytes[..8].copy_from_slice(&self.address.to_le_bytes());
        bytes[8..].copy_from_slice(&(STARTUP_BYTES as u64).to_le_bytes());
        Ok(bytes)
    }
}

/// Immutable per-thread bootstrap metadata, encoded explicitly in little endian.
///
/// The kernel-owned mapping must be user read-only/NX. All threads still share
/// process authority; these bytes neither authenticate the caller nor prove
/// mapping permissions, live ownership, executable entry or compiler TLS layout.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StartupDescriptor {
    /// Informational process-scoped thread identity.
    pub thread: Token,
    /// Shared one-page process startup mapping, including capability descriptors.
    pub process_startup: u64,
    /// Lowest committed stack byte, above its unmapped guard.
    pub stack_bottom: u64,
    /// Exclusive stack end, below its unmapped guard.
    pub stack_top: u64,
    /// Base of the private writable TLS allocation.
    pub tls_base: u64,
    /// Complete page-rounded TLS allocation size.
    pub tls_bytes: u64,
    /// FS base or `TPIDR_EL0`; checked separately against the compiler layout.
    pub thread_pointer: u64,
    /// This thread's private TX page; RX immediately follows it.
    pub ipc_tx: u64,
    /// Resolved immutable executable worker entry; zero for the initial thread.
    pub entry: u64,
    /// Opaque worker argument; zero for the initial thread.
    pub argument: u64,
    /// Identifies the supervisor-owned initial execution context.
    pub initial: bool,
    /// Self-address of this descriptor's dedicated read-only page.
    pub address: u64,
}

impl StartupDescriptor {
    /// Decode the exact descriptor prefix.
    ///
    /// # Errors
    /// Rejects unsupported format, reserved bytes, noncanonical page geometry,
    /// overlaps (including stack guards), and inconsistent initial-thread fields.
    pub fn decode(bytes: &[u8]) -> Result<Self, EncodingError> {
        if bytes.len() != STARTUP_BYTES
            || bytes[..8] != MAGIC
            || u16::from_le_bytes(read(bytes, 8)?) != 1
            || u16::from_le_bytes(read(bytes, 10)?) != 0
            || u32::from_le_bytes(read(bytes, 12)?) != PREFIX_BYTES
            || u64::from_le_bytes(read(bytes, 32)?) != PAGE_BYTES
            || u32::from_le_bytes(read(bytes, 112)?) > 1
            || bytes[116..120] != [0; 4]
        {
            return Err(EncodingError);
        }
        let result = Self {
            thread: token(u64::from_le_bytes(read(bytes, 16)?), Kind::Thread)?,
            process_startup: u64::from_le_bytes(read(bytes, 24)?),
            stack_bottom: u64::from_le_bytes(read(bytes, 40)?),
            stack_top: u64::from_le_bytes(read(bytes, 48)?),
            tls_base: u64::from_le_bytes(read(bytes, 56)?),
            tls_bytes: u64::from_le_bytes(read(bytes, 64)?),
            thread_pointer: u64::from_le_bytes(read(bytes, 72)?),
            ipc_tx: u64::from_le_bytes(read(bytes, 80)?),
            entry: u64::from_le_bytes(read(bytes, 96)?),
            argument: u64::from_le_bytes(read(bytes, 104)?),
            initial: bytes[112] == 1,
            address: u64::from_le_bytes(read(bytes, 120)?),
        };
        result.validate()?;
        if u64::from_le_bytes(read(bytes, 88)?) != result.ipc_tx + PAGE_BYTES {
            return Err(EncodingError);
        }
        Ok(result)
    }

    /// Decode a full mapping, requiring every byte after the prefix to be zero.
    ///
    /// # Errors
    /// Rejects a malformed descriptor, wrong mapping length or nonzero slack.
    pub fn decode_page(bytes: &[u8]) -> Result<Self, EncodingError> {
        if bytes.len() as u64 != STARTUP_MAPPING_BYTES
            || bytes[STARTUP_BYTES..].iter().any(|byte| *byte != 0)
        {
            return Err(EncodingError);
        }
        Self::decode(&bytes[..STARTUP_BYTES])
    }

    /// Encode a validated prefix; composition must zero the complete destination
    /// page before copying it and publish the mapping read-only/NX.
    ///
    /// # Errors
    /// Rejects invalid tokens, fields or geometry without producing partial bytes.
    pub fn encode(self) -> Result<[u8; STARTUP_BYTES], EncodingError> {
        self.validate()?;
        let mut bytes = [0; STARTUP_BYTES];
        bytes[..8].copy_from_slice(&MAGIC);
        bytes[8..10].copy_from_slice(&1_u16.to_le_bytes());
        bytes[12..16].copy_from_slice(&PREFIX_BYTES.to_le_bytes());
        for (offset, value) in [
            (16, self.thread.bits()),
            (24, self.process_startup),
            (32, PAGE_BYTES),
            (40, self.stack_bottom),
            (48, self.stack_top),
            (56, self.tls_base),
            (64, self.tls_bytes),
            (72, self.thread_pointer),
            (80, self.ipc_tx),
            (88, self.ipc_tx + PAGE_BYTES),
            (96, self.entry),
            (104, self.argument),
            (120, self.address),
        ] {
            bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
        }
        bytes[112] = u8::from(self.initial);
        Ok(bytes)
    }

    fn validate(self) -> Result<(), EncodingError> {
        token(self.thread.bits(), Kind::Thread)?;
        let process_end = user_range(self.process_startup, PAGE_BYTES)?;
        let stack_bytes = self
            .stack_top
            .checked_sub(self.stack_bottom)
            .ok_or(EncodingError)?;
        user_range(self.stack_bottom, stack_bytes)?;
        let guard_start = self
            .stack_bottom
            .checked_sub(PAGE_BYTES)
            .ok_or(EncodingError)?;
        let guard_end = user_range(
            guard_start,
            stack_bytes
                .checked_add(2 * PAGE_BYTES)
                .ok_or(EncodingError)?,
        )?;
        let tls_end = user_range(self.tls_base, self.tls_bytes)?;
        let ipc_end = user_range(self.ipc_tx, 2 * PAGE_BYTES)?;
        let descriptor_end = user_range(self.address, STARTUP_MAPPING_BYTES)?;
        if self.thread_pointer < self.tls_base
            || self.thread_pointer >= tls_end
            || !self.thread_pointer.is_multiple_of(8)
            || (self.initial && (self.entry != 0 || self.argument != 0))
            || (!self.initial && !(PAGE_BYTES..USER_END).contains(&self.entry))
        {
            return Err(EncodingError);
        }
        let ranges = [
            (self.process_startup, process_end),
            (guard_start, guard_end),
            (self.tls_base, tls_end),
            (self.ipc_tx, ipc_end),
            (self.address, descriptor_end),
        ];
        for (index, &(start, end)) in ranges.iter().enumerate() {
            if ranges[..index]
                .iter()
                .any(|&(other_start, other_end)| start < other_end && other_start < end)
            {
                return Err(EncodingError);
            }
            if !self.initial && (start..end).contains(&self.entry) {
                return Err(EncodingError);
            }
        }
        Ok(())
    }
}
