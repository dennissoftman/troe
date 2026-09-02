//! Immutable typed kernel and namespace diagnostics protocol.

/// Interface major version.
pub const MAJOR: u16 = 1;
/// Interface minor version.
pub const MINOR: u16 = 0;
/// Read the launch-time diagnostics snapshot.
pub const GET_SNAPSHOT: u16 = 1;
/// Exact canonical snapshot bytes.
pub const SNAPSHOT_BYTES: usize = 168;

const MACHINE_PRESENT: u8 = 1 << 0;
const INPUT_PRESENT: u8 = 1 << 1;
const KNOWN_FLAGS: u8 = MACHINE_PRESENT | INPUT_PRESENT;
const MACHINE_OFFSET: usize = 8;
const INPUT_OFFSET: usize = 72;
const RAMFS_OFFSET: usize = 128;
const CACHES_OFFSET: usize = 152;

/// Architecture that produced one diagnostics snapshot.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum Architecture {
    /// AMD64/Intel 64 machine profile.
    X86_64 = 1,
    /// `AArch64` machine profile.
    Aarch64 = 2,
}

/// Authority that owns the reported physical memory map.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum MemoryOwner {
    /// Hosted process; no physical memory map is exposed.
    Host = 1,
    /// Firmware snapshot retained for advisory reporting.
    Firmware = 2,
    /// Final map owned by the kernel.
    Kernel = 3,
}

/// Bounded memory-pressure state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum Pressure {
    /// The bounded RAMFS policy is within its configured limit.
    Normal = 1,
}

/// Optional full machine-memory counters.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MachineMemory {
    /// Bytes available for kernel use.
    pub usable_bytes: u64,
    /// Bytes excluded from kernel use.
    pub reserved_bytes: u64,
    /// Total owned physical frames.
    pub total_frames: u64,
    /// Currently free owned physical frames.
    pub free_frames: u64,
    /// Configured kernel heap bytes.
    pub heap_total_bytes: u64,
    /// Currently used kernel heap bytes.
    pub heap_used_bytes: u64,
    /// Peak kernel heap use since boot.
    pub heap_high_water_bytes: u64,
    /// Failed kernel allocations since boot.
    pub failed_allocations: u64,
}

/// Optional bounded input-queue counters.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InputQueue {
    /// Currently queued input events.
    pub queued: u64,
    /// Maximum queued input events.
    pub capacity: u64,
    /// Observed input interrupts.
    pub interrupts: u64,
    /// Delivered input events.
    pub delivered: u64,
    /// Dropped input events.
    pub dropped: u64,
    /// Cooperative input idle waits.
    pub idle_waits: u64,
    /// Input-driven cooperative wakeups.
    pub wakeups: u64,
}

/// One immutable launch-time diagnostics snapshot.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Snapshot {
    /// Machine architecture.
    pub architecture: Architecture,
    /// Physical memory-map owner.
    pub memory_owner: MemoryOwner,
    /// Current bounded pressure state.
    pub pressure: Pressure,
    /// Full machine counters when the platform owns them.
    pub machine_memory: Option<MachineMemory>,
    /// Input counters when the machine exposes an input queue.
    pub input: Option<InputQueue>,
    /// Current RAMFS use.
    pub ramfs_used_bytes: u64,
    /// Configured RAMFS limit.
    pub ramfs_limit_bytes: u64,
    /// Peak RAMFS use since boot.
    pub ramfs_high_water_bytes: u64,
    /// Current cache use.
    pub caches_used_bytes: u64,
    /// Configured cache limit.
    pub caches_limit_bytes: u64,
}

/// Invalid, inconsistent, or noncanonical snapshot encoding.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EncodingError;

/// Encode one canonical fixed-size diagnostics snapshot.
///
/// # Errors
///
/// Rejects inconsistent counters before producing any bytes.
pub fn encode_snapshot(snapshot: Snapshot) -> Result<[u8; SNAPSHOT_BYTES], EncodingError> {
    validate(snapshot)?;
    let mut bytes = [0_u8; SNAPSHOT_BYTES];
    bytes[0] = snapshot.architecture as u8;
    bytes[1] = snapshot.memory_owner as u8;
    bytes[2] = snapshot.pressure as u8;
    if let Some(memory) = snapshot.machine_memory {
        bytes[3] |= MACHINE_PRESENT;
        write_values(
            &mut bytes,
            MACHINE_OFFSET,
            &[
                memory.usable_bytes,
                memory.reserved_bytes,
                memory.total_frames,
                memory.free_frames,
                memory.heap_total_bytes,
                memory.heap_used_bytes,
                memory.heap_high_water_bytes,
                memory.failed_allocations,
            ],
        );
    }
    if let Some(input) = snapshot.input {
        bytes[3] |= INPUT_PRESENT;
        write_values(
            &mut bytes,
            INPUT_OFFSET,
            &[
                input.queued,
                input.capacity,
                input.interrupts,
                input.delivered,
                input.dropped,
                input.idle_waits,
                input.wakeups,
            ],
        );
    }
    write_values(
        &mut bytes,
        RAMFS_OFFSET,
        &[
            snapshot.ramfs_used_bytes,
            snapshot.ramfs_limit_bytes,
            snapshot.ramfs_high_water_bytes,
        ],
    );
    write_values(
        &mut bytes,
        CACHES_OFFSET,
        &[snapshot.caches_used_bytes, snapshot.caches_limit_bytes],
    );
    Ok(bytes)
}

/// Decode one exact canonical diagnostics snapshot.
///
/// # Errors
///
/// Rejects unknown enums/flags, nonzero reserved or absent fields, the
/// wrong length, and inconsistent counters.
pub fn decode_snapshot(bytes: &[u8]) -> Result<Snapshot, EncodingError> {
    if bytes.len() != SNAPSHOT_BYTES || bytes[3] & !KNOWN_FLAGS != 0 || bytes[4..8] != [0; 4] {
        return Err(EncodingError);
    }
    let architecture = match bytes[0] {
        1 => Architecture::X86_64,
        2 => Architecture::Aarch64,
        _ => return Err(EncodingError),
    };
    let memory_owner = match bytes[1] {
        1 => MemoryOwner::Host,
        2 => MemoryOwner::Firmware,
        3 => MemoryOwner::Kernel,
        _ => return Err(EncodingError),
    };
    let pressure = match bytes[2] {
        1 => Pressure::Normal,
        _ => return Err(EncodingError),
    };
    let machine_values = read_values::<8>(bytes, MACHINE_OFFSET)?;
    let machine_memory = if bytes[3] & MACHINE_PRESENT != 0 {
        Some(MachineMemory {
            usable_bytes: machine_values[0],
            reserved_bytes: machine_values[1],
            total_frames: machine_values[2],
            free_frames: machine_values[3],
            heap_total_bytes: machine_values[4],
            heap_used_bytes: machine_values[5],
            heap_high_water_bytes: machine_values[6],
            failed_allocations: machine_values[7],
        })
    } else if machine_values == [0; 8] {
        None
    } else {
        return Err(EncodingError);
    };
    let input_values = read_values::<7>(bytes, INPUT_OFFSET)?;
    let input = if bytes[3] & INPUT_PRESENT != 0 {
        Some(InputQueue {
            queued: input_values[0],
            capacity: input_values[1],
            interrupts: input_values[2],
            delivered: input_values[3],
            dropped: input_values[4],
            idle_waits: input_values[5],
            wakeups: input_values[6],
        })
    } else if input_values == [0; 7] {
        None
    } else {
        return Err(EncodingError);
    };
    let ramfs = read_values::<3>(bytes, RAMFS_OFFSET)?;
    let caches = read_values::<2>(bytes, CACHES_OFFSET)?;
    let snapshot = Snapshot {
        architecture,
        memory_owner,
        pressure,
        machine_memory,
        input,
        ramfs_used_bytes: ramfs[0],
        ramfs_limit_bytes: ramfs[1],
        ramfs_high_water_bytes: ramfs[2],
        caches_used_bytes: caches[0],
        caches_limit_bytes: caches[1],
    };
    validate(snapshot)?;
    Ok(snapshot)
}

fn validate(snapshot: Snapshot) -> Result<(), EncodingError> {
    if let Some(memory) = snapshot.machine_memory
        && (memory.free_frames > memory.total_frames
            || memory.heap_used_bytes > memory.heap_total_bytes)
    {
        return Err(EncodingError);
    }
    if let Some(input) = snapshot.input
        && input.queued > input.capacity
    {
        return Err(EncodingError);
    }
    if snapshot.ramfs_used_bytes > snapshot.ramfs_limit_bytes
        || snapshot.ramfs_high_water_bytes > snapshot.ramfs_limit_bytes
        || snapshot.caches_used_bytes > snapshot.caches_limit_bytes
    {
        return Err(EncodingError);
    }
    Ok(())
}

fn write_values(bytes: &mut [u8], offset: usize, values: &[u64]) {
    for (index, value) in values.iter().copied().enumerate() {
        let start = offset + index * 8;
        bytes[start..start + 8].copy_from_slice(&value.to_le_bytes());
    }
}

fn read_values<const N: usize>(bytes: &[u8], offset: usize) -> Result<[u64; N], EncodingError> {
    let mut values = [0_u64; N];
    for (index, value) in values.iter_mut().enumerate() {
        let start = offset + index * 8;
        let raw = bytes.get(start..start + 8).ok_or(EncodingError)?;
        *value = u64::from_le_bytes([
            raw[0], raw[1], raw[2], raw[3], raw[4], raw[5], raw[6], raw[7],
        ]);
    }
    Ok(values)
}

#[cfg(test)]
mod tests {
    use crate::diagnostics;

    #[test]
    fn diagnostics_snapshot_is_fixed_typed_and_canonical() {
        let snapshot = diagnostics::Snapshot {
            architecture: diagnostics::Architecture::Aarch64,
            memory_owner: diagnostics::MemoryOwner::Kernel,
            pressure: diagnostics::Pressure::Normal,
            machine_memory: Some(diagnostics::MachineMemory {
                usable_bytes: 1024,
                reserved_bytes: 512,
                total_frames: 4,
                free_frames: 3,
                heap_total_bytes: 256,
                heap_used_bytes: 64,
                heap_high_water_bytes: 96,
                failed_allocations: 0,
            }),
            input: Some(diagnostics::InputQueue {
                queued: 1,
                capacity: 32,
                interrupts: 7,
                delivered: 6,
                dropped: 0,
                idle_waits: 4,
                wakeups: 2,
            }),
            ramfs_used_bytes: 11,
            ramfs_limit_bytes: 64,
            ramfs_high_water_bytes: 12,
            caches_used_bytes: 0,
            caches_limit_bytes: 0,
        };
        let bytes =
            diagnostics::encode_snapshot(snapshot).unwrap_or_else(|_| std::process::abort());
        assert_eq!(diagnostics::decode_snapshot(&bytes), Ok(snapshot));
        assert!(diagnostics::decode_snapshot(&bytes[..bytes.len() - 1]).is_err());

        let mut unknown_flag = bytes;
        unknown_flag[3] |= 0x80;
        assert!(diagnostics::decode_snapshot(&unknown_flag).is_err());

        let mut absent_nonzero = bytes;
        absent_nonzero[3] &= !1;
        assert!(diagnostics::decode_snapshot(&absent_nonzero).is_err());

        let invalid = diagnostics::Snapshot {
            ramfs_used_bytes: 65,
            ..snapshot
        };
        assert!(diagnostics::encode_snapshot(invalid).is_err());
    }
}
