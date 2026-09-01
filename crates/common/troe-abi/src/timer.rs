//! Boot-relative monotonic timer protocol.

/// Interface major version.
pub const MAJOR: u16 = 1;
/// Interface minor version.
pub const MINOR: u16 = 0;
/// Read the current boot-relative monotonic millisecond count.
pub const NOW: u16 = 1;
/// Cooperatively wait until one boot-relative monotonic deadline.
pub const SLEEP_UNTIL: u16 = 2;
/// Read CPU ticks charged to the calling process and their frequency.
pub const PROCESS_CPU_TIME: u16 = 3;
/// Exact timestamp or deadline bytes.
pub const MILLISECONDS_BYTES: usize = 8;
/// Exact process CPU-time reply bytes.
pub const PROCESS_CPU_TIME_BYTES: usize = 16;

/// CPU time charged to one process in a machine-defined tick domain.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProcessCpuTime {
    /// Accumulated execution ticks.
    pub ticks: u64,
    /// Tick frequency used to convert ticks into seconds.
    pub frequency_hz: u64,
}

/// Invalid timer request or reply encoding.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EncodingError;

/// Encode one boot-relative monotonic millisecond count.
#[must_use]
pub const fn encode_milliseconds(milliseconds: u64) -> [u8; MILLISECONDS_BYTES] {
    milliseconds.to_le_bytes()
}

/// Decode one exact boot-relative monotonic millisecond count.
///
/// # Errors
///
/// Rejects every length other than eight bytes.
pub fn decode_milliseconds(bytes: &[u8]) -> Result<u64, EncodingError> {
    if bytes.len() != MILLISECONDS_BYTES {
        return Err(EncodingError);
    }
    Ok(u64::from_le_bytes([
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
    ]))
}

/// Encode one exact process CPU-time sample.
///
/// # Errors
///
/// Rejects a zero tick frequency.
pub fn encode_process_cpu_time(
    value: ProcessCpuTime,
) -> Result<[u8; PROCESS_CPU_TIME_BYTES], EncodingError> {
    if value.frequency_hz == 0 {
        return Err(EncodingError);
    }
    let mut bytes = [0_u8; PROCESS_CPU_TIME_BYTES];
    bytes[..8].copy_from_slice(&value.ticks.to_le_bytes());
    bytes[8..].copy_from_slice(&value.frequency_hz.to_le_bytes());
    Ok(bytes)
}

/// Decode one exact process CPU-time sample.
///
/// # Errors
///
/// Rejects the wrong length or a zero tick frequency.
pub fn decode_process_cpu_time(bytes: &[u8]) -> Result<ProcessCpuTime, EncodingError> {
    if bytes.len() != PROCESS_CPU_TIME_BYTES {
        return Err(EncodingError);
    }
    let value = ProcessCpuTime {
        ticks: u64::from_le_bytes(bytes[..8].try_into().map_err(|_| EncodingError)?),
        frequency_hz: u64::from_le_bytes(bytes[8..].try_into().map_err(|_| EncodingError)?),
    };
    if value.frequency_hz == 0 {
        return Err(EncodingError);
    }
    Ok(value)
}

#[cfg(test)]
mod tests {
    use crate::timer;

    #[test]
    fn timer_values_are_exact() {
        let encoded = timer::encode_milliseconds(u64::MAX);
        assert_eq!(timer::decode_milliseconds(&encoded), Ok(u64::MAX));
        assert!(timer::decode_milliseconds(&encoded[..7]).is_err());

        let cpu = timer::ProcessCpuTime {
            ticks: u64::MAX,
            frequency_hz: 1_000_000_000,
        };
        let encoded = timer::encode_process_cpu_time(cpu).unwrap_or_else(|_| unreachable!());
        assert_eq!(timer::decode_process_cpu_time(&encoded), Ok(cpu));
        assert!(timer::decode_process_cpu_time(&encoded[..15]).is_err());
        assert!(
            timer::encode_process_cpu_time(timer::ProcessCpuTime {
                ticks: 1,
                frequency_hz: 0,
            })
            .is_err()
        );
    }
}
