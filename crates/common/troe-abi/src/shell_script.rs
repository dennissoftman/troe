//! Bounded command-line submission protocol used by a shell interpreter.

use super::{MAX_SERVICE_PAYLOAD_BYTES, str};

/// Interface major version.
pub const MAJOR: u16 = 1;
/// Interface minor version.
pub const MINOR: u16 = 0;
/// Submit one nonempty physical source line.
pub const SUBMIT_LINE: u16 = 1;
/// Maximum UTF-8 bytes in one submitted command line.
pub const MAX_LINE_BYTES: usize = 512;
/// Maximum submitted command lines in one successful interpreter launch.
pub const MAX_LINES: usize = 1024;
/// Maximum aggregate submitted UTF-8 bytes in one interpreter launch.
pub const MAX_SCRIPT_BYTES: usize = 64 * 1024;
/// Fixed request bytes before the submitted UTF-8 line.
pub const HEADER_BYTES: usize = 8;
/// Largest canonical line-submission request.
pub const MAX_REQUEST_BYTES: usize = HEADER_BYTES + MAX_LINE_BYTES;

/// Invalid line number, source bytes, reserved fields, or destination size.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EncodingError;

/// One validated physical source line.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SubmittedLine<'a> {
    number: u32,
    source: &'a str,
}

impl<'a> SubmittedLine<'a> {
    /// One-based physical line number in the source file or input stream.
    #[must_use]
    pub const fn number(self) -> u32 {
        self.number
    }

    /// Exact UTF-8 source bytes excluding the line terminator.
    #[must_use]
    pub const fn source(self) -> &'a str {
        self.source
    }
}

/// Encode one canonical physical-line submission.
///
/// # Errors
///
/// Rejects line zero, empty or overlong source, embedded line terminators
/// or NUL, and an insufficient destination without modifying it.
pub fn encode_submit_line(
    number: u32,
    source: &str,
    destination: &mut [u8],
) -> Result<usize, EncodingError> {
    let encoded_bytes = HEADER_BYTES
        .checked_add(source.len())
        .ok_or(EncodingError)?;
    if number == 0
        || source.is_empty()
        || source.len() > MAX_LINE_BYTES
        || source
            .as_bytes()
            .iter()
            .any(|byte| matches!(byte, b'\0' | b'\n' | b'\r'))
        || encoded_bytes > MAX_SERVICE_PAYLOAD_BYTES
        || destination.len() < encoded_bytes
    {
        return Err(EncodingError);
    }
    let source_bytes = u16::try_from(source.len()).map_err(|_| EncodingError)?;
    let mut encoded = [0_u8; MAX_REQUEST_BYTES];
    encoded[0..4].copy_from_slice(&number.to_le_bytes());
    encoded[4..6].copy_from_slice(&source_bytes.to_le_bytes());
    encoded[HEADER_BYTES..encoded_bytes].copy_from_slice(source.as_bytes());
    destination[..encoded_bytes].copy_from_slice(&encoded[..encoded_bytes]);
    Ok(encoded_bytes)
}

/// Decode one exact canonical physical-line submission.
///
/// # Errors
///
/// Rejects every truncation, trailing byte, reserved field, invalid UTF-8,
/// embedded line terminator or NUL, empty line, or policy excess.
pub fn decode_submit_line(bytes: &[u8]) -> Result<SubmittedLine<'_>, EncodingError> {
    if bytes.len() < HEADER_BYTES {
        return Err(EncodingError);
    }
    let number = read_u32(bytes, 0)?;
    let source_bytes = usize::from(read_u16(bytes, 4)?);
    let encoded_bytes = HEADER_BYTES
        .checked_add(source_bytes)
        .ok_or(EncodingError)?;
    if number == 0
        || source_bytes == 0
        || source_bytes > MAX_LINE_BYTES
        || bytes.len() != encoded_bytes
        || bytes[6..HEADER_BYTES].iter().any(|byte| *byte != 0)
    {
        return Err(EncodingError);
    }
    let source = str::from_utf8(&bytes[HEADER_BYTES..]).map_err(|_| EncodingError)?;
    if source
        .as_bytes()
        .iter()
        .any(|byte| matches!(byte, b'\0' | b'\n' | b'\r'))
    {
        return Err(EncodingError);
    }
    Ok(SubmittedLine { number, source })
}

fn read_u16(bytes: &[u8], offset: usize) -> Result<u16, EncodingError> {
    let raw = bytes.get(offset..offset + 2).ok_or(EncodingError)?;
    Ok(u16::from_le_bytes([raw[0], raw[1]]))
}

fn read_u32(bytes: &[u8], offset: usize) -> Result<u32, EncodingError> {
    let raw = bytes.get(offset..offset + 4).ok_or(EncodingError)?;
    Ok(u32::from_le_bytes([raw[0], raw[1], raw[2], raw[3]]))
}

#[cfg(test)]
mod tests {
    use crate::shell_script;

    #[test]
    fn shell_script_lines_are_exact_utf8_and_bounded() {
        let mut bytes = [0xa5_u8; shell_script::MAX_REQUEST_BYTES];
        let count = shell_script::encode_submit_line(7, "echo 'hello world'", &mut bytes)
            .unwrap_or_else(|_| std::process::abort());
        let decoded = shell_script::decode_submit_line(&bytes[..count])
            .unwrap_or_else(|_| std::process::abort());
        assert_eq!(decoded.number(), 7);
        assert_eq!(decoded.source(), "echo 'hello world'");
        for end in 0..count {
            assert!(shell_script::decode_submit_line(&bytes[..end]).is_err());
        }
        assert!(shell_script::decode_submit_line(&bytes[..=count]).is_err());
        assert!(shell_script::encode_submit_line(0, "echo", &mut bytes).is_err());
        assert!(shell_script::encode_submit_line(1, "", &mut bytes).is_err());
        assert!(shell_script::encode_submit_line(1, "echo\nnext", &mut bytes).is_err());
        assert!(
            shell_script::encode_submit_line(
                1,
                &"x".repeat(shell_script::MAX_LINE_BYTES + 1),
                &mut bytes,
            )
            .is_err()
        );
    }
}
