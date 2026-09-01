//! Owner-scoped child-process launch and lifecycle protocol.

use super::{MAX_SERVICE_PAYLOAD_BYTES, command, exit, str};

/// Interface major version.
pub const MAJOR: u16 = 1;
/// Interface minor version.
pub const MINOR: u16 = 0;
/// Admit one child and return its owner-scoped token.
pub const SPAWN: u16 = 1;
/// Return current child state without blocking.
pub const POLL: u16 = 2;
/// Wait until one child becomes terminal.
pub const WAIT: u16 = 3;
/// Request cooperative child cancellation.
pub const CANCEL: u16 = 4;
/// Revoke a terminal child token and release retained metadata.
pub const REAP: u16 = 5;
/// Maximum environment entries passed to one child.
pub const MAX_ENVIRONMENT: usize = command::MAX_ENVIRONMENT;
/// Maximum aggregate environment UTF-8 bytes.
pub const MAX_ENVIRONMENT_BYTES: usize = command::MAX_ENVIRONMENT_BYTES;
/// Fixed spawn-request header bytes.
pub const SPAWN_HEADER_BYTES: usize = 48;
/// Maximum canonical spawn payload.
pub const MAX_SPAWN_BYTES: usize = SPAWN_HEADER_BYTES
    + command::MAX_INVOCATION_BYTES
    + MAX_ENVIRONMENT * 2
    + MAX_ENVIRONMENT_BYTES;
/// Exact child-token request bytes.
pub const TOKEN_BYTES: usize = 8;
/// Exact spawn reply bytes.
pub const SPAWN_REPLY_BYTES: usize = 16;
/// Exact poll/wait reply bytes.
pub const STATUS_BYTES: usize = 24;
/// Shell-visible status used for a contained child fault.
pub const FAULT_EXIT_STATUS: u32 = 125;

const MAGIC: [u8; 8] = *b"PSPNv1\0\0";

/// Standard-stream source or destination selected for a child.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum StreamMode {
    /// Share the launching process's corresponding standard stream.
    Inherit = 1,
    /// Attach an immediate EOF input or discarded output endpoint.
    Null = 2,
    /// Attach the corresponding endpoint of an owner-scoped pipe.
    Pipe = 3,
}

/// One child standard-stream selection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StreamSpec {
    /// Endpoint behavior.
    pub mode: StreamMode,
    /// Nonzero pipe token only when `mode` is [`StreamMode::Pipe`].
    pub pipe: u64,
}

impl StreamSpec {
    /// Inherit the launching process's corresponding stream.
    pub const INHERIT: Self = Self {
        mode: StreamMode::Inherit,
        pipe: 0,
    };
    /// Attach a null endpoint.
    pub const NULL: Self = Self {
        mode: StreamMode::Null,
        pipe: 0,
    };

    /// Attach one owner-scoped pipe token.
    ///
    /// # Errors
    ///
    /// Rejects the reserved zero token.
    pub const fn pipe(token: u64) -> Result<Self, EncodingError> {
        if token == 0 {
            Err(EncodingError)
        } else {
            Ok(Self {
                mode: StreamMode::Pipe,
                pipe: token,
            })
        }
    }
}

/// Borrowed validated child launch request.
#[derive(Clone, Copy, Debug)]
pub struct SpawnRequest<'a> {
    invocation: command::Invocation<'a>,
    environment_table: &'a [u8],
    environment_bytes: &'a [u8],
    environment_count: usize,
    stdin: StreamSpec,
    stdout: StreamSpec,
    stderr: StreamSpec,
}

impl<'a> SpawnRequest<'a> {
    /// Validated cwd and argv record, including command name as argument zero.
    #[must_use]
    pub const fn invocation(self) -> command::Invocation<'a> {
        self.invocation
    }

    /// Environment entries in canonical input order.
    #[must_use]
    pub const fn environment(self) -> Environment<'a> {
        Environment {
            lengths: self.environment_table,
            bytes: self.environment_bytes,
            count: self.environment_count,
            index: 0,
            offset: 0,
        }
    }

    /// Child standard input selection.
    #[must_use]
    pub const fn stdin(self) -> StreamSpec {
        self.stdin
    }

    /// Child standard output selection.
    #[must_use]
    pub const fn stdout(self) -> StreamSpec {
        self.stdout
    }

    /// Child standard error selection.
    #[must_use]
    pub const fn stderr(self) -> StreamSpec {
        self.stderr
    }
}

/// Iterator over validated `NAME=VALUE` environment strings.
#[derive(Clone)]
pub struct Environment<'a> {
    lengths: &'a [u8],
    bytes: &'a [u8],
    count: usize,
    index: usize,
    offset: usize,
}

impl<'a> Iterator for Environment<'a> {
    type Item = &'a str;

    fn next(&mut self) -> Option<Self::Item> {
        if self.index >= self.count {
            return None;
        }
        let at = self.index.checked_mul(2)?;
        let length = usize::from(u16::from_le_bytes([
            *self.lengths.get(at)?,
            *self.lengths.get(at + 1)?,
        ]));
        let end = self.offset.checked_add(length)?;
        let value = str::from_utf8(self.bytes.get(self.offset..end)?).ok()?;
        self.index += 1;
        self.offset = end;
        Some(value)
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let remaining = self.count.saturating_sub(self.index);
        (remaining, Some(remaining))
    }
}

impl ExactSizeIterator for Environment<'_> {}

/// Opaque owner-scoped child capability returned at admission.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ChildToken(u64);

impl ChildToken {
    /// Validate one nonzero opaque value.
    ///
    /// # Errors
    ///
    /// Rejects the reserved zero value.
    pub const fn new(value: u64) -> Result<Self, EncodingError> {
        if value == 0 {
            Err(EncodingError)
        } else {
            Ok(Self(value))
        }
    }

    /// Stable opaque ABI value.
    #[must_use]
    pub const fn value(self) -> u64 {
        self.0
    }
}

/// Successfully admitted child identity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SpawnedChild {
    /// Owner-scoped control capability.
    pub token: ChildToken,
    /// Read-only global observation identity.
    pub process_id: u64,
}

/// Current owner-visible child lifecycle.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum ChildState {
    /// Child has not reached a terminal state.
    Running = 1,
    /// Child exited normally with the returned status.
    Exited = 2,
    /// Child faulted and maps to [`FAULT_EXIT_STATUS`].
    Faulted = 3,
    /// Owner cancellation completed.
    Cancelled = 4,
}

/// Poll or wait result for one child.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ChildStatus {
    /// Owner-scoped child token.
    pub token: ChildToken,
    /// Read-only global process identity.
    pub process_id: u64,
    /// Preserved full application exit status.
    pub exit_status: u32,
    /// Current lifecycle.
    pub state: ChildState,
}

/// Invalid or noncanonical process-launch payload.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EncodingError;

/// Encode one canonical spawn request.
///
/// # Errors
///
/// Rejects malformed invocation/environment data, stream tokens, bounds,
/// or insufficient destination space without modifying it.
pub fn encode_spawn(
    invocation: &[u8],
    environment: &[&str],
    stdin: StreamSpec,
    stdout: StreamSpec,
    stderr: StreamSpec,
    destination: &mut [u8],
) -> Result<usize, EncodingError> {
    let _validated = command::Invocation::parse(invocation).map_err(|_| EncodingError)?;
    validate_stream(stdin)?;
    validate_stream(stdout)?;
    validate_stream(stderr)?;
    if environment.len() > MAX_ENVIRONMENT {
        return Err(EncodingError);
    }
    if has_duplicate_name(environment.iter().copied()) {
        return Err(EncodingError);
    }
    let mut environment_bytes = 0_usize;
    for value in environment {
        validate_environment(value)?;
        environment_bytes = environment_bytes
            .checked_add(value.len())
            .ok_or(EncodingError)?;
    }
    if environment_bytes > MAX_ENVIRONMENT_BYTES {
        return Err(EncodingError);
    }
    let table_bytes = environment.len().checked_mul(2).ok_or(EncodingError)?;
    let total = SPAWN_HEADER_BYTES
        .checked_add(invocation.len())
        .and_then(|value| value.checked_add(table_bytes))
        .and_then(|value| value.checked_add(environment_bytes))
        .ok_or(EncodingError)?;
    if total > MAX_SERVICE_PAYLOAD_BYTES || total > MAX_SPAWN_BYTES || destination.len() < total {
        return Err(EncodingError);
    }
    destination[..total].fill(0);
    destination[..8].copy_from_slice(&MAGIC);
    destination[8..10].copy_from_slice(
        &u16::try_from(total)
            .map_err(|_| EncodingError)?
            .to_le_bytes(),
    );
    destination[10..12].copy_from_slice(
        &u16::try_from(invocation.len())
            .map_err(|_| EncodingError)?
            .to_le_bytes(),
    );
    destination[12..14].copy_from_slice(
        &u16::try_from(environment.len())
            .map_err(|_| EncodingError)?
            .to_le_bytes(),
    );
    destination[14..16].copy_from_slice(
        &u16::try_from(environment_bytes)
            .map_err(|_| EncodingError)?
            .to_le_bytes(),
    );
    destination[16..24].copy_from_slice(&stdin.pipe.to_le_bytes());
    destination[24..32].copy_from_slice(&stdout.pipe.to_le_bytes());
    destination[32..40].copy_from_slice(&stderr.pipe.to_le_bytes());
    destination[40] = stdin.mode as u8;
    destination[41] = stdout.mode as u8;
    destination[42] = stderr.mode as u8;
    let invocation_end = SPAWN_HEADER_BYTES + invocation.len();
    destination[SPAWN_HEADER_BYTES..invocation_end].copy_from_slice(invocation);
    let table_start = invocation_end;
    let values_start = table_start + table_bytes;
    let mut cursor = values_start;
    for (index, value) in environment.iter().enumerate() {
        let at = table_start + index * 2;
        destination[at..at + 2].copy_from_slice(
            &u16::try_from(value.len())
                .map_err(|_| EncodingError)?
                .to_le_bytes(),
        );
        let end = cursor.checked_add(value.len()).ok_or(EncodingError)?;
        destination[cursor..end].copy_from_slice(value.as_bytes());
        cursor = end;
    }
    Ok(total)
}

/// Decode one exact canonical spawn request.
///
/// # Errors
///
/// Rejects every malformed, excessive, non-UTF-8, or trailing byte.
pub fn decode_spawn(bytes: &[u8]) -> Result<SpawnRequest<'_>, EncodingError> {
    if bytes.len() < SPAWN_HEADER_BYTES
        || bytes[..8] != MAGIC
        || usize::from(read_u16(bytes, 8)?) != bytes.len()
        || bytes[43..SPAWN_HEADER_BYTES].iter().any(|byte| *byte != 0)
    {
        return Err(EncodingError);
    }
    let invocation_bytes = usize::from(read_u16(bytes, 10)?);
    let environment_count = usize::from(read_u16(bytes, 12)?);
    let environment_bytes = usize::from(read_u16(bytes, 14)?);
    if environment_count > MAX_ENVIRONMENT || environment_bytes > MAX_ENVIRONMENT_BYTES {
        return Err(EncodingError);
    }
    let table_bytes = environment_count.checked_mul(2).ok_or(EncodingError)?;
    let invocation_end = SPAWN_HEADER_BYTES
        .checked_add(invocation_bytes)
        .ok_or(EncodingError)?;
    let table_end = invocation_end
        .checked_add(table_bytes)
        .ok_or(EncodingError)?;
    let values_end = table_end
        .checked_add(environment_bytes)
        .ok_or(EncodingError)?;
    if values_end != bytes.len() {
        return Err(EncodingError);
    }
    let invocation = command::Invocation::parse(&bytes[SPAWN_HEADER_BYTES..invocation_end])
        .map_err(|_| EncodingError)?;
    let stdin = decode_stream(bytes[40], read_u64(bytes, 16)?)?;
    let stdout = decode_stream(bytes[41], read_u64(bytes, 24)?)?;
    let stderr = decode_stream(bytes[42], read_u64(bytes, 32)?)?;
    let environment_table = &bytes[invocation_end..table_end];
    let environment_values = &bytes[table_end..values_end];
    let environment = Environment {
        lengths: environment_table,
        bytes: environment_values,
        count: environment_count,
        index: 0,
        offset: 0,
    };
    let mut consumed = 0_usize;
    for value in environment.clone() {
        validate_environment(value)?;
        consumed = consumed.checked_add(value.len()).ok_or(EncodingError)?;
    }
    if consumed != environment_bytes || has_duplicate_name(environment) {
        return Err(EncodingError);
    }
    Ok(SpawnRequest {
        invocation,
        environment_table,
        environment_bytes: environment_values,
        environment_count,
        stdin,
        stdout,
        stderr,
    })
}

/// Encode one child token request.
#[must_use]
pub const fn encode_token(token: ChildToken) -> [u8; TOKEN_BYTES] {
    token.value().to_le_bytes()
}

/// Decode one exact child token request.
///
/// # Errors
///
/// Rejects non-exact or zero tokens.
pub fn decode_token(bytes: &[u8]) -> Result<ChildToken, EncodingError> {
    if bytes.len() != TOKEN_BYTES {
        return Err(EncodingError);
    }
    ChildToken::new(read_u64(bytes, 0)?)
}

/// Encode one successful spawn reply.
#[must_use]
pub fn encode_spawned(child: SpawnedChild) -> [u8; SPAWN_REPLY_BYTES] {
    let mut bytes = [0_u8; SPAWN_REPLY_BYTES];
    bytes[..8].copy_from_slice(&child.token.value().to_le_bytes());
    bytes[8..16].copy_from_slice(&child.process_id.to_le_bytes());
    bytes
}

/// Decode one successful spawn reply.
///
/// # Errors
///
/// Rejects non-exact, zero, or invalid identities.
pub fn decode_spawned(bytes: &[u8]) -> Result<SpawnedChild, EncodingError> {
    if bytes.len() != SPAWN_REPLY_BYTES {
        return Err(EncodingError);
    }
    let process_id = read_u64(bytes, 8)?;
    if process_id == 0 {
        return Err(EncodingError);
    }
    Ok(SpawnedChild {
        token: ChildToken::new(read_u64(bytes, 0)?)?,
        process_id,
    })
}

/// Encode one canonical child status.
///
/// # Errors
///
/// Rejects inconsistent state/status combinations.
pub fn encode_status(status: ChildStatus) -> Result<[u8; STATUS_BYTES], EncodingError> {
    validate_status(status)?;
    let mut bytes = [0_u8; STATUS_BYTES];
    bytes[..8].copy_from_slice(&status.token.value().to_le_bytes());
    bytes[8..16].copy_from_slice(&status.process_id.to_le_bytes());
    bytes[16..20].copy_from_slice(&status.exit_status.to_le_bytes());
    bytes[20] = status.state as u8;
    Ok(bytes)
}

/// Decode one exact child status.
///
/// # Errors
///
/// Rejects malformed, reserved, or inconsistent values.
pub fn decode_status(bytes: &[u8]) -> Result<ChildStatus, EncodingError> {
    if bytes.len() != STATUS_BYTES || bytes[21..].iter().any(|byte| *byte != 0) {
        return Err(EncodingError);
    }
    let status = ChildStatus {
        token: ChildToken::new(read_u64(bytes, 0)?)?,
        process_id: read_u64(bytes, 8)?,
        exit_status: read_u32(bytes, 16)?,
        state: match bytes[20] {
            1 => ChildState::Running,
            2 => ChildState::Exited,
            3 => ChildState::Faulted,
            4 => ChildState::Cancelled,
            _ => return Err(EncodingError),
        },
    };
    validate_status(status)?;
    Ok(status)
}

fn validate_stream(stream: StreamSpec) -> Result<(), EncodingError> {
    if (stream.mode == StreamMode::Pipe) != (stream.pipe != 0) {
        return Err(EncodingError);
    }
    Ok(())
}

fn decode_stream(mode: u8, pipe: u64) -> Result<StreamSpec, EncodingError> {
    let stream = StreamSpec {
        mode: match mode {
            1 => StreamMode::Inherit,
            2 => StreamMode::Null,
            3 => StreamMode::Pipe,
            _ => return Err(EncodingError),
        },
        pipe,
    };
    validate_stream(stream)?;
    Ok(stream)
}

/// Whether any two validated entries declare the same name.
fn has_duplicate_name<'a, I>(entries: I) -> bool
where
    I: Iterator<Item = &'a str> + Clone,
{
    let mut remaining = entries;
    while let Some(entry) = remaining.next() {
        let Some((name, _)) = entry.split_once('=') else {
            continue;
        };
        if remaining
            .clone()
            .filter_map(|later| later.split_once('=').map(|(later, _)| later))
            .any(|later| later == name)
        {
            return true;
        }
    }
    false
}

fn validate_environment(value: &str) -> Result<(), EncodingError> {
    let Some((name, _value)) = value.split_once('=') else {
        return Err(EncodingError);
    };
    if name.is_empty()
        || name.as_bytes().first().is_some_and(u8::is_ascii_digit)
        || !name
            .as_bytes()
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || *byte == b'_')
        || value.as_bytes().contains(&0)
    {
        return Err(EncodingError);
    }
    Ok(())
}

fn validate_status(status: ChildStatus) -> Result<(), EncodingError> {
    if status.process_id == 0
        || (status.state == ChildState::Running && status.exit_status != 0)
        || (status.state == ChildState::Faulted && status.exit_status != FAULT_EXIT_STATUS)
        || (status.state == ChildState::Cancelled && status.exit_status != exit::CANCELLED)
    {
        return Err(EncodingError);
    }
    Ok(())
}

fn read_u16(bytes: &[u8], offset: usize) -> Result<u16, EncodingError> {
    let raw = bytes.get(offset..offset + 2).ok_or(EncodingError)?;
    Ok(u16::from_le_bytes([raw[0], raw[1]]))
}

fn read_u32(bytes: &[u8], offset: usize) -> Result<u32, EncodingError> {
    let raw = bytes.get(offset..offset + 4).ok_or(EncodingError)?;
    Ok(u32::from_le_bytes([raw[0], raw[1], raw[2], raw[3]]))
}

fn read_u64(bytes: &[u8], offset: usize) -> Result<u64, EncodingError> {
    let raw = bytes.get(offset..offset + 8).ok_or(EncodingError)?;
    Ok(u64::from_le_bytes([
        raw[0], raw[1], raw[2], raw[3], raw[4], raw[5], raw[6], raw[7],
    ]))
}

#[cfg(test)]
mod tests {
    use crate::{command, pipe, process_launch};

    #[test]
    fn process_launch_records_are_canonical_owner_scoped_and_full_status() {
        let mut invocation = [0_u8; command::MAX_INVOCATION_BYTES];
        let invocation_bytes = command::encode("/work", &["status", "203"], &mut invocation)
            .unwrap_or_else(|_| std::process::abort());
        let pipe_token =
            pipe::PipeToken::new(0x0000_0001_0000_0001).unwrap_or_else(|_| std::process::abort());
        let pipe_stream = process_launch::StreamSpec::pipe(pipe_token.value())
            .unwrap_or_else(|_| std::process::abort());
        let mut spawn = [0xa5_u8; process_launch::MAX_SPAWN_BYTES];
        let count = process_launch::encode_spawn(
            &invocation[..invocation_bytes],
            &["LANG=C", "PATH=/bin"],
            process_launch::StreamSpec::NULL,
            pipe_stream,
            process_launch::StreamSpec::INHERIT,
            &mut spawn,
        )
        .unwrap_or_else(|_| std::process::abort());
        let decoded =
            process_launch::decode_spawn(&spawn[..count]).unwrap_or_else(|_| std::process::abort());
        assert_eq!(decoded.invocation().cwd(), "/work");
        assert_eq!(
            decoded
                .invocation()
                .arguments()
                .collect::<std::vec::Vec<_>>(),
            ["status", "203"]
        );
        assert_eq!(
            decoded.environment().collect::<std::vec::Vec<_>>(),
            ["LANG=C", "PATH=/bin"]
        );
        assert_eq!(decoded.stdout(), pipe_stream);
        assert!(process_launch::decode_spawn(&spawn[..count - 1]).is_err());
        assert!(
            process_launch::encode_spawn(
                &invocation[..invocation_bytes],
                &["9BAD=value"],
                process_launch::StreamSpec::NULL,
                pipe_stream,
                process_launch::StreamSpec::INHERIT,
                &mut spawn,
            )
            .is_err()
        );

        let token = process_launch::ChildToken::new(0x0000_0002_0000_0001)
            .unwrap_or_else(|_| std::process::abort());
        let status = process_launch::ChildStatus {
            token,
            process_id: u64::MAX,
            exit_status: u32::MAX,
            state: process_launch::ChildState::Exited,
        };
        let encoded =
            process_launch::encode_status(status).unwrap_or_else(|_| std::process::abort());
        assert_eq!(process_launch::decode_status(&encoded), Ok(status));
    }
}
