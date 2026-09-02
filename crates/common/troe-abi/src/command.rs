//! Command-invocation protocol.

use super::{MAX_MESSAGE_BYTES, str};

/// Interface major version.
pub const MAJOR: u16 = 1;
/// Interface minor version.
pub const MINOR: u16 = 2;
/// Return the immutable invocation record.
pub const GET_INVOCATION: u16 = 1;
/// Return the immutable launch environment.
pub const GET_ENVIRONMENT: u16 = 2;
/// Return one bounded page of the immutable argument vector.
pub const GET_ARGUMENT_PAGE: u16 = 3;
/// Maximum arguments including the command name.
pub const MAX_ARGUMENTS: usize = 128;
/// Maximum encoded current-directory bytes.
pub const MAX_CWD_BYTES: usize = 256;
/// Maximum aggregate UTF-8 argument bytes.
pub const MAX_ARGUMENT_BYTES: usize = 1024;
/// Fixed invocation header bytes.
pub const HEADER_BYTES: usize = 8;
/// Maximum complete canonical invocation reply.
pub const MAX_INVOCATION_BYTES: usize =
    HEADER_BYTES + MAX_ARGUMENTS * 2 + MAX_CWD_BYTES + MAX_ARGUMENT_BYTES;
/// Maximum arguments in one paged record, including the command name.
///
/// A record larger than [`MAX_ARGUMENTS`] cannot be returned as one
/// message, so it is read page by page instead of being truncated.
pub const MAX_PAGED_ARGUMENTS: usize = 4096;
/// Maximum aggregate UTF-8 argument bytes in one paged record.
pub const MAX_PAGED_ARGUMENT_BYTES: usize = 64 * 1024;
/// Maximum UTF-8 bytes in any one argument.
///
/// Bounded so that every argument always fits inside one page.
pub const MAX_SINGLE_ARGUMENT_BYTES: usize = 1024;
/// Maximum arguments returned by one page.
pub const MAX_ARGUMENT_PAGE: usize = 64;
/// Maximum aggregate argument bytes returned by one page.
pub const MAX_ARGUMENT_PAGE_BYTES: usize = MAX_SINGLE_ARGUMENT_BYTES;
/// Fixed argument-page reply header bytes.
pub const ARGUMENT_PAGE_HEADER_BYTES: usize = 10;
/// Maximum canonical argument-page reply.
pub const MAX_ARGUMENT_PAGE_REPLY_BYTES: usize =
    ARGUMENT_PAGE_HEADER_BYTES + MAX_ARGUMENT_PAGE * 2 + MAX_ARGUMENT_PAGE_BYTES;
/// Exact canonical argument-page request bytes.
pub const ARGUMENT_PAGE_REQUEST_BYTES: usize = 2;
/// Conventional values a trusted top-level launcher supplies.
///
/// These belong to whichever component composes a launch. An application
/// never synthesizes them: it reads only what its launcher supplied, so
/// this list is shared by the composing side of every boundary rather than
/// compiled into the programs being launched.
pub const CONVENTIONAL_ENVIRONMENT: [&str; 7] = [
    "HOME=/",
    "PATH=/bin",
    "TMPDIR=/tmp",
    "SHELL=/bin/sh",
    "USER=root",
    "LOGNAME=root",
    // Every launch carries an explicit zone, so no conversion has to treat
    // an absent `TZ` as a special case. See ADR 0067.
    "TZ=UTC0",
];
/// Name of the conventional entry carrying the POSIX zone string.
pub const TIMEZONE_NAME: &str = "TZ";

/// The conventional entries with `TZ` replaced by one supplied entry.
///
/// A launcher that resolves a zone from configuration substitutes it here
/// rather than restating the other conventional names, so the list keeps
/// the single definition ADR 0054 gave it. `entry` is a complete
/// `TZ=VALUE` string whose value the caller has already validated. An
/// entry that does not name `TZ` leaves the list unchanged, because
/// silently renaming a caller's entry would be worse than ignoring it.
#[must_use]
pub fn conventional_environment_with_timezone(
    entry: &str,
) -> [&str; CONVENTIONAL_ENVIRONMENT.len()] {
    let mut composed = CONVENTIONAL_ENVIRONMENT;
    if entry
        .split_once('=')
        .is_some_and(|(name, _)| name == TIMEZONE_NAME)
    {
        for slot in &mut composed {
            if slot
                .split_once('=')
                .is_some_and(|(name, _)| name == TIMEZONE_NAME)
            {
                *slot = entry;
            }
        }
    }
    composed
}

/// Maximum launch-environment entries.
pub const MAX_ENVIRONMENT: usize = 128;
/// Maximum aggregate UTF-8 environment bytes.
pub const MAX_ENVIRONMENT_BYTES: usize = 2048;
/// Fixed launch-environment header bytes.
pub const ENVIRONMENT_HEADER_BYTES: usize = 4;
/// Maximum canonical launch-environment reply.
pub const MAX_ENCODED_ENVIRONMENT_BYTES: usize =
    ENVIRONMENT_HEADER_BYTES + MAX_ENVIRONMENT * 2 + MAX_ENVIRONMENT_BYTES;

/// Invocation encoding failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EncodeError {
    /// Argument count, current directory, or total bytes exceeded a bound.
    LimitExceeded,
    /// The current directory was not an absolute path.
    InvalidCwd,
    /// The destination cannot hold the exact canonical record.
    DestinationTooSmall,
}

/// Invocation decoding failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DecodeError {
    /// Header, version, length, or string-table layout was noncanonical.
    InvalidEncoding,
    /// Argument count or current-directory bytes exceeded a bound.
    LimitExceeded,
    /// Current-directory or argument bytes were not valid UTF-8.
    InvalidUtf8,
}

/// Borrowed, validated command invocation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Invocation<'a> {
    bytes: &'a [u8],
    argument_count: usize,
    cwd_start: usize,
    cwd_end: usize,
    arguments_start: usize,
}

impl<'a> Invocation<'a> {
    /// Parse one exact canonical invocation reply.
    ///
    /// # Errors
    ///
    /// Rejects every malformed, excessive, non-UTF-8, or trailing byte.
    pub fn parse(bytes: &'a [u8]) -> Result<Self, DecodeError> {
        if bytes.len() < HEADER_BYTES
            || usize::from(read_u16(bytes, 0)?) != bytes.len()
            || bytes[2] != u8::try_from(MAJOR).unwrap_or(u8::MAX)
            || bytes[3] != u8::try_from(MINOR).unwrap_or(u8::MAX)
        {
            return Err(DecodeError::InvalidEncoding);
        }
        let argument_count = usize::from(read_u16(bytes, 4)?);
        let cwd_bytes = usize::from(read_u16(bytes, 6)?);
        if !(1..=MAX_ARGUMENTS).contains(&argument_count) || cwd_bytes > MAX_CWD_BYTES {
            return Err(DecodeError::LimitExceeded);
        }
        let length_table_bytes = argument_count
            .checked_mul(2)
            .ok_or(DecodeError::InvalidEncoding)?;
        let cwd_start = HEADER_BYTES
            .checked_add(length_table_bytes)
            .ok_or(DecodeError::InvalidEncoding)?;
        let cwd_end = cwd_start
            .checked_add(cwd_bytes)
            .ok_or(DecodeError::InvalidEncoding)?;
        if cwd_end > bytes.len() {
            return Err(DecodeError::InvalidEncoding);
        }
        let cwd =
            str::from_utf8(&bytes[cwd_start..cwd_end]).map_err(|_| DecodeError::InvalidUtf8)?;
        if !cwd.starts_with('/') {
            return Err(DecodeError::InvalidEncoding);
        }
        let mut cursor = cwd_end;
        let mut argument_bytes = 0_usize;
        for index in 0..argument_count {
            let length = usize::from(read_u16(bytes, HEADER_BYTES + index * 2)?);
            argument_bytes = argument_bytes
                .checked_add(length)
                .ok_or(DecodeError::InvalidEncoding)?;
            if argument_bytes > MAX_ARGUMENT_BYTES {
                return Err(DecodeError::LimitExceeded);
            }
            let end = cursor
                .checked_add(length)
                .ok_or(DecodeError::InvalidEncoding)?;
            if end > bytes.len() || str::from_utf8(&bytes[cursor..end]).is_err() {
                return Err(if end > bytes.len() {
                    DecodeError::InvalidEncoding
                } else {
                    DecodeError::InvalidUtf8
                });
            }
            if index == 0 && length == 0 {
                return Err(DecodeError::InvalidEncoding);
            }
            cursor = end;
        }
        if cursor != bytes.len() {
            return Err(DecodeError::InvalidEncoding);
        }
        Ok(Self {
            bytes,
            argument_count,
            cwd_start,
            cwd_end,
            arguments_start: cwd_end,
        })
    }

    /// Absolute logical working directory selected by the shell.
    #[must_use]
    pub fn cwd(self) -> &'a str {
        // Parsing validated this exact range as UTF-8.
        str::from_utf8(&self.bytes[self.cwd_start..self.cwd_end]).unwrap_or("")
    }

    /// Number of arguments, including the command name at index zero.
    #[must_use]
    pub const fn len(self) -> usize {
        self.argument_count
    }

    /// Invocations always contain a command name.
    #[must_use]
    pub const fn is_empty(self) -> bool {
        false
    }

    /// Return one validated argument.
    #[must_use]
    pub fn argument(self, wanted: usize) -> Option<&'a str> {
        if wanted >= self.argument_count {
            return None;
        }
        let mut cursor = self.arguments_start;
        for index in 0..self.argument_count {
            let length = usize::from(read_u16(self.bytes, HEADER_BYTES + index * 2).ok()?);
            let end = cursor.checked_add(length)?;
            if index == wanted {
                return str::from_utf8(&self.bytes[cursor..end]).ok();
            }
            cursor = end;
        }
        None
    }

    /// Iterate over every validated argument.
    #[must_use]
    pub fn arguments(self) -> Arguments<'a> {
        Arguments {
            invocation: self,
            index: 0,
        }
    }
}

/// Iterator over borrowed invocation arguments.
pub struct Arguments<'a> {
    invocation: Invocation<'a>,
    index: usize,
}

impl<'a> Iterator for Arguments<'a> {
    type Item = &'a str;

    fn next(&mut self) -> Option<Self::Item> {
        let value = self.invocation.argument(self.index)?;
        self.index += 1;
        Some(value)
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let remaining = self.invocation.len().saturating_sub(self.index);
        (remaining, Some(remaining))
    }
}

impl ExactSizeIterator for Arguments<'_> {}

/// Borrowed validated `NAME=VALUE` launch environment.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Environment<'a> {
    bytes: &'a [u8],
    count: usize,
    values_start: usize,
}

impl<'a> Environment<'a> {
    /// Parse one exact canonical launch environment.
    ///
    /// # Errors
    ///
    /// Rejects malformed lengths, invalid UTF-8/names, bounds, or trailing bytes.
    pub fn parse(bytes: &'a [u8]) -> Result<Self, DecodeError> {
        if bytes.len() < ENVIRONMENT_HEADER_BYTES || usize::from(read_u16(bytes, 0)?) != bytes.len()
        {
            return Err(DecodeError::InvalidEncoding);
        }
        let count = usize::from(read_u16(bytes, 2)?);
        if count > MAX_ENVIRONMENT {
            return Err(DecodeError::LimitExceeded);
        }
        let values_start = ENVIRONMENT_HEADER_BYTES
            .checked_add(count.checked_mul(2).ok_or(DecodeError::InvalidEncoding)?)
            .ok_or(DecodeError::InvalidEncoding)?;
        if values_start > bytes.len()
            || bytes.len().saturating_sub(values_start) > MAX_ENVIRONMENT_BYTES
        {
            return Err(DecodeError::LimitExceeded);
        }
        let environment = Self {
            bytes,
            count,
            values_start,
        };
        let mut end = values_start;
        for value in environment.iter() {
            validate_environment(value).map_err(|_| DecodeError::InvalidEncoding)?;
            end = end
                .checked_add(value.len())
                .ok_or(DecodeError::InvalidEncoding)?;
        }
        if end != bytes.len() || has_duplicate_name(environment.iter()) {
            return Err(DecodeError::InvalidEncoding);
        }
        Ok(environment)
    }

    /// Number of launch-environment entries.
    #[must_use]
    pub const fn len(self) -> usize {
        self.count
    }

    /// Whether no environment entries were supplied.
    #[must_use]
    pub const fn is_empty(self) -> bool {
        self.count == 0
    }

    /// Iterate over canonical `NAME=VALUE` entries in launch order.
    #[must_use]
    pub const fn iter(self) -> EnvironmentEntries<'a> {
        EnvironmentEntries {
            environment: self,
            index: 0,
            offset: self.values_start,
        }
    }
}

/// Iterator over validated launch-environment entries.
#[derive(Clone)]
pub struct EnvironmentEntries<'a> {
    environment: Environment<'a>,
    index: usize,
    offset: usize,
}

impl<'a> Iterator for EnvironmentEntries<'a> {
    type Item = &'a str;

    fn next(&mut self) -> Option<Self::Item> {
        if self.index >= self.environment.count {
            return None;
        }
        let length = usize::from(
            read_u16(
                self.environment.bytes,
                ENVIRONMENT_HEADER_BYTES + self.index * 2,
            )
            .ok()?,
        );
        let end = self.offset.checked_add(length)?;
        let value = str::from_utf8(self.environment.bytes.get(self.offset..end)?).ok()?;
        self.index += 1;
        self.offset = end;
        Some(value)
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let remaining = self.environment.count.saturating_sub(self.index);
        (remaining, Some(remaining))
    }
}

impl ExactSizeIterator for EnvironmentEntries<'_> {}

/// Encode canonical `NAME=VALUE` launch entries.
///
/// # Errors
///
/// Rejects invalid names, bounds, arithmetic overflow, or insufficient space.
pub fn encode_environment(
    environment: &[&str],
    destination: &mut [u8],
) -> Result<usize, EncodeError> {
    if environment.len() > MAX_ENVIRONMENT {
        return Err(EncodeError::LimitExceeded);
    }
    let values_bytes = environment.iter().try_fold(0_usize, |total, value| {
        validate_environment(value)?;
        total
            .checked_add(value.len())
            .ok_or(EncodeError::LimitExceeded)
    })?;
    if has_duplicate_name(environment.iter().copied()) {
        return Err(EncodeError::LimitExceeded);
    }
    if values_bytes > MAX_ENVIRONMENT_BYTES {
        return Err(EncodeError::LimitExceeded);
    }
    let total = ENVIRONMENT_HEADER_BYTES
        .checked_add(
            environment
                .len()
                .checked_mul(2)
                .ok_or(EncodeError::LimitExceeded)?,
        )
        .and_then(|value| value.checked_add(values_bytes))
        .ok_or(EncodeError::LimitExceeded)?;
    if total > MAX_ENCODED_ENVIRONMENT_BYTES || destination.len() < total {
        return Err(EncodeError::DestinationTooSmall);
    }
    let mut encoded = [0_u8; MAX_ENCODED_ENVIRONMENT_BYTES];
    write_u16(
        &mut encoded,
        0,
        u16::try_from(total).map_err(|_| EncodeError::LimitExceeded)?,
    );
    write_u16(
        &mut encoded,
        2,
        u16::try_from(environment.len()).map_err(|_| EncodeError::LimitExceeded)?,
    );
    let mut cursor = ENVIRONMENT_HEADER_BYTES + environment.len() * 2;
    for (index, value) in environment.iter().enumerate() {
        write_u16(
            &mut encoded,
            ENVIRONMENT_HEADER_BYTES + index * 2,
            u16::try_from(value.len()).map_err(|_| EncodeError::LimitExceeded)?,
        );
        let end = cursor
            .checked_add(value.len())
            .ok_or(EncodeError::LimitExceeded)?;
        encoded[cursor..end].copy_from_slice(value.as_bytes());
        cursor = end;
    }
    destination[..total].copy_from_slice(&encoded[..total]);
    Ok(total)
}

/// Encode one canonical invocation into caller-owned storage.
///
/// # Errors
///
/// Rejects invalid current directories, policy excess, arithmetic overflow,
/// or insufficient output space without modifying `destination`.
pub fn encode<T: AsRef<str>>(
    cwd: &str,
    arguments: &[T],
    destination: &mut [u8],
) -> Result<usize, EncodeError> {
    if !cwd.starts_with('/') {
        return Err(EncodeError::InvalidCwd);
    }
    if cwd.len() > MAX_CWD_BYTES || !(1..=MAX_ARGUMENTS).contains(&arguments.len()) {
        return Err(EncodeError::LimitExceeded);
    }
    let mut total = HEADER_BYTES
        .checked_add(
            arguments
                .len()
                .checked_mul(2)
                .ok_or(EncodeError::LimitExceeded)?,
        )
        .and_then(|value| value.checked_add(cwd.len()))
        .ok_or(EncodeError::LimitExceeded)?;
    let mut argument_bytes = 0_usize;
    for (index, argument) in arguments.iter().enumerate() {
        let length = argument.as_ref().len();
        if (index == 0 && length == 0) || length > usize::from(u16::MAX) {
            return Err(EncodeError::LimitExceeded);
        }
        argument_bytes = argument_bytes
            .checked_add(length)
            .ok_or(EncodeError::LimitExceeded)?;
        if argument_bytes > MAX_ARGUMENT_BYTES {
            return Err(EncodeError::LimitExceeded);
        }
        total = total
            .checked_add(length)
            .ok_or(EncodeError::LimitExceeded)?;
    }
    if total > MAX_INVOCATION_BYTES || total > MAX_MESSAGE_BYTES || total > usize::from(u16::MAX) {
        return Err(EncodeError::LimitExceeded);
    }
    if destination.len() < total {
        return Err(EncodeError::DestinationTooSmall);
    }
    let mut encoded = [0_u8; MAX_MESSAGE_BYTES];
    write_u16(
        &mut encoded,
        0,
        u16::try_from(total).map_err(|_| EncodeError::LimitExceeded)?,
    );
    encoded[2] = u8::try_from(MAJOR).map_err(|_| EncodeError::LimitExceeded)?;
    encoded[3] = u8::try_from(MINOR).map_err(|_| EncodeError::LimitExceeded)?;
    write_u16(
        &mut encoded,
        4,
        u16::try_from(arguments.len()).map_err(|_| EncodeError::LimitExceeded)?,
    );
    write_u16(
        &mut encoded,
        6,
        u16::try_from(cwd.len()).map_err(|_| EncodeError::LimitExceeded)?,
    );
    let mut cursor = HEADER_BYTES + arguments.len() * 2;
    encoded[cursor..cursor + cwd.len()].copy_from_slice(cwd.as_bytes());
    cursor += cwd.len();
    for (index, argument) in arguments.iter().enumerate() {
        let bytes = argument.as_ref().as_bytes();
        write_u16(
            &mut encoded,
            HEADER_BYTES + index * 2,
            u16::try_from(bytes.len()).map_err(|_| EncodeError::LimitExceeded)?,
        );
        encoded[cursor..cursor + bytes.len()].copy_from_slice(bytes);
        cursor += bytes.len();
    }
    destination[..total].copy_from_slice(&encoded[..total]);
    Ok(total)
}

/// Encode the exact canonical request for one argument page.
///
/// # Errors
///
/// Rejects a start index beyond the paged bound or insufficient space.
pub fn encode_argument_page_request(
    start: usize,
    destination: &mut [u8],
) -> Result<usize, EncodeError> {
    if start > MAX_PAGED_ARGUMENTS || destination.len() < ARGUMENT_PAGE_REQUEST_BYTES {
        return Err(if start > MAX_PAGED_ARGUMENTS {
            EncodeError::LimitExceeded
        } else {
            EncodeError::DestinationTooSmall
        });
    }
    write_u16(
        destination,
        0,
        u16::try_from(start).map_err(|_| EncodeError::LimitExceeded)?,
    );
    Ok(ARGUMENT_PAGE_REQUEST_BYTES)
}

/// Decode the exact canonical request for one argument page.
///
/// # Errors
///
/// Rejects any length other than the canonical request or an excessive index.
pub fn decode_argument_page_request(bytes: &[u8]) -> Result<usize, DecodeError> {
    if bytes.len() != ARGUMENT_PAGE_REQUEST_BYTES {
        return Err(DecodeError::InvalidEncoding);
    }
    let start = usize::from(read_u16(bytes, 0)?);
    if start > MAX_PAGED_ARGUMENTS {
        return Err(DecodeError::LimitExceeded);
    }
    Ok(start)
}

/// Encode one canonical argument page starting at `start`.
///
/// The page carries as many consecutive arguments as fit within
/// [`MAX_ARGUMENT_PAGE`] and [`MAX_ARGUMENT_PAGE_BYTES`]. A start index
/// equal to `total` encodes the canonical empty final page, so a reader
/// always terminates.
///
/// `value` returns one argument by its absolute index and is the only way
/// the record is read, so a flat owned string table needs no intermediate
/// slice of references.
///
/// # Errors
///
/// Rejects a start index past `total`, a record exceeding the paged
/// bounds, an absent index below `total`, an argument exceeding
/// [`MAX_SINGLE_ARGUMENT_BYTES`], arithmetic overflow, or insufficient
/// output space.
pub fn encode_argument_page_with<'value, F>(
    total: usize,
    start: usize,
    value: F,
    destination: &mut [u8],
) -> Result<usize, EncodeError>
where
    F: Fn(usize) -> Option<&'value str>,
{
    if !(1..=MAX_PAGED_ARGUMENTS).contains(&total) || start > total {
        return Err(EncodeError::LimitExceeded);
    }
    let mut count = 0_usize;
    let mut page_bytes = 0_usize;
    while start + count < total {
        let argument = value(start + count).ok_or(EncodeError::LimitExceeded)?;
        let length = argument.len();
        if length > MAX_SINGLE_ARGUMENT_BYTES || (start + count == 0 && length == 0) {
            return Err(EncodeError::LimitExceeded);
        }
        let next_bytes = page_bytes
            .checked_add(length)
            .ok_or(EncodeError::LimitExceeded)?;
        if count == MAX_ARGUMENT_PAGE || next_bytes > MAX_ARGUMENT_PAGE_BYTES {
            break;
        }
        page_bytes = next_bytes;
        count += 1;
    }
    let total_bytes = ARGUMENT_PAGE_HEADER_BYTES
        .checked_add(count.checked_mul(2).ok_or(EncodeError::LimitExceeded)?)
        .and_then(|value| value.checked_add(page_bytes))
        .ok_or(EncodeError::LimitExceeded)?;
    if total_bytes > MAX_ARGUMENT_PAGE_REPLY_BYTES || total_bytes > MAX_MESSAGE_BYTES {
        return Err(EncodeError::LimitExceeded);
    }
    if destination.len() < total_bytes {
        return Err(EncodeError::DestinationTooSmall);
    }
    write_u16(
        destination,
        0,
        u16::try_from(total_bytes).map_err(|_| EncodeError::LimitExceeded)?,
    );
    destination[2] = u8::try_from(MAJOR).map_err(|_| EncodeError::LimitExceeded)?;
    destination[3] = u8::try_from(MINOR).map_err(|_| EncodeError::LimitExceeded)?;
    write_u16(
        destination,
        4,
        u16::try_from(total).map_err(|_| EncodeError::LimitExceeded)?,
    );
    write_u16(
        destination,
        6,
        u16::try_from(start).map_err(|_| EncodeError::LimitExceeded)?,
    );
    write_u16(
        destination,
        8,
        u16::try_from(count).map_err(|_| EncodeError::LimitExceeded)?,
    );
    let mut cursor = ARGUMENT_PAGE_HEADER_BYTES + count * 2;
    for index in 0..count {
        let bytes = value(start + index)
            .ok_or(EncodeError::LimitExceeded)?
            .as_bytes();
        write_u16(
            destination,
            ARGUMENT_PAGE_HEADER_BYTES + index * 2,
            u16::try_from(bytes.len()).map_err(|_| EncodeError::LimitExceeded)?,
        );
        destination[cursor..cursor + bytes.len()].copy_from_slice(bytes);
        cursor += bytes.len();
    }
    Ok(total_bytes)
}

/// Encode one canonical argument page from a contiguous argument slice.
///
/// # Errors
///
/// Reports every failure of [`encode_argument_page_with`].
pub fn encode_argument_page<T: AsRef<str>>(
    arguments: &[T],
    start: usize,
    destination: &mut [u8],
) -> Result<usize, EncodeError> {
    encode_argument_page_with(
        arguments.len(),
        start,
        |index| arguments.get(index).map(AsRef::as_ref),
        destination,
    )
}

/// One borrowed, validated page of an immutable argument vector.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ArgumentPage<'a> {
    bytes: &'a [u8],
    total: usize,
    start: usize,
    count: usize,
    values_start: usize,
}

impl<'a> ArgumentPage<'a> {
    /// Parse one exact canonical argument page.
    ///
    /// # Errors
    ///
    /// Rejects every malformed, excessive, non-UTF-8, or trailing byte.
    pub fn parse(bytes: &'a [u8]) -> Result<Self, DecodeError> {
        if bytes.len() < ARGUMENT_PAGE_HEADER_BYTES
            || usize::from(read_u16(bytes, 0)?) != bytes.len()
            || bytes[2] != u8::try_from(MAJOR).unwrap_or(u8::MAX)
            || bytes[3] != u8::try_from(MINOR).unwrap_or(u8::MAX)
        {
            return Err(DecodeError::InvalidEncoding);
        }
        let total = usize::from(read_u16(bytes, 4)?);
        let start = usize::from(read_u16(bytes, 6)?);
        let count = usize::from(read_u16(bytes, 8)?);
        if !(1..=MAX_PAGED_ARGUMENTS).contains(&total) || count > MAX_ARGUMENT_PAGE {
            return Err(DecodeError::LimitExceeded);
        }
        let end = start
            .checked_add(count)
            .ok_or(DecodeError::InvalidEncoding)?;
        if start > total || end > total {
            return Err(DecodeError::InvalidEncoding);
        }
        let values_start = ARGUMENT_PAGE_HEADER_BYTES
            .checked_add(count.checked_mul(2).ok_or(DecodeError::InvalidEncoding)?)
            .ok_or(DecodeError::InvalidEncoding)?;
        if values_start > bytes.len() {
            return Err(DecodeError::InvalidEncoding);
        }
        let mut cursor = values_start;
        let mut page_bytes = 0_usize;
        for index in 0..count {
            let length = usize::from(read_u16(bytes, ARGUMENT_PAGE_HEADER_BYTES + index * 2)?);
            if length > MAX_SINGLE_ARGUMENT_BYTES {
                return Err(DecodeError::LimitExceeded);
            }
            page_bytes = page_bytes
                .checked_add(length)
                .ok_or(DecodeError::InvalidEncoding)?;
            if page_bytes > MAX_ARGUMENT_PAGE_BYTES {
                return Err(DecodeError::LimitExceeded);
            }
            let value_end = cursor
                .checked_add(length)
                .ok_or(DecodeError::InvalidEncoding)?;
            if value_end > bytes.len() {
                return Err(DecodeError::InvalidEncoding);
            }
            if str::from_utf8(&bytes[cursor..value_end]).is_err() {
                return Err(DecodeError::InvalidUtf8);
            }
            if start + index == 0 && length == 0 {
                return Err(DecodeError::InvalidEncoding);
            }
            cursor = value_end;
        }
        if cursor != bytes.len() {
            return Err(DecodeError::InvalidEncoding);
        }
        Ok(Self {
            bytes,
            total,
            start,
            count,
            values_start,
        })
    }

    /// Total arguments in the whole record, including the command name.
    #[must_use]
    pub const fn total(self) -> usize {
        self.total
    }

    /// Index of this page's first argument within the whole record.
    #[must_use]
    pub const fn start(self) -> usize {
        self.start
    }

    /// Arguments carried by this page.
    #[must_use]
    pub const fn len(self) -> usize {
        self.count
    }

    /// Whether this page carries no argument.
    #[must_use]
    pub const fn is_empty(self) -> bool {
        self.count == 0
    }

    /// Index of the first argument after this page.
    ///
    /// Equals [`total`](Self::total) once the record has been read.
    #[must_use]
    pub const fn next_start(self) -> usize {
        self.start + self.count
    }

    /// Return one argument by its index within this page.
    #[must_use]
    pub fn get(self, wanted: usize) -> Option<&'a str> {
        if wanted >= self.count {
            return None;
        }
        let mut cursor = self.values_start;
        for index in 0..self.count {
            let length =
                usize::from(read_u16(self.bytes, ARGUMENT_PAGE_HEADER_BYTES + index * 2).ok()?);
            let end = cursor.checked_add(length)?;
            if index == wanted {
                return str::from_utf8(&self.bytes[cursor..end]).ok();
            }
            cursor = end;
        }
        None
    }

    /// Iterate over every argument carried by this page.
    #[must_use]
    pub fn iter(self) -> PageArguments<'a> {
        PageArguments {
            page: self,
            index: 0,
        }
    }
}

/// Iterator over one borrowed argument page.
pub struct PageArguments<'a> {
    page: ArgumentPage<'a>,
    index: usize,
}

impl<'a> Iterator for PageArguments<'a> {
    type Item = &'a str;

    fn next(&mut self) -> Option<Self::Item> {
        let value = self.page.get(self.index)?;
        self.index += 1;
        Some(value)
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let remaining = self.page.len().saturating_sub(self.index);
        (remaining, Some(remaining))
    }
}

impl ExactSizeIterator for PageArguments<'_> {}

fn read_u16(bytes: &[u8], offset: usize) -> Result<u16, DecodeError> {
    let raw = bytes
        .get(offset..offset + 2)
        .ok_or(DecodeError::InvalidEncoding)?;
    Ok(u16::from_le_bytes([raw[0], raw[1]]))
}

/// Whether any two validated entries declare the same name.
///
/// Duplicate names are rejected at the canonical boundary rather than
/// resolved by position, so no consumer has to remember a precedence rule
/// and no reply can carry an ambiguous environment.
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

fn validate_environment(value: &str) -> Result<(), EncodeError> {
    let Some((name, _)) = value.split_once('=') else {
        return Err(EncodeError::LimitExceeded);
    };
    if name.is_empty()
        || name.as_bytes().first().is_some_and(u8::is_ascii_digit)
        || !name
            .as_bytes()
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || *byte == b'_')
        || value.as_bytes().contains(&0)
    {
        return Err(EncodeError::LimitExceeded);
    }
    Ok(())
}

fn write_u16(bytes: &mut [u8], offset: usize, value: u16) {
    bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}

#[cfg(test)]
mod tests {
    use crate::{MAX_MESSAGE_BYTES, command, process_launch};

    #[test]
    fn substituting_the_zone_leaves_every_other_conventional_name() {
        use crate::command::{
            CONVENTIONAL_ENVIRONMENT, TIMEZONE_NAME, conventional_environment_with_timezone,
        };
        let composed = conventional_environment_with_timezone("TZ=EST5EDT,M3.2.0,M11.1.0");
        assert_eq!(composed.len(), CONVENTIONAL_ENVIRONMENT.len());
        assert!(composed.contains(&"TZ=EST5EDT,M3.2.0,M11.1.0"));
        // Exactly one entry names TZ, so the canonical encoding boundary, which
        // refuses a duplicate name, still accepts the composed result.
        assert_eq!(
            composed
                .iter()
                .filter(|entry| entry.starts_with("TZ="))
                .count(),
            1
        );
        for conventional in CONVENTIONAL_ENVIRONMENT {
            let named_tz = conventional.starts_with("TZ=");
            assert_eq!(
                composed.contains(&conventional),
                !named_tz,
                "{conventional}"
            );
        }
        assert_eq!(TIMEZONE_NAME, "TZ");
    }

    #[test]
    fn an_entry_that_does_not_name_the_zone_changes_nothing() {
        use crate::command::{CONVENTIONAL_ENVIRONMENT, conventional_environment_with_timezone};
        for entry in ["HOME=/elsewhere", "TZX=UTC0", "no-equals", "", "=UTC0"] {
            assert_eq!(
                conventional_environment_with_timezone(entry),
                CONVENTIONAL_ENVIRONMENT,
                "{entry}"
            );
        }
    }

    #[test]
    fn invocation_round_trips_without_allocation() {
        let arguments = ["grep", "needle", ""];
        let mut bytes = [0_u8; MAX_MESSAGE_BYTES];
        let count = command::encode("/vol/root", &arguments, &mut bytes)
            .unwrap_or_else(|_| std::process::abort());
        let invocation =
            command::Invocation::parse(&bytes[..count]).unwrap_or_else(|_| std::process::abort());
        assert_eq!(invocation.cwd(), "/vol/root");
        assert_eq!(
            invocation.arguments().collect::<std::vec::Vec<_>>(),
            arguments
        );

        let mut environment_bytes = [0_u8; command::MAX_ENCODED_ENVIRONMENT_BYTES];
        let count =
            command::encode_environment(&["HOME=/vol/root", "PATH=/bin"], &mut environment_bytes)
                .unwrap_or_else(|_| std::process::abort());
        let environment = command::Environment::parse(&environment_bytes[..count])
            .unwrap_or_else(|_| std::process::abort());
        assert_eq!(
            environment.iter().collect::<std::vec::Vec<_>>(),
            ["HOME=/vol/root", "PATH=/bin"]
        );
        assert!(command::encode_environment(&["BAD"], &mut environment_bytes).is_err());
    }

    #[test]
    fn environment_rejects_duplicate_names_at_both_boundaries() {
        let mut bytes = [0_u8; command::MAX_ENCODED_ENVIRONMENT_BYTES];
        assert!(command::encode_environment(&["HOME=/", "HOME=/other"], &mut bytes).is_err());
        assert!(command::encode_environment(&["HOME=/", "HOME=/"], &mut bytes).is_err());
        // A prefix is not a duplicate; only the exact name collides.
        let count = command::encode_environment(&["HOME=/", "HOMEDIR=/other"], &mut bytes)
            .unwrap_or_else(|_| std::process::abort());
        assert!(command::Environment::parse(&bytes[..count]).is_ok());

        // A reply that smuggles duplicates past the encoder is still rejected.
        let mut forged = [0_u8; command::MAX_ENCODED_ENVIRONMENT_BYTES];
        let count = command::encode_environment(&["A=1", "B=2"], &mut forged)
            .unwrap_or_else(|_| std::process::abort());
        let values = &mut forged[..count];
        let start = values
            .windows(3)
            .position(|window| window == b"B=2")
            .unwrap_or_else(|| std::process::abort());
        values[start] = b'A';
        assert!(command::Environment::parse(&forged[..count]).is_err());

        let mut invocation = [0_u8; MAX_MESSAGE_BYTES];
        let invocation_bytes = command::encode("/", &["child"], &mut invocation)
            .unwrap_or_else(|_| std::process::abort());
        let mut spawn = [0_u8; process_launch::MAX_SPAWN_BYTES];
        assert!(
            process_launch::encode_spawn(
                &invocation[..invocation_bytes],
                &["PATH=/bin", "PATH=/vol"],
                process_launch::StreamSpec::INHERIT,
                process_launch::StreamSpec::INHERIT,
                process_launch::StreamSpec::INHERIT,
                &mut spawn,
            )
            .is_err()
        );
    }

    #[test]
    fn invocation_rejects_every_truncation_and_trailing_byte() {
        let mut bytes = [0_u8; MAX_MESSAGE_BYTES];
        let count = command::encode("/", &["echo", "ready"], &mut bytes)
            .unwrap_or_else(|_| std::process::abort());
        for end in 0..count {
            assert!(command::Invocation::parse(&bytes[..end]).is_err());
        }
        let mut trailing = bytes[..count].to_vec();
        trailing.push(0);
        assert!(command::Invocation::parse(&trailing).is_err());
    }

    #[test]
    fn argument_pages_cover_a_record_larger_than_one_message() {
        // More operands than one single-message invocation record can carry.
        let mut arguments = std::vec::Vec::new();
        arguments.push(std::string::String::from("rm"));
        for index in 0..1000 {
            arguments.push(std::format!("operand-{index:04}.txt"));
        }
        let mut record = [0_u8; MAX_MESSAGE_BYTES];
        assert!(command::encode("/work", &arguments, &mut record).is_err());

        let mut seen = std::vec::Vec::new();
        let mut start = 0_usize;
        let mut pages = 0_usize;
        loop {
            let mut bytes = [0_u8; command::MAX_ARGUMENT_PAGE_REPLY_BYTES];
            let count = command::encode_argument_page(&arguments, start, &mut bytes)
                .unwrap_or_else(|_| std::process::abort());
            let page = command::ArgumentPage::parse(&bytes[..count])
                .unwrap_or_else(|_| std::process::abort());
            assert_eq!(page.total(), arguments.len());
            assert_eq!(page.start(), start);
            assert!(count <= MAX_MESSAGE_BYTES);
            if page.is_empty() {
                assert_eq!(page.start(), arguments.len());
                break;
            }
            seen.extend(page.iter().map(std::string::ToString::to_string));
            start = page.next_start();
            pages += 1;
            assert!(pages <= arguments.len(), "page reader failed to advance");
        }
        assert_eq!(seen, arguments);

        // A page request is exact, and its index is bounded.
        let mut request = [0_u8; command::ARGUMENT_PAGE_REQUEST_BYTES];
        let count = command::encode_argument_page_request(7, &mut request)
            .unwrap_or_else(|_| std::process::abort());
        assert_eq!(
            command::decode_argument_page_request(&request[..count]),
            Ok(7)
        );
        assert!(command::decode_argument_page_request(&[]).is_err());
        assert!(command::decode_argument_page_request(&[0, 0, 0]).is_err());
        assert!(
            command::encode_argument_page_request(command::MAX_PAGED_ARGUMENTS + 1, &mut request)
                .is_err()
        );
    }

    #[test]
    fn argument_pages_reject_every_truncation_and_trailing_byte() {
        let arguments = ["cat", "alpha.txt", "beta.txt"];
        let mut bytes = [0_u8; command::MAX_ARGUMENT_PAGE_REPLY_BYTES];
        let count = command::encode_argument_page(&arguments, 0, &mut bytes)
            .unwrap_or_else(|_| std::process::abort());
        for end in 0..count {
            assert!(command::ArgumentPage::parse(&bytes[..end]).is_err());
        }
        let mut trailing = bytes[..count].to_vec();
        trailing.push(0);
        assert!(command::ArgumentPage::parse(&trailing).is_err());

        // A start past the record, and an empty record, are both refused.
        assert!(command::encode_argument_page(&arguments, 4, &mut bytes).is_err());
        let empty: [&str; 0] = [];
        assert!(command::encode_argument_page(&empty, 0, &mut bytes).is_err());

        // The final page is empty rather than absent, so a reader terminates.
        let count = command::encode_argument_page(&arguments, arguments.len(), &mut bytes)
            .unwrap_or_else(|_| std::process::abort());
        let page =
            command::ArgumentPage::parse(&bytes[..count]).unwrap_or_else(|_| std::process::abort());
        assert!(page.is_empty());
        assert_eq!(page.next_start(), arguments.len());
    }

    #[test]
    fn failed_encoding_does_not_modify_destination() {
        let mut bytes = [0xa5_u8; 4];
        assert_eq!(
            command::encode("relative", &["echo"], &mut bytes),
            Err(command::EncodeError::InvalidCwd)
        );
        assert_eq!(bytes, [0xa5; 4]);
    }
}
