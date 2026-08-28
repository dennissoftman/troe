#![no_std]

#[cfg(test)]
extern crate std;

/// A failure while rendering one format string.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PrintError<OutputError> {
    /// The format contains an unsupported conversion or invalid numeric escape.
    InvalidFormat,
    /// A numeric conversion received an invalid integer argument.
    InvalidNumber,
    /// The standard-output service rejected a write.
    Output(OutputError),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Flow {
    Continue,
    Stop,
}

const MAX_FIELD_WIDTH: usize = 64 * 1024;

#[derive(Clone, Copy, Default)]
struct FormatSpec {
    alternate: bool,
    left: bool,
    plus: bool,
    space: bool,
    zero: bool,
    width: Option<usize>,
    precision: Option<usize>,
    conversion: u8,
}

/// Result of interpreting backslash escapes in one string.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EscapeOutcome {
    /// The complete string was rendered.
    Complete,
    /// A `\c` escape requested that all output stop.
    Stop,
}

/// Render C-style escapes from one string without allocation.
///
/// This is shared with commands such as `echo -e` so escape semantics remain
/// identical to `printf %b`.
pub fn render_escapes<Write, OutputError>(
    value: &str,
    mut write: Write,
) -> Result<EscapeOutcome, PrintError<OutputError>>
where
    Write: FnMut(&[u8]) -> Result<(), OutputError>,
{
    write_escaped(value.as_bytes(), &mut write).map(|flow| match flow {
        Flow::Continue => EscapeOutcome::Complete,
        Flow::Stop => EscapeOutcome::Stop,
    })
}

/// Render one bounded `printf` format without allocation.
///
/// The format supports C-style escapes, `%%`, `%s`, `%b`, `%c`, the standard
/// flags, bounded field widths and precisions, and the integer conversions
/// `%d`, `%i`, `%u`, `%o`, `%x`, and `%X`. It is repeated when needed to
/// consume additional arguments.
pub fn render<'argument, Arguments, Write, OutputError>(
    format: &str,
    arguments: Arguments,
    mut write: Write,
) -> Result<(), PrintError<OutputError>>
where
    Arguments: Iterator<Item = &'argument str>,
    Write: FnMut(&[u8]) -> Result<(), OutputError>,
{
    let mut arguments = arguments.peekable();
    loop {
        let (flow, substitutions) = render_pass(format, &mut arguments, &mut write)?;
        if flow == Flow::Stop || substitutions == 0 || arguments.peek().is_none() {
            return Ok(());
        }
    }
}

fn render_pass<'argument, Arguments, Write, OutputError>(
    format: &str,
    arguments: &mut core::iter::Peekable<Arguments>,
    write: &mut Write,
) -> Result<(Flow, usize), PrintError<OutputError>>
where
    Arguments: Iterator<Item = &'argument str>,
    Write: FnMut(&[u8]) -> Result<(), OutputError>,
{
    let bytes = format.as_bytes();
    let mut cursor = 0;
    let mut literal_start = 0;
    let mut substitutions = 0;
    while cursor < bytes.len() {
        match bytes[cursor] {
            b'\\' => {
                write_bytes(write, &bytes[literal_start..cursor])?;
                let (next, flow) = write_escape(bytes, cursor, write)?;
                cursor = next;
                literal_start = cursor;
                if flow == Flow::Stop {
                    return Ok((Flow::Stop, substitutions));
                }
            }
            b'%' => {
                write_bytes(write, &bytes[literal_start..cursor])?;
                let (spec, next, consumed) = parse_spec(bytes, cursor, arguments)?;
                substitutions += consumed;
                match spec.conversion {
                    b'%' => write_padded(write, b"%", spec)?,
                    b's' => {
                        let argument = arguments.next().unwrap_or("").as_bytes();
                        substitutions += 1;
                        let length = spec
                            .precision
                            .map_or(argument.len(), |maximum| argument.len().min(maximum));
                        write_padded(write, &argument[..length], spec)?;
                    }
                    b'b' => {
                        let argument = arguments.next().unwrap_or("");
                        substitutions += 1;
                        let (length, measured_flow) = measure_escaped(argument.as_bytes())
                            .map_err(|()| PrintError::InvalidFormat)?;
                        write_padding(
                            write,
                            spec.width.unwrap_or(0).saturating_sub(length),
                            b' ',
                            !spec.left,
                        )?;
                        if write_escaped(argument.as_bytes(), write)? == Flow::Stop {
                            return Ok((Flow::Stop, substitutions));
                        }
                        if measured_flow == Flow::Continue {
                            write_padding(
                                write,
                                spec.width.unwrap_or(0).saturating_sub(length),
                                b' ',
                                spec.left,
                            )?;
                        }
                    }
                    b'c' => {
                        let argument = arguments.next().unwrap_or("");
                        substitutions += 1;
                        if let Some(character) = argument.chars().next() {
                            let mut encoded = [0_u8; 4];
                            write_padded(
                                write,
                                character.encode_utf8(&mut encoded).as_bytes(),
                                spec,
                            )?;
                        } else {
                            write_padded(write, b"", spec)?;
                        }
                    }
                    b'd' | b'i' => {
                        let argument = arguments.next().unwrap_or("0");
                        substitutions += 1;
                        let (negative, magnitude) = parse_integer(argument)?;
                        if magnitude > i64::MAX as u64 + u64::from(negative) {
                            return Err(PrintError::InvalidNumber);
                        }
                        write_integer(write, magnitude, negative, 10, false, spec)?;
                    }
                    b'u' | b'o' | b'x' | b'X' => {
                        let argument = arguments.next().unwrap_or("0");
                        substitutions += 1;
                        let (negative, magnitude) = parse_integer(argument)?;
                        let value = if negative {
                            0_u64.wrapping_sub(magnitude)
                        } else {
                            magnitude
                        };
                        let radix = match spec.conversion {
                            b'o' => 8,
                            b'x' | b'X' => 16,
                            _ => 10,
                        };
                        write_integer(write, value, false, radix, spec.conversion == b'X', spec)?;
                    }
                    _ => return Err(PrintError::InvalidFormat),
                }
                cursor = next;
                literal_start = cursor;
            }
            _ => cursor += 1,
        }
    }
    write_bytes(write, &bytes[literal_start..])?;
    Ok((Flow::Continue, substitutions))
}

fn parse_spec<'argument, Arguments, OutputError>(
    bytes: &[u8],
    percent: usize,
    arguments: &mut core::iter::Peekable<Arguments>,
) -> Result<(FormatSpec, usize, usize), PrintError<OutputError>>
where
    Arguments: Iterator<Item = &'argument str>,
{
    let mut spec = FormatSpec::default();
    let mut cursor = percent + 1;
    while let Some(flag) = bytes.get(cursor).copied() {
        match flag {
            b'#' => spec.alternate = true,
            b'-' => spec.left = true,
            b'+' => spec.plus = true,
            b' ' => spec.space = true,
            b'0' => spec.zero = true,
            _ => break,
        }
        cursor += 1;
    }
    let mut consumed = 0_usize;
    if bytes.get(cursor) == Some(&b'*') {
        let width = parse_decimal(arguments.next().unwrap_or("0"))?;
        consumed += 1;
        cursor += 1;
        if width < 0 {
            spec.left = true;
        }
        spec.width = Some(limit_width(width.unsigned_abs())?);
    } else {
        let (width, next) = parse_format_number(bytes, cursor)?;
        spec.width = width;
        cursor = next;
    }
    if bytes.get(cursor) == Some(&b'.') {
        cursor += 1;
        if bytes.get(cursor) == Some(&b'*') {
            let precision = parse_decimal(arguments.next().unwrap_or("0"))?;
            consumed += 1;
            cursor += 1;
            if precision >= 0 {
                spec.precision = Some(limit_width(precision as u64)?);
            }
        } else {
            let (precision, next) = parse_format_number(bytes, cursor)?;
            spec.precision = Some(precision.unwrap_or(0));
            cursor = next;
        }
    }
    spec.conversion = *bytes.get(cursor).ok_or(PrintError::InvalidFormat)?;
    if spec.conversion == b'%' && consumed != 0 {
        return Err(PrintError::InvalidFormat);
    }
    Ok((spec, cursor + 1, consumed))
}

fn parse_format_number<OutputError>(
    bytes: &[u8],
    start: usize,
) -> Result<(Option<usize>, usize), PrintError<OutputError>> {
    let mut cursor = start;
    let mut value = 0_usize;
    while let Some(byte @ b'0'..=b'9') = bytes.get(cursor).copied() {
        value = value
            .checked_mul(10)
            .and_then(|value| value.checked_add(usize::from(byte - b'0')))
            .ok_or(PrintError::InvalidFormat)?;
        if value > MAX_FIELD_WIDTH {
            return Err(PrintError::InvalidFormat);
        }
        cursor += 1;
    }
    Ok(((cursor != start).then_some(value), cursor))
}

fn limit_width<OutputError>(value: u64) -> Result<usize, PrintError<OutputError>> {
    let value = usize::try_from(value).map_err(|_| PrintError::InvalidFormat)?;
    (value <= MAX_FIELD_WIDTH)
        .then_some(value)
        .ok_or(PrintError::InvalidFormat)
}

fn parse_decimal<OutputError>(value: &str) -> Result<i64, PrintError<OutputError>> {
    value.parse().map_err(|_| PrintError::InvalidNumber)
}

fn parse_integer<OutputError>(value: &str) -> Result<(bool, u64), PrintError<OutputError>> {
    if let Some(quoted) = value.strip_prefix(['\'', '"']) {
        let character = quoted.chars().next().unwrap_or('\0');
        return Ok((false, u64::from(character as u32)));
    }
    let (negative, unsigned) = if let Some(value) = value.strip_prefix('-') {
        (true, value)
    } else {
        (false, value.strip_prefix('+').unwrap_or(value))
    };
    let (radix, digits) = if let Some(value) = unsigned
        .strip_prefix("0x")
        .or_else(|| unsigned.strip_prefix("0X"))
    {
        (16, value)
    } else if unsigned.len() > 1 && unsigned.starts_with('0') {
        (8, &unsigned[1..])
    } else {
        (10, unsigned)
    };
    if digits.is_empty() {
        return if unsigned == "0" {
            Ok((negative, 0))
        } else {
            Err(PrintError::InvalidNumber)
        };
    }
    let magnitude = u64::from_str_radix(digits, radix).map_err(|_| PrintError::InvalidNumber)?;
    Ok((negative, magnitude))
}

fn write_integer<Write, OutputError>(
    write: &mut Write,
    mut value: u64,
    negative: bool,
    radix: u64,
    uppercase: bool,
    spec: FormatSpec,
) -> Result<(), PrintError<OutputError>>
where
    Write: FnMut(&[u8]) -> Result<(), OutputError>,
{
    let digits = if uppercase {
        b"0123456789ABCDEF"
    } else {
        b"0123456789abcdef"
    };
    let original = value;
    let mut buffer = [0_u8; 64];
    let mut cursor = buffer.len();
    while value != 0 {
        cursor -= 1;
        buffer[cursor] = digits[usize::try_from(value % radix).unwrap_or(0)];
        value /= radix;
    }
    if original == 0 && spec.precision != Some(0) {
        cursor -= 1;
        buffer[cursor] = b'0';
    }
    let sign = if negative {
        Some(b'-')
    } else if spec.plus {
        Some(b'+')
    } else if spec.space {
        Some(b' ')
    } else {
        None
    };
    let prefix = if spec.alternate && radix == 16 && original != 0 {
        if uppercase {
            b"0X".as_slice()
        } else {
            b"0x".as_slice()
        }
    } else if spec.alternate && radix == 8 && (cursor == buffer.len() || buffer[cursor] != b'0') {
        b"0".as_slice()
    } else {
        b"".as_slice()
    };
    let digits_length = buffer.len() - cursor;
    let precision_zeros = spec.precision.unwrap_or(0).saturating_sub(digits_length);
    let content_length = usize::from(sign.is_some())
        .saturating_add(prefix.len())
        .saturating_add(precision_zeros)
        .saturating_add(digits_length);
    let field_padding = spec.width.unwrap_or(0).saturating_sub(content_length);
    let zero_padding = spec.zero && !spec.left && spec.precision.is_none();
    write_padding(write, field_padding, b' ', !spec.left && !zero_padding)?;
    if let Some(sign) = sign {
        write_bytes(write, &[sign])?;
    }
    write_bytes(write, prefix)?;
    write_padding(write, field_padding, b'0', zero_padding)?;
    write_padding(write, precision_zeros, b'0', true)?;
    write_bytes(write, &buffer[cursor..])?;
    write_padding(write, field_padding, b' ', spec.left)
}

fn write_padded<Write, OutputError>(
    write: &mut Write,
    value: &[u8],
    spec: FormatSpec,
) -> Result<(), PrintError<OutputError>>
where
    Write: FnMut(&[u8]) -> Result<(), OutputError>,
{
    let padding = spec.width.unwrap_or(0).saturating_sub(value.len());
    write_padding(write, padding, b' ', !spec.left)?;
    write_bytes(write, value)?;
    write_padding(write, padding, b' ', spec.left)
}

fn write_padding<Write, OutputError>(
    write: &mut Write,
    mut count: usize,
    byte: u8,
    enabled: bool,
) -> Result<(), PrintError<OutputError>>
where
    Write: FnMut(&[u8]) -> Result<(), OutputError>,
{
    if !enabled {
        return Ok(());
    }
    let bytes = [byte; 64];
    while count != 0 {
        let chunk = count.min(bytes.len());
        write_bytes(write, &bytes[..chunk])?;
        count -= chunk;
    }
    Ok(())
}

fn measure_escaped(bytes: &[u8]) -> Result<(usize, Flow), ()> {
    let mut length = 0_usize;
    let flow = write_escaped(bytes, &mut |chunk| {
        length = length.checked_add(chunk.len()).ok_or(())?;
        Ok::<(), ()>(())
    })
    .map_err(|_| ())?;
    Ok((length, flow))
}

fn write_escaped<Write, OutputError>(
    bytes: &[u8],
    write: &mut Write,
) -> Result<Flow, PrintError<OutputError>>
where
    Write: FnMut(&[u8]) -> Result<(), OutputError>,
{
    let mut cursor = 0;
    let mut literal_start = 0;
    while cursor < bytes.len() {
        if bytes[cursor] != b'\\' {
            cursor += 1;
            continue;
        }
        write_bytes(write, &bytes[literal_start..cursor])?;
        let (next, flow) = write_escape(bytes, cursor, write)?;
        cursor = next;
        literal_start = cursor;
        if flow == Flow::Stop {
            return Ok(Flow::Stop);
        }
    }
    write_bytes(write, &bytes[literal_start..])?;
    Ok(Flow::Continue)
}

fn write_escape<Write, OutputError>(
    bytes: &[u8],
    slash: usize,
    write: &mut Write,
) -> Result<(usize, Flow), PrintError<OutputError>>
where
    Write: FnMut(&[u8]) -> Result<(), OutputError>,
{
    let Some(escaped) = bytes.get(slash + 1).copied() else {
        write_bytes(write, b"\\")?;
        return Ok((slash + 1, Flow::Continue));
    };
    let named = match escaped {
        b'\\' => Some(b'\\'),
        b'a' => Some(0x07),
        b'b' => Some(0x08),
        b'e' => Some(0x1b),
        b'f' => Some(0x0c),
        b'n' => Some(b'\n'),
        b'r' => Some(b'\r'),
        b't' => Some(b'\t'),
        b'v' => Some(0x0b),
        _ => None,
    };
    if let Some(value) = named {
        write_bytes(write, &[value])?;
        return Ok((slash + 2, Flow::Continue));
    }
    match escaped {
        b'c' => Ok((slash + 2, Flow::Stop)),
        b'x' => {
            let (value, next) = parse_digits(bytes, slash + 2, 2, 16)?;
            write_bytes(
                write,
                &[u8::try_from(value).map_err(|_| PrintError::InvalidFormat)?],
            )?;
            Ok((next, Flow::Continue))
        }
        b'u' => write_unicode(bytes, slash, 4, write),
        b'U' => write_unicode(bytes, slash, 8, write),
        b'0' => {
            let (value, next) = parse_optional_octal(bytes, slash + 2, 3);
            write_bytes(
                write,
                &[u8::try_from(value).map_err(|_| PrintError::InvalidFormat)?],
            )?;
            Ok((next, Flow::Continue))
        }
        b'1'..=b'7' => {
            let (value, next) = parse_digits(bytes, slash + 1, 3, 8)?;
            write_bytes(
                write,
                &[u8::try_from(value).map_err(|_| PrintError::InvalidFormat)?],
            )?;
            Ok((next, Flow::Continue))
        }
        _ => {
            write_bytes(write, b"\\")?;
            Ok((slash + 1, Flow::Continue))
        }
    }
}

fn parse_optional_octal(bytes: &[u8], start: usize, maximum: usize) -> (u32, usize) {
    let mut value = 0_u32;
    let mut cursor = start;
    while cursor < bytes.len() && cursor - start < maximum && matches!(bytes[cursor], b'0'..=b'7') {
        value = value * 8 + u32::from(bytes[cursor] - b'0');
        cursor += 1;
    }
    (value, cursor)
}

fn parse_digits<OutputError>(
    bytes: &[u8],
    start: usize,
    maximum: usize,
    radix: u32,
) -> Result<(u32, usize), PrintError<OutputError>> {
    let mut value = 0_u32;
    let mut cursor = start;
    while cursor < bytes.len() && cursor - start < maximum {
        let Some(digit) = char::from(bytes[cursor]).to_digit(radix) else {
            break;
        };
        value = value
            .checked_mul(radix)
            .and_then(|value| value.checked_add(digit))
            .ok_or(PrintError::InvalidFormat)?;
        cursor += 1;
    }
    if cursor == start {
        Err(PrintError::InvalidFormat)
    } else {
        Ok((value, cursor))
    }
}

fn write_unicode<Write, OutputError>(
    bytes: &[u8],
    slash: usize,
    maximum: usize,
    write: &mut Write,
) -> Result<(usize, Flow), PrintError<OutputError>>
where
    Write: FnMut(&[u8]) -> Result<(), OutputError>,
{
    let (value, next) = parse_digits(bytes, slash + 2, maximum, 16)?;
    let character = char::from_u32(value).ok_or(PrintError::InvalidFormat)?;
    let mut encoded = [0_u8; 4];
    write_bytes(write, character.encode_utf8(&mut encoded).as_bytes())?;
    Ok((next, Flow::Continue))
}

fn write_bytes<Write, OutputError>(
    write: &mut Write,
    bytes: &[u8],
) -> Result<(), PrintError<OutputError>>
where
    Write: FnMut(&[u8]) -> Result<(), OutputError>,
{
    if bytes.is_empty() {
        Ok(())
    } else {
        write(bytes).map_err(PrintError::Output)
    }
}

#[cfg(test)]
mod tests {
    use super::{EscapeOutcome, PrintError, render, render_escapes};
    use std::vec::Vec;

    fn output(format: &str, arguments: &[&str]) -> Result<Vec<u8>, PrintError<()>> {
        let mut bytes = Vec::new();
        render(format, arguments.iter().copied(), |chunk| {
            bytes.extend_from_slice(chunk);
            Ok(())
        })?;
        Ok(bytes)
    }

    #[test]
    fn named_escapes_do_not_add_an_implicit_newline() {
        assert_eq!(
            output(r"one\ttwo\n\e[31mred\e[0m", &[]),
            Ok(b"one\ttwo\n\x1b[31mred\x1b[0m".to_vec())
        );
    }

    #[test]
    fn numeric_and_unicode_escapes_emit_exact_bytes() {
        assert_eq!(
            output(r"\101\0102\x43\u03bb\U0001f980", &[]),
            Ok("ABCλ🦀".as_bytes().to_vec())
        );
    }

    #[test]
    fn string_and_escaped_string_conversions_repeat_the_format() {
        assert_eq!(
            output("[%s:%b]", &["a", r"b\n", "c"]),
            Ok(b"[a:b\n][c:]".to_vec())
        );
        assert_eq!(output("100%%", &["ignored"]), Ok(b"100%".to_vec()));
    }

    #[test]
    fn stop_escape_ends_the_complete_render() {
        assert_eq!(
            output(r"before\cafter%s", &["unused"]),
            Ok(b"before".to_vec())
        );
        assert_eq!(
            output("%b%s", &[r"value\cignored", "unused"]),
            Ok(b"value".to_vec())
        );
    }

    #[test]
    fn unknown_escapes_are_preserved_and_bad_conversions_fail() {
        assert_eq!(output(r"\q", &[]), Ok(br"\q".to_vec()));
        assert_eq!(output("%f", &["1"]), Err(PrintError::InvalidFormat));
        assert_eq!(output(r"\x", &[]), Err(PrintError::InvalidFormat));
    }

    #[test]
    fn character_and_integer_conversions_cover_standard_radices() {
        assert_eq!(
            output(
                "%c %d %i %u %o %x %X",
                &["λ", "-42", "7", "42", "42", "42", "42"]
            ),
            Ok("λ -42 7 42 52 2a 2A".as_bytes().to_vec())
        );
        assert_eq!(output("%d", &["nope"]), Err(PrintError::InvalidNumber));
    }

    #[test]
    fn flags_width_precision_and_dynamic_fields_are_bounded() {
        assert_eq!(
            output(
                "%#08x|%-5s|%.3s|%+d|% d|%.0d",
                &["42", "hi", "abcdef", "7", "7", "0"]
            ),
            Ok(b"0x00002a|hi   |abc|+7| 7|".to_vec())
        );
        assert_eq!(
            output("%*.*s", &["-6", "3", "abcdef"]),
            Ok(b"abc   ".to_vec())
        );
        assert_eq!(
            output("%d %d %d", &["'A", "0x10", "010"]),
            Ok(b"65 16 8".to_vec())
        );
        assert_eq!(output("%65537s", &["x"]), Err(PrintError::InvalidFormat));
    }

    #[test]
    fn public_escape_renderer_matches_percent_b_and_reports_stop() {
        let mut bytes = Vec::new();
        let outcome = render_escapes(r"one\ntwo\cignored", |chunk| {
            bytes.extend_from_slice(chunk);
            Ok::<(), ()>(())
        });
        assert_eq!(outcome, Ok(EscapeOutcome::Stop));
        assert_eq!(bytes, b"one\ntwo".to_vec());
    }
}
