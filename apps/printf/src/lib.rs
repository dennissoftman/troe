#![no_std]

#[cfg(test)]
extern crate std;

/// A failure while rendering one format string.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PrintError<OutputError> {
    /// The format contains an unsupported conversion or invalid numeric escape.
    InvalidFormat,
    /// The standard-output service rejected a write.
    Output(OutputError),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Flow {
    Continue,
    Stop,
}

/// Render one bounded `printf` format without allocation.
///
/// The format supports C-style escapes, `%%`, `%s`, and `%b`. It is repeated
/// when needed to consume additional arguments, matching the useful shell
/// `printf` behavior without introducing numeric formatting policy.
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
                let Some(conversion) = bytes.get(cursor + 1).copied() else {
                    return Err(PrintError::InvalidFormat);
                };
                match conversion {
                    b'%' => write_bytes(write, b"%")?,
                    b's' => {
                        write_bytes(write, arguments.next().unwrap_or("").as_bytes())?;
                        substitutions += 1;
                    }
                    b'b' => {
                        let argument = arguments.next().unwrap_or("");
                        substitutions += 1;
                        if write_escaped(argument.as_bytes(), write)? == Flow::Stop {
                            return Ok((Flow::Stop, substitutions));
                        }
                    }
                    _ => return Err(PrintError::InvalidFormat),
                }
                cursor += 2;
                literal_start = cursor;
            }
            _ => cursor += 1,
        }
    }
    write_bytes(write, &bytes[literal_start..])?;
    Ok((Flow::Continue, substitutions))
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
    use super::{PrintError, render};
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
        assert_eq!(output("%d", &["1"]), Err(PrintError::InvalidFormat));
        assert_eq!(output(r"\x", &[]), Err(PrintError::InvalidFormat));
    }
}
