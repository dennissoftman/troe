#![no_std]

#[cfg(test)]
extern crate std;

/// A rejected bounded sed script.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ScriptError;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Address {
    Every,
    Line(u64),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Command<'script> {
    Print,
    Delete,
    Substitute {
        needle: &'script [u8],
        replacement: &'script [u8],
        global: bool,
    },
}

/// One parsed command from the deliberately bounded sed language.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Script<'script> {
    address: Address,
    command: Command<'script>,
}

impl<'script> Script<'script> {
    /// Parse `[LINE]p`, `[LINE]d`, or `[LINE]s/OLD/NEW/[g]`.
    pub fn parse(text: &'script str) -> Result<Self, ScriptError> {
        let bytes = text.as_bytes();
        let mut cursor = 0;
        let mut line = 0_u64;
        while let Some(digit @ b'0'..=b'9') = bytes.get(cursor).copied() {
            line = line
                .checked_mul(10)
                .and_then(|value| value.checked_add(u64::from(digit - b'0')))
                .ok_or(ScriptError)?;
            cursor += 1;
        }
        let address = if cursor == 0 {
            Address::Every
        } else if line == 0 {
            return Err(ScriptError);
        } else {
            Address::Line(line)
        };
        let command = match bytes.get(cursor).copied() {
            Some(b'p') if cursor + 1 == bytes.len() => Command::Print,
            Some(b'd') if cursor + 1 == bytes.len() => Command::Delete,
            Some(b's') => parse_substitution(bytes, cursor + 1)?,
            _ => return Err(ScriptError),
        };
        Ok(Self { address, command })
    }

    fn selected(&self, line_number: u64) -> bool {
        match self.address {
            Address::Every => true,
            Address::Line(line) => line == line_number,
        }
    }
}

fn parse_substitution(bytes: &[u8], cursor: usize) -> Result<Command<'_>, ScriptError> {
    let delimiter = bytes.get(cursor).copied().ok_or(ScriptError)?;
    if delimiter.is_ascii_alphanumeric() || delimiter.is_ascii_whitespace() || delimiter == b'\\' {
        return Err(ScriptError);
    }
    let needle_start = cursor + 1;
    let needle_end = bytes[needle_start..]
        .iter()
        .position(|byte| *byte == delimiter)
        .map(|index| needle_start + index)
        .ok_or(ScriptError)?;
    if needle_end == needle_start {
        return Err(ScriptError);
    }
    let replacement_start = needle_end + 1;
    let replacement_end = bytes[replacement_start..]
        .iter()
        .position(|byte| *byte == delimiter)
        .map(|index| replacement_start + index)
        .ok_or(ScriptError)?;
    let flags = &bytes[replacement_end + 1..];
    let global = match flags {
        [] => false,
        [b'g'] => true,
        _ => return Err(ScriptError),
    };
    Ok(Command::Substitute {
        needle: &bytes[needle_start..needle_end],
        replacement: &bytes[replacement_start..replacement_end],
        global,
    })
}

/// Apply one script to one complete record.
///
/// `line` may include its input newline. Output is streamed through `write`.
pub fn apply<Write, OutputError>(
    script: Script<'_>,
    quiet: bool,
    line_number: u64,
    line: &[u8],
    mut write: Write,
) -> Result<(), OutputError>
where
    Write: FnMut(&[u8]) -> Result<(), OutputError>,
{
    if !script.selected(line_number) {
        if !quiet {
            write(line)?;
        }
        return Ok(());
    }
    match script.command {
        Command::Print => {
            if !quiet {
                write(line)?;
            }
            write(line)
        }
        Command::Delete => Ok(()),
        Command::Substitute {
            needle,
            replacement,
            global,
        } => {
            if quiet {
                return Ok(());
            }
            substitute(line, needle, replacement, global, &mut write)
        }
    }
}

fn substitute<Write, OutputError>(
    line: &[u8],
    needle: &[u8],
    replacement: &[u8],
    global: bool,
    write: &mut Write,
) -> Result<(), OutputError>
where
    Write: FnMut(&[u8]) -> Result<(), OutputError>,
{
    let mut cursor = 0;
    while cursor <= line.len() {
        let Some(relative) = find(&line[cursor..], needle) else {
            return write(&line[cursor..]);
        };
        let matched = cursor + relative;
        write(&line[cursor..matched])?;
        write_replacement(replacement, needle, write)?;
        cursor = matched + needle.len();
        if !global {
            return write(&line[cursor..]);
        }
    }
    Ok(())
}

fn write_replacement<Write, OutputError>(
    replacement: &[u8],
    matched: &[u8],
    write: &mut Write,
) -> Result<(), OutputError>
where
    Write: FnMut(&[u8]) -> Result<(), OutputError>,
{
    let mut cursor = 0;
    while let Some(relative) = replacement[cursor..].iter().position(|byte| *byte == b'&') {
        let ampersand = cursor + relative;
        write(&replacement[cursor..ampersand])?;
        write(matched)?;
        cursor = ampersand + 1;
    }
    write(&replacement[cursor..])
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

#[cfg(test)]
mod tests {
    use super::{Script, ScriptError, apply};
    use std::vec::Vec;

    fn run(script: &str, quiet: bool, number: u64, line: &[u8]) -> Vec<u8> {
        let script = Script::parse(script).unwrap_or_else(|_| std::process::abort());
        let mut output = Vec::new();
        apply(script, quiet, number, line, |bytes| {
            output.extend_from_slice(bytes);
            Ok::<(), ()>(())
        })
        .unwrap_or_else(|_| std::process::abort());
        output
    }

    #[test]
    fn substitution_supports_first_global_and_match_expansion() {
        assert_eq!(run("s/a/X/", false, 1, b"banana\n"), b"bXnana\n");
        assert_eq!(run("s/a/[&]/g", false, 1, b"banana\n"), b"b[a]n[a]n[a]\n");
    }

    #[test]
    fn print_delete_and_numeric_addresses_work() {
        assert_eq!(run("p", true, 1, b"one\n"), b"one\n");
        assert_eq!(run("p", false, 1, b"one\n"), b"one\none\n");
        assert_eq!(run("2d", false, 1, b"one\n"), b"one\n");
        assert_eq!(run("2d", false, 2, b"two\n"), b"");
    }

    #[test]
    fn malformed_or_expansive_language_is_rejected() {
        assert_eq!(Script::parse("s//x/"), Err(ScriptError));
        assert_eq!(Script::parse("1,2p"), Err(ScriptError));
        assert_eq!(Script::parse("s/a/b/i"), Err(ScriptError));
    }
}
