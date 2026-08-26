#![no_std]

#[cfg(test)]
extern crate std;

const MAX_PRINT_ITEMS: usize = 8;
const MAX_FIELDS: usize = 32;

/// A rejected bounded awk program.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProgramError;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Selector<'program> {
    All,
    Contains(&'program [u8]),
    FieldEquals { field: u8, value: &'program [u8] },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Item<'program> {
    Record,
    Field(u8),
    RecordNumber,
    FieldCount,
    Literal(&'program [u8]),
}

/// One parsed program from the bounded awk language.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Program<'program> {
    selector: Selector<'program>,
    items: [Option<Item<'program>>; MAX_PRINT_ITEMS],
    item_count: usize,
}

impl<'program> Program<'program> {
    /// Parse a record selector and an optional `{ print ... }` action.
    pub fn parse(text: &'program str) -> Result<Self, ProgramError> {
        let bytes = trim(text.as_bytes());
        let (selector_text, action_text) =
            if let Some(open) = bytes.iter().position(|byte| *byte == b'{') {
                let close = bytes
                    .iter()
                    .rposition(|byte| *byte == b'}')
                    .ok_or(ProgramError)?;
                if close < open || !trim(&bytes[close + 1..]).is_empty() {
                    return Err(ProgramError);
                }
                (trim(&bytes[..open]), Some(trim(&bytes[open + 1..close])))
            } else {
                (bytes, None)
            };
        let selector = parse_selector(selector_text)?;
        let mut items = [None; MAX_PRINT_ITEMS];
        let item_count = match action_text {
            None => {
                items[0] = Some(Item::Record);
                1
            }
            Some(action) => parse_action(action, &mut items)?,
        };
        Ok(Self {
            selector,
            items,
            item_count,
        })
    }
}

fn parse_selector(bytes: &[u8]) -> Result<Selector<'_>, ProgramError> {
    if bytes.is_empty() {
        return Ok(Selector::All);
    }
    if bytes.len() >= 2 && bytes[0] == b'/' && bytes[bytes.len() - 1] == b'/' {
        let pattern = &bytes[1..bytes.len() - 1];
        if pattern.is_empty() {
            return Err(ProgramError);
        }
        return Ok(Selector::Contains(pattern));
    }
    let mut cursor = 0;
    if bytes.get(cursor) != Some(&b'$') {
        return Err(ProgramError);
    }
    cursor += 1;
    let (field, next) = parse_number(bytes, cursor)?;
    cursor = next;
    cursor = skip_space(bytes, cursor);
    if bytes.get(cursor..cursor + 2) != Some(b"==") {
        return Err(ProgramError);
    }
    cursor = skip_space(bytes, cursor + 2);
    let (value, next) = parse_quoted(bytes, cursor)?;
    if !trim(&bytes[next..]).is_empty() {
        return Err(ProgramError);
    }
    Ok(Selector::FieldEquals { field, value })
}

fn parse_action<'program>(
    bytes: &'program [u8],
    items: &mut [Option<Item<'program>>; MAX_PRINT_ITEMS],
) -> Result<usize, ProgramError> {
    if !bytes.starts_with(b"print") || bytes.get(5).is_some_and(|byte| !byte.is_ascii_whitespace())
    {
        return Err(ProgramError);
    }
    let mut cursor = skip_space(bytes, 5);
    if cursor == bytes.len() {
        items[0] = Some(Item::Record);
        return Ok(1);
    }
    let mut count = 0;
    loop {
        if count == items.len() {
            return Err(ProgramError);
        }
        let (item, next) = parse_item(bytes, cursor)?;
        items[count] = Some(item);
        count += 1;
        cursor = skip_space(bytes, next);
        if cursor == bytes.len() {
            return Ok(count);
        }
        if bytes[cursor] != b',' {
            return Err(ProgramError);
        }
        cursor = skip_space(bytes, cursor + 1);
        if cursor == bytes.len() {
            return Err(ProgramError);
        }
    }
}

fn parse_item(bytes: &[u8], cursor: usize) -> Result<(Item<'_>, usize), ProgramError> {
    match bytes.get(cursor).copied() {
        Some(b'$') => {
            let (field, next) = parse_number(bytes, cursor + 1)?;
            Ok((
                if field == 0 {
                    Item::Record
                } else {
                    Item::Field(field)
                },
                next,
            ))
        }
        Some(b'"') => {
            let (literal, next) = parse_quoted(bytes, cursor)?;
            Ok((Item::Literal(literal), next))
        }
        Some(_) if bytes[cursor..].starts_with(b"NR") => Ok((Item::RecordNumber, cursor + 2)),
        Some(_) if bytes[cursor..].starts_with(b"NF") => Ok((Item::FieldCount, cursor + 2)),
        _ => Err(ProgramError),
    }
}

fn parse_number(bytes: &[u8], start: usize) -> Result<(u8, usize), ProgramError> {
    let mut cursor = start;
    let mut value = 0_u16;
    while let Some(digit @ b'0'..=b'9') = bytes.get(cursor).copied() {
        value = value
            .checked_mul(10)
            .and_then(|number| number.checked_add(u16::from(digit - b'0')))
            .ok_or(ProgramError)?;
        cursor += 1;
    }
    if cursor == start || value > MAX_FIELDS as u16 {
        return Err(ProgramError);
    }
    Ok((value as u8, cursor))
}

fn parse_quoted(bytes: &[u8], start: usize) -> Result<(&[u8], usize), ProgramError> {
    if bytes.get(start) != Some(&b'"') {
        return Err(ProgramError);
    }
    let content_start = start + 1;
    let relative = bytes[content_start..]
        .iter()
        .position(|byte| *byte == b'"')
        .ok_or(ProgramError)?;
    let end = content_start + relative;
    Ok((&bytes[content_start..end], end + 1))
}

fn skip_space(bytes: &[u8], mut cursor: usize) -> usize {
    while bytes.get(cursor).is_some_and(u8::is_ascii_whitespace) {
        cursor += 1;
    }
    cursor
}

fn trim(mut bytes: &[u8]) -> &[u8] {
    while bytes.first().is_some_and(u8::is_ascii_whitespace) {
        bytes = &bytes[1..];
    }
    while bytes.last().is_some_and(u8::is_ascii_whitespace) {
        bytes = &bytes[..bytes.len() - 1];
    }
    bytes
}

#[derive(Clone, Copy, Default)]
struct Field {
    start: usize,
    end: usize,
}

struct Fields {
    entries: [Field; MAX_FIELDS],
    stored: usize,
    total: usize,
}

impl Fields {
    fn parse(record: &[u8], separator: Option<u8>) -> Self {
        let mut fields = Self {
            entries: [Field::default(); MAX_FIELDS],
            stored: 0,
            total: 0,
        };
        match separator {
            Some(separator) => {
                let mut start = 0;
                for end in 0..=record.len() {
                    if end == record.len() || record[end] == separator {
                        fields.push(start, end);
                        start = end + 1;
                    }
                }
            }
            None => {
                let mut cursor = 0;
                while cursor < record.len() {
                    while cursor < record.len() && record[cursor].is_ascii_whitespace() {
                        cursor += 1;
                    }
                    let start = cursor;
                    while cursor < record.len() && !record[cursor].is_ascii_whitespace() {
                        cursor += 1;
                    }
                    if start != cursor {
                        fields.push(start, cursor);
                    }
                }
            }
        }
        fields
    }

    fn push(&mut self, start: usize, end: usize) {
        if self.stored < self.entries.len() {
            self.entries[self.stored] = Field { start, end };
            self.stored += 1;
        }
        self.total = self.total.saturating_add(1);
    }

    fn get<'record>(&self, record: &'record [u8], one_based: u8) -> &'record [u8] {
        let Some(index) = usize::from(one_based).checked_sub(1) else {
            return b"";
        };
        let Some(field) = self.entries.get(index).filter(|_| index < self.stored) else {
            return b"";
        };
        &record[field.start..field.end]
    }
}

/// Execute one program for one input record.
pub fn execute<Write, OutputError>(
    program: Program<'_>,
    separator: Option<u8>,
    record_number: u64,
    line: &[u8],
    mut write: Write,
) -> Result<(), OutputError>
where
    Write: FnMut(&[u8]) -> Result<(), OutputError>,
{
    let record = line.strip_suffix(b"\n").unwrap_or(line);
    let fields = Fields::parse(record, separator);
    let selected = match program.selector {
        Selector::All => true,
        Selector::Contains(pattern) => contains(record, pattern),
        Selector::FieldEquals { field: 0, value } => record == value,
        Selector::FieldEquals { field, value } => fields.get(record, field) == value,
    };
    if !selected {
        return Ok(());
    }
    for index in 0..program.item_count {
        if index != 0 {
            write(b" ")?;
        }
        match program.items[index] {
            Some(Item::Record) => write(record)?,
            Some(Item::Field(field)) => write(fields.get(record, field))?,
            Some(Item::RecordNumber) => write_number(record_number, &mut write)?,
            Some(Item::FieldCount) => write_number(fields.total as u64, &mut write)?,
            Some(Item::Literal(literal)) => write(literal)?,
            None => {}
        }
    }
    write(b"\n")
}

fn write_number<Write, OutputError>(mut number: u64, write: &mut Write) -> Result<(), OutputError>
where
    Write: FnMut(&[u8]) -> Result<(), OutputError>,
{
    let mut digits = [0_u8; 20];
    let mut cursor = digits.len();
    loop {
        cursor -= 1;
        digits[cursor] = b'0' + (number % 10) as u8;
        number /= 10;
        if number == 0 {
            return write(&digits[cursor..]);
        }
    }
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    needle.is_empty()
        || haystack
            .windows(needle.len())
            .any(|window| window == needle)
}

#[cfg(test)]
mod tests {
    use super::{Program, ProgramError, execute};
    use std::vec::Vec;

    fn run(program: &str, separator: Option<u8>, number: u64, line: &[u8]) -> Vec<u8> {
        let program = Program::parse(program).unwrap_or_else(|_| std::process::abort());
        let mut output = Vec::new();
        execute(program, separator, number, line, |bytes| {
            output.extend_from_slice(bytes);
            Ok::<(), ()>(())
        })
        .unwrap_or_else(|_| std::process::abort());
        output
    }

    #[test]
    fn prints_fields_and_builtins() {
        assert_eq!(
            run("{ print NR, NF, $2 }", None, 7, b"alpha beta gamma\n"),
            b"7 3 beta\n"
        );
        assert_eq!(run("{ print $2, $1 }", Some(b':'), 1, b"a:b:c\n"), b"b a\n");
    }

    #[test]
    fn literal_and_field_selectors_filter_records() {
        assert_eq!(
            run("/beta/ { print $1 }", None, 1, b"alpha beta\n"),
            b"alpha\n"
        );
        assert_eq!(run("/beta/ { print $1 }", None, 2, b"alpha gamma\n"), b"");
        assert_eq!(
            run("$2 == \"ready\" { print $1 }", None, 3, b"service ready\n"),
            b"service\n"
        );
        assert_eq!(
            run(
                "$0 == \"whole record\" { print NR }",
                None,
                4,
                b"whole record\n",
            ),
            b"4\n"
        );
    }

    #[test]
    fn unsupported_programs_are_rejected() {
        assert_eq!(Program::parse("BEGIN { print $1 }"), Err(ProgramError));
        assert_eq!(Program::parse("{ sum += $1 }"), Err(ProgramError));
        assert_eq!(Program::parse("{ print $33 }"), Err(ProgramError));
    }
}
