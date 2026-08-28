#![no_std]

#[cfg(test)]
extern crate std;

use core::ops::Range;

const MAX_INSTRUCTIONS: usize = 512;
const MAX_REPETITION: usize = 64;
const MAX_STEPS: usize = 40_000_000;
const NONE: usize = usize::MAX;
const PATCH_TAG: usize = 1_usize << (usize::BITS - 1);

/// Regular-expression syntax accepted by the matcher.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Syntax {
    /// POSIX basic regular expressions.
    Basic,
    /// POSIX extended regular expressions.
    Extended,
    /// Literal byte strings.
    Fixed,
}

/// A bounded regular-expression compilation or execution failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RegexError {
    /// The expression is malformed.
    Invalid,
    /// The expression exceeds the fixed program or repetition limits.
    TooComplex,
    /// Matching exceeded the deterministic operation budget.
    MatchLimit,
}

#[derive(Clone, Copy)]
enum Op {
    Byte(u8),
    Any,
    Class([u64; 4]),
    Split,
    Jump,
    Start,
    End,
    Match,
}

#[derive(Clone, Copy)]
struct Instruction {
    op: Op,
    x: usize,
    y: usize,
}

const EMPTY_INSTRUCTION: Instruction = Instruction {
    op: Op::Match,
    x: NONE,
    y: NONE,
};

#[derive(Clone, Copy)]
struct Fragment {
    start: usize,
    out: usize,
}

/// A compiled, allocation-free set of grep patterns.
pub struct Program {
    instructions: [Instruction; MAX_INSTRUCTIONS],
    length: usize,
    aggregate: Option<Fragment>,
    start: usize,
    finished: bool,
}

impl Default for Program {
    fn default() -> Self {
        Self::new()
    }
}

impl Program {
    /// Create an empty program to which one or more patterns may be added.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            instructions: [EMPTY_INSTRUCTION; MAX_INSTRUCTIONS],
            length: 0,
            aggregate: None,
            start: NONE,
            finished: false,
        }
    }

    /// Add a pattern. A line matches when any added pattern matches.
    pub fn add(&mut self, pattern: &str, syntax: Syntax) -> Result<(), RegexError> {
        if self.finished {
            return Err(RegexError::Invalid);
        }
        let fragment = if syntax == Syntax::Fixed {
            self.compile_fixed(pattern.as_bytes())?
        } else {
            Parser::new(self, pattern.as_bytes(), syntax).parse()?
        };
        self.aggregate = Some(match self.aggregate {
            None => fragment,
            Some(previous) => {
                let split = self.emit(Op::Split, previous.start, fragment.start)?;
                Fragment {
                    start: split,
                    out: self.append(previous.out, fragment.out)?,
                }
            }
        });
        Ok(())
    }

    /// Finish compilation after all patterns have been added.
    pub fn finish(&mut self) -> Result<(), RegexError> {
        let fragment = self.aggregate.ok_or(RegexError::Invalid)?;
        let matched = self.emit(Op::Match, NONE, NONE)?;
        self.patch(fragment.out, matched)?;
        self.start = fragment.start;
        self.finished = true;
        Ok(())
    }

    /// Find the leftmost, longest byte range at or after `from`.
    pub fn find(
        &self,
        subject: &[u8],
        from: usize,
        ignore_case: bool,
        whole_line: bool,
        whole_word: bool,
    ) -> Result<Option<Range<usize>>, RegexError> {
        if !self.finished || from > subject.len() {
            return Err(RegexError::Invalid);
        }
        let mut steps = 0_usize;
        let mut current = StateSet::new();
        let mut next = StateSet::new();
        let mut best = None::<Range<usize>>;
        let mut position = from;
        loop {
            let may_start = best.as_ref().is_none_or(|range| position <= range.start);
            let valid_start = !whole_word || position == 0 || !is_word(subject[position - 1]);
            if may_start && valid_start && (!whole_line || position == 0) {
                self.add_state(
                    &mut current,
                    self.start,
                    position,
                    subject.len(),
                    position,
                    &mut steps,
                )?;
            }

            if let Some(start) =
                current.accepted_start(self, subject, position, whole_line, whole_word)
            {
                match &mut best {
                    Some(range) if start == range.start => range.end = position,
                    Some(range) if start < range.start => best = Some(start..position),
                    None => best = Some(start..position),
                    Some(_) => {}
                }
            }

            if position == subject.len() {
                break;
            }
            if let Some(range) = &best
                && !current.has_consuming_from(self, range.start)
            {
                break;
            }

            next.clear();
            for index in 0..current.length {
                let pc = current.states[index];
                let origin = current.origins[pc];
                if best.as_ref().is_some_and(|range| origin > range.start) {
                    continue;
                }
                let instruction = self.instructions[pc];
                let accepts = match instruction.op {
                    Op::Byte(expected) => byte_eq(expected, subject[position], ignore_case),
                    Op::Any => true,
                    Op::Class(bits) => class_contains(bits, subject[position], ignore_case),
                    _ => false,
                };
                if accepts {
                    self.add_state(
                        &mut next,
                        instruction.x,
                        position + 1,
                        subject.len(),
                        origin,
                        &mut steps,
                    )?;
                }
                tick(&mut steps)?;
            }
            core::mem::swap(&mut current, &mut next);
            position += 1;
        }
        Ok(best)
    }

    fn compile_fixed(&mut self, pattern: &[u8]) -> Result<Fragment, RegexError> {
        let mut result = None;
        for byte in pattern {
            let instruction = self.emit(Op::Byte(*byte), NONE, NONE)?;
            let fragment = Fragment {
                start: instruction,
                out: self.list(instruction, false)?,
            };
            result = Some(match result {
                None => fragment,
                Some(previous) => self.concat(previous, fragment)?,
            });
        }
        result.map_or_else(|| self.empty(), Ok)
    }

    fn add_state(
        &self,
        states: &mut StateSet,
        initial: usize,
        position: usize,
        subject_length: usize,
        origin: usize,
        steps: &mut usize,
    ) -> Result<(), RegexError> {
        let mut pending = [NONE; MAX_INSTRUCTIONS];
        let mut pending_length = 1_usize;
        pending[0] = initial;
        while pending_length != 0 {
            pending_length -= 1;
            let pc = pending[pending_length];
            if pc >= self.length || origin >= states.origins[pc] {
                continue;
            }
            states.origins[pc] = origin;
            tick(steps)?;
            let instruction = self.instructions[pc];
            match instruction.op {
                Op::Split => {
                    push_pending(&mut pending, &mut pending_length, instruction.y)?;
                    push_pending(&mut pending, &mut pending_length, instruction.x)?;
                }
                Op::Jump => push_pending(&mut pending, &mut pending_length, instruction.x)?,
                Op::Start if position == 0 => {
                    push_pending(&mut pending, &mut pending_length, instruction.x)?;
                }
                Op::End if position == subject_length => {
                    push_pending(&mut pending, &mut pending_length, instruction.x)?;
                }
                Op::Start | Op::End => {}
                _ => states.push(pc)?,
            }
        }
        Ok(())
    }

    fn emit(&mut self, op: Op, x: usize, y: usize) -> Result<usize, RegexError> {
        if self.length == self.instructions.len() {
            return Err(RegexError::TooComplex);
        }
        let index = self.length;
        self.instructions[index] = Instruction { op, x, y };
        self.length += 1;
        Ok(index)
    }

    fn empty(&mut self) -> Result<Fragment, RegexError> {
        let jump = self.emit(Op::Jump, NONE, NONE)?;
        Ok(Fragment {
            start: jump,
            out: self.list(jump, false)?,
        })
    }

    fn concat(&mut self, left: Fragment, right: Fragment) -> Result<Fragment, RegexError> {
        self.patch(left.out, right.start)?;
        Ok(Fragment {
            start: left.start,
            out: right.out,
        })
    }

    fn alternate(&mut self, left: Fragment, right: Fragment) -> Result<Fragment, RegexError> {
        let split = self.emit(Op::Split, left.start, right.start)?;
        Ok(Fragment {
            start: split,
            out: self.append(left.out, right.out)?,
        })
    }

    fn star(&mut self, fragment: Fragment) -> Result<Fragment, RegexError> {
        let split = self.emit(Op::Split, fragment.start, NONE)?;
        self.patch(fragment.out, split)?;
        Ok(Fragment {
            start: split,
            out: self.list(split, true)?,
        })
    }

    fn plus(&mut self, fragment: Fragment) -> Result<Fragment, RegexError> {
        let split = self.emit(Op::Split, fragment.start, NONE)?;
        self.patch(fragment.out, split)?;
        Ok(Fragment {
            start: fragment.start,
            out: self.list(split, true)?,
        })
    }

    fn question(&mut self, fragment: Fragment) -> Result<Fragment, RegexError> {
        let split = self.emit(Op::Split, fragment.start, NONE)?;
        let empty_out = self.list(split, true)?;
        Ok(Fragment {
            start: split,
            out: self.append(fragment.out, empty_out)?,
        })
    }

    fn list(&mut self, instruction: usize, y: bool) -> Result<usize, RegexError> {
        let reference = patch_reference(instruction, y)?;
        self.set_patch_target(reference, NONE)?;
        Ok(reference)
    }

    fn append(&mut self, first: usize, second: usize) -> Result<usize, RegexError> {
        if first == NONE {
            return Ok(second);
        }
        let mut cursor = first;
        loop {
            let next = self.patch_target(cursor)?;
            if next == NONE {
                self.set_patch_target(cursor, second)?;
                return Ok(first);
            }
            cursor = next;
        }
    }

    fn patch(&mut self, mut list: usize, target: usize) -> Result<(), RegexError> {
        while list != NONE {
            let next = self.patch_target(list)?;
            self.set_patch_target(list, target)?;
            list = next;
        }
        Ok(())
    }

    fn patch_target(&self, reference: usize) -> Result<usize, RegexError> {
        let (index, y) = decode_patch_reference(reference)?;
        let instruction = self.instructions.get(index).ok_or(RegexError::Invalid)?;
        Ok(if y { instruction.y } else { instruction.x })
    }

    fn set_patch_target(&mut self, reference: usize, target: usize) -> Result<(), RegexError> {
        let (index, y) = decode_patch_reference(reference)?;
        let instruction = self
            .instructions
            .get_mut(index)
            .ok_or(RegexError::Invalid)?;
        if y {
            instruction.y = target;
        } else {
            instruction.x = target;
        }
        Ok(())
    }

    fn clone_fragment(
        &mut self,
        template_start: usize,
        template_end: usize,
        fragment: Fragment,
    ) -> Result<Fragment, RegexError> {
        let destination = self.length;
        let count = template_end
            .checked_sub(template_start)
            .ok_or(RegexError::Invalid)?;
        if destination.saturating_add(count) > self.instructions.len() {
            return Err(RegexError::TooComplex);
        }
        for source in template_start..template_end {
            let mut instruction = self.instructions[source];
            instruction.x = remap_target(instruction.x, template_start, template_end, destination)?;
            instruction.y = remap_target(instruction.y, template_start, template_end, destination)?;
            self.instructions[self.length] = instruction;
            self.length += 1;
        }
        Ok(Fragment {
            start: remap_index(fragment.start, template_start, template_end, destination)?,
            out: remap_patch(fragment.out, template_start, template_end, destination)?,
        })
    }
}

struct Parser<'program, 'pattern> {
    program: &'program mut Program,
    pattern: &'pattern [u8],
    cursor: usize,
    syntax: Syntax,
    depth: usize,
}

impl<'program, 'pattern> Parser<'program, 'pattern> {
    fn new(program: &'program mut Program, pattern: &'pattern [u8], syntax: Syntax) -> Self {
        Self {
            program,
            pattern,
            cursor: 0,
            syntax,
            depth: 0,
        }
    }

    fn parse(mut self) -> Result<Fragment, RegexError> {
        let fragment = self.parse_alternation(false)?;
        if self.cursor != self.pattern.len() {
            return Err(RegexError::Invalid);
        }
        Ok(fragment)
    }

    fn parse_alternation(&mut self, grouped: bool) -> Result<Fragment, RegexError> {
        let mut fragment = self.parse_concatenation(grouped)?;
        while self.at_alternation() {
            self.consume_operator(Operator::Alternation)?;
            let right = self.parse_concatenation(grouped)?;
            fragment = self.program.alternate(fragment, right)?;
        }
        Ok(fragment)
    }

    fn parse_concatenation(&mut self, grouped: bool) -> Result<Fragment, RegexError> {
        let mut result = None;
        while self.cursor < self.pattern.len()
            && !self.at_alternation()
            && !(grouped && self.at_group_end())
        {
            let fragment = self.parse_piece()?;
            result = Some(match result {
                None => fragment,
                Some(previous) => self.program.concat(previous, fragment)?,
            });
        }
        result.map_or_else(|| self.program.empty(), Ok)
    }

    fn parse_piece(&mut self) -> Result<Fragment, RegexError> {
        let template_start = self.program.length;
        let mut fragment = self.parse_atom()?;
        let template_end = self.program.length;
        if self.at_operator(Operator::Star) {
            self.consume_operator(Operator::Star)?;
            fragment = self.program.star(fragment)?;
        } else if self.at_operator(Operator::Plus) {
            self.consume_operator(Operator::Plus)?;
            fragment = self.program.plus(fragment)?;
        } else if self.at_operator(Operator::Question) {
            self.consume_operator(Operator::Question)?;
            fragment = self.program.question(fragment)?;
        } else if self.at_operator(Operator::Interval) {
            let (minimum, maximum) = self.parse_interval()?;
            fragment = self.repeat(template_start, template_end, fragment, minimum, maximum)?;
        }
        if self.at_operator(Operator::Star)
            || self.at_operator(Operator::Plus)
            || self.at_operator(Operator::Question)
            || self.at_operator(Operator::Interval)
        {
            return Err(RegexError::Invalid);
        }
        Ok(fragment)
    }

    fn parse_atom(&mut self) -> Result<Fragment, RegexError> {
        if self.at_group_start() {
            self.consume_group_start()?;
            self.depth = self.depth.checked_add(1).ok_or(RegexError::TooComplex)?;
            if self.depth > 32 {
                return Err(RegexError::TooComplex);
            }
            let fragment = self.parse_alternation(true)?;
            if !self.at_group_end() {
                return Err(RegexError::Invalid);
            }
            self.consume_group_end()?;
            self.depth -= 1;
            return Ok(fragment);
        }
        let byte = *self.pattern.get(self.cursor).ok_or(RegexError::Invalid)?;
        match byte {
            b'[' => self.parse_class(),
            b'.' => {
                self.cursor += 1;
                self.single(Op::Any)
            }
            b'^' => {
                self.cursor += 1;
                self.single(Op::Start)
            }
            b'$' => {
                self.cursor += 1;
                self.single(Op::End)
            }
            b'\\' => {
                let escaped = *self
                    .pattern
                    .get(self.cursor + 1)
                    .ok_or(RegexError::Invalid)?;
                if self.syntax == Syntax::Basic
                    && matches!(escaped, b'(' | b')' | b'|' | b'+' | b'?' | b'{')
                {
                    return Err(RegexError::Invalid);
                }
                self.cursor += 2;
                self.single(Op::Byte(escaped))
            }
            b')' | b'|' | b'*' | b'+' | b'?' if self.syntax == Syntax::Extended => {
                Err(RegexError::Invalid)
            }
            _ => {
                self.cursor += 1;
                self.single(Op::Byte(byte))
            }
        }
    }

    fn parse_class(&mut self) -> Result<Fragment, RegexError> {
        self.cursor += 1;
        let negated = self.pattern.get(self.cursor) == Some(&b'^');
        self.cursor += usize::from(negated);
        let mut bits = [0_u64; 4];
        let mut any = false;
        if self.pattern.get(self.cursor) == Some(&b']') {
            set_class_bit(&mut bits, b']');
            self.cursor += 1;
            any = true;
        }
        while self.cursor < self.pattern.len() && self.pattern[self.cursor] != b']' {
            if self.pattern.get(self.cursor..self.cursor + 2) == Some(b"[:") {
                self.parse_named_class(&mut bits)?;
                any = true;
                continue;
            }
            let start = self.class_byte()?;
            if self.pattern.get(self.cursor) == Some(&b'-')
                && self
                    .pattern
                    .get(self.cursor + 1)
                    .is_some_and(|byte| *byte != b']')
            {
                self.cursor += 1;
                let end = self.class_byte()?;
                if start > end {
                    return Err(RegexError::Invalid);
                }
                for byte in start..=end {
                    set_class_bit(&mut bits, byte);
                }
            } else {
                set_class_bit(&mut bits, start);
            }
            any = true;
        }
        if !any || self.pattern.get(self.cursor) != Some(&b']') {
            return Err(RegexError::Invalid);
        }
        self.cursor += 1;
        if negated {
            for word in &mut bits {
                *word = !*word;
            }
        }
        self.single(Op::Class(bits))
    }

    fn parse_named_class(&mut self, bits: &mut [u64; 4]) -> Result<(), RegexError> {
        let name_start = self.cursor + 2;
        let mut end = name_start;
        while end + 1 < self.pattern.len() && self.pattern.get(end..end + 2) != Some(b":]") {
            end += 1;
        }
        if self.pattern.get(end..end + 2) != Some(b":]") {
            return Err(RegexError::Invalid);
        }
        let name = &self.pattern[name_start..end];
        for value in u8::MIN..=u8::MAX {
            let selected = match name {
                b"alnum" => value.is_ascii_alphanumeric(),
                b"alpha" => value.is_ascii_alphabetic(),
                b"blank" => matches!(value, b' ' | b'\t'),
                b"cntrl" => value.is_ascii_control(),
                b"digit" => value.is_ascii_digit(),
                b"graph" => value.is_ascii_graphic(),
                b"lower" => value.is_ascii_lowercase(),
                b"print" => value.is_ascii_graphic() || value == b' ',
                b"punct" => value.is_ascii_punctuation(),
                b"space" => value.is_ascii_whitespace(),
                b"upper" => value.is_ascii_uppercase(),
                b"xdigit" => value.is_ascii_hexdigit(),
                _ => return Err(RegexError::Invalid),
            };
            if selected {
                set_class_bit(bits, value);
            }
        }
        self.cursor = end + 2;
        Ok(())
    }

    fn class_byte(&mut self) -> Result<u8, RegexError> {
        let byte = *self.pattern.get(self.cursor).ok_or(RegexError::Invalid)?;
        if byte == b'\\' {
            let escaped = *self
                .pattern
                .get(self.cursor + 1)
                .ok_or(RegexError::Invalid)?;
            self.cursor += 2;
            Ok(escaped)
        } else {
            self.cursor += 1;
            Ok(byte)
        }
    }

    fn single(&mut self, op: Op) -> Result<Fragment, RegexError> {
        let instruction = self.program.emit(op, NONE, NONE)?;
        Ok(Fragment {
            start: instruction,
            out: self.program.list(instruction, false)?,
        })
    }

    fn repeat(
        &mut self,
        template_start: usize,
        template_end: usize,
        original: Fragment,
        minimum: usize,
        maximum: Option<usize>,
    ) -> Result<Fragment, RegexError> {
        if minimum > MAX_REPETITION
            || maximum.is_some_and(|maximum| maximum > MAX_REPETITION || maximum < minimum)
        {
            return Err(RegexError::TooComplex);
        }
        let copies = maximum.unwrap_or(minimum.saturating_add(1));
        let mut fragments = [None; MAX_REPETITION + 1];
        if copies != 0 {
            fragments[0] = Some(original);
            for slot in fragments.iter_mut().take(copies).skip(1) {
                *slot = Some(self.program.clone_fragment(
                    template_start,
                    template_end,
                    original,
                )?);
            }
        }
        let mut result = None;
        for copy in fragments.iter().take(minimum).copied().flatten() {
            result = Some(match result {
                None => copy,
                Some(previous) => self.program.concat(previous, copy)?,
            });
        }
        match maximum {
            None => {
                let copy = fragments[minimum].ok_or(RegexError::Invalid)?;
                let tail = self.program.star(copy)?;
                Ok(match result {
                    None => tail,
                    Some(previous) => self.program.concat(previous, tail)?,
                })
            }
            Some(maximum) => {
                for copy in fragments[minimum..maximum].iter().copied().flatten() {
                    let optional = self.program.question(copy)?;
                    result = Some(match result {
                        None => optional,
                        Some(previous) => self.program.concat(previous, optional)?,
                    });
                }
                result.map_or_else(|| self.program.empty(), Ok)
            }
        }
    }

    fn parse_interval(&mut self) -> Result<(usize, Option<usize>), RegexError> {
        self.consume_operator(Operator::Interval)?;
        let minimum = self.number()?;
        let maximum = if self.pattern.get(self.cursor) == Some(&b',') {
            self.cursor += 1;
            if self.interval_end_at_cursor() {
                None
            } else {
                Some(self.number()?)
            }
        } else {
            Some(minimum)
        };
        self.consume_interval_end()?;
        Ok((minimum, maximum))
    }

    fn number(&mut self) -> Result<usize, RegexError> {
        let start = self.cursor;
        let mut value = 0_usize;
        while let Some(byte @ b'0'..=b'9') = self.pattern.get(self.cursor).copied() {
            value = value
                .checked_mul(10)
                .and_then(|value| value.checked_add(usize::from(byte - b'0')))
                .ok_or(RegexError::TooComplex)?;
            self.cursor += 1;
        }
        (self.cursor != start)
            .then_some(value)
            .ok_or(RegexError::Invalid)
    }

    fn at_alternation(&self) -> bool {
        self.at_operator(Operator::Alternation)
    }

    fn at_operator(&self, operator: Operator) -> bool {
        let extended = match operator {
            Operator::Alternation => b'|',
            Operator::Star => b'*',
            Operator::Plus => b'+',
            Operator::Question => b'?',
            Operator::Interval => b'{',
        };
        if operator == Operator::Star || self.syntax == Syntax::Extended {
            self.pattern.get(self.cursor) == Some(&extended)
        } else {
            self.pattern.get(self.cursor) == Some(&b'\\')
                && self.pattern.get(self.cursor + 1) == Some(&extended)
        }
    }

    fn consume_operator(&mut self, operator: Operator) -> Result<(), RegexError> {
        if !self.at_operator(operator) {
            return Err(RegexError::Invalid);
        }
        self.cursor += if operator == Operator::Star || self.syntax == Syntax::Extended {
            1
        } else {
            2
        };
        Ok(())
    }

    fn at_group_start(&self) -> bool {
        if self.syntax == Syntax::Extended {
            self.pattern.get(self.cursor) == Some(&b'(')
        } else {
            self.pattern.get(self.cursor..self.cursor + 2) == Some(b"\\(")
        }
    }

    fn at_group_end(&self) -> bool {
        if self.syntax == Syntax::Extended {
            self.pattern.get(self.cursor) == Some(&b')')
        } else {
            self.pattern.get(self.cursor..self.cursor + 2) == Some(b"\\)")
        }
    }

    fn consume_group_start(&mut self) -> Result<(), RegexError> {
        if !self.at_group_start() {
            return Err(RegexError::Invalid);
        }
        self.cursor += if self.syntax == Syntax::Extended {
            1
        } else {
            2
        };
        Ok(())
    }

    fn consume_group_end(&mut self) -> Result<(), RegexError> {
        if !self.at_group_end() {
            return Err(RegexError::Invalid);
        }
        self.cursor += if self.syntax == Syntax::Extended {
            1
        } else {
            2
        };
        Ok(())
    }

    fn interval_end_at_cursor(&self) -> bool {
        if self.syntax == Syntax::Extended {
            self.pattern.get(self.cursor) == Some(&b'}')
        } else {
            self.pattern.get(self.cursor..self.cursor + 2) == Some(b"\\}")
        }
    }

    fn consume_interval_end(&mut self) -> Result<(), RegexError> {
        if !self.interval_end_at_cursor() {
            return Err(RegexError::Invalid);
        }
        self.cursor += if self.syntax == Syntax::Extended {
            1
        } else {
            2
        };
        Ok(())
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum Operator {
    Alternation,
    Star,
    Plus,
    Question,
    Interval,
}

struct StateSet {
    states: [usize; MAX_INSTRUCTIONS],
    origins: [usize; MAX_INSTRUCTIONS],
    listed: [bool; MAX_INSTRUCTIONS],
    length: usize,
}

impl StateSet {
    const fn new() -> Self {
        Self {
            states: [NONE; MAX_INSTRUCTIONS],
            origins: [NONE; MAX_INSTRUCTIONS],
            listed: [false; MAX_INSTRUCTIONS],
            length: 0,
        }
    }

    fn clear(&mut self) {
        self.length = 0;
        self.origins.fill(NONE);
        self.listed.fill(false);
    }

    fn push(&mut self, pc: usize) -> Result<(), RegexError> {
        if self.listed[pc] {
            return Ok(());
        }
        if self.length == self.states.len() {
            return Err(RegexError::TooComplex);
        }
        self.states[self.length] = pc;
        self.listed[pc] = true;
        self.length += 1;
        Ok(())
    }

    fn accepted_start(
        &self,
        program: &Program,
        subject: &[u8],
        end: usize,
        whole_line: bool,
        whole_word: bool,
    ) -> Option<usize> {
        if (whole_line && end != subject.len())
            || (whole_word && end < subject.len() && is_word(subject[end]))
        {
            return None;
        }
        self.states[..self.length]
            .iter()
            .filter(|pc| matches!(program.instructions[**pc].op, Op::Match))
            .map(|pc| self.origins[*pc])
            .min()
    }

    fn has_consuming_from(&self, program: &Program, origin: usize) -> bool {
        self.states[..self.length].iter().any(|pc| {
            self.origins[*pc] == origin
                && matches!(
                    program.instructions[*pc].op,
                    Op::Byte(_) | Op::Any | Op::Class(_)
                )
        })
    }
}

fn patch_reference(index: usize, y: bool) -> Result<usize, RegexError> {
    if index >= MAX_INSTRUCTIONS {
        return Err(RegexError::Invalid);
    }
    Ok(PATCH_TAG | (index << 1) | usize::from(y))
}

fn decode_patch_reference(reference: usize) -> Result<(usize, bool), RegexError> {
    if reference == NONE || reference & PATCH_TAG == 0 {
        return Err(RegexError::Invalid);
    }
    let encoded = reference & !PATCH_TAG;
    Ok((encoded >> 1, encoded & 1 != 0))
}

fn remap_index(
    index: usize,
    source_start: usize,
    source_end: usize,
    destination: usize,
) -> Result<usize, RegexError> {
    if !(source_start..source_end).contains(&index) {
        return Err(RegexError::Invalid);
    }
    Ok(destination + index - source_start)
}

fn remap_patch(
    reference: usize,
    source_start: usize,
    source_end: usize,
    destination: usize,
) -> Result<usize, RegexError> {
    if reference == NONE {
        return Ok(NONE);
    }
    let (index, y) = decode_patch_reference(reference)?;
    patch_reference(
        remap_index(index, source_start, source_end, destination)?,
        y,
    )
}

fn remap_target(
    target: usize,
    source_start: usize,
    source_end: usize,
    destination: usize,
) -> Result<usize, RegexError> {
    if target == NONE {
        Ok(NONE)
    } else if target & PATCH_TAG != 0 {
        remap_patch(target, source_start, source_end, destination)
    } else {
        remap_index(target, source_start, source_end, destination)
    }
}

fn push_pending(
    pending: &mut [usize; MAX_INSTRUCTIONS],
    length: &mut usize,
    pc: usize,
) -> Result<(), RegexError> {
    if *length == pending.len() {
        return Err(RegexError::TooComplex);
    }
    pending[*length] = pc;
    *length += 1;
    Ok(())
}

fn tick(steps: &mut usize) -> Result<(), RegexError> {
    *steps = steps.checked_add(1).ok_or(RegexError::MatchLimit)?;
    if *steps > MAX_STEPS {
        Err(RegexError::MatchLimit)
    } else {
        Ok(())
    }
}

fn byte_eq(left: u8, right: u8, ignore_case: bool) -> bool {
    left == right || (ignore_case && left.eq_ignore_ascii_case(&right))
}

fn class_contains(bits: [u64; 4], byte: u8, ignore_case: bool) -> bool {
    has_class_bit(bits, byte)
        || (ignore_case
            && (has_class_bit(bits, byte.to_ascii_lowercase())
                || has_class_bit(bits, byte.to_ascii_uppercase())))
}

fn set_class_bit(bits: &mut [u64; 4], byte: u8) {
    bits[usize::from(byte) / 64] |= 1_u64 << (byte % 64);
}

fn has_class_bit(bits: [u64; 4], byte: u8) -> bool {
    bits[usize::from(byte) / 64] & (1_u64 << (byte % 64)) != 0
}

fn is_word(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_'
}

#[cfg(test)]
mod tests {
    use super::{Program, RegexError, Syntax};

    fn ranges(
        pattern: &str,
        syntax: Syntax,
        subject: &str,
    ) -> Result<Option<(usize, usize)>, RegexError> {
        let mut program = Program::new();
        program.add(pattern, syntax)?;
        program.finish()?;
        Ok(program
            .find(subject.as_bytes(), 0, false, false, false)?
            .map(|range| (range.start, range.end)))
    }

    #[test]
    fn extended_alternation_grouping_and_repetition_are_leftmost_longest() {
        assert_eq!(
            ranges("(abc|de)+f?", Syntax::Extended, "--abcdeff"),
            Ok(Some((2, 8)))
        );
        assert_eq!(
            ranges("a{2,4}", Syntax::Extended, "zaaaaax"),
            Ok(Some((1, 5)))
        );
    }

    #[test]
    fn basic_operators_require_backslashes() {
        assert_eq!(ranges("abc|def", Syntax::Basic, "def"), Ok(None));
        assert_eq!(ranges(r"abc\|def", Syntax::Basic, "def"), Ok(Some((0, 3))));
        assert_eq!(ranges(r"\(ab\)\+", Syntax::Basic, "abab"), Ok(Some((0, 4))));
    }

    #[test]
    fn classes_anchors_and_case_folding_work() {
        assert_eq!(
            ranges("^[[:alpha:]_][^0-9]*$", Syntax::Extended, "Name_x"),
            Ok(Some((0, 6)))
        );
        let mut program = Program::new();
        program.add("[a-f]+", Syntax::Extended).unwrap();
        program.finish().unwrap();
        assert_eq!(
            program.find(b"--BEEF--", 0, true, false, false),
            Ok(Some(2..6))
        );
    }

    #[test]
    fn fixed_whole_line_and_whole_word_modes_are_distinct() {
        let mut program = Program::new();
        program.add("cat", Syntax::Fixed).unwrap();
        program.finish().unwrap();
        assert_eq!(
            program.find(b"catfish cat", 0, false, false, true),
            Ok(Some(8..11))
        );
        assert_eq!(program.find(b"cat", 0, false, true, false), Ok(Some(0..3)));
        assert_eq!(program.find(b"a cat", 0, false, true, false), Ok(None));
    }

    #[test]
    fn multiple_patterns_are_combined() {
        let mut program = Program::new();
        program.add("one", Syntax::Fixed).unwrap();
        program.add("t.o", Syntax::Extended).unwrap();
        program.finish().unwrap();
        assert!(
            program
                .find(b"two", 0, false, false, false)
                .unwrap()
                .is_some()
        );
    }

    #[test]
    fn malformed_and_oversized_expressions_fail_cleanly() {
        assert_eq!(
            ranges("[abc", Syntax::Extended, "a"),
            Err(RegexError::Invalid)
        );
        assert_eq!(
            ranges("a{65}", Syntax::Extended, "a"),
            Err(RegexError::TooComplex)
        );
    }

    #[test]
    fn ambiguous_repetition_remains_linear_on_long_input() {
        let mut program = Program::new();
        program
            .add("a*a*a*a*z", Syntax::Extended)
            .expect("bounded expression");
        program.finish().expect("bounded program");
        let subject = std::vec![b'a'; 64 * 1024];
        assert_eq!(program.find(&subject, 0, false, false, false), Ok(None));
    }
}
