//! Configurable bounded terminal input decoding and line editing.
#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;
#[cfg(test)]
extern crate std;

use alloc::collections::VecDeque;
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;
use core::mem;

use troe_core::{MAX_LINE_BYTES, Output, StreamError};

/// Invalid terminal or editor resource policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConfigError {
    /// Editable lines must accept at least one byte.
    EmptyLineCapacity,
    /// History entry and byte capacities must both be zero or both be non-zero.
    InconsistentHistoryCapacity,
    /// An escape sequence must allow at least its introducer and final byte.
    EscapeCapacityTooSmall,
    /// Text-grid retention must accept at least one cell.
    EmptyCellCapacity,
    /// Tab stops must contain at least one column.
    EmptyTabWidth,
}

/// Volatile command-history resource policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HistoryConfig {
    max_entries: usize,
    max_bytes: usize,
}

impl HistoryConfig {
    /// Construct a history policy. Two zero values disable history.
    ///
    /// # Errors
    ///
    /// Fails if exactly one capacity is zero.
    pub const fn new(max_entries: usize, max_bytes: usize) -> Result<Self, ConfigError> {
        if (max_entries == 0) != (max_bytes == 0) {
            return Err(ConfigError::InconsistentHistoryCapacity);
        }
        Ok(Self {
            max_entries,
            max_bytes,
        })
    }

    /// A disabled history policy.
    #[must_use]
    pub const fn disabled() -> Self {
        Self {
            max_entries: 0,
            max_bytes: 0,
        }
    }

    /// Default bounded resource policy.
    #[must_use]
    pub const fn standard() -> Self {
        Self {
            max_entries: 32,
            max_bytes: 16 * 1024,
        }
    }

    /// Maximum retained command count.
    #[must_use]
    pub const fn max_entries(self) -> usize {
        self.max_entries
    }

    /// Maximum retained command payload bytes.
    #[must_use]
    pub const fn max_bytes(self) -> usize {
        self.max_bytes
    }

    /// Whether history retention is disabled.
    #[must_use]
    pub const fn is_disabled(self) -> bool {
        self.max_entries == 0
    }
}

/// Serial input-decoder resource policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InputConfig {
    max_escape_bytes: usize,
}

impl InputConfig {
    /// Construct an input policy.
    ///
    /// # Errors
    ///
    /// Fails when an escape sequence cannot contain an introducer and final byte.
    pub const fn new(max_escape_bytes: usize) -> Result<Self, ConfigError> {
        if max_escape_bytes < 2 {
            return Err(ConfigError::EscapeCapacityTooSmall);
        }
        Ok(Self { max_escape_bytes })
    }

    /// Default bounded resource policy.
    #[must_use]
    pub const fn standard() -> Self {
        Self {
            max_escape_bytes: 16,
        }
    }

    /// Maximum bytes consumed as one escape sequence.
    #[must_use]
    pub const fn max_escape_bytes(self) -> usize {
        self.max_escape_bytes
    }
}

/// Complete line-editor policy selected by a composition root.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EditorConfig {
    max_line_bytes: usize,
    history: HistoryConfig,
    input: InputConfig,
}

impl EditorConfig {
    /// Construct an editor policy from independently replaceable limits.
    ///
    /// # Errors
    ///
    /// Fails if editable lines have no capacity.
    pub const fn new(
        max_line_bytes: usize,
        history: HistoryConfig,
        input: InputConfig,
    ) -> Result<Self, ConfigError> {
        if max_line_bytes == 0 {
            return Err(ConfigError::EmptyLineCapacity);
        }
        Ok(Self {
            max_line_bytes,
            history,
            input,
        })
    }

    /// Default bounded resource policy.
    #[must_use]
    pub const fn standard() -> Self {
        Self {
            max_line_bytes: MAX_LINE_BYTES,
            history: HistoryConfig::standard(),
            input: InputConfig::standard(),
        }
    }

    /// Maximum editable line length in UTF-8 bytes.
    #[must_use]
    pub const fn max_line_bytes(self) -> usize {
        self.max_line_bytes
    }

    /// Volatile history policy.
    #[must_use]
    pub const fn history(self) -> HistoryConfig {
        self.history
    }

    /// Serial input policy.
    #[must_use]
    pub const fn input(self) -> InputConfig {
        self.input
    }
}

/// Transport-independent keys consumed by the editor.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KeyEvent {
    /// Insert one Unicode scalar value.
    Character(char),
    /// Submit the current line.
    Enter,
    /// Delete the character preceding the cursor.
    Backspace,
    /// Delete the character under the cursor.
    Delete,
    /// Move one character left.
    Left,
    /// Move one character right.
    Right,
    /// Move to the start of the line.
    Home,
    /// Move to the end of the line.
    End,
    /// Recall the previous history entry.
    Up,
    /// Recall the next history entry or the saved scratch line.
    Down,
    /// Request shell-aware completion.
    Complete,
    /// Cancel and clear the current line.
    Cancel,
    /// Request display clearing and redraw without changing the line.
    ClearDisplay,
    /// Delete from the start of the line to the cursor.
    KillBefore,
    /// Delete from the cursor to the end of the line.
    KillAfter,
    /// Delete the previous whitespace-delimited word.
    DeletePreviousWord,
    /// Signal end of input to a foreground reader.
    EndOfInput,
}

/// Observable result of one editor operation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum EditorOutcome {
    /// The line or cursor changed and should be redrawn.
    Changed,
    /// A complete owned line was submitted.
    Submitted(String),
    /// The current line was cancelled and cleared.
    Cancelled,
    /// The display should be cleared and the unchanged line redrawn.
    ClearRequested,
    /// The shell should calculate completion candidates for the current cursor.
    CompletionRequested,
    /// A configured capacity prevented the requested edit.
    LimitReached,
    /// The key had no effect in the current state.
    Ignored,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DecodeState {
    Ground,
    Escape {
        bytes: usize,
    },
    Csi {
        bytes: usize,
        parameter: u16,
        has_parameter: bool,
        unsupported: bool,
    },
    Ss3 {
        bytes: usize,
    },
    Discard,
}

/// Incremental UTF-8 and ANSI key decoder for byte-stream consoles.
#[derive(Debug)]
pub struct InputDecoder {
    config: InputConfig,
    state: DecodeState,
    discard_leading_lf: bool,
    utf8: [u8; 4],
    utf8_len: usize,
    utf8_expected: usize,
}

impl InputDecoder {
    /// Construct a decoder with an injected resource policy.
    #[must_use]
    pub const fn new(config: InputConfig) -> Self {
        Self {
            config,
            state: DecodeState::Ground,
            discard_leading_lf: false,
            utf8: [0; 4],
            utf8_len: 0,
            utf8_expected: 0,
        }
    }

    /// Consume one transport byte and emit at most one logical key.
    pub fn push(&mut self, byte: u8) -> Option<KeyEvent> {
        match self.state {
            DecodeState::Ground => self.push_ground(byte),
            DecodeState::Escape { bytes } => self.push_escape(byte, bytes),
            DecodeState::Csi {
                bytes,
                parameter,
                has_parameter,
                unsupported,
            } => self.push_csi(byte, bytes, parameter, has_parameter, unsupported),
            DecodeState::Ss3 { bytes } => self.push_ss3(byte, bytes),
            DecodeState::Discard => {
                self.push_discard(byte);
                None
            }
        }
    }

    fn push_ground(&mut self, byte: u8) -> Option<KeyEvent> {
        if self.discard_leading_lf && byte == b'\n' {
            self.discard_leading_lf = false;
            return None;
        }
        self.discard_leading_lf = false;
        match byte {
            b'\r' => {
                self.discard_leading_lf = true;
                Some(KeyEvent::Enter)
            }
            b'\n' => Some(KeyEvent::Enter),
            b'\x08' | b'\x7f' => Some(KeyEvent::Backspace),
            b'\t' => Some(KeyEvent::Complete),
            b'\x01' => Some(KeyEvent::Home),
            b'\x03' => Some(KeyEvent::Cancel),
            b'\x04' => Some(KeyEvent::EndOfInput),
            b'\x05' => Some(KeyEvent::End),
            b'\x0b' => Some(KeyEvent::KillAfter),
            b'\x0c' => Some(KeyEvent::ClearDisplay),
            b'\x15' => Some(KeyEvent::KillBefore),
            b'\x17' => Some(KeyEvent::DeletePreviousWord),
            b'\x1b' => {
                self.reset_utf8();
                self.state = DecodeState::Escape { bytes: 1 };
                None
            }
            0x20..=0x7e => Some(KeyEvent::Character(char::from(byte))),
            0x80..=0xff => self.push_utf8(byte),
            _ => None,
        }
    }

    fn push_escape(&mut self, byte: u8, bytes: usize) -> Option<KeyEvent> {
        let bytes = bytes.saturating_add(1);
        if bytes > self.config.max_escape_bytes() {
            self.state = DecodeState::Discard;
            return None;
        }
        match byte {
            b'[' => {
                self.state = DecodeState::Csi {
                    bytes,
                    parameter: 0,
                    has_parameter: false,
                    unsupported: false,
                };
                None
            }
            b'O' => {
                self.state = DecodeState::Ss3 { bytes };
                None
            }
            _ => {
                self.state = DecodeState::Ground;
                None
            }
        }
    }

    fn push_csi(
        &mut self,
        byte: u8,
        bytes: usize,
        mut parameter: u16,
        mut has_parameter: bool,
        mut unsupported: bool,
    ) -> Option<KeyEvent> {
        let bytes = bytes.saturating_add(1);
        if bytes > self.config.max_escape_bytes() {
            self.state = DecodeState::Discard;
            return None;
        }
        if byte.is_ascii_digit() && !unsupported {
            has_parameter = true;
            parameter = parameter
                .saturating_mul(10)
                .saturating_add(u16::from(byte - b'0'));
            self.state = DecodeState::Csi {
                bytes,
                parameter,
                has_parameter,
                unsupported,
            };
            return None;
        }
        if (0x20..=0x3f).contains(&byte) {
            unsupported = true;
            self.state = DecodeState::Csi {
                bytes,
                parameter,
                has_parameter,
                unsupported,
            };
            return None;
        }
        if (0x40..=0x7e).contains(&byte) {
            self.state = DecodeState::Ground;
            if unsupported {
                return None;
            }
            return match (byte, has_parameter.then_some(parameter)) {
                (b'A', None | Some(1)) => Some(KeyEvent::Up),
                (b'B', None | Some(1)) => Some(KeyEvent::Down),
                (b'C', None | Some(1)) => Some(KeyEvent::Right),
                (b'D', None | Some(1)) => Some(KeyEvent::Left),
                (b'H', None | Some(1)) | (b'~', Some(1 | 7)) => Some(KeyEvent::Home),
                (b'F', None | Some(1)) | (b'~', Some(4 | 8)) => Some(KeyEvent::End),
                (b'~', Some(3)) => Some(KeyEvent::Delete),
                _ => None,
            };
        }
        self.state = DecodeState::Discard;
        None
    }

    fn push_ss3(&mut self, byte: u8, bytes: usize) -> Option<KeyEvent> {
        let bytes = bytes.saturating_add(1);
        self.state = DecodeState::Ground;
        if bytes > self.config.max_escape_bytes() {
            return None;
        }
        match byte {
            b'A' => Some(KeyEvent::Up),
            b'B' => Some(KeyEvent::Down),
            b'C' => Some(KeyEvent::Right),
            b'D' => Some(KeyEvent::Left),
            b'H' => Some(KeyEvent::Home),
            b'F' => Some(KeyEvent::End),
            _ => None,
        }
    }

    fn push_discard(&mut self, byte: u8) {
        if (0x40..=0x7e).contains(&byte) {
            self.state = DecodeState::Ground;
        }
    }

    fn push_utf8(&mut self, byte: u8) -> Option<KeyEvent> {
        if self.utf8_len == 0 {
            self.utf8_expected = match byte {
                0xc2..=0xdf => 2,
                0xe0..=0xef => 3,
                0xf0..=0xf4 => 4,
                _ => return Some(KeyEvent::Character('\u{fffd}')),
            };
        } else if !(0x80..=0xbf).contains(&byte) {
            self.reset_utf8();
            return Some(KeyEvent::Character('\u{fffd}'));
        }
        self.utf8[self.utf8_len] = byte;
        self.utf8_len += 1;
        if self.utf8_len < self.utf8_expected {
            return None;
        }
        let character = core::str::from_utf8(&self.utf8[..self.utf8_len])
            .ok()
            .and_then(|text| text.chars().next())
            .unwrap_or('\u{fffd}');
        self.reset_utf8();
        Some(KeyEvent::Character(character))
    }

    const fn reset_utf8(&mut self) {
        self.utf8_len = 0;
        self.utf8_expected = 0;
    }
}

/// Configurable bounded line editor with volatile history.
#[derive(Debug)]
pub struct LineEditor {
    config: EditorConfig,
    line: String,
    cursor: usize,
    history: VecDeque<String>,
    history_bytes: usize,
    history_cursor: Option<usize>,
    scratch: String,
}

impl LineEditor {
    /// Construct an empty editor with an injected policy.
    #[must_use]
    pub const fn new(config: EditorConfig) -> Self {
        Self {
            config,
            line: String::new(),
            cursor: 0,
            history: VecDeque::new(),
            history_bytes: 0,
            history_cursor: None,
            scratch: String::new(),
        }
    }

    /// Current editable line.
    #[must_use]
    pub fn line(&self) -> &str {
        &self.line
    }

    /// UTF-8 byte offset of the cursor.
    #[must_use]
    pub const fn cursor(&self) -> usize {
        self.cursor
    }

    /// Current retained history entry count.
    #[must_use]
    pub fn history_len(&self) -> usize {
        self.history.len()
    }

    /// Current retained history payload bytes.
    #[must_use]
    pub const fn history_bytes(&self) -> usize {
        self.history_bytes
    }

    /// Apply one logical key.
    pub fn handle(&mut self, key: KeyEvent) -> EditorOutcome {
        match key {
            KeyEvent::Character(character) => self.insert(character),
            KeyEvent::Enter => self.submit(),
            KeyEvent::Backspace => self.backspace(),
            KeyEvent::Delete => self.delete(),
            KeyEvent::Left => self.move_left(),
            KeyEvent::Right => self.move_right(),
            KeyEvent::Home => self.move_home(),
            KeyEvent::End => self.move_end(),
            KeyEvent::Up => self.history_previous(),
            KeyEvent::Down => self.history_next(),
            KeyEvent::Complete => EditorOutcome::CompletionRequested,
            KeyEvent::Cancel => self.cancel(),
            KeyEvent::ClearDisplay => EditorOutcome::ClearRequested,
            KeyEvent::KillBefore => self.kill_before(),
            KeyEvent::KillAfter => self.kill_after(),
            KeyEvent::DeletePreviousWord => self.delete_previous_word(),
            KeyEvent::EndOfInput => EditorOutcome::Ignored,
        }
    }

    /// Replace a cursor-aligned byte range, used by bounded completion.
    pub fn replace_range(&mut self, start: usize, end: usize, replacement: &str) -> EditorOutcome {
        if start > end
            || end > self.line.len()
            || !self.line.is_char_boundary(start)
            || !self.line.is_char_boundary(end)
        {
            return EditorOutcome::Ignored;
        }
        let Some(new_len) = self
            .line
            .len()
            .checked_sub(end - start)
            .and_then(|length| length.checked_add(replacement.len()))
        else {
            return EditorOutcome::LimitReached;
        };
        if new_len > self.config.max_line_bytes() {
            return EditorOutcome::LimitReached;
        }
        self.leave_history_browse();
        self.line.replace_range(start..end, replacement);
        self.cursor = start + replacement.len();
        EditorOutcome::Changed
    }

    fn insert(&mut self, character: char) -> EditorOutcome {
        let Some(new_len) = self.line.len().checked_add(character.len_utf8()) else {
            return EditorOutcome::LimitReached;
        };
        if new_len > self.config.max_line_bytes() {
            return EditorOutcome::LimitReached;
        }
        self.leave_history_browse();
        self.line.insert(self.cursor, character);
        self.cursor += character.len_utf8();
        EditorOutcome::Changed
    }

    fn submit(&mut self) -> EditorOutcome {
        let submitted = mem::take(&mut self.line);
        self.cursor = 0;
        self.history_cursor = None;
        self.scratch.clear();
        self.record_history(&submitted);
        EditorOutcome::Submitted(submitted)
    }

    fn backspace(&mut self) -> EditorOutcome {
        let Some(previous) = previous_boundary(&self.line, self.cursor) else {
            return EditorOutcome::Ignored;
        };
        self.leave_history_browse();
        self.line.replace_range(previous..self.cursor, "");
        self.cursor = previous;
        EditorOutcome::Changed
    }

    fn delete(&mut self) -> EditorOutcome {
        let Some(next) = next_boundary(&self.line, self.cursor) else {
            return EditorOutcome::Ignored;
        };
        self.leave_history_browse();
        self.line.replace_range(self.cursor..next, "");
        EditorOutcome::Changed
    }

    fn move_left(&mut self) -> EditorOutcome {
        let Some(previous) = previous_boundary(&self.line, self.cursor) else {
            return EditorOutcome::Ignored;
        };
        self.cursor = previous;
        EditorOutcome::Changed
    }

    fn move_right(&mut self) -> EditorOutcome {
        let Some(next) = next_boundary(&self.line, self.cursor) else {
            return EditorOutcome::Ignored;
        };
        self.cursor = next;
        EditorOutcome::Changed
    }

    fn move_home(&mut self) -> EditorOutcome {
        if self.cursor == 0 {
            return EditorOutcome::Ignored;
        }
        self.cursor = 0;
        EditorOutcome::Changed
    }

    fn move_end(&mut self) -> EditorOutcome {
        if self.cursor == self.line.len() {
            return EditorOutcome::Ignored;
        }
        self.cursor = self.line.len();
        EditorOutcome::Changed
    }

    fn kill_before(&mut self) -> EditorOutcome {
        if self.cursor == 0 {
            return EditorOutcome::Ignored;
        }
        self.leave_history_browse();
        self.line.replace_range(..self.cursor, "");
        self.cursor = 0;
        EditorOutcome::Changed
    }

    fn kill_after(&mut self) -> EditorOutcome {
        if self.cursor == self.line.len() {
            return EditorOutcome::Ignored;
        }
        self.leave_history_browse();
        self.line.truncate(self.cursor);
        EditorOutcome::Changed
    }

    fn delete_previous_word(&mut self) -> EditorOutcome {
        if self.cursor == 0 {
            return EditorOutcome::Ignored;
        }
        let mut start = self.cursor;
        while let Some(previous) = previous_boundary(&self.line, start) {
            let Some(character) = self.line[previous..start].chars().next() else {
                break;
            };
            if !character.is_whitespace() {
                break;
            }
            start = previous;
        }
        while let Some(previous) = previous_boundary(&self.line, start) {
            let Some(character) = self.line[previous..start].chars().next() else {
                break;
            };
            if character.is_whitespace() {
                break;
            }
            start = previous;
        }
        self.leave_history_browse();
        self.line.replace_range(start..self.cursor, "");
        self.cursor = start;
        EditorOutcome::Changed
    }

    fn cancel(&mut self) -> EditorOutcome {
        self.line.clear();
        self.cursor = 0;
        self.history_cursor = None;
        self.scratch.clear();
        EditorOutcome::Cancelled
    }

    fn record_history(&mut self, line: &str) {
        let policy = self.config.history();
        if policy.is_disabled()
            || line.is_empty()
            || line.len() > policy.max_bytes()
            || self.history.back().is_some_and(|entry| entry == line)
        {
            return;
        }
        while self.history.len() >= policy.max_entries()
            || self
                .history_bytes
                .checked_add(line.len())
                .is_none_or(|bytes| bytes > policy.max_bytes())
        {
            let Some(removed) = self.history.pop_front() else {
                return;
            };
            self.history_bytes = self.history_bytes.saturating_sub(removed.len());
        }
        self.history.push_back(String::from(line));
        self.history_bytes += line.len();
    }

    fn history_previous(&mut self) -> EditorOutcome {
        if self.history.is_empty() {
            return EditorOutcome::Ignored;
        }
        let index = match self.history_cursor {
            None => {
                self.scratch.clone_from(&self.line);
                self.history.len() - 1
            }
            Some(0) => return EditorOutcome::Ignored,
            Some(index) => index - 1,
        };
        self.history_cursor = Some(index);
        self.line.clone_from(&self.history[index]);
        self.cursor = self.line.len();
        EditorOutcome::Changed
    }

    fn history_next(&mut self) -> EditorOutcome {
        let Some(index) = self.history_cursor else {
            return EditorOutcome::Ignored;
        };
        if index + 1 < self.history.len() {
            self.history_cursor = Some(index + 1);
            self.line.clone_from(&self.history[index + 1]);
        } else {
            self.history_cursor = None;
            self.line.clone_from(&self.scratch);
            self.scratch.clear();
        }
        self.cursor = self.line.len();
        EditorOutcome::Changed
    }

    fn leave_history_browse(&mut self) {
        if self.history_cursor.take().is_some() {
            self.scratch.clear();
        }
    }
}

fn previous_boundary(line: &str, cursor: usize) -> Option<usize> {
    line.get(..cursor)?
        .char_indices()
        .next_back()
        .map(|(index, _)| index)
}

fn next_boundary(line: &str, cursor: usize) -> Option<usize> {
    let character = line.get(cursor..)?.chars().next()?;
    Some(cursor + character.len_utf8())
}

/// Keyboard layout selected by the composition profile.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KeyboardLayout {
    /// US PC set-1 key positions.
    Us,
}

/// Native keyboard decoding policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct KeyboardConfig {
    layout: KeyboardLayout,
}

impl KeyboardConfig {
    /// Construct a keyboard policy.
    #[must_use]
    pub const fn new(layout: KeyboardLayout) -> Self {
        Self { layout }
    }

    /// Default bounded keyboard policy.
    #[must_use]
    pub const fn standard() -> Self {
        Self::new(KeyboardLayout::Us)
    }

    /// Selected physical key layout.
    #[must_use]
    pub const fn layout(self) -> KeyboardLayout {
        self.layout
    }
}

/// Incremental PC keyboard scan-code-set-1 decoder.
#[derive(Debug)]
pub struct Ps2Set1Decoder {
    config: KeyboardConfig,
    extended: bool,
    modifiers: u8,
}

const MODIFIER_LEFT_SHIFT: u8 = 1 << 0;
const MODIFIER_RIGHT_SHIFT: u8 = 1 << 1;
const MODIFIER_CONTROL: u8 = 1 << 2;
const MODIFIER_CAPS_LOCK: u8 = 1 << 3;

impl Ps2Set1Decoder {
    /// Construct a decoder with an injected layout policy.
    #[must_use]
    pub const fn new(config: KeyboardConfig) -> Self {
        Self {
            config,
            extended: false,
            modifiers: 0,
        }
    }

    /// Consume one set-1 scan-code byte and emit at most one logical key.
    pub fn push(&mut self, byte: u8) -> Option<KeyEvent> {
        if byte == 0xe0 {
            self.extended = true;
            return None;
        }
        let extended = mem::take(&mut self.extended);
        let released = byte & 0x80 != 0;
        let code = byte & 0x7f;
        if extended {
            if code == 0x1d {
                self.set_modifier(MODIFIER_CONTROL, !released);
                return None;
            }
            if released {
                return None;
            }
            return match code {
                0x47 => Some(KeyEvent::Home),
                0x48 => Some(KeyEvent::Up),
                0x4b => Some(KeyEvent::Left),
                0x4d => Some(KeyEvent::Right),
                0x4f => Some(KeyEvent::End),
                0x50 => Some(KeyEvent::Down),
                0x53 => Some(KeyEvent::Delete),
                _ => None,
            };
        }
        match code {
            0x1d => {
                self.set_modifier(MODIFIER_CONTROL, !released);
                return None;
            }
            0x2a => {
                self.set_modifier(MODIFIER_LEFT_SHIFT, !released);
                return None;
            }
            0x36 => {
                self.set_modifier(MODIFIER_RIGHT_SHIFT, !released);
                return None;
            }
            0x3a if !released => {
                self.modifiers ^= MODIFIER_CAPS_LOCK;
                return None;
            }
            _ => {}
        }
        if released {
            return None;
        }
        match code {
            0x0e => return Some(KeyEvent::Backspace),
            0x0f => return Some(KeyEvent::Complete),
            0x1c => return Some(KeyEvent::Enter),
            _ => {}
        }
        let shifted = self.modifiers & (MODIFIER_LEFT_SHIFT | MODIFIER_RIGHT_SHIFT) != 0;
        let character = match self.config.layout() {
            KeyboardLayout::Us => {
                us_set1_character(code, shifted, self.modifiers & MODIFIER_CAPS_LOCK != 0)
            }
        }?;
        if self.modifiers & MODIFIER_CONTROL != 0 {
            return control_key(character);
        }
        Some(KeyEvent::Character(character))
    }

    fn set_modifier(&mut self, modifier: u8, active: bool) {
        if active {
            self.modifiers |= modifier;
        } else {
            self.modifiers &= !modifier;
        }
    }
}

fn control_key(character: char) -> Option<KeyEvent> {
    match character.to_ascii_lowercase() {
        'a' => Some(KeyEvent::Home),
        'c' => Some(KeyEvent::Cancel),
        'd' => Some(KeyEvent::EndOfInput),
        'e' => Some(KeyEvent::End),
        'k' => Some(KeyEvent::KillAfter),
        'l' => Some(KeyEvent::ClearDisplay),
        'u' => Some(KeyEvent::KillBefore),
        'w' => Some(KeyEvent::DeletePreviousWord),
        _ => None,
    }
}

fn us_set1_character(code: u8, shifted: bool, caps_lock: bool) -> Option<char> {
    let base = match code {
        0x02 => '1',
        0x03 => '2',
        0x04 => '3',
        0x05 => '4',
        0x06 => '5',
        0x07 => '6',
        0x08 => '7',
        0x09 => '8',
        0x0a => '9',
        0x0b => '0',
        0x0c => '-',
        0x0d => '=',
        0x10 => 'q',
        0x11 => 'w',
        0x12 => 'e',
        0x13 => 'r',
        0x14 => 't',
        0x15 => 'y',
        0x16 => 'u',
        0x17 => 'i',
        0x18 => 'o',
        0x19 => 'p',
        0x1a => '[',
        0x1b => ']',
        0x1e => 'a',
        0x1f => 's',
        0x20 => 'd',
        0x21 => 'f',
        0x22 => 'g',
        0x23 => 'h',
        0x24 => 'j',
        0x25 => 'k',
        0x26 => 'l',
        0x27 => ';',
        0x28 => '\'',
        0x29 => '`',
        0x2b => '\\',
        0x2c => 'z',
        0x2d => 'x',
        0x2e => 'c',
        0x2f => 'v',
        0x30 => 'b',
        0x31 => 'n',
        0x32 => 'm',
        0x33 => ',',
        0x34 => '.',
        0x35 => '/',
        0x39 => ' ',
        _ => return None,
    };
    if base.is_ascii_alphabetic() {
        return Some(if shifted ^ caps_lock {
            base.to_ascii_uppercase()
        } else {
            base
        });
    }
    Some(if shifted {
        match base {
            '1' => '!',
            '2' => '@',
            '3' => '#',
            '4' => '$',
            '5' => '%',
            '6' => '^',
            '7' => '&',
            '8' => '*',
            '9' => '(',
            '0' => ')',
            '-' => '_',
            '=' => '+',
            '[' => '{',
            ']' => '}',
            ';' => ':',
            '\'' => '"',
            '`' => '~',
            '\\' => '|',
            ',' => '<',
            '.' => '>',
            '/' => '?',
            _ => base,
        }
    } else {
        base
    })
}

/// An RGB terminal color independent of framebuffer byte order.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Color {
    /// Red channel.
    pub red: u8,
    /// Green channel.
    pub green: u8,
    /// Blue channel.
    pub blue: u8,
}

impl Color {
    /// Construct an RGB color.
    #[must_use]
    pub const fn new(red: u8, green: u8, blue: u8) -> Self {
        Self { red, green, blue }
    }
}

/// Configurable text-console resource and rendering policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TextConsoleConfig {
    max_cells: usize,
    max_escape_bytes: usize,
    tab_width: usize,
    foreground: Color,
    background: Color,
}

impl TextConsoleConfig {
    /// Construct a text-console policy.
    ///
    /// # Errors
    ///
    /// Fails for an empty cell budget, undersized escape budget, or zero tab width.
    pub const fn new(
        max_cells: usize,
        max_escape_bytes: usize,
        tab_width: usize,
        foreground: Color,
        background: Color,
    ) -> Result<Self, ConfigError> {
        if max_cells == 0 {
            return Err(ConfigError::EmptyCellCapacity);
        }
        if max_escape_bytes < 2 {
            return Err(ConfigError::EscapeCapacityTooSmall);
        }
        if tab_width == 0 {
            return Err(ConfigError::EmptyTabWidth);
        }
        Ok(Self {
            max_cells,
            max_escape_bytes,
            tab_width,
            foreground,
            background,
        })
    }

    /// Default bounded text-console policy.
    #[must_use]
    pub const fn standard() -> Self {
        Self {
            max_cells: 32 * 1024,
            max_escape_bytes: 16,
            tab_width: 8,
            foreground: Color::new(0xd8, 0xde, 0xe9),
            background: Color::new(0x18, 0x1c, 0x24),
        }
    }

    /// Maximum retained text cells.
    #[must_use]
    pub const fn max_cells(self) -> usize {
        self.max_cells
    }

    /// Maximum consumed bytes in one output escape sequence.
    #[must_use]
    pub const fn max_escape_bytes(self) -> usize {
        self.max_escape_bytes
    }

    /// Columns per tab stop.
    #[must_use]
    pub const fn tab_width(self) -> usize {
        self.tab_width
    }

    /// Default foreground color.
    #[must_use]
    pub const fn foreground(self) -> Color {
        self.foreground
    }

    /// Default background color.
    #[must_use]
    pub const fn background(self) -> Color {
        self.background
    }
}

/// Pixel-surface operation failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SurfaceError {
    /// Surface dimensions or an addressed pixel are invalid.
    Bounds,
    /// The selected surface representation is unsupported.
    Unsupported,
    /// Checked surface arithmetic overflowed.
    Overflow,
}

/// Bytes occupied by one 32-bit framebuffer pixel.
pub const FRAMEBUFFER_BYTES_PER_PIXEL: usize = 4;

/// Supported 32-bit framebuffer channel order.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FramebufferPixelFormat {
    /// Red, green, blue, reserved bytes.
    Rgb,
    /// Blue, green, red, reserved bytes.
    Bgr,
}

/// Checked byte offset and channel encoding for one framebuffer pixel.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EncodedFramebufferPixel {
    byte_offset: usize,
    bytes: [u8; 4],
}

impl EncodedFramebufferPixel {
    /// Byte offset from the beginning of the framebuffer mapping.
    #[must_use]
    pub const fn byte_offset(self) -> usize {
        self.byte_offset
    }

    /// Four bytes in the framebuffer's selected channel order.
    #[must_use]
    pub const fn bytes(self) -> [u8; 4] {
        self.bytes
    }
}

/// Invalid physical framebuffer metadata.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FramebufferDescriptorError {
    /// Width, height, stride, byte length, or base address is zero.
    Empty,
    /// Visible width exceeds the scanline stride.
    InvalidStride,
    /// The byte range is too small for the declared geometry.
    TooSmall,
    /// Checked address or size arithmetic overflowed.
    Overflow,
}

/// Copied, firmware-independent physical framebuffer metadata.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FramebufferDescriptor {
    base_address: u64,
    byte_len: usize,
    width: usize,
    height: usize,
    stride: usize,
    pixel_format: FramebufferPixelFormat,
}

impl FramebufferDescriptor {
    /// Validate copied framebuffer metadata.
    ///
    /// # Errors
    ///
    /// Fails for empty fields, invalid stride, insufficient bytes, or overflow.
    pub fn new(
        base_address: u64,
        byte_len: usize,
        width: usize,
        height: usize,
        stride: usize,
        pixel_format: FramebufferPixelFormat,
    ) -> Result<Self, FramebufferDescriptorError> {
        if base_address == 0 || byte_len == 0 || width == 0 || height == 0 || stride == 0 {
            return Err(FramebufferDescriptorError::Empty);
        }
        if width > stride {
            return Err(FramebufferDescriptorError::InvalidStride);
        }
        let required = stride
            .checked_mul(height)
            .and_then(|pixels| pixels.checked_mul(FRAMEBUFFER_BYTES_PER_PIXEL))
            .ok_or(FramebufferDescriptorError::Overflow)?;
        if required > byte_len {
            return Err(FramebufferDescriptorError::TooSmall);
        }
        let byte_len_u64 =
            u64::try_from(byte_len).map_err(|_| FramebufferDescriptorError::Overflow)?;
        base_address
            .checked_add(byte_len_u64)
            .ok_or(FramebufferDescriptorError::Overflow)?;
        Ok(Self {
            base_address,
            byte_len,
            width,
            height,
            stride,
            pixel_format,
        })
    }

    /// Physical address of the first framebuffer byte.
    #[must_use]
    pub const fn base_address(self) -> u64 {
        self.base_address
    }

    /// Complete mapped byte length.
    #[must_use]
    pub const fn byte_len(self) -> usize {
        self.byte_len
    }

    /// Visible pixel width.
    #[must_use]
    pub const fn width(self) -> usize {
        self.width
    }

    /// Visible pixel height.
    #[must_use]
    pub const fn height(self) -> usize {
        self.height
    }

    /// Pixels per scanline.
    #[must_use]
    pub const fn stride(self) -> usize {
        self.stride
    }

    /// Byte order of one 32-bit pixel.
    #[must_use]
    pub const fn pixel_format(self) -> FramebufferPixelFormat {
        self.pixel_format
    }

    /// Encode one visible pixel as a checked framebuffer-relative write.
    ///
    /// # Errors
    ///
    /// Rejects coordinates outside the visible surface, arithmetic overflow,
    /// or a write extending beyond the validated framebuffer byte range.
    pub fn encode_pixel(
        self,
        x: usize,
        y: usize,
        color: Color,
    ) -> Result<EncodedFramebufferPixel, SurfaceError> {
        if x >= self.width || y >= self.height {
            return Err(SurfaceError::Bounds);
        }
        let pixel = y
            .checked_mul(self.stride)
            .and_then(|row| row.checked_add(x))
            .ok_or(SurfaceError::Overflow)?;
        let byte_offset = pixel.checked_mul(4).ok_or(SurfaceError::Overflow)?;
        let end = byte_offset.checked_add(4).ok_or(SurfaceError::Overflow)?;
        if end > self.byte_len {
            return Err(SurfaceError::Bounds);
        }
        let bytes = match self.pixel_format {
            FramebufferPixelFormat::Rgb => [color.red, color.green, color.blue, 0],
            FramebufferPixelFormat::Bgr => [color.blue, color.green, color.red, 0],
        };
        Ok(EncodedFramebufferPixel { byte_offset, bytes })
    }
}

/// Minimal owned pixel surface required by the text renderer.
pub trait PixelSurface {
    /// Surface width and height in pixels.
    fn dimensions(&self) -> (usize, usize);

    /// Write one pixel after validating its coordinates.
    ///
    /// # Errors
    ///
    /// Returns a typed surface failure without writing outside the surface.
    fn write_pixel(&mut self, x: usize, y: usize, color: Color) -> Result<(), SurfaceError>;

    /// Move the top `height` pixel rows up by `distance` and clear the band the
    /// move vacates, across the full surface width.
    ///
    /// A text console scrolls by one cell row for every line past the bottom of
    /// the screen. Redrawing every glyph instead costs one `write_pixel` per
    /// pixel of the whole grid, which on a framebuffer is four volatile byte
    /// writes each; a surface that can move its own memory in bulk does the
    /// same work in a handful of wide copies.
    ///
    /// A `distance` of zero leaves the surface untouched. A `distance` at least
    /// as large as `height` erases the whole band rather than failing, because
    /// scrolling everything off the top is a defined outcome and not an error.
    ///
    /// # Errors
    ///
    /// Returns [`SurfaceError::Unsupported`] when the surface cannot move
    /// pixels, which asks the caller to redraw the affected rows instead.
    /// Returns a typed failure without addressing outside the surface.
    fn scroll_up(
        &mut self,
        height: usize,
        distance: usize,
        background: Color,
    ) -> Result<(), SurfaceError> {
        let _ = (height, distance, background);
        Err(SurfaceError::Unsupported)
    }

    /// Fill a checked rectangle.
    ///
    /// # Errors
    ///
    /// Returns a typed surface failure without addressing outside the surface.
    fn fill_rect(
        &mut self,
        x: usize,
        y: usize,
        width: usize,
        height: usize,
        color: Color,
    ) -> Result<(), SurfaceError> {
        let (surface_width, surface_height) = self.dimensions();
        let end_x = x.checked_add(width).ok_or(SurfaceError::Overflow)?;
        let end_y = y.checked_add(height).ok_or(SurfaceError::Overflow)?;
        if end_x > surface_width || end_y > surface_height {
            return Err(SurfaceError::Bounds);
        }
        for row in y..end_y {
            for column in x..end_x {
                self.write_pixel(column, row, color)?;
            }
        }
        Ok(())
    }
}

/// Text-console construction failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TextConsoleError {
    /// The surface is too small for one glyph cell.
    SurfaceTooSmall,
    /// The configured retained-cell budget is smaller than the derived grid.
    CellCapacityExceeded,
    /// Checked grid arithmetic overflowed.
    Overflow,
    /// Initial surface clearing failed.
    Surface(SurfaceError),
}

impl From<SurfaceError> for TextConsoleError {
    fn from(error: SurfaceError) -> Self {
        Self::Surface(error)
    }
}

const GLYPH_WIDTH: usize = 5;
const GLYPH_HEIGHT: usize = 7;
const CELL_WIDTH: usize = GLYPH_WIDTH + 1;
const CELL_HEIGHT: usize = GLYPH_HEIGHT + 1;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum OutputState {
    Ground,
    Escape {
        bytes: usize,
    },
    Csi {
        bytes: usize,
        parameter: u16,
        has_parameter: bool,
        unsupported: bool,
    },
    Discard,
}

/// Bounded cell-grid terminal rendered onto an owned pixel surface.
#[derive(Debug)]
pub struct TextConsole<S> {
    surface: S,
    config: TextConsoleConfig,
    columns: usize,
    rows: usize,
    cells: Vec<char>,
    column: usize,
    row: usize,
    output_state: OutputState,
    utf8: [u8; 4],
    utf8_len: usize,
    utf8_expected: usize,
}

impl<S: PixelSurface> TextConsole<S> {
    /// Construct and clear a text console over a validated surface.
    ///
    /// # Errors
    ///
    /// Fails if the surface cannot hold one cell, grid arithmetic overflows,
    /// the selected cell budget is too small, or initial clearing fails.
    pub fn new(mut surface: S, config: TextConsoleConfig) -> Result<Self, TextConsoleError> {
        let (width, height) = surface.dimensions();
        let columns = width / CELL_WIDTH;
        let rows = height / CELL_HEIGHT;
        if columns == 0 || rows == 0 {
            return Err(TextConsoleError::SurfaceTooSmall);
        }
        let cell_count = columns
            .checked_mul(rows)
            .ok_or(TextConsoleError::Overflow)?;
        if cell_count > config.max_cells() {
            return Err(TextConsoleError::CellCapacityExceeded);
        }
        surface.fill_rect(0, 0, width, height, config.background())?;
        let mut console = Self {
            surface,
            config,
            columns,
            rows,
            cells: vec![' '; cell_count],
            column: 0,
            row: 0,
            output_state: OutputState::Ground,
            utf8: [0; 4],
            utf8_len: 0,
            utf8_expected: 0,
        };
        console.draw_cursor().map_err(TextConsoleError::Surface)?;
        Ok(console)
    }

    /// Derived text-grid dimensions.
    #[must_use]
    pub const fn grid_dimensions(&self) -> (usize, usize) {
        (self.columns, self.rows)
    }

    /// Current cursor position as column and row.
    #[must_use]
    pub const fn cursor_position(&self) -> (usize, usize) {
        (self.column, self.row)
    }

    /// Character retained in one cell.
    #[must_use]
    pub fn cell(&self, column: usize, row: usize) -> Option<char> {
        let index = row.checked_mul(self.columns)?.checked_add(column)?;
        self.cells.get(index).copied()
    }

    /// Borrow the underlying surface.
    #[must_use]
    pub const fn surface(&self) -> &S {
        &self.surface
    }

    /// Consume the console and recover its surface.
    #[must_use]
    pub fn into_surface(self) -> S {
        self.surface
    }

    fn push_byte(&mut self, byte: u8) -> Result<(), SurfaceError> {
        match self.output_state {
            OutputState::Ground => self.push_ground(byte),
            OutputState::Escape { bytes } => {
                self.push_escape(byte, bytes);
                Ok(())
            }
            OutputState::Csi {
                bytes,
                parameter,
                has_parameter,
                unsupported,
            } => self.push_csi(byte, bytes, parameter, has_parameter, unsupported),
            OutputState::Discard => {
                self.push_output_discard(byte);
                Ok(())
            }
        }
    }

    fn push_ground(&mut self, byte: u8) -> Result<(), SurfaceError> {
        match byte {
            b'\n' => self.newline(),
            b'\r' => self.move_column(0),
            b'\x08' => self.move_column(self.column.saturating_sub(1)),
            b'\t' => self.tab(),
            b'\x1b' => {
                self.output_state = OutputState::Escape { bytes: 1 };
                Ok(())
            }
            0x20..=0x7e => self.put_character(char::from(byte)),
            0x80..=0xff => self.push_output_utf8(byte),
            _ => Ok(()),
        }
    }

    fn push_escape(&mut self, byte: u8, bytes: usize) {
        let bytes = bytes.saturating_add(1);
        if bytes > self.config.max_escape_bytes() {
            self.output_state = OutputState::Discard;
        } else if byte == b'[' {
            self.output_state = OutputState::Csi {
                bytes,
                parameter: 0,
                has_parameter: false,
                unsupported: false,
            };
        } else {
            self.output_state = OutputState::Ground;
        }
    }

    fn push_csi(
        &mut self,
        byte: u8,
        bytes: usize,
        mut parameter: u16,
        mut has_parameter: bool,
        mut unsupported: bool,
    ) -> Result<(), SurfaceError> {
        let bytes = bytes.saturating_add(1);
        if bytes > self.config.max_escape_bytes() {
            self.output_state = OutputState::Discard;
            return Ok(());
        }
        if byte.is_ascii_digit() && !unsupported {
            parameter = parameter
                .saturating_mul(10)
                .saturating_add(u16::from(byte - b'0'));
            has_parameter = true;
            self.output_state = OutputState::Csi {
                bytes,
                parameter,
                has_parameter,
                unsupported,
            };
            return Ok(());
        }
        if (0x20..=0x3f).contains(&byte) {
            unsupported = true;
            self.output_state = OutputState::Csi {
                bytes,
                parameter,
                has_parameter,
                unsupported,
            };
            return Ok(());
        }
        if (0x40..=0x7e).contains(&byte) {
            self.output_state = OutputState::Ground;
            if unsupported {
                return Ok(());
            }
            let count = usize::from(if has_parameter { parameter.max(1) } else { 1 });
            return match (byte, has_parameter.then_some(parameter)) {
                (b'J', Some(2)) => self.clear(),
                (b'H', _) => self.move_cursor(0, 0),
                (b'K', None | Some(0)) => self.erase_to_end(),
                (b'D', _) => self.move_column(self.column.saturating_sub(count)),
                (b'C', _) => self.move_column((self.column + count).min(self.columns - 1)),
                (b'A', _) => self.move_row(self.row.saturating_sub(count)),
                (b'B', _) => self.move_row((self.row + count).min(self.rows - 1)),
                _ => Ok(()),
            };
        }
        self.output_state = OutputState::Discard;
        Ok(())
    }

    fn push_output_discard(&mut self, byte: u8) {
        if (0x40..=0x7e).contains(&byte) {
            self.output_state = OutputState::Ground;
        }
    }

    fn push_output_utf8(&mut self, byte: u8) -> Result<(), SurfaceError> {
        if self.utf8_len == 0 {
            self.utf8_expected = match byte {
                0xc2..=0xdf => 2,
                0xe0..=0xef => 3,
                0xf0..=0xf4 => 4,
                _ => return self.put_character('\u{fffd}'),
            };
        } else if !(0x80..=0xbf).contains(&byte) {
            self.reset_output_utf8();
            return self.put_character('\u{fffd}');
        }
        self.utf8[self.utf8_len] = byte;
        self.utf8_len += 1;
        if self.utf8_len < self.utf8_expected {
            return Ok(());
        }
        let character = core::str::from_utf8(&self.utf8[..self.utf8_len])
            .ok()
            .and_then(|text| text.chars().next())
            .unwrap_or('\u{fffd}');
        self.reset_output_utf8();
        self.put_character(character)
    }

    const fn reset_output_utf8(&mut self) {
        self.utf8_len = 0;
        self.utf8_expected = 0;
    }

    fn put_character(&mut self, character: char) -> Result<(), SurfaceError> {
        self.erase_cursor()?;
        let index = self.row * self.columns + self.column;
        self.cells[index] = character;
        self.draw_cell(self.column, self.row)?;
        self.column += 1;
        if self.column == self.columns {
            self.column = 0;
            self.row += 1;
            if self.row == self.rows {
                self.scroll()?;
            }
        }
        self.draw_cursor()
    }

    fn tab(&mut self) -> Result<(), SurfaceError> {
        let stop = ((self.column / self.config.tab_width()) + 1) * self.config.tab_width();
        let spaces = stop.saturating_sub(self.column).max(1);
        for _ in 0..spaces {
            self.put_character(' ')?;
        }
        Ok(())
    }

    fn newline(&mut self) -> Result<(), SurfaceError> {
        self.erase_cursor()?;
        self.column = 0;
        self.row += 1;
        if self.row == self.rows {
            self.scroll()?;
        }
        self.draw_cursor()
    }

    fn scroll(&mut self) -> Result<(), SurfaceError> {
        self.cells.copy_within(self.columns.., 0);
        let last_row = (self.rows - 1) * self.columns;
        self.cells[last_row..].fill(' ');
        self.row = self.rows - 1;
        // Only the cell grid moves. A surface taller than `rows * CELL_HEIGHT`
        // keeps the remainder band untouched, exactly as a redraw would.
        match self.surface.scroll_up(
            self.rows * CELL_HEIGHT,
            CELL_HEIGHT,
            self.config.background(),
        ) {
            Ok(()) => Ok(()),
            Err(SurfaceError::Unsupported) => self.redraw_all(),
            Err(error) => Err(error),
        }
    }

    fn clear(&mut self) -> Result<(), SurfaceError> {
        let (width, height) = self.surface.dimensions();
        self.surface
            .fill_rect(0, 0, width, height, self.config.background())?;
        self.cells.fill(' ');
        self.column = 0;
        self.row = 0;
        self.draw_cursor()
    }

    fn erase_to_end(&mut self) -> Result<(), SurfaceError> {
        self.erase_cursor()?;
        for column in self.column..self.columns {
            let index = self.row * self.columns + column;
            self.cells[index] = ' ';
            self.draw_cell(column, self.row)?;
        }
        self.draw_cursor()
    }

    fn move_cursor(&mut self, column: usize, row: usize) -> Result<(), SurfaceError> {
        self.erase_cursor()?;
        self.column = column.min(self.columns - 1);
        self.row = row.min(self.rows - 1);
        self.draw_cursor()
    }

    fn move_column(&mut self, column: usize) -> Result<(), SurfaceError> {
        self.move_cursor(column, self.row)
    }

    fn move_row(&mut self, row: usize) -> Result<(), SurfaceError> {
        self.move_cursor(self.column, row)
    }

    fn redraw_all(&mut self) -> Result<(), SurfaceError> {
        for row in 0..self.rows {
            for column in 0..self.columns {
                self.draw_cell(column, row)?;
            }
        }
        Ok(())
    }

    fn erase_cursor(&mut self) -> Result<(), SurfaceError> {
        self.draw_cell(self.column, self.row)
    }

    fn draw_cursor(&mut self) -> Result<(), SurfaceError> {
        let x = self.column * CELL_WIDTH;
        let y = self.row * CELL_HEIGHT + GLYPH_HEIGHT;
        self.surface
            .fill_rect(x, y, GLYPH_WIDTH, 1, self.config.foreground())
    }

    fn draw_cell(&mut self, column: usize, row: usize) -> Result<(), SurfaceError> {
        let x = column * CELL_WIDTH;
        let y = row * CELL_HEIGHT;
        self.surface
            .fill_rect(x, y, CELL_WIDTH, CELL_HEIGHT, self.config.background())?;
        let character = self.cells[row * self.columns + column];
        let glyph = glyph_rows(character);
        for (glyph_y, bits) in glyph.into_iter().enumerate() {
            for glyph_x in 0..GLYPH_WIDTH {
                if bits & (1 << (GLYPH_WIDTH - 1 - glyph_x)) != 0 {
                    self.surface
                        .write_pixel(x + glyph_x, y + glyph_y, self.config.foreground())?;
                }
            }
        }
        Ok(())
    }
}

impl<S: PixelSurface> Output for TextConsole<S> {
    fn write(&mut self, bytes: &[u8]) -> Result<usize, StreamError> {
        for byte in bytes {
            self.push_byte(*byte).map_err(|_| StreamError::Device)?;
        }
        Ok(bytes.len())
    }
}

fn glyph_rows(character: char) -> [u8; GLYPH_HEIGHT] {
    let character = character.to_ascii_uppercase();
    match character {
        'A' => [0x0e, 0x11, 0x11, 0x1f, 0x11, 0x11, 0x11],
        'B' => [0x1e, 0x11, 0x11, 0x1e, 0x11, 0x11, 0x1e],
        'C' => [0x0e, 0x11, 0x10, 0x10, 0x10, 0x11, 0x0e],
        'D' => [0x1e, 0x11, 0x11, 0x11, 0x11, 0x11, 0x1e],
        'E' => [0x1f, 0x10, 0x10, 0x1e, 0x10, 0x10, 0x1f],
        'F' => [0x1f, 0x10, 0x10, 0x1e, 0x10, 0x10, 0x10],
        'G' => [0x0e, 0x11, 0x10, 0x17, 0x11, 0x11, 0x0f],
        'H' => [0x11, 0x11, 0x11, 0x1f, 0x11, 0x11, 0x11],
        'I' => [0x0e, 0x04, 0x04, 0x04, 0x04, 0x04, 0x0e],
        'J' => [0x07, 0x02, 0x02, 0x02, 0x12, 0x12, 0x0c],
        'K' => [0x11, 0x12, 0x14, 0x18, 0x14, 0x12, 0x11],
        'L' => [0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x1f],
        'M' => [0x11, 0x1b, 0x15, 0x15, 0x11, 0x11, 0x11],
        'N' => [0x11, 0x19, 0x15, 0x13, 0x11, 0x11, 0x11],
        'O' => [0x0e, 0x11, 0x11, 0x11, 0x11, 0x11, 0x0e],
        'P' => [0x1e, 0x11, 0x11, 0x1e, 0x10, 0x10, 0x10],
        'Q' => [0x0e, 0x11, 0x11, 0x11, 0x15, 0x12, 0x0d],
        'R' => [0x1e, 0x11, 0x11, 0x1e, 0x14, 0x12, 0x11],
        'S' => [0x0f, 0x10, 0x10, 0x0e, 0x01, 0x01, 0x1e],
        'T' => [0x1f, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04],
        'U' => [0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x0e],
        'V' => [0x11, 0x11, 0x11, 0x11, 0x11, 0x0a, 0x04],
        'W' => [0x11, 0x11, 0x11, 0x15, 0x15, 0x15, 0x0a],
        'X' => [0x11, 0x11, 0x0a, 0x04, 0x0a, 0x11, 0x11],
        'Y' => [0x11, 0x11, 0x0a, 0x04, 0x04, 0x04, 0x04],
        'Z' => [0x1f, 0x01, 0x02, 0x04, 0x08, 0x10, 0x1f],
        '0' => [0x0e, 0x11, 0x13, 0x15, 0x19, 0x11, 0x0e],
        '1' => [0x04, 0x0c, 0x14, 0x04, 0x04, 0x04, 0x1f],
        '2' => [0x0e, 0x11, 0x01, 0x02, 0x04, 0x08, 0x1f],
        '3' => [0x1e, 0x01, 0x01, 0x0e, 0x01, 0x01, 0x1e],
        '4' => [0x02, 0x06, 0x0a, 0x12, 0x1f, 0x02, 0x02],
        '5' => [0x1f, 0x10, 0x10, 0x1e, 0x01, 0x01, 0x1e],
        '6' => [0x0e, 0x10, 0x10, 0x1e, 0x11, 0x11, 0x0e],
        '7' => [0x1f, 0x01, 0x02, 0x04, 0x08, 0x08, 0x08],
        '8' => [0x0e, 0x11, 0x11, 0x0e, 0x11, 0x11, 0x0e],
        '9' => [0x0e, 0x11, 0x11, 0x0f, 0x01, 0x01, 0x0e],
        '/' => [0x01, 0x02, 0x02, 0x04, 0x08, 0x08, 0x10],
        '\\' => [0x10, 0x08, 0x08, 0x04, 0x02, 0x02, 0x01],
        ':' => [0, 0x04, 0x04, 0, 0x04, 0x04, 0],
        ';' => [0, 0x04, 0x04, 0, 0x04, 0x04, 0x08],
        '.' => [0, 0, 0, 0, 0, 0x0c, 0x0c],
        ',' => [0, 0, 0, 0, 0x0c, 0x0c, 0x08],
        '-' => [0, 0, 0, 0x1f, 0, 0, 0],
        '_' => [0, 0, 0, 0, 0, 0, 0x1f],
        '>' => [0x10, 0x08, 0x04, 0x02, 0x04, 0x08, 0x10],
        '<' => [0x01, 0x02, 0x04, 0x08, 0x04, 0x02, 0x01],
        '=' => [0, 0, 0x1f, 0, 0x1f, 0, 0],
        '+' => [0, 0x04, 0x04, 0x1f, 0x04, 0x04, 0],
        '*' => [0, 0x11, 0x0a, 0x1f, 0x0a, 0x11, 0],
        '!' => [0x04, 0x04, 0x04, 0x04, 0x04, 0, 0x04],
        '?' => [0x0e, 0x11, 0x01, 0x02, 0x04, 0, 0x04],
        '[' => [0x0e, 0x08, 0x08, 0x08, 0x08, 0x08, 0x0e],
        ']' => [0x0e, 0x02, 0x02, 0x02, 0x02, 0x02, 0x0e],
        '(' => [0x02, 0x04, 0x08, 0x08, 0x08, 0x04, 0x02],
        ')' => [0x08, 0x04, 0x02, 0x02, 0x02, 0x04, 0x08],
        '|' => [0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04],
        '\'' => [0x04, 0x04, 0x08, 0, 0, 0, 0],
        '"' => [0x0a, 0x0a, 0x14, 0, 0, 0, 0],
        '#' => [0x0a, 0x1f, 0x0a, 0x0a, 0x1f, 0x0a, 0],
        '%' => [0x19, 0x19, 0x02, 0x04, 0x08, 0x13, 0x13],
        '&' => [0x0c, 0x12, 0x14, 0x08, 0x15, 0x12, 0x0d],
        '@' => [0x0e, 0x11, 0x17, 0x15, 0x17, 0x10, 0x0e],
        '$' => [0x04, 0x0f, 0x14, 0x0e, 0x05, 0x1e, 0x04],
        '^' => [0x04, 0x0a, 0x11, 0, 0, 0, 0],
        '~' => [0, 0, 0x09, 0x16, 0, 0, 0],
        ' ' => [0; GLYPH_HEIGHT],
        _ => [0x1f, 0x11, 0x01, 0x02, 0x04, 0, 0x04],
    }
}

#[cfg(test)]
mod tests {
    use super::{
        Color, ConfigError, EditorConfig, EditorOutcome, FramebufferDescriptor,
        FramebufferDescriptorError, FramebufferPixelFormat, HistoryConfig, InputConfig,
        InputDecoder, KeyEvent, KeyboardConfig, LineEditor, PixelSurface, Ps2Set1Decoder,
        SurfaceError, TextConsole, TextConsoleConfig, TextConsoleError,
    };
    use alloc::vec;
    use alloc::vec::Vec;
    use troe_core::{Output, write_all};

    #[derive(Debug)]
    struct MemorySurface {
        width: usize,
        height: usize,
        pixels: Vec<Color>,
        writes: usize,
    }

    impl MemorySurface {
        fn new(width: usize, height: usize) -> Self {
            Self {
                width,
                height,
                pixels: vec![Color::new(0, 0, 0); width * height],
                writes: 0,
            }
        }
    }

    impl PixelSurface for MemorySurface {
        fn dimensions(&self) -> (usize, usize) {
            (self.width, self.height)
        }

        fn write_pixel(&mut self, x: usize, y: usize, color: Color) -> Result<(), SurfaceError> {
            if x >= self.width || y >= self.height {
                return Err(SurfaceError::Bounds);
            }
            self.writes += 1;
            self.pixels[y * self.width + x] = color;
            Ok(())
        }

        fn scroll_up(
            &mut self,
            height: usize,
            distance: usize,
            background: Color,
        ) -> Result<(), SurfaceError> {
            if distance == 0 {
                return Ok(());
            }
            if height > self.height {
                return Err(SurfaceError::Bounds);
            }
            let moved_rows = height.saturating_sub(distance);
            if moved_rows != 0 {
                self.pixels
                    .copy_within(distance * self.width..height * self.width, 0);
            }
            for row in moved_rows..height {
                for column in 0..self.width {
                    self.pixels[row * self.width + column] = background;
                }
            }
            Ok(())
        }
    }

    /// A surface that cannot move its own pixels, so the console must redraw.
    struct RedrawOnlySurface(MemorySurface);

    /// Feed identical text through both scroll paths and compare every pixel.
    ///
    /// The bulk move is only a valid optimization if it is indistinguishable
    /// from redrawing the grid, so the test compares the rendered surfaces
    /// rather than asserting the move happened.
    #[test]
    fn a_bulk_scroll_renders_exactly_what_a_redraw_would() {
        const WIDTH: usize = 60;
        const HEIGHT: usize = 40;
        // Enough lines to scroll the grid several times over.
        let text = b"the quick brown fox 0123\njumps over 456\nlazy dogs +-*=\n\n                     wrapping a much longer line than the grid is wide\n789\n";

        let mut moved = TextConsole::new(
            MemorySurface::new(WIDTH, HEIGHT),
            TextConsoleConfig::standard(),
        )
        .unwrap_or_else(|_| std::process::abort());
        let mut redrawn = TextConsole::new(
            RedrawOnlySurface(MemorySurface::new(WIDTH, HEIGHT)),
            TextConsoleConfig::standard(),
        )
        .unwrap_or_else(|_| std::process::abort());
        for _ in 0..6 {
            for byte in text {
                moved
                    .push_byte(*byte)
                    .unwrap_or_else(|_| std::process::abort());
                redrawn
                    .push_byte(*byte)
                    .unwrap_or_else(|_| std::process::abort());
            }
        }

        let moved_surface = moved.into_surface();
        let redrawn_surface = redrawn.into_surface().0;
        assert_eq!(
            moved_surface.pixels, redrawn_surface.pixels,
            "bulk scroll and redraw must be pixel-identical"
        );
        // The point of the move is cost. Redrawing writes at least one pixel
        // per cell of the whole grid on every scrolled line; the move writes
        // only the band it clears.
        assert!(
            moved_surface.writes * 4 < redrawn_surface.writes,
            "expected the bulk move to cut pixel writes several-fold, got {} against {}",
            moved_surface.writes,
            redrawn_surface.writes
        );
    }

    /// A move at least as tall as the band is an erase, not a failure, and a
    /// zero move leaves the surface untouched.
    #[test]
    fn degenerate_scroll_distances_are_defined() {
        let mut surface = MemorySurface::new(8, 4);
        let ink = Color::new(9, 9, 9);
        for y in 0..4 {
            for x in 0..8 {
                surface
                    .write_pixel(x, y, ink)
                    .unwrap_or_else(|_| std::process::abort());
            }
        }
        let background = Color::new(0, 0, 0);
        surface
            .scroll_up(4, 0, background)
            .unwrap_or_else(|_| std::process::abort());
        assert!(surface.pixels.iter().all(|pixel| *pixel == ink));
        surface
            .scroll_up(4, 9, background)
            .unwrap_or_else(|_| std::process::abort());
        assert!(surface.pixels.iter().all(|pixel| *pixel == background));
        assert_eq!(
            surface.scroll_up(5, 1, background),
            Err(SurfaceError::Bounds)
        );
    }

    impl PixelSurface for RedrawOnlySurface {
        fn dimensions(&self) -> (usize, usize) {
            self.0.dimensions()
        }

        fn write_pixel(&mut self, x: usize, y: usize, color: Color) -> Result<(), SurfaceError> {
            self.0.write_pixel(x, y, color)
        }
    }

    fn config(max_line_bytes: usize, entries: usize, bytes: usize) -> EditorConfig {
        let history =
            HistoryConfig::new(entries, bytes).unwrap_or_else(|_| HistoryConfig::disabled());
        EditorConfig::new(max_line_bytes, history, InputConfig::standard())
            .unwrap_or_else(|_| EditorConfig::standard())
    }

    #[test]
    fn configuration_rejects_inconsistent_or_empty_limits() {
        assert_eq!(
            HistoryConfig::new(1, 0),
            Err(ConfigError::InconsistentHistoryCapacity)
        );
        assert_eq!(
            InputConfig::new(1),
            Err(ConfigError::EscapeCapacityTooSmall)
        );
        assert_eq!(
            EditorConfig::new(0, HistoryConfig::disabled(), InputConfig::standard()),
            Err(ConfigError::EmptyLineCapacity)
        );
    }

    #[test]
    fn decoder_normalizes_keys_utf8_and_crlf() {
        let mut decoder = InputDecoder::new(InputConfig::standard());
        assert_eq!(decoder.push(b'\r'), Some(KeyEvent::Enter));
        assert_eq!(decoder.push(b'\n'), None);
        assert_eq!(decoder.push(0xc3), None);
        assert_eq!(decoder.push(0xa9), Some(KeyEvent::Character('é')));
        assert_eq!(decoder.push(0x08), Some(KeyEvent::Backspace));
        assert_eq!(decoder.push(0x7f), Some(KeyEvent::Backspace));
    }

    #[test]
    fn decoders_report_end_of_input_without_disturbing_the_editor() {
        let mut decoder = InputDecoder::new(InputConfig::standard());
        assert_eq!(decoder.push(0x04), Some(KeyEvent::EndOfInput));
        assert_eq!(decoder.push(0x03), Some(KeyEvent::Cancel));

        let mut keyboard = Ps2Set1Decoder::new(KeyboardConfig::standard());
        assert_eq!(keyboard.push(0x1d), None);
        assert_eq!(keyboard.push(0x20), Some(KeyEvent::EndOfInput));
        assert_eq!(keyboard.push(0x9d), None);
        assert_eq!(keyboard.push(0x20), Some(KeyEvent::Character('d')));

        let mut editor = LineEditor::new(EditorConfig::standard());
        assert_eq!(
            editor.handle(KeyEvent::Character('a')),
            EditorOutcome::Changed
        );
        assert_eq!(editor.handle(KeyEvent::EndOfInput), EditorOutcome::Ignored);
        assert_eq!(editor.line(), "a");
    }

    #[test]
    fn decoder_recognizes_navigation_and_discards_unknown_sequences() {
        let mut decoder = InputDecoder::new(InputConfig::standard());
        assert_eq!(decoder.push(0x1b), None);
        assert_eq!(decoder.push(b'['), None);
        assert_eq!(decoder.push(b'A'), Some(KeyEvent::Up));
        assert_eq!(decoder.push(0x1b), None);
        assert_eq!(decoder.push(b'['), None);
        assert_eq!(decoder.push(b'9'), None);
        assert_eq!(decoder.push(b'9'), None);
        assert_eq!(decoder.push(b'~'), None);
        assert_eq!(decoder.push(b'x'), Some(KeyEvent::Character('x')));

        let input = InputConfig::new(4).unwrap_or_else(|_| InputConfig::standard());
        let mut bounded = InputDecoder::new(input);
        for byte in b"\x1b[123456~" {
            assert_eq!(bounded.push(*byte), None);
        }
        assert_eq!(bounded.push(b'y'), Some(KeyEvent::Character('y')));
    }

    #[test]
    fn ps2_decoder_maps_modifiers_navigation_and_control_editing() {
        let mut decoder = Ps2Set1Decoder::new(KeyboardConfig::standard());
        assert_eq!(decoder.push(0x1e), Some(KeyEvent::Character('a')));
        assert_eq!(decoder.push(0x2a), None);
        assert_eq!(decoder.push(0x1e), Some(KeyEvent::Character('A')));
        assert_eq!(decoder.push(0xaa), None);
        assert_eq!(decoder.push(0xe0), None);
        assert_eq!(decoder.push(0x48), Some(KeyEvent::Up));
        assert_eq!(decoder.push(0x1d), None);
        assert_eq!(decoder.push(0x2e), Some(KeyEvent::Cancel));
        assert_eq!(decoder.push(0x9d), None);
    }

    #[test]
    fn editor_inserts_and_deletes_at_utf8_boundaries() {
        let mut editor = LineEditor::new(config(16, 4, 32));
        assert_eq!(
            editor.handle(KeyEvent::Character('a')),
            EditorOutcome::Changed
        );
        assert_eq!(
            editor.handle(KeyEvent::Character('é')),
            EditorOutcome::Changed
        );
        assert_eq!(
            editor.handle(KeyEvent::Character('c')),
            EditorOutcome::Changed
        );
        assert_eq!(editor.handle(KeyEvent::Left), EditorOutcome::Changed);
        assert_eq!(editor.handle(KeyEvent::Backspace), EditorOutcome::Changed);
        assert_eq!(editor.line(), "ac");
        assert_eq!(editor.cursor(), 1);
        assert_eq!(editor.handle(KeyEvent::Delete), EditorOutcome::Changed);
        assert_eq!(editor.line(), "a");
    }

    #[test]
    fn configured_line_capacity_is_atomic() {
        let mut editor = LineEditor::new(config(2, 4, 32));
        assert_eq!(
            editor.handle(KeyEvent::Character('é')),
            EditorOutcome::Changed
        );
        assert_eq!(
            editor.handle(KeyEvent::Character('x')),
            EditorOutcome::LimitReached
        );
        assert_eq!(editor.line(), "é");
    }

    #[test]
    fn history_evicts_by_both_configured_limits_and_restores_scratch() {
        let mut editor = LineEditor::new(config(32, 2, 7));
        for line in ["one", "two", "three"] {
            for character in line.chars() {
                let _outcome = editor.handle(KeyEvent::Character(character));
            }
            let _outcome = editor.handle(KeyEvent::Enter);
        }
        assert_eq!(editor.history_len(), 1);
        assert_eq!(editor.history_bytes(), 5);
        let _outcome = editor.handle(KeyEvent::Character('x'));
        assert_eq!(editor.handle(KeyEvent::Up), EditorOutcome::Changed);
        assert_eq!(editor.line(), "three");
        assert_eq!(editor.handle(KeyEvent::Down), EditorOutcome::Changed);
        assert_eq!(editor.line(), "x");
    }

    #[test]
    fn history_can_be_disabled() {
        let mut editor = LineEditor::new(config(8, 0, 0));
        let _outcome = editor.handle(KeyEvent::Character('x'));
        let _outcome = editor.handle(KeyEvent::Enter);
        assert_eq!(editor.history_len(), 0);
        assert_eq!(editor.handle(KeyEvent::Up), EditorOutcome::Ignored);
    }

    #[test]
    fn completion_replacement_obeys_line_capacity() {
        let mut editor = LineEditor::new(config(5, 0, 0));
        for character in "ca".chars() {
            let _outcome = editor.handle(KeyEvent::Character(character));
        }
        assert_eq!(editor.replace_range(0, 2, "cat "), EditorOutcome::Changed);
        assert_eq!(
            editor.replace_range(0, 4, "hexdump"),
            EditorOutcome::LimitReached
        );
        assert_eq!(editor.line(), "cat ");
    }

    #[test]
    fn text_console_configuration_and_grid_are_bounded() {
        let colors = (Color::new(1, 2, 3), Color::new(4, 5, 6));
        assert_eq!(
            TextConsoleConfig::new(0, 8, 4, colors.0, colors.1),
            Err(ConfigError::EmptyCellCapacity)
        );
        let limited = TextConsoleConfig::new(1, 8, 4, colors.0, colors.1)
            .unwrap_or_else(|_| TextConsoleConfig::standard());
        assert!(matches!(
            TextConsole::new(MemorySurface::new(24, 16), limited),
            Err(TextConsoleError::CellCapacityExceeded)
        ));
    }

    #[test]
    fn framebuffer_descriptor_checks_geometry_and_address_range() {
        assert_eq!(
            FramebufferDescriptor::new(0x1000, 64, 4, 4, 4, FramebufferPixelFormat::Rgb)
                .map(FramebufferDescriptor::byte_len),
            Ok(64)
        );
        assert_eq!(
            FramebufferDescriptor::new(0x1000, 63, 4, 4, 4, FramebufferPixelFormat::Bgr),
            Err(FramebufferDescriptorError::TooSmall)
        );
        assert_eq!(
            FramebufferDescriptor::new(0x1000, 64, 5, 4, 4, FramebufferPixelFormat::Rgb),
            Err(FramebufferDescriptorError::InvalidStride)
        );
    }

    #[test]
    fn framebuffer_pixel_encoding_checks_format_stride_and_extent() {
        let color = Color::new(0x12, 0x34, 0x56);
        let rgb = FramebufferDescriptor::new(0x1000, 32, 2, 2, 4, FramebufferPixelFormat::Rgb)
            .unwrap_or_else(|_| std::process::abort());
        let first = rgb
            .encode_pixel(0, 0, color)
            .unwrap_or_else(|_| std::process::abort());
        assert_eq!(first.byte_offset(), 0);
        assert_eq!(first.bytes(), [0x12, 0x34, 0x56, 0]);

        let last_visible = rgb
            .encode_pixel(1, 1, color)
            .unwrap_or_else(|_| std::process::abort());
        assert_eq!(last_visible.byte_offset(), 20);

        let bgr = FramebufferDescriptor::new(0x1000, 32, 4, 2, 4, FramebufferPixelFormat::Bgr)
            .unwrap_or_else(|_| std::process::abort());
        let last_mapped = bgr
            .encode_pixel(3, 1, color)
            .unwrap_or_else(|_| std::process::abort());
        assert_eq!(last_mapped.byte_offset(), 28);
        assert_eq!(last_mapped.bytes(), [0x56, 0x34, 0x12, 0]);

        assert_eq!(rgb.encode_pixel(2, 0, color), Err(SurfaceError::Bounds));
        assert_eq!(rgb.encode_pixel(0, 2, color), Err(SurfaceError::Bounds));

        let malformed = FramebufferDescriptor {
            base_address: 0x1000,
            byte_len: usize::MAX,
            width: 2,
            height: 2,
            stride: usize::MAX,
            pixel_format: FramebufferPixelFormat::Rgb,
        };
        assert_eq!(
            malformed.encode_pixel(1, 1, color),
            Err(SurfaceError::Overflow)
        );
    }

    #[test]
    fn text_console_renders_controls_and_scrolls_retained_cells() {
        let surface = MemorySurface::new(24, 16);
        let mut console = TextConsole::new(surface, TextConsoleConfig::standard())
            .unwrap_or_else(|_| std::process::abort());
        assert_eq!(console.grid_dimensions(), (4, 2));
        assert_eq!(write_all(&mut console, b"AB\nCD\nE"), Ok(()));
        assert_eq!(console.cell(0, 0), Some('C'));
        assert_eq!(console.cell(1, 0), Some('D'));
        assert_eq!(console.cell(0, 1), Some('E'));
        assert_eq!(write_all(&mut console, b"\x1b[2J\x1b[H"), Ok(()));
        assert_eq!(console.cursor_position(), (0, 0));
        assert_eq!(console.cell(0, 0), Some(' '));
    }

    #[test]
    fn text_console_renders_invalid_utf8_as_replacement_character() {
        let surface = MemorySurface::new(12, 8);
        let mut console = TextConsole::new(surface, TextConsoleConfig::standard())
            .unwrap_or_else(|_| std::process::abort());

        assert_eq!(write_all(&mut console, &[0xff]), Ok(()));
        assert_eq!(console.cell(0, 0), Some('\u{fffd}'));
    }

    #[test]
    fn text_console_satisfies_partial_output_contract() {
        let surface = MemorySurface::new(12, 8);
        let mut console = TextConsole::new(surface, TextConsoleConfig::standard())
            .unwrap_or_else(|_| std::process::abort());
        assert_eq!(Output::write(&mut console, b"x"), Ok(1));
    }

    #[test]
    fn text_console_discards_overlong_control_sequences_atomically() {
        let policy =
            TextConsoleConfig::new(4, 4, 8, Color::new(255, 255, 255), Color::new(0, 0, 0))
                .unwrap_or_else(|_| TextConsoleConfig::standard());
        let mut console = TextConsole::new(MemorySurface::new(12, 8), policy)
            .unwrap_or_else(|_| std::process::abort());

        assert_eq!(write_all(&mut console, b"\x1b[123456~Z"), Ok(()));
        assert_eq!(console.cell(0, 0), Some('Z'));
        assert_eq!(console.cell(1, 0), Some(' '));
    }
}
