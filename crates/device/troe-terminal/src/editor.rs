//! Bounded line editing over decoded keys, with volatile history.

use alloc::collections::VecDeque;
use alloc::string::String;
use core::mem;

use troe_core::MAX_LINE_BYTES;

use crate::decode::InputConfig;
use crate::{ConfigError, KeyEvent};

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
