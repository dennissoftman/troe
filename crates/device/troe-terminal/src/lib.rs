//! Configurable bounded terminal input decoding and line editing.
#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;

mod decode;
mod editor;
mod scancode;
#[cfg(test)]
mod tests;

pub use crate::decode::{InputConfig, InputDecoder};
pub use crate::editor::{EditorConfig, EditorOutcome, HistoryConfig, LineEditor};
pub use crate::scancode::{KeyboardConfig, KeyboardLayout, Ps2Set1Decoder};

/// Invalid input or editor resource policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConfigError {
    /// Editable lines must accept at least one byte.
    EmptyLineCapacity,
    /// History entry and byte capacities must both be zero or both be non-zero.
    InconsistentHistoryCapacity,
    /// An escape sequence must allow at least its introducer and final byte.
    EscapeCapacityTooSmall,
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
