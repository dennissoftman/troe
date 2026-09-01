//! Incremental UTF-8 and ANSI decoding of a byte-stream console.

use crate::{ConfigError, KeyEvent};

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
