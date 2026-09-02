//! PC keyboard scan-code set 1 translation into decoded keys.

use core::mem;

use crate::KeyEvent;

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
