//! Bounded cell-grid text rendering onto a pixel surface.

use alloc::vec;
use alloc::vec::Vec;

use troe_core::{Output, StreamError};

use crate::ConfigError;
use crate::framebuffer::{Color, PixelSurface, SurfaceError};

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

    pub(crate) fn push_byte(&mut self, byte: u8) -> Result<(), SurfaceError> {
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
