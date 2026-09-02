use super::{
    Color, ConfigError, FramebufferDescriptor, FramebufferDescriptorError, FramebufferPixelFormat,
    PixelSurface, SurfaceError, TextConsole, TextConsoleConfig, TextConsoleError,
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

impl PixelSurface for RedrawOnlySurface {
    fn dimensions(&self) -> (usize, usize) {
        self.0.dimensions()
    }

    fn write_pixel(&mut self, x: usize, y: usize, color: Color) -> Result<(), SurfaceError> {
        self.0.write_pixel(x, y, color)
    }
}

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
    let policy = TextConsoleConfig::new(4, 4, 8, Color::new(255, 255, 255), Color::new(0, 0, 0))
        .unwrap_or_else(|_| TextConsoleConfig::standard());
    let mut console = TextConsole::new(MemorySurface::new(12, 8), policy)
        .unwrap_or_else(|_| std::process::abort());

    assert_eq!(write_all(&mut console, b"\x1b[123456~Z"), Ok(()));
    assert_eq!(console.cell(0, 0), Some('Z'));
    assert_eq!(console.cell(1, 0), Some(' '));
}
