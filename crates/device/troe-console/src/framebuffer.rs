//! Physical framebuffer metadata, pixel encoding, and the pixel surface.

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
    pub(crate) base_address: u64,
    pub(crate) byte_len: usize,
    pub(crate) width: usize,
    pub(crate) height: usize,
    pub(crate) stride: usize,
    pub(crate) pixel_format: FramebufferPixelFormat,
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
