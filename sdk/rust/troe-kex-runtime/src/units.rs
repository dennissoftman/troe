//! Human-readable representations of byte quantities.

use core::fmt;

const LABELS: [&str; 7] = ["B", "KiB", "MiB", "GiB", "TiB", "PiB", "EiB"];
const MAX_FRACTION_DIGITS: u8 = 2;

/// A byte count rendered with 1024-based IEC units.
///
/// Values are rounded to the requested maximum precision and trailing zeroes
/// are omitted. The default retains at most two fractional digits.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HumanBytes {
    bytes: u64,
    maximum_fraction_digits: u8,
}

impl HumanBytes {
    /// Select a human-readable IEC representation for `bytes`.
    #[must_use]
    pub const fn new(bytes: u64) -> Self {
        Self {
            bytes,
            maximum_fraction_digits: MAX_FRACTION_DIGITS,
        }
    }

    /// Limit the number of fractional digits to zero, one, or two.
    ///
    /// Larger limits are clamped to two so formatting remains small and
    /// deterministic in `no_std` applications.
    #[must_use]
    pub const fn with_maximum_fraction_digits(mut self, digits: u8) -> Self {
        self.maximum_fraction_digits = if digits > MAX_FRACTION_DIGITS {
            MAX_FRACTION_DIGITS
        } else {
            digits
        };
        self
    }

    /// Number of terminal columns occupied by the formatted representation.
    #[must_use]
    pub fn display_width(self) -> usize {
        let parts = self.parts();
        decimal_width(parts.whole)
            + usize::from(parts.fraction_digits != 0) * (usize::from(parts.fraction_digits) + 1)
            + 1
            + LABELS[parts.unit].len()
    }

    fn parts(self) -> Parts {
        let mut unit = 0_usize;
        let mut divisor = 1_u64;
        while unit + 1 < LABELS.len() && self.bytes / divisor >= 1024 {
            divisor = divisor.saturating_mul(1024);
            unit += 1;
        }

        let scale = match self.maximum_fraction_digits {
            0 => 1_u128,
            1 => 10_u128,
            _ => 100_u128,
        };
        let mut scaled =
            (u128::from(self.bytes) * scale + u128::from(divisor / 2)) / u128::from(divisor);
        if scaled >= 1024 * scale && unit + 1 < LABELS.len() {
            divisor = divisor.saturating_mul(1024);
            unit += 1;
            scaled =
                (u128::from(self.bytes) * scale + u128::from(divisor / 2)) / u128::from(divisor);
        }

        let whole = u64::try_from(scaled / scale).unwrap_or(u64::MAX);
        let mut fraction = u64::try_from(scaled % scale).unwrap_or(0);
        let mut fraction_digits = self.maximum_fraction_digits;
        while fraction_digits != 0 && fraction.is_multiple_of(10) {
            fraction /= 10;
            fraction_digits -= 1;
        }
        Parts {
            whole,
            fraction,
            fraction_digits,
            unit,
        }
    }
}

impl fmt::Display for HumanBytes {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let parts = self.parts();
        write!(formatter, "{}", parts.whole)?;
        if parts.fraction_digits != 0 {
            write!(
                formatter,
                ".{:0width$}",
                parts.fraction,
                width = usize::from(parts.fraction_digits)
            )?;
        }
        write!(formatter, " {}", LABELS[parts.unit])
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Parts {
    whole: u64,
    fraction: u64,
    fraction_digits: u8,
    unit: usize,
}

fn decimal_width(mut value: u64) -> usize {
    let mut width = 1;
    while value >= 10 {
        value /= 10;
        width += 1;
    }
    width
}

#[cfg(test)]
mod tests {
    use super::HumanBytes;
    use std::{format, string::ToString};

    #[test]
    fn uses_iec_units_and_1024_boundaries() {
        assert_eq!(HumanBytes::new(0).to_string(), "0 B");
        assert_eq!(HumanBytes::new(1023).to_string(), "1023 B");
        assert_eq!(HumanBytes::new(1024).to_string(), "1 KiB");
        assert_eq!(HumanBytes::new(1024 * 1024).to_string(), "1 MiB");
        assert_eq!(HumanBytes::new(1024 * 1024 * 1024).to_string(), "1 GiB");
    }

    #[test]
    fn rounds_at_the_selected_precision_and_promotes_units() {
        assert_eq!(HumanBytes::new(1536).to_string(), "1.5 KiB");
        assert_eq!(HumanBytes::new(1280).to_string(), "1.25 KiB");
        assert_eq!(
            HumanBytes::new(1024 * 1024 - 1)
                .with_maximum_fraction_digits(1)
                .to_string(),
            "1 MiB"
        );
        assert_eq!(
            HumanBytes::new(u64::MAX)
                .with_maximum_fraction_digits(1)
                .to_string(),
            "16 EiB"
        );
    }

    #[test]
    fn display_width_matches_formatted_text() {
        for bytes in [0, 1023, 1024, 1536, 10 * 1024 * 1024, u64::MAX] {
            let value = HumanBytes::new(bytes).with_maximum_fraction_digits(1);
            assert_eq!(value.display_width(), format!("{value}").chars().count());
        }
    }
}
