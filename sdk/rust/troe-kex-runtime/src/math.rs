//! Freestanding numeric helpers used by C-compatible language runtimes.
#![allow(unsafe_code)]

/// Parse one complete UTF-8 decimal token.
#[must_use]
pub fn parse_decimal(text: &str) -> Option<f64> {
    text.parse::<f64>().ok()
}

/// Parse the longest leading decimal token using the C `strtod` grammar.
///
/// The returned byte count includes leading ASCII whitespace. Hexadecimal,
/// infinity, and NaN spellings are deliberately outside this first profile.
#[must_use]
pub fn parse_decimal_prefix(text: &str) -> Option<(f64, usize)> {
    let bytes = text.as_bytes();
    let mut start = 0_usize;
    while bytes.get(start).is_some_and(u8::is_ascii_whitespace) {
        start += 1;
    }
    let mut cursor = start;
    if bytes
        .get(cursor)
        .is_some_and(|byte| matches!(*byte, b'+' | b'-'))
    {
        cursor += 1;
    }
    let mut digits = 0_usize;
    while bytes.get(cursor).is_some_and(u8::is_ascii_digit) {
        digits += 1;
        cursor += 1;
    }
    if bytes.get(cursor) == Some(&b'.') {
        cursor += 1;
        while bytes.get(cursor).is_some_and(u8::is_ascii_digit) {
            digits += 1;
            cursor += 1;
        }
    }
    if digits == 0 {
        return None;
    }
    let exponent = cursor;
    if bytes
        .get(cursor)
        .is_some_and(|byte| matches!(*byte, b'e' | b'E'))
    {
        cursor += 1;
        if bytes
            .get(cursor)
            .is_some_and(|byte| matches!(*byte, b'+' | b'-'))
        {
            cursor += 1;
        }
        let exponent_digits = cursor;
        while bytes.get(cursor).is_some_and(u8::is_ascii_digit) {
            cursor += 1;
        }
        if cursor == exponent_digits {
            cursor = exponent;
        }
    }
    parse_decimal(&text[start..cursor]).map(|value| (value, cursor))
}

/// Decimal prefix returned to the minimal C compatibility core.
#[derive(Clone, Copy, Debug, PartialEq)]
#[repr(C)]
pub struct DecimalResult {
    /// Zero on success.
    pub status: i32,
    /// Bytes consumed from the original input.
    pub consumed: usize,
    /// Parsed value when `status` is zero.
    pub value: f64,
}

/// Fraction and exponent returned by [`frexp`].
#[derive(Clone, Copy, Debug, PartialEq)]
#[repr(C)]
pub struct FrexpResult {
    /// Fraction bits.
    pub fraction_bits: u64,
    /// Binary exponent.
    pub exponent: i32,
}

macro_rules! unary_math {
    ($bridge:ident, $name:ident) => {
        #[doc = concat!("C ABI bit bridge for `", stringify!($name), "`.")]
        #[must_use]
        #[unsafe(no_mangle)]
        pub extern "C" fn $bridge(value_bits: u64) -> u64 {
            libm::$name(f64::from_bits(value_bits)).to_bits()
        }
    };
}

unary_math!(troe_math_acos_bits, acos);
unary_math!(troe_math_asin_bits, asin);
unary_math!(troe_math_atan_bits, atan);
unary_math!(troe_math_ceil_bits, ceil);
unary_math!(troe_math_cos_bits, cos);
unary_math!(troe_math_exp_bits, exp);
unary_math!(troe_math_fabs_bits, fabs);
unary_math!(troe_math_floor_bits, floor);
unary_math!(troe_math_log_bits, log);
unary_math!(troe_math_log10_bits, log10);
unary_math!(troe_math_sin_bits, sin);
unary_math!(troe_math_sqrt_bits, sqrt);
unary_math!(troe_math_tan_bits, tan);

/// C ABI bit bridge for `atan2`.
#[must_use]
#[unsafe(no_mangle)]
pub extern "C" fn troe_math_atan2_bits(y_bits: u64, x_bits: u64) -> u64 {
    libm::atan2(f64::from_bits(y_bits), f64::from_bits(x_bits)).to_bits()
}

/// C ABI bit bridge for `fmod`.
#[must_use]
#[unsafe(no_mangle)]
pub extern "C" fn troe_math_fmod_bits(x_bits: u64, y_bits: u64) -> u64 {
    libm::fmod(f64::from_bits(x_bits), f64::from_bits(y_bits)).to_bits()
}

/// C ABI bit bridge for `frexp` without an output pointer.
#[unsafe(no_mangle)]
#[must_use]
pub extern "C" fn troe_math_frexp_bits(value_bits: u64) -> FrexpResult {
    let (fraction, exponent) = libm::frexp(f64::from_bits(value_bits));
    FrexpResult {
        fraction_bits: fraction.to_bits(),
        exponent,
    }
}

/// C ABI bit bridge for `ldexp`.
#[must_use]
#[unsafe(no_mangle)]
pub extern "C" fn troe_math_ldexp_bits(value_bits: u64, exponent: i32) -> u64 {
    libm::ldexp(f64::from_bits(value_bits), exponent).to_bits()
}

/// C ABI bit bridge for `pow`.
#[must_use]
#[unsafe(no_mangle)]
pub extern "C" fn troe_math_pow_bits(x_bits: u64, y_bits: u64) -> u64 {
    libm::pow(f64::from_bits(x_bits), f64::from_bits(y_bits)).to_bits()
}

#[cfg(test)]
mod tests {
    use super::parse_decimal_prefix;

    #[test]
    fn decimal_prefix_is_bounded_and_does_not_consume_bad_exponents() {
        assert_eq!(parse_decimal_prefix("  -12.5e2tail"), Some((-1250.0, 9)));
        assert_eq!(parse_decimal_prefix("1e+tail"), Some((1.0, 1)));
        assert_eq!(parse_decimal_prefix("  .tail"), None);
    }
}
