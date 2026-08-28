//! Locale-independent ASCII classification for freestanding C consumers.
#![allow(unsafe_code)]

fn ascii(value: i32) -> Option<u8> {
    u8::try_from(value).ok().filter(u8::is_ascii)
}

macro_rules! classifier {
    ($bridge:ident, $symbol:literal, $predicate:expr) => {
        #[doc = concat!("C ABI implementation of `", $symbol, "` for the C locale.")]
        #[must_use]
        #[unsafe(export_name = $symbol)]
        pub extern "C" fn $bridge(value: i32) -> i32 {
            i32::from(ascii(value).is_some_and($predicate))
        }
    };
}

classifier!(troe_c_isdigit, "isdigit", |value: u8| value
    .is_ascii_digit());
classifier!(troe_c_islower, "islower", |value: u8| value
    .is_ascii_lowercase());
classifier!(troe_c_isupper, "isupper", |value: u8| value
    .is_ascii_uppercase());
classifier!(troe_c_isalpha, "isalpha", |value: u8| value
    .is_ascii_alphabetic());
classifier!(troe_c_isalnum, "isalnum", |value: u8| value
    .is_ascii_alphanumeric());
classifier!(troe_c_iscntrl, "iscntrl", |value: u8| value
    .is_ascii_control());
classifier!(troe_c_isprint, "isprint", |value: u8| matches!(
    value,
    0x20..=0x7e
));
classifier!(troe_c_isgraph, "isgraph", |value: u8| matches!(
    value,
    0x21..=0x7e
));
classifier!(troe_c_isspace, "isspace", |value: u8| value
    .is_ascii_whitespace());
classifier!(troe_c_isxdigit, "isxdigit", |value: u8| value
    .is_ascii_hexdigit());
classifier!(troe_c_ispunct, "ispunct", |value: u8| value
    .is_ascii_punctuation());

/// C ABI implementation of `tolower` for the C locale.
#[unsafe(export_name = "tolower")]
#[must_use]
pub extern "C" fn troe_c_tolower(value: i32) -> i32 {
    ascii(value).map_or(value, |byte| i32::from(byte.to_ascii_lowercase()))
}

/// C ABI implementation of `toupper` for the C locale.
#[unsafe(export_name = "toupper")]
#[must_use]
pub extern "C" fn troe_c_toupper(value: i32) -> i32 {
    ascii(value).map_or(value, |byte| i32::from(byte.to_ascii_uppercase()))
}

/// C ABI implementation of `abs`.
#[unsafe(export_name = "abs")]
#[must_use]
pub extern "C" fn troe_c_abs(value: i32) -> i32 {
    if value < 0 {
        value.wrapping_neg()
    } else {
        value
    }
}

#[cfg(test)]
mod tests {
    use super::{troe_c_isalpha, troe_c_isspace, troe_c_tolower};

    #[test]
    fn c_locale_classification_rejects_non_ascii_values() {
        assert_eq!(troe_c_isalpha(i32::from(b'A')), 1);
        assert_eq!(troe_c_isspace(i32::from(b'\n')), 1);
        assert_eq!(troe_c_isalpha(0x100), 0);
        assert_eq!(troe_c_tolower(i32::from(b'A')), i32::from(b'a'));
    }
}
