#![no_std]

#[cfg(test)]
extern crate std;

/// Byte-oriented counts reported by `wc`.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Counts {
    /// Newline bytes seen in the input.
    pub lines: u64,
    /// ASCII-whitespace-delimited words seen in the input.
    pub words: u64,
    /// Bytes seen in the input.
    pub bytes: u64,
    in_word: bool,
}

impl Counts {
    /// Incorporate one input chunk.
    pub fn feed(&mut self, input: &[u8]) {
        self.bytes = self.bytes.saturating_add(input.len() as u64);
        for byte in input {
            if *byte == b'\n' {
                self.lines = self.lines.saturating_add(1);
            }
            if byte.is_ascii_whitespace() {
                self.in_word = false;
            } else if !self.in_word {
                self.words = self.words.saturating_add(1);
                self.in_word = true;
            }
        }
    }

    /// Add finalized counts, as used for the multi-file total.
    pub fn add(&mut self, other: Self) {
        self.lines = self.lines.saturating_add(other.lines);
        self.words = self.words.saturating_add(other.words);
        self.bytes = self.bytes.saturating_add(other.bytes);
        self.in_word = false;
    }
}

#[cfg(test)]
mod tests {
    use super::Counts;

    #[test]
    fn counts_across_partial_chunks() {
        let mut counts = Counts::default();
        counts.feed(b"alpha be");
        counts.feed(b"ta\n\tgamma");
        assert_eq!(
            counts,
            Counts {
                lines: 1,
                words: 3,
                bytes: 17,
                in_word: true,
            }
        );
    }

    #[test]
    fn empty_and_unterminated_inputs_follow_wc_byte_rules() {
        let mut empty = Counts::default();
        empty.feed(b"");
        assert_eq!(empty.lines, 0);
        assert_eq!(empty.words, 0);

        let mut one = Counts::default();
        one.feed(b"word");
        assert_eq!((one.lines, one.words, one.bytes), (0, 1, 4));
    }
}
