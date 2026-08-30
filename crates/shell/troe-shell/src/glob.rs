//! Bounded pathname-pattern matching for one path component.
//!
//! Patterns are matched one `/`-separated component at a time, so `*` can
//! never cross a component boundary. Each character carries whether it was
//! written inside quotes; a quoted metacharacter is matched literally, which is
//! what makes `rm "*.txt"` name one file while `rm *.txt` names a set.

use alloc::string::String;
use alloc::vec::Vec;

/// One pattern character and whether quoting made it literal.
pub type Unit = (char, bool);

/// Whether one component holds an active metacharacter.
#[must_use]
pub fn is_pattern(component: &[Unit]) -> bool {
    component
        .iter()
        .any(|(character, literal)| !literal && matches!(character, '*' | '?' | '['))
}

/// Longest leading run of characters that match themselves.
///
/// Used as the directory-listing name prefix so a scan is pruned before the
/// matcher runs, never to decide a match.
#[must_use]
pub fn literal_prefix(component: &[Unit]) -> String {
    let mut prefix = String::new();
    for (character, literal) in component {
        if !literal && matches!(character, '*' | '?' | '[') {
            break;
        }
        prefix.push(*character);
    }
    prefix
}

/// Split one word into `/`-separated components.
///
/// `/` separates components regardless of quoting: quoting suppresses pattern
/// matching, not path structure.
#[must_use]
pub fn components(units: &[Unit]) -> Vec<&[Unit]> {
    let mut parts = Vec::new();
    let mut start = 0_usize;
    for (index, (character, _)) in units.iter().enumerate() {
        if *character == '/' {
            parts.push(&units[start..index]);
            start = index + 1;
        }
    }
    parts.push(&units[start..]);
    parts
}

/// Whether one component pattern matches one directory entry name.
///
/// A name beginning with `.` matches only a pattern beginning with a literal
/// `.`, so an unanchored `*` never selects a hidden entry.
#[must_use]
pub fn matches(pattern: &[Unit], name: &str) -> bool {
    if name.starts_with('.') && !starts_with_literal_dot(pattern) {
        return false;
    }
    let mut pattern_index = 0_usize;
    let mut name_offset = 0_usize;
    let mut backtrack: Option<(usize, usize)> = None;
    loop {
        if pattern_index == pattern.len() && name_offset == name.len() {
            return true;
        }
        if let Some(step) = advance(pattern, pattern_index, name, name_offset) {
            match step {
                Step::Star => {
                    backtrack = Some((pattern_index, name_offset));
                    pattern_index += 1;
                    continue;
                }
                Step::Consumed {
                    pattern_index: next_pattern,
                    name_offset: next_name,
                } => {
                    pattern_index = next_pattern;
                    name_offset = next_name;
                    continue;
                }
            }
        }
        let Some((star_index, star_offset)) = backtrack else {
            return false;
        };
        let Some(character) = name[star_offset..].chars().next() else {
            return false;
        };
        let resumed = star_offset + character.len_utf8();
        backtrack = Some((star_index, resumed));
        pattern_index = star_index + 1;
        name_offset = resumed;
    }
}

enum Step {
    Star,
    Consumed {
        pattern_index: usize,
        name_offset: usize,
    },
}

/// Try to consume one pattern element against the remaining name.
fn advance(pattern: &[Unit], pattern_index: usize, name: &str, name_offset: usize) -> Option<Step> {
    let (character, literal) = *pattern.get(pattern_index)?;
    if !literal {
        match character {
            '*' => return Some(Step::Star),
            '?' => {
                let next = name[name_offset..].chars().next()?;
                return Some(Step::Consumed {
                    pattern_index: pattern_index + 1,
                    name_offset: name_offset + next.len_utf8(),
                });
            }
            '[' => {
                if let Some(end) = class_end(pattern, pattern_index) {
                    let next = name[name_offset..].chars().next()?;
                    return class_matches(&pattern[pattern_index + 1..end], next).then_some(
                        Step::Consumed {
                            pattern_index: end + 1,
                            name_offset: name_offset + next.len_utf8(),
                        },
                    );
                }
            }
            _ => {}
        }
    }
    let next = name[name_offset..].chars().next()?;
    (next == character).then_some(Step::Consumed {
        pattern_index: pattern_index + 1,
        name_offset: name_offset + next.len_utf8(),
    })
}

/// Index of the unquoted `]` closing a well-formed class opened at `start`.
///
/// An unterminated or empty `[` is not a class and is matched literally.
fn class_end(pattern: &[Unit], start: usize) -> Option<usize> {
    let mut index = start + 1;
    if matches!(pattern.get(index), Some(('!' | '^', false))) {
        index += 1;
    }
    if matches!(pattern.get(index), Some((']', false))) {
        index += 1;
    }
    while index < pattern.len() {
        if pattern[index] == (']', false) {
            return (index > start + 1).then_some(index);
        }
        index += 1;
    }
    None
}

/// Whether one character satisfies the body of a bracket class.
fn class_matches(body: &[Unit], value: char) -> bool {
    let (negated, body) = match body.first() {
        Some(('!' | '^', false)) => (true, &body[1..]),
        _ => (false, body),
    };
    let mut index = 0_usize;
    let mut found = false;
    while index < body.len() {
        let (low, _) = body[index];
        let is_range = matches!(body.get(index + 1), Some(('-', false)))
            && body.get(index + 2).is_some()
            && !matches!(body.get(index + 2), Some((']', false)));
        if is_range {
            let (high, _) = body[index + 2];
            if low <= value && value <= high {
                found = true;
            }
            index += 3;
        } else {
            if low == value {
                found = true;
            }
            index += 1;
        }
    }
    found != negated
}

/// Whether a pattern begins with a `.` that matches itself.
fn starts_with_literal_dot(pattern: &[Unit]) -> bool {
    matches!(pattern.first(), Some(('.', _)))
}

#[cfg(test)]
mod tests {
    use super::{Unit, components, is_pattern, literal_prefix, matches};
    use alloc::vec::Vec;

    /// Build one unquoted pattern.
    fn bare(value: &str) -> Vec<Unit> {
        value.chars().map(|character| (character, false)).collect()
    }

    /// Build one pattern whose bytes inside `"` are literal, `"` excluded.
    fn quoted(value: &str) -> Vec<Unit> {
        let mut units = Vec::new();
        let mut inside = false;
        for character in value.chars() {
            if character == '"' {
                inside = !inside;
                continue;
            }
            units.push((character, inside));
        }
        units
    }

    #[test]
    fn star_question_and_classes_match_one_component() {
        assert!(matches(&bare("*.txt"), "notes.txt"));
        assert!(matches(&bare("*.txt"), "a.txt"));
        assert!(!matches(&bare("*.txt"), "notes.md"));
        assert!(matches(&bare("note?.txt"), "notes.txt"));
        assert!(!matches(&bare("note?.txt"), "note.txt"));
        assert!(matches(&bare("[abc]ing"), "bing"));
        assert!(!matches(&bare("[abc]ing"), "ding"));
        assert!(matches(&bare("[a-c]ing"), "cing"));
        assert!(!matches(&bare("[a-c]ing"), "ding"));
        assert!(matches(&bare("[!a-c]ing"), "ding"));
        assert!(!matches(&bare("[^a-c]ing"), "aing"));
        assert!(matches(&bare("*"), "anything"));
        assert!(matches(&bare("a*b*c"), "aXbYc"));
        assert!(!matches(&bare("a*b*c"), "aXbYd"));
    }

    #[test]
    fn unanchored_wildcards_never_select_hidden_entries() {
        assert!(!matches(&bare("*"), ".profile"));
        assert!(!matches(&bare("?profile"), ".profile"));
        assert!(matches(&bare(".*"), ".profile"));
        assert!(matches(&bare(".prof*"), ".profile"));
    }

    #[test]
    fn quoted_metacharacters_match_themselves() {
        assert!(!is_pattern(&quoted("\"*.txt\"")));
        assert!(matches(&quoted("\"*.txt\""), "*.txt"));
        assert!(!matches(&quoted("\"*.txt\""), "notes.txt"));
        assert!(is_pattern(&quoted("\"a\"*")));
        assert!(matches(&quoted("\"a\"*"), "anything"));
        assert!(is_pattern(&quoted("\"*\"a*")));
        assert!(matches(&quoted("\"*\"a*"), "*anything"));
        assert!(!matches(&quoted("\"*\"a*"), "banything"));
    }

    #[test]
    fn unterminated_and_empty_classes_are_literal() {
        assert!(matches(&bare("a[bc"), "a[bc"));
        assert!(matches(&bare("a[]"), "a[]"));
        assert!(matches(&bare("[]]"), "]"));
    }

    #[test]
    fn literal_prefix_stops_at_the_first_active_metacharacter() {
        assert_eq!(literal_prefix(&bare("notes*.txt")), "notes");
        assert_eq!(literal_prefix(&bare("*.txt")), "");
        assert_eq!(literal_prefix(&quoted("\"*\"note*")), "*note");
        assert_eq!(literal_prefix(&bare("plain.txt")), "plain.txt");
    }

    #[test]
    fn components_split_on_every_separator_regardless_of_quoting() {
        let units = quoted("logs/\"*\"/x*");
        let parts = components(&units);
        assert_eq!(parts.len(), 3);
        assert!(!is_pattern(parts[1]));
        assert!(is_pattern(parts[2]));
        assert_eq!(components(&bare("/a")).len(), 2);
        assert!(components(&bare("/a"))[0].is_empty());
    }
}
