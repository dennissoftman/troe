use super::{
    ConfigError, EditorConfig, EditorOutcome, HistoryConfig, InputConfig, InputDecoder, KeyEvent,
    KeyboardConfig, LineEditor, Ps2Set1Decoder,
};

fn config(max_line_bytes: usize, entries: usize, bytes: usize) -> EditorConfig {
    let history = HistoryConfig::new(entries, bytes).unwrap_or_else(|_| HistoryConfig::disabled());
    EditorConfig::new(max_line_bytes, history, InputConfig::standard())
        .unwrap_or_else(|_| EditorConfig::standard())
}

#[test]
fn configuration_rejects_inconsistent_or_empty_limits() {
    assert_eq!(
        HistoryConfig::new(1, 0),
        Err(ConfigError::InconsistentHistoryCapacity)
    );
    assert_eq!(
        InputConfig::new(1),
        Err(ConfigError::EscapeCapacityTooSmall)
    );
    assert_eq!(
        EditorConfig::new(0, HistoryConfig::disabled(), InputConfig::standard()),
        Err(ConfigError::EmptyLineCapacity)
    );
}

#[test]
fn decoder_normalizes_keys_utf8_and_crlf() {
    let mut decoder = InputDecoder::new(InputConfig::standard());
    assert_eq!(decoder.push(b'\r'), Some(KeyEvent::Enter));
    assert_eq!(decoder.push(b'\n'), None);
    assert_eq!(decoder.push(0xc3), None);
    assert_eq!(decoder.push(0xa9), Some(KeyEvent::Character('é')));
    assert_eq!(decoder.push(0x08), Some(KeyEvent::Backspace));
    assert_eq!(decoder.push(0x7f), Some(KeyEvent::Backspace));
}

#[test]
fn decoders_report_end_of_input_without_disturbing_the_editor() {
    let mut decoder = InputDecoder::new(InputConfig::standard());
    assert_eq!(decoder.push(0x04), Some(KeyEvent::EndOfInput));
    assert_eq!(decoder.push(0x03), Some(KeyEvent::Cancel));

    let mut keyboard = Ps2Set1Decoder::new(KeyboardConfig::standard());
    assert_eq!(keyboard.push(0x1d), None);
    assert_eq!(keyboard.push(0x20), Some(KeyEvent::EndOfInput));
    assert_eq!(keyboard.push(0x9d), None);
    assert_eq!(keyboard.push(0x20), Some(KeyEvent::Character('d')));

    let mut editor = LineEditor::new(EditorConfig::standard());
    assert_eq!(
        editor.handle(KeyEvent::Character('a')),
        EditorOutcome::Changed
    );
    assert_eq!(editor.handle(KeyEvent::EndOfInput), EditorOutcome::Ignored);
    assert_eq!(editor.line(), "a");
}

#[test]
fn decoder_recognizes_navigation_and_discards_unknown_sequences() {
    let mut decoder = InputDecoder::new(InputConfig::standard());
    assert_eq!(decoder.push(0x1b), None);
    assert_eq!(decoder.push(b'['), None);
    assert_eq!(decoder.push(b'A'), Some(KeyEvent::Up));
    assert_eq!(decoder.push(0x1b), None);
    assert_eq!(decoder.push(b'['), None);
    assert_eq!(decoder.push(b'9'), None);
    assert_eq!(decoder.push(b'9'), None);
    assert_eq!(decoder.push(b'~'), None);
    assert_eq!(decoder.push(b'x'), Some(KeyEvent::Character('x')));

    let input = InputConfig::new(4).unwrap_or_else(|_| InputConfig::standard());
    let mut bounded = InputDecoder::new(input);
    for byte in b"\x1b[123456~" {
        assert_eq!(bounded.push(*byte), None);
    }
    assert_eq!(bounded.push(b'y'), Some(KeyEvent::Character('y')));
}

#[test]
fn ps2_decoder_maps_modifiers_navigation_and_control_editing() {
    let mut decoder = Ps2Set1Decoder::new(KeyboardConfig::standard());
    assert_eq!(decoder.push(0x1e), Some(KeyEvent::Character('a')));
    assert_eq!(decoder.push(0x2a), None);
    assert_eq!(decoder.push(0x1e), Some(KeyEvent::Character('A')));
    assert_eq!(decoder.push(0xaa), None);
    assert_eq!(decoder.push(0xe0), None);
    assert_eq!(decoder.push(0x48), Some(KeyEvent::Up));
    assert_eq!(decoder.push(0x1d), None);
    assert_eq!(decoder.push(0x2e), Some(KeyEvent::Cancel));
    assert_eq!(decoder.push(0x9d), None);
}

#[test]
fn editor_inserts_and_deletes_at_utf8_boundaries() {
    let mut editor = LineEditor::new(config(16, 4, 32));
    assert_eq!(
        editor.handle(KeyEvent::Character('a')),
        EditorOutcome::Changed
    );
    assert_eq!(
        editor.handle(KeyEvent::Character('é')),
        EditorOutcome::Changed
    );
    assert_eq!(
        editor.handle(KeyEvent::Character('c')),
        EditorOutcome::Changed
    );
    assert_eq!(editor.handle(KeyEvent::Left), EditorOutcome::Changed);
    assert_eq!(editor.handle(KeyEvent::Backspace), EditorOutcome::Changed);
    assert_eq!(editor.line(), "ac");
    assert_eq!(editor.cursor(), 1);
    assert_eq!(editor.handle(KeyEvent::Delete), EditorOutcome::Changed);
    assert_eq!(editor.line(), "a");
}

#[test]
fn configured_line_capacity_is_atomic() {
    let mut editor = LineEditor::new(config(2, 4, 32));
    assert_eq!(
        editor.handle(KeyEvent::Character('é')),
        EditorOutcome::Changed
    );
    assert_eq!(
        editor.handle(KeyEvent::Character('x')),
        EditorOutcome::LimitReached
    );
    assert_eq!(editor.line(), "é");
}

#[test]
fn history_evicts_by_both_configured_limits_and_restores_scratch() {
    let mut editor = LineEditor::new(config(32, 2, 7));
    for line in ["one", "two", "three"] {
        for character in line.chars() {
            let _outcome = editor.handle(KeyEvent::Character(character));
        }
        let _outcome = editor.handle(KeyEvent::Enter);
    }
    assert_eq!(editor.history_len(), 1);
    assert_eq!(editor.history_bytes(), 5);
    let _outcome = editor.handle(KeyEvent::Character('x'));
    assert_eq!(editor.handle(KeyEvent::Up), EditorOutcome::Changed);
    assert_eq!(editor.line(), "three");
    assert_eq!(editor.handle(KeyEvent::Down), EditorOutcome::Changed);
    assert_eq!(editor.line(), "x");
}

#[test]
fn history_can_be_disabled() {
    let mut editor = LineEditor::new(config(8, 0, 0));
    let _outcome = editor.handle(KeyEvent::Character('x'));
    let _outcome = editor.handle(KeyEvent::Enter);
    assert_eq!(editor.history_len(), 0);
    assert_eq!(editor.handle(KeyEvent::Up), EditorOutcome::Ignored);
}

#[test]
fn completion_replacement_obeys_line_capacity() {
    let mut editor = LineEditor::new(config(5, 0, 0));
    for character in "ca".chars() {
        let _outcome = editor.handle(KeyEvent::Character(character));
    }
    assert_eq!(editor.replace_range(0, 2, "cat "), EditorOutcome::Changed);
    assert_eq!(
        editor.replace_range(0, 4, "hexdump"),
        EditorOutcome::LimitReached
    );
    assert_eq!(editor.line(), "cat ");
}
