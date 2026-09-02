//! The session terminal: input decoding, the cooked line discipline, and the
//! prompt line editor.
//!
//! One owner holds decoding for the whole machine. At the prompt the decoded
//! keys drive the line editor; while a foreground process holds the loan the
//! same keys instead fill a bounded cooked byte stream that the process reads
//! through its ordinary standard-input handle.

use crate::console::SharedConsoleOutput;
use crate::handles::{OwnedNamespace, SharedProcessTable, SharedRuntime};
use crate::limits::RESIDENT_POLL_MILLISECONDS;
use crate::machine::OwnedAccounting;
use crate::resident::ResidentProcessTable;
use crate::shell::NativeCompletionEnvironment;
use crate::supervision::ServiceRuntime;
use crate::support::write_all;
use alloc::collections::VecDeque;
use alloc::rc::Rc;
use alloc::string::String;
use core::cell::RefCell;
use core::fmt::Write as _;
use troe_core::{Input, MAX_LINE_BYTES, Output, StreamError};
use troe_driver::{InputEvent, InputSource};
use troe_shell::{CompletionConfig, CompletionEnvironment, Shell};
use troe_task::{Capabilities, Scheduler, TaskId};
use troe_terminal::{
    EditorOutcome, InputConfig, InputDecoder, KeyEvent, KeyboardConfig, LineEditor, Ps2Set1Decoder,
};

/// Reserved generation-checked identity for one session terminal read.
pub(crate) const SESSION_TERMINAL_WAIT_IDENTITY: u64 = u64::MAX;

/// Cooked bytes retained for a foreground reader before input is refused.
pub(crate) const SESSION_TERMINAL_READY_BYTES: usize = 4 * (MAX_LINE_BYTES + 1);

/// The single owner of session input decoding and the cooked line
/// discipline.
///
/// The line editor consumes decoded keys at the prompt. While one
/// foreground process holds the loan, the same decoders instead feed a
/// bounded cooked byte stream that the process reads through its ordinary
/// standard-input handle. Background jobs, services, staged script lines,
/// and owner-scoped children never hold the loan.
pub(crate) struct SessionTerminal {
    runtime: SharedRuntime,
    echo: SharedConsoleOutput,
    input_config: InputConfig,
    keyboard_config: KeyboardConfig,
    decoder: InputDecoder,
    keyboard: Ps2Set1Decoder,
    pending: String,
    ready: VecDeque<u8>,
    end_of_input: bool,
    owner: Option<TaskId>,
}

pub(crate) type SharedSessionTerminal = Rc<RefCell<SessionTerminal>>;

impl SessionTerminal {
    pub(crate) fn new(
        runtime: SharedRuntime,
        echo: SharedConsoleOutput,
        input_config: InputConfig,
        keyboard_config: KeyboardConfig,
    ) -> Result<Self, ()> {
        let mut pending = String::new();
        pending.try_reserve_exact(MAX_LINE_BYTES).map_err(|_| ())?;
        let mut ready = VecDeque::new();
        ready
            .try_reserve_exact(SESSION_TERMINAL_READY_BYTES)
            .map_err(|_| ())?;
        Ok(Self {
            runtime,
            echo,
            input_config,
            keyboard_config,
            decoder: InputDecoder::new(input_config),
            keyboard: Ps2Set1Decoder::new(keyboard_config),
            pending,
            ready,
            end_of_input: false,
            owner: None,
        })
    }

    /// Decode one machine event with the session-owned decoders.
    fn decode(&mut self, event: InputEvent) -> Option<KeyEvent> {
        match event.source() {
            InputSource::Serial => self.decoder.push(event.byte()),
            InputSource::Keyboard => self.keyboard.push(event.byte()),
        }
    }

    /// Lend the terminal to one foreground process.
    pub(crate) fn lend(&mut self, owner: TaskId) -> Result<(), ()> {
        if self.owner.is_some() {
            return Err(());
        }
        self.reset();
        self.owner = Some(owner);
        Ok(())
    }

    /// Return the loan and discard unread cooked input.
    pub(crate) fn release(&mut self) {
        self.owner = None;
        self.reset();
    }

    fn reset(&mut self) {
        self.pending.clear();
        self.ready.clear();
        self.end_of_input = false;
        self.decoder = InputDecoder::new(self.input_config);
        self.keyboard = Ps2Set1Decoder::new(self.keyboard_config);
    }

    /// Drain retained machine events into the cooked stream.
    ///
    /// Cancellation is intercepted before this point, so a cancelling key
    /// never reaches the line discipline.
    pub(crate) fn pump(&mut self) {
        if self.owner.is_none() {
            return;
        }
        loop {
            let event = match self.runtime.try_borrow_mut() {
                Ok(mut runtime) => runtime.take_input_event(),
                Err(_) => return,
            };
            let Some(event) = event else {
                return;
            };
            if let Some(key) = self.decode(event) {
                self.apply(key);
            }
        }
    }

    fn apply(&mut self, key: KeyEvent) {
        if self.end_of_input {
            return;
        }
        match key {
            KeyEvent::Character(character) => self.insert(character),
            KeyEvent::Enter => self.submit(),
            KeyEvent::Backspace => self.erase(),
            KeyEvent::KillBefore => {
                while !self.pending.is_empty() {
                    self.erase();
                }
            }
            KeyEvent::EndOfInput => {
                if self.pending.is_empty() {
                    self.end_of_input = true;
                } else {
                    self.publish(false);
                }
            }
            // The cooked discipline has no completion, history, or cursor
            // movement, so the editor keys those transports carry are
            // either taken literally or ignored.
            KeyEvent::Complete => self.insert('\t'),
            KeyEvent::Cancel
            | KeyEvent::Delete
            | KeyEvent::Left
            | KeyEvent::Right
            | KeyEvent::Home
            | KeyEvent::End
            | KeyEvent::Up
            | KeyEvent::Down
            | KeyEvent::ClearDisplay
            | KeyEvent::KillAfter
            | KeyEvent::DeletePreviousWord => {}
        }
    }

    fn insert(&mut self, character: char) {
        let width = character.len_utf8();
        if self.pending.len().saturating_add(width) > MAX_LINE_BYTES {
            return;
        }
        let mut encoded = [0_u8; 4];
        let text = character.encode_utf8(&mut encoded);
        if write_all(&mut self.echo, text.as_bytes()).is_err() {
            return;
        }
        self.pending.push(character);
    }

    fn erase(&mut self) {
        if self.pending.pop().is_none() {
            return;
        }
        let _echo = write_all(&mut self.echo, b"\x08 \x08");
    }

    fn submit(&mut self) {
        self.publish(true);
    }

    /// Move the pending line into the cooked stream when it fits.
    fn publish(&mut self, newline: bool) {
        let terminator = usize::from(newline);
        let required = self.pending.len().saturating_add(terminator);
        if self.ready.len().saturating_add(required) > SESSION_TERMINAL_READY_BYTES {
            return;
        }
        if newline && write_all(&mut self.echo, b"\n").is_err() {
            return;
        }
        for byte in self.pending.as_bytes() {
            self.ready.push_back(*byte);
        }
        if newline {
            self.ready.push_back(b'\n');
        }
        self.pending.clear();
    }

    /// Whether a read can complete without waiting.
    pub(crate) fn read_ready(&self) -> bool {
        !self.ready.is_empty() || self.end_of_input
    }

    /// Copy cooked bytes out of the stream. Zero means end of input.
    pub(crate) fn take(&mut self, destination: &mut [u8]) -> usize {
        let mut count = 0;
        while count < destination.len() {
            let Some(byte) = self.ready.pop_front() else {
                break;
            };
            destination[count] = byte;
            count += 1;
        }
        count
    }
}

/// Standard input bound to the session terminal loan.
///
/// Application reads are admitted through the deferred-call path, which
/// blocks without starving the event loop. This direct implementation
/// serves shell-owned consumers that read the same stream synchronously.
pub(crate) struct SessionTerminalInput {
    terminal: SharedSessionTerminal,
}

impl SessionTerminalInput {
    pub(crate) const fn new(terminal: SharedSessionTerminal) -> Self {
        Self { terminal }
    }
}

impl Input for SessionTerminalInput {
    fn read(&mut self, destination: &mut [u8]) -> Result<usize, StreamError> {
        loop {
            let runtime = {
                let mut terminal = self
                    .terminal
                    .try_borrow_mut()
                    .map_err(|_| StreamError::Device)?;
                terminal.pump();
                if terminal.read_ready() {
                    return Ok(terminal.take(destination));
                }
                terminal.runtime.clone()
            };
            if runtime.borrow_mut().checkpoint().is_err() {
                return Ok(0);
            }
            troe_machine::wait_for_runtime_event_timeout(RESIDENT_POLL_MILLISECONDS)
                .map_err(|_| StreamError::Device)?;
        }
    }

    fn is_terminal(&self) -> bool {
        true
    }
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn read_edited_line(
    editor: &mut LineEditor,
    terminal: &SharedSessionTerminal,
    namespace: &OwnedNamespace,
    shell: &mut Shell,
    runtime: &SharedRuntime,
    residents: &mut ResidentProcessTable,
    processes: &SharedProcessTable,
    services: &mut Option<ServiceRuntime>,
    scheduler: &mut Scheduler,
    accounting: &mut OwnedAccounting,
    shell_id: TaskId,
    shell_capabilities: Capabilities,
    completion_config: CompletionConfig,
    prompt: &str,
    console: &mut dyn Output,
) -> Result<String, ()> {
    loop {
        let key = loop {
            let event = loop {
                if let Some(event) = runtime.borrow_mut().poll_input_event() {
                    break event;
                }
                residents.pump(scheduler, accounting, shell_id, shell_capabilities)?;
                if let Some(services) = services.as_mut() {
                    services.drive(
                        namespace,
                        shell,
                        residents,
                        processes,
                        scheduler,
                        accounting,
                        shell_id,
                        shell_capabilities,
                        runtime,
                    )?;
                }
                let _event =
                    troe_machine::wait_for_runtime_event_timeout(RESIDENT_POLL_MILLISECONDS);
            };
            let key = terminal.try_borrow_mut().map_err(|_| ())?.decode(event);
            if let Some(key) = key {
                break key;
            }
        };
        match editor.handle(key) {
            EditorOutcome::Changed => match key {
                KeyEvent::Left => write_all(console, b"\x1b[D")?,
                KeyEvent::Right => write_all(console, b"\x1b[C")?,
                _ => redraw_editor(editor, prompt, console)?,
            },
            EditorOutcome::Submitted(line) => {
                write_all(console, b"\n")?;
                return Ok(line);
            }
            EditorOutcome::Cancelled => {
                write_all(console, b"^C\n")?;
                return Ok(String::new());
            }
            EditorOutcome::ClearRequested => {
                write_all(console, b"\x1b[2J\x1b[H")?;
                redraw_editor(editor, prompt, console)?;
            }
            EditorOutcome::CompletionRequested => {
                let mut environment = NativeCompletionEnvironment {
                    residents,
                    services: services.as_ref(),
                    volumes: &accounting.boot_mount_manifest,
                };
                complete_editor(
                    editor,
                    shell,
                    completion_config,
                    &mut environment,
                    prompt,
                    console,
                )?;
            }
            EditorOutcome::LimitReached => write_all(console, b"\x07")?,
            EditorOutcome::Ignored => {}
        }
    }
}

pub(crate) fn redraw_editor(
    editor: &LineEditor,
    prompt: &str,
    console: &mut dyn Output,
) -> Result<(), ()> {
    write_all(console, b"\r")?;
    write_all(console, prompt.as_bytes())?;
    write_all(console, editor.line().as_bytes())?;
    write_all(console, b"\x1b[K")?;
    let suffix_characters = editor.line()[editor.cursor()..].chars().count();
    if suffix_characters != 0 {
        let mut movement = String::new();
        write!(movement, "\x1b[{suffix_characters}D").map_err(|_| ())?;
        write_all(console, movement.as_bytes())?;
    }
    Ok(())
}

pub(crate) fn complete_editor(
    editor: &mut LineEditor,
    shell: &mut Shell,
    config: CompletionConfig,
    environment: &mut dyn CompletionEnvironment,
    prompt: &str,
    console: &mut dyn Output,
) -> Result<(), ()> {
    let completion =
        shell.complete_with_environment(editor.line(), editor.cursor(), config, environment);
    if completion.candidates.is_empty() {
        write_all(console, b"\x07")?;
        return Ok(());
    }
    let current = &editor.line()[completion.replacement_start..completion.replacement_end];
    let Some(replacement) = completion.common_replacement() else {
        return Ok(());
    };
    let can_apply = !completion.truncated
        && (completion.candidates.len() == 1 || replacement.len() > current.len());
    if can_apply {
        let _outcome = editor.replace_range(
            completion.replacement_start,
            completion.replacement_end,
            replacement,
        );
        return redraw_editor(editor, prompt, console);
    }

    write_all(console, b"\n")?;
    for candidate in &completion.candidates {
        write_all(console, candidate.display.as_bytes())?;
        write_all(console, b"\n")?;
    }
    if completion.truncated {
        write_all(
            console,
            b"... completion list truncated by standard limits\n",
        )?;
    }
    redraw_editor(editor, prompt, console)
}
