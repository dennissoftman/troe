//! Bounded direct-command parsing and child-process lifecycle helpers.

use troe_kex_sdk::{Error as KexError, Pipes, ProcessLauncher, command, pipe, process_launch};

/// Direct-command or child-lifecycle failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    /// The direct command was empty or malformed.
    InvalidCommand,
    /// A quote was not closed.
    UnclosedQuote,
    /// A trailing escape had no following byte.
    TrailingEscape,
    /// Shell syntax is unavailable to the direct-command profile.
    ShellSyntax,
    /// Argument bytes or entries exceeded the canonical command ABI.
    LimitExceeded,
    /// The typed KEX process or pipe service failed.
    Service(KexError),
}

impl From<KexError> for Error {
    fn from(error: KexError) -> Self {
        Self::Service(error)
    }
}

/// One parsed direct command borrowing caller-provided byte storage.
pub struct DirectCommand<'storage> {
    arguments: [&'storage str; command::MAX_ARGUMENTS],
    count: usize,
}

impl<'storage> DirectCommand<'storage> {
    /// Borrow argument zero and all following arguments.
    #[must_use]
    pub fn arguments(&self) -> &[&'storage str] {
        &self.arguments[..self.count]
    }
}

/// Parse one bounded direct command without shell expansion or operators.
///
/// Single and double quotes group bytes. Backslash escapes are accepted
/// outside single quotes. Shell operators, expansion, substitution, and
/// redirection are rejected deliberately.
///
/// # Errors
///
/// Reports malformed quoting/escaping, shell syntax, invalid UTF-8, or ABI
/// argument ceilings.
pub fn parse_direct_command<'storage>(
    source: &[u8],
    storage: &'storage mut [u8; command::MAX_ARGUMENT_BYTES],
    ranges: &mut [(usize, usize); command::MAX_ARGUMENTS],
) -> Result<DirectCommand<'storage>, Error> {
    let mut source_at = 0_usize;
    let mut storage_at = 0_usize;
    let mut count = 0_usize;
    while source_at < source.len() {
        while source.get(source_at).is_some_and(u8::is_ascii_whitespace) {
            source_at += 1;
        }
        if source_at == source.len() {
            break;
        }
        if count == ranges.len() {
            return Err(Error::LimitExceeded);
        }
        let start = storage_at;
        let mut quote = 0_u8;
        let mut token_present = false;
        while source_at < source.len() {
            let byte = source[source_at];
            if quote == 0 && byte.is_ascii_whitespace() {
                break;
            }
            if byte == b'\'' && quote != b'"' {
                token_present = true;
                quote = if quote == b'\'' { 0 } else { b'\'' };
                source_at += 1;
                continue;
            }
            if byte == b'"' && quote != b'\'' {
                token_present = true;
                quote = if quote == b'"' { 0 } else { b'"' };
                source_at += 1;
                continue;
            }
            if byte == b'\\' && quote != b'\'' {
                token_present = true;
                source_at += 1;
                if source_at == source.len() {
                    return Err(Error::TrailingEscape);
                }
                if storage_at == storage.len() {
                    return Err(Error::LimitExceeded);
                }
                storage[storage_at] = source[source_at];
                storage_at += 1;
                source_at += 1;
                continue;
            }
            if quote == 0 && b"|&;<>()$`".contains(&byte) {
                return Err(Error::ShellSyntax);
            }
            if storage_at == storage.len() {
                return Err(Error::LimitExceeded);
            }
            storage[storage_at] = byte;
            token_present = true;
            storage_at += 1;
            source_at += 1;
        }
        if quote != 0 {
            return Err(Error::UnclosedQuote);
        }
        if !token_present {
            return Err(Error::InvalidCommand);
        }
        ranges[count] = (start, storage_at);
        count += 1;
    }
    if count == 0 {
        return Err(Error::InvalidCommand);
    }
    let mut arguments = [""; command::MAX_ARGUMENTS];
    for (argument, (start, end)) in arguments[..count].iter_mut().zip(ranges[..count].iter()) {
        *argument =
            core::str::from_utf8(&storage[*start..*end]).map_err(|_| Error::InvalidCommand)?;
    }
    Ok(DirectCommand { arguments, count })
}

/// Spawn one parsed direct command with explicit standard streams.
///
/// # Errors
///
/// Reports parsing, launch encoding, authority, or service failures.
#[allow(clippy::too_many_arguments)]
pub fn spawn_direct(
    launcher: &mut ProcessLauncher,
    source: &[u8],
    cwd: &str,
    environment: &[&str],
    stdin: process_launch::StreamSpec,
    stdout: process_launch::StreamSpec,
    stderr: process_launch::StreamSpec,
) -> Result<process_launch::SpawnedChild, Error> {
    let mut bytes = [0_u8; command::MAX_ARGUMENT_BYTES];
    let mut ranges = [(0_usize, 0_usize); command::MAX_ARGUMENTS];
    let parsed = parse_direct_command(source, &mut bytes, &mut ranges)?;
    launcher
        .spawn(cwd, parsed.arguments(), environment, stdin, stdout, stderr)
        .map_err(Into::into)
}

/// Wait for one child and always attempt to reap its lifecycle token.
///
/// A failed wait requests cancellation and waits once more before reaping.
///
/// # Errors
///
/// Reports terminal observation or reap failures.
pub fn finish_child(
    launcher: &mut ProcessLauncher,
    child: process_launch::ChildToken,
) -> Result<process_launch::ChildStatus, Error> {
    let mut status = launcher.wait(child);
    if status.is_err() {
        let _ignored = launcher.cancel(child);
        status = launcher.wait(child);
    }
    let reaped = launcher.reap(child);
    let status = status?;
    reaped?;
    Ok(status)
}

/// Direction of the parent side of one child pipe.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PipeMode {
    /// Parent reads the child's standard output.
    Read,
    /// Parent writes the child's standard input.
    Write,
}

/// Owned identifiers for one child connected to one parent pipe endpoint.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PipedChild {
    /// Child lifecycle authority.
    pub child: process_launch::ChildToken,
    /// Pipe endpoint authority.
    pub pipe: pipe::PipeToken,
    /// Direction retained by the parent.
    pub mode: PipeMode,
}

/// Spawn one direct command with a single parent-facing pipe.
///
/// # Errors
///
/// Reports pipe, parser, launch, or endpoint-cleanup failures. Failed launches
/// close both pipe endpoints; failed post-launch setup cancels and reaps the
/// child.
pub fn open_piped_direct(
    launcher: &mut ProcessLauncher,
    pipes: &mut Pipes,
    source: &[u8],
    cwd: &str,
    environment: &[&str],
    mode: PipeMode,
) -> Result<PipedChild, Error> {
    let pipe = pipes.create(pipe::MIN_CAPACITY)?;
    let Ok(pipe_stream) = process_launch::StreamSpec::pipe(pipe.value()) else {
        let _ignored = pipes.close_writer(pipe);
        let _ignored = pipes.close_reader(pipe);
        return Err(Error::InvalidCommand);
    };
    let (stdin, stdout) = match mode {
        PipeMode::Read => (process_launch::StreamSpec::INHERIT, pipe_stream),
        PipeMode::Write => (pipe_stream, process_launch::StreamSpec::INHERIT),
    };
    let child = match spawn_direct(
        launcher,
        source,
        cwd,
        environment,
        stdin,
        stdout,
        process_launch::StreamSpec::INHERIT,
    ) {
        Ok(child) => child,
        Err(error) => {
            let _ignored = pipes.close_writer(pipe);
            let _ignored = pipes.close_reader(pipe);
            return Err(error);
        }
    };
    let closed = match mode {
        PipeMode::Read => pipes.close_writer(pipe),
        PipeMode::Write => pipes.close_reader(pipe),
    };
    if let Err(error) = closed {
        let _ignored = launcher.cancel(child.token);
        let _ignored = finish_child(launcher, child.token);
        return Err(error.into());
    }
    Ok(PipedChild {
        child: child.token,
        pipe,
        mode,
    })
}

/// Close the retained pipe endpoint, then wait for and reap its child.
///
/// # Errors
///
/// Reports endpoint, wait, cancellation, or reap failures.
pub fn close_piped(
    launcher: &mut ProcessLauncher,
    pipes: &mut Pipes,
    child: PipedChild,
) -> Result<process_launch::ChildStatus, Error> {
    let endpoint = match child.mode {
        PipeMode::Read => pipes.close_reader(child.pipe),
        PipeMode::Write => pipes.close_writer(child.pipe),
    };
    let status = finish_child(launcher, child.child);
    endpoint?;
    status
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::{Error, parse_direct_command};
    use troe_kex_sdk::command;

    fn parse(source: &[u8]) -> Result<std::vec::Vec<std::string::String>, Error> {
        let mut bytes = [0_u8; command::MAX_ARGUMENT_BYTES];
        let mut ranges = [(0_usize, 0_usize); command::MAX_ARGUMENTS];
        parse_direct_command(source, &mut bytes, &mut ranges).map(|command| {
            command
                .arguments()
                .iter()
                .map(|argument| std::string::String::from(*argument))
                .collect()
        })
    }

    #[test]
    fn direct_parser_handles_quotes_and_rejects_shell_syntax() {
        assert_eq!(
            parse(br#"printf "a b" 'c d' e\ f"#),
            Ok(std::vec![
                std::string::String::from("printf"),
                std::string::String::from("a b"),
                std::string::String::from("c d"),
                std::string::String::from("e f"),
            ])
        );
        assert_eq!(parse(b"echo x | cat"), Err(Error::ShellSyntax));
        assert_eq!(parse(b"echo 'x"), Err(Error::UnclosedQuote));
        assert_eq!(parse(b"echo x\\"), Err(Error::TrailingEscape));
        assert_eq!(parse(b"   "), Err(Error::InvalidCommand));
    }
}
