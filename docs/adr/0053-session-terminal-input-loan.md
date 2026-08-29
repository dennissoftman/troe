# ADR 0053: Session terminal input as a foreground loan

Status: accepted and implemented, 2026-08-29. Supersedes the input ownership
statement in ADR 0037.

## Context

ADR 0037 states that a foreground process owns session terminal input. The
implementation did not provide it. Every interactive command received an empty
standard-input stream, so a foreground `cat` with no operands observed immediate
end of input and `udp send ADDRESS PORT` transmitted an empty datagram instead
of a typed payload. The documented contract and the implementation disagreed.

Session input is a single physical resource. Serial bytes and PS/2 scan codes
arrive on one machine event queue that the shell line editor already consumes at
the prompt. Any application-visible input contract must therefore decide who
owns that queue at each moment, how a blocked reader coexists with resident
jobs, supervised services, and network progress, and how ownership returns after
exit, cancellation, or fault.

The stream services that back `STANDARD_INPUT` are synchronous. A terminal read
has no bounded completion time, so satisfying it inside a dispatcher service
call would either return a false end of input or block the single event loop.

## Decision

### Cooked line byte stream, not a new interface

Foreground standard input is a **cooked line byte stream** delivered over the
existing `STANDARD_INPUT` handle and unchanged `stream` interface. Applications
read it with the same calls they already use for files and pipes, so every
existing consumer works without change and redirected and piped input remain
byte-identical.

Terminal *detection* and raw or richer editing authority are deliberately not
part of this contract. They remain a separate typed capability. Interactive
prompts, multiline continuation, and history for language runtimes are
[issue #35](https://github.com/dennissoftman/troe/issues/35).

### One session terminal, lent to one foreground process

The native shell task owns one `SessionTerminal`. It is the single owner of
serial decoding, keyboard decoding, and the cooked line discipline for the
session, and it is lent to at most one process at a time:

- An ordinary foreground command launched from the interactive session receives
  the loan for the duration of its run.
- Background jobs, supervised services, and commands staged by `sh.kex` receive
  an empty stream and observe deterministic end of input.
- Owner-scoped nested children never inherit the loan. A child that requests
  inherited standard input while its parent holds the terminal receives an empty
  stream instead. The loan is not transitive, so two readers can never compete
  for one keystroke.
- Redirected (`< path`) and piped stages are unaffected: the shell already
  substitutes a file or slice input before the runner sees the stream, so those
  stages are not terminal-backed and take no loan.

The loan is released when the foreground process exits, faults, or is cancelled.
Release discards the partial line and any cooked bytes the process did not read,
so input ownership returns to baseline.

Standard input is bound once, when a process is launched. `fg` therefore waits
for a background job without handing it the terminal: a backgrounded command
keeps the empty stream it was given. Re-binding a running process's stream would
mean replacing a live typed capability, which this design does not do.

### Cooked line discipline and bounds

Keys decoded from the session queue are applied to a pending line:

| Key | Effect |
| --- | --- |
| character | append and echo, refused when the line is full |
| Tab | append a literal tab; there is no completion under the loan |
| Enter | echo newline, publish the line and a newline to the read buffer |
| Backspace | remove the last character and erase one echoed cell |
| Ctrl-U | clear the pending line and erase its echo |
| Ctrl-D | publish a non-empty pending line, otherwise latch end of input |
| Ctrl-C | never reaches the discipline; it stays session cancellation |
| any other key | ignored without echo |

Completion, history, and cursor movement stay with the line editor. The keys the
serial and keyboard transports decode for them are ignored while the loan is
held, because a cooked stream has nowhere to apply them.

Two exact ceilings apply. A pending line holds at most `MAX_LINE_BYTES`, the
same policy the shell parser enforces. The cooked read buffer holds at most four
lines and their newlines. Input that would exceed either ceiling is refused
without echo, so the keyboard applies backpressure and neither buffer grows.

Echo is written to the shell console, so serial and framebuffer consoles mirror
typed input exactly as they do at the prompt, and it is independent of the
process's standard output. Echo remains correct when output is redirected.

### Blocked reads are deferred, never polled

A terminal read is admitted through the existing deferred-call machinery that
already serves pipes, children, timers, and datagrams:

- Cooked bytes available, or a latched end of input, completes immediately.
- Otherwise the call registers a generation-checked wait on the terminal
  resource and the process blocks.

The foreground loop then continues to drain machine events, service the network,
step resident background processes, and honor the architecture execution lease.
It sleeps only when the foreground process is blocked and no resident process is
runnable. Cancellation is unchanged: Ctrl-C is intercepted before the discipline
sees it, the pending wait is cancelled, and the blocked read returns a cancelled
reply.

The boot-time non-resident application path has no session terminal and rejects
a terminal wait, exactly as it already rejects pipe and diagnostics waits.

One boundary is unchanged and now more visible. The foreground loop steps
resident processes, including already-running service processes, but it does not
drive the service supervisor's own state machine: restart, backoff, and new
service launches are evaluated between commands, because launching a service
re-enters the shell that is currently executing the foreground command. That was
already true of any blocked foreground wait, but a terminal read can block for
as long as nobody types, so the window is no longer bounded by a deadline.
Driving supervision from inside a foreground command needs a launch path that
does not re-enter `Shell`, which this change does not introduce.

### End of stream and cancellation are distinct

A zero-length read remains the single end-of-stream signal, the same one files,
pipes, and TCP already use. Terminal end of input is latched, so once a read
returns zero every later read returns zero, and buffered bytes are always
delivered before it. A reader that drains to zero and then reads again to check
for excess sees a consistent answer.

Cancellation is a third outcome that standard input did not previously have.
A blocked terminal read returns a cancelled reply rather than a false end of
input or a transport error. Applications that read standard input must report it
as cancellation, exactly as they already do for timer and network waits;
reporting it as an I/O failure would give the wrong message and the wrong exit
status.

Output needs no matching signal. Process teardown is the output end of stream:
dropping a pipe output service detaches its writer endpoint, and a pipe read
returns zero once no writers remain, so a reader always observes the end.
An application that must end a stream before it exits closes the writer
explicitly with `pipe::CLOSE_WRITER` or `tcp_connect::CLOSE`. Shell pipelines
are sequential, so a later stage reads a complete retained buffer rather than a
live stream. There is therefore no consumer for half-closing a process's own
standard output, and no such operation exists.

## Consequences

`cat`, `wc`, `grep`, `sed`, `awk`, `hexdump`, `udp send`, and a Lua standard
input script now consume typed lines at the prompt without any application
change. A foreground command that reads input no longer starves background jobs,
supervised services, or network progress.

Bare `lua` with no operands now reads a standard-input script until Ctrl-D
instead of exiting immediately on end of input. That matches the upstream
contract for a non-interactive standard-input script; an interactive REPL
requires the terminal capability in issue #35.

Commands staged by `sh.kex` still observe end of input. A stateful shell
evaluator that owns a `read` builtin is
[issue #51](https://github.com/dennissoftman/troe/issues/51), which will take
the foreground loan for `sh.kex` itself rather than widening it to staged
batches.

The session keeps exactly one decoder pair. Handing the terminal between the
line editor and a foreground process cannot split a UTF-8 sequence or an escape
sequence across two decoding states.
