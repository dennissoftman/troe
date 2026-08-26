# ADR 0002: shell grammar, pipelines, and status

Status: accepted, 2026-08-22.

Ship literal single and double quoting in 0.1. Ship `|` as shell-level
composition, not as a kernel pipe object. Limit a line to 512 bytes, a command
to 32 words, a pipeline to 8 stages, and each dynamically growing intermediate
byte stream to 1 MiB. Execute stages sequentially and stop on the first
non-success status.

Unquoted `<` supplies the first stage through incremental offset reads.
Unquoted `>` truncates or creates its destination before execution and streams
the final stage into it; `>>` creates or streams at the existing end. Ordinary
file streams use a 16 KiB working buffer and have no shell file-size ceiling.
Applications may select a power-of-two aggregation size from 4 KiB through
1 MiB; archive workloads use 1 MiB. Quoted operators remain literal arguments.
Redirection paths never enter application `argv`. As on a conventional shell,
an output failure can leave an empty file or a successfully written prefix.
Expansion, descriptor-number syntax, stderr redirection, heredocs, and
intermediate-stage redirection remain outside this grammar.

Statuses are stable categories (`Success`, `Failure`, `Usage`, `NotFound`,
`Denied`, `Cancelled`) with hosted numeric mappings 0, 1, 2, 3, 126, and 130,
respectively. `Cancelled` records an explicit cooperative user cancellation and
does not conflate it with a command or I/O failure. Expected errors never panic.
Stderr is not piped in 0.1.

Omitting pipelines would force commands toward console coupling. Because the
current pipeline stages execute sequentially, only intermediate pipeline data
retains a 1 MiB accounting ceiling; it is allocated as bytes arrive. Standard
streams and file redirection forward message-sized calls and bounded file
chunks instead of retaining complete output. Concurrent ring buffers were
rejected until cooperative tasks exist; they add scheduler state without
changing command semantics.

Revisit the implementation when tasks land, preserving byte order, EOF,
capacity, partial-I/O, and failure semantics.

Implementation note, 2026-08-23: Stage 4 introduced cooperative tasks, but no
measured workload justified concurrent pipeline rings or their wakeup state.
Pipelines therefore remain sequential with the original bounded semantics.
