# ADR 0002: shell grammar, pipelines, and status

Status: accepted, 2026-08-22.

Ship single and double quoting in 0.1. Ship `|` now as shell-level composition,
not as a kernel pipe object. Limit a line to 512 bytes, a command to 32 words, a
pipeline to 8 stages, and each intermediate byte stream to 64 KiB. Execute
stages sequentially and stop on the first non-success status.

Statuses are stable categories (`Success`, `Failure`, `Usage`, `NotFound`,
`Denied`) with hosted numeric mappings. Expected errors never panic. Stderr is
not piped in 0.1.

Omitting pipelines would force commands toward console coupling. Unbounded
buffers were rejected. Concurrent ring buffers were rejected until cooperative
tasks exist; they add scheduler state without changing command semantics.

Revisit the implementation when tasks land, preserving byte order, EOF,
capacity, partial-I/O, and failure semantics.

Implementation note, 2026-08-23: Stage 4 introduced cooperative tasks, but no
measured workload justified concurrent pipeline rings or their wakeup state.
Pipelines therefore remain sequential with the original bounded semantics.
