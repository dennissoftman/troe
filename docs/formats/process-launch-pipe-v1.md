# Process launch and pipe 1.0

Process launch is KEX interface 20. Pipe is interface 21. Both are version 1.0,
owner-scoped, copied-message protocols. Every multi-byte integer is unsigned
little-endian. Opaque tokens are nonzero 64-bit values and must never be treated
as global process IDs or shared between authorities.

## Process launch

The opcodes are `SPAWN` 1, `POLL` 2, `WAIT` 3, `CANCEL` 4, and `REAP` 5.
`POLL`, `WAIT`, `CANCEL`, and `REAP` accept exactly one eight-byte child token.
`WAIT` blocks without retaining a user pointer. `REAP` accepts only a terminal
child and invalidates its token.

The canonical `SPAWN` request begins with a 48-byte header:

| Offset | Bytes | Field | Rule |
| ---: | ---: | --- | --- |
| 0 | 8 | magic | `PSPNv1`, two zero bytes |
| 8 | 2 | total bytes | exact request length |
| 10 | 2 | invocation bytes | exact command 1.1 record length |
| 12 | 2 | environment count | 0–128 |
| 14 | 2 | environment value bytes | 0–2,048 |
| 16 | 8 | stdin pipe token | nonzero only for pipe mode |
| 24 | 8 | stdout pipe token | nonzero only for pipe mode |
| 32 | 8 | stderr pipe token | nonzero only for pipe mode |
| 40 | 1 | stdin mode | 1 inherit, 2 null, 3 pipe |
| 41 | 1 | stdout mode | 1 inherit, 2 null, 3 pipe |
| 42 | 1 | stderr mode | 1 inherit, 2 null, 3 pipe |
| 43 | 5 | reserved | zero |

The header is followed by one canonical command invocation, `count` little-
endian `u16` environment lengths, and the concatenated UTF-8 `NAME=VALUE`
strings. Names are nonempty ASCII alphanumeric/underscore identifiers, cannot
start with a digit, and values cannot contain NUL. A name appears at most once:
both the encoder and the decoder reject a duplicate, so a launcher replaces an
inherited entry rather than appending a second one, and no consumer resolves
precedence by position. The whole request fits the 4,094-byte service payload.

A successful spawn reply is 16 bytes: child token at offset 0 and monotonic
global process ID at offset 8. A poll/wait/cancel reply is 24 bytes:

| Offset | Bytes | Field |
| ---: | ---: | --- |
| 0 | 8 | child token |
| 8 | 8 | global process ID |
| 16 | 4 | complete application exit status |
| 20 | 1 | state: 1 running, 2 exited, 3 faulted, 4 cancelled |
| 21 | 3 | reserved, zero |

Running status is zero. A contained fault maps to 125 and cancellation maps to
130. Normal exits preserve the full `u32` application status.

When `argv[0]` contains no `/`, launch resolves exactly
`/bin/<argv[0]>.kex`. When it contains `/`, launch resolves that exact path
against the invocation cwd; it performs no suffix inference, `PATH` search, or
implicit current-directory lookup. The selected node must resolve to a regular
file and pass complete KEX package validation. The child's package manifest
must be an attenuation of the launcher's manifest. The owner-scoped child
token, not the observable process ID, authorizes lifecycle calls.

## Pipe

The opcodes are `CREATE` 1, `WRITE` 2, `READ` 3, `CLOSE_WRITER` 4, and
`CLOSE_READER` 5.

- `CREATE` accepts one `u32` capacity from 4 KiB through 1 MiB and returns an
  eight-byte pipe token.
- `WRITE` accepts an eight-byte token followed by 1–4,086 bytes. A complete
  write blocks until all bytes fit; it never commits a partial message.
- `READ` accepts a 16-byte request containing the token, a nonzero `u16`
  maximum at offset 8, and six zero bytes. It returns up to that many bytes.
- close operations accept exactly the token and close one owner endpoint.

Reads block while the buffer is empty and any writer remains. A zero-byte
successful read is EOF. Writes block under backpressure and fail after every
reader closes. A pipe object is reclaimed only after both owner directions and
every attached child endpoint close.

One owner may retain at most 65,536 pipes and 256 MiB of aggregate pipe
capacity. These are hard policy ceilings; storage is allocated only on create.
