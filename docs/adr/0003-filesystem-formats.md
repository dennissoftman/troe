# ADR 0003: KEFS and boot container

Status: accepted, 2026-08-22.

Use the documented KEFS v1 record format for embedded read-only content. Use a
fixed 1.44 MiB FAT12 boot container containing only the architecture-native UEFI
fallback executable. Builders are dependency-free Python and perform an exact
round-trip verification.

Embedding source files directly with many `include_bytes!` calls was rejected
because it has no independently fuzzable/versioned mount boundary. General FAT
libraries remain a good option when the boot container needs more files;
today's fixed three-directory/one-file layout is smaller to audit and entirely
validated by extraction.

Revisit FAT tooling when the container needs mutation, long filenames, multiple
payloads, or non-FAT media. Bump KEFS for any incompatible record change.

