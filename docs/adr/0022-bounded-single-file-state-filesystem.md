# ADR 0022: bounded single-file state filesystem

Status: accepted and implemented for Stage 8, 2026-08-24.

The first persistent filesystem mutation surface is STFS v1, not partial ext4
journal mutation. STFS owns an exact PRGN-selected four-block GPT region and
exposes only `/state.bin`, bounded by the containing TXSLOT payload ceiling.
Create/replace and removal serialize the complete filesystem image and commit
it with data/flush/commit/flush ordering. A mutation is visible in memory only
after the final flush succeeds; reopen selects only a completely committed
slot. The virtio profile supplies flush and explicitly does not claim FUA.

The VFS distinguishes read-only and writable provider mounts. Existing ext4
and FAT providers retain default read-only mutation methods. Only the explicitly
selected STFS provider is attached writable at `/vol/state`; its block region
cannot reach the ext4 root, activation transaction, GPT metadata, or another
device.

This deliberately small filesystem supplies a durable selected-state primitive
and a testable mutation boundary without claiming ext4 journal replay, general
directory mutation, rename, ACL, or multi-file transaction support. Those
features require their own format and recovery work. Host tests cover VFS
create/replace, reopen, remove, and malformed inner images; both native QEMU
profiles increment the persistent file across five process terminations and
the harness independently validates the outer TXSLOT record, STFS checksum,
transaction generation, and file value after every reopen.
