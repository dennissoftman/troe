# TROE configuration projection v1

Configuration projection v1 is the canonical interchange and in-memory
contract used to construct the read-only `/sys/config` view for one immutable
deployment generation. It does not authorize package or directory access. The
hosted lifecycle stores the canonical JSON/base64 form as desired state and
materializes exact raw files inside each immutable candidate; the native VFS
consumes the validated path/byte pairs rather than parsing JSON.

## Inputs and limits

One replacement operation contains:

- a nonzero unsigned 64-bit deployment generation;
- zero to 128 files;
- at most 8 KiB per file; and
- at most 64 KiB of aggregate file payload.

The canonical document contains exactly `schema: 1` and `files`. Each sorted
file entry contains exactly a relative `path` and canonical base64 `data`.

Paths are UTF-8 relative paths, are nonempty, contain no empty, `.` or `..`
component, and are supplied in strictly increasing byte-lexical order. Absolute
paths and normalized aliases are invalid. No path may be both a file and an
ancestor directory. The resolved absolute path retains the VFS limits of 256
bytes, 255 bytes per component, and 16 components including `sys/config`.
Parents are implicit and do not consume a file slot.

The byte payload is exact and uninterpreted at the VFS boundary. Package schema
validation and normalization happen before construction. Secret material is
not eligible for this projection.

## Atomic visibility

The implementation clones the namespace state, removes the previous children
of `/sys/config`, validates and inserts every candidate file into that staged
state, and then replaces the namespace map and recorded generation together.
Any invalid path, collision, checked-arithmetic overflow, or exceeded limit
leaves the prior map and generation unchanged. An empty valid projection
removes all prior children while retaining the `/sys/config` directory.

Ordinary file writes, truncation, deletion, directory creation, and link
creation cannot mutate this view. `/config` is outside the replacement prefix
and therefore remains independent.
