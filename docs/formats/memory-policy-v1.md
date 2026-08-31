# TROE memory policy version 1

Memory policy v1 defines the restricted operator-authored TOML accepted from
`/config/system/resources/memory.toml`, its deterministic active projection at
`/sys/config/system/resources/memory.toml`, and the equivalent typed values
retained in the active SCFG generation. The typed SCFG record is authoritative
for enforcement. The TOML projection is read-only, non-secret observability.

## Restricted TOML profile

The document is UTF-8 and uses only the tables and keys defined below. Bare
keys, decimal integers, and the boolean values `true` and `false` are accepted.
Strings, floats, dates, arrays, inline tables, dotted keys, numeric separators,
radix prefixes, duplicate tables, duplicate keys, unknown keys, and values
outside unsigned 64-bit range are rejected.

Input comments and insignificant whitespace are accepted in desired state. The
active projection removes comments and uses this deterministic form:

- tables occur in the order specified below;
- keys occur in the order specified for each table;
- one ASCII space surrounds `=`;
- integers use shortest unsigned decimal spelling;
- booleans use lowercase `true` or `false`;
- tables are separated by one empty line; and
- the document ends with exactly one newline.

The first key is the top-level integer `schema = 1`.

## Tables

`[system]` contains:

- `minimum_free_pages`: nonzero frames which application commitment cannot
  consume.

`[system.application_commit]` contains:

- `limited`: whether active policy imposes a boot-wide application committed
  page limit in addition to available frames and `minimum_free_pages`; and
- `maximum`: a nonzero page count, present if and only if `limited` is `true`.

`[process.default.committed_pages]` contains:

- `limited`: whether a process receives a default committed-page ceiling; and
- `maximum`: a nonzero page count, present if and only if `limited` is `true`.

`[process.default.reserved_pages]` contains the same two fields for reserved
private virtual pages. Reservation and commitment are accounted separately;
committed pages also count as reserved pages.

`[process.default.mappings]` contains mandatory nonzero `maximum`, the maximum
number of normalized dynamic mapping records retained for one process.

`[process.default.metadata_bytes]` contains mandatory nonzero `maximum`, the
maximum charged kernel metadata bytes retained for one process's dynamic
virtual-memory state.

`[kernel]` contains:

- `global_metadata_bytes`: a mandatory nonzero boot-wide budget for charged
  dynamic virtual-memory metadata; and
- `operation_quantum_pages`: a mandatory nonzero maximum extent used by one
  private-backing or launch-reservation allocation/zeroing substep. It bounds
  contiguous allocator work and is not a limit on the total request. A
  reservation that cannot find a free run of this size halves the request rather
  than failing, so the value is a ceiling on one substep and not a contiguity
  requirement.

All page counts refer to TROE's 4 KiB page. Multiplication by page size and
conversion to target address types use checked arithmetic.

## Canonical example

```toml
schema = 1

[system]
minimum_free_pages = 8192

[system.application_commit]
limited = false

[process.default.committed_pages]
limited = false

[process.default.reserved_pages]
limited = false

[process.default.mappings]
maximum = 65536

[process.default.metadata_bytes]
maximum = 8388608

[kernel]
global_metadata_bytes = 33554432
operation_quantum_pages = 256
```

The example values are the repository profile, not ABI constants. A deployment
may select different validated values within the compiled safety backstops and
available machine geometry.

## Validation and activation

Activation rejects a policy when:

- an optional limit has a missing `limited` field, has `maximum` while
  unlimited, or lacks `maximum` while limited;
- a mandatory value or enabled maximum is zero;
- a per-process committed limit exceeds an enabled system commitment limit;
- conversion to bytes or the dynamic user arena overflows;
- a mapping or metadata bound exceeds its compiled safety backstop;
- the global metadata budget is smaller than one permitted process metadata
  budget; or
- the generated normalized TOML cannot be decoded to the exact same typed
  values encoded in SCFG.

The typed policy participates in the immutable generation identity, rollback,
and health decision. A desired-policy edit has no runtime effect until a new
generation is constructed, validated, and activated. Recovery uses its own
compiled conservative policy when no valid generation is available and
publishes that distinction through diagnostics.

## Attenuation and observation

Package resource requests and explicit launch limits may only attenuate these
defaults. A process committed-page limit covers its initial image, startup page,
heap, stack, heap growth, and committed private mappings. A missing optional
system or process limit means no additional policy ceiling; architectural
address-space bounds, available committed frames, the minimum free-frame
reserve, mapping count, metadata budgets, and ownership checks still apply.

The active TOML reports generation policy, not live use. The private-memory
capability query reports the caller's granted limits plus current and high-water
dynamic mapping use. Existing process observation reports aggregate retained
private pages; richer boot-wide commitment/rejection diagnostics remain future
typed observation work.
