# TROE package model v1

PMAN v1, PLOCK v1, and TPKG v1 are the bounded hosted contracts for package
inspection and resolution. They are not Cargo metadata, repository build
scripts, a registry protocol, or authority to mutate a running TROE system.
The reference library is [`tools/package_model.py`](../../tools/package_model.py);
[`tools/troe.py`](../../tools/troe.py) is only its presentation and file-output
layer.

All three formats use UTF-8 JSON with integer numbers only. Duplicate keys,
unknown fields, unknown targets, unknown capabilities, ambiguous identities,
invalid ordering, and values outside the documented ceilings fail closed.
Canonical documents sort object keys, use no insignificant whitespace, encode
non-ASCII text as UTF-8, and end with one newline. Locks and package artifacts
must arrive in that exact canonical encoding; manifests are normalized before
their identity is computed.

## PMAN v1 package manifest

A manifest has exactly these fields:

- `schema`: integer `1`;
- `name` and `version`: canonical package name and a three-integer version;
- `dependencies`: at most 32 unique name-sorted inclusive-minimum,
  exclusive-maximum version ranges;
- `targets`: one or both of `x86_64-unknown-uefi` and
  `aarch64-unknown-uefi`, sorted by target, with matching architecture, ABI
  1.0/1.1, artifact length/digest, SDK digest, and toolchain digest;
- `capabilities`: at most 32 unique sorted values from the closed typed-service
  vocabulary;
- `directories`: at most eight unique sorted package root declarations. Roles
  are `assets`, `config`, or `data`; assets and resolved configuration are
  read-only, while data may separately request `read-mutate`;
- `resources`: 1–50 ms execution lease, 1–8 initial handles, 4 KiB–64 MiB heap,
  and 4 KiB–1 MiB stack; and
- `services`: at most 16 unique sorted service names bound to package commands.

An absolute host or guest path is not part of a directory declaration. Native
activation must resolve each named role to the generation-bound directory
capability defined by ADR 0040.

## PLOCK v1 target lock

A lock names one root and one exact target, then records at most 128 packages
sorted by name. Every record binds the exact package version, canonical
manifest SHA-256, artifact SHA-256 and length, SDK SHA-256, toolchain SHA-256,
and exact sorted dependency versions. Every dependency must resolve to exactly
one record. Identical manifest catalogs and target selection produce identical
lock bytes regardless of catalog enumeration order.

The resolver selects the highest version satisfying every accumulated range.
Missing dependencies, conflicting ranges, duplicate identities, cycles,
unsupported targets, and capacity exhaustion are errors; partial locks are
never returned.

## TPKG v1 package artifact

A TPKG v1 document contains exactly `schema`, `target`, `manifest`, `lock`, and
canonical base64 `artifact` fields. It is limited to 8 MiB. Parsing independently
revalidates PMAN and PLOCK, requires the manifest to be the locked root, and
checks the artifact length and SHA-256 against the selected target. Rebuilding
from parsed fields must reproduce every package byte.

TPKG SHA-256 supplies content integrity and deterministic addressing only.
Publisher authentication, freshness, revocation, provenance, and atomic
publication are separate trust-policy inputs; a digest alone grants no trust or
runtime capability.

## Stable tool result

Every `tools/troe.py --format json` command emits exactly `schema`, `command`,
`ok`, `diagnostics`, and `data`. Diagnostics have exactly `code`, `path`, and
`detail`. Human output is derived from the same typed result. `check`,
`diagnostics`, `inspect`, `explain`, and `plan` perform no writes. `resolve` and
`build` write only an explicit absent host output path and refuse replacement;
no package-model command connects to or mutates a running TROE system.
