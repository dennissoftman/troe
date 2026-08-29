# TROE installation record v1

The installation record is the durable evidence that one supported TROE machine
was provisioned from one verified production bundle. `setup-troe` writes it
before it mutates any destination and rewrites it only after every installed
byte has been read back and matched. A record therefore distinguishes an
interrupted install from a completed one without inspecting the media.

Canonical JSON means UTF-8, sorted keys, no insignificant whitespace, no
duplicate fields or non-integer numbers, and one trailing newline. Every digest
is lowercase SHA-256 of the exact file bytes.

## Document

The record contains exactly `bundle`, `format`, `schema`, `state`, and
`targets`. `format` is `troe-installation-record-v1` and `schema` is `1`.

`state` is exactly one of:

- `writing` — the record was published and destinations may have been mutated.
  The installation is incomplete and must be restarted. It is never a verified
  deployment.
- `verified` — every target was written, flushed, read back in full, and
  matched against the bundle's declared digest.

No other value is accepted. A record that is absent, unparseable, oversized, or
carries an unknown state is not evidence of an installation.

## Bundle identity

`bundle` contains exactly `environment`, `format`, `kind`, `matrix_entry`,
`path`, `platform`, and `platform_id`, reproduced from the verified
[`troe-cloud-raw-bundle-v1`](../cloud-platform-support.md) manifest. `kind` is
`production` for a supported deployment; `development` and `acceptance` bundles
require explicit test-artifact authority and never describe a supported
machine.

## Targets

`targets` is one entry per role in the exact order `system`, `activation`,
`state`. Each entry contains exactly:

- `role` — the exact bundle role; enumeration order never assigns a role;
- `kind` — `file` for a private per-machine image or `device` for a raw device;
- `path` and `requested` — the resolved destination and the operator's request;
- `identity` — the stable target identity: `device:MAJOR:MINOR` for a device,
  `file:DEVICE:INODE` for an existing file, `path:PATH` for one created by this
  installation. Two targets that resolve to one identity are refused;
- `capacity_bytes` and `image_bytes` — the destination length and the exact
  installed length. A destination shorter than its image is refused;
- `signatures` — the recognizable on-media signatures observed before the
  destructive write, for example `gpt-primary-header`, `mbr-boot-signature`,
  `ext2-ext3-ext4-superblock`, `fat32-boot-sector`, `fat-boot-sector`, or
  `unrecognized-nonzero-content`;
- `expected_sha256` — the digest the verified bundle declares; and
- `installed_sha256` — the digest of the bytes read back after the flush, or
  `null` while the state is `writing`.

## Secrets

The record names bundles, platforms, environments, targets, lengths, and
digests. It never contains keys, identity seed material, or any bundle
payload bytes.
