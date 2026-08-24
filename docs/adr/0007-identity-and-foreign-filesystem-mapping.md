# ADR 0007: identity and foreign filesystem mapping

Status: accepted for Stage 8, 2026-08-24. Serialized registry, mapping-table,
mount-record, and ACL formats still require versioned format records before a
persistent writer consumes them.

## Context

The MVP has no users, groups, login authentication, persistent writable
filesystem, or discretionary permission checks. Stage 8 support for ext4, FAT,
exFAT, and later NTFS must preserve ownership and access metadata without making
an identifier from another machine authoritative merely because its numeric or
textual value looks familiar.

POSIX filesystems store numeric UIDs and GIDs whose meaning depends on an
external identity database. NTFS identifies trustees with authority-scoped SIDs
and stores richer security descriptors. Neither representation always
translates losslessly to the other. FAT-family filesystems carry no trustworthy
per-object identity at all.

Authentication proves a principal, mapping interprets external metadata,
ownership attributes an object, and capabilities convey active authority. None
substitutes for another.

## Decision

### Native identifiers and records

- A native principal identifier is an opaque, nonzero 128-bit value. It is
  stable for the lifetime of the installation, never reused after deletion,
  and carries no authority by its numeric value. The all-zero value is invalid.
- Users, groups, services, and system actors share the same identifier width
  but carry a closed principal-kind field. A group is a distinct principal kind,
  not an untyped integer namespace.
- Trusted installer or identity-service tooling creates identifiers from a
  cryptographically secure random source. A kernel without an approved entropy
  source does not mint persistent identifiers; it may consume an already
  validated registry or remain in recovery mode.
- A registry record contains the identifier, kind, active/disabled/tombstoned
  state, optional compatibility UID or GID, and a bounded UTF-8 display label.
  Labels and compatibility numbers are lookup attributes, never authority.
- Deleted identifiers become permanent tombstones. A restore preserves the
  identifier only when restoring the same security actor; otherwise it creates
  a new identifier and requires an explicit metadata remap.
- The `tiny` profile accepts at most 256 principal records, 32 direct group
  memberships per principal, and 1,024 external mapping entries. The `full`
  profile accepts at most 65,536 records, 256 direct memberships, and 262,144
  mappings. Membership expansion is iterative and cycle checked. `micro`
  carries no persistent identity registry.

### Identity domains and foreign values

- Every on-disk compatibility identity is paired with a nonzero opaque 128-bit
  identity-domain identifier. Equal UIDs on unrelated volumes are not equal
  identities unless policy deliberately binds both to the same domain.
- POSIX UIDs and GIDs are unsigned 32-bit values and retain whether they name a
  user or group.
- A Windows SID is retained exactly: revision 1, a six-byte identifier
  authority, and at most 15 little-endian 32-bit subauthorities, for a maximum
  of 68 bytes. Invalid revisions, counts, lengths, or encodings fail parsing.
- An unknown external scheme is representable as a nonzero 32-bit scheme ID and
  at most 64 opaque bytes. It may be inspected and round-tripped but cannot
  authorize access until a scheme-specific evaluator is accepted.
- A mapping key is the complete `(domain, scheme, value, kind)` tuple. One key
  maps to at most one native principal. Several foreign keys may deliberately
  map to one native principal, but are not aliases outside that mapping snapshot.

### Mapping ownership and updates

- A mapping table is an immutable, versioned snapshot owned by a named system
  generation. It records its domain, monotonically increasing version, exact
  entry count, bounded encoded length, and integrity digest. Entries are sorted
  canonically and duplicates are rejected before activation.
- Updates construct and validate a complete replacement snapshot and activate
  it through the crash-consistent system-generation pointer. Mapping tables are
  never edited in place.
- Only a principal holding identity-administration authority may construct or
  activate a mapping snapshot. A mapped UID, GID, SID, familiar name, or on-disk
  owner field does not grant that authority.
- If the selected snapshot is absent, corrupt, outside its profile, or
  unavailable offline, affected identities remain unmapped. The volume may be
  inspected read-only with raw metadata, but resolution never falls back to the
  current user, `nobody`, UID 0, an administrator SID, or a name match.

### Closed mount-policy vocabulary

Every persistent mount selects exactly one identity mode:

1. `native-mapped` binds a locally administered volume domain to a validated
   registry and mapping snapshot. This is required for the writable ext4 system
   store.
2. `explicit-mapping` binds foreign metadata to one named immutable mapping
   snapshot. Writes are allowed only when the provider preserves the mapped and
   raw semantics exactly.
3. `shifted-view` applies checked UID/GID display offsets inside one foreign
   domain. Shifted numbers remain foreign and grant no native authority without
   an explicit mapping.
4. `fixed-owner` assigns one configured native principal and group as synthetic
   mount metadata. This is the writable FAT/exFAT mode; synthetic values are not
   written as if the format supplied per-object ownership.
5. `foreign-unmapped` preserves and exposes raw metadata without resolving it.
   The mount is read-only and raw identities grant no native authority.
6. `read-only-untrusted` exposes data through a caller-granted read capability
   while treating all on-disk security metadata as informational. It is the
   default recovery mode when a domain or mapping cannot be trusted.

A mount record includes the mode, domain, referenced mapping version when
applicable, synthetic owner when applicable, and whether raw security metadata
is available losslessly. Providers may not invent an implicit fallback.

### Authorization and ACLs

- A live object or filesystem capability is required before discretionary
  metadata is evaluated. Identity attributes never manufacture a device, mount,
  namespace, or mutation capability.
- The native ext4 profile evaluates mapped owner, group, mode bits, and the
  accepted bounded POSIX ACL subset. Owner and named-user entries precede group
  class evaluation; the ACL mask limits named-user and group-class rights; the
  other entry applies only after no owner or group-class match. Malformed,
  duplicate, incomplete, or over-limit ACLs fail the object closed.
- `tiny` retains at most 32 ACL entries per object and `full` at most 256. ACL
  lookup and membership work remain inside the selected membership bounds.
- An unresolved owner or group never matches a native principal. On a trusted
  `native-mapped` or `explicit-mapping` mount, a valid `other` entry may still
  grant its deliberately broad rights. In either untrusted read-only mode, disk
  mode and ACL data is informational and grants nothing.
- NTFS security descriptors remain losslessly inspectable but non-authorizing
  until another ADR accepts an exact bounded ordered allow/deny, inheritance,
  and audit evaluator. NTFS therefore remains read-only under this contract.
- Capability policy may further restrict a metadata-derived right. It cannot
  broaden a denied or unmapped decision on a writable multi-principal mount,
  except through an explicit audited recovery capability.

### Lifecycle, copies, and recovery

- Delegation transfers explicit capabilities, not identity numbers. Revocation
  invalidates handles or generations. Disabling a principal prevents new
  authorization; existing handle fate follows the service's revocation policy.
- A cloned writable native volume retains its domain identifier. Detecting two
  writable instances of one domain forces both read-only until an explicit
  re-domain/remap operation completes. Read-only clones are permitted.
- Cross-filesystem copy, archive, restore, and backup operations return one
  fidelity result: `preserved`, `mapped`, `approximated`, or `dropped`. A caller
  must explicitly authorize `approximated` or `dropped`; ordinary copy fails
  rather than silently losing security metadata.
- Recovery retains raw supported identity and ACL bytes even when the registry
  is unavailable. Recovery tooling may activate a previously valid generation
  or construct a separately authorized remap; it never infers authority from
  media contents.
- Resource accounting is charged to a native principal or resource domain,
  never directly to an untrusted on-disk identifier.

## Filesystem preservation rules

- Ext4-style providers preserve raw UID, GID, mode, and accepted POSIX ACL
  metadata. The mount's identity domain determines their interpretation.
- NTFS providers preserve owner/group SIDs and the complete supported security
  descriptor. A POSIX-looking view is explicitly approximate and cannot
  overwrite richer metadata implicitly.
- Filesystems without native ownership use `fixed-owner` or an untrusted
  read-only mode; synthetic ownership is never presented as disk metadata.
- Privileged inspection exposes both resolved native principal and raw source
  identity.
- Copy and backup operations surface their security-metadata fidelity result.

## Format work required before writes

Before a persistent writer consumes this model, define and test:

- canonical serialized registry, mapping-snapshot, mount-record, and native ACL
  encodings, each with magic, major/minor version, exact length, integrity
  coverage, reserved-zero fields, and profile ceilings;
- the installation entropy source and identifier-provisioning procedure for
  each supported deployment;
- crash-consistent generation activation and recovery tests shared with the
  Stage 8 configuration store;
- exact ext4 UID/GID, mode, POSIX ACL, and xattr feature validation in the
  constrained ext4 format ADR; and
- stable inspection APIs that return both native resolution and raw source
  identity without treating display names as keys.

The owner-less KEFS image and single-session RAMFS remain unchanged because
they are bootstrap formats with no multi-user security claim. Read-only
filesystem experiments are permitted when they retain raw metadata and do not
treat it as native authority. No persistent writer or stable VFS
security-metadata ABI may land until its applicable format work above is
accepted.

[ADR 0009](0009-persistent-filesystems-and-partitions.md) selects constrained
ext4 for native persistent volumes, FAT/exFAT for synthetic-owner interchange,
and later modular NTFS. That storage direction consumes this ADR's principal
widths, domain bindings, ACL policy, and fail-closed mapping rules.

## Consequences

- Native authority cannot be acquired by presenting a familiar foreign number,
  SID, or account name.
- Writable native storage depends on a valid registry and mapping generation;
  losing it degrades to inspectable read-only recovery rather than guessing.
- FAT and exFAT remain writable interchange formats without pretending to
  preserve per-object native identity.
- NTFS can progress through lossless read-only inspection without prematurely
  freezing an approximate authorization model.
- Registry, mapping, ACL, and generation formats add implementation work, but
  bounded immutable snapshots avoid hidden network identity dependencies and
  in-place corruption states.
