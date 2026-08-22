# ADR 0007: identity and foreign filesystem mapping

Status: proposed direction; TBD before persistent filesystem metadata or
foreign-filesystem write support.

## Context

The MVP has no users, groups, login authentication, persistent writable
filesystem, or discretionary permission checks. Later support for ext4, XFS,
NTFS, and other existing filesystems must preserve their ownership and access
metadata without making an identifier from another machine authoritative on
this system merely because its numeric or textual value looks familiar.

POSIX filesystems commonly store numeric UIDs and GIDs whose meaning depends on
an external identity database. NTFS identifies trustees with authority-scoped
SIDs and stores richer security descriptors containing owner, group, access,
and audit policy. Neither representation can always be translated losslessly
to the other. Filesystems such as FAT may carry no per-object identity metadata
at all.

## Proposed planning direction

Plan around a small neutral identity layer rather than selecting raw UID/GID or
Windows SID as the kernel-wide canonical identity:

- native users, groups, services, and other security actors are represented by
  stable, opaque, non-reused principal identifiers;
- UID/GID remains a first-class compatibility identity, not a discarded or
  second-class feature;
- Windows SIDs remain bounded, losslessly representable external identities;
- a mount/import mapping domain translates external identities to native
  principals and may provide a different session or compatibility view without
  rewriting every on-disk object;
- authentication proves a principal, mapping interprets external metadata,
  ownership attributes an object, and capabilities convey active authority;
  none substitutes for the others;
- raw UID 0, an administrator SID, or a familiar account name from foreign
  media never grants native administrative authority by itself;
- unmapped identities remain distinct and round-trippable and fail closed for
  authorization rather than becoming `nobody`, the current user, or an
  administrator;
- resource accounting is charged to a native principal or resource domain,
  never directly to an untrusted on-disk identifier.

## Filesystem preservation direction

- ext4/XFS-style drivers preserve raw UID, GID, mode, and supported POSIX ACL
  metadata. A mount policy determines the identity domain in which those
  numeric values are interpreted.
- NTFS drivers preserve owner and group SIDs plus the complete supported
  security descriptor, including ordered allow/deny entries, inheritance, and
  audit metadata. A POSIX-looking view may be derived for compatibility but is
  explicitly approximate and must not overwrite richer metadata implicitly.
- filesystems without native ownership use an explicit fixed-owner or similar
  mount policy; synthetic ownership is not written as if it came from disk.
- privileged inspection exposes both the resolved native principal and the raw
  source identity when available.
- cross-filesystem copy, archive, restore, and backup operations report whether
  security metadata was preserved, mapped, approximated, or dropped. Silent
  lossy conversion is rejected.

## Decisions still required

Before this ADR can be accepted, decide and test:

- the bit width, allocation, persistence, and recovery rules for native
  principal and group identifiers;
- whether groups are a distinct identifier type or a kind of principal;
- the bounded representation for external and unknown identity schemes;
- mapping-table ownership, versioning, atomic update, audit, and offline
  behavior;
- mount-policy vocabulary, including identity, explicit, shifted, fixed-owner,
  foreign/unmapped, and read-only-untrusted modes;
- authorization behavior when mappings or identity services are unavailable;
- the native ACL/authorization model and which POSIX and NTFS semantics can be
  enforced exactly;
- rules for delegation, revocation, account deletion, identifier non-reuse,
  removable media, cloning, and restore to another system;
- compatibility API behavior when a native principal has no numeric UID/GID;
- security metadata limits, parser validation, caching, and memory accounting.

## Constraint on implementation

The current owner-less KEFS image and single-session RAMFS may remain unchanged
because they are bootstrap formats with no multi-user security claim. No
persistent writable format, foreign-filesystem write path, or stable VFS
security-metadata ABI should be frozen until this ADR is resolved. Read-only
experiments are permitted when they retain raw metadata and do not treat it as
native authority.
