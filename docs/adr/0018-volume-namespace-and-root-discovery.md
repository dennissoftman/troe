# ADR 0018: volume namespace and deterministic root discovery

Status: accepted and implemented for Stage 8, 2026-08-24. BMNT v1 parsing,
portable stable-identity resolution, and the production post-handoff activation
path are implemented. Both native profiles use the owned BMNT record to locate
the exact root provider and `/system.cspk`; enumeration order never grants a
role. A mounted root becomes the desired system only after generation and
identity recovery also succeeds. Missing, ambiguous, corrupt, or unauthorized
media remains inspectable only through the static KEFS recovery environment.
Loading an installed manifest from the EFI system partition belongs to Stage 9
deployment tooling; the Stage 8 QEMU fixture validates the identical owned BMNT
record and post-handoff selection rules.

The current native scope publishes a bounded deterministic `/sys/storage`
snapshot containing every scanned device, GPT region, stable identity, probe
state, and configured role result. The kernel retains those bytes before
consuming provider plans but publishes them only after every returned provider
and the optional StateFS mount have attached successfully, so a `matched`
report cannot describe a failed namespace attachment.
The activation TXSLOT and StateFS devices are consumed into exclusive region
capabilities before the BMNT provider pass; two bounded `internal` records
therefore retain their exact PRGN disk, partition, and type identities plus the
selected generation and StateFS mount outcomes. The combined file remains
inside the 32 KiB report ceiling.

## Context

KEFS already supplies an immutable recovery filesystem, while ADR 0009 selects
a constrained ext4 profile for persistent native storage. The system still
needs a simple answer to three separate questions:

1. which paths name mounted volumes;
2. who creates the persistent system volume; and
3. how boot chooses that volume when a machine has zero, one, or several block
   devices.

Choosing the first enumerated disk is unsafe and unstable. Inferring a system
role from a mutable filesystem label is also ambiguous, and storing the only
root selector inside the root filesystem creates a circular dependency. At the
same time, the recovery environment must remain usable on a diskless machine or
when persistent storage is missing or corrupt.

## Decision

### Namespace

The initial volume namespace is deliberately small:

```text
/                 immutable KEFS recovery environment
/vol/root         selected persistent ext4 system volume
/vol/boot         EFI system partition, normally mounted read-only
/vol/<name>       explicitly configured additional volumes
/sys/storage      discovered devices, regions, identities, and mount state
```

`root` and `boot` are reserved role names. Additional names are explicit,
bounded, and use a conservative lowercase ASCII, digit, and hyphen syntax. They
are not derived automatically from filesystem labels. A later mount policy may
permit explicitly authorized Linux-like target paths, but `/vol/<name>` remains
the safe default and no arbitrary target is inferred from media metadata.

The `/vol`, `/vol/root`, and `/vol/boot` mountpoint directories originate in
KEFS. If a volume is absent, the corresponding mountpoint remains an empty,
read-only recovery directory rather than making the base namespace unusable.
Mounting overlays that directory; it does not replace KEFS as the recovery
root.

### Creation and ownership

The kernel does not format or partition a disk during ordinary boot. Explicit
host image-building or installer tooling creates an installed layout:

- a GPT when partitions are required;
- a FAT32 EFI system partition;
- a constrained ext4 root filesystem with fresh identifiers;
- the initial persistent files; and
- the boot mount manifest that binds the installed boot environment to the
  intended root volume.

Whole-device ext4 remains supported for tests and deliberately simple systems.
Partition creation, formatting, identifier regeneration, and destructive
layout changes stay outside automatic mount discovery.

### Bootstrap manifest

Root selection is stored outside the root filesystem in a small, versioned,
checksummed boot mount manifest beside the boot artifacts on the EFI system
partition. The UEFI bootstrap reads and validates it before the one-way
firmware handoff and copies the bounded result into owned memory. This keeps
selection independent of the persistent volume and leaves no live firmware
protocol dependency after handoff.

The first QEMU acceptance fixture compiles that generated manifest into the EFI
artifact and validates the owned parsed result before handoff. This exercises
the complete post-handoff discovery policy without adding a live firmware
dependency. Installed-media support must replace that fixture source with the
loaded-image EFI system partition path; it must not change BMNT matching rules.

The manifest is separate from SCFG. It answers only enough bootstrap questions
to locate volumes; SCFG can then be loaded and activated from a selected,
validated source without creating a root-discovery cycle. Its exact binary
encoding and ceilings require a format specification before implementation.

Each entry contains an explicit role or mount name, filesystem profile, access
mode, availability policy, and stable selectors. A partitioned root requires
the GPT disk GUID, partition unique GUID, and filesystem UUID to agree. A
deliberately unpartitioned whole-device root uses its filesystem UUID. The boot
entry may additionally be correlated with the validated UEFI loaded-image
device path. Enumeration index and mutable labels are never sufficient
selectors.

### Discovery and failure behavior

Boot processes storage in this order:

```text
native transport discovery
  -> checked whole-device geometry
  -> bounded GPT discovery or explicit whole-device candidate
  -> minimal filesystem identity validation
  -> exact manifest-selector match
  -> filesystem-profile validation
  -> VFS mount
```

Probing is bounded by platform device limits, GPT limits, supported filesystem
profiles, and manifest entry limits. Filesystem providers receive only the
matched block-region capability.

The following outcomes are deterministic:

- With no persistent disk and no matching entry, KEFS boots normally,
  `/vol/root` remains empty and read-only, and `/sys/storage` reports the
  missing role.
- With one matching disk, every supplied stable identity must agree before the
  volume mounts.
- With several disks, only the exact configured identity may mount. A different
  valid ext4 volume is merely discovered; it is not promoted to `root`.
- Duplicate identifiers or multiple exact matches are an ambiguity failure.
  TROE keeps the recovery environment active and does not guess.
- A missing, dirty, corrupt, unsupported, or mismatched root also enters the
  recovery environment with a specific mount-state diagnostic.

An availability policy distinguishes an intentionally diskless configuration
from an installed configuration that expects persistence. A required root that
cannot mount marks the desired system unavailable, but it still cannot suppress
the static KEFS recovery shell.

Custom volumes later use the same manifest and matching rules. Unconfigured
partitions appear only in `/sys/storage`; fixed media is not automatically
mounted merely because a recognized filesystem is present.

## Consequences

- Diskless boot is a normal supported state rather than a special error path.
- Adding or reordering disks cannot silently change the selected root.
- Cloned media with duplicated identifiers fails visibly instead of producing
  nondeterministic mounts.
- KEFS remains an independent recovery foundation while `/vol/root` provides a
  clear persistent-system role.
- The installer owns destructive provisioning, and the kernel owns bounded,
  read-only discovery and policy enforcement.
- A tiny bootstrap format is added, but it avoids coupling root discovery to
  the larger desired-system configuration format.

## Revisit conditions

Revisit this decision if a supported platform cannot supply or identify an EFI
boot source, if verified boot requires the manifest to move into a signed
container, if redundant roots need an explicit priority/failover protocol, or
if custom mount targets require a richer namespace policy. None of those cases
permits fallback to device enumeration order.
