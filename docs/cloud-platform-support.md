# Cloud platform support and raw artifacts

Status: Phase B implemented for two exact discoverable QEMU contracts. The
combined cloud bundle passes the complete runtime and fault matrix on both;
real cloud-provider entries remain unsupported until separately accepted.

TROE support is an exact `(platform, environment)` claim. An architecture,
UEFI, or the presence of virtio alone is not enough. The authoritative
machine-readable matrix is
[`tools/cloud-environments.json`](../tools/cloud-environments.json); the
validator and deterministic packager are
[`tools/mkcloud.py`](../tools/mkcloud.py).

The accepted QEMU runner uses 128 MiB for the x86-64 combined-disk/ACPI
composition. Its UEFI drivers and the embedded immutable application root must
coexist before handoff; the smaller 64 MiB x86-64 split-disk regression runner
does not establish enough headroom for that composition. AArch64 QEMU runners
also use 128 MiB.

## Raw bundle v1

One bundle contains exactly four files:

| File | Bytes | Authority |
| --- | ---: | --- |
| `system.raw` | 52 MiB | immutable GPT system disk |
| `activation.raw` | 2 MiB | per-machine writable TXSLOT seed |
| `state.raw` | 2 MiB | per-machine writable StateFS seed |
| `bundle.json` | bounded canonical JSON | exact platform/environment, geometry, GUID, length, and SHA-256 metadata |

`system.raw` has fixed 512-byte logical sectors and this layout:

| Region | LBA range | Size | Contents |
| --- | ---: | ---: | --- |
| protective MBR and primary GPT | 0–33 | 17 KiB | canonical UEFI GPT metadata |
| alignment gap | 34–2047 | 1007 KiB | zero |
| `esp` | 2048–71679 | 34 MiB | deterministic fixed-media FAT32 ESP with one architecture-native fallback EFI executable |
| `root` | 71680–104447 | 16 MiB | exact constrained-ext4 payload from the verified root source disk |
| trailing gap | 104448–106462 | 1007.5 KiB | zero |
| backup GPT | 106463–106495 | 16.5 KiB | entry-array copy and backup header |

The combined disk preserves the root source disk GUID, root partition GUID,
filesystem UUID, and bytes. This is required because BMNT selects all three
root identities rather than an enumeration index. Packaging and verification
extract the EFI-embedded BMNT and require it to select those exact three root
identities. The selected platform identifier must also occur exactly once in
the executable, preventing accidental cross-platform artifact labeling. The ESP
has the standard EFI System Partition type and the architecture-native UEFI
fallback executable.

The protective MBR uses UEFI's canonical `00 02 00` starting CHS and
`ff ff ff` ending sentinel. The ESP is FAT32 because it is a GPT EFI System
Partition on fixed media; the smaller FAT12 image remains only the pinned-QEMU
source/fixture format and is not copied into `system.raw`.

Every bundle has one explicit kind:

| Kind | CSPK identity policy | EFI probe policy | Default verification |
| --- | --- | --- | --- |
| `production` | rejects every reserved fixture identity | rejects acceptance markers | allowed |
| `development` | requires all reserved fixture identities | rejects acceptance markers | requires `--allow-test-artifacts` |
| `acceptance` | requires all reserved fixture identities | requires an acceptance marker | requires `--allow-test-artifacts` |

Activation and state images use the existing PRGN-selected disk, partition,
and type GUIDs. Their four-block payloads are zero in a release bundle. The
system image contains the default writable ext4 root role. Clone all three
images for each machine and attach them writable; never share one mutable copy
between machines.

## Build and verify

First provision deployment identities, then produce the platform boot image and
constrained root. The cloud tool intentionally does not compile a kernel or
invoke a provider:

```sh
python3 tools/mkidentity.py --output build/deployment-identities.json
python3 scripts/build.py \
  --platform x86_64-q35-uefi \
  --identity-file build/deployment-identities.json
python3 tools/mkcloud.py build \
  --platform x86_64-q35-uefi \
  --environment qemu \
  --boot build/boot-x86_64-q35-uefi.img \
  --root build/storage-root.img \
  --kind production \
  --output build/cloud-x86_64-q35-uefi-qemu
```

Development builds use `scripts/build.py --fixture-identities` and
`tools/mkcloud.py build --kind development`. Acceptance builds additionally
select `--acceptance-probes` in the kernel build and `--kind acceptance` in the
cloud build. The kind is required; it is never inferred from filenames.

The output directory must not already exist. Publication uses a sibling staging
directory and happens only after full verification. Repeating the build from
identical inputs yields byte-identical raw disks and manifest.

Verify a received or copied bundle without rebuilding it:

```sh
python3 tools/mkcloud.py verify \
  --bundle build/cloud-x86_64-q35-uefi-qemu
```

Only production is authorized by default. Deliberate verification of a
development or acceptance bundle adds `--allow-test-artifacts`.

Print the validated support matrix with:

```sh
python3 tools/mkcloud.py matrix
```

## Verification boundary

The verifier fails closed and owns its parsing bounds. It checks:

- exact file set, canonical JSON schemas, unique identities, and every recorded
  length and SHA-256 digest;
- a 64 MiB maximum per disk, 512-byte sectors, at most 16 live partitions, and
  contiguous canonical GPT entry use;
- exact UEFI protective MBR, primary and backup GPT headers, header and array CRCs,
  reciprocal locations, identical entry arrays, usable bounds, alignment,
  non-overlap, unique GUIDs/names, zero attributes, and zero unused sectors;
- exact ESP and root geometry, FAT32 BPB/backup/FSInfo, both FAT copies, the
  complete canonical directory/allocation tree, and zero unallocated space;
- bounded PE/COFF header location and section table, PE32+ EFI-application
  subsystem, architecture-native Machine value, selected platform marker, and
  embedded BMNT binding to the packaged root;
- the explicit production/development/acceptance identity and probe policy;
- the existing independent constrained-ext4 semantic verifier for the root,
  including extraction and exact-tree verification of `/system.cspk`;
  and
- exact empty TXSLOT and StateFS seed identities and geometry.

Truncation, trailing files, sparse GPT entries, metadata disagreement, payload
changes, unexpected allocation, and schema extensions are rejected. GPT CRCs
do not cover partition payloads, so bundle SHA-256 records bind every complete
disk and every partition payload separately.

## Acceptance matrix

The current matrix deliberately separates three states:

| Environment | Platform | Runtime status | Artifact status | Meaning |
| --- | --- | --- | --- | --- |
| pinned QEMU q35 | `x86_64-q35-uefi` | compatible-unverified | host-verified | Its split-media runtime is accepted, but this exact platform has not consumed the combined bundle. |
| pinned QEMU `virt`/GICv2 | `aarch64-virt-uefi` | compatible-unverified | host-verified | Its split-media runtime is accepted, but this exact platform has not consumed the combined bundle. |
| QEMU discoverable UEFI/ACPI | `x86_64-uefi-virtio-pci` | accepted | host-verified | The combined bundle passes boot, reboot, persistence, networking, and all fault sessions after bounded ACPI validation. |
| QEMU discoverable UEFI/device tree | `aarch64-uefi-virtio-mmio` | accepted | host-verified | The combined bundle passes boot, reboot, persistence, networking, and all fault sessions after bounded FDT validation. |
| QEMU q35 with KVM | `x86_64-q35-uefi` | compatible-unverified | host-verified | Same described machine contract, but no pinned KVM result. |
| QEMU `virt` with KVM | `aarch64-virt-uefi` | compatible-unverified | host-verified | Same described machine contract, but no pinned AArch64 KVM result. |
| AWS Nitro | none | incompatible | unavailable | Requires validated provider discovery plus NVMe and ENA drivers. |
| Azure Generation 2 | none | incompatible | unavailable | Requires Hyper-V/VMBus storage, network, interrupt discovery, and a provider import format. |

Provider rows are engineering gap records, not promises about every present or
future instance type. They must be rechecked against provider documentation and
accepted on real instances before promotion. No qcow2, VHD, VMDK, snapshot, or
provider-import wrapper is produced yet; raw GPT is the only implemented cloud
artifact format.

The accepted x86 contract uses QEMU q35 with a deterministic injected SPCR,
ACPI-discovered ECAM/APIC topology, the FADT PM timer, and reset-only lifecycle
control. The accepted AArch64 contract pins QEMU `virt,gic-version=2,acpi=off`
and validates the edk2-published FDT for GICv2, PSCI-HVC, PL011, timer, RAM, and
virtio-MMIO. These are exact environment claims, not generic q35/`virt` or
provider-cloud claims. The next portability increment is a named provider only
after its storage/network drivers, firmware contract, import format, and real
instance acceptance exist.
