# Cloud Hypervisor v53 production target

Status: exact target and acceptance harness implemented; live Linux/KVM
acceptance has not yet been recorded. This document does not claim generic
Cloud Hypervisor, KVM, x86-64, or cloud-provider support.

The first non-QEMU target is exactly this pair:

| Axis | Pinned contract |
| --- | --- |
| TROE platform | `x86_64-uefi-virtio-pci` |
| Execution environment | `cloud-hypervisor-kvm-v53` |
| Host | Linux x86-64 with readable/writable `/dev/kvm` |
| VMM | Cloud Hypervisor `v53.0`, official static x86-64 asset |
| Firmware | Cloud Hypervisor edk2 `ch-f308d878a6`, `CLOUDHV.fd` |
| CPU | one vCPU, 46-bit guest physical-address ceiling |
| Memory | 128 MiB guest; at least 512 MiB host `MemAvailable` |
| Boot | UEFI removable-media fallback from raw GPT `system.raw` |
| Storage | one-queue modern virtio-blk PCI; per-machine writable clones of `system`, `activation`, and `state` |
| Network | one-queue modern virtio-net PCI; pre-created TAP at `10.0.2.2/24`, guest `10.0.2.15/24` |
| Interrupt/discovery | Cloud Hypervisor ACPI, LAPIC/IOAPIC, SPCR 16550, one PCI segment |
| Lifecycle control | TROE ACPI reset/soft-off policy plus a private Cloud Hypervisor API socket |

[`tools/cloud-hypervisor-profile.json`](../tools/cloud-hypervisor-profile.json)
is authoritative for release assets, byte lengths, SHA-256 digests, resource
floors, addresses, and MAC. The support row remains `compatible-unverified` in
[`tools/cloud-environments.json`](../tools/cloud-environments.json) until the
complete command below passes on a real KVM host and its evidence is reviewed.

## Threat model and trust boundary

The deployment trusts the Linux host kernel, KVM, the pinned Cloud Hypervisor
and edk2 bytes, the operator-controlled TAP, the three verified bundle seeds,
and the deployment signing keys used to build the production CSPK. A hostile
KEX application and malformed guest network/storage input are inside the
adversarial boundary; a compromised host, malicious firmware, physical DMA,
host administrator, or substituted release asset is outside it.

The VMM runs unprivileged after the operator creates the TAP. It receives no
host directory, shared filesystem, host device, balloon, hotplug, migration,
snapshot, debug console, or passthrough authority. Seccomp and Landlock are
enabled. The API socket, VMM log, event stream, and mutable disk clones live in
one mode-restricted operator runtime directory. The host TAP is isolated: this
profile defines no forwarding, NAT, DNS, metadata endpoint, or Internet route.
Adding any of those is a new threat model and is not covered by acceptance.

Production identities and signing material are build inputs only. They are not
placed in the runtime directory, guest disks, command line, TAP configuration,
logs, or evidence. The bundle verifier rejects fixture identities and every
acceptance-probe marker before launch.

## Fetch and verify the pinned runtime

Download only the three assets named by the profile. The recorded upstream
digests and sizes are:

| Asset | Bytes | SHA-256 |
| --- | ---: | --- |
| `cloud-hypervisor-static` | 7,062,256 | `448af3d4e59b22c2987f7df94c213ad40fb53a10d437e42b5ee6c4fce7c29ecc` |
| `ch-remote-static` | 1,798,776 | `13f32ba952e6791fd901f2279be2055fbacc64005f96c42a8e90d58860df84a7` |
| `CLOUDHV.fd` | 4,194,304 | `edd3ceb8de672ec4317a9d68de1f5edc9f48ef2c0283853c7c681332573ff46a` |

```sh
install -d -m 0700 build/cloud-hypervisor-v53
curl --fail --location \
  https://github.com/cloud-hypervisor/cloud-hypervisor/releases/download/v53.0/cloud-hypervisor-static \
  --output build/cloud-hypervisor-v53/cloud-hypervisor-static
curl --fail --location \
  https://github.com/cloud-hypervisor/cloud-hypervisor/releases/download/v53.0/ch-remote-static \
  --output build/cloud-hypervisor-v53/ch-remote-static
curl --fail --location \
  https://github.com/cloud-hypervisor/edk2/releases/download/ch-f308d878a6/CLOUDHV.fd \
  --output build/cloud-hypervisor-v53/CLOUDHV.fd
chmod 0500 \
  build/cloud-hypervisor-v53/cloud-hypervisor-static \
  build/cloud-hypervisor-v53/ch-remote-static
```

The acceptance driver independently checks exact lengths, hashes, executable
mode, non-symlink paths, and exact `--version` output. A download alone is not
evidence.

## Build a production bundle

Generate deployment identities in a protected operator directory. Never use
`--fixture-identities` for this target.

```sh
python3 tools/mkidentity.py \
  --output build/cloud-hypervisor-v53/deployment-identities.json
python3 scripts/build.py \
  --platform x86_64-uefi-virtio-pci \
  --identity-file build/cloud-hypervisor-v53/deployment-identities.json
python3 tools/mkcloud.py build \
  --platform x86_64-uefi-virtio-pci \
  --environment cloud-hypervisor-kvm-v53 \
  --boot build/boot-x86_64-uefi-virtio-pci.img \
  --root build/storage-root.img \
  --kind production \
  --output build/cloud-x86_64-uefi-virtio-pci-cloud-hypervisor-kvm-v53
python3 tools/mkcloud.py verify \
  --bundle build/cloud-x86_64-uefi-virtio-pci-cloud-hypervisor-kvm-v53
```

Move `deployment-identities.json` out of `build/` or destroy it according to the
operator key-handling policy before launching the VM. The acceptance driver
reads only the verified bundle.

## Prepare the isolated TAP

Run these privileged setup steps on the Linux/KVM host, substituting the
unprivileged VMM account for `$USER` when appropriate:

```sh
sudo ip tuntap add dev troe0 mode tap user "$USER"
sudo ip address add 10.0.2.2/24 dev troe0
sudo ip link set dev troe0 up
```

Do not enable IP forwarding or attach `troe0` to a bridge for this profile. The
driver rejects a missing/non-TAP device or a TAP without the exact host address.

## Run the live acceptance matrix

Choose a new runtime directory and a new evidence filename for every run. The
driver refuses to overwrite a runtime directory or evidence record.

```sh
python3 scripts/test-cloud-hypervisor.py \
  --platform x86_64-uefi-virtio-pci \
  --environment cloud-hypervisor-kvm-v53 \
  --vmm build/cloud-hypervisor-v53/cloud-hypervisor-static \
  --control build/cloud-hypervisor-v53/ch-remote-static \
  --firmware build/cloud-hypervisor-v53/CLOUDHV.fd \
  --bundle build/cloud-x86_64-uefi-virtio-pci-cloud-hypervisor-kvm-v53 \
  --runtime-dir build/cloud-hypervisor-run-001 \
  --tap troe0
```

The driver performs the following bounded sequence:

1. verify the profile, all three upstream assets, the matrix row, and a
   production-only bundle;
2. clone all three seed disks into a fresh per-machine runtime and start the
   VMM with one queue per virtio device, seccomp, Landlock, serial-only console,
   and a private API socket;
3. exercise boot ownership, ACPI/SPCR discovery, API control, static TAP
   networking, resident services, shell, Lua, and quota/memory bounds;
4. persist a root-volume marker, prove the configured generation-2 health
   failure durably rolled back to generation 1, destroy, and reopen the process;
5. verify persistence, issue an in-place cold reboot, and verify persistence
   again;
6. corrupt only the newest StateFS slot, reboot from its intact predecessor,
   require a new committed slot, remove the marker, and destroy the VMM; and
7. publish canonical evidence beside the removed runtime directory.

`--keep-runtime` retains mutable disks, API/log files, and guest data for
diagnosis. Treat that directory as sensitive and delete it after analysis. A
failed run is not acceptance evidence, even if an earlier phase passed.

## Hard ceilings and unsupported variants

- Exactly one vCPU, 128 MiB guest RAM, one PCI segment, three raw GPT disks,
  one virtio queue per disk/NIC, and no hotplug are accepted.
- Host free-space preflight is 256 MiB; the immutable seed bundle is 56 MiB and
  the runtime holds three full writable copies plus bounded logs.
- Snapshot, restore, live migration, memory/device hotplug, multi-queue I/O,
  qcow2/VHD/VHDX, vhost-user, VFIO, IOMMU, confidential-computing modes,
  multiple PCI segments, AArch64, nested virtualization, and Internet-facing
  networking are unsupported.
- The host cost is one Linux x86-64 KVM machine for the duration of acceptance.
  No cloud vendor, paid instance type, or recurring service is implied. Provider
  pricing and tenancy are outside this environment claim and must be recorded
  for any separately proposed provider-specific row.

## Recovery and operator diagnostics

The immutable bundle remains the recovery source. Never boot directly from or
modify it; the harness and deployment launcher clone it per machine. On a failed
activation, retain active, previous, recovery, and in-flight roots, inspect the
bounded lifecycle diagnostics, and use the hosted `troe-system recover` and
`troe-system rollback` procedures before garbage collection. Forward-only
migration failure remains `recovery-required`; it never starts predecessor code
over newer data.

For a VMM or platform failure, preserve the runtime directory, VMM log, event
stream, API socket state, acceptance transcript, and the three mutable clones.
Verify the original production bundle and pinned assets again before attributing
the failure to TROE. Restore service by cloning the immutable seeds into a new
runtime and reapplying desired configuration and separately backed-up mutable
data; do not repair the published seed in place.

Promotion to `accepted` requires reviewing a successful evidence record and
the retained transcript, removing every gap from the matrix row, and recording
the exact command as `acceptance_evidence`. Until then the row must remain
`compatible-unverified`.
