# ADR 0016: VM platforms and the emulator role

Status: accepted, 2026-08-24; cloud-first scope amendment and Phases A and B
implemented for the named QEMU contracts, 2026-08-25.

## Context

TROE boots native x86-64 and AArch64 UEFI images under pinned QEMU q35 and
`virt` machines. Those environments are fast, repeatable, and suitable for
destructive fault testing. They are evidence for two exact VM compositions,
not definitions of either CPU architecture and not evidence that the image runs
on an arbitrary cloud VM.

Before Phase A, the machine boundary embedded q35 I/O APIC routes and legacy
ports near x86-64 mechanisms, and QEMU `virt` GICv2, PL011, timer, and
virtio-MMIO facts near AArch64 mechanisms. Selecting an architecture therefore
selected a board implicitly. That blocked honest cloud portability: a CPU does
not imply one interrupt topology, firmware description, bus, virtio transport,
UART, or lifecycle mechanism.

Cloud virtual machines are the product target. Physical boards,
microcontroller-class systems, and no-MMU compositions are outside the current
scope.

## Decision

### Separate architecture, platform, and environment

TROE treats three axes independently:

- an **architecture** implementation owns CPU feature validation, privilege
  transition, page-table encoding, exception entry, cache/TLB operations,
  context switching, and architecture timer primitives;
- a **platform descriptor** owns the firmware contract, validated hardware
  description, interrupt topology, timer selection, UART, buses, boot media,
  framebuffer/input integration, virtio transports, and lifecycle resources;
  and
- an **execution environment** identifies QEMU, another hypervisor, or a named
  cloud environment used to run that platform contract.

An architecture flag must not silently choose a platform or environment.
Platform resources come from an explicit named descriptor or bounded ACPI,
device-tree, PCI, and UEFI discovery. Fixed addresses and interrupt IDs are
allowed only inside an exact descriptor. All discovered ranges, routes, and
controller relationships are checked for size, alignment, overlap,
architecture compatibility, and collisions before volatile I/O, device
publication, DMA enable, or interrupt unmask.

Portable crates receive typed capabilities and never infer a platform from the
target architecture. The intended dependency direction is:

```text
portable policy -> typed machine capabilities
                         ^
reusable driver -> validated platform/discovery -> architecture mechanisms
```

This boundary may use checked data and modules; it does not require a trait for
every device. q35 and QEMU `virt` constants must nevertheless live in their
named platform definitions rather than architecture-wide mechanism modules.

### Make virtio the primary cloud device contract

Virtio is the preferred portable block and network boundary for supported
cloud VMs. PCI and MMIO are transports selected by the platform descriptor or
validated discovery, not by `cfg(target_arch)`. Queue size, feature negotiation,
DMA ownership, interrupt routing, reset, teardown, and failure behavior remain
bounded and transactional. A platform may omit a virtio device, but it may not
silently substitute an ambient or unvalidated device.

Non-virtio devices such as e1000, GPU, audio, USB, and provider-specific
hardware are later capability additions. They are not prerequisites to the
platform split and do not belong in the architecture layer.

### Keep QEMU as the exhaustive deterministic backend

`x86_64-q35-uefi` and `aarch64-virt-uefi` remain pinned acceptance platforms.
Host tests cover portable state spaces; QEMU covers complete boot, both virtio
transports, and destructive fault injection. Support for another hypervisor or
cloud is a separately named matrix entry even when it reuses the same drivers
and discoverable standards.

Phase A closes the current architectural gap before new cloud features:

1. define named, validated q35 and `virt` platform descriptors;
2. require an explicit platform for builds and a separate explicit execution
   environment for launch/acceptance APIs;
3. move platform resources and routes out of architecture mechanisms;
4. reject invalid descriptors before machine mutation; and
5. prove on the host that one architecture can validate more than one platform
   description while preserving both existing QEMU gates.

Phase B adds bounded ACPI, device-tree, PCI, and UEFI discovery plus named cloud
VM descriptors. No claim of “any cloud VM” is made. The supported matrix records
the exact architecture, firmware/boot contract, machine type, required CPU
features, interrupt model, virtio transports, image format, hypervisor or cloud
environment, and acceptance evidence for each entry.

### Treat boot formats as internal until a matrix entry consumes them

There is no installed release or live-machine compatibility contract yet.
Boot, storage, configuration, and application formats may therefore change
when doing so materially improves efficiency, reliability, security, or
auditability. Every change still updates its versioned specification,
independent verifier, deterministic fixtures, corruption tests, and all
consumers atomically.

The small FAT image remains a QEMU acceptance artifact. Cloud-image work may
replace or wrap it with a deterministic GPT/EFI disk and provider import format
when the first non-QEMU matrix entry requires that contract; unused physical
media tooling is not built preemptively.

### Phase A and Phase B implementation

`troe-platform` now owns the named q35/`virt` descriptions and validates their
identity, address domain, complete resource extents, interrupt topology, and
device/controller composition before machine mutation. The machine crate
consumes the validated description and dispatches native virtio without a
kernel transport branch. Build artifacts select a platform explicitly; runner
records select the execution environment independently. Host policy tests and
both pinned QEMU gates enforce the boundary.

Phase B adds bounded, allocation-free ACPI and FDT discovery. The x86 discovery
contract validates ACPI topology, ECAM, serial, PM timer, reset, and legacy
input evidence before publication. The AArch64 contract validates FDT memory,
GICv2, PSCI, timer, UART, and virtio-MMIO facts. A deterministic FAT32/GPT cloud
bundle with separate mutable activation and state disks passes the complete
boot, persistence, networking, lifecycle, and fault matrix on both exact
discoverable QEMU environments. The machine-readable matrix records those two
accepted claims and keeps KVM, AWS, and Azure unaccepted with explicit gaps.

## Consequences

- ADR 0016 Phases A and B establish the reusable VM boundary; physical-machine
  bring-up is not a prerequisite to broadening named cloud support.
- Existing q35 and `virt` constants move rather than disappear, making their
  ownership explicit and host-testable.
- Architecture-specific compilation remains valid for CPU mechanisms but may
  not choose a bus, route, address, or power controller.
- Virtio drivers become reusable capability producers across named platforms.
- A new VM is unsupported until its exact descriptor/discovery and acceptance
  matrix entry pass; resemblance to QEMU is insufficient.
- Format compatibility does not constrain cleanup before the first installed
  release, but versioning and fail-closed verification still constrain every
  change.

## Rejected alternatives

- **Treat QEMU `virt` and q35 as architecture contracts.** This spreads
  emulator-specific assumptions and blocks other cloud VM shapes.
- **Claim universal cloud compatibility from virtio alone.** Firmware,
  transport discovery, interrupts, CPU features, boot images, and lifecycle
  behavior still differ.
- **Add e1000, GPU, audio, and board drivers before the platform split.** That
  multiplies assumptions at the wrong boundary.
- **Maintain micro/tiny/full resource or embedded platform variants now.** One
  bounded standard cloud policy is simpler and matches the intended product.
- **Freeze provisional formats for compatibility with nonexistent installs.**
  This preserves accidental complexity without protecting a user.

## Revisit when

Revisit physical-machine scope only after the supported cloud matrix is useful
and a concrete deployment justifies its maintenance cost. Revisit the
UEFI-first boot contract or add a non-virtio baseline only when a named cloud
environment cannot be supported cleanly through the current discovery and
transport boundaries.
