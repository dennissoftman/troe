# ADR 0020: first dual-slot durability transaction

Status: accepted; portable core and native QEMU acceptance implemented,
2026-08-24.

The first persistent writer is a four-logical-block dual-slot record, not an
ext4 metadata writer. Each slot contains one checksummed data block and one
checksummed commit block. Recovery accepts a slot only when both canonical
blocks agree on a nonzero generation and the commit repeats the data checksum.

A commit always targets the inactive slot in this order:

1. write the complete new data block;
2. flush the device;
3. write the matching commit block; and
4. flush the device again.

The active in-memory generation changes only after step 4 succeeds. At any
earlier interruption, the predecessor slot remains valid. A torn data or commit
block fails its checksum; an old commit paired with overwritten data fails its
generation/checksum match. Equal committed generations in both slots are an
ambiguity failure, and generation arithmetic never wraps.

The region capability must be exactly four blocks, writable, alignment one,
and backed by explicit flush. FUA is neither required nor claimed. Payload is
bounded to one logical block minus the fixed header. This format is suitable
for a small activation pointer or registry root; it does not by itself make
ext4, FAT, arbitrary application data, or directory operations crash-safe.

Host fault tests interrupt every write/flush boundary and reopen from only
durable bytes. QEMU acceptance assigns each architecture a private GPT disk,
uses a checksummed PRGN v1 record to match its exact disk, partition, and type
GUIDs, requires the selected partition to be exactly four blocks, and executes
the real virtio data/flush/commit/flush sequence. It then terminates the
process, reopens the medium in a fresh VM, and validates the on-media generation
after each boot. Using the selected record for an SCFG activation pointer
remains the next increment.
