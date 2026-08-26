//! Bounded boot mount manifests and deterministic stable-identity resolution.
#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;
#[cfg(test)]
extern crate std;

use alloc::string::String;
use alloc::vec::Vec;

/// Product-name-independent boot mount manifest v1 format identifier.
pub const BOOT_MOUNT_V1_MAGIC: [u8; 8] = *b"BMNTv1\0\0";
/// Maximum accepted encoded manifest size.
pub const MAX_MANIFEST_BYTES: usize = 4 * 1024;
/// Maximum number of configured mount entries.
pub const MAX_MOUNT_ENTRIES: usize = 16;
/// Maximum mount-name length.
pub const MAX_MOUNT_NAME_BYTES: usize = 32;
/// Maximum discovered candidates accepted by one resolution pass.
pub const MAX_DISCOVERED_VOLUMES: usize = 64;

const HEADER_BYTES: usize = 64;
const RECORD_BYTES: usize = 96;
const CHECKSUM_OFFSET: usize = 20;
const CHECKSUM_END: usize = 24;

/// Whether a selector names an unpartitioned device or one GPT partition.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum SelectorKind {
    /// The filesystem occupies the complete block device.
    WholeDevice = 1,
    /// The filesystem occupies one exactly identified GPT partition.
    GptPartition = 2,
}

/// Closed filesystem profiles understood by BMNT v1.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum FilesystemProfile {
    /// Strict FAT32 profile used by the EFI system partition provider.
    Fat32 = 1,
    /// Constrained clean ext4 read-only profile fixed by ADR 0017.
    Ext4V1 = 2,
}

/// Requested mount authority. Parsing this value does not grant it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum AccessMode {
    /// Mount without mutation authority.
    ReadOnly = 1,
    /// Request mutation authority from a later policy gate.
    ReadWrite = 2,
}

/// Effect of a missing configured volume on desired-system availability.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum AvailabilityPolicy {
    /// Absence is expected and does not make the desired system unavailable.
    Optional = 1,
    /// Absence retains recovery but makes the desired system unavailable.
    Required = 2,
}

/// Whether a validated volume attaches during boot or awaits explicit activation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum ActivationMode {
    /// Attach the volume during namespace composition.
    Auto = 1,
    /// Retain the prepared provider until an authorized runtime request.
    Manual = 2,
}

/// One nonzero stable 128-bit identifier in exact on-media byte order.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct StableIdentifier([u8; 16]);

impl StableIdentifier {
    /// Construct a nonzero identifier.
    ///
    /// # Errors
    ///
    /// Rejects the all-zero value reserved for an absent identifier.
    pub fn new(bytes: [u8; 16]) -> Result<Self, IdentityError> {
        if bytes.iter().all(|byte| *byte == 0) {
            return Err(IdentityError::Zero);
        }
        Ok(Self(bytes))
    }

    /// Exact bytes as stored by the source format.
    #[must_use]
    pub const fn bytes(self) -> [u8; 16] {
        self.0
    }
}

/// Invalid stable-identity construction.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IdentityError {
    /// An identifier was the reserved all-zero value.
    Zero,
    /// A FAT32 volume identifier was zero.
    ZeroFat32VolumeId,
}

/// Complete stable selector shared by manifest entries and discovery results.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct VolumeSelector {
    kind: SelectorKind,
    filesystem: FilesystemProfile,
    disk_guid: Option<StableIdentifier>,
    partition_guid: Option<StableIdentifier>,
    filesystem_identity: StableIdentifier,
}

impl VolumeSelector {
    /// Select a whole-device ext4 volume by its exact filesystem UUID.
    ///
    /// # Errors
    ///
    /// Rejects an all-zero UUID.
    pub fn whole_ext4(filesystem_uuid: [u8; 16]) -> Result<Self, IdentityError> {
        Ok(Self {
            kind: SelectorKind::WholeDevice,
            filesystem: FilesystemProfile::Ext4V1,
            disk_guid: None,
            partition_guid: None,
            filesystem_identity: StableIdentifier::new(filesystem_uuid)?,
        })
    }

    /// Select one GPT ext4 volume by disk, partition, and filesystem identity.
    ///
    /// # Errors
    ///
    /// Rejects any all-zero identifier.
    pub fn gpt_ext4(
        disk_guid: [u8; 16],
        partition_guid: [u8; 16],
        filesystem_uuid: [u8; 16],
    ) -> Result<Self, IdentityError> {
        Self::gpt(
            FilesystemProfile::Ext4V1,
            disk_guid,
            partition_guid,
            StableIdentifier::new(filesystem_uuid)?,
        )
    }

    /// Select one GPT FAT32 volume by disk, partition, and volume identity.
    ///
    /// # Errors
    ///
    /// Rejects zero GUIDs or a zero FAT32 volume ID.
    pub fn gpt_fat32(
        disk_guid: [u8; 16],
        partition_guid: [u8; 16],
        volume_id: u32,
    ) -> Result<Self, IdentityError> {
        if volume_id == 0 {
            return Err(IdentityError::ZeroFat32VolumeId);
        }
        let mut filesystem_identity = [0_u8; 16];
        filesystem_identity[..4].copy_from_slice(&volume_id.to_le_bytes());
        Self::gpt(
            FilesystemProfile::Fat32,
            disk_guid,
            partition_guid,
            StableIdentifier(filesystem_identity),
        )
    }

    fn gpt(
        filesystem: FilesystemProfile,
        disk_guid: [u8; 16],
        partition_guid: [u8; 16],
        filesystem_identity: StableIdentifier,
    ) -> Result<Self, IdentityError> {
        Ok(Self {
            kind: SelectorKind::GptPartition,
            filesystem,
            disk_guid: Some(StableIdentifier::new(disk_guid)?),
            partition_guid: Some(StableIdentifier::new(partition_guid)?),
            filesystem_identity,
        })
    }

    /// Selector namespace.
    #[must_use]
    pub const fn kind(self) -> SelectorKind {
        self.kind
    }

    /// Required filesystem provider profile.
    #[must_use]
    pub const fn filesystem(self) -> FilesystemProfile {
        self.filesystem
    }

    /// GPT disk GUID, absent for a whole-device selector.
    #[must_use]
    pub const fn disk_guid(self) -> Option<StableIdentifier> {
        self.disk_guid
    }

    /// GPT unique partition GUID, absent for a whole-device selector.
    #[must_use]
    pub const fn partition_guid(self) -> Option<StableIdentifier> {
        self.partition_guid
    }

    /// Profile-specific filesystem identity.
    #[must_use]
    pub const fn filesystem_identity(self) -> StableIdentifier {
        self.filesystem_identity
    }
}

/// One fully validated manifest entry.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MountEntry {
    name: String,
    filesystem: FilesystemProfile,
    access: AccessMode,
    availability: AvailabilityPolicy,
    activation: ActivationMode,
    selector: VolumeSelector,
}

impl MountEntry {
    /// Name below `/vol`, including the reserved `root` and `boot` roles.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Filesystem provider profile required before mount.
    #[must_use]
    pub const fn filesystem(&self) -> FilesystemProfile {
        self.filesystem
    }

    /// Requested access policy, subject to later authority checks.
    #[must_use]
    pub const fn access(&self) -> AccessMode {
        self.access
    }

    /// Missing-volume policy.
    #[must_use]
    pub const fn availability(&self) -> AvailabilityPolicy {
        self.availability
    }

    /// Boot-time or explicitly requested activation policy.
    #[must_use]
    pub const fn activation(&self) -> ActivationMode {
        self.activation
    }

    /// Exact stable selector.
    #[must_use]
    pub const fn selector(&self) -> VolumeSelector {
        self.selector
    }
}

/// Fully validated immutable boot mount policy.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BootMountManifest {
    entries: Vec<MountEntry>,
}

impl BootMountManifest {
    /// Canonically name-sorted mount entries.
    #[must_use]
    pub fn entries(&self) -> &[MountEntry] {
        &self.entries
    }

    /// Resolve all configured entries against bounded discovered identities.
    ///
    /// # Errors
    ///
    /// Rejects a candidate set above the hard discovery ceiling or allocation
    /// failure before returning partial resolution state.
    pub fn resolve(
        &self,
        candidates: &[VolumeSelector],
    ) -> Result<MountResolution, ResolutionError> {
        if candidates.len() > MAX_DISCOVERED_VOLUMES {
            return Err(ResolutionError::CandidateLimit);
        }
        let mut entries = Vec::new();
        entries
            .try_reserve_exact(self.entries.len())
            .map_err(|_| ResolutionError::MetadataExhausted)?;
        let mut desired_system_available = true;
        for entry in &self.entries {
            let mut first = None;
            let mut ambiguous = false;
            for (index, candidate) in candidates.iter().enumerate() {
                if *candidate != entry.selector {
                    continue;
                }
                if first.is_some() {
                    ambiguous = true;
                    break;
                }
                first = Some(index);
            }
            let state = if ambiguous {
                desired_system_available = false;
                MatchState::Ambiguous
            } else if let Some(candidate_index) = first {
                MatchState::Matched {
                    candidate_index: u8::try_from(candidate_index)
                        .map_err(|_| ResolutionError::CandidateLimit)?,
                }
            } else {
                if entry.availability == AvailabilityPolicy::Required {
                    desired_system_available = false;
                }
                MatchState::Missing
            };
            entries.push(EntryResolution { state });
        }
        Ok(MountResolution {
            entries,
            desired_system_available,
        })
    }
}

/// Stable manifest rejection reasons.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ManifestError {
    /// Magic, version, size, checksum, flags, or reserved header bytes failed.
    InvalidHeader,
    /// An entry enum, reserved field, identity, or role/profile rule failed.
    InvalidEntry,
    /// A name or string-table placement was invalid or noncanonical.
    InvalidString,
    /// Two entries name the same stable selector.
    DuplicateSelector,
    /// The bounded parser could not retain validated metadata.
    MetadataExhausted,
}

/// Parse one allocation-bounded canonical BMNT v1 image.
///
/// # Errors
///
/// Rejects every unknown version, enum, flag, nonzero reserved byte, invalid
/// length/checksum, noncanonical string, duplicate name or selector, invalid
/// role/profile pairing, and allocation failure transactionally.
pub fn parse_manifest(bytes: &[u8]) -> Result<BootMountManifest, ManifestError> {
    if bytes.len() < HEADER_BYTES
        || bytes.len() > MAX_MANIFEST_BYTES
        || bytes.get(..8) != Some(&BOOT_MOUNT_V1_MAGIC)
        || read_u16(bytes, 8)? != 1
        || read_u16(bytes, 10)? != 1
        || usize::from(read_u16(bytes, 12)?) != HEADER_BYTES
        || usize::from(read_u16(bytes, 14)?) != RECORD_BYTES
        || usize::try_from(read_u32(bytes, 16)?).map_err(|_| ManifestError::InvalidHeader)?
            != bytes.len()
        || read_u16(bytes, 26)? != 0
        || bytes[32..HEADER_BYTES].iter().any(|byte| *byte != 0)
    {
        return Err(ManifestError::InvalidHeader);
    }
    let expected_checksum = read_u32(bytes, CHECKSUM_OFFSET)?;
    if crc32_with_zeroed_checksum(bytes) != expected_checksum {
        return Err(ManifestError::InvalidHeader);
    }
    let entry_count = usize::from(read_u16(bytes, 24)?);
    let string_bytes =
        usize::try_from(read_u32(bytes, 28)?).map_err(|_| ManifestError::InvalidHeader)?;
    let record_bytes = entry_count
        .checked_mul(RECORD_BYTES)
        .ok_or(ManifestError::InvalidHeader)?;
    let string_start = HEADER_BYTES
        .checked_add(record_bytes)
        .ok_or(ManifestError::InvalidHeader)?;
    if entry_count > MAX_MOUNT_ENTRIES
        || string_start.checked_add(string_bytes) != Some(bytes.len())
    {
        return Err(ManifestError::InvalidHeader);
    }
    let strings = bytes
        .get(string_start..)
        .ok_or(ManifestError::InvalidHeader)?;
    let mut entries = Vec::new();
    entries
        .try_reserve_exact(entry_count)
        .map_err(|_| ManifestError::MetadataExhausted)?;
    let mut expected_string_offset = 0_usize;
    for index in 0..entry_count {
        let start = HEADER_BYTES
            .checked_add(
                index
                    .checked_mul(RECORD_BYTES)
                    .ok_or(ManifestError::InvalidHeader)?,
            )
            .ok_or(ManifestError::InvalidHeader)?;
        let record = bytes
            .get(start..start + RECORD_BYTES)
            .ok_or(ManifestError::InvalidHeader)?;
        let entry = parse_entry(record, strings, expected_string_offset)?;
        expected_string_offset = expected_string_offset
            .checked_add(entry.name.len())
            .ok_or(ManifestError::InvalidString)?;
        if entries
            .last()
            .is_some_and(|previous: &MountEntry| previous.name >= entry.name)
        {
            return Err(ManifestError::InvalidString);
        }
        if entries
            .iter()
            .any(|previous| previous.selector == entry.selector)
        {
            return Err(ManifestError::DuplicateSelector);
        }
        entries.push(entry);
    }
    if expected_string_offset != strings.len() {
        return Err(ManifestError::InvalidString);
    }
    Ok(BootMountManifest { entries })
}

fn parse_entry(
    record: &[u8],
    strings: &[u8],
    expected_string_offset: usize,
) -> Result<MountEntry, ManifestError> {
    if record.len() != RECORD_BYTES
        || record[11..16].iter().any(|byte| *byte != 0)
        || record[64..].iter().any(|byte| *byte != 0)
    {
        return Err(ManifestError::InvalidEntry);
    }
    let activation = match record[10] {
        1 => ActivationMode::Auto,
        2 => ActivationMode::Manual,
        _ => return Err(ManifestError::InvalidEntry),
    };
    let kind = match record[0] {
        1 => SelectorKind::WholeDevice,
        2 => SelectorKind::GptPartition,
        _ => return Err(ManifestError::InvalidEntry),
    };
    let filesystem = match record[1] {
        1 => FilesystemProfile::Fat32,
        2 => FilesystemProfile::Ext4V1,
        _ => return Err(ManifestError::InvalidEntry),
    };
    let access = match record[2] {
        1 => AccessMode::ReadOnly,
        2 => AccessMode::ReadWrite,
        _ => return Err(ManifestError::InvalidEntry),
    };
    let availability = match record[3] {
        1 => AvailabilityPolicy::Optional,
        2 => AvailabilityPolicy::Required,
        _ => return Err(ManifestError::InvalidEntry),
    };
    let name_offset =
        usize::try_from(read_u32(record, 4)?).map_err(|_| ManifestError::InvalidString)?;
    let name_bytes = usize::from(read_u16(record, 8)?);
    if name_offset != expected_string_offset || name_bytes == 0 || name_bytes > MAX_MOUNT_NAME_BYTES
    {
        return Err(ManifestError::InvalidString);
    }
    let name_end = name_offset
        .checked_add(name_bytes)
        .ok_or(ManifestError::InvalidString)?;
    let name_raw = strings
        .get(name_offset..name_end)
        .ok_or(ManifestError::InvalidString)?;
    let name = core::str::from_utf8(name_raw).map_err(|_| ManifestError::InvalidString)?;
    if !name
        .bytes()
        .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
    {
        return Err(ManifestError::InvalidString);
    }
    if (name == "root"
        && (filesystem != FilesystemProfile::Ext4V1 || activation != ActivationMode::Auto))
        || (name == "boot" && filesystem != FilesystemProfile::Fat32)
    {
        return Err(ManifestError::InvalidEntry);
    }
    let disk = array_16(record, 16)?;
    let partition = array_16(record, 32)?;
    let filesystem_raw = array_16(record, 48)?;
    let selector = parse_selector(kind, filesystem, disk, partition, filesystem_raw)?;
    let mut retained_name = String::new();
    retained_name
        .try_reserve_exact(name.len())
        .map_err(|_| ManifestError::MetadataExhausted)?;
    retained_name.push_str(name);
    Ok(MountEntry {
        name: retained_name,
        filesystem,
        access,
        availability,
        activation,
        selector,
    })
}

fn parse_selector(
    kind: SelectorKind,
    filesystem: FilesystemProfile,
    disk: [u8; 16],
    partition: [u8; 16],
    filesystem_raw: [u8; 16],
) -> Result<VolumeSelector, ManifestError> {
    let filesystem_identity = parse_filesystem_identity(filesystem, filesystem_raw)?;
    match kind {
        SelectorKind::WholeDevice => {
            if filesystem != FilesystemProfile::Ext4V1
                || disk.iter().any(|byte| *byte != 0)
                || partition.iter().any(|byte| *byte != 0)
            {
                return Err(ManifestError::InvalidEntry);
            }
            Ok(VolumeSelector {
                kind,
                filesystem,
                disk_guid: None,
                partition_guid: None,
                filesystem_identity,
            })
        }
        SelectorKind::GptPartition => Ok(VolumeSelector {
            kind,
            filesystem,
            disk_guid: Some(StableIdentifier::new(disk).map_err(|_| ManifestError::InvalidEntry)?),
            partition_guid: Some(
                StableIdentifier::new(partition).map_err(|_| ManifestError::InvalidEntry)?,
            ),
            filesystem_identity,
        }),
    }
}

fn parse_filesystem_identity(
    filesystem: FilesystemProfile,
    bytes: [u8; 16],
) -> Result<StableIdentifier, ManifestError> {
    let identity = StableIdentifier::new(bytes).map_err(|_| ManifestError::InvalidEntry)?;
    if filesystem == FilesystemProfile::Fat32 && bytes[4..].iter().any(|byte| *byte != 0) {
        return Err(ManifestError::InvalidEntry);
    }
    Ok(identity)
}

/// Result for one manifest entry, in canonical manifest order.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EntryResolution {
    state: MatchState,
}

impl EntryResolution {
    /// Stable match state for this entry.
    #[must_use]
    pub const fn state(self) -> MatchState {
        self.state
    }
}

/// Deterministic selector outcome.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MatchState {
    /// No discovered candidate supplied every configured identity.
    Missing,
    /// Exactly one candidate supplied every configured identity.
    Matched {
        /// Index in the candidate slice passed to [`BootMountManifest::resolve`].
        candidate_index: u8,
    },
    /// More than one candidate supplied the same complete identity tuple.
    Ambiguous,
}

/// Complete bounded manifest resolution.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MountResolution {
    entries: Vec<EntryResolution>,
    desired_system_available: bool,
}

impl MountResolution {
    /// Per-entry states in canonical manifest order.
    #[must_use]
    pub fn entries(&self) -> &[EntryResolution] {
        &self.entries
    }

    /// Whether no required entry is missing and no selector is ambiguous.
    #[must_use]
    pub const fn desired_system_available(&self) -> bool {
        self.desired_system_available
    }
}

/// Stable resolution failures unrelated to media presence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ResolutionError {
    /// Candidate count exceeds [`MAX_DISCOVERED_VOLUMES`].
    CandidateLimit,
    /// Resolution metadata could not be retained.
    MetadataExhausted,
}

fn read_u16(bytes: &[u8], offset: usize) -> Result<u16, ManifestError> {
    let raw = bytes
        .get(offset..offset + 2)
        .ok_or(ManifestError::InvalidHeader)?;
    Ok(u16::from_le_bytes([raw[0], raw[1]]))
}

fn read_u32(bytes: &[u8], offset: usize) -> Result<u32, ManifestError> {
    let raw = bytes
        .get(offset..offset + 4)
        .ok_or(ManifestError::InvalidHeader)?;
    Ok(u32::from_le_bytes([raw[0], raw[1], raw[2], raw[3]]))
}

fn array_16(bytes: &[u8], offset: usize) -> Result<[u8; 16], ManifestError> {
    bytes
        .get(offset..offset + 16)
        .ok_or(ManifestError::InvalidEntry)?
        .try_into()
        .map_err(|_| ManifestError::InvalidEntry)
}

fn crc32_with_zeroed_checksum(bytes: &[u8]) -> u32 {
    let mut crc = u32::MAX;
    for (index, byte) in bytes.iter().copied().enumerate() {
        let byte = if (CHECKSUM_OFFSET..CHECKSUM_END).contains(&index) {
            0
        } else {
            byte
        };
        crc ^= u32::from(byte);
        for _ in 0..8 {
            let mask = 0_u32.wrapping_sub(crc & 1);
            crc = (crc >> 1) ^ (0xedb8_8320 & mask);
        }
    }
    !crc
}

#[cfg(test)]
mod tests {
    use alloc::vec;
    use alloc::vec::Vec;

    use super::{
        AccessMode, ActivationMode, AvailabilityPolicy, BOOT_MOUNT_V1_MAGIC, FilesystemProfile,
        HEADER_BYTES, IdentityError, MAX_DISCOVERED_VOLUMES, MAX_MOUNT_ENTRIES, ManifestError,
        MatchState, RECORD_BYTES, ResolutionError, SelectorKind, VolumeSelector,
        crc32_with_zeroed_checksum, parse_manifest,
    };

    #[derive(Clone)]
    struct EncodedEntry<'a> {
        name: &'a str,
        access: AccessMode,
        availability: AvailabilityPolicy,
        activation: ActivationMode,
        selector: VolumeSelector,
    }

    fn id(byte: u8) -> [u8; 16] {
        [byte; 16]
    }

    fn root_selector() -> VolumeSelector {
        VolumeSelector::gpt_ext4(id(1), id(2), id(3)).unwrap_or_else(|_| std::process::abort())
    }

    fn boot_selector() -> VolumeSelector {
        VolumeSelector::gpt_fat32(id(1), id(4), 0x1234_5678)
            .unwrap_or_else(|_| std::process::abort())
    }

    fn whole_selector() -> VolumeSelector {
        VolumeSelector::whole_ext4(id(9)).unwrap_or_else(|_| std::process::abort())
    }

    fn entry(
        name: &str,
        availability: AvailabilityPolicy,
        selector: VolumeSelector,
    ) -> EncodedEntry<'_> {
        EncodedEntry {
            name,
            access: AccessMode::ReadOnly,
            availability,
            activation: ActivationMode::Auto,
            selector,
        }
    }

    fn encode(entries: &[EncodedEntry<'_>]) -> Vec<u8> {
        let string_bytes = entries.iter().map(|entry| entry.name.len()).sum::<usize>();
        let total = HEADER_BYTES + entries.len() * RECORD_BYTES + string_bytes;
        let mut bytes = vec![0_u8; total];
        bytes[..8].copy_from_slice(&BOOT_MOUNT_V1_MAGIC);
        put_u16(&mut bytes, 8, 1);
        put_u16(&mut bytes, 10, 1);
        put_u16(&mut bytes, 12, to_u16(HEADER_BYTES));
        put_u16(&mut bytes, 14, to_u16(RECORD_BYTES));
        put_u32(&mut bytes, 16, to_u32(total));
        put_u16(&mut bytes, 24, to_u16(entries.len()));
        put_u32(&mut bytes, 28, to_u32(string_bytes));
        let string_start = HEADER_BYTES + entries.len() * RECORD_BYTES;
        let mut string_offset = 0;
        for (index, entry) in entries.iter().enumerate() {
            let start = HEADER_BYTES + index * RECORD_BYTES;
            bytes[start] = entry.selector.kind as u8;
            bytes[start + 1] = entry.selector.filesystem as u8;
            bytes[start + 2] = entry.access as u8;
            bytes[start + 3] = entry.availability as u8;
            bytes[start + 10] = entry.activation as u8;
            put_u32(&mut bytes, start + 4, to_u32(string_offset));
            put_u16(&mut bytes, start + 8, to_u16(entry.name.len()));
            if let Some(disk) = entry.selector.disk_guid {
                bytes[start + 16..start + 32].copy_from_slice(&disk.bytes());
            }
            if let Some(partition) = entry.selector.partition_guid {
                bytes[start + 32..start + 48].copy_from_slice(&partition.bytes());
            }
            bytes[start + 48..start + 64]
                .copy_from_slice(&entry.selector.filesystem_identity.bytes());
            let name_end = string_offset + entry.name.len();
            bytes[string_start + string_offset..string_start + name_end]
                .copy_from_slice(entry.name.as_bytes());
            string_offset = name_end;
        }
        refresh_checksum(&mut bytes);
        bytes
    }

    fn refresh_checksum(bytes: &mut [u8]) {
        bytes[20..24].fill(0);
        put_u32(bytes, 20, crc32_with_zeroed_checksum(bytes));
    }

    fn put_u16(bytes: &mut [u8], offset: usize, value: u16) {
        bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
    }

    fn put_u32(bytes: &mut [u8], offset: usize, value: u32) {
        bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }

    fn to_u8(value: usize) -> u8 {
        u8::try_from(value).unwrap_or_else(|_| std::process::abort())
    }

    fn to_u16(value: usize) -> u16 {
        u16::try_from(value).unwrap_or_else(|_| std::process::abort())
    }

    fn to_u32(value: usize) -> u32 {
        u32::try_from(value).unwrap_or_else(|_| std::process::abort())
    }

    fn valid_entries() -> Vec<EncodedEntry<'static>> {
        let mut data = entry("data", AvailabilityPolicy::Optional, whole_selector());
        data.access = AccessMode::ReadWrite;
        vec![
            entry("boot", AvailabilityPolicy::Optional, boot_selector()),
            data,
            entry("root", AvailabilityPolicy::Required, root_selector()),
        ]
    }

    #[test]
    fn parses_canonical_roles_and_policies() {
        let manifest =
            parse_manifest(&encode(&valid_entries())).unwrap_or_else(|_| std::process::abort());
        assert_eq!(manifest.entries().len(), 3);
        let boot = &manifest.entries()[0];
        assert_eq!(boot.name(), "boot");
        assert_eq!(boot.filesystem(), FilesystemProfile::Fat32);
        assert_eq!(boot.access(), AccessMode::ReadOnly);
        assert_eq!(boot.availability(), AvailabilityPolicy::Optional);
        assert_eq!(boot.activation(), ActivationMode::Auto);
        assert_eq!(boot.selector().kind(), SelectorKind::GptPartition);
        assert_eq!(
            boot.selector()
                .disk_guid()
                .map(super::StableIdentifier::bytes),
            Some(id(1))
        );
        assert_eq!(
            boot.selector()
                .partition_guid()
                .map(super::StableIdentifier::bytes),
            Some(id(4))
        );
        assert_eq!(
            manifest.entries()[1].selector().kind(),
            SelectorKind::WholeDevice
        );
        assert_eq!(manifest.entries()[1].access(), AccessMode::ReadWrite);
        assert_eq!(manifest.entries()[2].name(), "root");
        assert_eq!(
            manifest.entries()[2].filesystem(),
            FilesystemProfile::Ext4V1
        );
    }

    #[test]
    fn empty_manifest_is_canonical_diskless_policy() {
        let manifest = parse_manifest(&encode(&[])).unwrap_or_else(|_| std::process::abort());
        assert!(manifest.entries().is_empty());
        let resolution = manifest
            .resolve(&[])
            .unwrap_or_else(|_| std::process::abort());
        assert!(resolution.entries().is_empty());
        assert!(resolution.desired_system_available());
    }

    #[test]
    fn minor_one_manual_is_canonical_and_old_minor_is_rejected() {
        let mut entries = valid_entries();
        entries[1].activation = ActivationMode::Manual;
        let manifest = parse_manifest(&encode(&entries)).unwrap_or_else(|_| std::process::abort());
        assert_eq!(manifest.entries()[1].activation(), ActivationMode::Manual);

        let mut legacy = encode(&valid_entries());
        put_u16(&mut legacy, 10, 0);
        for index in 0..valid_entries().len() {
            legacy[HEADER_BYTES + index * RECORD_BYTES + 10] = 0;
        }
        refresh_checksum(&mut legacy);
        assert_eq!(parse_manifest(&legacy), Err(ManifestError::InvalidHeader));
    }

    #[test]
    fn exact_matching_ignores_unconfigured_and_mismatched_media() {
        let manifest =
            parse_manifest(&encode(&valid_entries())).unwrap_or_else(|_| std::process::abort());
        let wrong_root =
            VolumeSelector::gpt_ext4(id(1), id(2), id(8)).unwrap_or_else(|_| std::process::abort());
        let candidates = [wrong_root, root_selector(), boot_selector()];
        let resolution = manifest
            .resolve(&candidates)
            .unwrap_or_else(|_| std::process::abort());
        assert_eq!(
            resolution.entries()[0].state(),
            MatchState::Matched { candidate_index: 2 }
        );
        assert_eq!(resolution.entries()[1].state(), MatchState::Missing);
        assert_eq!(
            resolution.entries()[2].state(),
            MatchState::Matched { candidate_index: 1 }
        );
        assert!(resolution.desired_system_available());
    }

    #[test]
    fn every_gpt_identity_must_match() {
        let encoded = encode(&[entry("root", AvailabilityPolicy::Required, root_selector())]);
        let manifest = parse_manifest(&encoded).unwrap_or_else(|_| std::process::abort());
        let candidates = [
            VolumeSelector::gpt_ext4(id(7), id(2), id(3)).unwrap_or_else(|_| std::process::abort()),
            VolumeSelector::gpt_ext4(id(1), id(7), id(3)).unwrap_or_else(|_| std::process::abort()),
            VolumeSelector::gpt_ext4(id(1), id(2), id(7)).unwrap_or_else(|_| std::process::abort()),
        ];
        let resolution = manifest
            .resolve(&candidates)
            .unwrap_or_else(|_| std::process::abort());
        assert_eq!(resolution.entries()[0].state(), MatchState::Missing);
        assert!(!resolution.desired_system_available());
    }

    #[test]
    fn duplicate_discovered_identity_is_ambiguous() {
        let encoded = encode(&[entry("root", AvailabilityPolicy::Required, root_selector())]);
        let manifest = parse_manifest(&encoded).unwrap_or_else(|_| std::process::abort());
        let resolution = manifest
            .resolve(&[root_selector(), root_selector()])
            .unwrap_or_else(|_| std::process::abort());
        assert_eq!(resolution.entries()[0].state(), MatchState::Ambiguous);
        assert!(!resolution.desired_system_available());
    }

    #[test]
    fn optional_missing_is_available_but_required_missing_is_not() {
        let optional = parse_manifest(&encode(&[entry(
            "data",
            AvailabilityPolicy::Optional,
            whole_selector(),
        )]))
        .unwrap_or_else(|_| std::process::abort());
        assert!(
            optional
                .resolve(&[])
                .unwrap_or_else(|_| std::process::abort())
                .desired_system_available()
        );
        let required = parse_manifest(&encode(&[entry(
            "data",
            AvailabilityPolicy::Required,
            whole_selector(),
        )]))
        .unwrap_or_else(|_| std::process::abort());
        assert!(
            !required
                .resolve(&[])
                .unwrap_or_else(|_| std::process::abort())
                .desired_system_available()
        );
    }

    #[test]
    fn header_checksum_reserved_and_length_fail_closed() {
        let mut checksum = encode(&valid_entries());
        checksum[40] ^= 1;
        assert_eq!(parse_manifest(&checksum), Err(ManifestError::InvalidHeader));

        let mut reserved = encode(&valid_entries());
        reserved[32] = 1;
        refresh_checksum(&mut reserved);
        assert_eq!(parse_manifest(&reserved), Err(ManifestError::InvalidHeader));

        let mut length = encode(&valid_entries());
        let wrong_length = to_u32(length.len()) + 1;
        put_u32(&mut length, 16, wrong_length);
        refresh_checksum(&mut length);
        assert_eq!(parse_manifest(&length), Err(ManifestError::InvalidHeader));
    }

    #[test]
    fn entry_enums_reserved_fields_and_roles_fail_closed() {
        for offset in [0_usize, 1, 2, 3] {
            let mut invalid = encode(&valid_entries());
            invalid[HEADER_BYTES + offset] = 0xff;
            refresh_checksum(&mut invalid);
            assert_eq!(parse_manifest(&invalid), Err(ManifestError::InvalidEntry));
        }

        let mut reserved = encode(&valid_entries());
        reserved[HEADER_BYTES + 64] = 1;
        refresh_checksum(&mut reserved);
        assert_eq!(parse_manifest(&reserved), Err(ManifestError::InvalidEntry));

        let mut root_fat = encode(&valid_entries());
        let root_record = HEADER_BYTES + 2 * RECORD_BYTES;
        root_fat[root_record + 1] = FilesystemProfile::Fat32 as u8;
        root_fat[root_record + 52..root_record + 64].fill(0);
        refresh_checksum(&mut root_fat);
        assert_eq!(parse_manifest(&root_fat), Err(ManifestError::InvalidEntry));
    }

    #[test]
    fn zero_noncanonical_and_whole_fat_identities_fail_closed() {
        let mut zero = encode(&valid_entries());
        zero[HEADER_BYTES + 16..HEADER_BYTES + 32].fill(0);
        refresh_checksum(&mut zero);
        assert_eq!(parse_manifest(&zero), Err(ManifestError::InvalidEntry));

        let mut fat_tail = encode(&valid_entries());
        fat_tail[HEADER_BYTES + 53] = 1;
        refresh_checksum(&mut fat_tail);
        assert_eq!(parse_manifest(&fat_tail), Err(ManifestError::InvalidEntry));

        let mut whole_fat = encode(&[entry(
            "data",
            AvailabilityPolicy::Optional,
            whole_selector(),
        )]);
        whole_fat[HEADER_BYTES + 1] = FilesystemProfile::Fat32 as u8;
        whole_fat[HEADER_BYTES + 52..HEADER_BYTES + 64].fill(0);
        refresh_checksum(&mut whole_fat);
        assert_eq!(parse_manifest(&whole_fat), Err(ManifestError::InvalidEntry));
    }

    #[test]
    fn strings_are_gapless_valid_and_strictly_sorted() {
        let mut invalid_character = encode(&valid_entries());
        let strings = HEADER_BYTES + valid_entries().len() * RECORD_BYTES;
        invalid_character[strings] = b'B';
        refresh_checksum(&mut invalid_character);
        assert_eq!(
            parse_manifest(&invalid_character),
            Err(ManifestError::InvalidString)
        );

        let unsorted = encode(&[
            entry("root", AvailabilityPolicy::Required, root_selector()),
            entry("boot", AvailabilityPolicy::Optional, boot_selector()),
        ]);
        assert_eq!(parse_manifest(&unsorted), Err(ManifestError::InvalidString));

        let mut gap = encode(&valid_entries());
        put_u32(&mut gap, HEADER_BYTES + RECORD_BYTES + 4, 6);
        refresh_checksum(&mut gap);
        assert_eq!(parse_manifest(&gap), Err(ManifestError::InvalidString));
    }

    #[test]
    fn duplicate_selector_and_hard_limits_fail_closed() {
        let duplicate = encode(&[
            entry("data", AvailabilityPolicy::Optional, whole_selector()),
            entry("other", AvailabilityPolicy::Optional, whole_selector()),
        ]);
        assert_eq!(
            parse_manifest(&duplicate),
            Err(ManifestError::DuplicateSelector)
        );

        let too_many_entries = (0..=MAX_MOUNT_ENTRIES)
            .map(|index| {
                let name = alloc::format!("v{index:02}");
                let name: &'static str = std::boxed::Box::leak(name.into_boxed_str());
                let mut uuid = id(8);
                uuid[0] = to_u8(index) + 1;
                entry(
                    name,
                    AvailabilityPolicy::Optional,
                    VolumeSelector::whole_ext4(uuid).unwrap_or_else(|_| std::process::abort()),
                )
            })
            .collect::<Vec<_>>();
        assert_eq!(
            parse_manifest(&encode(&too_many_entries)),
            Err(ManifestError::InvalidHeader)
        );

        let manifest = parse_manifest(&encode(&[])).unwrap_or_else(|_| std::process::abort());
        assert_eq!(
            manifest.resolve(&vec![whole_selector(); MAX_DISCOVERED_VOLUMES + 1]),
            Err(ResolutionError::CandidateLimit)
        );
    }

    #[test]
    fn public_identity_constructors_reject_zero_values() {
        assert_eq!(
            VolumeSelector::whole_ext4([0; 16]),
            Err(IdentityError::Zero)
        );
        assert_eq!(
            VolumeSelector::gpt_ext4([0; 16], id(2), id(3)),
            Err(IdentityError::Zero)
        );
        assert_eq!(
            VolumeSelector::gpt_fat32(id(1), id(2), 0),
            Err(IdentityError::ZeroFat32VolumeId)
        );
    }
}
