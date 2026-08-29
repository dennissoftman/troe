//! Canonical bounded native-identity and foreign-mapping snapshots.
#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;
#[cfg(test)]
extern crate std;

use alloc::string::String;
use alloc::vec::Vec;
use core::cmp::Ordering;

/// Product-independent native identity-registry v1 identifier.
pub const REGISTRY_MAGIC: [u8; 8] = *b"IREGv1\0\0";
/// Product-independent foreign mapping-snapshot v1 identifier.
pub const MAPPING_MAGIC: [u8; 8] = *b"IMAPv1\0\0";
/// Product-independent mount identity-policy v1 identifier.
pub const MOUNT_MAGIC: [u8; 8] = *b"IMNTv1\0\0";
/// Product-independent native ACL v1 identifier.
pub const ACL_MAGIC: [u8; 8] = *b"IACLv1\0\0";
/// Exact mount-policy record size.
pub const MOUNT_BYTES: usize = 192;

const HEADER_BYTES: usize = 64;
const REGISTRY_RECORD_BYTES: usize = 64;
const MEMBERSHIP_BYTES: usize = 16;
const MAPPING_RECORD_BYTES: usize = 128;
const ACL_RECORD_BYTES: usize = 32;
const CHECKSUM_OFFSET: usize = 20;
const MOUNT_CHECKSUM_OFFSET: usize = 16;
const POSIX_SCHEME: u32 = 1;
const WINDOWS_SID_SCHEME: u32 = 2;

/// Stable identity-format parse or referential-integrity failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IdentityError {
    /// Header, version, length, flags, or reserved bytes were invalid.
    InvalidHeader,
    /// Integrity checksum failed.
    Checksum,
    /// A configured resource-policy ceiling was exceeded.
    Limit,
    /// One record, string, identifier, or foreign value was malformed.
    InvalidRecord,
    /// Canonical ordering or uniqueness was violated.
    NonCanonical,
    /// A referenced principal, group, mapping, or generation was absent/wrong.
    InvalidReference,
    /// Direct group membership contains a cycle.
    MembershipCycle,
    /// Two individually valid snapshots violate a permanent lifecycle invariant.
    InvalidTransition,
    /// Allocation failed within an already validated ceiling.
    Exhausted,
}

/// Resource ceilings for the standard cloud-VM deployment policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct IdentityLimits {
    principals: usize,
    memberships_per_principal: usize,
    mappings: usize,
    acl_entries: usize,
    encoded_bytes: usize,
}

impl IdentityLimits {
    /// Standard bounded identity ceilings.
    #[must_use]
    pub const fn standard() -> Self {
        Self {
            principals: 65_536,
            memberships_per_principal: 256,
            mappings: 262_144,
            acl_entries: 256,
            encoded_bytes: 64 * 1024 * 1024,
        }
    }
}

/// Opaque nonzero native principal identifier.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct PrincipalId([u8; 16]);

impl PrincipalId {
    /// Construct a nonzero opaque identifier.
    ///
    /// # Errors
    ///
    /// Rejects the all-zero identifier.
    pub fn new(bytes: [u8; 16]) -> Result<Self, IdentityError> {
        if bytes == [0; 16] {
            return Err(IdentityError::InvalidRecord);
        }
        Ok(Self(bytes))
    }

    /// Exact opaque identifier bytes.
    #[must_use]
    pub const fn bytes(self) -> [u8; 16] {
        self.0
    }
}

/// Opaque nonzero identity-domain identifier.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct DomainId([u8; 16]);

impl DomainId {
    /// Construct a nonzero opaque domain identifier.
    ///
    /// # Errors
    ///
    /// Rejects the all-zero identifier.
    pub fn new(bytes: [u8; 16]) -> Result<Self, IdentityError> {
        if bytes == [0; 16] {
            return Err(IdentityError::InvalidRecord);
        }
        Ok(Self(bytes))
    }

    /// Exact opaque identifier bytes.
    #[must_use]
    pub const fn bytes(self) -> [u8; 16] {
        self.0
    }
}

/// Closed native principal kinds.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum PrincipalKind {
    /// Interactive or noninteractive user actor.
    User = 1,
    /// Membership-bearing group actor.
    Group = 2,
    /// Service actor.
    Service = 3,
    /// Installation/system actor.
    System = 4,
}

impl PrincipalKind {
    fn parse(value: u8) -> Result<Self, IdentityError> {
        match value {
            1 => Ok(Self::User),
            2 => Ok(Self::Group),
            3 => Ok(Self::Service),
            4 => Ok(Self::System),
            _ => Err(IdentityError::InvalidRecord),
        }
    }
}

/// Closed native principal lifecycle states.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum PrincipalState {
    /// May participate in new authorization decisions.
    Active = 1,
    /// Retained but barred from new authorization decisions.
    Disabled = 2,
    /// Permanently retained deleted identifier.
    Tombstoned = 3,
}

impl PrincipalState {
    fn parse(value: u8) -> Result<Self, IdentityError> {
        match value {
            1 => Ok(Self::Active),
            2 => Ok(Self::Disabled),
            3 => Ok(Self::Tombstoned),
            _ => Err(IdentityError::InvalidRecord),
        }
    }
}

/// Optional compatibility lookup attribute; never an authority token.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CompatibilityId {
    /// POSIX-compatible user number.
    User(u32),
    /// POSIX-compatible group number.
    Group(u32),
}

/// One verified registry principal.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PrincipalRecord {
    id: PrincipalId,
    kind: PrincipalKind,
    state: PrincipalState,
    compatibility: Option<CompatibilityId>,
    label: String,
    memberships: Vec<PrincipalId>,
}

impl PrincipalRecord {
    /// Opaque authority identity.
    #[must_use]
    pub const fn id(&self) -> PrincipalId {
        self.id
    }

    /// Closed actor kind.
    #[must_use]
    pub const fn kind(&self) -> PrincipalKind {
        self.kind
    }

    /// Lifecycle state.
    #[must_use]
    pub const fn state(&self) -> PrincipalState {
        self.state
    }

    /// Optional compatibility lookup attribute.
    #[must_use]
    pub const fn compatibility(&self) -> Option<CompatibilityId> {
        self.compatibility
    }

    /// Bounded display-only UTF-8 label.
    #[must_use]
    pub fn label(&self) -> &str {
        &self.label
    }

    /// Canonically sorted direct group memberships.
    #[must_use]
    pub fn memberships(&self) -> &[PrincipalId] {
        &self.memberships
    }
}

/// Fully verified immutable native registry snapshot.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IdentityRegistry {
    generation: u64,
    principals: Vec<PrincipalRecord>,
}

impl IdentityRegistry {
    /// Parse a canonical checksummed IREG v1 snapshot.
    ///
    /// # Errors
    ///
    /// Rejects malformed lengths, resource excess, unsorted/duplicate records,
    /// invalid UTF-8, compatibility collisions, invalid memberships, and cycles.
    #[allow(clippy::too_many_lines)]
    pub fn parse(image: &[u8], limits: IdentityLimits) -> Result<Self, IdentityError> {
        check_common_header(image, REGISTRY_MAGIC, REGISTRY_RECORD_BYTES, limits)?;
        let principal_count = read_count(image, 24)?;
        let membership_count = read_count(image, 28)?;
        let label_bytes = read_count(image, 32)?;
        let generation = read_u64(image, 36)?;
        if generation == 0
            || principal_count > limits.principals
            || image[44..HEADER_BYTES].iter().any(|byte| *byte != 0)
        {
            return Err(IdentityError::Limit);
        }
        let record_end = checked_table_end(HEADER_BYTES, principal_count, REGISTRY_RECORD_BYTES)?;
        let membership_end = checked_table_end(record_end, membership_count, MEMBERSHIP_BYTES)?;
        let expected_end = membership_end
            .checked_add(label_bytes)
            .ok_or(IdentityError::InvalidHeader)?;
        if expected_end != image.len() {
            return Err(IdentityError::InvalidHeader);
        }
        let mut principals = Vec::new();
        principals
            .try_reserve_exact(principal_count)
            .map_err(|_| IdentityError::Exhausted)?;
        let mut membership_cursor = 0_usize;
        let mut label_cursor = 0_usize;
        let mut compatibility = Vec::new();
        compatibility
            .try_reserve_exact(principal_count)
            .map_err(|_| IdentityError::Exhausted)?;
        for index in 0..principal_count {
            let offset = HEADER_BYTES + index * REGISTRY_RECORD_BYTES;
            let raw = &image[offset..offset + REGISTRY_RECORD_BYTES];
            let id = PrincipalId::new(copy16(raw, 0)?)?;
            if principals
                .last()
                .is_some_and(|record: &PrincipalRecord| record.id >= id)
                || raw[19] != 0
                || raw[36..].iter().any(|byte| *byte != 0)
            {
                return Err(IdentityError::NonCanonical);
            }
            let kind = PrincipalKind::parse(raw[16])?;
            let state = PrincipalState::parse(raw[17])?;
            let compatibility_value = read_u32(raw, 20)?;
            let compatibility_id = match raw[18] {
                0 if compatibility_value == 0 => None,
                1 if kind == PrincipalKind::User => {
                    Some(CompatibilityId::User(compatibility_value))
                }
                2 if kind == PrincipalKind::Group => {
                    Some(CompatibilityId::Group(compatibility_value))
                }
                _ => return Err(IdentityError::InvalidRecord),
            };
            if let Some(value) = compatibility_id {
                compatibility.push(match value {
                    CompatibilityId::User(number) => (1_u8, number),
                    CompatibilityId::Group(number) => (2_u8, number),
                });
            }
            let label_offset = read_count(raw, 24)?;
            let label_length = usize::from(read_u16(raw, 28)?);
            let direct_count = usize::from(read_u16(raw, 30)?);
            let direct_start = read_count(raw, 32)?;
            if label_offset != label_cursor
                || direct_start != membership_cursor
                || label_length > 64
                || direct_count > limits.memberships_per_principal
                || (state == PrincipalState::Tombstoned && (label_length != 0 || direct_count != 0))
            {
                return Err(IdentityError::InvalidRecord);
            }
            let label_end = label_cursor
                .checked_add(label_length)
                .ok_or(IdentityError::InvalidRecord)?;
            let membership_record_end = membership_cursor
                .checked_add(direct_count)
                .ok_or(IdentityError::InvalidRecord)?;
            if label_end > label_bytes || membership_record_end > membership_count {
                return Err(IdentityError::InvalidRecord);
            }
            let label = String::from_utf8(
                image[membership_end + label_cursor..membership_end + label_end].to_vec(),
            )
            .map_err(|_| IdentityError::InvalidRecord)?;
            if label.chars().any(char::is_control) {
                return Err(IdentityError::InvalidRecord);
            }
            let mut memberships = Vec::new();
            memberships
                .try_reserve_exact(direct_count)
                .map_err(|_| IdentityError::Exhausted)?;
            for membership_index in membership_cursor..membership_record_end {
                let membership_offset = record_end + membership_index * MEMBERSHIP_BYTES;
                let target = PrincipalId::new(copy16(image, membership_offset)?)?;
                if target == id
                    || memberships
                        .last()
                        .is_some_and(|previous| *previous >= target)
                {
                    return Err(IdentityError::NonCanonical);
                }
                memberships.push(target);
            }
            principals.push(PrincipalRecord {
                id,
                kind,
                state,
                compatibility: compatibility_id,
                label,
                memberships,
            });
            membership_cursor = membership_record_end;
            label_cursor = label_end;
        }
        if membership_cursor != membership_count || label_cursor != label_bytes {
            return Err(IdentityError::NonCanonical);
        }
        compatibility.sort_unstable();
        if compatibility.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(IdentityError::NonCanonical);
        }
        let registry = Self {
            generation,
            principals,
        };
        registry.validate_memberships()?;
        Ok(registry)
    }

    fn validate_memberships(&self) -> Result<(), IdentityError> {
        for principal in &self.principals {
            for group in &principal.memberships {
                let target = self.get(*group).ok_or(IdentityError::InvalidReference)?;
                if target.kind != PrincipalKind::Group || target.state == PrincipalState::Tombstoned
                {
                    return Err(IdentityError::InvalidReference);
                }
            }
        }
        let mut colors = alloc::vec![0_u8; self.principals.len()];
        for start in 0..self.principals.len() {
            if self.principals[start].kind != PrincipalKind::Group || colors[start] == 2 {
                continue;
            }
            let mut stack = Vec::new();
            stack
                .try_reserve_exact(self.principals.len())
                .map_err(|_| IdentityError::Exhausted)?;
            stack.push((start, false));
            while let Some((index, exiting)) = stack.pop() {
                if exiting {
                    colors[index] = 2;
                    continue;
                }
                if colors[index] == 1 {
                    return Err(IdentityError::MembershipCycle);
                }
                if colors[index] == 2 {
                    continue;
                }
                colors[index] = 1;
                stack.push((index, true));
                for group in self.principals[index].memberships.iter().rev() {
                    let target = self
                        .index_of(*group)
                        .ok_or(IdentityError::InvalidReference)?;
                    if self.principals[target].kind == PrincipalKind::Group {
                        stack.push((target, false));
                    }
                }
            }
        }
        Ok(())
    }

    fn index_of(&self, id: PrincipalId) -> Option<usize> {
        self.principals
            .binary_search_by_key(&id, |record| record.id)
            .ok()
    }

    /// Registry generation bound into system activation.
    #[must_use]
    pub const fn generation(&self) -> u64 {
        self.generation
    }

    /// Canonically sorted records.
    #[must_use]
    pub fn principals(&self) -> &[PrincipalRecord] {
        &self.principals
    }

    /// Exact opaque-identifier lookup.
    #[must_use]
    pub fn get(&self, id: PrincipalId) -> Option<&PrincipalRecord> {
        self.index_of(id).map(|index| &self.principals[index])
    }
}

/// Foreign key kind retained separately from its scheme/value.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum ForeignKind {
    /// User-like foreign identity.
    User = 1,
    /// Group-like foreign identity.
    Group = 2,
}

impl ForeignKind {
    fn parse(value: u8) -> Result<Self, IdentityError> {
        match value {
            1 => Ok(Self::User),
            2 => Ok(Self::Group),
            _ => Err(IdentityError::InvalidRecord),
        }
    }
}

/// One canonical foreign-to-native mapping entry.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MappingEntry {
    scheme: u32,
    kind: ForeignKind,
    value: Vec<u8>,
    target: PrincipalId,
}

impl MappingEntry {
    /// Nonzero scheme identifier (`1` POSIX, `2` SID, other values opaque).
    #[must_use]
    pub const fn scheme(&self) -> u32 {
        self.scheme
    }

    /// Foreign user/group namespace.
    #[must_use]
    pub const fn kind(&self) -> ForeignKind {
        self.kind
    }

    /// Exact canonical foreign value bytes.
    #[must_use]
    pub fn value(&self) -> &[u8] {
        &self.value
    }

    /// Exact native target identifier.
    #[must_use]
    pub const fn target(&self) -> PrincipalId {
        self.target
    }
}

/// Fully verified immutable foreign mapping snapshot.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MappingSnapshot {
    domain: DomainId,
    version: u64,
    entries: Vec<MappingEntry>,
}

impl MappingSnapshot {
    /// Parse a canonical checksummed IMAP v1 snapshot.
    ///
    /// # Errors
    ///
    /// Rejects invalid domains/versions, ceilings, ordering, duplicates, POSIX
    /// widths, SID encodings, opaque-value bounds, and reserved bytes.
    pub fn parse(image: &[u8], limits: IdentityLimits) -> Result<Self, IdentityError> {
        check_common_header(image, MAPPING_MAGIC, MAPPING_RECORD_BYTES, limits)?;
        let count = read_count(image, 24)?;
        if count > limits.mappings || image[28..32].iter().any(|byte| *byte != 0) {
            return Err(IdentityError::Limit);
        }
        let version = read_u64(image, 32)?;
        let domain = DomainId::new(copy16(image, 40)?)?;
        if version == 0 || image[56..64].iter().any(|byte| *byte != 0) {
            return Err(IdentityError::InvalidHeader);
        }
        if checked_table_end(HEADER_BYTES, count, MAPPING_RECORD_BYTES)? != image.len() {
            return Err(IdentityError::InvalidHeader);
        }
        let mut entries = Vec::new();
        entries
            .try_reserve_exact(count)
            .map_err(|_| IdentityError::Exhausted)?;
        for index in 0..count {
            let offset = HEADER_BYTES + index * MAPPING_RECORD_BYTES;
            let raw = &image[offset..offset + MAPPING_RECORD_BYTES];
            let scheme = read_u32(raw, 0)?;
            let kind = ForeignKind::parse(raw[4])?;
            let length = usize::from(raw[5]);
            if scheme == 0
                || length == 0
                || length > 64
                || raw[6..8].iter().any(|byte| *byte != 0)
                || raw[24 + length..].iter().any(|byte| *byte != 0)
            {
                return Err(IdentityError::InvalidRecord);
            }
            let target = PrincipalId::new(copy16(raw, 8)?)?;
            let value = raw[24..24 + length].to_vec();
            validate_foreign_value(scheme, kind, &value)?;
            let entry = MappingEntry {
                scheme,
                kind,
                value,
                target,
            };
            if entries
                .last()
                .is_some_and(|previous| compare_mapping(previous, &entry) != Ordering::Less)
            {
                return Err(IdentityError::NonCanonical);
            }
            entries.push(entry);
        }
        Ok(Self {
            domain,
            version,
            entries,
        })
    }

    /// Cross-check every target against one exact native registry.
    ///
    /// # Errors
    ///
    /// Rejects absent, disabled/tombstoned, or user/group-incompatible targets.
    pub fn validate_against(&self, registry: &IdentityRegistry) -> Result<(), IdentityError> {
        for entry in &self.entries {
            let target = registry
                .get(entry.target)
                .ok_or(IdentityError::InvalidReference)?;
            let compatible = matches!(
                (entry.kind, target.kind),
                (ForeignKind::User, PrincipalKind::User)
                    | (ForeignKind::Group, PrincipalKind::Group)
            );
            if !compatible || target.state != PrincipalState::Active {
                return Err(IdentityError::InvalidReference);
            }
        }
        Ok(())
    }

    /// Bound foreign identity domain.
    #[must_use]
    pub const fn domain(&self) -> DomainId {
        self.domain
    }

    /// Monotonic mapping snapshot version.
    #[must_use]
    pub const fn version(&self) -> u64 {
        self.version
    }

    /// Canonically sorted complete mapping entries.
    #[must_use]
    pub fn entries(&self) -> &[MappingEntry] {
        &self.entries
    }
}

/// Closed persistent mount identity modes from ADR 0007.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum MountIdentityMode {
    /// Locally administered native mapping.
    NativeMapped = 1,
    /// Named immutable foreign mapping snapshot.
    ExplicitMapping = 2,
    /// Non-authorizing checked POSIX display offsets.
    ShiftedView = 3,
    /// Synthetic fixed native owner/group.
    FixedOwner = 4,
    /// Lossless raw metadata without authority resolution.
    ForeignUnmapped = 5,
    /// Recovery read-only data capability; metadata is informational.
    ReadOnlyUntrusted = 6,
}

impl MountIdentityMode {
    fn parse(value: u8) -> Result<Self, IdentityError> {
        match value {
            1 => Ok(Self::NativeMapped),
            2 => Ok(Self::ExplicitMapping),
            3 => Ok(Self::ShiftedView),
            4 => Ok(Self::FixedOwner),
            5 => Ok(Self::ForeignUnmapped),
            6 => Ok(Self::ReadOnlyUntrusted),
            _ => Err(IdentityError::InvalidRecord),
        }
    }
}

/// Exact verified mount identity-policy record.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MountPolicy {
    role: String,
    mode: MountIdentityMode,
    raw_metadata_lossless: bool,
    domain: Option<DomainId>,
    mapping_version: u64,
    owner: Option<PrincipalId>,
    group: Option<PrincipalId>,
    uid_shift: i64,
    gid_shift: i64,
}

impl MountPolicy {
    /// Parse an exact checksummed IMNT v1 record.
    ///
    /// # Errors
    ///
    /// Rejects invalid mode-specific fields, roles, flags, checksum, and
    /// noncanonical zero/reserved fields.
    pub fn parse(image: &[u8]) -> Result<Self, IdentityError> {
        if image.len() != MOUNT_BYTES
            || image.get(..8) != Some(&MOUNT_MAGIC)
            || read_u16(image, 8)? != 1
            || read_u16(image, 10)? != 0
            || usize::from(read_u16(image, 12)?) != MOUNT_BYTES
            || image[22..32].iter().any(|byte| *byte != 0)
            || image[136..].iter().any(|byte| *byte != 0)
        {
            return Err(IdentityError::InvalidHeader);
        }
        if crc32_zeroed(image, MOUNT_CHECKSUM_OFFSET)? != read_u32(image, MOUNT_CHECKSUM_OFFSET)? {
            return Err(IdentityError::Checksum);
        }
        let mode = MountIdentityMode::parse(image[14])?;
        let raw_metadata_lossless = match image[15] {
            0 => false,
            1 => true,
            _ => return Err(IdentityError::InvalidRecord),
        };
        let role_length = usize::from(read_u16(image, 20)?);
        if role_length == 0
            || role_length > 32
            || image[32 + role_length..64].iter().any(|byte| *byte != 0)
        {
            return Err(IdentityError::InvalidRecord);
        }
        let role = String::from_utf8(image[32..32 + role_length].to_vec())
            .map_err(|_| IdentityError::InvalidRecord)?;
        if !canonical_role(&role) {
            return Err(IdentityError::InvalidRecord);
        }
        let domain_bytes = copy16(image, 64)?;
        let owner_bytes = copy16(image, 88)?;
        let group_bytes = copy16(image, 104)?;
        let domain = optional_domain(domain_bytes)?;
        let owner = optional_principal(owner_bytes)?;
        let group = optional_principal(group_bytes)?;
        let mapping_version = read_u64(image, 80)?;
        let uid_shift = read_i64(image, 120)?;
        let gid_shift = read_i64(image, 128)?;
        match mode {
            MountIdentityMode::NativeMapped | MountIdentityMode::ExplicitMapping
                if domain.is_some()
                    && mapping_version != 0
                    && owner.is_none()
                    && group.is_none()
                    && uid_shift == 0
                    && gid_shift == 0 => {}
            MountIdentityMode::ShiftedView
                if domain.is_some()
                    && mapping_version == 0
                    && owner.is_none()
                    && group.is_none() => {}
            MountIdentityMode::FixedOwner
                if domain.is_none()
                    && mapping_version == 0
                    && owner.is_some()
                    && group.is_some()
                    && uid_shift == 0
                    && gid_shift == 0 => {}
            MountIdentityMode::ForeignUnmapped
                if domain.is_some()
                    && mapping_version == 0
                    && owner.is_none()
                    && group.is_none()
                    && uid_shift == 0
                    && gid_shift == 0 => {}
            MountIdentityMode::ReadOnlyUntrusted
                if mapping_version == 0
                    && owner.is_none()
                    && group.is_none()
                    && uid_shift == 0
                    && gid_shift == 0 => {}
            _ => return Err(IdentityError::InvalidRecord),
        }
        Ok(Self {
            role,
            mode,
            raw_metadata_lossless,
            domain,
            mapping_version,
            owner,
            group,
            uid_shift,
            gid_shift,
        })
    }

    /// Cross-check all mode-specific references against selected snapshots.
    ///
    /// # Errors
    ///
    /// Rejects absent/wrong mapping versions, domains, owners, or groups.
    pub fn validate_against(
        &self,
        registry: &IdentityRegistry,
        mapping: &MappingSnapshot,
    ) -> Result<(), IdentityError> {
        if matches!(
            self.mode,
            MountIdentityMode::NativeMapped | MountIdentityMode::ExplicitMapping
        ) && (self.domain != Some(mapping.domain) || self.mapping_version != mapping.version)
        {
            return Err(IdentityError::InvalidReference);
        }
        if let Some(owner) = self.owner {
            let record = registry.get(owner).ok_or(IdentityError::InvalidReference)?;
            if record.kind != PrincipalKind::User || record.state != PrincipalState::Active {
                return Err(IdentityError::InvalidReference);
            }
        }
        if let Some(group) = self.group {
            let record = registry.get(group).ok_or(IdentityError::InvalidReference)?;
            if record.kind != PrincipalKind::Group || record.state != PrincipalState::Active {
                return Err(IdentityError::InvalidReference);
            }
        }
        Ok(())
    }

    /// Canonical mount role.
    #[must_use]
    pub fn role(&self) -> &str {
        &self.role
    }
    /// Selected closed identity mode.
    #[must_use]
    pub const fn mode(&self) -> MountIdentityMode {
        self.mode
    }
    /// Whether raw security metadata is losslessly available.
    #[must_use]
    pub const fn raw_metadata_lossless(&self) -> bool {
        self.raw_metadata_lossless
    }
}

/// Closed POSIX-like native ACL entry tags.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum AclTag {
    /// Owning principal rights.
    Owner = 1,
    /// Named user principal rights.
    NamedUser = 2,
    /// Owning group rights.
    GroupObject = 3,
    /// Named group principal rights.
    NamedGroup = 4,
    /// Named/group-class mask.
    Mask = 5,
    /// Fallback other rights.
    Other = 6,
}

impl AclTag {
    fn parse(value: u8) -> Result<Self, IdentityError> {
        match value {
            1 => Ok(Self::Owner),
            2 => Ok(Self::NamedUser),
            3 => Ok(Self::GroupObject),
            4 => Ok(Self::NamedGroup),
            5 => Ok(Self::Mask),
            6 => Ok(Self::Other),
            _ => Err(IdentityError::InvalidRecord),
        }
    }
}

/// One verified native ACL entry.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AclEntry {
    tag: AclTag,
    rights: u8,
    principal: Option<PrincipalId>,
}

impl AclEntry {
    /// Closed entry tag.
    #[must_use]
    pub const fn tag(self) -> AclTag {
        self.tag
    }
    /// POSIX-style read/write/execute bits.
    #[must_use]
    pub const fn rights(self) -> u8 {
        self.rights
    }
    /// Principal for named user/group entries only.
    #[must_use]
    pub const fn principal(self) -> Option<PrincipalId> {
        self.principal
    }
}

/// Fully verified canonical native ACL.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NativeAcl {
    entries: Vec<AclEntry>,
}

impl NativeAcl {
    /// Parse a canonical checksummed IACL v1 image.
    ///
    /// # Errors
    ///
    /// Rejects invalid ceilings, ordering, duplicates, rights, principals,
    /// missing base entries, or a missing mask for named entries.
    pub fn parse(image: &[u8], limits: IdentityLimits) -> Result<Self, IdentityError> {
        check_common_header(image, ACL_MAGIC, ACL_RECORD_BYTES, limits)?;
        let count = read_count(image, 24)?;
        if count > limits.acl_entries || image[28..64].iter().any(|byte| *byte != 0) {
            return Err(IdentityError::Limit);
        }
        if checked_table_end(HEADER_BYTES, count, ACL_RECORD_BYTES)? != image.len() {
            return Err(IdentityError::InvalidHeader);
        }
        let mut entries = Vec::new();
        entries
            .try_reserve_exact(count)
            .map_err(|_| IdentityError::Exhausted)?;
        let mut base = [0_u8; 4];
        let mut has_named = false;
        for index in 0..count {
            let offset = HEADER_BYTES + index * ACL_RECORD_BYTES;
            let raw = &image[offset..offset + ACL_RECORD_BYTES];
            let tag = AclTag::parse(raw[0])?;
            let rights = raw[1];
            if rights & !0x7 != 0
                || raw[2..8].iter().any(|byte| *byte != 0)
                || raw[24..].iter().any(|byte| *byte != 0)
            {
                return Err(IdentityError::InvalidRecord);
            }
            let principal_bytes = copy16(raw, 8)?;
            let principal = match tag {
                AclTag::NamedUser | AclTag::NamedGroup => {
                    has_named = true;
                    Some(PrincipalId::new(principal_bytes)?)
                }
                _ if principal_bytes == [0; 16] => None,
                _ => return Err(IdentityError::InvalidRecord),
            };
            let entry = AclEntry {
                tag,
                rights,
                principal,
            };
            if entries
                .last()
                .is_some_and(|previous| compare_acl(*previous, entry) != Ordering::Less)
            {
                return Err(IdentityError::NonCanonical);
            }
            match tag {
                AclTag::Owner => base[0] = base[0].saturating_add(1),
                AclTag::GroupObject => base[1] = base[1].saturating_add(1),
                AclTag::Mask => base[2] = base[2].saturating_add(1),
                AclTag::Other => base[3] = base[3].saturating_add(1),
                AclTag::NamedUser | AclTag::NamedGroup => {}
            }
            entries.push(entry);
        }
        if base[0] != 1
            || base[1] != 1
            || base[3] != 1
            || base[2] > 1
            || (has_named && base[2] != 1)
        {
            return Err(IdentityError::InvalidRecord);
        }
        Ok(Self { entries })
    }

    /// Cross-check named entries against active native user/group records.
    ///
    /// # Errors
    ///
    /// Rejects absent, inactive, or kind-incompatible named principals.
    pub fn validate_against(&self, registry: &IdentityRegistry) -> Result<(), IdentityError> {
        for entry in &self.entries {
            let Some(id) = entry.principal else { continue };
            let target = registry.get(id).ok_or(IdentityError::InvalidReference)?;
            let compatible = matches!(
                (entry.tag, target.kind),
                (AclTag::NamedUser, PrincipalKind::User)
                    | (AclTag::NamedGroup, PrincipalKind::Group)
            );
            if !compatible || target.state != PrincipalState::Active {
                return Err(IdentityError::InvalidReference);
            }
        }
        Ok(())
    }

    /// Canonically ordered entries.
    #[must_use]
    pub fn entries(&self) -> &[AclEntry] {
        &self.entries
    }
}

/// Four cross-validated security metadata objects for one system generation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IdentitySnapshot {
    /// Selected registry.
    pub registry: IdentityRegistry,
    /// Selected immutable foreign mapping.
    pub mapping: MappingSnapshot,
    /// Selected mount identity policy.
    pub mount: MountPolicy,
    /// Selected native ACL policy fixture/root.
    pub acl: NativeAcl,
}

/// Parse and cross-validate all security objects selected by one generation.
///
/// # Errors
///
/// Returns any canonical parse, ceiling, generation, or cross-reference error.
pub fn validate_snapshot(
    registry: &[u8],
    mapping: &[u8],
    mount: &[u8],
    acl: &[u8],
    generation: u64,
    limits: IdentityLimits,
) -> Result<IdentitySnapshot, IdentityError> {
    let registry = IdentityRegistry::parse(registry, limits)?;
    if registry.generation != generation {
        return Err(IdentityError::InvalidReference);
    }
    let mapping = MappingSnapshot::parse(mapping, limits)?;
    mapping.validate_against(&registry)?;
    let mount = MountPolicy::parse(mount)?;
    mount.validate_against(&registry, &mapping)?;
    let acl = NativeAcl::parse(acl, limits)?;
    acl.validate_against(&registry)?;
    Ok(IdentitySnapshot {
        registry,
        mapping,
        mount,
        acl,
    })
}

/// Validate one generation's identity snapshot as a successor to another.
///
/// # Errors
///
/// Rejects non-increasing registry generations or mapping versions, identity
/// domain changes, removed principal records, principal-kind changes, and the
/// resurrection of a permanent tombstone.
pub fn validate_successor(
    predecessor: &IdentitySnapshot,
    successor: &IdentitySnapshot,
) -> Result<(), IdentityError> {
    if successor.registry.generation <= predecessor.registry.generation
        || successor.mapping.version <= predecessor.mapping.version
        || successor.mapping.domain != predecessor.mapping.domain
    {
        return Err(IdentityError::InvalidTransition);
    }
    for previous in &predecessor.registry.principals {
        let current = successor
            .registry
            .get(previous.id)
            .ok_or(IdentityError::InvalidTransition)?;
        if current.kind != previous.kind
            || (previous.state == PrincipalState::Tombstoned
                && current.state != PrincipalState::Tombstoned)
        {
            return Err(IdentityError::InvalidTransition);
        }
    }
    Ok(())
}

fn validate_foreign_value(
    scheme: u32,
    kind: ForeignKind,
    value: &[u8],
) -> Result<(), IdentityError> {
    match scheme {
        POSIX_SCHEME if value.len() == 4 => Ok(()),
        POSIX_SCHEME => Err(IdentityError::InvalidRecord),
        WINDOWS_SID_SCHEME => {
            if value.len() < 8 || value[0] != 1 || usize::from(value[1]) > 15 {
                return Err(IdentityError::InvalidRecord);
            }
            let expected = 8_usize
                .checked_add(usize::from(value[1]) * 4)
                .ok_or(IdentityError::InvalidRecord)?;
            if value.len() != expected {
                return Err(IdentityError::InvalidRecord);
            }
            let _ = kind;
            Ok(())
        }
        _ => Ok(()),
    }
}

fn compare_mapping(left: &MappingEntry, right: &MappingEntry) -> Ordering {
    (left.scheme, left.kind, left.value.as_slice()).cmp(&(
        right.scheme,
        right.kind,
        right.value.as_slice(),
    ))
}

fn compare_acl(left: AclEntry, right: AclEntry) -> Ordering {
    (left.tag as u8, left.principal.map(PrincipalId::bytes))
        .cmp(&(right.tag as u8, right.principal.map(PrincipalId::bytes)))
}

fn canonical_role(role: &str) -> bool {
    role.bytes().enumerate().all(|(index, byte)| {
        byte.is_ascii_lowercase() || (index != 0 && (byte.is_ascii_digit() || byte == b'-'))
    })
}

fn optional_principal(bytes: [u8; 16]) -> Result<Option<PrincipalId>, IdentityError> {
    if bytes == [0; 16] {
        Ok(None)
    } else {
        PrincipalId::new(bytes).map(Some)
    }
}

fn optional_domain(bytes: [u8; 16]) -> Result<Option<DomainId>, IdentityError> {
    if bytes == [0; 16] {
        Ok(None)
    } else {
        DomainId::new(bytes).map(Some)
    }
}

fn check_common_header(
    image: &[u8],
    magic: [u8; 8],
    record_bytes: usize,
    limits: IdentityLimits,
) -> Result<(), IdentityError> {
    if image.len() < HEADER_BYTES
        || image.len() > limits.encoded_bytes
        || image.get(..8) != Some(&magic)
        || read_u16(image, 8)? != 1
        || read_u16(image, 10)? != 0
        || usize::from(read_u16(image, 12)?) != HEADER_BYTES
        || usize::from(read_u16(image, 14)?) != record_bytes
        || read_count(image, 16)? != image.len()
    {
        return Err(IdentityError::InvalidHeader);
    }
    if crc32_zeroed(image, CHECKSUM_OFFSET)? != read_u32(image, CHECKSUM_OFFSET)? {
        return Err(IdentityError::Checksum);
    }
    Ok(())
}

fn checked_table_end(start: usize, count: usize, stride: usize) -> Result<usize, IdentityError> {
    count
        .checked_mul(stride)
        .and_then(|bytes| start.checked_add(bytes))
        .ok_or(IdentityError::InvalidHeader)
}

fn read_count(bytes: &[u8], offset: usize) -> Result<usize, IdentityError> {
    usize::try_from(read_u32(bytes, offset)?).map_err(|_| IdentityError::InvalidHeader)
}

fn read_u16(bytes: &[u8], offset: usize) -> Result<u16, IdentityError> {
    let raw = bytes
        .get(offset..offset + 2)
        .ok_or(IdentityError::InvalidHeader)?;
    Ok(u16::from_le_bytes([raw[0], raw[1]]))
}

fn read_u32(bytes: &[u8], offset: usize) -> Result<u32, IdentityError> {
    let raw = bytes
        .get(offset..offset + 4)
        .ok_or(IdentityError::InvalidHeader)?;
    Ok(u32::from_le_bytes([raw[0], raw[1], raw[2], raw[3]]))
}

fn read_u64(bytes: &[u8], offset: usize) -> Result<u64, IdentityError> {
    let raw = bytes
        .get(offset..offset + 8)
        .ok_or(IdentityError::InvalidHeader)?;
    Ok(u64::from_le_bytes(
        raw.try_into().map_err(|_| IdentityError::InvalidHeader)?,
    ))
}

fn read_i64(bytes: &[u8], offset: usize) -> Result<i64, IdentityError> {
    let raw = bytes
        .get(offset..offset + 8)
        .ok_or(IdentityError::InvalidHeader)?;
    Ok(i64::from_le_bytes(
        raw.try_into().map_err(|_| IdentityError::InvalidHeader)?,
    ))
}

fn copy16(bytes: &[u8], offset: usize) -> Result<[u8; 16], IdentityError> {
    bytes
        .get(offset..offset + 16)
        .ok_or(IdentityError::InvalidHeader)?
        .try_into()
        .map_err(|_| IdentityError::InvalidHeader)
}

fn crc32_zeroed(bytes: &[u8], zero_offset: usize) -> Result<u32, IdentityError> {
    if zero_offset
        .checked_add(4)
        .is_none_or(|end| end > bytes.len())
    {
        return Err(IdentityError::InvalidHeader);
    }
    Ok(troe_checksum::crc32_with_zeroed_field(bytes, zero_offset))
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    const USER: [u8; 16] = [1; 16];
    const GROUP: [u8; 16] = [2; 16];
    const DOMAIN: [u8; 16] = [3; 16];

    fn checksum(image: &mut [u8], offset: usize) {
        image[offset..offset + 4].fill(0);
        let value = crc32_zeroed(image, offset).unwrap_or(0);
        image[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }

    fn registry(group_membership: Option<[u8; 16]>) -> Vec<u8> {
        let membership_count = usize::from(group_membership.is_some());
        let labels = b"usergroup";
        let mut image = vec![0; 64 + 2 * 64 + membership_count * 16 + labels.len()];
        image[..8].copy_from_slice(&REGISTRY_MAGIC);
        image[8..10].copy_from_slice(&1_u16.to_le_bytes());
        image[12..14].copy_from_slice(&64_u16.to_le_bytes());
        image[14..16].copy_from_slice(&64_u16.to_le_bytes());
        let total = u32::try_from(image.len()).unwrap_or(0);
        image[16..20].copy_from_slice(&total.to_le_bytes());
        image[24..28].copy_from_slice(&2_u32.to_le_bytes());
        image[28..32].copy_from_slice(&u32::try_from(membership_count).unwrap_or(0).to_le_bytes());
        image[32..36].copy_from_slice(&u32::try_from(labels.len()).unwrap_or(0).to_le_bytes());
        image[36..44].copy_from_slice(&1_u64.to_le_bytes());
        let user = &mut image[64..128];
        user[..16].copy_from_slice(&USER);
        user[16] = PrincipalKind::User as u8;
        user[17] = PrincipalState::Active as u8;
        user[18] = 1;
        user[28..30].copy_from_slice(&4_u16.to_le_bytes());
        let group = &mut image[128..192];
        group[..16].copy_from_slice(&GROUP);
        group[16] = PrincipalKind::Group as u8;
        group[17] = PrincipalState::Active as u8;
        group[18] = 2;
        group[24..28].copy_from_slice(&4_u32.to_le_bytes());
        group[28..30].copy_from_slice(&5_u16.to_le_bytes());
        group[30..32].copy_from_slice(&u16::try_from(membership_count).unwrap_or(0).to_le_bytes());
        if let Some(target) = group_membership {
            image[192..208].copy_from_slice(&target);
        }
        let labels_start = 192 + membership_count * 16;
        image[labels_start..].copy_from_slice(labels);
        checksum(&mut image, CHECKSUM_OFFSET);
        image
    }

    fn cyclic_registry() -> Vec<u8> {
        let labels = b"firstsecond";
        let mut image = vec![0; 64 + 2 * 64 + 2 * 16 + labels.len()];
        image[..8].copy_from_slice(&REGISTRY_MAGIC);
        image[8..10].copy_from_slice(&1_u16.to_le_bytes());
        image[12..14].copy_from_slice(&64_u16.to_le_bytes());
        image[14..16].copy_from_slice(&64_u16.to_le_bytes());
        let total = u32::try_from(image.len()).unwrap_or(0);
        image[16..20].copy_from_slice(&total.to_le_bytes());
        image[24..28].copy_from_slice(&2_u32.to_le_bytes());
        image[28..32].copy_from_slice(&2_u32.to_le_bytes());
        image[32..36].copy_from_slice(&u32::try_from(labels.len()).unwrap_or(0).to_le_bytes());
        image[36..44].copy_from_slice(&1_u64.to_le_bytes());
        let first = &mut image[64..128];
        first[..16].copy_from_slice(&USER);
        first[16] = PrincipalKind::Group as u8;
        first[17] = PrincipalState::Active as u8;
        first[18] = 2;
        first[20..24].copy_from_slice(&1_u32.to_le_bytes());
        first[28..30].copy_from_slice(&5_u16.to_le_bytes());
        first[30..32].copy_from_slice(&1_u16.to_le_bytes());
        let second = &mut image[128..192];
        second[..16].copy_from_slice(&GROUP);
        second[16] = PrincipalKind::Group as u8;
        second[17] = PrincipalState::Active as u8;
        second[18] = 2;
        second[20..24].copy_from_slice(&2_u32.to_le_bytes());
        second[24..28].copy_from_slice(&5_u32.to_le_bytes());
        second[28..30].copy_from_slice(&6_u16.to_le_bytes());
        second[30..32].copy_from_slice(&1_u16.to_le_bytes());
        second[32..36].copy_from_slice(&1_u32.to_le_bytes());
        image[192..208].copy_from_slice(&GROUP);
        image[208..224].copy_from_slice(&USER);
        image[224..].copy_from_slice(labels);
        checksum(&mut image, CHECKSUM_OFFSET);
        image
    }

    fn mapping() -> Vec<u8> {
        let mut image = vec![0; 64 + 2 * 128];
        image[..8].copy_from_slice(&MAPPING_MAGIC);
        image[8..10].copy_from_slice(&1_u16.to_le_bytes());
        image[12..14].copy_from_slice(&64_u16.to_le_bytes());
        image[14..16].copy_from_slice(&128_u16.to_le_bytes());
        let total = u32::try_from(image.len()).unwrap_or(0);
        image[16..20].copy_from_slice(&total.to_le_bytes());
        image[24..28].copy_from_slice(&2_u32.to_le_bytes());
        image[32..40].copy_from_slice(&1_u64.to_le_bytes());
        image[40..56].copy_from_slice(&DOMAIN);
        let user = &mut image[64..192];
        user[..4].copy_from_slice(&POSIX_SCHEME.to_le_bytes());
        user[4] = ForeignKind::User as u8;
        user[5] = 4;
        user[8..24].copy_from_slice(&USER);
        let group = &mut image[192..320];
        group[..4].copy_from_slice(&POSIX_SCHEME.to_le_bytes());
        group[4] = ForeignKind::Group as u8;
        group[5] = 4;
        group[8..24].copy_from_slice(&GROUP);
        checksum(&mut image, CHECKSUM_OFFSET);
        image
    }

    fn mount() -> Vec<u8> {
        let mut image = vec![0; MOUNT_BYTES];
        image[..8].copy_from_slice(&MOUNT_MAGIC);
        image[8..10].copy_from_slice(&1_u16.to_le_bytes());
        image[12..14].copy_from_slice(&u16::try_from(MOUNT_BYTES).unwrap_or(0).to_le_bytes());
        image[14] = MountIdentityMode::ExplicitMapping as u8;
        image[15] = 1;
        image[20..22].copy_from_slice(&4_u16.to_le_bytes());
        image[32..36].copy_from_slice(b"root");
        image[64..80].copy_from_slice(&DOMAIN);
        image[80..88].copy_from_slice(&1_u64.to_le_bytes());
        checksum(&mut image, MOUNT_CHECKSUM_OFFSET);
        image
    }

    fn acl() -> Vec<u8> {
        let mut image = vec![0; 64 + 3 * 32];
        image[..8].copy_from_slice(&ACL_MAGIC);
        image[8..10].copy_from_slice(&1_u16.to_le_bytes());
        image[12..14].copy_from_slice(&64_u16.to_le_bytes());
        image[14..16].copy_from_slice(&32_u16.to_le_bytes());
        let total = u32::try_from(image.len()).unwrap_or(0);
        image[16..20].copy_from_slice(&total.to_le_bytes());
        image[24..28].copy_from_slice(&3_u32.to_le_bytes());
        for (index, tag) in [AclTag::Owner, AclTag::GroupObject, AclTag::Other]
            .into_iter()
            .enumerate()
        {
            image[64 + index * 32] = tag as u8;
            image[65 + index * 32] = 4;
        }
        checksum(&mut image, CHECKSUM_OFFSET);
        image
    }

    fn snapshot(generation: u64, mapping_version: u64, domain: [u8; 16]) -> IdentitySnapshot {
        let mut registry = registry(None);
        registry[36..44].copy_from_slice(&generation.to_le_bytes());
        checksum(&mut registry, CHECKSUM_OFFSET);
        let mut mapping = mapping();
        mapping[32..40].copy_from_slice(&mapping_version.to_le_bytes());
        mapping[40..56].copy_from_slice(&domain);
        checksum(&mut mapping, CHECKSUM_OFFSET);
        let mut mount = mount();
        mount[64..80].copy_from_slice(&domain);
        mount[80..88].copy_from_slice(&mapping_version.to_le_bytes());
        checksum(&mut mount, MOUNT_CHECKSUM_OFFSET);
        validate_snapshot(
            &registry,
            &mapping,
            &mount,
            &acl(),
            generation,
            IdentityLimits::standard(),
        )
        .unwrap_or_else(|_| unreachable!())
    }

    #[test]
    fn canonical_snapshot_cross_validates() -> Result<(), IdentityError> {
        let snapshot = validate_snapshot(
            &registry(None),
            &mapping(),
            &mount(),
            &acl(),
            1,
            IdentityLimits::standard(),
        )?;
        assert_eq!(snapshot.registry.principals().len(), 2);
        assert_eq!(snapshot.mapping.entries().len(), 2);
        assert_eq!(snapshot.mount.role(), "root");
        assert_eq!(snapshot.acl.entries().len(), 3);
        Ok(())
    }

    #[test]
    fn every_truncation_and_corruption_fails_closed() {
        for image in [registry(None), mapping(), mount(), acl()] {
            for length in 0..image.len() {
                let result = if image.starts_with(&REGISTRY_MAGIC) {
                    IdentityRegistry::parse(&image[..length], IdentityLimits::standard())
                        .map(|_| ())
                } else if image.starts_with(&MAPPING_MAGIC) {
                    MappingSnapshot::parse(&image[..length], IdentityLimits::standard()).map(|_| ())
                } else if image.starts_with(&MOUNT_MAGIC) {
                    MountPolicy::parse(&image[..length]).map(|_| ())
                } else {
                    NativeAcl::parse(&image[..length], IdentityLimits::standard()).map(|_| ())
                };
                assert!(result.is_err());
            }
            for offset in 0..image.len() {
                let mut corrupt = image.clone();
                corrupt[offset] ^= 1;
                let result = if image.starts_with(&REGISTRY_MAGIC) {
                    IdentityRegistry::parse(&corrupt, IdentityLimits::standard()).map(|_| ())
                } else if image.starts_with(&MAPPING_MAGIC) {
                    MappingSnapshot::parse(&corrupt, IdentityLimits::standard()).map(|_| ())
                } else if image.starts_with(&MOUNT_MAGIC) {
                    MountPolicy::parse(&corrupt).map(|_| ())
                } else {
                    NativeAcl::parse(&corrupt, IdentityLimits::standard()).map(|_| ())
                };
                assert!(result.is_err());
            }
        }
    }

    #[test]
    fn cycles_references_sid_and_acl_order_fail_closed() {
        assert!(
            IdentityRegistry::parse(&registry(Some(GROUP)), IdentityLimits::standard()).is_err()
        );
        assert_eq!(
            IdentityRegistry::parse(&cyclic_registry(), IdentityLimits::standard()),
            Err(IdentityError::MembershipCycle)
        );
        let registry = IdentityRegistry::parse(&registry(None), IdentityLimits::standard())
            .unwrap_or_else(|_| unreachable!());
        let mut wrong_mapping = mapping();
        wrong_mapping[72..88].fill(9);
        checksum(&mut wrong_mapping, CHECKSUM_OFFSET);
        let mapping = MappingSnapshot::parse(&wrong_mapping, IdentityLimits::standard())
            .unwrap_or_else(|_| unreachable!());
        assert_eq!(
            mapping.validate_against(&registry),
            Err(IdentityError::InvalidReference)
        );
        assert!(
            validate_foreign_value(
                WINDOWS_SID_SCHEME,
                ForeignKind::User,
                &[1, 1, 0, 0, 0, 0, 0, 5]
            )
            .is_err()
        );
        let mut unordered_acl = acl();
        unordered_acl[64] = AclTag::Other as u8;
        checksum(&mut unordered_acl, CHECKSUM_OFFSET);
        assert!(NativeAcl::parse(&unordered_acl, IdentityLimits::standard()).is_err());
    }

    #[test]
    fn successor_requires_monotonic_versions_and_domain_continuity() {
        let predecessor = snapshot(1, 7, DOMAIN);
        let successor = snapshot(2, 8, DOMAIN);
        assert_eq!(validate_successor(&predecessor, &successor), Ok(()));

        let stale_generation = snapshot(1, 8, DOMAIN);
        assert_eq!(
            validate_successor(&predecessor, &stale_generation),
            Err(IdentityError::InvalidTransition)
        );
        let stale_mapping = snapshot(2, 7, DOMAIN);
        assert_eq!(
            validate_successor(&predecessor, &stale_mapping),
            Err(IdentityError::InvalidTransition)
        );
        let changed_domain = snapshot(2, 8, [4; 16]);
        assert_eq!(
            validate_successor(&predecessor, &changed_domain),
            Err(IdentityError::InvalidTransition)
        );
    }

    #[test]
    fn successor_retains_ids_kinds_and_permanent_tombstones() {
        let mut predecessor = snapshot(1, 1, DOMAIN);
        let mut successor = snapshot(2, 2, DOMAIN);

        successor.registry.principals.remove(0);
        assert_eq!(
            validate_successor(&predecessor, &successor),
            Err(IdentityError::InvalidTransition)
        );

        let mut successor = snapshot(2, 2, DOMAIN);
        successor.registry.principals[0].kind = PrincipalKind::Service;
        assert_eq!(
            validate_successor(&predecessor, &successor),
            Err(IdentityError::InvalidTransition)
        );

        predecessor.registry.principals[0].state = PrincipalState::Tombstoned;
        let successor = snapshot(2, 2, DOMAIN);
        assert_eq!(
            validate_successor(&predecessor, &successor),
            Err(IdentityError::InvalidTransition)
        );
        let mut successor = successor;
        successor.registry.principals[0].state = PrincipalState::Tombstoned;
        assert_eq!(validate_successor(&predecessor, &successor), Ok(()));
    }
}
