//! Bounded immutable SHA-256-addressed content packs.
#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;
#[cfg(test)]
extern crate std;

use alloc::vec::Vec;

/// Product-independent immutable content-pack identifier.
pub const CONTENT_PACK_MAGIC: [u8; 8] = *b"CSPKv1\0\0";
/// Fixed CSPK header size.
pub const HEADER_BYTES: usize = 64;
/// Fixed CSPK object-record size.
pub const RECORD_BYTES: usize = 64;
/// Hard maximum encoded pack size.
pub const MAX_PACK_BYTES: usize = 4 * 1024 * 1024;
/// Hard maximum retained object count.
pub const MAX_OBJECTS: usize = 64;
/// Hard maximum size of one immutable object.
pub const MAX_OBJECT_BYTES: usize = 1024 * 1024;
/// Exact encoded generation-manifest size.
pub const GENERATION_MANIFEST_BYTES: usize = 128;
/// Exact encoded identity-security manifest size.
pub const SECURITY_MANIFEST_BYTES: usize = 192;

const CHECKSUM_OFFSET: usize = 20;
const GENERATION_CHECKSUM_OFFSET: usize = 88;
const GENERATION_PREVIOUS: u16 = 1;
const GENERATION_SECURITY: u16 = 1 << 1;
const GENERATION_MAGIC: [u8; 8] = *b"GMANv1\0\0";
const SECURITY_CHECKSUM_OFFSET: usize = 152;
const SECURITY_MAGIC: [u8; 8] = *b"ISECv1\0\0";

/// SHA-256 content identity.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct ContentDigest([u8; 32]);

impl ContentDigest {
    /// Hash exact object bytes.
    #[must_use]
    pub fn of(bytes: &[u8]) -> Self {
        Self(sha256(bytes))
    }

    /// Construct from exact digest bytes.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Return exact digest bytes.
    #[must_use]
    pub const fn bytes(self) -> [u8; 32] {
        self.0
    }
}

/// Canonical immutable desired-system generation root.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GenerationManifest {
    generation: u64,
    config: ContentDigest,
    previous: Option<ContentDigest>,
    security: Option<ContentDigest>,
}

impl GenerationManifest {
    /// Construct a bounded generation root.
    ///
    /// # Errors
    ///
    /// Rejects generation zero and zero content identities.
    pub fn new(
        generation: u64,
        config: ContentDigest,
        previous: Option<ContentDigest>,
    ) -> Result<Self, ContentError> {
        if generation == 0
            || config.bytes() == [0; 32]
            || previous.is_some_and(|digest| digest.bytes() == [0; 32])
        {
            return Err(ContentError::InvalidManifest);
        }
        Ok(Self {
            generation,
            config,
            previous,
            security: None,
        })
    }

    /// Bind one exact immutable identity-security manifest to this generation.
    ///
    /// # Errors
    ///
    /// Rejects a zero content identity.
    pub fn with_security(mut self, security: ContentDigest) -> Result<Self, ContentError> {
        if security.bytes() == [0; 32] {
            return Err(ContentError::InvalidManifest);
        }
        self.security = Some(security);
        Ok(self)
    }

    /// Parse one exact checksummed GMAN v1 object.
    ///
    /// # Errors
    ///
    /// Rejects malformed headers, flags, reserved bytes, checksum, generation,
    /// or content identities.
    pub fn parse(bytes: &[u8]) -> Result<Self, ContentError> {
        if bytes.len() != GENERATION_MANIFEST_BYTES
            || bytes.get(..8) != Some(&GENERATION_MAGIC)
            || read_u16(bytes, 8)? != 1
            || read_u16(bytes, 10)? != 0
            || read_u16(bytes, 12)? != 128
            || bytes[92..96].iter().any(|byte| *byte != 0)
        {
            return Err(ContentError::InvalidManifest);
        }
        let flags = read_u16(bytes, 14)?;
        if flags & !(GENERATION_PREVIOUS | GENERATION_SECURITY) != 0
            || crc32_with_zeroed(bytes, GENERATION_CHECKSUM_OFFSET)
                != read_u32(bytes, GENERATION_CHECKSUM_OFFSET)?
        {
            return Err(ContentError::InvalidManifest);
        }
        let mut config = [0_u8; 32];
        config.copy_from_slice(&bytes[24..56]);
        let mut previous = [0_u8; 32];
        previous.copy_from_slice(&bytes[56..88]);
        let previous = if flags & GENERATION_PREVIOUS != 0 {
            Some(ContentDigest::from_bytes(previous))
        } else {
            if previous != [0; 32] {
                return Err(ContentError::InvalidManifest);
            }
            None
        };
        let security = if flags & GENERATION_SECURITY != 0 {
            let mut digest = [0_u8; 32];
            digest.copy_from_slice(&bytes[96..128]);
            Some(ContentDigest::from_bytes(digest))
        } else {
            if bytes[96..128].iter().any(|byte| *byte != 0) {
                return Err(ContentError::InvalidManifest);
            }
            None
        };
        let manifest = Self::new(
            read_u64(bytes, 16)?,
            ContentDigest::from_bytes(config),
            previous,
        )?;
        match security {
            Some(digest) => manifest.with_security(digest),
            None => Ok(manifest),
        }
    }

    /// Encode this manifest as canonical checksummed GMAN v1 bytes.
    #[must_use]
    pub fn encode(self) -> [u8; GENERATION_MANIFEST_BYTES] {
        let mut bytes = [0_u8; GENERATION_MANIFEST_BYTES];
        bytes[..8].copy_from_slice(&GENERATION_MAGIC);
        write_u16(&mut bytes, 8, 1);
        write_u16(&mut bytes, 12, 128);
        let mut flags = 0_u16;
        if self.previous.is_some() {
            flags |= GENERATION_PREVIOUS;
        }
        if self.security.is_some() {
            flags |= GENERATION_SECURITY;
        }
        write_u16(&mut bytes, 14, flags);
        write_u64(&mut bytes, 16, self.generation);
        bytes[24..56].copy_from_slice(&self.config.bytes());
        if let Some(previous) = self.previous {
            bytes[56..88].copy_from_slice(&previous.bytes());
        }
        if let Some(security) = self.security {
            bytes[96..128].copy_from_slice(&security.bytes());
        }
        let checksum = crc32_with_zeroed(&bytes, GENERATION_CHECKSUM_OFFSET);
        write_u32(&mut bytes, GENERATION_CHECKSUM_OFFSET, checksum);
        bytes
    }

    /// Monotonic desired-system generation number.
    #[must_use]
    pub const fn generation(self) -> u64 {
        self.generation
    }

    /// SCFG object selected by this generation.
    #[must_use]
    pub const fn config(self) -> ContentDigest {
        self.config
    }

    /// Optional predecessor generation-manifest identity.
    #[must_use]
    pub const fn previous(self) -> Option<ContentDigest> {
        self.previous
    }

    /// Optional immutable identity-security manifest identity.
    #[must_use]
    pub const fn security(self) -> Option<ContentDigest> {
        self.security
    }
}

/// Immutable root for the four canonical identity-security metadata objects.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SecurityManifest {
    generation: u64,
    registry: ContentDigest,
    mapping: ContentDigest,
    mount: ContentDigest,
    acl: ContentDigest,
}

impl SecurityManifest {
    /// Construct one complete security root.
    ///
    /// # Errors
    ///
    /// Rejects generation zero, zero identities, and repeated identities.
    pub fn new(
        generation: u64,
        registry: ContentDigest,
        mapping: ContentDigest,
        mount: ContentDigest,
        acl: ContentDigest,
    ) -> Result<Self, ContentError> {
        let digests = [registry, mapping, mount, acl];
        if generation == 0
            || digests.iter().any(|digest| digest.bytes() == [0; 32])
            || digests
                .iter()
                .enumerate()
                .any(|(index, digest)| digests[..index].contains(digest))
        {
            return Err(ContentError::InvalidManifest);
        }
        Ok(Self {
            generation,
            registry,
            mapping,
            mount,
            acl,
        })
    }

    /// Parse one exact checksummed ISEC v1 object.
    ///
    /// # Errors
    ///
    /// Rejects malformed versions, lengths, checksum, reserved bytes, or roots.
    pub fn parse(bytes: &[u8]) -> Result<Self, ContentError> {
        if bytes.len() != SECURITY_MANIFEST_BYTES
            || bytes.get(..8) != Some(&SECURITY_MAGIC)
            || read_u16(bytes, 8)? != 1
            || read_u16(bytes, 10)? != 0
            || usize::from(read_u16(bytes, 12)?) != SECURITY_MANIFEST_BYTES
            || read_u16(bytes, 14)? != 0
            || bytes[156..].iter().any(|byte| *byte != 0)
            || crc32_with_zeroed(bytes, SECURITY_CHECKSUM_OFFSET)
                != read_u32(bytes, SECURITY_CHECKSUM_OFFSET)?
        {
            return Err(ContentError::InvalidManifest);
        }
        Self::new(
            read_u64(bytes, 16)?,
            ContentDigest::from_bytes(copy_digest(bytes, 24)?),
            ContentDigest::from_bytes(copy_digest(bytes, 56)?),
            ContentDigest::from_bytes(copy_digest(bytes, 88)?),
            ContentDigest::from_bytes(copy_digest(bytes, 120)?),
        )
    }

    /// Encode canonical checksummed ISEC v1 bytes.
    #[must_use]
    pub fn encode(self) -> [u8; SECURITY_MANIFEST_BYTES] {
        let mut bytes = [0_u8; SECURITY_MANIFEST_BYTES];
        bytes[..8].copy_from_slice(&SECURITY_MAGIC);
        write_u16(&mut bytes, 8, 1);
        write_u16(&mut bytes, 12, 192);
        write_u64(&mut bytes, 16, self.generation);
        bytes[24..56].copy_from_slice(&self.registry.bytes());
        bytes[56..88].copy_from_slice(&self.mapping.bytes());
        bytes[88..120].copy_from_slice(&self.mount.bytes());
        bytes[120..152].copy_from_slice(&self.acl.bytes());
        let checksum = crc32_with_zeroed(&bytes, SECURITY_CHECKSUM_OFFSET);
        write_u32(&mut bytes, SECURITY_CHECKSUM_OFFSET, checksum);
        bytes
    }

    /// Bound system generation.
    #[must_use]
    pub const fn generation(self) -> u64 {
        self.generation
    }
    /// Native identity registry object.
    #[must_use]
    pub const fn registry(self) -> ContentDigest {
        self.registry
    }
    /// Foreign mapping snapshot object.
    #[must_use]
    pub const fn mapping(self) -> ContentDigest {
        self.mapping
    }
    /// Mount identity-policy object.
    #[must_use]
    pub const fn mount(self) -> ContentDigest {
        self.mount
    }
    /// Native ACL object.
    #[must_use]
    pub const fn acl(self) -> ContentDigest {
        self.acl
    }
}

/// Closed immutable object roles.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum ObjectKind {
    /// Canonical SCFG image.
    SystemConfig = 1,
    /// Canonical KEX application artifact.
    Application = 2,
    /// Desired-system generation manifest.
    GenerationManifest = 3,
    /// Opaque immutable service data.
    Data = 4,
    /// Canonical native identity registry.
    IdentityRegistry = 5,
    /// Canonical foreign identity mapping snapshot.
    IdentityMapping = 6,
    /// Canonical persistent mount identity policy.
    MountPolicy = 7,
    /// Canonical native ACL.
    NativeAcl = 8,
    /// Security root referencing registry, mapping, mount, and ACL objects.
    SecurityManifest = 9,
}

impl ObjectKind {
    fn parse(value: u8) -> Result<Self, ContentError> {
        match value {
            1 => Ok(Self::SystemConfig),
            2 => Ok(Self::Application),
            3 => Ok(Self::GenerationManifest),
            4 => Ok(Self::Data),
            5 => Ok(Self::IdentityRegistry),
            6 => Ok(Self::IdentityMapping),
            7 => Ok(Self::MountPolicy),
            8 => Ok(Self::NativeAcl),
            9 => Ok(Self::SecurityManifest),
            _ => Err(ContentError::InvalidRecord),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Record {
    digest: ContentDigest,
    kind: ObjectKind,
    offset: usize,
    length: usize,
}

/// One verified immutable object borrowed from a pack.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ContentObject<'a> {
    /// Verified SHA-256 identity.
    pub digest: ContentDigest,
    /// Declared object role.
    pub kind: ObjectKind,
    /// Exact immutable bytes.
    pub bytes: &'a [u8],
}

/// Fully verified bounded immutable content pack.
pub struct ContentPack<'a> {
    image: &'a [u8],
    records: Vec<Record>,
}

impl<'a> ContentPack<'a> {
    /// Parse and verify a canonical CSPK v1 image.
    ///
    /// # Errors
    ///
    /// Rejects invalid headers/checksums, resource ceilings, noncanonical
    /// records/layout, duplicate or unsorted identities, and any object whose
    /// bytes fail its SHA-256 identity.
    pub fn parse(image: &'a [u8]) -> Result<Self, ContentError> {
        if !(HEADER_BYTES..=MAX_PACK_BYTES).contains(&image.len())
            || image.get(..8) != Some(&CONTENT_PACK_MAGIC)
            || read_u16(image, 8)? != 1
            || read_u16(image, 10)? != 0
            || read_u16(image, 12)? != 64
            || read_u16(image, 14)? != 64
            || usize::try_from(read_u32(image, 16)?).map_err(|_| ContentError::InvalidHeader)?
                != image.len()
            || image[26..HEADER_BYTES].iter().any(|byte| *byte != 0)
        {
            return Err(ContentError::InvalidHeader);
        }
        let count = usize::from(read_u16(image, 24)?);
        if count == 0 || count > MAX_OBJECTS {
            return Err(ContentError::LimitExceeded);
        }
        let table_end = HEADER_BYTES
            .checked_add(
                count
                    .checked_mul(RECORD_BYTES)
                    .ok_or(ContentError::LimitExceeded)?,
            )
            .ok_or(ContentError::LimitExceeded)?;
        if table_end > image.len() || crc32_zeroed(image) != read_u32(image, CHECKSUM_OFFSET)? {
            return Err(ContentError::Checksum);
        }
        let mut records = Vec::new();
        records
            .try_reserve_exact(count)
            .map_err(|_| ContentError::MetadataExhausted)?;
        let mut expected_offset = table_end;
        for index in 0..count {
            let start = HEADER_BYTES + index * RECORD_BYTES;
            let raw = &image[start..start + RECORD_BYTES];
            if raw[33..40].iter().chain(&raw[48..]).any(|byte| *byte != 0) {
                return Err(ContentError::InvalidRecord);
            }
            let mut digest = [0_u8; 32];
            digest.copy_from_slice(&raw[..32]);
            let digest = ContentDigest(digest);
            let kind = ObjectKind::parse(raw[32])?;
            let offset =
                usize::try_from(read_u32(raw, 40)?).map_err(|_| ContentError::InvalidRecord)?;
            let length =
                usize::try_from(read_u32(raw, 44)?).map_err(|_| ContentError::InvalidRecord)?;
            let end = offset
                .checked_add(length)
                .ok_or(ContentError::InvalidRecord)?;
            if length == 0
                || length > MAX_OBJECT_BYTES
                || offset != expected_offset
                || end > image.len()
                || records
                    .last()
                    .is_some_and(|prior: &Record| prior.digest >= digest)
                || ContentDigest::of(&image[offset..end]) != digest
            {
                return Err(ContentError::InvalidRecord);
            }
            if kind == ObjectKind::GenerationManifest {
                GenerationManifest::parse(&image[offset..end])?;
            } else if kind == ObjectKind::SecurityManifest {
                SecurityManifest::parse(&image[offset..end])?;
            }
            records.push(Record {
                digest,
                kind,
                offset,
                length,
            });
            expected_offset = end;
        }
        if expected_offset != image.len() {
            return Err(ContentError::InvalidRecord);
        }
        Ok(Self { image, records })
    }

    /// Number of verified objects.
    #[must_use]
    pub fn len(&self) -> usize {
        self.records.len()
    }

    /// Whether the pack contains no object (canonical packs never do).
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    /// Resolve one exact digest with logarithmic bounded lookup.
    #[must_use]
    pub fn get(&self, digest: ContentDigest) -> Option<ContentObject<'a>> {
        let index = self
            .records
            .binary_search_by(|record| record.digest.cmp(&digest))
            .ok()?;
        let record = self.records[index];
        Some(ContentObject {
            digest: record.digest,
            kind: record.kind,
            bytes: &self.image[record.offset..record.offset + record.length],
        })
    }

    /// Iterate over every verified object in canonical digest order.
    pub fn objects(&self) -> impl Iterator<Item = ContentObject<'a>> + '_ {
        self.records.iter().map(|record| ContentObject {
            digest: record.digest,
            kind: record.kind,
            bytes: &self.image[record.offset..record.offset + record.length],
        })
    }

    /// Resolve a bounded active/predecessor generation chain into unique GC roots.
    ///
    /// Each retained generation contributes its manifest and SCFG object plus,
    /// when present, a security manifest and its four declared typed objects.
    /// Manifest links must be acyclic, strictly generation-descending, and
    /// reference objects of the declared kinds.
    ///
    /// # Errors
    ///
    /// Rejects empty or excessive policy, missing/wrong-kind objects, invalid
    /// manifests, cycles, non-descending generations, and allocation failure.
    pub fn generation_roots(
        &self,
        active_manifest: ContentDigest,
        max_generations: usize,
    ) -> Result<Vec<ContentDigest>, ContentError> {
        const MAX_ROOTS_PER_GENERATION: usize = 7;
        if max_generations == 0 || max_generations > MAX_OBJECTS / MAX_ROOTS_PER_GENERATION {
            return Err(ContentError::LimitExceeded);
        }
        let mut roots = Vec::new();
        roots
            .try_reserve_exact(max_generations.saturating_mul(MAX_ROOTS_PER_GENERATION))
            .map_err(|_| ContentError::MetadataExhausted)?;
        let mut next = Some(active_manifest);
        let mut newer_generation = None;
        let mut generation_count = 0_usize;
        while let Some(digest) = next {
            if generation_count == max_generations || roots.contains(&digest) {
                return Err(ContentError::InvalidManifest);
            }
            let object = self.get(digest).ok_or(ContentError::MissingObject)?;
            if object.kind != ObjectKind::GenerationManifest {
                return Err(ContentError::InvalidManifest);
            }
            let manifest = GenerationManifest::parse(object.bytes)?;
            if newer_generation.is_some_and(|newer| manifest.generation() >= newer) {
                return Err(ContentError::InvalidManifest);
            }
            let config = self
                .get(manifest.config())
                .ok_or(ContentError::MissingObject)?;
            if config.kind != ObjectKind::SystemConfig {
                return Err(ContentError::InvalidManifest);
            }
            push_unique_root(&mut roots, digest);
            push_unique_root(&mut roots, manifest.config());
            generation_count += 1;
            if let Some(security_digest) = manifest.security() {
                let security_object = self
                    .get(security_digest)
                    .ok_or(ContentError::MissingObject)?;
                if security_object.kind != ObjectKind::SecurityManifest {
                    return Err(ContentError::InvalidManifest);
                }
                let security = SecurityManifest::parse(security_object.bytes)?;
                if security.generation() != manifest.generation() {
                    return Err(ContentError::InvalidManifest);
                }
                let typed = [
                    (security.registry(), ObjectKind::IdentityRegistry),
                    (security.mapping(), ObjectKind::IdentityMapping),
                    (security.mount(), ObjectKind::MountPolicy),
                    (security.acl(), ObjectKind::NativeAcl),
                ];
                push_unique_root(&mut roots, security_digest);
                for (identity, expected_kind) in typed {
                    let referenced = self.get(identity).ok_or(ContentError::MissingObject)?;
                    if referenced.kind != expected_kind {
                        return Err(ContentError::InvalidManifest);
                    }
                    push_unique_root(&mut roots, identity);
                }
            }
            newer_generation = Some(manifest.generation());
            next = manifest.previous();
        }
        Ok(roots)
    }

    /// Rebuild a canonical pack containing exactly the requested identities.
    ///
    /// This is the bounded mark-and-copy publication primitive. Input roots
    /// may be unordered or repeated; output is digest-sorted and deduplicated.
    /// The caller must add transitive manifest dependencies to `roots` before
    /// publication.
    ///
    /// # Errors
    ///
    /// Rejects empty/missing roots, policy above hard ceilings, output above
    /// the declared byte/object budgets, and allocation failure.
    pub fn retain(
        &self,
        roots: &[ContentDigest],
        max_objects: usize,
        max_bytes: usize,
    ) -> Result<Vec<u8>, ContentError> {
        if roots.is_empty()
            || max_objects == 0
            || max_objects > MAX_OBJECTS
            || !(HEADER_BYTES + RECORD_BYTES + 1..=MAX_PACK_BYTES).contains(&max_bytes)
        {
            return Err(ContentError::LimitExceeded);
        }
        let mut identities = Vec::new();
        identities
            .try_reserve_exact(roots.len().min(max_objects))
            .map_err(|_| ContentError::MetadataExhausted)?;
        for digest in roots {
            if self.get(*digest).is_none() {
                return Err(ContentError::MissingObject);
            }
            if !identities.contains(digest) {
                if identities.len() == max_objects {
                    return Err(ContentError::LimitExceeded);
                }
                identities.push(*digest);
            }
        }
        identities.sort_unstable();
        let table_end = HEADER_BYTES
            .checked_add(
                identities
                    .len()
                    .checked_mul(RECORD_BYTES)
                    .ok_or(ContentError::LimitExceeded)?,
            )
            .ok_or(ContentError::LimitExceeded)?;
        let mut total = table_end;
        for digest in &identities {
            total = total
                .checked_add(
                    self.get(*digest)
                        .ok_or(ContentError::MissingObject)?
                        .bytes
                        .len(),
                )
                .ok_or(ContentError::LimitExceeded)?;
        }
        if total > max_bytes {
            return Err(ContentError::LimitExceeded);
        }
        let mut output = Vec::new();
        output
            .try_reserve_exact(total)
            .map_err(|_| ContentError::MetadataExhausted)?;
        output.resize(total, 0);
        output[..8].copy_from_slice(&CONTENT_PACK_MAGIC);
        write_u16(&mut output, 8, 1);
        write_u16(&mut output, 12, 64);
        write_u16(&mut output, 14, 64);
        write_u32(
            &mut output,
            16,
            u32::try_from(total).map_err(|_| ContentError::LimitExceeded)?,
        );
        write_u16(
            &mut output,
            24,
            u16::try_from(identities.len()).map_err(|_| ContentError::LimitExceeded)?,
        );
        let mut offset = table_end;
        for (index, digest) in identities.iter().enumerate() {
            let object = self.get(*digest).ok_or(ContentError::MissingObject)?;
            let record = HEADER_BYTES + index * RECORD_BYTES;
            output[record..record + 32].copy_from_slice(&digest.bytes());
            output[record + 32] = object.kind as u8;
            write_u32(
                &mut output,
                record + 40,
                u32::try_from(offset).map_err(|_| ContentError::LimitExceeded)?,
            );
            write_u32(
                &mut output,
                record + 44,
                u32::try_from(object.bytes.len()).map_err(|_| ContentError::LimitExceeded)?,
            );
            output[offset..offset + object.bytes.len()].copy_from_slice(object.bytes);
            offset += object.bytes.len();
        }
        let checksum = crc32_zeroed(&output);
        write_u32(&mut output, CHECKSUM_OFFSET, checksum);
        Ok(output)
    }
}

fn push_unique_root(roots: &mut Vec<ContentDigest>, digest: ContentDigest) {
    if !roots.contains(&digest) {
        roots.push(digest);
    }
}

/// Stable CSPK rejection reason.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ContentError {
    /// Magic, version, sizes, total length, or reserved header bytes failed.
    InvalidHeader,
    /// Whole-pack CRC32 failed.
    Checksum,
    /// Object count, pack bytes, or object bytes exceeded a hard ceiling.
    LimitExceeded,
    /// An object role, layout, order, digest, or reserved field failed.
    InvalidRecord,
    /// A generation-manifest object was not canonical.
    InvalidManifest,
    /// Bounded record retention failed.
    MetadataExhausted,
    /// A requested retained identity was absent from the verified source pack.
    MissingObject,
}

fn read_u16(bytes: &[u8], offset: usize) -> Result<u16, ContentError> {
    let raw = bytes
        .get(offset..offset + 2)
        .ok_or(ContentError::InvalidHeader)?;
    Ok(u16::from_le_bytes([raw[0], raw[1]]))
}

fn read_u32(bytes: &[u8], offset: usize) -> Result<u32, ContentError> {
    let raw = bytes
        .get(offset..offset + 4)
        .ok_or(ContentError::InvalidHeader)?;
    Ok(u32::from_le_bytes([raw[0], raw[1], raw[2], raw[3]]))
}

fn read_u64(bytes: &[u8], offset: usize) -> Result<u64, ContentError> {
    let raw = bytes
        .get(offset..offset + 8)
        .ok_or(ContentError::InvalidManifest)?;
    let mut value = [0_u8; 8];
    value.copy_from_slice(raw);
    Ok(u64::from_le_bytes(value))
}

fn copy_digest(bytes: &[u8], offset: usize) -> Result<[u8; 32], ContentError> {
    bytes
        .get(offset..offset + 32)
        .ok_or(ContentError::InvalidManifest)?
        .try_into()
        .map_err(|_| ContentError::InvalidManifest)
}

fn write_u16(bytes: &mut [u8], offset: usize, value: u16) {
    bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}

fn write_u32(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn write_u64(bytes: &mut [u8], offset: usize, value: u64) {
    bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

fn crc32_zeroed(bytes: &[u8]) -> u32 {
    crc32_with_zeroed(bytes, CHECKSUM_OFFSET)
}

fn crc32_with_zeroed(bytes: &[u8], zero_offset: usize) -> u32 {
    troe_checksum::crc32_with_zeroed_field(bytes, zero_offset)
}

// FIPS 180-4 SHA-256 with fixed stack state and no allocation.
#[allow(
    clippy::many_single_char_names,
    clippy::unreadable_literal,
    clippy::comparison_chain
)] // Names and constants follow the FIPS 180-4 compression function.
fn sha256(input: &[u8]) -> [u8; 32] {
    const K: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
        0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
        0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
        0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
        0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
        0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
        0xc67178f2,
    ];
    let bit_len = u64::try_from(input.len())
        .unwrap_or(u64::MAX)
        .wrapping_mul(8);
    let blocks = (input.len() + 9).div_ceil(64);
    let mut state: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ];
    for block_index in 0..blocks {
        let mut block = [0_u8; 64];
        for (index, byte) in block.iter_mut().enumerate() {
            let absolute = block_index * 64 + index;
            *byte = if absolute < input.len() {
                input[absolute]
            } else if absolute == input.len() {
                0x80
            } else {
                0
            };
        }
        if block_index + 1 == blocks {
            block[56..].copy_from_slice(&bit_len.to_be_bytes());
        }
        let mut w = [0_u32; 64];
        for (index, chunk) in block.chunks_exact(4).enumerate() {
            w[index] = u32::from_be_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
        }
        for index in 16..64 {
            let s0 = w[index - 15].rotate_right(7)
                ^ w[index - 15].rotate_right(18)
                ^ (w[index - 15] >> 3);
            let s1 = w[index - 2].rotate_right(17)
                ^ w[index - 2].rotate_right(19)
                ^ (w[index - 2] >> 10);
            w[index] = w[index - 16]
                .wrapping_add(s0)
                .wrapping_add(w[index - 7])
                .wrapping_add(s1);
        }
        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = state;
        for index in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ (!e & g);
            let t1 = h
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K[index])
                .wrapping_add(w[index]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let t2 = s0.wrapping_add(maj);
            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);
        }
        for (slot, value) in state.iter_mut().zip([a, b, c, d, e, f, g, h]) {
            *slot = (*slot).wrapping_add(value);
        }
    }
    let mut output = [0_u8; 32];
    for (chunk, value) in output.chunks_exact_mut(4).zip(state) {
        chunk.copy_from_slice(&value.to_be_bytes());
    }
    output
}

#[cfg(test)]
mod tests {
    use alloc::vec;
    use alloc::vec::Vec;

    use super::{
        CONTENT_PACK_MAGIC, ContentDigest, ContentError, ContentPack, GenerationManifest,
        HEADER_BYTES, ObjectKind, RECORD_BYTES, SecurityManifest, crc32_zeroed,
    };

    fn pack(objects: &[(ObjectKind, &[u8])]) -> Vec<u8> {
        let mut sorted: Vec<_> = objects
            .iter()
            .map(|(kind, bytes)| (ContentDigest::of(bytes), *kind, *bytes))
            .collect();
        sorted.sort_by_key(|(digest, _, _)| *digest);
        let payload_bytes: usize = sorted.iter().map(|(_, _, bytes)| bytes.len()).sum();
        let table_end = HEADER_BYTES + sorted.len() * RECORD_BYTES;
        let mut image = vec![0_u8; table_end + payload_bytes];
        let image_bytes = u32::try_from(image.len()).unwrap_or(0);
        image[..8].copy_from_slice(&CONTENT_PACK_MAGIC);
        image[8..10].copy_from_slice(&1_u16.to_le_bytes());
        image[12..14].copy_from_slice(&64_u16.to_le_bytes());
        image[14..16].copy_from_slice(&64_u16.to_le_bytes());
        image[16..20].copy_from_slice(&image_bytes.to_le_bytes());
        image[24..26].copy_from_slice(&u16::try_from(sorted.len()).unwrap_or(0).to_le_bytes());
        let mut offset = table_end;
        for (index, (digest, kind, bytes)) in sorted.iter().enumerate() {
            let record = HEADER_BYTES + index * RECORD_BYTES;
            image[record..record + 32].copy_from_slice(&digest.bytes());
            image[record + 32] = *kind as u8;
            image[record + 40..record + 44]
                .copy_from_slice(&u32::try_from(offset).unwrap_or(0).to_le_bytes());
            image[record + 44..record + 48]
                .copy_from_slice(&u32::try_from(bytes.len()).unwrap_or(0).to_le_bytes());
            image[offset..offset + bytes.len()].copy_from_slice(bytes);
            offset += bytes.len();
        }
        let checksum = crc32_zeroed(&image);
        image[20..24].copy_from_slice(&checksum.to_le_bytes());
        image
    }

    #[test]
    fn sha256_matches_fips_vectors() {
        assert_eq!(
            ContentDigest::of(b"").bytes(),
            [
                0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f,
                0xb9, 0x24, 0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b,
                0x78, 0x52, 0xb8, 0x55
            ]
        );
    }

    #[test]
    fn generation_chain_is_canonical_bounded_and_gc_rooted() -> Result<(), ContentError> {
        let previous_config = b"previous config";
        let active_config = b"active config";
        let previous =
            GenerationManifest::new(1, ContentDigest::of(previous_config), None)?.encode();
        let active = GenerationManifest::new(
            2,
            ContentDigest::of(active_config),
            Some(ContentDigest::of(&previous)),
        )?
        .encode();
        let image = pack(&[
            (ObjectKind::SystemConfig, previous_config.as_slice()),
            (ObjectKind::SystemConfig, active_config.as_slice()),
            (ObjectKind::GenerationManifest, previous.as_slice()),
            (ObjectKind::GenerationManifest, active.as_slice()),
        ]);
        let store = ContentPack::parse(&image)?;
        let roots = store.generation_roots(ContentDigest::of(&active), 2)?;
        assert_eq!(roots.len(), 4);
        let retained = store.retain(&roots, 4, image.len())?;
        assert_eq!(ContentPack::parse(&retained)?.len(), 4);
        assert_eq!(
            store.generation_roots(ContentDigest::of(&active), 1),
            Err(ContentError::InvalidManifest)
        );

        let mut malformed = active;
        malformed[16..24].fill(0);
        let malformed_pack = pack(&[(ObjectKind::GenerationManifest, &malformed)]);
        assert!(matches!(
            ContentPack::parse(&malformed_pack),
            Err(ContentError::InvalidManifest)
        ));
        Ok(())
    }

    #[test]
    fn security_manifest_is_typed_generation_bound_and_gc_rooted() -> Result<(), ContentError> {
        let config = b"config";
        let registry = b"registry";
        let mapping = b"mapping";
        let mount = b"mount";
        let acl = b"acl";
        let security = SecurityManifest::new(
            1,
            ContentDigest::of(registry),
            ContentDigest::of(mapping),
            ContentDigest::of(mount),
            ContentDigest::of(acl),
        )?
        .encode();
        let generation = GenerationManifest::new(1, ContentDigest::of(config), None)?
            .with_security(ContentDigest::of(&security))?
            .encode();
        let image = pack(&[
            (ObjectKind::SystemConfig, config),
            (ObjectKind::IdentityRegistry, registry),
            (ObjectKind::IdentityMapping, mapping),
            (ObjectKind::MountPolicy, mount),
            (ObjectKind::NativeAcl, acl),
            (ObjectKind::SecurityManifest, &security),
            (ObjectKind::GenerationManifest, &generation),
        ]);
        let store = ContentPack::parse(&image)?;
        let roots = store.generation_roots(ContentDigest::of(&generation), 1)?;
        assert_eq!(roots.len(), 7);
        assert_eq!(
            ContentPack::parse(&store.retain(&roots, 7, image.len())?)?.len(),
            7
        );

        let wrong_kind = pack(&[
            (ObjectKind::SystemConfig, config),
            (ObjectKind::Data, registry),
            (ObjectKind::IdentityMapping, mapping),
            (ObjectKind::MountPolicy, mount),
            (ObjectKind::NativeAcl, acl),
            (ObjectKind::SecurityManifest, &security),
            (ObjectKind::GenerationManifest, &generation),
        ]);
        assert_eq!(
            ContentPack::parse(&wrong_kind)?.generation_roots(ContentDigest::of(&generation), 1),
            Err(ContentError::InvalidManifest)
        );
        Ok(())
    }

    #[test]
    fn generation_roots_are_deterministic_and_deduplicate_shared_identity_objects()
    -> Result<(), ContentError> {
        let previous_config = b"previous config";
        let active_config = b"active config";
        let previous_registry = b"previous registry";
        let active_registry = b"active registry";
        let previous_mapping = b"previous mapping";
        let active_mapping = b"active mapping";
        let previous_mount = b"previous mount";
        let active_mount = b"active mount";
        let shared_acl = b"shared acl";
        let previous_security = SecurityManifest::new(
            1,
            ContentDigest::of(previous_registry),
            ContentDigest::of(previous_mapping),
            ContentDigest::of(previous_mount),
            ContentDigest::of(shared_acl),
        )?
        .encode();
        let active_security = SecurityManifest::new(
            2,
            ContentDigest::of(active_registry),
            ContentDigest::of(active_mapping),
            ContentDigest::of(active_mount),
            ContentDigest::of(shared_acl),
        )?
        .encode();
        let previous = GenerationManifest::new(1, ContentDigest::of(previous_config), None)?
            .with_security(ContentDigest::of(&previous_security))?
            .encode();
        let active = GenerationManifest::new(
            2,
            ContentDigest::of(active_config),
            Some(ContentDigest::of(&previous)),
        )?
        .with_security(ContentDigest::of(&active_security))?
        .encode();
        let image = pack(&[
            (ObjectKind::SystemConfig, previous_config),
            (ObjectKind::SystemConfig, active_config),
            (ObjectKind::IdentityRegistry, previous_registry),
            (ObjectKind::IdentityRegistry, active_registry),
            (ObjectKind::IdentityMapping, previous_mapping),
            (ObjectKind::IdentityMapping, active_mapping),
            (ObjectKind::MountPolicy, previous_mount),
            (ObjectKind::MountPolicy, active_mount),
            (ObjectKind::NativeAcl, shared_acl),
            (ObjectKind::SecurityManifest, &previous_security),
            (ObjectKind::SecurityManifest, &active_security),
            (ObjectKind::GenerationManifest, &previous),
            (ObjectKind::GenerationManifest, &active),
        ]);
        let store = ContentPack::parse(&image)?;
        let roots = store.generation_roots(ContentDigest::of(&active), 2)?;
        assert_eq!(roots.len(), 13);
        assert_eq!(
            roots,
            store.generation_roots(ContentDigest::of(&active), 2)?
        );
        for (index, root) in roots.iter().enumerate() {
            assert!(!roots[..index].contains(root));
        }
        let retained = store.retain(&roots, roots.len(), image.len())?;
        assert_eq!(ContentPack::parse(&retained)?.len(), 13);
        Ok(())
    }

    #[test]
    fn canonical_pack_verifies_and_resolves() -> Result<(), ContentError> {
        let image = pack(&[
            (ObjectKind::SystemConfig, b"config"),
            (ObjectKind::Data, b"data"),
        ]);
        let parsed = ContentPack::parse(&image)?;
        assert_eq!(parsed.len(), 2);
        let object = parsed
            .get(ContentDigest::of(b"config"))
            .ok_or(ContentError::InvalidRecord)?;
        assert_eq!(object.kind, ObjectKind::SystemConfig);
        assert_eq!(object.bytes, b"config");
        Ok(())
    }

    #[test]
    fn corruption_and_duplicate_content_fail_closed() {
        let mut corrupt = pack(&[(ObjectKind::Data, b"data")]);
        let last = corrupt.len() - 1;
        corrupt[last] ^= 1;
        assert!(matches!(
            ContentPack::parse(&corrupt),
            Err(ContentError::Checksum)
        ));

        let duplicate = pack(&[(ObjectKind::Data, b"same"), (ObjectKind::Data, b"same")]);
        assert!(matches!(
            ContentPack::parse(&duplicate),
            Err(ContentError::InvalidRecord)
        ));
    }

    #[test]
    fn retain_is_bounded_deduplicated_and_reverified() -> Result<(), ContentError> {
        let image = pack(&[
            (ObjectKind::SystemConfig, b"config"),
            (ObjectKind::Data, b"keep"),
            (ObjectKind::Data, b"discard"),
        ]);
        let source = ContentPack::parse(&image)?;
        let config = ContentDigest::of(b"config");
        let keep = ContentDigest::of(b"keep");
        let rebuilt = source.retain(&[keep, config, keep], 2, 1024)?;
        let retained = ContentPack::parse(&rebuilt)?;
        assert_eq!(retained.len(), 2);
        assert!(retained.get(config).is_some());
        assert!(retained.get(keep).is_some());
        assert!(retained.get(ContentDigest::of(b"discard")).is_none());
        assert_eq!(
            source.retain(&[ContentDigest::of(b"missing")], 2, 1024),
            Err(ContentError::MissingObject)
        );
        Ok(())
    }
}
