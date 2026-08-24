//! Versioned bounded system and service-startup configuration.
#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;

use alloc::string::{String, ToString};
use alloc::vec::Vec;
use troe_content::ContentDigest;
use troe_vfs::{MAX_PATH_BYTES, canonicalize};

/// Product-name-independent system-configuration v1 format identifier.
pub const CONFIG_V1_MAGIC: [u8; 8] = *b"SCFGv1\0\0";
/// Product-name-independent SCFG activation-pointer identifier.
pub const ACTIVATION_V1_MAGIC: [u8; 8] = *b"SACTv1\0\0";
/// Exact encoded activation-pointer size.
pub const ACTIVATION_V1_BYTES: usize = 128;
const HEADER_BYTES: usize = 64;
const RECORD_BYTES: usize = 64;
const MAX_CONFIG_BYTES: usize = 16 * 1024;
const MAX_SERVICES: usize = 32;
const MAX_DEPENDENCIES: usize = 4;
const MAX_SERVICE_NAME_BYTES: usize = 32;
const MAX_BOOT_ATTEMPTS: u8 = 8;
const MAX_HEALTH_WINDOW_MS: u32 = 10 * 60 * 1000;
const MAX_EXECUTION_LEASE_MS: u16 = 50;
const MAX_INITIAL_HANDLES: u8 = 8;
const FLAG_FALLBACK_PREVIOUS: u8 = 1 << 0;
const FLAG_RECOVERY_SHELL: u8 = 1 << 1;
const KNOWN_FLAGS: u8 = FLAG_FALLBACK_PREVIOUS | FLAG_RECOVERY_SHELL;
const ACTIVATION_PREVIOUS: u16 = 1;
const ACTIVATION_CHECKSUM_OFFSET: usize = 112;

/// Immutable identity of one fully validated SCFG image.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ConfigReference {
    generation: u64,
    byte_count: u32,
    checksum: u32,
    digest: ContentDigest,
}

impl ConfigReference {
    /// Validate an SCFG image and retain its exact content identity.
    ///
    /// # Errors
    ///
    /// Returns the underlying canonical SCFG parse failure.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ConfigError> {
        let config = parse_config(bytes)?;
        Ok(Self {
            generation: config.generation(),
            byte_count: u32::try_from(bytes.len()).map_err(|_| ConfigError::InvalidHeader)?,
            checksum: read_u32(bytes, 20)?,
            digest: ContentDigest::of(bytes),
        })
    }

    /// SCFG generation identity.
    #[must_use]
    pub const fn generation(self) -> u64 {
        self.generation
    }

    /// Exact encoded SCFG length.
    #[must_use]
    pub const fn byte_count(self) -> u32 {
        self.byte_count
    }

    /// Canonical SCFG CRC32 field.
    #[must_use]
    pub const fn checksum(self) -> u32 {
        self.checksum
    }

    /// SHA-256 immutable content-store address.
    #[must_use]
    pub const fn digest(self) -> ContentDigest {
        self.digest
    }

    /// Whether bytes parse canonically and reproduce this exact identity.
    #[must_use]
    pub fn matches(self, bytes: &[u8]) -> bool {
        Self::from_bytes(bytes) == Ok(self)
    }
}

/// Crash-consistent active and predecessor SCFG references stored in TXSLOT.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ActivationPointer {
    active: ConfigReference,
    previous: Option<ConfigReference>,
}

impl ActivationPointer {
    /// Construct a canonical activation pointer.
    ///
    /// # Errors
    ///
    /// Rejects a predecessor that is not strictly older than the active SCFG.
    pub const fn new(
        active: ConfigReference,
        previous: Option<ConfigReference>,
    ) -> Result<Self, ActivationError> {
        if let Some(predecessor) = previous
            && predecessor.generation >= active.generation
        {
            return Err(ActivationError::InvalidPredecessor);
        }
        Ok(Self { active, previous })
    }

    /// Parse one exact checksummed SACT v1 record.
    ///
    /// # Errors
    ///
    /// Rejects noncanonical headers, checksum/reserved failures, empty
    /// references, and invalid predecessor ordering.
    pub fn parse(bytes: &[u8]) -> Result<Self, ActivationError> {
        if bytes.len() != ACTIVATION_V1_BYTES
            || bytes.get(..8) != Some(&ACTIVATION_V1_MAGIC)
            || read_activation_u16(bytes, 8)? != 1
            || read_activation_u16(bytes, 10)? != 0
            || read_activation_u16(bytes, 12)? != 128
        {
            return Err(ActivationError::InvalidHeader);
        }
        let flags = read_activation_u16(bytes, 14)?;
        if flags & !ACTIVATION_PREVIOUS != 0 || bytes[116..].iter().any(|byte| *byte != 0) {
            return Err(ActivationError::InvalidHeader);
        }
        let mut checked = [0_u8; ACTIVATION_V1_BYTES];
        checked.copy_from_slice(bytes);
        checked[ACTIVATION_CHECKSUM_OFFSET..ACTIVATION_CHECKSUM_OFFSET + 4].fill(0);
        if crc32(&checked) != read_activation_u32(bytes, ACTIVATION_CHECKSUM_OFFSET)? {
            return Err(ActivationError::Checksum);
        }
        let active = read_reference(bytes, 16)?;
        let previous = if flags & ACTIVATION_PREVIOUS != 0 {
            Some(read_reference(bytes, 64)?)
        } else {
            if bytes[64..112].iter().any(|byte| *byte != 0) {
                return Err(ActivationError::InvalidPredecessor);
            }
            None
        };
        Self::new(active, previous)
    }

    /// Encode the canonical checksummed SACT v1 record.
    #[must_use]
    pub fn encode(self) -> [u8; ACTIVATION_V1_BYTES] {
        let mut bytes = [0_u8; ACTIVATION_V1_BYTES];
        bytes[..8].copy_from_slice(&ACTIVATION_V1_MAGIC);
        bytes[8..10].copy_from_slice(&1_u16.to_le_bytes());
        bytes[12..14].copy_from_slice(&128_u16.to_le_bytes());
        if self.previous.is_some() {
            bytes[14..16].copy_from_slice(&ACTIVATION_PREVIOUS.to_le_bytes());
        }
        write_reference(&mut bytes, 16, self.active);
        if let Some(previous) = self.previous {
            write_reference(&mut bytes, 64, previous);
        }
        let checksum = crc32(&bytes);
        bytes[ACTIVATION_CHECKSUM_OFFSET..ACTIVATION_CHECKSUM_OFFSET + 4]
            .copy_from_slice(&checksum.to_le_bytes());
        bytes
    }

    /// Selected active configuration identity.
    #[must_use]
    pub const fn active(self) -> ConfigReference {
        self.active
    }

    /// Optional rollback predecessor identity.
    #[must_use]
    pub const fn previous(self) -> Option<ConfigReference> {
        self.previous
    }
}

/// Stable SACT parse or construction failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ActivationError {
    /// Header, flags, reserved bytes, or a reference was malformed.
    InvalidHeader,
    /// Whole-record CRC32 failed.
    Checksum,
    /// The predecessor was absent-but-nonzero or not strictly older.
    InvalidPredecessor,
}

/// When one configured service becomes eligible for startup.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum StartupMode {
    /// Required during ordinary generation activation.
    BootRequired = 1,
    /// Attempted during activation but not required for generation health.
    BootOptional = 2,
    /// Started only by an explicitly authorized client.
    OnDemand = 3,
    /// Eligible only while the static recovery environment is active.
    RecoveryOnly = 4,
}

/// Bounded response to a service startup or health failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum FailureAction {
    /// Record the optional failure and continue activation.
    Continue = 1,
    /// Retry only up to the service's explicit restart ceiling.
    Restart = 2,
    /// Reject this generation and activate its declared predecessor.
    PreviousGeneration = 3,
    /// Reject this generation and enter the static recovery shell.
    RecoveryShell = 4,
}

/// Global activation and recovery policy carried by one generation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RecoveryPolicy {
    max_boot_attempts: u8,
    health_window_ms: u32,
    fallback_previous: bool,
    recovery_shell: bool,
}

impl RecoveryPolicy {
    /// Maximum complete activation attempts before fallback.
    #[must_use]
    pub const fn max_boot_attempts(self) -> u8 {
        self.max_boot_attempts
    }

    /// Deadline for the generation-wide health decision.
    #[must_use]
    pub const fn health_window_ms(self) -> u32 {
        self.health_window_ms
    }

    /// Whether a declared predecessor may be reactivated.
    #[must_use]
    pub const fn fallback_previous(self) -> bool {
        self.fallback_previous
    }

    /// Whether the independent static recovery shell remains a final fallback.
    #[must_use]
    pub const fn recovery_shell(self) -> bool {
        self.recovery_shell
    }
}

/// One canonical service-startup record.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ServiceConfig {
    id: u32,
    mode: StartupMode,
    failure_action: FailureAction,
    restart_limit: u8,
    initial_handles: u8,
    execution_lease_ms: u16,
    health_timeout_ms: u32,
    lifetime_limit_ms: u32,
    capability_bits: u32,
    dependencies: Vec<u32>,
    name: String,
    artifact_path: String,
}

impl ServiceConfig {
    /// Stable nonzero service identity within configuration formats.
    #[must_use]
    pub const fn id(&self) -> u32 {
        self.id
    }

    /// Startup eligibility policy.
    #[must_use]
    pub const fn mode(&self) -> StartupMode {
        self.mode
    }

    /// Failure response selected before activation.
    #[must_use]
    pub const fn failure_action(&self) -> FailureAction {
        self.failure_action
    }

    /// Maximum restarts when the action is [`FailureAction::Restart`].
    #[must_use]
    pub const fn restart_limit(&self) -> u8 {
        self.restart_limit
    }

    /// Maximum initial handles granted by launch policy.
    #[must_use]
    pub const fn initial_handles(&self) -> u8 {
        self.initial_handles
    }

    /// Maximum uninterrupted application lease.
    #[must_use]
    pub const fn execution_lease_ms(&self) -> u16 {
        self.execution_lease_ms
    }

    /// Deadline for this service's health result.
    #[must_use]
    pub const fn health_timeout_ms(&self) -> u32 {
        self.health_timeout_ms
    }

    /// Total service lifetime ceiling, or zero for no additional ceiling.
    #[must_use]
    pub const fn lifetime_limit_ms(&self) -> u32 {
        self.lifetime_limit_ms
    }

    /// Explicit launcher-defined capability request bits.
    #[must_use]
    pub const fn capability_bits(&self) -> u32 {
        self.capability_bits
    }

    /// Sorted dependencies, all of which precede this record.
    #[must_use]
    pub fn dependencies(&self) -> &[u32] {
        &self.dependencies
    }

    /// Stable ASCII service name used for diagnostics and lookup.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Canonical absolute path to one immutable target-specific artifact.
    #[must_use]
    pub fn artifact_path(&self) -> &str {
        &self.artifact_path
    }
}

/// Fully validated immutable desired-system configuration.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SystemConfig {
    generation: u64,
    previous_generation: Option<u64>,
    recovery: RecoveryPolicy,
    services: Vec<ServiceConfig>,
}

impl SystemConfig {
    /// Nonzero monotonically selected generation identity.
    #[must_use]
    pub const fn generation(&self) -> u64 {
        self.generation
    }

    /// Explicit predecessor eligible for bounded rollback.
    #[must_use]
    pub const fn previous_generation(&self) -> Option<u64> {
        self.previous_generation
    }

    /// Generation-wide activation and recovery policy.
    #[must_use]
    pub const fn recovery(&self) -> RecoveryPolicy {
        self.recovery
    }

    /// Canonically ID-sorted service records.
    #[must_use]
    pub fn services(&self) -> &[ServiceConfig] {
        &self.services
    }
}

/// Stable configuration rejection reasons.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConfigError {
    /// Header magic, version, sizes, reserved fields, or checksum is invalid.
    InvalidHeader,
    /// Global activation or fallback behavior is invalid or inconsistent.
    InvalidRecoveryPolicy,
    /// A service record contains an unknown or inconsistent policy value.
    InvalidService,
    /// Service identities or dependency edges are noncanonical.
    InvalidDependency,
    /// A name or artifact string is invalid, aliased, or noncanonical.
    InvalidString,
    /// The bounded parser could not retain validated metadata.
    MetadataExhausted,
}

/// Parse one allocation-bounded canonical configuration image.
///
/// # Errors
///
/// Rejects every unknown version or flag, invalid length/checksum/reserved byte,
/// invalid recovery policy, unsorted/cyclic dependency, invalid string, and
/// allocation failure before returning a partial configuration.
pub fn parse_config(bytes: &[u8]) -> Result<SystemConfig, ConfigError> {
    if bytes.len() < HEADER_BYTES
        || bytes.len() > MAX_CONFIG_BYTES
        || bytes.get(..8) != Some(&CONFIG_V1_MAGIC)
        || read_u16(bytes, 8)? != 1
        || read_u16(bytes, 10)? != 0
        || read_u16(bytes, 12)? != 64
        || read_u16(bytes, 14)? != 64
        || usize::try_from(read_u32(bytes, 16)?).map_err(|_| ConfigError::InvalidHeader)?
            != bytes.len()
        || bytes[52..HEADER_BYTES].iter().any(|byte| *byte != 0)
    {
        return Err(ConfigError::InvalidHeader);
    }
    let expected_crc = read_u32(bytes, 20)?;
    let mut checksum_bytes = Vec::new();
    checksum_bytes
        .try_reserve_exact(bytes.len())
        .map_err(|_| ConfigError::MetadataExhausted)?;
    checksum_bytes.extend_from_slice(bytes);
    checksum_bytes[20..24].fill(0);
    if crc32(&checksum_bytes) != expected_crc {
        return Err(ConfigError::InvalidHeader);
    }
    let generation = read_u64(bytes, 24)?;
    let previous_raw = read_u64(bytes, 32)?;
    let service_count = usize::from(read_u16(bytes, 40)?);
    let max_boot_attempts = bytes[42];
    let flags = bytes[43];
    let health_window_ms = read_u32(bytes, 44)?;
    let string_bytes =
        usize::try_from(read_u32(bytes, 48)?).map_err(|_| ConfigError::InvalidHeader)?;
    let record_bytes = service_count
        .checked_mul(RECORD_BYTES)
        .ok_or(ConfigError::InvalidHeader)?;
    let string_start = HEADER_BYTES
        .checked_add(record_bytes)
        .ok_or(ConfigError::InvalidHeader)?;
    if generation == 0
        || (previous_raw != 0 && previous_raw >= generation)
        || service_count > MAX_SERVICES
        || string_start.checked_add(string_bytes) != Some(bytes.len())
        || flags & !KNOWN_FLAGS != 0
        || flags & FLAG_RECOVERY_SHELL == 0
        || max_boot_attempts == 0
        || max_boot_attempts > MAX_BOOT_ATTEMPTS
        || health_window_ms == 0
        || health_window_ms > MAX_HEALTH_WINDOW_MS
        || (flags & FLAG_FALLBACK_PREVIOUS != 0) != (previous_raw != 0)
    {
        return Err(ConfigError::InvalidRecoveryPolicy);
    }
    let recovery = RecoveryPolicy {
        max_boot_attempts,
        health_window_ms,
        fallback_previous: flags & FLAG_FALLBACK_PREVIOUS != 0,
        recovery_shell: true,
    };
    let string_table = bytes
        .get(string_start..)
        .ok_or(ConfigError::InvalidHeader)?;
    let mut services = Vec::new();
    services
        .try_reserve_exact(service_count)
        .map_err(|_| ConfigError::MetadataExhausted)?;
    let mut expected_string_offset = 0_usize;
    for index in 0..service_count {
        let start = HEADER_BYTES + index * RECORD_BYTES;
        let record = bytes
            .get(start..start + RECORD_BYTES)
            .ok_or(ConfigError::InvalidHeader)?;
        let service = parse_service(record, string_table, &services, &mut expected_string_offset)?;
        services.push(service);
    }
    if expected_string_offset != string_table.len() {
        return Err(ConfigError::InvalidString);
    }
    Ok(SystemConfig {
        generation,
        previous_generation: (previous_raw != 0).then_some(previous_raw),
        recovery,
        services,
    })
}

fn parse_service(
    record: &[u8],
    strings: &[u8],
    previous: &[ServiceConfig],
    expected_string_offset: &mut usize,
) -> Result<ServiceConfig, ConfigError> {
    if record.len() != RECORD_BYTES
        || record[11] != 0
        || read_u16(record, 46)? != 0
        || read_u16(record, 54)? != 0
        || record[56..].iter().any(|byte| *byte != 0)
    {
        return Err(ConfigError::InvalidService);
    }
    let id = read_u32(record, 0)?;
    if id == 0 || previous.last().is_some_and(|service| service.id >= id) {
        return Err(ConfigError::InvalidDependency);
    }
    let mode = match record[4] {
        1 => StartupMode::BootRequired,
        2 => StartupMode::BootOptional,
        3 => StartupMode::OnDemand,
        4 => StartupMode::RecoveryOnly,
        _ => return Err(ConfigError::InvalidService),
    };
    let failure_action = match record[5] {
        1 => FailureAction::Continue,
        2 => FailureAction::Restart,
        3 => FailureAction::PreviousGeneration,
        4 => FailureAction::RecoveryShell,
        _ => return Err(ConfigError::InvalidService),
    };
    let restart_limit = record[6];
    let initial_handles = record[7];
    let execution_lease_ms = read_u16(record, 8)?;
    let dependency_count = usize::from(record[10]);
    let health_timeout_ms = read_u32(record, 12)?;
    let lifetime_limit_ms = read_u32(record, 16)?;
    if execution_lease_ms == 0
        || execution_lease_ms > MAX_EXECUTION_LEASE_MS
        || initial_handles > MAX_INITIAL_HANDLES
        || dependency_count > MAX_DEPENDENCIES
        || (failure_action == FailureAction::Restart) != (restart_limit != 0)
        || (mode == StartupMode::BootRequired && failure_action == FailureAction::Continue)
        || (mode == StartupMode::RecoveryOnly
            && !matches!(
                failure_action,
                FailureAction::Continue | FailureAction::Restart
            ))
        || (matches!(mode, StartupMode::BootRequired | StartupMode::BootOptional)
            && health_timeout_ms == 0)
        || (lifetime_limit_ms != 0 && lifetime_limit_ms < health_timeout_ms)
    {
        return Err(ConfigError::InvalidService);
    }
    let dependencies = parse_dependencies(record, dependency_count, previous)?;
    let name = parse_string(
        strings,
        read_u32(record, 40)?,
        read_u16(record, 44)?,
        expected_string_offset,
        MAX_SERVICE_NAME_BYTES,
    )?;
    if !name.bytes().all(|byte| {
        byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'-' | b'_')
    }) {
        return Err(ConfigError::InvalidString);
    }
    let artifact_path = parse_string(
        strings,
        read_u32(record, 48)?,
        read_u16(record, 52)?,
        expected_string_offset,
        MAX_PATH_BYTES,
    )?;
    if canonicalize("/", &artifact_path).map_err(|_| ConfigError::InvalidString)? != artifact_path
        || !artifact_path.starts_with('/')
    {
        return Err(ConfigError::InvalidString);
    }
    Ok(ServiceConfig {
        id,
        mode,
        failure_action,
        restart_limit,
        initial_handles,
        execution_lease_ms,
        health_timeout_ms,
        lifetime_limit_ms,
        capability_bits: read_u32(record, 20)?,
        dependencies,
        name,
        artifact_path,
    })
}

fn parse_dependencies(
    record: &[u8],
    dependency_count: usize,
    previous: &[ServiceConfig],
) -> Result<Vec<u32>, ConfigError> {
    let mut dependencies = Vec::new();
    dependencies
        .try_reserve_exact(dependency_count)
        .map_err(|_| ConfigError::MetadataExhausted)?;
    for index in 0..MAX_DEPENDENCIES {
        let dependency = read_u32(record, 24 + index * 4)?;
        if index < dependency_count {
            if dependency == 0
                || dependencies
                    .last()
                    .is_some_and(|value| *value >= dependency)
                || !previous.iter().any(|service| service.id == dependency)
            {
                return Err(ConfigError::InvalidDependency);
            }
            dependencies.push(dependency);
        } else if dependency != 0 {
            return Err(ConfigError::InvalidDependency);
        }
    }
    Ok(dependencies)
}

fn parse_string(
    strings: &[u8],
    offset: u32,
    length: u16,
    expected_offset: &mut usize,
    limit: usize,
) -> Result<String, ConfigError> {
    let offset = usize::try_from(offset).map_err(|_| ConfigError::InvalidString)?;
    let length = usize::from(length);
    if offset != *expected_offset || length == 0 || length > limit {
        return Err(ConfigError::InvalidString);
    }
    let end = offset
        .checked_add(length)
        .ok_or(ConfigError::InvalidString)?;
    let value = core::str::from_utf8(strings.get(offset..end).ok_or(ConfigError::InvalidString)?)
        .map_err(|_| ConfigError::InvalidString)?;
    if value.as_bytes().contains(&0) {
        return Err(ConfigError::InvalidString);
    }
    *expected_offset = end;
    Ok(value.to_string())
}

fn read_u16(bytes: &[u8], offset: usize) -> Result<u16, ConfigError> {
    let value = bytes
        .get(offset..offset + 2)
        .and_then(|slice| <[u8; 2]>::try_from(slice).ok())
        .ok_or(ConfigError::InvalidHeader)?;
    Ok(u16::from_le_bytes(value))
}

fn read_u32(bytes: &[u8], offset: usize) -> Result<u32, ConfigError> {
    let value = bytes
        .get(offset..offset + 4)
        .and_then(|slice| <[u8; 4]>::try_from(slice).ok())
        .ok_or(ConfigError::InvalidHeader)?;
    Ok(u32::from_le_bytes(value))
}

fn read_u64(bytes: &[u8], offset: usize) -> Result<u64, ConfigError> {
    let value = bytes
        .get(offset..offset + 8)
        .and_then(|slice| <[u8; 8]>::try_from(slice).ok())
        .ok_or(ConfigError::InvalidHeader)?;
    Ok(u64::from_le_bytes(value))
}

fn read_activation_u16(bytes: &[u8], offset: usize) -> Result<u16, ActivationError> {
    let raw = bytes
        .get(offset..offset + 2)
        .ok_or(ActivationError::InvalidHeader)?;
    Ok(u16::from_le_bytes([raw[0], raw[1]]))
}

fn read_activation_u32(bytes: &[u8], offset: usize) -> Result<u32, ActivationError> {
    let raw = bytes
        .get(offset..offset + 4)
        .ok_or(ActivationError::InvalidHeader)?;
    Ok(u32::from_le_bytes([raw[0], raw[1], raw[2], raw[3]]))
}

fn read_activation_u64(bytes: &[u8], offset: usize) -> Result<u64, ActivationError> {
    let raw = bytes
        .get(offset..offset + 8)
        .ok_or(ActivationError::InvalidHeader)?;
    Ok(u64::from_le_bytes([
        raw[0], raw[1], raw[2], raw[3], raw[4], raw[5], raw[6], raw[7],
    ]))
}

fn read_reference(bytes: &[u8], offset: usize) -> Result<ConfigReference, ActivationError> {
    let reference = ConfigReference {
        generation: read_activation_u64(bytes, offset)?,
        byte_count: read_activation_u32(bytes, offset + 8)?,
        checksum: read_activation_u32(bytes, offset + 12)?,
        digest: {
            let mut digest = [0_u8; 32];
            digest.copy_from_slice(
                bytes
                    .get(offset + 16..offset + 48)
                    .ok_or(ActivationError::InvalidHeader)?,
            );
            ContentDigest::from_bytes(digest)
        },
    };
    if reference.generation == 0
        || usize::try_from(reference.byte_count).map_or(true, |count| {
            !(HEADER_BYTES..=MAX_CONFIG_BYTES).contains(&count)
        })
        || reference.digest.bytes().iter().all(|byte| *byte == 0)
    {
        return Err(ActivationError::InvalidHeader);
    }
    Ok(reference)
}

fn write_reference(bytes: &mut [u8], offset: usize, reference: ConfigReference) {
    bytes[offset..offset + 8].copy_from_slice(&reference.generation.to_le_bytes());
    bytes[offset + 8..offset + 12].copy_from_slice(&reference.byte_count.to_le_bytes());
    bytes[offset + 12..offset + 16].copy_from_slice(&reference.checksum.to_le_bytes());
    bytes[offset + 16..offset + 48].copy_from_slice(&reference.digest.bytes());
}

fn crc32(bytes: &[u8]) -> u32 {
    let mut crc = u32::MAX;
    for byte in bytes {
        crc ^= u32::from(*byte);
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
        ACTIVATION_V1_BYTES, ActivationError, ActivationPointer, CONFIG_V1_MAGIC, ConfigError,
        ConfigReference, ContentDigest, FailureAction, HEADER_BYTES, RECORD_BYTES, StartupMode,
        crc32, parse_config,
    };

    fn valid_config() -> Vec<u8> {
        let strings = b"storage/bin/storage.kexshell/bin/shell.kex";
        let mut bytes = vec![0_u8; HEADER_BYTES + 2 * RECORD_BYTES + strings.len()];
        bytes[..8].copy_from_slice(&CONFIG_V1_MAGIC);
        put_u16(&mut bytes, 8, 1);
        put_u16(&mut bytes, 12, 64);
        put_u16(&mut bytes, 14, 64);
        let total = u32::try_from(bytes.len()).unwrap_or(0);
        put_u32(&mut bytes, 16, total);
        put_u64(&mut bytes, 24, 7);
        put_u64(&mut bytes, 32, 6);
        put_u16(&mut bytes, 40, 2);
        bytes[42] = 3;
        bytes[43] = 3;
        put_u32(&mut bytes, 44, 30_000);
        put_u32(&mut bytes, 48, u32::try_from(strings.len()).unwrap_or(0));
        service_record(&mut bytes[64..128], 1, 0, 7, 16, 0, 0);
        service_record(&mut bytes[128..192], 2, 23, 5, 14, 0, 1);
        bytes[192..].copy_from_slice(strings);
        refresh_crc(&mut bytes);
        bytes
    }

    fn service_record(
        record: &mut [u8],
        id: u32,
        name_offset: u32,
        name_length: u16,
        artifact_length: u16,
        artifact_offset: u32,
        dependency: u32,
    ) {
        put_u32(record, 0, id);
        record[4] = 1;
        record[5] = 4;
        record[7] = 2;
        put_u16(record, 8, 50);
        record[10] = u8::from(dependency != 0);
        put_u32(record, 12, 5_000);
        put_u32(record, 16, 60_000);
        put_u32(record, 24, dependency);
        put_u32(record, 40, name_offset);
        put_u16(record, 44, name_length);
        put_u32(
            record,
            48,
            name_offset + u32::from(name_length) + artifact_offset,
        );
        put_u16(record, 52, artifact_length);
    }

    fn refresh_crc(bytes: &mut [u8]) {
        put_u32(bytes, 20, 0);
        put_u32(bytes, 20, crc32(bytes));
    }

    fn put_u16(bytes: &mut [u8], offset: usize, value: u16) {
        bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
    }

    fn put_u32(bytes: &mut [u8], offset: usize, value: u32) {
        bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }

    fn put_u64(bytes: &mut [u8], offset: usize, value: u64) {
        bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
    }

    #[test]
    fn valid_config_has_canonical_dependencies_and_recovery() -> Result<(), ConfigError> {
        let config = parse_config(&valid_config())?;
        assert_eq!(config.generation(), 7);
        assert_eq!(config.previous_generation(), Some(6));
        assert!(config.recovery().fallback_previous());
        assert!(config.recovery().recovery_shell());
        assert_eq!(config.services().len(), 2);
        assert_eq!(config.services()[0].name(), "storage");
        assert_eq!(config.services()[1].dependencies(), &[1]);
        assert_eq!(config.services()[1].mode(), StartupMode::BootRequired);
        assert_eq!(
            config.services()[1].failure_action(),
            FailureAction::RecoveryShell
        );
        Ok(())
    }

    #[test]
    fn checksum_reserved_and_trailing_bytes_fail_closed() {
        let mut checksum = valid_config();
        checksum[24] ^= 1;
        assert_eq!(parse_config(&checksum), Err(ConfigError::InvalidHeader));

        let mut reserved = valid_config();
        reserved[63] = 1;
        refresh_crc(&mut reserved);
        assert_eq!(parse_config(&reserved), Err(ConfigError::InvalidHeader));
    }

    #[test]
    fn recovery_requires_static_shell_and_matching_predecessor() {
        let mut no_shell = valid_config();
        no_shell[43] = 1;
        refresh_crc(&mut no_shell);
        assert_eq!(
            parse_config(&no_shell),
            Err(ConfigError::InvalidRecoveryPolicy)
        );

        let mut no_previous = valid_config();
        put_u64(&mut no_previous, 32, 0);
        refresh_crc(&mut no_previous);
        assert_eq!(
            parse_config(&no_previous),
            Err(ConfigError::InvalidRecoveryPolicy)
        );

        let mut forward_previous = valid_config();
        put_u64(&mut forward_previous, 32, 8);
        refresh_crc(&mut forward_previous);
        assert_eq!(
            parse_config(&forward_previous),
            Err(ConfigError::InvalidRecoveryPolicy)
        );
    }

    #[test]
    fn service_order_dependencies_and_strings_are_canonical() {
        let mut dependency = valid_config();
        put_u32(&mut dependency[128..192], 24, 2);
        refresh_crc(&mut dependency);
        assert_eq!(
            parse_config(&dependency),
            Err(ConfigError::InvalidDependency)
        );

        let mut alias = valid_config();
        put_u32(&mut alias[128..192], 40, 0);
        refresh_crc(&mut alias);
        assert_eq!(parse_config(&alias), Err(ConfigError::InvalidString));
    }

    #[test]
    fn activation_pointer_round_trips_exact_config_identities() -> Result<(), ConfigError> {
        let config = valid_config();
        let active = ConfigReference::from_bytes(&config)?;
        assert!(active.matches(&config));
        let previous = ConfigReference {
            generation: 6,
            byte_count: 64,
            checksum: 0x1234_5678,
            digest: ContentDigest::of(b"previous"),
        };
        let pointer = ActivationPointer::new(active, Some(previous))
            .map_err(|_| ConfigError::InvalidRecoveryPolicy)?;
        let encoded = pointer.encode();
        assert_eq!(encoded.len(), ACTIVATION_V1_BYTES);
        assert_eq!(ActivationPointer::parse(&encoded), Ok(pointer));
        assert_eq!(pointer.active(), active);
        assert_eq!(pointer.previous(), Some(previous));
        Ok(())
    }

    #[test]
    fn activation_pointer_checksum_and_predecessor_fail_closed() -> Result<(), ConfigError> {
        let active = ConfigReference::from_bytes(&valid_config())?;
        assert_eq!(
            ActivationPointer::new(active, Some(active)),
            Err(ActivationError::InvalidPredecessor)
        );
        let pointer =
            ActivationPointer::new(active, None).map_err(|_| ConfigError::InvalidRecoveryPolicy)?;
        let mut encoded = pointer.encode();
        encoded[24] ^= 1;
        assert_eq!(
            ActivationPointer::parse(&encoded),
            Err(ActivationError::Checksum)
        );
        Ok(())
    }
}
