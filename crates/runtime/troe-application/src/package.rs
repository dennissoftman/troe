//! The KEX package envelope binding a manifest to one executable.

use crate::bytes::{write_u16, write_u32, write_u64};
use crate::{
    ApplicationLimits, KEX_PACKAGE_V1_HEADER_BYTES, KEX_PACKAGE_V1_MAGIC, MAX_KEX_PACKAGE_BYTES,
    PACKAGE_FLAG_COMPLETION, PACKAGE_HEADER_BYTES, PACKAGE_HEADER_COMPLETION_OFFSET,
    PACKAGE_HEADER_EXECUTABLE_BYTES, PACKAGE_HEADER_EXECUTABLE_OFFSET, PACKAGE_HEADER_FLAGS,
    PACKAGE_HEADER_MAJOR, PACKAGE_HEADER_MANIFEST_BYTES, PACKAGE_HEADER_MANIFEST_OFFSET,
    PACKAGE_HEADER_MINOR, PACKAGE_HEADER_PACKAGE_BYTES, PACKAGE_MAJOR, PACKAGE_MINOR,
};
use alloc::vec::Vec;
use core::fmt;
use troe_abi::requirements;

/// One validated single-file package borrowing its manifest and KEX executable.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct KexPackage<'package> {
    manifest: requirements::Manifest<'package>,
    executable: &'package [u8],
    completion: Option<&'package [u8]>,
}

impl<'package> KexPackage<'package> {
    /// Optional startup interfaces required by this package.
    #[must_use]
    pub const fn requirements(self) -> requirements::Manifest<'package> {
        self.manifest
    }

    /// Complete canonical KEX v1 executable contained by this package.
    #[must_use]
    pub const fn executable(self) -> &'package [u8] {
        self.executable
    }

    /// Canonical package-owned CMPL artifact, when present.
    #[must_use]
    pub const fn completion(self) -> Option<&'package [u8]> {
        self.completion
    }
}

/// Deterministic single-file package rejection category.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PackageError {
    /// Input exceeds the complete package admission ceiling.
    PackageTooLarge,
    /// Input is shorter than the fixed package header.
    TruncatedHeader,
    /// Header magic is not the KEX package identifier.
    InvalidMagic,
    /// Package major or minor version is unsupported.
    UnsupportedVersion,
    /// Fixed header or embedded ranges are noncanonical.
    InvalidLayout,
    /// An unsupported package flag or reserved field is nonzero.
    NonzeroReserved,
    /// Declared package size differs from the exact input length.
    LengthMismatch,
    /// Embedded capability requirements are malformed.
    InvalidManifest,
    /// Embedded package-owned completion metadata is malformed.
    InvalidCompletion,
}

impl fmt::Display for PackageError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::PackageTooLarge => "KEX package exceeds the staging budget",
            Self::TruncatedHeader => "KEX package header is truncated",
            Self::InvalidMagic => "KEX package magic is invalid",
            Self::UnsupportedVersion => "KEX package version is unsupported",
            Self::InvalidLayout => "KEX package layout is noncanonical",
            Self::NonzeroReserved => "KEX package reserved field or unsupported flag is nonzero",
            Self::LengthMismatch => "KEX package declared length differs from its input length",
            Self::InvalidManifest => "KEX package capability manifest is invalid",
            Self::InvalidCompletion => "KEX package completion artifact is invalid",
        })
    }
}

/// Deterministic single-file package encoding failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PackageEncodeError {
    /// The executable is empty or exceeds the KEX v1 ceiling.
    InvalidExecutable,
    /// The requirements are excessive, duplicate, unordered, or invalid.
    InvalidManifest,
    /// The supplied CMPL artifact is malformed or excessive.
    InvalidCompletion,
    /// Checked package layout arithmetic overflowed.
    ArithmeticOverflow,
    /// Exact output allocation failed.
    AllocationFailed,
}
/// Encode one canonical package containing requirements and a KEX v1 executable.
///
/// # Errors
///
/// Rejects empty or excessive executables, invalid requirements, checked
/// arithmetic failure, and exact allocation failure without producing output.
pub fn encode_kex_package(
    executable: &[u8],
    required: &[requirements::Requirement],
) -> Result<Vec<u8>, PackageEncodeError> {
    encode_kex_package_with_completion(executable, required, None)
}

/// Encode one canonical package with an optional package-owned CMPL artifact.
///
/// # Errors
///
/// Rejects malformed completion bytes in addition to the ordinary package
/// encoder failures. Completion is appended after the executable and bound by
/// the package envelope; it is never installed as a loose sidecar.
pub fn encode_kex_package_with_completion(
    executable: &[u8],
    required: &[requirements::Requirement],
    completion: Option<&[u8]>,
) -> Result<Vec<u8>, PackageEncodeError> {
    if executable.is_empty() || executable.len() > ApplicationLimits::standard().encoded_bytes() {
        return Err(PackageEncodeError::InvalidExecutable);
    }
    if let Some(bytes) = completion {
        troe_completion::CompletionArtifact::parse(bytes)
            .map_err(|_| PackageEncodeError::InvalidCompletion)?;
    }
    let mut manifest = [0_u8; requirements::MAX_MANIFEST_BYTES];
    let manifest_bytes = requirements::encode(required, &mut manifest)
        .map_err(|_| PackageEncodeError::InvalidManifest)?;
    let executable_offset = KEX_PACKAGE_V1_HEADER_BYTES
        .checked_add(manifest_bytes)
        .ok_or(PackageEncodeError::ArithmeticOverflow)?;
    let executable_end = executable_offset
        .checked_add(executable.len())
        .ok_or(PackageEncodeError::ArithmeticOverflow)?;
    let package_bytes = executable_end
        .checked_add(completion.map_or(0, <[u8]>::len))
        .ok_or(PackageEncodeError::ArithmeticOverflow)?;
    if package_bytes > MAX_KEX_PACKAGE_BYTES {
        return Err(PackageEncodeError::InvalidExecutable);
    }
    let mut package = Vec::new();
    package
        .try_reserve_exact(package_bytes)
        .map_err(|_| PackageEncodeError::AllocationFailed)?;
    package.resize(package_bytes, 0);
    package[..8].copy_from_slice(&KEX_PACKAGE_V1_MAGIC);
    write_u16(&mut package, PACKAGE_HEADER_MAJOR, PACKAGE_MAJOR);
    write_u16(&mut package, PACKAGE_HEADER_MINOR, PACKAGE_MINOR);
    write_u16(
        &mut package,
        PACKAGE_HEADER_FLAGS,
        if completion.is_some() {
            PACKAGE_FLAG_COMPLETION
        } else {
            0
        },
    );
    write_u16(
        &mut package,
        PACKAGE_HEADER_BYTES,
        u16::try_from(KEX_PACKAGE_V1_HEADER_BYTES)
            .map_err(|_| PackageEncodeError::ArithmeticOverflow)?,
    );
    write_u32(
        &mut package,
        PACKAGE_HEADER_MANIFEST_OFFSET,
        u32::try_from(KEX_PACKAGE_V1_HEADER_BYTES)
            .map_err(|_| PackageEncodeError::ArithmeticOverflow)?,
    );
    write_u32(
        &mut package,
        PACKAGE_HEADER_MANIFEST_BYTES,
        u32::try_from(manifest_bytes).map_err(|_| PackageEncodeError::ArithmeticOverflow)?,
    );
    write_u32(
        &mut package,
        PACKAGE_HEADER_EXECUTABLE_OFFSET,
        u32::try_from(executable_offset).map_err(|_| PackageEncodeError::ArithmeticOverflow)?,
    );
    if completion.is_some() {
        write_u32(
            &mut package,
            PACKAGE_HEADER_COMPLETION_OFFSET,
            u32::try_from(executable_end).map_err(|_| PackageEncodeError::ArithmeticOverflow)?,
        );
    }
    write_u64(
        &mut package,
        PACKAGE_HEADER_EXECUTABLE_BYTES,
        u64::try_from(executable.len()).map_err(|_| PackageEncodeError::ArithmeticOverflow)?,
    );
    write_u64(
        &mut package,
        PACKAGE_HEADER_PACKAGE_BYTES,
        u64::try_from(package_bytes).map_err(|_| PackageEncodeError::ArithmeticOverflow)?,
    );
    package[KEX_PACKAGE_V1_HEADER_BYTES..executable_offset]
        .copy_from_slice(&manifest[..manifest_bytes]);
    package[executable_offset..executable_end].copy_from_slice(executable);
    if let Some(completion) = completion {
        package[executable_end..].copy_from_slice(completion);
    }
    Ok(package)
}

/// Parse one exact single-file KEX application package.
///
/// This validates the envelope and capability manifest. Call [`parse_kex`] on
/// [`KexPackage::executable`] before allocating or mapping application pages.
///
/// # Errors
///
/// Rejects every truncation, unsupported version, noncanonical range,
/// reserved value, length mismatch, and malformed capability manifest.
pub fn parse_kex_package(package: &[u8]) -> Result<KexPackage<'_>, PackageError> {
    if package.len() > MAX_KEX_PACKAGE_BYTES {
        return Err(PackageError::PackageTooLarge);
    }
    if package.len() < KEX_PACKAGE_V1_HEADER_BYTES {
        return Err(PackageError::TruncatedHeader);
    }
    if package[..8] != KEX_PACKAGE_V1_MAGIC {
        return Err(PackageError::InvalidMagic);
    }
    if read_package_u16(package, PACKAGE_HEADER_MAJOR)? != PACKAGE_MAJOR
        || read_package_u16(package, PACKAGE_HEADER_MINOR)? != PACKAGE_MINOR
    {
        return Err(PackageError::UnsupportedVersion);
    }
    let flags = read_package_u16(package, PACKAGE_HEADER_FLAGS)?;
    if flags & !PACKAGE_FLAG_COMPLETION != 0 {
        return Err(PackageError::NonzeroReserved);
    }
    let header_bytes = usize::from(read_package_u16(package, PACKAGE_HEADER_BYTES)?);
    let manifest_offset =
        usize::try_from(read_package_u32(package, PACKAGE_HEADER_MANIFEST_OFFSET)?)
            .map_err(|_| PackageError::InvalidLayout)?;
    let manifest_bytes = usize::try_from(read_package_u32(package, PACKAGE_HEADER_MANIFEST_BYTES)?)
        .map_err(|_| PackageError::InvalidLayout)?;
    let executable_offset =
        usize::try_from(read_package_u32(package, PACKAGE_HEADER_EXECUTABLE_OFFSET)?)
            .map_err(|_| PackageError::InvalidLayout)?;
    let executable_bytes =
        usize::try_from(read_package_u64(package, PACKAGE_HEADER_EXECUTABLE_BYTES)?)
            .map_err(|_| PackageError::InvalidLayout)?;
    let completion_offset =
        usize::try_from(read_package_u32(package, PACKAGE_HEADER_COMPLETION_OFFSET)?)
            .map_err(|_| PackageError::InvalidLayout)?;
    let package_bytes = usize::try_from(read_package_u64(package, PACKAGE_HEADER_PACKAGE_BYTES)?)
        .map_err(|_| PackageError::LengthMismatch)?;
    if package_bytes != package.len() {
        return Err(PackageError::LengthMismatch);
    }
    let manifest_end = manifest_offset
        .checked_add(manifest_bytes)
        .ok_or(PackageError::InvalidLayout)?;
    let executable_end = executable_offset
        .checked_add(executable_bytes)
        .ok_or(PackageError::InvalidLayout)?;
    if header_bytes != KEX_PACKAGE_V1_HEADER_BYTES
        || manifest_offset != KEX_PACKAGE_V1_HEADER_BYTES
        || manifest_bytes > requirements::MAX_MANIFEST_BYTES
        || executable_offset != manifest_end
        || executable_bytes == 0
        || executable_bytes > ApplicationLimits::standard().encoded_bytes()
        || (flags == 0 && (completion_offset != 0 || executable_end != package.len()))
        || (flags == PACKAGE_FLAG_COMPLETION
            && (completion_offset != executable_end
                || completion_offset >= package.len()
                || package.len() - completion_offset > troe_completion::MAX_ARTIFACT_BYTES))
    {
        return Err(PackageError::InvalidLayout);
    }
    let manifest = requirements::Manifest::parse(
        package
            .get(manifest_offset..manifest_end)
            .ok_or(PackageError::InvalidLayout)?,
    )
    .map_err(|_| PackageError::InvalidManifest)?;
    let executable = package
        .get(executable_offset..executable_end)
        .ok_or(PackageError::InvalidLayout)?;
    let completion = if flags == PACKAGE_FLAG_COMPLETION {
        let bytes = package
            .get(completion_offset..)
            .ok_or(PackageError::InvalidLayout)?;
        troe_completion::CompletionArtifact::parse(bytes)
            .map_err(|_| PackageError::InvalidCompletion)?;
        Some(bytes)
    } else {
        None
    };
    Ok(KexPackage {
        manifest,
        executable,
        completion,
    })
}

/// Locate an embedded CMPL artifact using only the fixed package header and
/// authoritative file length.
///
/// This is the bounded activation-registry path: callers can read 48 header
/// bytes and then only the small completion range instead of staging an entire
/// executable. Full application launch still uses [`parse_kex_package`].
///
/// # Errors
///
/// Rejects incomplete headers, unknown flags or versions, inconsistent file
/// lengths, and noncanonical completion placement.
pub fn kex_package_completion_range(
    header: &[u8],
    file_bytes: u64,
) -> Result<Option<(u64, usize)>, PackageError> {
    if header.len() != KEX_PACKAGE_V1_HEADER_BYTES {
        return Err(PackageError::TruncatedHeader);
    }
    if header[..8] != KEX_PACKAGE_V1_MAGIC {
        return Err(PackageError::InvalidMagic);
    }
    if read_package_u16(header, PACKAGE_HEADER_MAJOR)? != PACKAGE_MAJOR
        || read_package_u16(header, PACKAGE_HEADER_MINOR)? != PACKAGE_MINOR
    {
        return Err(PackageError::UnsupportedVersion);
    }
    if usize::from(read_package_u16(header, PACKAGE_HEADER_BYTES)?) != KEX_PACKAGE_V1_HEADER_BYTES {
        return Err(PackageError::InvalidLayout);
    }
    let flags = read_package_u16(header, PACKAGE_HEADER_FLAGS)?;
    if flags & !PACKAGE_FLAG_COMPLETION != 0 {
        return Err(PackageError::NonzeroReserved);
    }
    let declared = read_package_u64(header, PACKAGE_HEADER_PACKAGE_BYTES)?;
    if declared != file_bytes
        || file_bytes > u64::try_from(MAX_KEX_PACKAGE_BYTES).unwrap_or(u64::MAX)
    {
        return Err(PackageError::LengthMismatch);
    }
    let manifest_offset = u64::from(read_package_u32(header, PACKAGE_HEADER_MANIFEST_OFFSET)?);
    let manifest_bytes = u64::from(read_package_u32(header, PACKAGE_HEADER_MANIFEST_BYTES)?);
    let executable_offset = u64::from(read_package_u32(header, PACKAGE_HEADER_EXECUTABLE_OFFSET)?);
    let executable_bytes = read_package_u64(header, PACKAGE_HEADER_EXECUTABLE_BYTES)?;
    if manifest_offset != u64::try_from(KEX_PACKAGE_V1_HEADER_BYTES).unwrap_or(u64::MAX)
        || manifest_bytes > u64::try_from(requirements::MAX_MANIFEST_BYTES).unwrap_or(u64::MAX)
        || executable_offset != manifest_offset.saturating_add(manifest_bytes)
        || executable_bytes == 0
        || executable_bytes
            > u64::try_from(ApplicationLimits::standard().encoded_bytes()).unwrap_or(u64::MAX)
    {
        return Err(PackageError::InvalidLayout);
    }
    let executable_end = executable_offset
        .checked_add(executable_bytes)
        .ok_or(PackageError::InvalidLayout)?;
    let completion_offset = u64::from(read_package_u32(header, PACKAGE_HEADER_COMPLETION_OFFSET)?);
    if flags == 0 {
        if completion_offset != 0 || executable_end != file_bytes {
            return Err(PackageError::InvalidLayout);
        }
        return Ok(None);
    }
    let completion_bytes = file_bytes
        .checked_sub(completion_offset)
        .and_then(|value| usize::try_from(value).ok())
        .ok_or(PackageError::InvalidLayout)?;
    if flags != PACKAGE_FLAG_COMPLETION
        || completion_offset != executable_end
        || completion_bytes == 0
        || completion_bytes > troe_completion::MAX_ARTIFACT_BYTES
    {
        return Err(PackageError::InvalidLayout);
    }
    Ok(Some((completion_offset, completion_bytes)))
}

pub(crate) fn read_package_u16(bytes: &[u8], offset: usize) -> Result<u16, PackageError> {
    let value = bytes
        .get(offset..offset + 2)
        .ok_or(PackageError::InvalidLayout)?;
    Ok(u16::from_le_bytes([value[0], value[1]]))
}

pub(crate) fn read_package_u32(bytes: &[u8], offset: usize) -> Result<u32, PackageError> {
    let value = bytes
        .get(offset..offset + 4)
        .ok_or(PackageError::InvalidLayout)?;
    Ok(u32::from_le_bytes([value[0], value[1], value[2], value[3]]))
}

pub(crate) fn read_package_u64(bytes: &[u8], offset: usize) -> Result<u64, PackageError> {
    let value = bytes
        .get(offset..offset + 8)
        .ok_or(PackageError::InvalidLayout)?;
    Ok(u64::from_le_bytes([
        value[0], value[1], value[2], value[3], value[4], value[5], value[6], value[7],
    ]))
}
