//! Streamed package verification and bounded segment replay.

use crate::bytes::{read_u32, read_u64};
use crate::executable::{ParsedHeader, application_layout, parse_header_with_len};
use crate::package::{read_package_u16, read_package_u32, read_package_u64};
use crate::sha256::Sha256;
use crate::startup::encode_startup_page;
use crate::{
    ApplicationLayout, ApplicationLimits, KEX_PACKAGE_V1_HEADER_BYTES, KEX_PACKAGE_V1_MAGIC,
    KEX_V1_DECLARED_SPAN_ABI_MINOR, KEX_V1_LOAD_RECORD_BYTES, KEX_V1_RELOCATION_RECORD_BYTES,
    LoadCharges, LoadPlacement, LoadSegmentLayout, MAX_KEX_PACKAGE_BYTES, MAX_LOAD_RECORDS,
    PACKAGE_FLAG_COMPLETION, PACKAGE_HEADER_BYTES, PACKAGE_HEADER_COMPLETION_OFFSET,
    PACKAGE_HEADER_EXECUTABLE_BYTES, PACKAGE_HEADER_EXECUTABLE_OFFSET, PACKAGE_HEADER_FLAGS,
    PACKAGE_HEADER_MAJOR, PACKAGE_HEADER_MANIFEST_BYTES, PACKAGE_HEADER_MANIFEST_OFFSET,
    PACKAGE_HEADER_MINOR, PACKAGE_HEADER_PACKAGE_BYTES, PACKAGE_MAJOR, PACKAGE_MINOR, PAGE_BYTES,
    PAGE_SIZE, PackageError, ParseError, RECORD_FILE_BYTES, RECORD_FILE_OFFSET,
    RECORD_IMAGE_OFFSET, RECORD_MEMORY_BYTES, RECORD_PERMISSIONS, RECORD_RESERVED,
    RELOCATION_TARGET_OFFSET, RELOCATION_VALUE_OFFSET, RelativeRelocation, STARTUP_PAGES,
    STREAM_PREFIX_BYTES, STREAM_WORKING_SET_BYTES, SegmentPermissions, StartupInfo,
    StartupPageError, Target, canonical_image_span_bytes, maximum_table_pages,
};
use alloc::vec::Vec;
use troe_abi::requirements;

/// Failure while validating or replaying a bounded streamed package.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StreamError {
    /// Source length is empty, unrepresentable, or above the package ceiling.
    InvalidLength,
    /// The source reported an I/O or integrity failure.
    SourceFailed,
    /// The source ended early, made no progress, or over-reported a read.
    IncompleteRead,
    /// Bounded verifier scratch storage could not be allocated.
    AllocationFailed,
    /// The package envelope or capability manifest was rejected.
    Package(PackageError),
    /// The embedded executable was rejected.
    Executable(ParseError),
    /// A replay pass did not match the bytes used to construct the plan.
    SourceChanged,
    /// The inactive-frame or relocation consumer rejected a verified chunk.
    SinkFailed,
}

/// Owned, pointer-free KEX plan produced from a bounded streaming source.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StreamedLoadPlan {
    target: Target,
    abi_minor: u16,
    image_base: u64,
    entry_offset: u64,
    stack_pages: u64,
    heap_pages: u64,
    segments: [Option<LoadSegmentLayout>; MAX_LOAD_RECORDS],
    segment_count: usize,
    relocations_offset: u64,
    relocation_count: usize,
    charges: LoadCharges,
    layout: ApplicationLayout,
}

impl StreamedLoadPlan {
    /// Artifact target.
    #[must_use]
    pub const fn target(&self) -> Target {
        self.target
    }

    /// Minimum ABI minor required by the artifact.
    #[must_use]
    pub const fn abi_minor(&self) -> u16 {
        self.abi_minor
    }

    /// Kernel-selected image base.
    #[must_use]
    pub const fn image_base(&self) -> u64 {
        self.image_base
    }

    /// Absolute application entry address.
    #[must_use]
    pub const fn entry_address(&self) -> u64 {
        self.image_base + self.entry_offset
    }

    /// Requested initial stack pages.
    #[must_use]
    pub const fn stack_pages(&self) -> u64 {
        self.stack_pages
    }

    /// Requested initial zeroed heap pages.
    #[must_use]
    pub const fn heap_pages(&self) -> u64 {
        self.heap_pages
    }

    /// Ordered validated load-segment geometry.
    pub fn segments(&self) -> impl Iterator<Item = LoadSegmentLayout> + '_ {
        self.segments[..self.segment_count]
            .iter()
            .flatten()
            .copied()
    }

    /// Preliminary bounded-staging and page charges.
    #[must_use]
    pub const fn charges(&self) -> LoadCharges {
        self.charges
    }

    /// Canonical startup, heap, guard, and stack virtual placement.
    #[must_use]
    pub const fn layout(&self) -> ApplicationLayout {
        self.layout
    }

    /// Encode the immutable ABI startup page.
    ///
    /// # Errors
    ///
    /// Rejects invalid task or handle metadata before modifying the page.
    pub fn encode_startup_page(
        &self,
        info: StartupInfo<'_>,
        destination: &mut [u8; PAGE_BYTES],
    ) -> Result<(), StartupPageError> {
        encode_startup_page(
            self.abi_minor,
            self.image_base,
            self.layout,
            info,
            destination,
        )
    }
}

/// Complete validated package identity and its streamed executable plan.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StreamedKexPackage {
    package_bytes: usize,
    pub(crate) executable_offset: u64,
    manifest: [u8; requirements::MAX_MANIFEST_BYTES],
    manifest_bytes: usize,
    executable: StreamedLoadPlan,
    digest: [u8; 32],
    relocation_digest: [u8; 32],
}

impl StreamedKexPackage {
    /// Validated optional startup interfaces required by this package.
    #[must_use]
    pub fn requirements(&self) -> requirements::Manifest<'_> {
        requirements::Manifest::parse(&self.manifest[..self.manifest_bytes])
            .unwrap_or_else(|_| unreachable!())
    }

    /// Owned pointer-free executable plan.
    #[must_use]
    pub const fn executable(&self) -> &StreamedLoadPlan {
        &self.executable
    }

    /// Exact package length replayed by the coherent verifier.
    #[must_use]
    pub const fn package_bytes(&self) -> usize {
        self.package_bytes
    }
}

/// Parse and fully validate one package through bounded random-access reads.
///
/// The first pass retains a fixed one-page prefix and fingerprints every
/// source byte. Relocations are then reread, validated, and fingerprinted
/// independently. Later materialization APIs require both fingerprints to
/// match before the inactive address space can be activated.
///
/// # Errors
///
/// Rejects source contract violations, every normal package/KEX format error,
/// and any source mutation observed between validation passes.
pub fn parse_streamed_kex_package(
    byte_len: u64,
    mut read_at: impl FnMut(u64, &mut [u8]) -> Result<usize, ()>,
    expected_target: Target,
    supported_abi_minor: u16,
    placement: LoadPlacement,
) -> Result<StreamedKexPackage, StreamError> {
    let package_bytes = usize::try_from(byte_len).map_err(|_| StreamError::InvalidLength)?;
    if package_bytes == 0 || package_bytes > MAX_KEX_PACKAGE_BYTES {
        return Err(StreamError::InvalidLength);
    }
    let prefix_bytes = package_bytes.min(STREAM_PREFIX_BYTES);
    let mut prefix = [0_u8; STREAM_PREFIX_BYTES];
    read_stream_exact(&mut read_at, 0, &mut prefix[..prefix_bytes])?;

    let parsed = parse_stream_prefix(
        &prefix[..prefix_bytes],
        package_bytes,
        expected_target,
        supported_abi_minor,
        placement,
    )?;
    let relocation_start = usize::try_from(parsed.executable_offset)
        .ok()
        .and_then(|offset| {
            usize::try_from(parsed.executable.relocations_offset)
                .ok()
                .and_then(|relocation| offset.checked_add(relocation))
        })
        .ok_or(StreamError::Executable(ParseError::ArithmeticOverflow))?;
    let relocation_bytes = parsed
        .executable
        .relocation_count
        .checked_mul(KEX_V1_RELOCATION_RECORD_BYTES)
        .ok_or(StreamError::Executable(ParseError::ArithmeticOverflow))?;
    let relocation_end = relocation_start
        .checked_add(relocation_bytes)
        .ok_or(StreamError::Executable(ParseError::ArithmeticOverflow))?;

    let mut package_hash = Sha256::new();
    package_hash.update(&prefix[..prefix_bytes]);
    let mut relocation_hash = Sha256::new();
    hash_overlap(
        &mut relocation_hash,
        0,
        &prefix[..prefix_bytes],
        relocation_start,
        relocation_end,
    );
    let mut buffer = [0_u8; PAGE_BYTES];
    let mut offset = prefix_bytes;
    while offset < package_bytes {
        let count = (package_bytes - offset).min(buffer.len());
        read_stream_exact(
            &mut read_at,
            u64::try_from(offset).map_err(|_| StreamError::InvalidLength)?,
            &mut buffer[..count],
        )?;
        package_hash.update(&buffer[..count]);
        hash_overlap(
            &mut relocation_hash,
            offset,
            &buffer[..count],
            relocation_start,
            relocation_end,
        );
        offset = offset
            .checked_add(count)
            .ok_or(StreamError::InvalidLength)?;
    }
    let digest = package_hash.finish();
    let relocation_digest = relocation_hash.finish();
    if let Some((completion_offset, completion_bytes)) = parsed.completion {
        validate_streamed_completion(completion_offset, completion_bytes, &mut read_at)?;
    }
    validate_streamed_relocations(
        &parsed.executable,
        parsed.executable_offset,
        &mut read_at,
        relocation_digest,
    )?;

    Ok(StreamedKexPackage {
        package_bytes,
        executable_offset: parsed.executable_offset,
        manifest: parsed.manifest,
        manifest_bytes: parsed.manifest_bytes,
        executable: parsed.executable,
        digest,
        relocation_digest,
    })
}

fn validate_streamed_completion(
    offset: u64,
    byte_count: usize,
    read_at: &mut impl FnMut(u64, &mut [u8]) -> Result<usize, ()>,
) -> Result<(), StreamError> {
    let mut buffer = Vec::new();
    buffer
        .try_reserve_exact(byte_count)
        .map_err(|_| StreamError::AllocationFailed)?;
    buffer.resize(byte_count, 0);
    read_stream_exact(read_at, offset, &mut buffer)?;
    troe_completion::CompletionArtifact::parse(&buffer)
        .map_err(|_| StreamError::Package(PackageError::InvalidCompletion))?;
    Ok(())
}

/// Replay a validated package and copy only its segment payload bytes.
///
/// `consume` receives a segment index, a byte offset within that segment, and
/// one bounded verified-source chunk. A fingerprint mismatch is reported after
/// the replay; callers must keep destination frames provisional until success.
///
/// # Errors
///
/// Reports source failures, mutation, or a rejected destination chunk.
pub fn stream_verified_segments(
    package: &StreamedKexPackage,
    mut read_at: impl FnMut(u64, &mut [u8]) -> Result<usize, ()>,
    mut consume: impl FnMut(usize, u64, &[u8]) -> Result<(), ()>,
) -> Result<(), StreamError> {
    let mut hash = Sha256::new();
    let mut buffer = [0_u8; PAGE_BYTES];
    let mut offset = 0_usize;
    while offset < package.package_bytes {
        let count = (package.package_bytes - offset).min(buffer.len());
        read_stream_exact(
            &mut read_at,
            u64::try_from(offset).map_err(|_| StreamError::InvalidLength)?,
            &mut buffer[..count],
        )?;
        hash.update(&buffer[..count]);
        let chunk_end = offset
            .checked_add(count)
            .ok_or(StreamError::InvalidLength)?;
        for (index, segment) in package.executable.segments().enumerate() {
            let start = usize::try_from(package.executable_offset)
                .ok()
                .and_then(|base| {
                    usize::try_from(segment.file_offset())
                        .ok()
                        .and_then(|relative| base.checked_add(relative))
                })
                .ok_or(StreamError::InvalidLength)?;
            let end = usize::try_from(segment.file_byte_count())
                .ok()
                .and_then(|bytes| start.checked_add(bytes))
                .ok_or(StreamError::InvalidLength)?;
            let overlap_start = offset.max(start);
            let overlap_end = chunk_end.min(end);
            if overlap_start < overlap_end {
                let source_start = overlap_start - offset;
                let source_end = overlap_end - offset;
                consume(
                    index,
                    u64::try_from(overlap_start - start).map_err(|_| StreamError::InvalidLength)?,
                    &buffer[source_start..source_end],
                )
                .map_err(|()| StreamError::SinkFailed)?;
            }
        }
        offset = chunk_end;
    }
    if hash.finish() != package.digest {
        return Err(StreamError::SourceChanged);
    }
    Ok(())
}

/// Replay and visit every validated relocation using bounded storage.
///
/// The relocation-table fingerprint is checked after visitation. Callers must
/// discard provisional frames on any returned error.
///
/// # Errors
///
/// Reports source failures, mutation, malformed replay bytes, or sink failure.
pub fn visit_verified_relocations(
    package: &StreamedKexPackage,
    mut read_at: impl FnMut(u64, &mut [u8]) -> Result<usize, ()>,
    mut consume: impl FnMut(RelativeRelocation) -> Result<(), ()>,
) -> Result<(), StreamError> {
    let start = package
        .executable_offset
        .checked_add(package.executable.relocations_offset)
        .ok_or(StreamError::InvalidLength)?;
    let byte_count = package
        .executable
        .relocation_count
        .checked_mul(KEX_V1_RELOCATION_RECORD_BYTES)
        .ok_or(StreamError::InvalidLength)?;
    let mut hash = Sha256::new();
    let mut buffer = [0_u8; PAGE_BYTES];
    let mut consumed = 0_usize;
    while consumed < byte_count {
        let count = (byte_count - consumed).min(buffer.len());
        let offset = start
            .checked_add(u64::try_from(consumed).map_err(|_| StreamError::InvalidLength)?)
            .ok_or(StreamError::InvalidLength)?;
        read_stream_exact(&mut read_at, offset, &mut buffer[..count])?;
        hash.update(&buffer[..count]);
        for record in buffer[..count].chunks_exact(KEX_V1_RELOCATION_RECORD_BYTES) {
            let relocation = RelativeRelocation {
                target_offset: read_u64(record, RELOCATION_TARGET_OFFSET)
                    .map_err(StreamError::Executable)?,
                value_offset: read_u64(record, RELOCATION_VALUE_OFFSET)
                    .map_err(StreamError::Executable)?,
            };
            consume(relocation).map_err(|()| StreamError::SinkFailed)?;
        }
        consumed = consumed
            .checked_add(count)
            .ok_or(StreamError::InvalidLength)?;
    }
    if hash.finish() != package.relocation_digest {
        return Err(StreamError::SourceChanged);
    }
    Ok(())
}

struct ParsedStreamPrefix {
    executable_offset: u64,
    completion: Option<(u64, usize)>,
    manifest: [u8; requirements::MAX_MANIFEST_BYTES],
    manifest_bytes: usize,
    executable: StreamedLoadPlan,
}

#[allow(clippy::too_many_lines)]
fn parse_stream_prefix(
    prefix: &[u8],
    package_bytes: usize,
    expected_target: Target,
    supported_abi_minor: u16,
    placement: LoadPlacement,
) -> Result<ParsedStreamPrefix, StreamError> {
    if prefix.len() < KEX_PACKAGE_V1_HEADER_BYTES {
        return Err(StreamError::Package(PackageError::TruncatedHeader));
    }
    if prefix[..8] != KEX_PACKAGE_V1_MAGIC {
        return Err(StreamError::Package(PackageError::InvalidMagic));
    }
    if read_package_u16(prefix, PACKAGE_HEADER_MAJOR).map_err(StreamError::Package)?
        != PACKAGE_MAJOR
        || read_package_u16(prefix, PACKAGE_HEADER_MINOR).map_err(StreamError::Package)?
            != PACKAGE_MINOR
    {
        return Err(StreamError::Package(PackageError::UnsupportedVersion));
    }
    let flags = read_package_u16(prefix, PACKAGE_HEADER_FLAGS).map_err(StreamError::Package)?;
    if flags & !PACKAGE_FLAG_COMPLETION != 0 {
        return Err(StreamError::Package(PackageError::NonzeroReserved));
    }
    let header_bytes =
        usize::from(read_package_u16(prefix, PACKAGE_HEADER_BYTES).map_err(StreamError::Package)?);
    let manifest_offset = usize::try_from(
        read_package_u32(prefix, PACKAGE_HEADER_MANIFEST_OFFSET).map_err(StreamError::Package)?,
    )
    .map_err(|_| StreamError::Package(PackageError::InvalidLayout))?;
    let manifest_bytes = usize::try_from(
        read_package_u32(prefix, PACKAGE_HEADER_MANIFEST_BYTES).map_err(StreamError::Package)?,
    )
    .map_err(|_| StreamError::Package(PackageError::InvalidLayout))?;
    let executable_offset = usize::try_from(
        read_package_u32(prefix, PACKAGE_HEADER_EXECUTABLE_OFFSET).map_err(StreamError::Package)?,
    )
    .map_err(|_| StreamError::Package(PackageError::InvalidLayout))?;
    let completion_offset = usize::try_from(
        read_package_u32(prefix, PACKAGE_HEADER_COMPLETION_OFFSET).map_err(StreamError::Package)?,
    )
    .map_err(|_| StreamError::Package(PackageError::InvalidLayout))?;
    let executable_bytes = usize::try_from(
        read_package_u64(prefix, PACKAGE_HEADER_EXECUTABLE_BYTES).map_err(StreamError::Package)?,
    )
    .map_err(|_| StreamError::Package(PackageError::InvalidLayout))?;
    let declared_package_bytes = usize::try_from(
        read_package_u64(prefix, PACKAGE_HEADER_PACKAGE_BYTES).map_err(StreamError::Package)?,
    )
    .map_err(|_| StreamError::Package(PackageError::LengthMismatch))?;
    if declared_package_bytes != package_bytes {
        return Err(StreamError::Package(PackageError::LengthMismatch));
    }
    let manifest_end = manifest_offset
        .checked_add(manifest_bytes)
        .ok_or(StreamError::Package(PackageError::InvalidLayout))?;
    let executable_end = executable_offset
        .checked_add(executable_bytes)
        .ok_or(StreamError::Package(PackageError::InvalidLayout))?;
    if header_bytes != KEX_PACKAGE_V1_HEADER_BYTES
        || manifest_offset != KEX_PACKAGE_V1_HEADER_BYTES
        || manifest_bytes > requirements::MAX_MANIFEST_BYTES
        || executable_offset != manifest_end
        || executable_bytes == 0
        || executable_bytes > ApplicationLimits::standard().encoded_bytes()
    {
        return Err(StreamError::Package(PackageError::InvalidLayout));
    }
    let completion = if flags == 0 {
        if completion_offset != 0 || executable_end != package_bytes {
            return Err(StreamError::Package(PackageError::InvalidLayout));
        }
        None
    } else {
        let completion_bytes = package_bytes
            .checked_sub(completion_offset)
            .ok_or(StreamError::Package(PackageError::InvalidLayout))?;
        if completion_offset != executable_end
            || completion_bytes == 0
            || completion_bytes > troe_completion::MAX_ARTIFACT_BYTES
        {
            return Err(StreamError::Package(PackageError::InvalidLayout));
        }
        Some((
            u64::try_from(completion_offset)
                .map_err(|_| StreamError::Package(PackageError::InvalidLayout))?,
            completion_bytes,
        ))
    };
    let manifest_source = prefix
        .get(manifest_offset..manifest_end)
        .ok_or(StreamError::Package(PackageError::InvalidLayout))?;
    requirements::Manifest::parse(manifest_source)
        .map_err(|_| StreamError::Package(PackageError::InvalidManifest))?;
    let executable_prefix = prefix
        .get(executable_offset..)
        .ok_or(StreamError::Executable(ParseError::TruncatedHeader))?;
    let header = parse_header_with_len(
        executable_prefix,
        executable_bytes,
        expected_target,
        supported_abi_minor,
        ApplicationLimits::standard(),
    )
    .map_err(StreamError::Executable)?;
    let parsed = parse_stream_segments(
        executable_prefix,
        executable_bytes,
        header,
        placement.image_base,
    )
    .map_err(StreamError::Executable)?;
    let layout = application_layout(
        header.stack_pages,
        header.heap_pages,
        header.abi_minor,
        header.image_span_bytes,
        ApplicationLimits::standard(),
        placement,
    )
    .map_err(StreamError::Executable)?;
    let private_pages = parsed
        .image_pages
        .checked_add(header.stack_pages)
        .and_then(|pages| pages.checked_add(header.heap_pages))
        .and_then(|pages| pages.checked_add(STARTUP_PAGES))
        .ok_or(StreamError::Executable(ParseError::ArithmeticOverflow))?;
    let reserved_resident_pages = maximum_table_pages(private_pages)
        .and_then(|tables| private_pages.checked_add(tables))
        .ok_or(StreamError::Executable(ParseError::ArithmeticOverflow))?;
    if reserved_resident_pages > ApplicationLimits::standard().resident_pages {
        return Err(StreamError::Executable(ParseError::ResidentBudgetExceeded));
    }
    let mut manifest = [0_u8; requirements::MAX_MANIFEST_BYTES];
    manifest[..manifest_bytes].copy_from_slice(manifest_source);
    Ok(ParsedStreamPrefix {
        executable_offset: u64::try_from(executable_offset)
            .map_err(|_| StreamError::Package(PackageError::InvalidLayout))?,
        completion,
        manifest,
        manifest_bytes,
        executable: StreamedLoadPlan {
            target: header.target,
            abi_minor: header.abi_minor,
            image_base: placement.image_base,
            entry_offset: header.entry_offset,
            stack_pages: header.stack_pages,
            heap_pages: header.heap_pages,
            segments: parsed.segments,
            segment_count: header.record_count,
            relocations_offset: u64::try_from(header.relocations_offset)
                .map_err(|_| StreamError::Executable(ParseError::ArithmeticOverflow))?,
            relocation_count: header.relocation_count,
            charges: LoadCharges {
                staging_bytes: STREAM_WORKING_SET_BYTES,
                image_pages: parsed.image_pages,
                stack_pages: header.stack_pages,
                heap_pages: header.heap_pages,
                private_pages,
                reserved_resident_pages,
            },
            layout,
        },
    })
}

struct ParsedStreamSegments {
    segments: [Option<LoadSegmentLayout>; MAX_LOAD_RECORDS],
    image_pages: u64,
}

#[allow(clippy::too_many_lines)]
fn parse_stream_segments(
    prefix: &[u8],
    executable_bytes: usize,
    header: ParsedHeader,
    image_base: u64,
) -> Result<ParsedStreamSegments, ParseError> {
    let mut segments = [None; MAX_LOAD_RECORDS];
    let mut expected_file_offset = header.payload_offset;
    let mut previous_image_end = 0_u64;
    let mut image_pages = 0_u64;
    let mut executable = false;
    let mut entry_is_executable = false;
    for (index, destination) in segments[..header.record_count].iter_mut().enumerate() {
        let record_start = header
            .records_offset
            .checked_add(
                index
                    .checked_mul(KEX_V1_LOAD_RECORD_BYTES)
                    .ok_or(ParseError::ArithmeticOverflow)?,
            )
            .ok_or(ParseError::ArithmeticOverflow)?;
        let record_end = record_start
            .checked_add(KEX_V1_LOAD_RECORD_BYTES)
            .ok_or(ParseError::ArithmeticOverflow)?;
        let record = prefix
            .get(record_start..record_end)
            .ok_or(ParseError::InvalidLayout)?;
        let image_offset = read_u64(record, RECORD_IMAGE_OFFSET)?;
        let file_offset = usize::try_from(read_u64(record, RECORD_FILE_OFFSET)?)
            .map_err(|_| ParseError::ArithmeticOverflow)?;
        let file_byte_count = read_u64(record, RECORD_FILE_BYTES)?;
        let file_bytes =
            usize::try_from(file_byte_count).map_err(|_| ParseError::ArithmeticOverflow)?;
        let memory_bytes = read_u64(record, RECORD_MEMORY_BYTES)?;
        let permissions = SegmentPermissions::from_raw(read_u32(record, RECORD_PERMISSIONS)?)
            .ok_or(ParseError::InvalidPermissions)?;
        if read_u32(record, RECORD_RESERVED)? != 0 {
            return Err(ParseError::NonzeroReserved);
        }
        if memory_bytes == 0
            || !image_offset.is_multiple_of(PAGE_SIZE)
            || !memory_bytes.is_multiple_of(PAGE_SIZE)
            || file_byte_count > memory_bytes
        {
            return Err(ParseError::InvalidSegmentRange);
        }
        let image_end = image_offset
            .checked_add(memory_bytes)
            .ok_or(ParseError::ArithmeticOverflow)?;
        image_base
            .checked_add(image_end)
            .ok_or(ParseError::ArithmeticOverflow)?;
        if index != 0 && image_offset < previous_image_end {
            return Err(ParseError::OverlappingSegments);
        }
        if image_end > header.image_span_bytes {
            return Err(ParseError::ImageSpanExceeded);
        }
        if file_offset != expected_file_offset {
            return Err(ParseError::NoncanonicalPayload);
        }
        let file_end = file_offset
            .checked_add(file_bytes)
            .ok_or(ParseError::ArithmeticOverflow)?;
        if file_end > executable_bytes {
            return Err(ParseError::NoncanonicalPayload);
        }
        image_pages = image_pages
            .checked_add(memory_bytes / PAGE_SIZE)
            .ok_or(ParseError::ArithmeticOverflow)?;
        if permissions.executable() {
            executable = true;
            let entry_end = header
                .entry_offset
                .checked_add(1)
                .ok_or(ParseError::ArithmeticOverflow)?;
            entry_is_executable |= header.entry_offset >= image_offset && entry_end <= image_end;
        }
        *destination = Some(LoadSegmentLayout {
            image_base,
            image_offset,
            memory_bytes,
            file_offset: u64::try_from(file_offset).map_err(|_| ParseError::ArithmeticOverflow)?,
            file_byte_count,
            permissions,
        });
        expected_file_offset = file_end;
        previous_image_end = image_end;
    }
    if expected_file_offset != executable_bytes {
        return Err(ParseError::NoncanonicalPayload);
    }
    if !executable {
        return Err(ParseError::MissingExecutableSegment);
    }
    if !entry_is_executable {
        return Err(ParseError::InvalidEntryPoint);
    }
    // Artifacts that declare their own span must declare the exact one. ABI
    // 1.0 and 1.1 artifacts have a fixed implied span and are held only to the
    // segment bound already checked above.
    if header.abi_minor >= KEX_V1_DECLARED_SPAN_ABI_MINOR
        && canonical_image_span_bytes(previous_image_end) != Some(header.image_span_bytes)
    {
        return Err(ParseError::InvalidImageSpan);
    }
    Ok(ParsedStreamSegments {
        segments,
        image_pages,
    })
}

fn validate_streamed_relocations(
    plan: &StreamedLoadPlan,
    executable_offset: u64,
    read_at: &mut impl FnMut(u64, &mut [u8]) -> Result<usize, ()>,
    expected_digest: [u8; 32],
) -> Result<(), StreamError> {
    let start = executable_offset
        .checked_add(plan.relocations_offset)
        .ok_or(StreamError::InvalidLength)?;
    let byte_count = plan
        .relocation_count
        .checked_mul(KEX_V1_RELOCATION_RECORD_BYTES)
        .ok_or(StreamError::InvalidLength)?;
    let image_end = plan
        .segments()
        .try_fold(0_u64, |end, segment| {
            segment
                .image_offset()
                .checked_add(segment.memory_bytes())
                .map(|segment_end| end.max(segment_end))
        })
        .ok_or(StreamError::Executable(ParseError::ArithmeticOverflow))?;
    let mut previous_target = None;
    let mut hash = Sha256::new();
    let mut buffer = [0_u8; PAGE_BYTES];
    let mut consumed = 0_usize;
    while consumed < byte_count {
        let count = (byte_count - consumed).min(buffer.len());
        let offset = start
            .checked_add(u64::try_from(consumed).map_err(|_| StreamError::InvalidLength)?)
            .ok_or(StreamError::InvalidLength)?;
        read_stream_exact(read_at, offset, &mut buffer[..count])?;
        hash.update(&buffer[..count]);
        for record in buffer[..count].chunks_exact(KEX_V1_RELOCATION_RECORD_BYTES) {
            let target_offset =
                read_u64(record, RELOCATION_TARGET_OFFSET).map_err(StreamError::Executable)?;
            let value_offset =
                read_u64(record, RELOCATION_VALUE_OFFSET).map_err(StreamError::Executable)?;
            let target_end = target_offset
                .checked_add(8)
                .ok_or(StreamError::Executable(ParseError::InvalidRelocation))?;
            if previous_target.is_some_and(|previous| target_offset <= previous)
                || value_offset >= image_end
                || !plan.segments().any(|segment| {
                    let segment_end = segment.image_offset().checked_add(segment.memory_bytes());
                    segment.image_offset() <= target_offset
                        && segment_end.is_some_and(|end| target_end <= end)
                })
            {
                return Err(StreamError::Executable(ParseError::InvalidRelocation));
            }
            previous_target = Some(target_offset);
        }
        consumed = consumed
            .checked_add(count)
            .ok_or(StreamError::InvalidLength)?;
    }
    if hash.finish() != expected_digest {
        return Err(StreamError::SourceChanged);
    }
    Ok(())
}

fn read_stream_exact(
    read_at: &mut impl FnMut(u64, &mut [u8]) -> Result<usize, ()>,
    offset: u64,
    destination: &mut [u8],
) -> Result<(), StreamError> {
    let mut filled = 0_usize;
    while filled < destination.len() {
        let current = offset
            .checked_add(u64::try_from(filled).map_err(|_| StreamError::InvalidLength)?)
            .ok_or(StreamError::InvalidLength)?;
        let available = destination.len() - filled;
        let count =
            read_at(current, &mut destination[filled..]).map_err(|()| StreamError::SourceFailed)?;
        if count == 0 || count > available {
            return Err(StreamError::IncompleteRead);
        }
        filled = filled
            .checked_add(count)
            .ok_or(StreamError::InvalidLength)?;
    }
    Ok(())
}

fn hash_overlap(
    hash: &mut Sha256,
    chunk_start: usize,
    chunk: &[u8],
    range_start: usize,
    range_end: usize,
) {
    let Some(chunk_end) = chunk_start.checked_add(chunk.len()) else {
        return;
    };
    let start = chunk_start.max(range_start);
    let end = chunk_end.min(range_end);
    if start < end {
        hash.update(&chunk[start - chunk_start..end - chunk_start]);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ABI_MINOR, LoadPlacement, MAX_KEX_PACKAGE_BYTES, Target};

    #[test]
    fn streamed_package_rejects_oversize_without_reading() {
        let mut reads = 0;
        assert_eq!(
            parse_streamed_kex_package(
                MAX_KEX_PACKAGE_BYTES as u64 + 1,
                |_offset, _destination| {
                    reads += 1;
                    Ok(0)
                },
                Target::X86_64,
                ABI_MINOR,
                LoadPlacement::STANDARD,
            ),
            Err(StreamError::InvalidLength)
        );
        assert_eq!(reads, 0);
    }
}
