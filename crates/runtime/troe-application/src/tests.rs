//! Fixture-driven corpus over encoded KEX packages and executables.

extern crate std;

use std::vec;
use std::vec::Vec;

use super::*;
use crate::bytes::{read_u16, read_u32, read_u64, write_u64};
use crate::executable::parse_with_limits;
use crate::package::read_package_u32;

#[derive(Clone, Copy)]
struct TestSegment<'bytes> {
    image_offset: u64,
    memory_bytes: u64,
    permissions: u32,
    payload: &'bytes [u8],
}

#[derive(Clone, Copy)]
struct TestRelocation {
    target_offset: u64,
    value_offset: u64,
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

fn usize_u16(value: usize) -> u16 {
    u16::try_from(value).unwrap_or_else(|_| unreachable!())
}

fn usize_u32(value: usize) -> u32 {
    u32::try_from(value).unwrap_or_else(|_| unreachable!())
}

fn usize_u64(value: usize) -> u64 {
    u64::try_from(value).unwrap_or_else(|_| unreachable!())
}

#[allow(clippy::too_many_lines)]
fn artifact_with_relocations(
    target: Target,
    segments: &[TestSegment<'_>],
    relocations: &[TestRelocation],
) -> Vec<u8> {
    let payload_bytes = segments
        .iter()
        .map(|segment| segment.payload.len())
        .sum::<usize>();
    let relocations_offset = KEX_V1_HEADER_BYTES + segments.len() * KEX_V1_LOAD_RECORD_BYTES;
    let payload_offset = relocations_offset + relocations.len() * KEX_V1_RELOCATION_RECORD_BYTES;
    let artifact_bytes = payload_offset + payload_bytes;
    let mut bytes = vec![0_u8; artifact_bytes];
    bytes[..8].copy_from_slice(&KEX_V1_MAGIC);
    put_u16(&mut bytes, HEADER_CONTAINER_MAJOR, CONTAINER_MAJOR);
    put_u16(&mut bytes, HEADER_CONTAINER_MINOR, CONTAINER_MINOR);
    put_u16(&mut bytes, HEADER_TARGET, target as u16);
    put_u16(&mut bytes, HEADER_BYTES, usize_u16(KEX_V1_HEADER_BYTES));
    put_u16(
        &mut bytes,
        HEADER_RECORD_BYTES,
        usize_u16(KEX_V1_LOAD_RECORD_BYTES),
    );
    put_u16(&mut bytes, HEADER_ABI_MAJOR, ABI_MAJOR);
    put_u16(&mut bytes, HEADER_ABI_MINOR, ABI_MINOR);
    let image_end = segments
        .iter()
        .map(|segment| segment.image_offset + segment.memory_bytes)
        .max()
        .unwrap_or(0);
    // Degenerate geometries under test can end at zero; keep the header
    // itself well formed so the property under test is what fails.
    let span_bytes = canonical_image_span_bytes(image_end.max(1)).unwrap_or_else(|| unreachable!());
    put_u32(
        &mut bytes,
        HEADER_IMAGE_SPAN_PAGES,
        u32::try_from(span_bytes / PAGE_SIZE).unwrap_or_else(|_| unreachable!()),
    );
    put_u64(&mut bytes, HEADER_ENTRY_OFFSET, 0);
    put_u16(&mut bytes, HEADER_RECORD_COUNT, usize_u16(segments.len()));
    put_u64(&mut bytes, HEADER_STACK_PAGES, 4);
    put_u64(&mut bytes, HEADER_HEAP_PAGES, 0);
    put_u32(
        &mut bytes,
        HEADER_RECORDS_OFFSET,
        usize_u32(KEX_V1_HEADER_BYTES),
    );
    put_u32(
        &mut bytes,
        HEADER_RELOCATIONS_OFFSET,
        usize_u32(relocations_offset),
    );
    put_u32(
        &mut bytes,
        HEADER_RELOCATION_COUNT,
        usize_u32(relocations.len()),
    );
    put_u16(
        &mut bytes,
        HEADER_RELOCATION_BYTES,
        usize_u16(KEX_V1_RELOCATION_RECORD_BYTES),
    );
    put_u32(&mut bytes, HEADER_PAYLOAD_OFFSET, usize_u32(payload_offset));
    put_u64(&mut bytes, HEADER_ARTIFACT_BYTES, usize_u64(artifact_bytes));

    for (index, relocation) in relocations.iter().enumerate() {
        let start = relocations_offset + index * KEX_V1_RELOCATION_RECORD_BYTES;
        put_u64(
            &mut bytes,
            start + RELOCATION_TARGET_OFFSET,
            relocation.target_offset,
        );
        put_u64(
            &mut bytes,
            start + RELOCATION_VALUE_OFFSET,
            relocation.value_offset,
        );
    }

    let mut file_offset = payload_offset;
    for (index, segment) in segments.iter().enumerate() {
        let start = KEX_V1_HEADER_BYTES + index * KEX_V1_LOAD_RECORD_BYTES;
        put_u64(
            &mut bytes,
            start + RECORD_IMAGE_OFFSET,
            segment.image_offset,
        );
        put_u64(
            &mut bytes,
            start + RECORD_FILE_OFFSET,
            usize_u64(file_offset),
        );
        put_u64(
            &mut bytes,
            start + RECORD_FILE_BYTES,
            usize_u64(segment.payload.len()),
        );
        put_u64(
            &mut bytes,
            start + RECORD_MEMORY_BYTES,
            segment.memory_bytes,
        );
        put_u32(&mut bytes, start + RECORD_PERMISSIONS, segment.permissions);
        let end = file_offset + segment.payload.len();
        bytes[file_offset..end].copy_from_slice(segment.payload);
        file_offset = end;
    }
    bytes
}

fn artifact(target: Target, segments: &[TestSegment<'_>]) -> Vec<u8> {
    artifact_with_relocations(target, segments, &[])
}

fn valid_artifact(target: Target) -> Vec<u8> {
    artifact(
        target,
        &[
            TestSegment {
                image_offset: 0,
                memory_bytes: PAGE_SIZE,
                permissions: SegmentPermissions::ReadExecute as u32,
                payload: &[0x90, 0xc3],
            },
            TestSegment {
                image_offset: PAGE_SIZE,
                memory_bytes: PAGE_SIZE,
                permissions: SegmentPermissions::ReadWrite as u32,
                payload: &[1, 2, 3],
            },
        ],
    )
}

fn parse_standard(bytes: &[u8], target: Target) -> Result<LoadPlan<'_>, ParseError> {
    parse_kex(bytes, target, ABI_MINOR)
}

#[test]
fn package_round_trip_binds_manifest_and_executable() {
    let executable = valid_artifact(Target::X86_64);
    let required = [requirements::Requirement {
        interface: 6,
        major: 1,
        minor: 0,
    }];
    let bytes =
        encode_kex_package(&executable, &required).unwrap_or_else(|_| std::process::abort());
    let package = parse_kex_package(&bytes).unwrap_or_else(|_| std::process::abort());
    assert_eq!(package.executable(), executable);
    assert_eq!(package.requirements().iter().collect::<Vec<_>>(), required);
    assert!(parse_standard(package.executable(), Target::X86_64).is_ok());
    assert_eq!(
        bytes.len(),
        KEX_PACKAGE_V1_HEADER_BYTES
            + requirements::HEADER_BYTES
            + requirements::RECORD_BYTES
            + executable.len()
    );
}

#[test]
fn package_round_trip_binds_and_locates_completion_without_staging_executable() {
    let executable = valid_artifact(Target::X86_64);
    let completion = b"CMPL\t1\techo\n";
    let bytes = encode_kex_package_with_completion(&executable, &[], Some(completion))
        .unwrap_or_else(|_| std::process::abort());
    let package = parse_kex_package(&bytes).unwrap_or_else(|_| std::process::abort());
    assert_eq!(package.completion(), Some(completion.as_slice()));
    let range = kex_package_completion_range(
        &bytes[..KEX_PACKAGE_V1_HEADER_BYTES],
        u64::try_from(bytes.len()).unwrap_or(u64::MAX),
    )
    .unwrap_or_else(|_| std::process::abort())
    .unwrap_or_else(|| std::process::abort());
    assert_eq!(&bytes[usize::try_from(range.0).unwrap_or(0)..], completion);
    assert_eq!(range.1, completion.len());

    let streamed = parse_streamed_kex_package(
        bytes.len() as u64,
        |offset, destination| {
            let start = usize::try_from(offset).map_err(|_| ())?;
            let count = destination.len().min(bytes.len() - start);
            destination[..count].copy_from_slice(&bytes[start..start + count]);
            Ok(count)
        },
        Target::X86_64,
        ABI_MINOR,
        LoadPlacement::STANDARD,
    )
    .unwrap_or_else(|_| std::process::abort());
    assert_eq!(
        streamed.executable().charges().staging_bytes(),
        STREAM_WORKING_SET_BYTES
    );

    let mut malformed = bytes.clone();
    *malformed.last_mut().unwrap_or_else(|| unreachable!()) = b'x';
    assert_eq!(
        parse_streamed_kex_package(
            malformed.len() as u64,
            |offset, destination| {
                let start = usize::try_from(offset).map_err(|_| ())?;
                let count = destination.len().min(malformed.len() - start);
                destination[..count].copy_from_slice(&malformed[start..start + count]);
                Ok(count)
            },
            Target::X86_64,
            ABI_MINOR,
            LoadPlacement::STANDARD,
        ),
        Err(StreamError::Package(PackageError::InvalidCompletion))
    );
}

#[test]
fn streamed_package_plan_replays_payload_and_relocations_boundedly() {
    let executable = artifact_with_relocations(
        Target::X86_64,
        &[
            TestSegment {
                image_offset: 0,
                memory_bytes: PAGE_SIZE,
                permissions: SegmentPermissions::ReadExecute as u32,
                payload: &[0x90, 0xc3],
            },
            TestSegment {
                image_offset: PAGE_SIZE,
                memory_bytes: PAGE_SIZE,
                permissions: SegmentPermissions::ReadWrite as u32,
                payload: &[0; 16],
            },
        ],
        &[TestRelocation {
            target_offset: PAGE_SIZE,
            value_offset: 1,
        }],
    );
    let required = [requirements::Requirement {
        interface: 23,
        major: 1,
        minor: 0,
    }];
    let package =
        encode_kex_package(&executable, &required).unwrap_or_else(|_| std::process::abort());
    let placement = LoadPlacement::new(
        KEX_V1_MIN_IMAGE_BASE + KEX_V1_IMAGE_ALIGNMENT,
        KEX_V1_USER_END - KEX_V1_IMAGE_ALIGNMENT,
    );
    let streamed = parse_streamed_kex_package(
        package.len() as u64,
        |offset, destination| {
            let start = usize::try_from(offset).map_err(|_| ())?;
            let count = destination.len().min(37).min(package.len() - start);
            destination[..count].copy_from_slice(&package[start..start + count]);
            Ok(count)
        },
        Target::X86_64,
        ABI_MINOR,
        placement,
    )
    .unwrap_or_else(|_| std::process::abort());
    assert_eq!(streamed.requirements().iter().collect::<Vec<_>>(), required);
    let conventional = parse_kex_at(&executable, Target::X86_64, ABI_MINOR, placement)
        .unwrap_or_else(|_| std::process::abort());
    assert_eq!(
        streamed.executable().entry_address(),
        conventional.entry_address()
    );
    assert_eq!(
        streamed.executable().charges().private_pages(),
        conventional.charges().private_pages()
    );
    assert_eq!(
        streamed.executable().charges().staging_bytes(),
        STREAM_WORKING_SET_BYTES
    );
    let mut copied = [Vec::new(), Vec::new()];
    stream_verified_segments(
        &streamed,
        |offset, destination| {
            let start = usize::try_from(offset).map_err(|_| ())?;
            let count = destination.len().min(package.len() - start);
            destination[..count].copy_from_slice(&package[start..start + count]);
            Ok(count)
        },
        |segment, offset, bytes| {
            assert_eq!(usize::try_from(offset), Ok(copied[segment].len()));
            copied[segment].extend_from_slice(bytes);
            Ok(())
        },
    )
    .unwrap_or_else(|_| std::process::abort());
    assert_eq!(copied[0], [0x90, 0xc3]);
    assert_eq!(copied[1], [0; 16]);
    let mut relocations = Vec::new();
    visit_verified_relocations(
        &streamed,
        |offset, destination| {
            let start = usize::try_from(offset).map_err(|_| ())?;
            let count = destination.len().min(package.len() - start);
            destination[..count].copy_from_slice(&package[start..start + count]);
            Ok(count)
        },
        |relocation| {
            relocations.push(relocation);
            Ok(())
        },
    )
    .unwrap_or_else(|_| std::process::abort());
    assert_eq!(relocations.len(), 1);
    assert_eq!(relocations[0].target_offset(), PAGE_SIZE);
    assert_eq!(relocations[0].value_offset(), 1);
}

#[test]
fn streamed_package_detects_payload_and_relocation_changes_before_activation() {
    let executable = artifact_with_relocations(
        Target::X86_64,
        &[
            TestSegment {
                image_offset: 0,
                memory_bytes: PAGE_SIZE,
                permissions: SegmentPermissions::ReadExecute as u32,
                payload: &[0x90, 0xc3],
            },
            TestSegment {
                image_offset: PAGE_SIZE,
                memory_bytes: PAGE_SIZE,
                permissions: SegmentPermissions::ReadWrite as u32,
                payload: &[0; 16],
            },
        ],
        &[TestRelocation {
            target_offset: PAGE_SIZE,
            value_offset: 1,
        }],
    );
    let mut package =
        encode_kex_package(&executable, &[]).unwrap_or_else(|_| std::process::abort());
    let placement = LoadPlacement::new(
        KEX_V1_MIN_IMAGE_BASE + KEX_V1_IMAGE_ALIGNMENT,
        KEX_V1_USER_END - KEX_V1_IMAGE_ALIGNMENT,
    );
    let streamed = parse_streamed_kex_package(
        package.len() as u64,
        |offset, destination| {
            let start = usize::try_from(offset).map_err(|_| ())?;
            let count = destination.len().min(package.len() - start);
            destination[..count].copy_from_slice(&package[start..start + count]);
            Ok(count)
        },
        Target::X86_64,
        ABI_MINOR,
        placement,
    )
    .unwrap_or_else(|_| std::process::abort());
    let payload = usize::try_from(streamed.executable_offset)
        .unwrap_or(0)
        .checked_add(
            usize::try_from(
                streamed
                    .executable()
                    .segments()
                    .next()
                    .unwrap_or_else(|| unreachable!())
                    .file_offset(),
            )
            .unwrap_or(0),
        )
        .unwrap_or(0);
    package[payload] ^= 1;
    assert_eq!(
        stream_verified_segments(
            &streamed,
            |offset, destination| {
                let start = usize::try_from(offset).map_err(|_| ())?;
                let count = destination.len().min(package.len() - start);
                destination[..count].copy_from_slice(&package[start..start + count]);
                Ok(count)
            },
            |_segment, _offset, _bytes| Ok(()),
        ),
        Err(StreamError::SourceChanged)
    );
}

#[test]
fn package_parser_rejects_every_noncanonical_boundary() {
    let executable = valid_artifact(Target::Aarch64);
    let canonical = encode_kex_package(&executable, &[]).unwrap_or_else(|_| std::process::abort());
    for end in 0..canonical.len() {
        assert!(parse_kex_package(&canonical[..end]).is_err());
    }

    let mut invalid = canonical.clone();
    invalid[0] ^= 1;
    assert_eq!(parse_kex_package(&invalid), Err(PackageError::InvalidMagic));
    invalid = canonical.clone();
    put_u16(&mut invalid, PACKAGE_HEADER_MAJOR, 2);
    assert_eq!(
        parse_kex_package(&invalid),
        Err(PackageError::UnsupportedVersion)
    );
    invalid = canonical.clone();
    put_u16(&mut invalid, PACKAGE_HEADER_FLAGS, 2);
    assert_eq!(
        parse_kex_package(&invalid),
        Err(PackageError::NonzeroReserved)
    );
    invalid = canonical.clone();
    put_u32(&mut invalid, PACKAGE_HEADER_MANIFEST_OFFSET, 0);
    assert_eq!(
        parse_kex_package(&invalid),
        Err(PackageError::InvalidLayout)
    );
    invalid = canonical.clone();
    invalid[KEX_PACKAGE_V1_HEADER_BYTES] ^= 1;
    assert_eq!(
        parse_kex_package(&invalid),
        Err(PackageError::InvalidManifest)
    );
    invalid = canonical.clone();
    put_u64(
        &mut invalid,
        PACKAGE_HEADER_PACKAGE_BYTES,
        usize_u64(canonical.len() - 1),
    );
    assert_eq!(
        parse_kex_package(&invalid),
        Err(PackageError::LengthMismatch)
    );
    invalid = canonical.clone();
    invalid.push(0);
    assert_eq!(
        parse_kex_package(&invalid),
        Err(PackageError::LengthMismatch)
    );

    let executable_offset = usize::try_from(
        read_package_u32(&canonical, PACKAGE_HEADER_EXECUTABLE_OFFSET)
            .unwrap_or_else(|_| unreachable!()),
    )
    .unwrap_or_else(|_| unreachable!());
    invalid = canonical;
    invalid[executable_offset] ^= 1;
    let package = parse_kex_package(&invalid).unwrap_or_else(|_| unreachable!());
    assert!(parse_standard(package.executable(), Target::Aarch64).is_err());
}

#[test]
fn package_encoder_rejects_invalid_inputs_without_output() {
    assert_eq!(
        encode_kex_package(&[], &[]),
        Err(PackageEncodeError::InvalidExecutable)
    );
    let executable = valid_artifact(Target::X86_64);
    let duplicate = [
        requirements::Requirement {
            interface: 6,
            major: 1,
            minor: 0,
        },
        requirements::Requirement {
            interface: 6,
            major: 1,
            minor: 0,
        },
    ];
    assert_eq!(
        encode_kex_package(&executable, &duplicate),
        Err(PackageEncodeError::InvalidManifest)
    );
}

#[test]
fn valid_plan_is_ordered_bounded_and_exactly_charged() {
    for target in [Target::X86_64, Target::Aarch64] {
        let bytes = valid_artifact(target);
        let plan = parse_standard(&bytes, target).unwrap_or_else(|_| unreachable!());
        let segments = plan.segments().collect::<Vec<_>>();

        assert_eq!(plan.target(), target);
        assert_eq!(plan.abi_minor(), ABI_MINOR);
        assert_eq!(plan.entry_address(), KEX_V1_IMAGE_BASE);
        assert_eq!(segments.len(), 2);
        assert_eq!(segments[0].file_bytes(), [0x90, 0xc3]);
        assert_eq!(segments[0].zero_fill_bytes(), PAGE_SIZE - 2);
        assert_eq!(segments[1].virtual_address(), KEX_V1_IMAGE_BASE + PAGE_SIZE);
        assert!(segments[0].permissions().executable());
        assert!(segments[1].permissions().writable());
        assert_eq!(plan.charges().staging_bytes(), bytes.len());
        assert_eq!(plan.charges().image_pages(), 2);
        assert_eq!(plan.charges().private_pages(), 7);
        assert_eq!(
            plan.charges().reserved_resident_pages(),
            7 + maximum_table_pages(7).unwrap_or_else(|| unreachable!())
        );
        let layout = plan.layout();
        assert_eq!(
            layout.startup_address(),
            KEX_V1_IMAGE_BASE + KEX_V1_IMAGE_ALIGNMENT
        );
        assert_eq!(layout.heap_bytes(), 0);
        assert_eq!(layout.stack_top() - layout.stack_bottom(), 4 * PAGE_SIZE);
        assert_eq!(layout.upper_guard_address(), layout.stack_top());
        assert!(layout.lower_guard_address() < layout.stack_bottom());
    }
}

#[test]
fn relative_relocations_and_randomized_placement_are_exact() {
    let segments = [
        TestSegment {
            image_offset: 0,
            memory_bytes: PAGE_SIZE,
            permissions: SegmentPermissions::ReadExecute as u32,
            payload: &[0x90, 0xc3],
        },
        TestSegment {
            image_offset: PAGE_SIZE,
            memory_bytes: PAGE_SIZE,
            permissions: SegmentPermissions::ReadOnly as u32,
            payload: &[0; 16],
        },
    ];
    let relocation = [TestRelocation {
        target_offset: PAGE_SIZE,
        value_offset: 1,
    }];
    let artifact = artifact_with_relocations(Target::X86_64, &segments, &relocation);
    let placement = LoadPlacement::new(
        KEX_V1_MIN_IMAGE_BASE + 6 * KEX_V1_IMAGE_ALIGNMENT,
        0x0000_7000_1000_0000,
    );
    let plan = parse_kex_at(&artifact, Target::X86_64, ABI_MINOR, placement)
        .unwrap_or_else(|_| unreachable!());
    assert_eq!(plan.image_base(), placement.image_base());
    assert_eq!(plan.entry_address(), placement.image_base());
    assert_eq!(plan.layout().stack_top(), placement.stack_top());
    assert_eq!(
        plan.segments().nth(1).map(LoadSegment::virtual_address),
        Some(placement.image_base() + PAGE_SIZE)
    );
    assert_eq!(
        plan.relocations().collect::<Vec<_>>(),
        [RelativeRelocation {
            target_offset: PAGE_SIZE,
            value_offset: 1,
        }]
    );

    let mut invalid = artifact.clone();
    put_u64(
        &mut invalid,
        KEX_V1_HEADER_BYTES + segments.len() * KEX_V1_LOAD_RECORD_BYTES + RELOCATION_TARGET_OFFSET,
        2 * PAGE_SIZE,
    );
    assert_eq!(
        parse_kex_at(&invalid, Target::X86_64, ABI_MINOR, placement),
        Err(ParseError::InvalidRelocation)
    );
    assert_eq!(
        parse_kex_at(
            &artifact,
            Target::X86_64,
            ABI_MINOR,
            LoadPlacement::new(0, placement.stack_top())
        ),
        Err(ParseError::InvalidPlacement)
    );
}

#[test]
fn startup_page_is_canonical_and_rejections_are_atomic() {
    let bytes = valid_artifact(Target::X86_64);
    let plan = parse_standard(&bytes, Target::X86_64).unwrap_or_else(|_| unreachable!());
    let handles = [
        InitialHandle {
            value: 0x1000_0001,
            rights: 1,
            interface: 7,
            major: 1,
            minor: 0,
        },
        InitialHandle {
            value: 0x1000_0002,
            rights: 3,
            interface: 9,
            major: 2,
            minor: 4,
        },
    ];
    let mut page = [0xa5_u8; PAGE_BYTES];
    plan.encode_startup_page(
        StartupInfo {
            task_id: 42,
            handles: &handles,
        },
        &mut page,
    )
    .unwrap_or_else(|_| unreachable!());

    assert_eq!(read_u32(&page, 0), Ok(112));
    assert_eq!(read_u16(&page, 4), Ok(ABI_MAJOR));
    assert_eq!(read_u16(&page, 6), Ok(ABI_MINOR));
    assert_eq!(read_u32(&page, 8), Ok(4096));
    assert_eq!(read_u16(&page, 12), Ok(0));
    assert_eq!(read_u16(&page, 14), Ok(2));
    assert_eq!(read_u64(&page, 16), Ok(KEX_V1_IMAGE_BASE));
    assert_eq!(read_u64(&page, 24), Ok(plan.layout().heap_address()));
    assert_eq!(read_u64(&page, 40), Ok(plan.layout().stack_bottom()));
    assert_eq!(read_u64(&page, 48), Ok(plan.layout().stack_top()));
    assert_eq!(read_u64(&page, 56), Ok(42));
    assert_eq!(read_u64(&page, 64), Ok(handles[0].value));
    assert_eq!(read_u32(&page, 72), Ok(handles[0].rights));
    assert_eq!(read_u64(&page, 88), Ok(handles[1].value));
    assert!(page[112..].iter().all(|byte| *byte == 0));

    let original = [0x5a_u8; PAGE_BYTES];
    let mut rejected = original;
    assert_eq!(
        plan.encode_startup_page(
            StartupInfo {
                task_id: 0,
                handles: &[],
            },
            &mut rejected,
        ),
        Err(StartupPageError::InvalidTaskId)
    );
    assert_eq!(rejected, original);

    let zero = [InitialHandle {
        value: 0,
        ..handles[0]
    }];
    assert_eq!(
        plan.encode_startup_page(
            StartupInfo {
                task_id: 1,
                handles: &zero,
            },
            &mut rejected,
        ),
        Err(StartupPageError::InvalidHandle)
    );
    assert_eq!(rejected, original);

    let duplicate = [handles[0], handles[0]];
    assert_eq!(
        plan.encode_startup_page(
            StartupInfo {
                task_id: 1,
                handles: &duplicate,
            },
            &mut rejected,
        ),
        Err(StartupPageError::DuplicateHandle)
    );
    assert_eq!(rejected, original);

    let too_many = [handles[0]; 33];
    assert_eq!(
        plan.encode_startup_page(
            StartupInfo {
                task_id: 1,
                handles: &too_many,
            },
            &mut rejected,
        ),
        Err(StartupPageError::TooManyHandles)
    );
    assert_eq!(rejected, original);
}

#[test]
fn legacy_startup_page_retains_abi_and_layout() {
    let current_bytes = valid_artifact(Target::X86_64);
    let current = parse_standard(&current_bytes, Target::X86_64).unwrap_or_else(|_| unreachable!());
    let mut legacy_bytes = current_bytes.clone();
    put_u16(&mut legacy_bytes, HEADER_ABI_MINOR, 0);
    put_u32(&mut legacy_bytes, HEADER_IMAGE_SPAN_PAGES, 0);
    let legacy = parse_standard(&legacy_bytes, Target::X86_64).unwrap_or_else(|_| unreachable!());
    let mut legacy_page = [0_u8; PAGE_BYTES];
    legacy
        .encode_startup_page(
            StartupInfo {
                task_id: 43,
                handles: &[],
            },
            &mut legacy_page,
        )
        .unwrap_or_else(|_| unreachable!());

    assert_eq!(read_u16(&legacy_page, 6), Ok(0));
    assert_ne!(legacy.layout().stack_top(), current.layout().stack_top());
    assert_eq!(
        legacy.layout().lower_guard_address(),
        legacy.layout().heap_address() + ApplicationLimits::standard().heap_pages() * PAGE_SIZE
    );
}

#[test]
fn format_identifier_is_product_name_independent() {
    assert_eq!(KEX_V1_MAGIC, *b"KEX\0FMT\0");
}

#[test]
fn rejects_executable_above_the_encoded_ceiling_without_staging_it() {
    // The ceiling is far larger than any artifact worth materializing, so
    // this drives the streamed path, which decides from declared lengths
    // inside a fixed working set rather than from a staged copy.
    let executable = artifact(
        Target::X86_64,
        &[TestSegment {
            image_offset: 0,
            memory_bytes: PAGE_SIZE,
            permissions: SegmentPermissions::ReadExecute as u32,
            payload: &[0x90, 0xc3],
        }],
    );
    let mut package =
        encode_kex_package(&executable, &[]).unwrap_or_else(|_| std::process::abort());
    let oversize = u64::try_from(ApplicationLimits::STANDARD.encoded_bytes)
        .unwrap_or_else(|_| unreachable!())
        + 1;
    write_u64(&mut package, PACKAGE_HEADER_EXECUTABLE_BYTES, oversize);
    let mut reads = 0;
    assert_eq!(
        parse_streamed_kex_package(
            package.len() as u64,
            |offset, destination| {
                reads += 1;
                let start = usize::try_from(offset).map_err(|_| ())?;
                let count = destination.len().min(package.len() - start);
                destination[..count].copy_from_slice(&package[start..start + count]);
                Ok(count)
            },
            Target::X86_64,
            ABI_MINOR,
            LoadPlacement::STANDARD,
        )
        .err(),
        Some(StreamError::Package(PackageError::InvalidLayout))
    );
    assert!(reads <= 2);
}

#[test]
fn rejects_truncated_magic_version_target_and_abi() {
    assert_eq!(
        parse_standard(&[0_u8; KEX_V1_HEADER_BYTES - 1], Target::X86_64),
        Err(ParseError::TruncatedHeader)
    );
    let valid = valid_artifact(Target::X86_64);
    for (offset, error) in [
        (0, ParseError::InvalidMagic),
        (
            HEADER_CONTAINER_MAJOR,
            ParseError::UnsupportedContainerVersion,
        ),
        (
            HEADER_CONTAINER_MINOR,
            ParseError::UnsupportedContainerVersion,
        ),
        (HEADER_TARGET, ParseError::WrongTarget),
        (HEADER_ABI_MAJOR, ParseError::UnsupportedAbi),
        (HEADER_ABI_MINOR, ParseError::UnsupportedAbi),
    ] {
        let mut bytes = valid.clone();
        bytes[offset] = bytes[offset].wrapping_add(1);
        assert_eq!(parse_standard(&bytes, Target::X86_64), Err(error));
    }
    assert_eq!(
        parse_standard(&valid, Target::Aarch64),
        Err(ParseError::WrongTarget)
    );
}

#[test]
fn rejects_noncanonical_header_and_reserved_fields() {
    let valid = valid_artifact(Target::X86_64);
    for offset in [
        HEADER_BYTES,
        HEADER_RECORD_BYTES,
        HEADER_RECORDS_OFFSET,
        HEADER_PAYLOAD_OFFSET,
    ] {
        let mut bytes = valid.clone();
        bytes[offset] = bytes[offset].wrapping_add(1);
        assert_eq!(
            parse_standard(&bytes, Target::X86_64),
            Err(ParseError::InvalidLayout)
        );
    }
    for offset in [HEADER_FLAGS, HEADER_RESERVED16] {
        let mut bytes = valid.clone();
        bytes[offset] = 1;
        assert_eq!(
            parse_standard(&bytes, Target::X86_64),
            Err(ParseError::NonzeroReserved)
        );
    }
    let mut wrong_length = valid;
    let declared = usize_u64(wrong_length.len()) + 1;
    put_u64(&mut wrong_length, HEADER_ARTIFACT_BYTES, declared);
    assert_eq!(
        parse_standard(&wrong_length, Target::X86_64),
        Err(ParseError::LengthMismatch)
    );
}

#[test]
fn rejects_invalid_record_counts() {
    let mut empty = valid_artifact(Target::X86_64);
    put_u16(&mut empty, HEADER_RECORD_COUNT, 0);
    assert_eq!(
        parse_standard(&empty, Target::X86_64),
        Err(ParseError::InvalidRecordCount)
    );

    let segments = vec![
        TestSegment {
            image_offset: 0,
            memory_bytes: PAGE_SIZE,
            permissions: SegmentPermissions::ReadExecute as u32,
            payload: &[1],
        };
        ApplicationLimits::STANDARD.load_records + 1
    ];
    let too_many = artifact(Target::X86_64, &segments);
    assert_eq!(
        parse_standard(&too_many, Target::X86_64),
        Err(ParseError::InvalidRecordCount)
    );
}

#[test]
fn rejects_invalid_permissions_and_segment_geometry() {
    for permissions in [0, 4, u32::MAX] {
        let bytes = artifact(
            Target::X86_64,
            &[TestSegment {
                image_offset: 0,
                memory_bytes: PAGE_SIZE,
                permissions,
                payload: &[1],
            }],
        );
        assert_eq!(
            parse_standard(&bytes, Target::X86_64),
            Err(ParseError::InvalidPermissions)
        );
    }

    for (image_offset, memory_bytes, payload) in [
        (1, PAGE_SIZE, &[1][..]),
        (0, 0, &[1][..]),
        (0, PAGE_SIZE - 1, &[1][..]),
        (0, PAGE_SIZE, &[0_u8; 4097][..]),
    ] {
        let bytes = artifact(
            Target::X86_64,
            &[TestSegment {
                image_offset,
                memory_bytes,
                permissions: SegmentPermissions::ReadExecute as u32,
                payload,
            }],
        );
        assert_eq!(
            parse_standard(&bytes, Target::X86_64),
            Err(ParseError::InvalidSegmentRange)
        );
    }
}

#[test]
fn rejects_overlap_sparse_span_and_page_budget() {
    let overlap = artifact(
        Target::X86_64,
        &[
            TestSegment {
                image_offset: PAGE_SIZE,
                memory_bytes: PAGE_SIZE,
                permissions: SegmentPermissions::ReadExecute as u32,
                payload: &[1],
            },
            TestSegment {
                image_offset: 0,
                memory_bytes: PAGE_SIZE,
                permissions: SegmentPermissions::ReadOnly as u32,
                payload: &[2],
            },
        ],
    );
    assert_eq!(
        parse_standard(&overlap, Target::X86_64),
        Err(ParseError::OverlappingSegments)
    );

    // A sparse image is admitted, and its declared span covers it exactly.
    let mut sparse = artifact(
        Target::X86_64,
        &[TestSegment {
            image_offset: 64 * KEX_V1_IMAGE_ALIGNMENT,
            memory_bytes: PAGE_SIZE,
            permissions: SegmentPermissions::ReadExecute as u32,
            payload: &[1],
        }],
    );
    put_u64(
        &mut sparse,
        HEADER_ENTRY_OFFSET,
        64 * KEX_V1_IMAGE_ALIGNMENT,
    );
    let sparse_plan = parse_standard(&sparse, Target::X86_64).unwrap_or_else(|_| unreachable!());
    assert_eq!(
        sparse_plan.layout().startup_address(),
        LoadPlacement::STANDARD.image_base + 65 * KEX_V1_IMAGE_ALIGNMENT
    );

    // Shrinking the declared span below the image rejects the segment.
    let mut shrunk = sparse.clone();
    put_u32(
        &mut shrunk,
        HEADER_IMAGE_SPAN_PAGES,
        u32::try_from(64 * KEX_V1_IMAGE_ALIGNMENT / PAGE_SIZE).unwrap_or_else(|_| unreachable!()),
    );
    assert_eq!(
        parse_standard(&shrunk, Target::X86_64),
        Err(ParseError::ImageSpanExceeded)
    );

    // Growing it past the canonical span reserves unmapped address space.
    let mut padded = sparse.clone();
    put_u32(
        &mut padded,
        HEADER_IMAGE_SPAN_PAGES,
        u32::try_from(66 * KEX_V1_IMAGE_ALIGNMENT / PAGE_SIZE).unwrap_or_else(|_| unreachable!()),
    );
    assert_eq!(
        parse_standard(&padded, Target::X86_64),
        Err(ParseError::InvalidImageSpan)
    );

    // A span above the standard policy is refused before any segment work.
    let mut oversize = sparse.clone();
    put_u32(
        &mut oversize,
        HEADER_IMAGE_SPAN_PAGES,
        u32::try_from(MAX_IMAGE_SPAN_PAGES + KEX_V1_IMAGE_ALIGNMENT / PAGE_SIZE)
            .unwrap_or_else(|_| unreachable!()),
    );
    assert_eq!(
        parse_standard(&oversize, Target::X86_64),
        Err(ParseError::InvalidImageSpan)
    );

    let mut overflowing = valid_artifact(Target::X86_64);
    put_u64(
        &mut overflowing,
        KEX_V1_HEADER_BYTES + RECORD_IMAGE_OFFSET,
        u64::MAX - (PAGE_SIZE - 1),
    );
    assert_eq!(
        parse_standard(&overflowing, Target::X86_64),
        Err(ParseError::ArithmeticOverflow)
    );
}

#[test]
fn rejects_noncanonical_payload_and_record_reserved_bytes() {
    let valid = valid_artifact(Target::X86_64);
    let first_record = KEX_V1_HEADER_BYTES;

    let mut gap = valid.clone();
    let offset =
        read_u64(&gap[first_record..], RECORD_FILE_OFFSET).unwrap_or_else(|_| unreachable!());
    put_u64(&mut gap, first_record + RECORD_FILE_OFFSET, offset + 1);
    assert_eq!(
        parse_standard(&gap, Target::X86_64),
        Err(ParseError::NoncanonicalPayload)
    );

    let mut trailing = valid.clone();
    trailing.push(0);
    let length = usize_u64(trailing.len());
    put_u64(&mut trailing, HEADER_ARTIFACT_BYTES, length);
    assert_eq!(
        parse_standard(&trailing, Target::X86_64),
        Err(ParseError::NoncanonicalPayload)
    );

    let mut reserved = valid;
    put_u32(&mut reserved, first_record + RECORD_RESERVED, 1);
    assert_eq!(
        parse_standard(&reserved, Target::X86_64),
        Err(ParseError::NonzeroReserved)
    );
}

#[test]
fn rejects_stack_heap_and_aggregate_resident_budgets() {
    let valid = valid_artifact(Target::X86_64);
    for stack_pages in [0_u64, 3, (1 << 32) + 1] {
        let mut bytes = valid.clone();
        put_u64(&mut bytes, HEADER_STACK_PAGES, stack_pages);
        assert_eq!(
            parse_standard(&bytes, Target::X86_64),
            Err(ParseError::StackBudgetExceeded)
        );
    }
    let mut heap = valid.clone();
    put_u64(&mut heap, HEADER_HEAP_PAGES, (1 << 32) + 1);
    assert_eq!(
        parse_standard(&heap, Target::X86_64),
        Err(ParseError::HeapBudgetExceeded)
    );

    let limits = ApplicationLimits {
        resident_pages: 16,
        ..ApplicationLimits::STANDARD
    };
    assert_eq!(
        parse_with_limits(
            &valid,
            Target::X86_64,
            ABI_MINOR,
            limits,
            LoadPlacement::STANDARD,
        ),
        Err(ParseError::ResidentBudgetExceeded)
    );
}

#[test]
fn rejects_missing_executable_and_nonexecuting_entry() {
    let missing = artifact(
        Target::X86_64,
        &[TestSegment {
            image_offset: 0,
            memory_bytes: PAGE_SIZE,
            permissions: SegmentPermissions::ReadOnly as u32,
            payload: &[1],
        }],
    );
    assert_eq!(
        parse_standard(&missing, Target::X86_64),
        Err(ParseError::MissingExecutableSegment)
    );

    let mut bad_entry = valid_artifact(Target::X86_64);
    put_u64(&mut bad_entry, HEADER_ENTRY_OFFSET, PAGE_SIZE);
    assert_eq!(
        parse_standard(&bad_entry, Target::X86_64),
        Err(ParseError::InvalidEntryPoint)
    );
    put_u64(&mut bad_entry, HEADER_ENTRY_OFFSET, u64::MAX);
    assert_eq!(
        parse_standard(&bad_entry, Target::X86_64),
        Err(ParseError::ArithmeticOverflow)
    );
}

#[test]
fn generated_shared_corpus_covers_both_targets_and_exact_boundaries() {
    let valid = include!("../../../../tests/kex-corpus/valid.inc");
    for (name, bytes, target) in valid {
        let parsed = parse_kex(bytes, target, ABI_MINOR);
        assert!(parsed.is_ok(), "{name}: {:?}", parsed.as_ref().err());
        let plan = parsed.unwrap_or_else(|_| unreachable!());
        let limits = ApplicationLimits::standard();
        let segments = plan.segments().collect::<Vec<_>>();
        let image_pages = segments
            .iter()
            .map(|segment| segment.memory_bytes() / PAGE_SIZE)
            .sum::<u64>();
        assert_eq!(plan.charges().staging_bytes(), bytes.len(), "{name}");
        assert_eq!(plan.charges().image_pages(), image_pages, "{name}");
        assert_eq!(
            plan.charges().private_pages(),
            image_pages + 1 + plan.stack_pages() + plan.heap_pages(),
            "{name}"
        );
        assert_eq!(
            plan.charges().reserved_resident_pages(),
            plan.charges().private_pages()
                + maximum_table_pages(plan.charges().private_pages())
                    .unwrap_or_else(|| unreachable!()),
            "{name}"
        );
        for pair in segments.windows(2) {
            assert!(
                pair[0].virtual_address() + pair[0].memory_bytes() <= pair[1].virtual_address(),
                "{name}"
            );
        }
        assert!(segments.iter().all(|segment| {
            !(segment.permissions().writable() && segment.permissions().executable())
        }));
        if name.contains("max-records") {
            assert_eq!(segments.len(), limits.load_records(), "{name}");
        }
        if name.contains("max-span") {
            let last = segments.last().unwrap_or_else(|| unreachable!());
            assert_eq!(
                last.image_offset() + last.memory_bytes(),
                limits.maximum_image_span_bytes(),
                "{name}"
            );
        }
        if name.contains("minimum-span") {
            let last = segments.last().unwrap_or_else(|| unreachable!());
            assert!(
                last.image_offset() + last.memory_bytes() <= KEX_V1_IMAGE_ALIGNMENT,
                "{name}"
            );
        }
        if name.contains("max-stack-heap") {
            assert_eq!(plan.stack_pages(), limits.stack_pages().1, "{name}");
            assert_eq!(plan.heap_pages(), limits.heap_pages(), "{name}");
        }
    }

    let x86_rejections = include!("../../../../tests/kex-corpus/rejections-x86_64.inc");
    for (name, bytes, expected) in x86_rejections {
        assert_eq!(
            parse_kex(bytes, Target::X86_64, ABI_MINOR),
            Err(expected),
            "{name}"
        );
    }
    let arm_rejections = include!("../../../../tests/kex-corpus/rejections-aarch64.inc");
    for (name, bytes, expected) in arm_rejections {
        assert_eq!(
            parse_kex(bytes, Target::Aarch64, ABI_MINOR),
            Err(expected),
            "{name}"
        );
    }
}

#[test]
fn deterministic_plan_properties_hold_across_varied_disjoint_segments() {
    let mut state = 0x9e37_79b9_7f4a_7c15_u64;
    for iteration in 0..256_u64 {
        state = state
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1);
        let count = usize::try_from(state % 16 + 1).unwrap_or_else(|_| unreachable!());
        let mut segments = Vec::new();
        let mut image_offset = 0_u64;
        for index in 0..count {
            state = state
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1);
            let pages = state % 4 + 1;
            let permissions = if index == 0 {
                SegmentPermissions::ReadExecute
            } else {
                match state % 3 {
                    0 => SegmentPermissions::ReadOnly,
                    1 => SegmentPermissions::ReadExecute,
                    _ => SegmentPermissions::ReadWrite,
                }
            };
            let payload = match index % 3 {
                0 => &[0x90, 0xc3][..],
                1 => &[1, 2, 3][..],
                _ => &[][..],
            };
            segments.push(TestSegment {
                image_offset,
                memory_bytes: pages * PAGE_SIZE,
                permissions: permissions as u32,
                payload,
            });
            image_offset += (pages + state % 3) * PAGE_SIZE;
        }
        let target = if iteration % 2 == 0 {
            Target::X86_64
        } else {
            Target::Aarch64
        };
        let mut bytes = artifact(target, &segments);
        let stack_pages = u32::try_from(4 + state % 253).unwrap_or_else(|_| unreachable!());
        let heap_pages = u32::try_from(state % 4097).unwrap_or_else(|_| unreachable!());
        put_u64(&mut bytes, HEADER_STACK_PAGES, u64::from(stack_pages));
        put_u64(&mut bytes, HEADER_HEAP_PAGES, u64::from(heap_pages));
        let plan = parse_standard(&bytes, target).unwrap_or_else(|_| unreachable!());
        let parsed = plan.segments().collect::<Vec<_>>();
        assert_eq!(parsed.len(), count);
        let mut exact_image_pages = 0_u64;
        let mut previous_end = 0_u64;
        for segment in parsed {
            assert!(segment.image_offset() >= previous_end);
            assert!(!(segment.permissions().writable() && segment.permissions().executable()));
            previous_end = segment.image_offset() + segment.memory_bytes();
            exact_image_pages += segment.memory_bytes() / PAGE_SIZE;
        }
        assert_eq!(plan.charges().staging_bytes(), bytes.len());
        assert_eq!(plan.charges().image_pages(), exact_image_pages);
        assert_eq!(
            plan.charges().private_pages(),
            exact_image_pages + 1 + u64::from(stack_pages) + u64::from(heap_pages)
        );
        assert_eq!(
            plan.charges().reserved_resident_pages(),
            plan.charges().private_pages()
                + maximum_table_pages(plan.charges().private_pages())
                    .unwrap_or_else(|| unreachable!())
        );
    }
}

#[test]
fn every_truncation_fails_without_a_plan() {
    let valid = valid_artifact(Target::X86_64);
    for length in 0..valid.len() {
        assert!(parse_standard(&valid[..length], Target::X86_64).is_err());
    }
}
