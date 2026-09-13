use super::*;
use crate::bytes::write_u16;
use crate::{ABI_MINOR, KEX_V1_LOAD_RECORD_BYTES, KEX_V1_MAGIC, PAGE_SIZE, parse_kex};
use alloc::{vec, vec::Vec};

fn fixture(target: Target) -> Vec<u8> {
    let payload = HEADER_BYTES + 2 * KEX_V1_LOAD_RECORD_BYTES + KEX_V1_RELOCATION_RECORD_BYTES;
    let metadata = Metadata {
        source_offset: PAGE_SIZE,
        file_offset: (payload + 32) as u64,
        file_bytes: 3,
        memory_bytes: 37,
        alignment: 64,
        trampoline_offset: 4,
    };
    let mut bytes = vec![0; payload + 35];
    bytes[..8].copy_from_slice(&KEX_V1_MAGIC);
    for (offset, value) in [
        (8, 1),
        (10, CONTAINER_MINOR),
        (12, target as u16),
        (14, 160),
        (16, 40),
        (18, 1),
        (20, 4),
        (22, FLAG),
        (32, 2),
        (72, 16),
    ] {
        write_u16(&mut bytes, offset, value);
    }
    for (offset, value) in [
        (36, 512),
        (56, 160),
        (
            60,
            u32::try_from(payload).unwrap_or_else(|_| unreachable!()),
        ),
        (64, 240),
        (68, 1),
    ] {
        write_u32(&mut bytes, offset, value);
    }
    write_u64(&mut bytes, 40, 4);
    write_u64(&mut bytes, 80, (payload + 35) as u64);
    bytes[96..HEADER_BYTES]
        .copy_from_slice(&metadata.encode(target).unwrap_or_else(|_| unreachable!()));
    for (index, permissions) in [2, 3].into_iter().enumerate() {
        let at = HEADER_BYTES + index * KEX_V1_LOAD_RECORD_BYTES;
        write_u64(&mut bytes, at, index as u64 * PAGE_SIZE);
        write_u64(&mut bytes, at + 8, (payload + index * 16) as u64);
        write_u64(&mut bytes, at + 16, 16);
        write_u64(&mut bytes, at + 24, PAGE_SIZE);
        write_u32(&mut bytes, at + 32, permissions);
    }
    write_u64(&mut bytes, 240, PAGE_SIZE + 8);
    bytes[payload..payload + 16].fill(0x90);
    bytes[payload + 16..payload + 19].copy_from_slice(&[1, 2, 3]);
    bytes[payload + 32..].copy_from_slice(&[1, 2, 3]);
    bytes
}

#[test]
fn canonical_tls_artifact_has_an_independent_initializer_on_both_targets() {
    for target in [Target::X86_64, Target::Aarch64] {
        let bytes = fixture(target);
        let artifact = Artifact::parse(&bytes, target).unwrap_or_else(|_| unreachable!());
        assert_eq!(artifact.target(), target);
        assert_eq!(artifact.entry_offset(), 0);
        assert_eq!(artifact.image_span_bytes(), 2 * 1024 * 1024);
        assert_eq!(artifact.stack_pages(), 4);
        assert_eq!(artifact.heap_pages(), 0);
        assert_eq!(artifact.template(), &[1, 2, 3]);
        assert_eq!(artifact.segments().count(), 2);
        assert_eq!(artifact.relocations().count(), 1);
        let layout = artifact
            .metadata()
            .layout(target, 1)
            .unwrap_or_else(|_| unreachable!());
        let mut destination = vec![0xa5; 4096];
        assert!(
            layout
                .initialize(0x10000, artifact.template(), &mut destination)
                .is_ok()
        );
        let start = usize::try_from(layout.template_offset()).unwrap_or_else(|_| unreachable!());
        assert_eq!(&destination[start..start + 3], &[1, 2, 3]);
        assert!(
            destination[start + 3..start + 37]
                .iter()
                .all(|byte| *byte == 0)
        );
        assert!(artifact.metadata().layout(target, 0).is_err());
    }
}

#[test]
fn native_parser_rejects_new_container_even_with_a_higher_caller_abi_ceiling() {
    for target in [Target::X86_64, Target::Aarch64] {
        let bytes = fixture(target);
        for minor in [ABI_MINOR, 4, u16::MAX] {
            assert_eq!(
                parse_kex(&bytes, target, minor).err(),
                Some(ParseError::UnsupportedContainerVersion)
            );
            let package = crate::encode_kex_package(&bytes, &[]).unwrap_or_else(|_| unreachable!());
            let parsed = crate::parse_kex_package(&package).unwrap_or_else(|_| unreachable!());
            assert!(Artifact::parse(parsed.executable(), target).is_ok());
            let streamed = crate::parse_streamed_kex_package(
                package.len() as u64,
                |offset, destination| {
                    let start = usize::try_from(offset).map_err(|_| ())?;
                    let remaining = package.get(start..).ok_or(())?;
                    let count = destination.len().min(remaining.len()).min(37);
                    destination[..count].copy_from_slice(&remaining[..count]);
                    Ok(count)
                },
                target,
                minor,
                crate::LoadPlacement::STANDARD,
            );
            assert!(matches!(
                streamed,
                Err(crate::StreamError::Executable(
                    ParseError::UnsupportedContainerVersion
                ))
            ));
        }
    }
}

#[test]
fn malformed_versions_reserved_fields_and_all_truncations_fail_closed() {
    let bytes = fixture(Target::X86_64);
    for length in 0..bytes.len() {
        assert!(Artifact::parse(&bytes[..length], Target::X86_64).is_err());
    }
    for offset in [
        0, 8, 10, 14, 16, 18, 20, 22, 34, 56, 60, 64, 72, 74, 76, 88, 144, 148, 152, 159,
    ] {
        let mut bad = bytes.clone();
        bad[offset] ^= 0x80;
        assert!(
            Artifact::parse(&bad, Target::X86_64).is_err(),
            "offset {offset}"
        );
    }
    let mut trailing = bytes.clone();
    trailing.push(0);
    assert!(Artifact::parse(&trailing, Target::X86_64).is_err());
    assert!(Artifact::parse(&bytes, Target::Aarch64).is_err());
}

#[test]
fn source_and_suffix_cannot_alias_code_tables_gaps_or_disagree() {
    let bytes = fixture(Target::X86_64);
    for source in [0, PAGE_SIZE - 1, PAGE_SIZE + 14, 2 * PAGE_SIZE, u64::MAX] {
        let mut bad = bytes.clone();
        write_u64(&mut bad, 96, source);
        assert!(Artifact::parse(&bad, Target::X86_64).is_err());
    }
    for offset in [0, 96, 160, 240, 256, 257, bytes.len() as u64, u64::MAX] {
        let mut bad = bytes.clone();
        write_u64(&mut bad, 104, offset);
        assert!(Artifact::parse(&bad, Target::X86_64).is_err());
    }
    let mut bad = bytes.clone();
    let last = bad.len() - 1;
    bad[last] ^= 1;
    assert_eq!(
        Artifact::parse(&bad, Target::X86_64).err(),
        Some(Error::InconsistentTemplate)
    );
    for offset in [112, 120, 128] {
        let mut bad = bytes.clone();
        write_u64(&mut bad, offset, u64::MAX);
        assert!(Artifact::parse(&bad, Target::X86_64).is_err());
    }
}

#[test]
fn relocations_into_any_initialized_tls_byte_are_rejected() {
    let source = PAGE_SIZE + 8;
    for offset in source - 7..source + 3 {
        let mut bytes = fixture(Target::X86_64);
        write_u64(&mut bytes, 96, source);
        bytes[280..283].copy_from_slice(&[1, 2, 3]);
        write_u64(&mut bytes, 240, offset);
        assert_eq!(
            Artifact::parse(&bytes, Target::X86_64).err(),
            Some(Error::RelocatedTemplate)
        );
    }
    // Touching the first byte after the initializer is not an overlap.
    let mut bytes = fixture(Target::X86_64);
    write_u64(&mut bytes, 240, PAGE_SIZE + 3);
    assert!(Artifact::parse(&bytes, Target::X86_64).is_ok());
    let mut bytes = fixture(Target::X86_64);
    write_u64(&mut bytes, 96, source);
    bytes[280..283].copy_from_slice(&[1, 2, 3]);
    write_u64(&mut bytes, 240, source - 8);
    assert!(Artifact::parse(&bytes, Target::X86_64).is_ok());
}

#[test]
fn main_and_worker_entries_must_be_backed_code_with_arm_instruction_alignment() {
    for target in [Target::X86_64, Target::Aarch64] {
        for field in [24, 136] {
            for entry in [16, PAGE_SIZE, u64::MAX] {
                let mut bytes = fixture(target);
                write_u64(&mut bytes, field, entry);
                assert!(Artifact::parse(&bytes, target).is_err());
            }
            let mut bytes = fixture(target);
            write_u64(&mut bytes, field, 1);
            assert_eq!(
                Artifact::parse(&bytes, target).is_ok(),
                target == Target::X86_64
            );
        }
    }
}

#[test]
fn empty_and_bss_only_templates_are_explicit_without_fake_image_source() {
    for target in [Target::X86_64, Target::Aarch64] {
        for memory_bytes in [0, 37] {
            let mut bytes = fixture(target);
            bytes.truncate(bytes.len() - 3);
            let length = bytes.len() as u64;
            write_u64(&mut bytes, 80, length);
            write_u64(&mut bytes, 96, 0);
            write_u64(&mut bytes, 112, 0);
            write_u64(&mut bytes, 120, memory_bytes);
            let artifact = Artifact::parse(&bytes, target).unwrap_or_else(|_| unreachable!());
            assert!(artifact.template().is_empty());
            assert_eq!(
                artifact
                    .metadata()
                    .layout(target, 1)
                    .map(StaticTlsLayout::pages),
                Ok(1)
            );
            write_u64(&mut bytes, 96, PAGE_SIZE);
            assert!(Artifact::parse(&bytes, target).is_err());
        }
    }
}
