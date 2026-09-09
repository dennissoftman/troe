//! Geometry, budget, and initialization boundaries independent of a compiler.

use alloc::vec;

use super::*;

const BASE: u64 = 0x10_0000;

fn index(value: u64) -> usize {
    usize::try_from(value).unwrap_or_else(|_| unreachable!())
}

fn plan(target: Target, file: u64, memory: u64, alignment: u64) -> StaticTlsLayout {
    StaticTlsLayout::new(target, file, memory, alignment, u64::MAX)
        .unwrap_or_else(|_| unreachable!())
}

#[test]
fn architecture_offsets_preserve_linker_template_geometry() {
    // Tiny x86 templates need leading padding for the aligned self-pointer,
    // not extra padding between the template and the thread pointer.
    for (memory, alignment, x86_template, x86_pointer, arm_template) in [
        (0, 1, 0, 0, 16),
        (1, 1, 7, 8, 16),
        (3, 2, 4, 8, 16),
        (13, 8, 0, 16, 16),
        (37, 64, 0, 64, 64),
        (65, 64, 0, 128, 64),
        (4097, 8192, 0, 8192, 8192),
    ] {
        let x86 = plan(Target::X86_64, 0, memory, alignment);
        assert_eq!(x86.template_offset(), x86_template);
        assert_eq!(x86.thread_pointer_offset(), x86_pointer);
        let arm = plan(Target::Aarch64, 0, memory, alignment);
        assert_eq!(arm.template_offset(), arm_template);
        assert_eq!(arm.thread_pointer_offset(), 0);
    }
}

#[test]
fn every_padding_and_control_byte_is_charged() {
    for target in [Target::X86_64, Target::Aarch64] {
        let layout = plan(target, 1, PAGE_SIZE, PAGE_SIZE);
        assert_eq!(layout.pages(), 2);
        assert_eq!(layout.mapped_bytes(), 2 * PAGE_SIZE);
        assert_eq!(
            StaticTlsLayout::new(target, 1, PAGE_SIZE, PAGE_SIZE, 1),
            Err(StaticTlsError::PageBudget)
        );
        assert_eq!(
            StaticTlsLayout::new(target, 1, PAGE_SIZE, PAGE_SIZE, 2),
            Ok(layout)
        );
        assert_eq!(
            StaticTlsLayout::new(target, 0, 0, 1, 0),
            Err(StaticTlsError::PageBudget)
        );
        let over_aligned = plan(target, 0, 1, 8192);
        assert_eq!(over_aligned.mapping_alignment(), 8192);
        assert_eq!(over_aligned.pages(), 3);
    }
}

#[test]
fn initialization_copies_prefix_and_erases_all_stale_storage() {
    for target in [Target::X86_64, Target::Aarch64] {
        for alignment in [1, 2, 8, 16, 64, PAGE_SIZE, 8192] {
            for memory in [0, 1, 3, 17, 37, PAGE_SIZE + 1] {
                let file = memory.min(3);
                let layout = plan(target, file, memory, alignment);
                let mut storage = vec![0xa5; index(layout.mapped_bytes())];
                let template = &b"abc"[..index(file)];
                let pointer = layout
                    .initialize(BASE, template, &mut storage)
                    .unwrap_or_else(|_| unreachable!());
                assert_eq!(pointer, BASE + layout.thread_pointer_offset());
                assert!((BASE + layout.template_offset()).is_multiple_of(alignment));
                assert!(pointer.is_multiple_of(alignment.max(8)));
                let mut expected = vec![0; storage.len()];
                let start = index(layout.template_offset());
                expected[start..start + template.len()].copy_from_slice(template);
                if target == Target::X86_64 {
                    let start = index(layout.thread_pointer_offset());
                    expected[start..start + 8].copy_from_slice(&pointer.to_le_bytes());
                }
                assert_eq!(storage, expected);
            }
        }
    }
}

#[test]
fn thread_instances_have_independent_state_and_self_pointers() {
    for target in [Target::X86_64, Target::Aarch64] {
        let layout = plan(target, 3, 7, 1);
        let mut first = vec![0; index(layout.mapped_bytes())];
        let mut second = first.clone();
        assert!(layout.initialize(BASE, b"abc", &mut first).is_ok());
        assert!(
            layout
                .initialize(BASE + PAGE_SIZE, b"abc", &mut second)
                .is_ok()
        );
        first[index(layout.template_offset())] = b'z';
        assert_eq!(second[index(layout.template_offset())], b'a');
        if target == Target::X86_64 {
            assert_ne!(first[8..16], second[8..16]);
        }
        // Reusing storage must also erase the former thread's modifications.
        assert!(layout.initialize(BASE, b"abc", &mut first).is_ok());
        assert_eq!(first[index(layout.template_offset())], b'a');
    }
}

#[test]
fn malformed_descriptors_and_overflow_fail_before_allocation() {
    for target in [Target::X86_64, Target::Aarch64] {
        for alignment in [0, 3, 7, u64::MAX] {
            assert_eq!(
                StaticTlsLayout::new(target, 0, 1, alignment, u64::MAX),
                Err(StaticTlsError::InvalidAlignment)
            );
        }
        assert_eq!(
            StaticTlsLayout::new(target, 2, 1, 1, u64::MAX),
            Err(StaticTlsError::InvalidTemplateSize)
        );
        assert_eq!(
            StaticTlsLayout::new(target, 0, u64::MAX, 16, u64::MAX),
            Err(StaticTlsError::ArithmeticOverflow)
        );
        assert_eq!(
            StaticTlsLayout::new(target, 0, 0, 1 << 63, u64::MAX),
            Err(StaticTlsError::OffsetLimit)
        );
    }
}

#[test]
fn displacement_ceiling_includes_architecture_padding() {
    assert!(StaticTlsLayout::new(Target::X86_64, 0, LOCAL_EXEC_BYTES, 1, 4097).is_ok());
    assert_eq!(
        StaticTlsLayout::new(Target::X86_64, 0, LOCAL_EXEC_BYTES + 1, 1, u64::MAX),
        Err(StaticTlsError::OffsetLimit)
    );
    assert!(StaticTlsLayout::new(Target::Aarch64, 0, LOCAL_EXEC_BYTES - 16, 1, 4096).is_ok());
    assert_eq!(
        StaticTlsLayout::new(Target::Aarch64, 0, LOCAL_EXEC_BYTES - 15, 1, u64::MAX),
        Err(StaticTlsError::OffsetLimit)
    );
    assert_eq!(
        StaticTlsLayout::new(Target::Aarch64, 0, LOCAL_EXEC_BYTES - 16, 64, u64::MAX),
        Err(StaticTlsError::OffsetLimit)
    );
}

#[test]
fn rejected_initialization_never_modifies_destination() {
    for target in [Target::X86_64, Target::Aarch64] {
        let layout = plan(target, 3, 9, 8192);
        let original = vec![0xa5; index(layout.mapped_bytes())];
        for base in [0, 1, BASE + 1, BASE + PAGE_SIZE, KEX_V1_USER_END, u64::MAX] {
            let mut storage = original.clone();
            assert_eq!(
                layout.initialize(base, b"abc", &mut storage),
                Err(StaticTlsError::InvalidMapping)
            );
            assert_eq!(storage, original);
        }
        for template in [b"".as_slice(), b"ab", b"abcd"] {
            let mut storage = original.clone();
            assert_eq!(
                layout.initialize(BASE, template, &mut storage),
                Err(StaticTlsError::InvalidBufferSize)
            );
            assert_eq!(storage, original);
        }
        for bytes in [0, original.len() - 1, original.len() + 1] {
            let mut storage = vec![0xa5; bytes];
            assert_eq!(
                layout.initialize(BASE, b"abc", &mut storage),
                Err(StaticTlsError::InvalidBufferSize)
            );
            assert!(storage.iter().all(|byte| *byte == 0xa5));
        }
    }
}

#[test]
fn complete_mapping_must_fit_below_user_end() {
    for target in [Target::X86_64, Target::Aarch64] {
        let layout = plan(target, 0, PAGE_SIZE, 1);
        let mut storage = vec![0xa5; index(layout.mapped_bytes())];
        assert_eq!(layout.pages(), 2);
        assert_eq!(
            layout.initialize(KEX_V1_USER_END - PAGE_SIZE, &[], &mut storage),
            Err(StaticTlsError::InvalidMapping)
        );
        assert!(storage.iter().all(|byte| *byte == 0xa5));
        assert!(
            layout
                .initialize(KEX_V1_USER_END - layout.mapped_bytes(), &[], &mut storage)
                .is_ok()
        );
    }
}
