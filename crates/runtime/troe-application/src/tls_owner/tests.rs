use super::*;
use crate::{KEX_V1_MIN_IMAGE_BASE, KEX_V1_USER_END, PAGE_BYTES, test_support::TlsFixture};
use alloc::vec;

const UNLIMITED: ProcessMemoryBudget = ProcessMemoryBudget {
    mapped_pages: u64::MAX,
    resident_pages: u64::MAX,
    reserved_pages: u64::MAX,
    ordinary_frames: u64::MAX,
    ipc_pairs: u64::MAX,
    tls_pages: u64::MAX,
    template_pages: u64::MAX,
    staging_bytes: u64::MAX,
};
const PLACEMENT: ProcessMemoryPlacement = ProcessMemoryPlacement {
    image_base: KEX_V1_MIN_IMAGE_BASE,
    heap_capacity_pages: 16,
    initial_thread_base: KEX_V1_MIN_IMAGE_BASE + (1 << 24),
};
fn prepared(account: &TlsBackingAccount, target: Target) -> StagedTlsImage<'_> {
    StagedTlsImage::prepare(
        TlsFixture::default().encode(target),
        target,
        PLACEMENT,
        UNLIMITED,
        account,
    )
    .unwrap_or_else(|error| unreachable!("{error:?}"))
}
fn exact(plan: &ProcessMemoryPlan) -> ProcessMemoryBudget {
    let c = plan.charges();
    ProcessMemoryBudget {
        mapped_pages: c.mapped_pages(),
        resident_pages: c.peak_resident_pages(),
        reserved_pages: c.reserved_pages(),
        ordinary_frames: c.peak_ordinary_frames(),
        ipc_pairs: c.ipc_pairs(),
        tls_pages: c.tls_pages(),
        template_pages: c.template_pages(),
        staging_bytes: c.staging_bytes(),
    }
}

#[test]
fn initialized_tls_remains_independent_of_staging_running_image_and_other_threads() {
    for target in [Target::X86_64, Target::Aarch64] {
        for (file, memory, alignment) in
            [(0, 0, 1), (0, 5001, 8192), (3, 37, 64), (4097, 9001, 65536)]
        {
            let account = TlsBackingAccount::new(32);
            let fixture = TlsFixture {
                file,
                memory,
                alignment,
                ..TlsFixture::default()
            };
            let staged = StagedTlsImage::prepare(
                fixture.encode(target),
                target,
                PLACEMENT,
                UNLIMITED,
                &account,
            )
            .unwrap_or_else(|error| unreachable!("{error:?}"));
            let artifact = staged.artifact().unwrap_or_else(|_| unreachable!());
            assert_eq!(artifact.template(), vec![0x5a; file]);
            let mut image = artifact
                .segments()
                .map(|segment| segment.file_bytes().to_vec())
                .collect::<Vec<_>>();
            let process = staged.release_staging();
            assert_eq!(account.usage().staging_pages(), 0);
            assert_eq!(
                account.usage().initializer_pages(),
                (file as u64).div_ceil(PAGE_SIZE)
            );
            assert_eq!(account.usage().pages(), process.backing_pages());
            for segment in &mut image {
                segment.fill(0xe7);
            }
            let tls = process.plan().tls_layout();
            let mut first =
                vec![0xa5; usize::try_from(tls.mapped_bytes()).unwrap_or_else(|_| unreachable!())];
            let mut second = first.clone();
            let base = process.plan().initial_thread().regions()[1].start();
            assert_eq!(
                process.initialize(base, &mut first),
                Ok(process.plan().initial_thread().thread_pointer())
            );
            first.fill(0xc3);
            let next_base = base + tls.mapping_alignment() * 4;
            assert_eq!(
                process.initialize(next_base, &mut second),
                Ok(next_base + tls.thread_pointer_offset())
            );
            let start = usize::try_from(tls.template_offset()).unwrap_or_else(|_| unreachable!());
            assert!(second[start..start + file].iter().all(|byte| *byte == 0x5a));
            assert!(
                second[start + file
                    ..start + usize::try_from(memory).unwrap_or_else(|_| unreachable!())]
                    .iter()
                    .all(|byte| *byte == 0)
            );
            let pointer =
                usize::try_from(tls.thread_pointer_offset()).unwrap_or_else(|_| unreachable!());
            for (index, byte) in second.iter().copied().enumerate() {
                if (start..start + file).contains(&index)
                    || (target == Target::X86_64 && (pointer..pointer + 8).contains(&index))
                {
                    continue;
                }
                assert_eq!(byte, 0, "uncleared TLS slack at {index}");
            }
            drop(process);
            assert_eq!(account.usage(), TlsBackingUsage::default());
        }
    }
}

#[test]
fn stop_revokes_copying_but_refunds_nothing_until_the_owner_is_dropped() {
    let account = TlsBackingAccount::new(2);
    let mut process = prepared(&account, Target::X86_64).release_staging();
    let baseline = account.usage();
    let mut destination = vec![0xb6; PAGE_BYTES];
    assert!(!process.creation_stopped());
    process.stop_creation();
    process.stop_creation();
    assert!(process.creation_stopped());
    assert_eq!(
        process.initialize(0x10000, &mut destination),
        Err(TlsOwnerError::Stopped)
    );
    assert_eq!(
        process.initialize(1, &mut destination),
        Err(TlsOwnerError::Stopped)
    );
    assert_eq!(destination, vec![0xb6; PAGE_BYTES]);
    assert_eq!(account.usage(), baseline);
    drop(process);
    assert_eq!(account.usage().pages(), 0);
}

#[test]
fn bad_destinations_leave_bytes_and_retained_charges_unchanged() {
    for target in [Target::X86_64, Target::Aarch64] {
        let account = TlsBackingAccount::new(2);
        let process = prepared(&account, target).release_staging();
        let baseline = account.usage();
        for (base, length) in [
            (0, PAGE_BYTES),
            (1, PAGE_BYTES),
            (KEX_V1_USER_END, PAGE_BYTES),
            (0x10000, PAGE_BYTES - 1),
            (0x10000, PAGE_BYTES + 1),
        ] {
            let mut destination = vec![0xab; length];
            assert!(matches!(
                process.initialize(base, &mut destination),
                Err(TlsOwnerError::Initialize(_))
            ));
            assert_eq!(destination, vec![0xab; length]);
            assert_eq!(account.usage(), baseline);
        }
    }
}

#[test]
fn malformed_artifacts_and_placement_fail_before_initializer_allocation() {
    let account = TlsBackingAccount::new(64);
    let mut corrupt = TlsFixture::default().encode(Target::X86_64);
    *corrupt.last_mut().unwrap_or_else(|| unreachable!()) ^= 1;
    for (bytes, target, placement) in [
        (vec![], Target::X86_64, PLACEMENT),
        (corrupt, Target::X86_64, PLACEMENT),
        (
            TlsFixture::default().encode(Target::Aarch64),
            Target::X86_64,
            PLACEMENT,
        ),
        (
            TlsFixture::default().encode(Target::X86_64),
            Target::X86_64,
            ProcessMemoryPlacement {
                initial_thread_base: PLACEMENT.image_base,
                ..PLACEMENT
            },
        ),
    ] {
        let called = Cell::new(false);
        assert!(
            StagedTlsImage::prepare_with(bytes, target, placement, UNLIMITED, &account, |_| {
                called.set(true);
                Err(TlsOwnerError::AllocationFailed)
            })
            .is_err()
        );
        assert!(!called.get());
        assert_eq!(account.usage(), TlsBackingUsage::default());
    }
}

#[test]
fn insufficient_combined_backing_refuses_before_allocation() {
    for pages in [0, 1] {
        let account = TlsBackingAccount::new(pages);
        let called = Cell::new(false);
        let result = StagedTlsImage::prepare_with(
            TlsFixture::default().encode(Target::X86_64),
            Target::X86_64,
            PLACEMENT,
            UNLIMITED,
            &account,
            |_| {
                called.set(true);
                Err(TlsOwnerError::AllocationFailed)
            },
        );
        assert_eq!(result.err(), Some(TlsOwnerError::BackingBudget));
        assert!(!called.get());
        assert_eq!(account.usage().pages(), 0);
    }
}

#[test]
fn allocation_failure_rolls_back_after_reservation_without_refunding_another_owner() {
    let account = TlsBackingAccount::new(3);
    let other = prepared(&account, Target::X86_64).release_staging();
    let baseline = account.usage();
    let result = StagedTlsImage::prepare_with(
        TlsFixture::default().encode(Target::X86_64),
        Target::X86_64,
        PLACEMENT,
        UNLIMITED,
        &account,
        |bytes| {
            assert_eq!(bytes, PAGE_BYTES);
            assert_eq!(account.usage().pages(), 3);
            assert_eq!(account.usage().staging_pages(), 1);
            assert_eq!(account.usage().initializer_pages(), 2);
            Err(TlsOwnerError::AllocationFailed)
        },
    );
    assert_eq!(result.err(), Some(TlsOwnerError::AllocationFailed));
    assert_eq!(account.usage(), baseline);
    drop(other);
    assert_eq!(account.usage().pages(), 0);
}

fn excessive_buffer(requested: usize) -> Result<Vec<u8>, TlsOwnerError> {
    let mut bytes = allocate(requested + PAGE_BYTES)?;
    bytes.resize(bytes.capacity(), 0xb7);
    Ok(bytes)
}

#[test]
fn excess_initializer_capacity_is_fully_charged_cleared_and_retained() {
    let account = TlsBackingAccount::new(8);
    let staged = StagedTlsImage::prepare_with(
        TlsFixture::default().encode(Target::X86_64),
        Target::X86_64,
        PLACEMENT,
        UNLIMITED,
        &account,
        excessive_buffer,
    )
    .unwrap_or_else(|_| unreachable!());
    let charged = capacity_pages(staged.process.initializer.bytes.capacity())
        .unwrap_or_else(|_| unreachable!());
    assert!(charged >= 2);
    assert_eq!(staged.plan().charges().template_pages(), charged);
    assert_eq!(account.usage().initializer_pages(), charged);
    assert_eq!(
        staged.plan().charges().peak_resident_pages(),
        staged.plan().charges().mapped_pages()
            + staged.plan().charges().table_pages()
            + account.usage().pages()
    );
    assert_eq!(&staged.process.initializer.bytes[..3], &[0x5a; 3]);
    assert!(
        staged.process.initializer.bytes[3..]
            .iter()
            .all(|byte| *byte == 0)
    );
    let process = staged.release_staging();
    assert_eq!(account.usage().pages(), charged);
    drop(process);
    assert_eq!(account.usage().pages(), 0);
}

#[test]
fn excess_initializer_capacity_must_fit_both_accounts_or_roll_back() {
    for (pages, budget, error) in [
        (2, UNLIMITED, TlsOwnerError::BackingBudget),
        (
            8,
            ProcessMemoryBudget {
                template_pages: 1,
                ..UNLIMITED
            },
            TlsOwnerError::Memory(ProcessMemoryError::TemplateBudget),
        ),
    ] {
        let account = TlsBackingAccount::new(pages);
        let result = StagedTlsImage::prepare_with(
            TlsFixture::default().encode(Target::X86_64),
            Target::X86_64,
            PLACEMENT,
            budget,
            &account,
            excessive_buffer,
        );
        assert_eq!(result.err(), Some(error));
        assert_eq!(account.usage().pages(), 0);
    }
}

#[test]
fn staging_spare_capacity_is_charged_before_any_initializer_allocation() {
    let source = TlsFixture::default().encode(Target::X86_64);
    let artifact = Artifact::parse(&source, Target::X86_64).unwrap_or_else(|_| unreachable!());
    let plan =
        ProcessMemoryPlan::new(&artifact, PLACEMENT, UNLIMITED).unwrap_or_else(|_| unreachable!());
    let mut padded = Vec::with_capacity(source.len() + 3 * PAGE_BYTES);
    padded.extend_from_slice(&source);
    let staged_pages = capacity_pages(padded.capacity()).unwrap_or_else(|_| unreachable!());
    let account = TlsBackingAccount::new(16);
    let called = Cell::new(false);
    let failed = StagedTlsImage::prepare_with(
        padded.clone(),
        Target::X86_64,
        PLACEMENT,
        ProcessMemoryBudget {
            staging_bytes: 0,
            ..UNLIMITED
        },
        &account,
        |_| {
            called.set(true);
            Err(TlsOwnerError::AllocationFailed)
        },
    );
    assert_eq!(
        failed.err(),
        Some(TlsOwnerError::Memory(ProcessMemoryError::StagingBudget))
    );
    assert!(!called.get());
    // Cloning a Vec need not preserve spare capacity; move the original below.
    let failed = StagedTlsImage::prepare_with(
        padded,
        Target::X86_64,
        PLACEMENT,
        exact(&plan),
        &account,
        |_| {
            called.set(true);
            Err(TlsOwnerError::AllocationFailed)
        },
    );
    assert_eq!(
        failed.err(),
        Some(TlsOwnerError::Memory(
            ProcessMemoryError::ResidentPageBudget
        ))
    );
    assert!(!called.get());
    assert_eq!(account.usage().pages(), 0);
    let mut padded = Vec::with_capacity(source.len() + 3 * PAGE_BYTES);
    padded.extend_from_slice(&source);
    let staged = StagedTlsImage::prepare(padded, Target::X86_64, PLACEMENT, UNLIMITED, &account)
        .unwrap_or_else(|_| unreachable!());
    assert_eq!(staged.plan().charges().staging_pages(), staged_pages);
    assert_eq!(staged.plan().charges().staging_bytes(), source.len() as u64);
    assert_eq!(account.usage().staging_pages(), staged_pages);
    drop(staged);
    assert_eq!(account.usage().pages(), 0);
}

#[test]
fn stopped_and_unreleased_owners_compete_for_capacity_until_actual_drop() {
    let account = TlsBackingAccount::new(3);
    let mut first = prepared(&account, Target::X86_64).release_staging();
    let second = prepared(&account, Target::Aarch64).release_staging();
    first.stop_creation();
    assert_eq!(account.usage().pages(), 2);
    assert_eq!(
        StagedTlsImage::prepare(
            TlsFixture::default().encode(Target::X86_64),
            Target::X86_64,
            PLACEMENT,
            UNLIMITED,
            &account
        )
        .err(),
        Some(TlsOwnerError::BackingBudget)
    );
    assert_eq!(account.usage().pages(), 2);
    drop(first);
    let third = prepared(&account, Target::X86_64).release_staging();
    drop(second);
    assert_eq!(account.usage().pages(), third.backing_pages());
    drop(third);
    assert_eq!(account.usage().pages(), 0);
}

#[test]
fn reservation_arithmetic_cannot_wrap_or_refund_a_failed_increase() {
    let account = TlsBackingAccount::new(u64::MAX);
    let mut reservation = account
        .reserve(BackingKind::Staging, u64::MAX)
        .unwrap_or_else(|_| unreachable!());
    assert_eq!(
        account.reserve(BackingKind::Initializer, 1).err(),
        Some(TlsOwnerError::ArithmeticOverflow)
    );
    assert_eq!(reservation.grow(0), Err(TlsOwnerError::ArithmeticOverflow));
    assert_eq!(account.usage().pages(), u64::MAX);
    drop(reservation);
    assert_eq!(account.usage().pages(), 0);
    assert!(capacity_pages(usize::MAX).is_err());
}

#[test]
fn invalid_actual_backing_updates_leave_the_plan_unchanged() {
    let account = TlsBackingAccount::new(2);
    let staged = prepared(&account, Target::X86_64);
    let mut plan = staged.plan().clone();
    let original = plan.clone();
    for (template, staging, error) in [
        (0, 1, ProcessMemoryError::InvalidBacking),
        (1, 0, ProcessMemoryError::InvalidBacking),
        (u64::MAX, 1, ProcessMemoryError::ArithmeticOverflow),
        (1, u64::MAX, ProcessMemoryError::ArithmeticOverflow),
    ] {
        assert_eq!(
            plan.charge_backing(template, staging, UNLIMITED),
            Err(error)
        );
        assert_eq!(plan, original);
    }
}
