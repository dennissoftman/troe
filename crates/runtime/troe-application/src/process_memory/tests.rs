use super::*;
use crate::{
    ABI_MINOR, KEX_V1_LOAD_RECORD_BYTES, KEX_V1_MAGIC, PAGE_BYTES, Target,
    bytes::{write_u16, write_u32, write_u64},
    canonical_image_span_bytes, parse_kex,
    static_tls::LOCAL_EXEC_BYTES,
    tls_artifact::{HEADER_BYTES, Metadata},
};
use alloc::{collections::BTreeSet, vec, vec::Vec};
use troe_abi::threading::{Kind, StartupReference};

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

struct Fixture {
    heap: u64,
    stack: u64,
    file: usize,
    memory: u64,
    alignment: u64,
    segments: usize,
    gap: u64,
}
impl Default for Fixture {
    fn default() -> Self {
        Self {
            heap: 3,
            stack: 4,
            file: 3,
            memory: 37,
            alignment: 64,
            segments: 2,
            gap: 0,
        }
    }
}
impl Fixture {
    fn encode(&self, target: Target) -> Vec<u8> {
        let payload = HEADER_BYTES + self.segments * KEX_V1_LOAD_RECORD_BYTES;
        let file_offset = payload + 16 + self.file;
        let mut bytes = vec![0; file_offset + self.file];
        bytes[..8].copy_from_slice(&KEX_V1_MAGIC);
        for (offset, value) in [
            (8, 1),
            (10, 3),
            (12, target as u16),
            (14, 160),
            (16, 40),
            (18, 1),
            (20, 4),
            (22, 2),
            (
                32,
                u16::try_from(self.segments).unwrap_or_else(|_| unreachable!()),
            ),
            (72, 16),
        ] {
            write_u16(&mut bytes, offset, value);
        }
        for (offset, value) in [(56, HEADER_BYTES), (60, payload), (64, payload)] {
            write_u32(
                &mut bytes,
                offset,
                u32::try_from(value).unwrap_or_else(|_| unreachable!()),
            );
        }
        write_u64(&mut bytes, 40, self.stack);
        write_u64(&mut bytes, 48, self.heap);
        write_u64(&mut bytes, 80, (file_offset + self.file) as u64);
        let mut image_end = 0;
        let mut source = 0;
        let mut file_at = payload;
        for index in 0..self.segments {
            let at = HEADER_BYTES + index * KEX_V1_LOAD_RECORD_BYTES;
            let offset = if index == 0 { 0 } else { image_end + self.gap };
            let file = match index {
                0 => 16,
                1 => self.file,
                _ => 0,
            };
            let memory = pages_for(file as u64)
                .unwrap_or_else(|_| unreachable!())
                .max(1)
                * PAGE_SIZE;
            for (field, value) in [
                (0, offset),
                (8, file_at as u64),
                (16, file as u64),
                (24, memory),
            ] {
                write_u64(&mut bytes, at + field, value);
            }
            write_u32(
                &mut bytes,
                at + 32,
                match index {
                    0 => 2,
                    1 => 3,
                    _ => 1,
                },
            );
            if index == 1 {
                source = offset;
            }
            bytes[file_at..file_at + file].fill(if index == 0 { 0x90 } else { 0x5a });
            image_end = offset + memory;
            file_at += file;
        }
        let span = canonical_image_span_bytes(image_end).unwrap_or_else(|| unreachable!());
        write_u32(
            &mut bytes,
            36,
            u32::try_from(span / PAGE_SIZE).unwrap_or_else(|_| unreachable!()),
        );
        bytes[file_offset..].fill(0x5a);
        let extension = Metadata {
            source_offset: if self.file == 0 { 0 } else { source },
            file_offset: file_offset as u64,
            file_bytes: self.file as u64,
            memory_bytes: self.memory,
            alignment: self.alignment,
            trampoline_offset: 4,
        }
        .encode(target)
        .unwrap_or_else(|_| unreachable!());
        bytes[96..HEADER_BYTES].copy_from_slice(&extension);
        bytes
    }
}

fn plan(bytes: &[u8], target: Target, placement: ProcessMemoryPlacement) -> ProcessMemoryPlan {
    let artifact = Artifact::parse(bytes, target).unwrap_or_else(|error| unreachable!("{error:?}"));
    ProcessMemoryPlan::new(&artifact, placement, UNLIMITED)
        .unwrap_or_else(|error| unreachable!("{error:?}"))
}
fn exact(charges: ProcessMemoryCharges) -> ProcessMemoryBudget {
    ProcessMemoryBudget {
        mapped_pages: charges.mapped_pages(),
        resident_pages: charges.peak_resident_pages(),
        reserved_pages: charges.reserved_pages(),
        ordinary_frames: charges.peak_ordinary_frames(),
        ipc_pairs: charges.ipc_pairs(),
        tls_pages: charges.tls_pages(),
        template_pages: charges.template_pages(),
        staging_bytes: charges.staging_bytes(),
    }
}

// Enumerate mapped pages, independently identifying every lower table. This
// deliberately does not use the interval-prefix implementation under test.
fn oracle(plan: &ProcessMemoryPlan) -> u64 {
    let mut prefixes = BTreeSet::new();
    for region in plan.regions() {
        for address in (region.start()..region.end()).step_by(PAGE_BYTES) {
            for shift in [21, 30, 39] {
                prefixes.insert((shift, address >> shift));
            }
        }
    }
    1 + prefixes.len() as u64
}

#[test]
fn initial_thread_composes_with_shared_memory_and_roundtrips_its_descriptor() {
    for target in [Target::X86_64, Target::Aarch64] {
        let bytes = Fixture::default().encode(target);
        let planned = plan(&bytes, target, PLACEMENT);
        assert_eq!(planned.startup_address(), PLACEMENT.image_base + (1 << 21));
        assert_eq!(
            planned.heap_address(),
            planned.startup_address() + PAGE_SIZE
        );
        assert_eq!(planned.heap_capacity_pages(), 16);
        assert_eq!(planned.entry_address(), PLACEMENT.image_base);
        assert_eq!(planned.trampoline_address(), PLACEMENT.image_base + 4);
        let mut total = 0;
        for region in planned.regions() {
            assert_eq!(region.start() % PAGE_SIZE, 0);
            total += region.pages();
            let expected = match region.kind() {
                ProcessMemoryKind::Startup
                | ProcessMemoryKind::Thread(ThreadMemoryKind::Startup) => {
                    SegmentPermissions::ReadOnly
                }
                ProcessMemoryKind::Image if region.start() == planned.entry_address() => {
                    SegmentPermissions::ReadExecute
                }
                _ => SegmentPermissions::ReadWrite,
            };
            assert_eq!(region.permissions(), expected);
            assert!(
                !planned
                    .regions()
                    .any(|other| region.start() != other.start()
                        && region.start() < other.end()
                        && other.start() < region.end())
            );
        }
        assert_eq!(planned.regions().count(), 8);
        assert_eq!(total, planned.charges().mapped_pages());
        let thread = Token::new(Kind::Thread, 1, 1).unwrap_or_else(|_| unreachable!());
        let descriptor = planned
            .initial_descriptor(thread)
            .unwrap_or_else(|_| unreachable!());
        assert!(descriptor.initial);
        assert_eq!((descriptor.entry, descriptor.argument), (0, 0));
        assert_eq!(descriptor.process_startup, planned.startup_address());
        assert_eq!(
            descriptor.thread_pointer,
            planned.initial_thread().thread_pointer()
        );
        let prefix = descriptor.encode().unwrap_or_else(|_| unreachable!());
        let mut page = [0; PAGE_BYTES];
        page[..prefix.len()].copy_from_slice(&prefix);
        assert_eq!(StartupDescriptor::decode_page(&page), Ok(descriptor));
        let reference = StartupReference {
            address: descriptor.address,
        };
        assert_eq!(
            StartupReference::decode(&reference.encode().unwrap_or_else(|_| unreachable!())),
            Ok(reference)
        );
        let wrong = Token::new(Kind::Mutex, 1, 1).unwrap_or_else(|_| unreachable!());
        assert!(planned.initial_descriptor(wrong).is_err());
    }
}

#[test]
fn peaks_include_independent_initializer_and_staging_without_recharging_boot_ipc() {
    let bytes = Fixture::default().encode(Target::X86_64);
    let planned = plan(&bytes, Target::X86_64, PLACEMENT);
    let c = planned.charges();
    assert_eq!(c.shared_pages(), 6); // two image pages, startup, three heap pages
    assert_eq!(c.initial_thread_pages(), 8);
    assert_eq!(c.template_pages(), 1);
    assert_eq!(c.staging_bytes(), bytes.len() as u64);
    assert_eq!(c.staging_pages(), 1);
    assert_eq!(c.table_pages(), 6); // root, one L3, one L2, three distinct L1 tables
    assert_eq!(c.table_pages(), oracle(&planned));
    assert_eq!(c.resident_pages(), 21);
    assert_eq!(c.peak_resident_pages(), 22);
    assert_eq!(c.ordinary_frames(), 19);
    assert_eq!(c.peak_ordinary_frames(), 20);
    assert_eq!(c.ipc_pairs(), 1);
    assert_eq!(c.reserved_pages(), 512 + 1 + 16 + 11);
}

#[test]
fn each_independent_allowance_is_required_at_the_exact_boundary() {
    let bytes = Fixture::default().encode(Target::X86_64);
    let artifact = Artifact::parse(&bytes, Target::X86_64).unwrap_or_else(|_| unreachable!());
    let planned = plan(&bytes, Target::X86_64, PLACEMENT);
    let exact = exact(planned.charges());
    assert!(ProcessMemoryPlan::new(&artifact, PLACEMENT, exact).is_ok());
    for (budget, error) in [
        (
            ProcessMemoryBudget {
                mapped_pages: exact.mapped_pages - 1,
                ..exact
            },
            ProcessMemoryError::MappedPageBudget,
        ),
        (
            ProcessMemoryBudget {
                resident_pages: exact.resident_pages - 1,
                ..exact
            },
            ProcessMemoryError::ResidentPageBudget,
        ),
        (
            ProcessMemoryBudget {
                reserved_pages: exact.reserved_pages - 1,
                ..exact
            },
            ProcessMemoryError::ReservedPageBudget,
        ),
        (
            ProcessMemoryBudget {
                ordinary_frames: exact.ordinary_frames - 1,
                ..exact
            },
            ProcessMemoryError::FrameBudget,
        ),
        (
            ProcessMemoryBudget {
                ipc_pairs: 0,
                ..exact
            },
            ProcessMemoryError::IpcBudget,
        ),
        (
            ProcessMemoryBudget {
                tls_pages: exact.tls_pages - 1,
                ..exact
            },
            ProcessMemoryError::TlsPageBudget,
        ),
        (
            ProcessMemoryBudget {
                template_pages: 0,
                ..exact
            },
            ProcessMemoryError::TemplateBudget,
        ),
        (
            ProcessMemoryBudget {
                staging_bytes: exact.staging_bytes - 1,
                ..exact
            },
            ProcessMemoryError::StagingBudget,
        ),
    ] {
        assert_eq!(
            ProcessMemoryPlan::new(&artifact, PLACEMENT, budget),
            Err(error)
        );
        assert_eq!(budget.check(planned.charges()), Err(error));
    }
}

#[test]
fn reservation_collisions_include_image_holes_heap_growth_and_thread_guards() {
    let bytes = Fixture::default().encode(Target::Aarch64);
    let artifact = Artifact::parse(&bytes, Target::Aarch64).unwrap_or_else(|_| unreachable!());
    let baseline = plan(&bytes, Target::Aarch64, PLACEMENT);
    let (shared_start, shared_end) = baseline.shared_reservation();
    let window = baseline.initial_thread().reservation_end() - PLACEMENT.initial_thread_base;
    for base in [
        shared_start,
        shared_start + 64 * PAGE_SIZE,
        baseline.startup_address(),
        baseline.heap_address() + 15 * PAGE_SIZE,
        shared_end - PAGE_SIZE,
        shared_start - window + PAGE_SIZE,
    ] {
        assert_eq!(
            ProcessMemoryPlan::new(
                &artifact,
                ProcessMemoryPlacement {
                    initial_thread_base: base,
                    ..PLACEMENT
                },
                UNLIMITED
            ),
            Err(ProcessMemoryError::Overlap)
        );
    }
    for base in [shared_end, shared_start - window] {
        let adjacent = plan(
            &bytes,
            Target::Aarch64,
            ProcessMemoryPlacement {
                initial_thread_base: base,
                ..PLACEMENT
            },
        );
        assert_eq!(adjacent.charges().table_pages(), oracle(&adjacent));
        assert!(
            adjacent
                .initial_descriptor(
                    Token::new(Kind::Thread, 1, 1).unwrap_or_else(|_| unreachable!())
                )
                .is_ok()
        );
    }
}

#[test]
fn invalid_capacity_placement_and_arithmetic_fail_before_publication() {
    let bytes = Fixture::default().encode(Target::X86_64);
    let artifact = Artifact::parse(&bytes, Target::X86_64).unwrap_or_else(|_| unreachable!());
    for capacity in [0, 2, (1 << 32) + 1, u64::MAX] {
        assert_eq!(
            ProcessMemoryPlan::new(
                &artifact,
                ProcessMemoryPlacement {
                    heap_capacity_pages: capacity,
                    ..PLACEMENT
                },
                UNLIMITED
            ),
            Err(ProcessMemoryError::InvalidHeapCapacity)
        );
    }
    for base in [
        0,
        PAGE_SIZE,
        KEX_V1_MIN_IMAGE_BASE - KEX_V1_IMAGE_ALIGNMENT,
        KEX_V1_MIN_IMAGE_BASE + PAGE_SIZE,
        KEX_V1_USER_END - KEX_V1_IMAGE_ALIGNMENT,
        KEX_V1_USER_END,
    ] {
        assert_eq!(
            ProcessMemoryPlan::new(
                &artifact,
                ProcessMemoryPlacement {
                    image_base: base,
                    ..PLACEMENT
                },
                UNLIMITED
            ),
            Err(ProcessMemoryError::InvalidPlacement)
        );
    }
    assert_eq!(
        ProcessMemoryPlan::new(
            &artifact,
            ProcessMemoryPlacement {
                image_base: !(KEX_V1_IMAGE_ALIGNMENT - 1),
                ..PLACEMENT
            },
            UNLIMITED
        ),
        Err(ProcessMemoryError::ArithmeticOverflow)
    );
    for base in [0, 1, KEX_V1_USER_END - PAGE_SIZE, !(PAGE_SIZE - 1)] {
        assert!(matches!(
            ProcessMemoryPlan::new(
                &artifact,
                ProcessMemoryPlacement {
                    initial_thread_base: base,
                    ..PLACEMENT
                },
                UNLIMITED
            ),
            Err(ProcessMemoryError::Thread(_))
        ));
    }
}

#[test]
fn empty_bss_and_initialized_tls_charge_and_initialize_the_actual_target_layout() {
    for target in [Target::X86_64, Target::Aarch64] {
        for (file, memory, alignment) in
            [(0, 0, 1), (0, 5001, 8192), (3, 37, 64), (4097, 9001, 65536)]
        {
            let bytes = Fixture {
                file,
                memory,
                alignment,
                heap: 0,
                ..Fixture::default()
            }
            .encode(target);
            let planned = plan(
                &bytes,
                target,
                ProcessMemoryPlacement {
                    heap_capacity_pages: 0,
                    ..PLACEMENT
                },
            );
            assert!(
                !planned
                    .regions()
                    .any(|region| region.kind() == ProcessMemoryKind::Heap)
            );
            assert_eq!(
                planned.charges().template_pages(),
                (file as u64).div_ceil(PAGE_SIZE)
            );
            assert_eq!(
                planned.charges().staging_pages(),
                (bytes.len() as u64).div_ceil(PAGE_SIZE)
            );
            let tls = planned.tls_layout();
            let template = Artifact::parse(&bytes, target).unwrap_or_else(|_| unreachable!());
            let mut destination =
                vec![0xa5; usize::try_from(tls.mapped_bytes()).unwrap_or_else(|_| unreachable!())];
            let tls_base = planned.initial_thread().regions()[1].start();
            assert_eq!(
                tls.initialize(tls_base, template.template(), &mut destination),
                Ok(planned.initial_thread().thread_pointer())
            );
            let begin = usize::try_from(tls.template_offset()).unwrap_or_else(|_| unreachable!());
            assert!(
                destination[begin..begin + file]
                    .iter()
                    .all(|byte| *byte == 0x5a)
            );
            assert!(
                destination[begin + file
                    ..begin + usize::try_from(memory).unwrap_or_else(|_| unreachable!())]
                    .iter()
                    .all(|byte| *byte == 0)
            );
            assert_eq!(planned.charges().table_pages(), oracle(&planned));
        }
    }
}

#[test]
fn prefix_union_matches_page_oracle_across_sparse_images_and_both_thread_sides() {
    for target in [Target::X86_64, Target::Aarch64] {
        for index in 0..128_u64 {
            let fixture = Fixture {
                alignment: 1 << (index % 17),
                segments: if index % 3 == 0 { MAX_LOAD_RECORDS } else { 2 },
                gap: (index % 4) * (1 << 21),
                heap: index % 17,
                stack: 4 + index % 19,
                ..Fixture::default()
            };
            let bytes = fixture.encode(target);
            let image_base = (1 << 39) - KEX_V1_IMAGE_ALIGNMENT + (index % 3) * (1 << 30);
            for thread_base in [
                image_base - (1 << 28) + (index % 7) * PAGE_SIZE,
                image_base + (1 << 28) - (index % 7) * PAGE_SIZE,
            ] {
                let planned = plan(
                    &bytes,
                    target,
                    ProcessMemoryPlacement {
                        image_base,
                        initial_thread_base: thread_base,
                        heap_capacity_pages: 64,
                    },
                );
                assert_eq!(
                    planned.charges().table_pages(),
                    oracle(&planned),
                    "{target:?} case {index}"
                );
                assert!(planned.regions().count() <= MAX_REGIONS);
                if fixture.segments == MAX_LOAD_RECORDS && fixture.heap != 0 {
                    assert_eq!(planned.regions().count(), MAX_REGIONS);
                }
            }
        }
    }
}

#[test]
fn huge_commit_and_alignment_require_bounded_region_work_without_backing() {
    for target in [Target::X86_64, Target::Aarch64] {
        let bytes = Fixture {
            heap: 1 << 32,
            stack: 1 << 32,
            file: 0,
            memory: 0,
            alignment: LOCAL_EXEC_BYTES,
            ..Fixture::default()
        }
        .encode(target);
        let planned = plan(
            &bytes,
            target,
            ProcessMemoryPlacement {
                heap_capacity_pages: 1 << 32,
                initial_thread_base: 1 << 46,
                ..PLACEMENT
            },
        );
        assert_eq!(planned.regions().count(), 8);
        let tls_pages = if target == Target::X86_64 { 1 } else { 4096 };
        assert_eq!(
            planned.charges().mapped_pages(),
            2 * (1 << 32) + 6 + tls_pages
        );
        assert!(planned.charges().reserved_pages() > planned.charges().mapped_pages());
        assert!(planned.charges().table_pages() < 1 << 26);
    }
}

#[test]
fn process_preflight_cannot_enable_native_admission_or_mutate_the_artifact() {
    for target in [Target::X86_64, Target::Aarch64] {
        let bytes = Fixture::default().encode(target);
        let original = bytes.clone();
        let planned = plan(&bytes, target, PLACEMENT);
        assert_eq!(planned.charges().staging_bytes(), bytes.len() as u64);
        assert_eq!(bytes, original);
        for minor in [ABI_MINOR, 4, u16::MAX] {
            assert!(parse_kex(&bytes, target, minor).is_err());
        }
    }
}

#[test]
fn reservations_may_end_at_user_end_and_read_only_image_permissions_survive() {
    for target in [Target::X86_64, Target::Aarch64] {
        let bytes = Fixture {
            segments: 3,
            ..Fixture::default()
        }
        .encode(target);
        let shared_at_end = plan(
            &bytes,
            target,
            ProcessMemoryPlacement {
                image_base: KEX_V1_USER_END - 2 * KEX_V1_IMAGE_ALIGNMENT,
                heap_capacity_pages: KEX_V1_IMAGE_ALIGNMENT / PAGE_SIZE - 1,
                ..PLACEMENT
            },
        );
        assert_eq!(shared_at_end.shared_reservation().1, KEX_V1_USER_END);
        let thread_at_end = plan(
            &bytes,
            target,
            ProcessMemoryPlacement {
                initial_thread_base: KEX_V1_USER_END - 11 * PAGE_SIZE,
                ..PLACEMENT
            },
        );
        assert_eq!(
            thread_at_end.initial_thread().reservation_end(),
            KEX_V1_USER_END
        );
        for planned in [shared_at_end, thread_at_end] {
            let read_only_image = planned
                .regions()
                .find(|region| {
                    region.kind() == ProcessMemoryKind::Image
                        && region.start() == planned.entry_address() + 2 * PAGE_SIZE
                })
                .unwrap_or_else(|| unreachable!());
            assert_eq!(read_only_image.permissions(), SegmentPermissions::ReadOnly);
            assert_eq!(planned.charges().table_pages(), oracle(&planned));
        }
    }
}
