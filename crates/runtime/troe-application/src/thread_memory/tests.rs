use super::*;
use crate::{PAGE_BYTES, Target, static_tls::LOCAL_EXEC_BYTES};
use alloc::{collections::BTreeSet, vec};

const UNLIMITED: ThreadMemoryBudget = ThreadMemoryBudget {
    mapped_pages: u64::MAX,
    resident_pages: u64::MAX,
    reserved_pages: u64::MAX,
    ordinary_frames: u64::MAX,
    ipc_pairs: u64::MAX,
};

fn tls(target: Target, memory: u64, alignment: u64) -> StaticTlsLayout {
    StaticTlsLayout::new(target, memory.min(3), memory, alignment, u64::MAX)
        .unwrap_or_else(|_| unreachable!())
}

fn plan(base: u64, stack: u64, tls: StaticTlsLayout) -> ThreadMemoryPlan {
    ThreadMemoryPlan::new(base, stack, tls, UNLIMITED).unwrap_or_else(|_| unreachable!())
}

fn exact_budget(charges: ThreadMemoryCharges) -> ThreadMemoryBudget {
    ThreadMemoryBudget {
        mapped_pages: charges.mapped_pages(),
        resident_pages: charges.resident_pages(),
        reserved_pages: charges.reserved_pages(),
        ordinary_frames: charges.ordinary_frames(),
        ipc_pairs: charges.ipc_pairs(),
    }
}

// Independent exhaustive oracle: enumerate actual mapped pages and collect the
// identity of their parent table at each level. Do not count guards or the root.
fn table_oracle(plan: ThreadMemoryPlan) -> u64 {
    let mut tables = BTreeSet::new();
    for region in plan.regions() {
        for address in (region.start()..region.end()).step_by(PAGE_BYTES) {
            for shift in [21, 30, 39] {
                tables.insert((shift, address >> shift));
            }
        }
    }
    u64::try_from(tables.len()).unwrap_or_else(|_| unreachable!())
}

#[test]
fn canonical_window_keeps_all_three_guards_unmapped() {
    for target in [Target::X86_64, Target::Aarch64] {
        let description = tls(target, 37, 64);
        let planned = plan(0x1_0000_0000, 4, description);
        let [stack, template, ipc] = planned.regions();
        assert_eq!(stack.start(), planned.reservation_base() + PAGE_SIZE);
        assert_eq!(stack.pages(), 4);
        assert_eq!(stack.end() % 16, 0);
        assert_eq!(template.start(), stack.end() + PAGE_SIZE);
        assert_eq!(template.pages(), description.pages());
        assert_eq!(ipc.start(), template.end());
        assert_eq!(ipc.pages(), 2);
        assert_eq!(planned.reservation_end(), ipc.end() + PAGE_SIZE);
        assert_eq!(planned.charges().mapped_pages(), 7);
        assert_eq!(planned.charges().reserved_pages(), 10);
        assert_eq!(planned.charges().table_pages(), 3);
        assert_eq!(planned.charges().ordinary_frames(), 8);
        assert_eq!(planned.charges().resident_pages(), 10);
        assert_eq!(planned.charges().ipc_pairs(), 1);
        assert_eq!(table_oracle(planned), 3);
    }
}

#[test]
fn all_mapped_pages_and_only_mapped_pages_need_backing() {
    for target in [Target::X86_64, Target::Aarch64] {
        for alignment in [1, 8, 4096, 8192, 65536] {
            let description = tls(target, 5001, alignment);
            let planned = plan(3 * PAGE_SIZE, 17, description);
            let regions = planned.regions();
            let mut mapped = 0;
            let mut unmapped = 0;
            for address in
                (planned.reservation_base()..planned.reservation_end()).step_by(PAGE_BYTES)
            {
                let matches = regions
                    .iter()
                    .filter(|region| region.start() <= address && address < region.end())
                    .count();
                assert!(matches <= 1, "aliased planned regions");
                if matches == 1 {
                    mapped += 1;
                } else {
                    unmapped += 1;
                }
            }
            assert_eq!(mapped, planned.charges().mapped_pages());
            assert!(unmapped >= 3);
            assert_eq!(mapped + unmapped, planned.charges().reserved_pages());
            assert_eq!(
                unmapped,
                3 + (regions[1].start() - regions[0].end() - PAGE_SIZE) / PAGE_SIZE
            );
            assert_eq!(regions[1].start() % description.mapping_alignment(), 0);
        }
    }
}

#[test]
fn thread_pointer_and_tls_initialization_agree_at_actual_placement() {
    for target in [Target::X86_64, Target::Aarch64] {
        for (memory, alignment) in [(0, 1), (3, 1), (37, 64), (8193, 8192)] {
            let description = tls(target, memory, alignment);
            let planned = plan(7 * PAGE_SIZE, 5, description);
            let template = vec![
                19;
                usize::try_from(description.file_bytes())
                    .unwrap_or_else(|_| unreachable!())
            ];
            let mut destination = vec![
                0xa5;
                usize::try_from(description.mapped_bytes())
                    .unwrap_or_else(|_| unreachable!())
            ];
            assert_eq!(
                description.initialize(planned.regions()[1].start(), &template, &mut destination),
                Ok(planned.thread_pointer())
            );
            let region = planned.regions()[1];
            assert!(region.start() <= planned.thread_pointer());
            assert!(planned.thread_pointer() < region.end());
        }
    }
}

#[test]
fn every_budget_is_independently_binding_including_boot_ipc() {
    let description = tls(Target::X86_64, 5001, 8192);
    let planned = plan(PAGE_SIZE, 4, description);
    let exact = exact_budget(planned.charges());
    assert_eq!(
        ThreadMemoryPlan::new(PAGE_SIZE, 4, description, exact),
        Ok(planned)
    );
    for (budget, error) in [
        (
            ThreadMemoryBudget {
                mapped_pages: exact.mapped_pages - 1,
                ..exact
            },
            ThreadMemoryError::MappedPageBudget,
        ),
        (
            ThreadMemoryBudget {
                resident_pages: exact.resident_pages - 1,
                ..exact
            },
            ThreadMemoryError::ResidentPageBudget,
        ),
        (
            ThreadMemoryBudget {
                reserved_pages: exact.reserved_pages - 1,
                ..exact
            },
            ThreadMemoryError::ReservedPageBudget,
        ),
        (
            ThreadMemoryBudget {
                ordinary_frames: exact.ordinary_frames - 1,
                ..exact
            },
            ThreadMemoryError::FrameBudget,
        ),
        (
            ThreadMemoryBudget {
                ipc_pairs: 0,
                ..exact
            },
            ThreadMemoryError::IpcBudget,
        ),
    ] {
        assert_eq!(
            ThreadMemoryPlan::new(PAGE_SIZE, 4, description, budget),
            Err(error)
        );
    }
    assert_eq!(
        exact.ordinary_frames + 2,
        planned.charges().resident_pages(),
        "boot-reserved IPC is logically charged without allocating ordinary frames again"
    );
}

#[test]
fn sparse_alignment_gap_costs_virtual_pages_but_no_leaf_tables_or_frames() {
    let description = tls(Target::X86_64, 0, LOCAL_EXEC_BYTES);
    let planned = plan(PAGE_SIZE, 1, description);
    assert_eq!(planned.regions()[1].start(), LOCAL_EXEC_BYTES);
    assert_eq!(planned.charges().mapped_pages(), 4);
    assert_eq!(planned.charges().table_pages(), 4);
    assert_eq!(planned.charges().ordinary_frames(), 6);
    assert_eq!(
        planned.charges().reserved_pages(),
        LOCAL_EXEC_BYTES / PAGE_SIZE + 3
    );
    assert_eq!(table_oracle(planned), 4);
    let small_virtual = ThreadMemoryBudget {
        reserved_pages: 100,
        ..UNLIMITED
    };
    assert_eq!(
        ThreadMemoryPlan::new(PAGE_SIZE, 1, description, small_virtual),
        Err(ThreadMemoryError::ReservedPageBudget)
    );
}

#[test]
fn table_reservation_matches_oracle_across_every_level_boundary() {
    for boundary in [1_u64 << 21, 1 << 30, 1 << 39, KEX_V1_USER_END - (1 << 21)] {
        for distance in [1, 2, 3, 5, 8] {
            for target in [Target::X86_64, Target::Aarch64] {
                let planned = plan(boundary - distance * PAGE_SIZE, 8, tls(target, 5001, 8192));
                assert_eq!(planned.charges().table_pages(), table_oracle(planned));
            }
        }
    }
}

#[test]
fn varied_layouts_match_independent_page_enumeration() {
    let mut seed = 0x749f_82e1_u64;
    for _ in 0..256 {
        seed = seed.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1);
        let base = (1 + seed % (KEX_V1_USER_END / PAGE_SIZE - 8192)) * PAGE_SIZE;
        let stack = 1 + (seed >> 17) % 700;
        let alignment = 1 << ((seed >> 29) % 17);
        let memory = (seed >> 33) % 17000;
        for target in [Target::X86_64, Target::Aarch64] {
            let planned = plan(base, stack, tls(target, memory, alignment));
            assert_eq!(planned.charges().table_pages(), table_oracle(planned));
            assert_eq!(
                planned.charges().mapped_pages(),
                stack + planned.regions()[1].pages() + 2
            );
        }
    }
}

#[test]
fn invalid_and_overflowing_ranges_fail_before_a_plan_exists() {
    let description = tls(Target::X86_64, 0, 1);
    assert_eq!(
        ThreadMemoryPlan::new(PAGE_SIZE, 0, description, UNLIMITED),
        Err(ThreadMemoryError::EmptyStack)
    );
    for base in [0, 1, PAGE_SIZE - 1, PAGE_SIZE + 1, KEX_V1_USER_END] {
        assert_eq!(
            ThreadMemoryPlan::new(base, 1, description, UNLIMITED),
            Err(ThreadMemoryError::InvalidPlacement)
        );
    }
    for (base, stack) in [
        (PAGE_SIZE, u64::MAX),
        (!(PAGE_SIZE - 1), 1),
        (PAGE_SIZE, u64::MAX / PAGE_SIZE),
    ] {
        assert_eq!(
            ThreadMemoryPlan::new(base, stack, description, UNLIMITED),
            Err(ThreadMemoryError::ArithmeticOverflow)
        );
    }
    // One stack page, one TLS page, two IPC pages and three guards exactly fit.
    let base = KEX_V1_USER_END - 7 * PAGE_SIZE;
    let planned = plan(base, 1, description);
    assert_eq!(planned.reservation_end(), KEX_V1_USER_END);
    assert_eq!(
        ThreadMemoryPlan::new(base + PAGE_SIZE, 1, description, UNLIMITED),
        Err(ThreadMemoryError::InvalidPlacement)
    );
}

#[test]
fn huge_stack_planning_is_bounded_without_allocating_or_walking_pages() {
    let pages = (1_u64 << 40) / PAGE_SIZE;
    let planned = plan(PAGE_SIZE, pages, tls(Target::X86_64, 0, 1));
    assert_eq!(planned.regions()[0].pages(), pages);
    // All three levels cross their starting prefix boundary; sparse guards
    // at the two ends do not create additional prefixes beyond these.
    assert_eq!(
        planned.charges().table_pages(),
        (1 << 19) + 1 + (1 << 10) + 1 + 3
    );
    assert_eq!(planned.charges().mapped_pages(), pages + 3);
}

#[test]
fn aggregate_prepared_and_retained_plans_exhaust_all_allowances() {
    let description = tls(Target::X86_64, 37, 64);
    let first = plan(PAGE_SIZE, 4, description);
    let second = plan(1 << 39, 11, description);
    let zero = ThreadMemoryCharges::default();
    assert_eq!(zero.checked_add(first.charges()), Ok(first.charges()));
    let both = first
        .charges()
        .checked_add(second.charges())
        .unwrap_or_else(|_| unreachable!());
    assert_eq!(both.mapped_pages(), 21);
    assert_eq!(both.reserved_pages(), 27);
    assert_eq!(both.ipc_pairs(), 2);
    assert_eq!(both.table_pages(), 6);
    assert_eq!(both.ordinary_frames(), 23);
    assert_eq!(both.resident_pages(), 27);
    assert_eq!(exact_budget(both).check(both), Ok(()));
    assert_eq!(
        ThreadMemoryBudget {
            ipc_pairs: 1,
            ..UNLIMITED
        }
        .check(both),
        Err(ThreadMemoryError::IpcBudget)
    );
    assert_eq!(
        exact_budget(first.charges()).check(both),
        Err(ThreadMemoryError::MappedPageBudget)
    );
    // A snapshot is not an ownership ledger: merely checking never refunds or
    // mutates these cumulative charges, even when an execution has completed.
    assert_eq!(exact_budget(both).check(both), Ok(()));
}

#[test]
fn aggregate_overflow_is_rejected_instead_of_wrapping_a_derived_charge() {
    let mut charge = plan(PAGE_SIZE, 1, tls(Target::X86_64, 0, 1)).charges();
    let mut rejected = false;
    for _ in 0..64 {
        match charge.checked_add(charge) {
            Ok(doubled) => {
                assert_eq!(doubled.resident_pages(), charge.resident_pages() * 2);
                assert_eq!(doubled.ordinary_frames(), charge.ordinary_frames() * 2);
                assert!(doubled.reserved_pages().checked_mul(PAGE_SIZE).is_some());
                charge = doubled;
            }
            Err(ThreadMemoryError::ArithmeticOverflow) => {
                rejected = true;
                break;
            }
            Err(_) => unreachable!(),
        }
    }
    assert!(rejected);
}
