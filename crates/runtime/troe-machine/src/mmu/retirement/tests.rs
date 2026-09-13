#![allow(clippy::unwrap_used, clippy::unnecessary_wraps, clippy::panic)]

use super::*;
use alloc::{vec, vec::Vec};
use troe_memory::MappingPermissions;

fn virtual_range(start: u64, pages: u64) -> VirtualRange {
    VirtualRange::from_pages(start * BASE_PAGE_SIZE, pages).unwrap()
}
fn physical(start: u64, pages: u64) -> PhysicalRange {
    PhysicalRange::from_pages(start * BASE_PAGE_SIZE, pages).unwrap()
}
fn region(start: u64, pages: u64) -> UserRegion {
    UserRegion {
        range: virtual_range(start, pages),
        permissions: MappingPermissions::READ_WRITE,
    }
}
fn identity(address: u64) -> Result<u64, MmuError> {
    Ok(address)
}

#[test]
fn split_coalesced_region_with_unsorted_fragmented_backing_without_allocation() {
    let mut regions = vec![region(1, 10), region(20, 1)];
    regions.reserve_exact(4);
    let capacity = regions.capacity();
    let high = [physical(8, 1)];
    let low = [physical(100, 1), physical(200, 1)];
    let targets = [
        Backing {
            range: virtual_range(8, 1),
            physical: &high,
            writable: true,
        },
        Backing {
            range: virtual_range(3, 2),
            physical: &low,
            writable: true,
        },
    ];
    let translation = |address| {
        Ok(match address / BASE_PAGE_SIZE {
            3 => 100 * BASE_PAGE_SIZE,
            4 => 200 * BASE_PAGE_SIZE,
            _ => address,
        })
    };
    assert_eq!(preflight(&regions, &targets, capacity, translation), Ok(3));
    let mut removed = Vec::new();
    unmap(&targets, |address| {
        removed.push(address / BASE_PAGE_SIZE);
        translation(address)
    })
    .unwrap();
    remove_regions(&mut regions, &targets).unwrap();
    assert_eq!(removed, [8, 3, 4]);
    assert_eq!(
        regions
            .iter()
            .map(|r| (r.range.start() / BASE_PAGE_SIZE, r.range.page_count()))
            .collect::<Vec<_>>(),
        [(1, 2), (5, 3), (9, 2), (20, 1)]
    );
    assert_eq!(regions.capacity(), capacity);
}

#[test]
fn alias_outside_target_rejects_before_unmapping() {
    let regions = [region(1, 5)];
    let backing = [physical(2, 1)];
    let target = [Backing {
        range: virtual_range(2, 1),
        physical: &backing,
        writable: true,
    }];
    assert!(
        preflight(&regions, &target, 2, |address| {
            Ok(if address == 5 * BASE_PAGE_SIZE {
                2 * BASE_PAGE_SIZE
            } else {
                address
            })
        })
        .is_err()
    );
}

#[test]
fn mismatched_missing_and_short_backing_reject() {
    let regions = [region(1, 5)];
    for backing in [
        vec![],
        vec![physical(2, 1)],
        vec![physical(2, 3)],
        vec![physical(10, 2)],
    ] {
        let target = [Backing {
            range: virtual_range(2, 2),
            physical: &backing,
            writable: true,
        }];
        assert!(preflight(&regions, &target, 2, identity).is_err());
    }
    let backing = [physical(2, 2)];
    let target = [Backing {
        range: virtual_range(2, 2),
        physical: &backing,
        writable: true,
    }];
    assert!(preflight(&regions, &target, 2, |_| Err(MmuError::InvalidUserContext)).is_err());
}

#[test]
fn duplicated_or_overlapping_physical_extents_reject() {
    let regions = [region(1, 8)];
    for backing in [
        vec![physical(2, 1), physical(2, 1)],
        vec![physical(2, 2), physical(3, 1)],
    ] {
        let pages = backing.iter().map(|range| range.page_count()).sum();
        let targets = [Backing {
            range: virtual_range(2, pages),
            physical: &backing,
            writable: true,
        }];
        assert!(preflight(&regions, &targets, 8, identity).is_err());
    }
    let backing = [physical(2, 1)];
    let targets = [
        Backing {
            range: virtual_range(2, 1),
            physical: &backing,
            writable: true,
        },
        Backing {
            range: virtual_range(4, 1),
            physical: &backing,
            writable: true,
        },
    ];
    assert!(preflight(&regions, &targets, 8, identity).is_err());
}

#[test]
fn virtual_overlap_holes_unsorted_regions_and_permission_mismatch_reject() {
    let backing = [physical(2, 3)];
    let targets = [Backing {
        range: virtual_range(2, 3),
        physical: &backing,
        writable: true,
    }];
    assert!(preflight(&[region(1, 2), region(4, 2)], &targets, 8, identity).is_err());
    assert!(preflight(&[region(4, 2), region(1, 3)], &targets, 8, identity).is_err());
    let mut wrong = region(1, 5);
    wrong.permissions = MappingPermissions::READ_ONLY;
    assert!(preflight(&[wrong], &targets, 8, identity).is_err());
    wrong.permissions = MappingPermissions::READ_EXECUTE;
    assert!(preflight(&[wrong], &targets, 8, identity).is_err());
    let other = [physical(30, 1)];
    let overlapping = [
        targets[0],
        Backing {
            range: virtual_range(3, 1),
            physical: &other,
            writable: true,
        },
    ];
    assert!(preflight(&[region(1, 5)], &overlapping, 8, identity).is_err());
}

#[test]
fn capacity_preflight_happens_before_leaf_reads() {
    let backing = [physical(2, 1)];
    let targets = [Backing {
        range: virtual_range(2, 1),
        physical: &backing,
        writable: true,
    }];
    assert!(preflight(&[region(1, 3)], &targets, 1, |_| panic!("no leaf reads")).is_err());
    assert!(preflight(&[region(1, 3)], &[], 1, |_| panic!("no leaf reads")).is_err());
    assert!(
        preflight(&[region(1, 3)], &[targets[0]; 5], 8, |_| panic!(
            "no leaf reads"
        ))
        .is_err()
    );
}

#[test]
fn complete_and_edge_removals_preserve_remaining_permissions() {
    let backing = [physical(1, 2)];
    for (start, pages) in [(1, 2), (1, 3), (0, 3)] {
        let mut regions = vec![region(start, pages)];
        let targets = [Backing {
            range: virtual_range(1, 2),
            physical: &backing,
            writable: true,
        }];
        preflight(&regions, &targets, regions.capacity(), identity).unwrap();
        remove_regions(&mut regions, &targets).unwrap();
        assert_eq!(regions.len(), usize::from(pages == 3));
        assert!(
            regions
                .iter()
                .all(|r| r.range.page_count() == 1
                    && r.permissions == MappingPermissions::READ_WRITE)
        );
    }
}

#[test]
fn private_startup_requires_exact_read_only_nx_permission() {
    let mut regions = [region(1, 1)];
    regions[0].permissions = MappingPermissions::READ_ONLY;
    let backing = [physical(1, 1)];
    let targets = [Backing {
        range: virtual_range(1, 1),
        physical: &backing,
        writable: false,
    }];
    assert_eq!(preflight(&regions, &targets, 1, identity), Ok(1));
    regions[0].permissions = MappingPermissions::READ_WRITE;
    assert!(preflight(&regions, &targets, 1, identity).is_err());
}

#[test]
fn unmap_failure_stops_at_first_error_without_changing_region_metadata() {
    let mut regions = vec![region(1, 4)];
    let backing = [physical(1, 4)];
    let targets = [Backing {
        range: virtual_range(1, 4),
        physical: &backing,
        writable: true,
    }];
    preflight(&regions, &targets, regions.capacity(), identity).unwrap();
    let mut writes = 0;
    assert!(
        unmap(&targets, |address| {
            writes += 1;
            if writes == 2 {
                Err(MmuError::InvalidUserContext)
            } else {
                Ok(address)
            }
        })
        .is_err()
    );
    assert_eq!(writes, 2);
    assert_eq!(regions[0].range, virtual_range(1, 4));
    // Composition must now stop the native process, retain all physical owners,
    // and tear down the complete root; it must not apply the success summary.
    regions.clear();
}
