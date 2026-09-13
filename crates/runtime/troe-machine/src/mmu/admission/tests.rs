#![allow(clippy::unwrap_used, clippy::panic)]

use super::*;
use alloc::{vec, vec::Vec};

fn vr(page: u64, pages: u64) -> VirtualRange {
    VirtualRange::from_pages(page * BASE_PAGE_SIZE, pages).unwrap()
}
fn pr(page: u64, pages: u64) -> PhysicalRange {
    PhysicalRange::from_pages(page * BASE_PAGE_SIZE, pages).unwrap()
}
fn targets(backing: &[PhysicalRange; 4]) -> [Backing<'_>; 4] {
    core::array::from_fn(|index| Backing {
        range: vr([11, 14, 15, 17][index], [2, 1, 2, 1][index]),
        physical: &backing[index..=index],
        writable: index != 3,
    })
}
fn extents() -> [PhysicalRange; 4] {
    [pr(100, 2), pr(200, 1), pr(300, 2), pr(400, 1)]
}
fn missing(_: u64) -> Result<u64, MmuError> {
    Err(MmuError::InvalidUserContext)
}

#[test]
fn admission_maps_fragmented_backing_and_permissions_without_metadata_allocation() {
    let backing = extents();
    let mut mappings = targets(&backing);
    let fragmented = [pr(600, 1), pr(700, 1)];
    mappings[0].physical = &fragmented;
    let mut regions = Vec::with_capacity(4);
    let capacity = regions.capacity();
    assert_eq!(
        preflight(&regions, vr(10, 9), &mappings, pr(1, 2), capacity, missing),
        Ok(6)
    );
    let mut leaves = Vec::new();
    map(&mappings, |address, physical, perms| {
        leaves.push((address, physical, perms));
        Ok(())
    })
    .unwrap();
    assert_eq!(leaves.len(), 6);
    assert_eq!(
        leaves[0],
        (
            11 * BASE_PAGE_SIZE,
            600 * BASE_PAGE_SIZE,
            MappingPermissions::READ_WRITE
        )
    );
    assert_eq!(leaves[1].1, 700 * BASE_PAGE_SIZE);
    assert_eq!(leaves[5].2, MappingPermissions::READ_ONLY);
    add_regions(&mut regions, &mappings).unwrap();
    assert_eq!(regions.capacity(), capacity);
    assert_eq!(regions.len(), 4);
    // Admission's split records are directly consumable by retirement. No
    // external alias or coalescing assumption is needed to remove them again.
    assert_eq!(
        super::super::retirement::preflight(&regions, &mappings, capacity, |address| leaves
            .iter()
            .find(|leaf| leaf.0 == address)
            .map(|leaf| leaf.1)
            .ok_or(MmuError::InvalidUserContext)),
        Ok(6)
    );
    super::super::retirement::remove_regions(&mut regions, &mappings).unwrap();
    assert!(regions.is_empty());
    assert_eq!(regions.capacity(), capacity);
}

#[test]
fn cheap_geometry_backing_and_capacity_errors_do_not_read_leaves() {
    let backing = extents();
    let good = targets(&backing);
    let tables = pr(1, 2);
    let reject = |window, targets: &[Backing<'_>], capacity| {
        assert!(
            preflight(&[], window, targets, tables, capacity, |_| panic!(
                "unexpected leaf read"
            ))
            .is_err()
        );
    };
    reject(vr(10, 9), &good, 3);
    reject(vr(0, 19), &good, 4);
    reject(vr(10, 7), &good, 4);
    reject(vr(10, 9), &good[..3], 4);
    for index in 0..4 {
        let mut bad = good;
        bad[index].physical = &[];
        reject(vr(10, 9), &bad, 4);
    }
    let alias = [backing[0], pr(101, 1), backing[2], backing[3]];
    reject(vr(10, 9), &targets(&alias), 4);
    let table_alias = [backing[0], pr(2, 1), backing[2], backing[3]];
    reject(vr(10, 9), &targets(&table_alias), 4);
    let repeated = [pr(100, 1), pr(100, 1)];
    let mut bad = good;
    bad[0].physical = &repeated;
    reject(vr(10, 9), &bad, 4);
    bad = good;
    bad[1].range = vr(12, 1);
    reject(vr(10, 9), &bad, 4);
}

#[test]
fn every_guard_gap_and_payload_leaf_must_be_absent() {
    let backing = extents();
    let targets = targets(&backing);
    for hidden_page in 10..19 {
        assert!(
            preflight(&[], vr(10, 9), &targets, pr(1, 2), 4, |address| {
                if address == hidden_page * BASE_PAGE_SIZE {
                    Ok(999 * BASE_PAGE_SIZE)
                } else {
                    missing(address)
                }
            })
            .is_err()
        );
        assert!(
            preflight(
                &[UserRegion {
                    range: vr(hidden_page, 1),
                    permissions: MappingPermissions::READ_ONLY
                }],
                vr(10, 9),
                &targets,
                pr(1, 2),
                5,
                |_| panic!("overlap must precede leaf reads")
            )
            .is_err()
        );
    }
    assert!(
        preflight(&[], vr(10, 9), &targets, pr(1, 2), 4, |_| Err(
            MmuError::AddressUnsupported
        ))
        .is_err()
    );
}

#[test]
fn existing_user_aliases_and_broken_region_summaries_fail_before_mapping() {
    let backing = extents();
    let targets = targets(&backing);
    let region = UserRegion {
        range: vr(30, 1),
        permissions: MappingPermissions::READ_ONLY,
    };
    for physical in [100, 101, 200, 300, 301, 400] {
        assert!(
            preflight(&[region], vr(10, 9), &targets, pr(1, 2), 5, |address| {
                if address == 30 * BASE_PAGE_SIZE {
                    Ok(physical * BASE_PAGE_SIZE)
                } else {
                    missing(address)
                }
            })
            .is_err()
        );
    }
    assert!(
        preflight(
            &[region, region],
            vr(10, 9),
            &targets,
            pr(1, 2),
            6,
            |_| panic!("invalid metadata must precede leaf reads")
        )
        .is_err()
    );
    assert!(preflight(&[region], vr(10, 9), &targets, pr(1, 2), 5, missing).is_err());
}

#[test]
fn partial_mapping_stops_at_first_error_and_metadata_failure_never_allocates() {
    let backing = extents();
    let targets = targets(&backing);
    let mut calls = 0;
    assert_eq!(
        map(&targets, |_, _, _| {
            calls += 1;
            if calls == 2 {
                Err(MmuError::TableArenaExhausted)
            } else {
                Ok(())
            }
        }),
        Err(MmuError::TableArenaExhausted)
    );
    assert_eq!(calls, 2);
    let mut regions = vec![];
    assert!(add_regions(&mut regions, &targets).is_err());
    assert_eq!(regions.capacity(), 0);
}
