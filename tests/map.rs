//! Id mapping: `map_ids` against hand-built translations, and compared with
//! the kernel's own translation of a list's ids across a user namespace whose
//! map does not keep the order of ids, in both directions.

mod support;

use std::cell::Cell;
use std::collections::BTreeSet;

use file_acl::xattr::{self, DecodeError};
use file_acl::{Acl, Entry, Invalid, MapError, Perm, Qualifier, Tag, UNDEFINED_ID};
use support::{IdMap, Rng};

fn acl(spec: &[(Qualifier, u16)]) -> Acl {
    Acl::new(
        spec.iter()
            .map(|&(qualifier, bits)| Entry::new(qualifier, Perm::from_bits(bits).unwrap()))
            .collect(),
    )
    .unwrap()
}

/// Users 3 and 5, groups 2 and 7.
fn naming_four() -> Acl {
    acl(&[
        (Qualifier::UserObj, 7),
        (Qualifier::User(3), 4),
        (Qualifier::User(5), 2),
        (Qualifier::GroupObj, 5),
        (Qualifier::Group(2), 1),
        (Qualifier::Group(7), 6),
        (Qualifier::Mask, 7),
        (Qualifier::Other, 0),
    ])
}

#[test]
fn users_are_read_through_one_translation_and_groups_through_the_other() {
    let mapped = naming_four()
        .map_ids(|id| Some(id + 1000), |id| Some(id + 2000))
        .unwrap();
    assert_eq!(
        mapped,
        acl(&[
            (Qualifier::UserObj, 7),
            (Qualifier::User(1003), 4),
            (Qualifier::User(1005), 2),
            (Qualifier::GroupObj, 5),
            (Qualifier::Group(2002), 1),
            (Qualifier::Group(2007), 6),
            (Qualifier::Mask, 7),
            (Qualifier::Other, 0),
        ])
    );
}

#[test]
fn the_result_is_in_canonical_order_whatever_the_translation_does_to_it() {
    let reversed = naming_four()
        .map_ids(|id| Some(100 - id), |id| Some(100 - id))
        .unwrap();
    let qualifiers: Vec<_> = reversed.entries().iter().map(|e| e.qualifier).collect();
    assert_eq!(
        qualifiers,
        [
            Qualifier::UserObj,
            Qualifier::User(95),
            Qualifier::User(97),
            Qualifier::GroupObj,
            Qualifier::Group(93),
            Qualifier::Group(98),
            Qualifier::Mask,
            Qualifier::Other,
        ]
    );
    assert_eq!(reversed.perm(Qualifier::User(97)), Some(Perm::READ));
    // A list naming no one is as it was, the translations never asked.
    let minimal = acl(&[
        (Qualifier::UserObj, 6),
        (Qualifier::GroupObj, 4),
        (Qualifier::Other, 4),
    ]);
    let never = |_: u32| -> Option<u32> { panic!("asked about an id the list does not name") };
    assert_eq!(minimal.map_ids(never, never), Ok(minimal.clone()));
}

#[test]
fn the_first_id_without_an_answer_is_named_and_none_after_it_is_asked() {
    let asked = Cell::new(0);
    let users = |id: u32| {
        asked.set(asked.get() + 1);
        (id != 3).then_some(id)
    };
    let groups = |_: u32| -> Option<u32> { panic!("asked about a group after an unmapped user") };
    assert_eq!(
        naming_four().map_ids(users, groups),
        Err(MapError::Unmapped {
            tag: Tag::User,
            id: 3
        })
    );
    assert_eq!(asked.get(), 1);
    assert_eq!(
        naming_four().map_ids(Some, |id| (id != 7).then_some(id)),
        Err(MapError::Unmapped {
            tag: Tag::Group,
            id: 7
        })
    );
    // Users come before groups.
    assert_eq!(
        naming_four().map_ids(|_| None, |_| None),
        Err(MapError::Unmapped {
            tag: Tag::User,
            id: 3
        })
    );
}

#[test]
fn two_ids_translated_to_one_make_no_list() {
    assert_eq!(
        naming_four().map_ids(|_| Some(9), Some),
        Err(MapError::Invalid(Invalid::Repeated {
            qualifier: Qualifier::User(9)
        }))
    );
    assert_eq!(
        naming_four().map_ids(Some, |id| Some(id.min(2))),
        Err(MapError::Invalid(Invalid::Repeated {
            qualifier: Qualifier::Group(2)
        }))
    );
    // The same id for a user and a group is two entries, and valid: user 3
    // and group 2 both become 9.
    let shared = naming_four()
        .map_ids(|id| Some(id + 6), |id| Some(id + 7))
        .unwrap();
    assert_eq!(shared.perm(Qualifier::User(9)), Some(Perm::READ));
    assert_eq!(shared.perm(Qualifier::Group(9)), Some(Perm::EXECUTE));
    assert_eq!(
        naming_four().map_ids(|id| Some(if id == 5 { UNDEFINED_ID } else { id }), Some),
        Err(MapError::Invalid(Invalid::UndefinedId { tag: Tag::User }))
    );
}

#[test]
fn an_id_without_an_answer_is_left_out_and_every_other_entry_kept() {
    // Users 3 and 5, groups 2 and 7; user 5 has no answer.
    let mut asked = Vec::new();
    let uid = |id: u32| {
        asked.push(id);
        (id == 3).then_some(1003)
    };
    let partial = naming_four()
        .map_ids_partial(uid, |id| Some(id + 2000))
        .unwrap();
    assert_eq!(
        partial.list,
        acl(&[
            (Qualifier::UserObj, 7),
            (Qualifier::User(1003), 4),
            (Qualifier::GroupObj, 5),
            (Qualifier::Group(2002), 1),
            (Qualifier::Group(2007), 6),
            (Qualifier::Mask, 7),
            (Qualifier::Other, 0),
        ])
    );
    assert_eq!(partial.left_out, 1);
    // Every named entry is asked about, past one without an answer.
    assert_eq!(asked, [3, 5]);

    // With every id answered, it is `map_ids`.
    let translate = |id: u32| Some(100 - id);
    let partial = naming_four().map_ids_partial(translate, translate).unwrap();
    assert_eq!(
        Ok(partial.list),
        naming_four().map_ids(translate, translate)
    );
    assert_eq!(partial.left_out, 0);

    // With none, the entries naming no one, the mask among them.
    let partial = naming_four().map_ids_partial(|_| None, |_| None).unwrap();
    assert_eq!(
        partial.list,
        acl(&[
            (Qualifier::UserObj, 7),
            (Qualifier::GroupObj, 5),
            (Qualifier::Mask, 7),
            (Qualifier::Other, 0),
        ])
    );
    assert_eq!(partial.left_out, 4);

    // Two ids translated to one make no list, whatever is left out.
    assert_eq!(
        naming_four().map_ids_partial(|_| Some(9), |_| None),
        Err(Invalid::Repeated {
            qualifier: Qualifier::User(9)
        })
    );
    assert_eq!(
        naming_four().map_ids_partial(|_| None, |_| Some(UNDEFINED_ID)),
        Err(Invalid::UndefinedId { tag: Tag::Group })
    );
}

#[test]
fn leaving_an_entry_out_keeps_a_denial_the_narrowing_loses() {
    // User 1 may not read what everyone else may; user 2 has no answer.
    let acl = acl(&[
        (Qualifier::UserObj, 6),
        (Qualifier::User(1), 0),
        (Qualifier::User(2), 6),
        (Qualifier::GroupObj, 4),
        (Qualifier::Mask, 6),
        (Qualifier::Other, 4),
    ]);
    let partial = acl
        .map_ids_partial(|id| (id == 1).then_some(1), Some)
        .unwrap();
    assert_eq!(partial.list.perm(Qualifier::User(1)), Some(Perm::NONE));
    assert_eq!(partial.list.mask(), Some(Perm::READ | Perm::WRITE));
    // The narrowing leaves user 1 to other's entry, which may read.
    assert_eq!(acl.narrowed().perm(Qualifier::User(1)), None);
    assert_eq!(acl.narrowed().other(), Perm::READ);
}

#[test]
fn each_map_error_says_what_failed() {
    let unmapped = MapError::Unmapped {
        tag: Tag::Group,
        id: 4242,
    };
    assert_eq!(unmapped.to_string(), "group 4242 has no id in the map");
    let repeated = MapError::from(Invalid::Repeated {
        qualifier: Qualifier::User(9),
    });
    assert_eq!(repeated.to_string(), "the list names user 9 twice");
}

/// A valid list naming users from `users` and groups from `groups`.
fn generated(rng: &mut Rng, users: &[u32], groups: &[u32]) -> Acl {
    let perm = |rng: &mut Rng| Perm::from_bits(rng.below(8) as u16).unwrap();
    let mut entries = vec![
        Entry::new(Qualifier::UserObj, perm(rng)),
        Entry::new(Qualifier::GroupObj, perm(rng)),
        Entry::new(Qualifier::Mask, perm(rng)),
        Entry::new(Qualifier::Other, perm(rng)),
    ];
    for &id in users {
        if rng.below(3) == 0 {
            entries.push(Entry::new(Qualifier::User(id), perm(rng)));
        }
    }
    for &id in groups {
        if rng.below(3) == 0 {
            entries.push(Entry::new(Qualifier::Group(id), perm(rng)));
        }
    }
    Acl::new(entries).unwrap()
}

/// Every id `pairs` maps, on the side `side` picks.
fn sides(pairs: &[(u32, u32)], side: fn(&(u32, u32)) -> u32) -> Vec<u32> {
    pairs.iter().map(side).collect()
}

#[test]
fn map_ids_agrees_with_the_kernel_setting_a_list_from_inside_a_namespace() {
    let dir = support::scratch("map-set-inside");
    let Some((mut inside, map)) = support::kernel_across_an_id_map(&dir) else {
        return;
    };
    let Some(mut outside) = support::kernel(&dir) else {
        return;
    };
    let users = sides(&map.users, |pair| pair.0);
    let groups = sides(&map.groups, |pair| pair.0);
    let mut rng = Rng::seeded(21);
    let mut out_of_order = 0;
    for case in 0..500 {
        let list = generated(&mut rng, &users, &groups);
        let context = format!("seed {}, case {case}, {list:?}", rng.seed());
        let path = inside.make(&dir, support::Kind::File);
        inside
            .set(&path, xattr::ACCESS, &xattr::encode(&list))
            .unwrap();
        let held = outside.get(&path, xattr::ACCESS).unwrap();
        let expected = list
            .map_ids(|id| map.user_outside(id), |id| map.group_outside(id))
            .unwrap();
        assert_eq!(
            xattr::decode(&held),
            Ok(Some(expected.clone())),
            "{context}"
        );
        if held != xattr::encode(&expected) {
            out_of_order += 1;
        }
    }
    // The kernel keeps the stored order, which the map does not keep.
    assert!(out_of_order > 0);
}

#[test]
fn map_ids_agrees_with_the_kernel_reading_a_list_inside_a_namespace() {
    let dir = support::scratch("map-read-inside");
    let Some((mut inside, map)) = support::kernel_across_an_id_map(&dir) else {
        return;
    };
    let Some(mut outside) = support::kernel(&dir) else {
        return;
    };
    // The ids the namespace maps, and two beside them it does not.
    let unmapped = |pairs: &[(u32, u32)]| {
        let first = pairs[1].1;
        [first + 30, first + 4242]
    };
    let users = [
        sides(&map.users, |pair| pair.1),
        unmapped(&map.users).to_vec(),
    ]
    .concat();
    let groups = [
        sides(&map.groups, |pair| pair.1),
        unmapped(&map.groups).to_vec(),
    ]
    .concat();
    let mut rng = Rng::seeded(22);
    let mut seen = BTreeSet::new();
    for case in 0..500 {
        let list = generated(&mut rng, &users, &groups);
        let context = format!("seed {}, case {case}, {list:?}", rng.seed());
        let path = outside.make(&dir, support::Kind::File);
        outside
            .set(&path, xattr::ACCESS, &xattr::encode(&list))
            .unwrap();
        let read = xattr::decode(&inside.get(&path, xattr::ACCESS).unwrap());
        let mapped = list.map_ids(|id| map.user_inside(id), |id| map.group_inside(id));
        match (&read, &mapped) {
            (Ok(read), Ok(mapped)) => {
                assert_eq!(read.as_ref(), Some(mapped), "{context}");
                seen.insert("mapped");
            }
            // The kernel reads an id its namespace does not map as the
            // undefined id: the same entry `map_ids` names.
            (
                Err(DecodeError::UnmappedId { entry, tag }),
                Err(MapError::Unmapped { tag: t, id }),
            ) => {
                assert_eq!(tag, t, "{context}");
                let named = list
                    .entries()
                    .iter()
                    .position(|e| e.qualifier == Qualifier::new(*t, *id));
                assert_eq!(named, Some(*entry), "{context}");
                seen.insert(if *tag == Tag::User { "user" } else { "group" });
            }
            _ => panic!("the kernel's reading {read:?}, map_ids {mapped:?}: {context}"),
        }
    }
    assert_eq!(seen, BTreeSet::from(["group", "mapped", "user"]));
}

#[test]
fn the_map_holds_ids_out_of_order() {
    // So that the comparisons above reach the kernel's keeping the stored
    // order: inside 20 to 22 are outside in descending order.
    let dir = support::scratch("map-shape");
    let Some((_, map)) = support::kernel_across_an_id_map(&dir) else {
        return;
    };
    let check = |pairs: &[(u32, u32)]| {
        let outside: Vec<u32> = [20, 21, 22]
            .iter()
            .map(|inner| pairs.iter().find(|p| p.0 == *inner).unwrap().1)
            .collect();
        assert!(outside[0] > outside[1] && outside[1] > outside[2]);
    };
    check(&map.users);
    check(&map.groups);
    let _: &IdMap = &map;
}
