//! The model: canonical order, the validity rules, and their agreement with
//! libacl's checker.

mod support;

use file_acl::{Acl, Entry, Invalid, Perm, Qualifier, Tag, UNDEFINED_ID};
use support::{Answer, Oracle, Rng, hex};

const R: Perm = Perm::READ;
const RW: Perm = Perm::READ.union(Perm::WRITE);

fn entry(qualifier: Qualifier, perm: Perm) -> Entry {
    Entry::new(qualifier, perm)
}

/// The owner, the owning group and everyone else, and nothing more.
fn minimal() -> Vec<Entry> {
    vec![
        entry(Qualifier::UserObj, RW),
        entry(Qualifier::GroupObj, R),
        entry(Qualifier::Other, Perm::NONE),
    ]
}

#[test]
fn entries_are_held_in_canonical_order() {
    let given = vec![
        entry(Qualifier::Other, Perm::NONE),
        entry(Qualifier::Group(20), R),
        entry(Qualifier::Mask, RW),
        entry(Qualifier::User(1000), RW),
        entry(Qualifier::GroupObj, R),
        entry(Qualifier::User(5), R),
        entry(Qualifier::Group(3), Perm::ALL),
        entry(Qualifier::UserObj, RW),
    ];
    let acl = Acl::new(given.clone()).unwrap();
    let order: Vec<Qualifier> = acl.entries().iter().map(|e| e.qualifier).collect();
    assert_eq!(
        order,
        [
            Qualifier::UserObj,
            Qualifier::User(5),
            Qualifier::User(1000),
            Qualifier::GroupObj,
            Qualifier::Group(3),
            Qualifier::Group(20),
            Qualifier::Mask,
            Qualifier::Other,
        ]
    );
    // The same entries in another order are the same list.
    let mut reversed = given;
    reversed.reverse();
    assert_eq!(Acl::new(reversed).unwrap(), acl);
    assert_eq!(Acl::new(acl.clone().into_entries()).unwrap(), acl);

    assert_eq!(acl.perm(Qualifier::User(1000)), Some(RW));
    assert_eq!(acl.perm(Qualifier::Group(3)), Some(Perm::ALL));
    assert_eq!(acl.perm(Qualifier::User(6)), None);
    assert_eq!(acl.owner(), RW);
    assert_eq!(acl.owning_group(), R);
    assert_eq!(acl.mask(), Some(RW));
    assert_eq!(acl.other(), Perm::NONE);
    assert!(acl.names_anyone());
}

#[test]
fn a_list_naming_no_one_needs_no_mask_and_may_have_one() {
    let acl = Acl::new(minimal()).unwrap();
    assert_eq!(acl.mask(), None);
    assert_eq!(acl.perm(Qualifier::Mask), None);
    assert!(!acl.names_anyone());

    let mut masked = minimal();
    masked.push(entry(Qualifier::Mask, R));
    let acl = Acl::new(masked).unwrap();
    assert_eq!(acl.mask(), Some(R));
    assert!(!acl.names_anyone());
}

#[test]
fn each_rule_a_list_breaks_is_named() {
    let without = |gone: Qualifier| -> Vec<Entry> {
        minimal()
            .into_iter()
            .filter(|e| e.qualifier != gone)
            .collect()
    };
    let with = |extra: &[Entry]| -> Vec<Entry> {
        let mut entries = minimal();
        entries.extend_from_slice(extra);
        entries
    };
    let missing = |tag| Invalid::Missing { tag };
    let repeated = |qualifier| Invalid::Repeated { qualifier };
    let cases = [
        (Vec::new(), missing(Tag::UserObj)),
        (without(Qualifier::UserObj), missing(Tag::UserObj)),
        (without(Qualifier::GroupObj), missing(Tag::GroupObj)),
        (without(Qualifier::Other), missing(Tag::Other)),
        (with(&[entry(Qualifier::User(5), R)]), missing(Tag::Mask)),
        (with(&[entry(Qualifier::Group(5), R)]), missing(Tag::Mask)),
        (
            with(&[entry(Qualifier::UserObj, R)]),
            repeated(Qualifier::UserObj),
        ),
        (
            with(&[entry(Qualifier::GroupObj, R)]),
            repeated(Qualifier::GroupObj),
        ),
        (
            with(&[entry(Qualifier::Mask, R), entry(Qualifier::Mask, RW)]),
            repeated(Qualifier::Mask),
        ),
        (
            with(&[entry(Qualifier::Other, R)]),
            repeated(Qualifier::Other),
        ),
        (
            with(&[
                entry(Qualifier::User(5), R),
                entry(Qualifier::User(5), RW),
                entry(Qualifier::Mask, RW),
            ]),
            repeated(Qualifier::User(5)),
        ),
        (
            with(&[
                entry(Qualifier::Group(5), R),
                entry(Qualifier::Group(5), R),
                entry(Qualifier::Mask, RW),
            ]),
            repeated(Qualifier::Group(5)),
        ),
        (
            with(&[
                entry(Qualifier::User(UNDEFINED_ID), R),
                entry(Qualifier::Mask, R),
            ]),
            Invalid::UndefinedId { tag: Tag::User },
        ),
        (
            with(&[
                entry(Qualifier::Group(UNDEFINED_ID), R),
                entry(Qualifier::Mask, R),
            ]),
            Invalid::UndefinedId { tag: Tag::Group },
        ),
        // Where several rules are broken, an entry that repeats another is
        // named before a required entry that is missing.
        (
            vec![
                entry(Qualifier::Other, R),
                entry(Qualifier::Other, R),
                entry(Qualifier::GroupObj, R),
            ],
            repeated(Qualifier::Other),
        ),
    ];
    for (entries, expected) in cases {
        assert_eq!(Acl::new(entries.clone()), Err(expected), "{entries:?}");
    }
    // The same user and the same group may both be named.
    assert!(
        Acl::new(with(&[
            entry(Qualifier::User(5), R),
            entry(Qualifier::Group(5), R),
            entry(Qualifier::Mask, R),
        ]))
        .is_ok()
    );
}

#[test]
fn a_broken_rule_says_what_breaks_it() {
    for (invalid, text) in [
        (
            Invalid::Missing { tag: Tag::GroupObj },
            "the list has no owning group entry",
        ),
        (
            Invalid::Missing { tag: Tag::Other },
            "the list has no entry for everyone else",
        ),
        (
            Invalid::Missing { tag: Tag::Mask },
            "the list names a user or group but has no mask entry",
        ),
        (
            Invalid::Repeated {
                qualifier: Qualifier::User(1000),
            },
            "the list names user 1000 twice",
        ),
        (
            Invalid::Repeated {
                qualifier: Qualifier::Mask,
            },
            "the list has more than one mask entry",
        ),
        (
            Invalid::Repeated {
                qualifier: Qualifier::Other,
            },
            "the list has more than one entry for everyone else",
        ),
        (
            Invalid::UndefinedId { tag: Tag::Group },
            "a named group entry carries the undefined id 4294967295",
        ),
    ] {
        assert_eq!(invalid.to_string(), text);
    }
}

#[test]
fn a_perm_holds_read_write_and_execute_and_nothing_else() {
    for bits in 0..=7 {
        assert_eq!(Perm::from_bits(bits).unwrap().bits(), bits);
    }
    for bits in [0o10, 0o17, 0x100, u16::MAX] {
        assert_eq!(Perm::from_bits(bits), None, "{bits:#x}");
    }
    assert_eq!(Perm::NONE.to_string(), "---");
    assert_eq!((Perm::READ | Perm::EXECUTE).to_string(), "r-x");
    assert_eq!(Perm::ALL.to_string(), "rwx");
    assert_eq!(format!("{RW:?}"), "Perm(rw-)");
    assert!(Perm::ALL.contains(RW));
    assert!(!RW.contains(Perm::EXECUTE));
    assert_eq!(Perm::ALL & RW, RW);
    let mut perm = R;
    perm |= Perm::WRITE;
    assert_eq!(perm, RW);
    perm &= Perm::WRITE;
    assert_eq!(perm, Perm::WRITE);
}

#[test]
fn each_tag_has_the_value_the_binary_form_stores() {
    let tags = [
        (Tag::UserObj, 0x01),
        (Tag::User, 0x02),
        (Tag::GroupObj, 0x04),
        (Tag::Group, 0x08),
        (Tag::Mask, 0x10),
        (Tag::Other, 0x20),
    ];
    for (tag, raw) in tags {
        assert_eq!(tag.to_raw(), raw);
        assert_eq!(Tag::from_raw(raw), Some(tag));
        assert_eq!(tag.is_named(), matches!(tag, Tag::User | Tag::Group));
    }
    assert_eq!(
        (0..=u16::MAX)
            .filter(|raw| Tag::from_raw(*raw).is_some())
            .count(),
        tags.len()
    );
    // The order of the tags is the order of their values, and of a list.
    assert!(tags.windows(2).all(|w| w[0].0 < w[1].0 && w[0].1 < w[1].1));
}

#[test]
fn a_qualifier_keeps_an_id_only_where_its_tag_names_someone() {
    for qualifier in [
        Qualifier::UserObj,
        Qualifier::User(7),
        Qualifier::GroupObj,
        Qualifier::Group(7),
        Qualifier::Mask,
        Qualifier::Other,
    ] {
        assert_eq!(Qualifier::new(qualifier.tag(), 7), qualifier);
        assert_eq!(qualifier.id().is_some(), qualifier.tag().is_named());
    }
    assert_eq!(Qualifier::new(Tag::Mask, UNDEFINED_ID), Qualifier::Mask);
    assert!(Qualifier::User(2) < Qualifier::User(10));
    assert!(Qualifier::User(u32::MAX) < Qualifier::GroupObj);
    assert_eq!(Qualifier::Group(100).to_string(), "group 100");
    assert_eq!(Qualifier::GroupObj.to_string(), "owning group");
}

/// The text libacl reads for `entries`, in the order given, with long tags
/// and numeric ids.
fn text(entries: &[Entry]) -> String {
    let fields: Vec<String> = entries
        .iter()
        .map(|e| {
            let (tag, id) = match e.qualifier {
                Qualifier::UserObj => ("user", None),
                Qualifier::User(id) => ("user", Some(id)),
                Qualifier::GroupObj => ("group", None),
                Qualifier::Group(id) => ("group", Some(id)),
                Qualifier::Mask => ("mask", None),
                Qualifier::Other => ("other", None),
            };
            let id = id.map(|id| id.to_string()).unwrap_or_default();
            format!("{tag}:{id}:{}", e.perm)
        })
        .collect();
    fields.join(",")
}

/// Whether a named entry names id 4294967295, which libacl 2.3 reads as a
/// number and its checker refuses, and libacl 2.4 reads only as a name: with
/// no account of that name, libacl 2.4 does not read the text.
fn names_the_undefined_id(entries: &[Entry]) -> bool {
    entries.iter().any(|entry| {
        matches!(
            entry.qualifier,
            Qualifier::User(UNDEFINED_ID) | Qualifier::Group(UNDEFINED_ID)
        )
    })
}

/// libacl's verdict on `text`: `None` where `acl_from_text` does not read it,
/// otherwise `acl_check`'s answer, its error code where it refuses the list.
fn libacl_verdict(oracle: &mut Oracle, text: &str) -> Option<Result<(), u32>> {
    match oracle.ask("check", &[&hex(text.as_bytes())]) {
        Answer::Ok(fields) if fields == ["valid"] => Some(Ok(())),
        Answer::Ok(fields) if fields.len() == 2 && fields[0] == "invalid" => {
            let code = fields[1].trim_start_matches("0x");
            Some(Err(
                u32::from_str_radix(code, 16).expect("a code is hexadecimal")
            ))
        }
        Answer::Err(word) if word == "unread" => None,
        other => panic!("check answered {other:?}"),
    }
}

/// The answers `acl_check` gives for a list with the one fault `invalid`
/// (measured with libacl 2.3): `Missing or wrong entry` for an absent entry,
/// and also for other repeated; `Multiple entries of same type` for the
/// owner, owning group or mask repeated; `Duplicate entries` for a user or
/// group named twice. For a named entry carrying the undefined id it answers
/// either `Duplicate entries` or `Missing or wrong entry`, depending on where
/// the text places the entry, so either is taken.
fn libacl_codes(invalid: Invalid) -> &'static [u32] {
    const MULTI: u32 = 0x1000;
    const DUPLICATE: u32 = 0x2000;
    const MISS: u32 = 0x3000;
    match invalid {
        Invalid::Missing { .. }
        | Invalid::Repeated {
            qualifier: Qualifier::Other,
        } => &[MISS],
        Invalid::Repeated {
            qualifier: Qualifier::User(_) | Qualifier::Group(_),
        } => &[DUPLICATE],
        Invalid::UndefinedId { .. } => &[DUPLICATE, MISS],
        Invalid::Repeated { .. } => &[MULTI],
        _ => unreachable!("no other kind is generated"),
    }
}

/// A valid list of random entries, then at most one fault, the entries in
/// random order: the entries and the rule they break, if any.
fn one_fault(rng: &mut Rng) -> (Vec<Entry>, Option<Invalid>) {
    const IDS: [u32; 6] = [0, 1, 2, 1000, 65534, UNDEFINED_ID - 1];
    let perm = |rng: &mut Rng| Perm::from_bits(rng.below(8) as u16).unwrap();
    let mut entries = vec![
        entry(Qualifier::UserObj, perm(rng)),
        entry(Qualifier::GroupObj, perm(rng)),
        entry(Qualifier::Other, perm(rng)),
    ];
    for named in [Qualifier::User as fn(u32) -> Qualifier, Qualifier::Group] {
        let mut ids: Vec<u32> = (0..rng.below(4)).map(|_| *rng.pick(&IDS)).collect();
        ids.sort_unstable();
        ids.dedup();
        for id in ids {
            entries.push(entry(named(id), perm(rng)));
        }
    }
    let names_anyone = entries.len() > 3;
    if names_anyone || rng.below(2) == 0 {
        entries.push(entry(Qualifier::Mask, perm(rng)));
    }
    let fault = match rng.below(8) {
        0 => {
            let tag = *rng.pick(&[Tag::UserObj, Tag::GroupObj, Tag::Other]);
            entries.retain(|e| e.qualifier.tag() != tag);
            Some(Invalid::Missing { tag })
        }
        1 if names_anyone => {
            entries.retain(|e| e.qualifier != Qualifier::Mask);
            Some(Invalid::Missing { tag: Tag::Mask })
        }
        2 | 3 => {
            let again = *rng.pick(&entries);
            entries.push(entry(again.qualifier, perm(rng)));
            Some(Invalid::Repeated {
                qualifier: again.qualifier,
            })
        }
        4 if names_anyone => {
            let named: Vec<usize> = (0..entries.len())
                .filter(|at| entries[*at].qualifier.tag().is_named())
                .collect();
            let at = *rng.pick(&named);
            let tag = entries[at].qualifier.tag();
            entries[at].qualifier = Qualifier::new(tag, UNDEFINED_ID);
            Some(Invalid::UndefinedId { tag })
        }
        _ => None,
    };
    rng.shuffle(&mut entries);
    (entries, fault)
}

#[test]
fn validity_agrees_with_libacls_checker_on_lists_with_one_fault() {
    let Some(mut oracle) = support::libacl() else {
        return;
    };
    let mut rng = Rng::seeded(1);
    for _ in 0..3000 {
        let (entries, fault) = one_fault(&mut rng);
        let text = text(&entries);
        let ours = Acl::new(entries.clone());
        let context = format!("seed {}, {text}", rng.seed());
        assert_eq!(ours.as_ref().err().copied(), fault, "{context}");
        let Some(theirs) = libacl_verdict(&mut oracle, &text) else {
            assert!(
                names_the_undefined_id(&entries) && ours.is_err(),
                "libacl does not read {context}"
            );
            continue;
        };
        match (ours, theirs) {
            (Ok(_), Ok(())) => {}
            (Err(invalid), Err(code)) => assert!(
                libacl_codes(invalid).contains(&code),
                "{context}: {invalid:?}, libacl {code:#x}"
            ),
            (ours, theirs) => panic!("{context}: ours {ours:?}, libacl {theirs:?}"),
        }
    }
}

#[test]
fn validity_agrees_with_libacls_checker_on_any_entries() {
    let Some(mut oracle) = support::libacl() else {
        return;
    };
    const TAGS: [Tag; 6] = [
        Tag::UserObj,
        Tag::User,
        Tag::GroupObj,
        Tag::Group,
        Tag::Mask,
        Tag::Other,
    ];
    let mut rng = Rng::seeded(2);
    for _ in 0..3000 {
        let entries: Vec<Entry> = (0..rng.below(9))
            .map(|_| {
                let tag = *rng.pick(&TAGS);
                let id = *rng.pick(&[0, 1, 2, UNDEFINED_ID]);
                let perm = Perm::from_bits(rng.below(8) as u16).unwrap();
                entry(Qualifier::new(tag, id), perm)
            })
            .collect();
        let text = text(&entries);
        let context = format!("seed {}, {text:?}", rng.seed());
        let ours = Acl::new(entries.clone()).is_ok();
        let theirs = match libacl_verdict(&mut oracle, &text) {
            Some(verdict) => verdict.is_ok(),
            None if entries.is_empty() || names_the_undefined_id(&entries) => false,
            None => panic!("libacl does not read {context}"),
        };
        assert_eq!(ours, theirs, "{context}");
    }
}
