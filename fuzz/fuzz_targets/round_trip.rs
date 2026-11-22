//! Lists built from arbitrary input, written in each form and read back.
//!
//! The input is read as entries, three bytes each after a count: a tag, the
//! permissions and an id; then, after a `0xff`, names of any bytes for the
//! named users and groups, separated by `0xff`. Where the entries make a
//! list, checked:
//!
//! - the list is its entries in canonical order, and they make it again;
//! - the binary form decodes to the list, and encodes it to the same bytes;
//! - its text in every spelling, with numeric ids and with the names, parses
//!   and resolves to the list, and where the spelling records ids, it does
//!   with no lookup and preferring the ids;
//! - resolved in part, through a lookup answering some of the names, its text
//!   states the list a translation answering the same ids gives in part, and
//!   where the spelling records ids, the whole list;
//! - the narrowing and the computed mask of its text are the list's;
//! - where the entries make no list, `Acl::new` names a rule they break, and
//!   it displays.

#![no_main]
#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};

use file_acl::text::{self, Names, Prefer, Separator, Spelling, Tags};
use file_acl::xattr;
use file_acl::{Acl, Entry, Invalid, Perm, Qualifier, Tag};
use libfuzzer_sys::fuzz_target;

const SPELLINGS: [Spelling; 8] = [
    Spelling::GNU_TAR,
    Spelling::new(Tags::Short, Separator::Comma, Names::Alone),
    Spelling::new(Tags::Long, Separator::Comma, Names::Alone),
    Spelling::new(Tags::Short, Separator::Newline, Names::Alone),
    Spelling::STAR,
    Spelling::new(Tags::Short, Separator::Comma, Names::WithIds),
    Spelling::new(Tags::Long, Separator::Newline, Names::WithIds),
    Spelling::new(Tags::Short, Separator::Newline, Names::WithIds),
];

const TAGS: [Tag; 6] = [
    Tag::UserObj,
    Tag::User,
    Tag::GroupObj,
    Tag::Group,
    Tag::Mask,
    Tag::Other,
];

/// The entries the input states, and the rest of it.
fn entries(input: &[u8]) -> (Vec<Entry>, &[u8]) {
    let Some((&count, mut rest)) = input.split_first() else {
        return (Vec::new(), input);
    };
    let mut entries = Vec::new();
    for _ in 0..count % 16 {
        let Some(([tag, perm, id], after)) = rest.split_first_chunk::<3>() else {
            break;
        };
        rest = after;
        let tag = TAGS[usize::from(*tag) % TAGS.len()];
        let perm = Perm::from_bits(u16::from(*perm & 7)).expect("three bits");
        // Few ids, so that some repeat.
        entries.push(Entry::new(Qualifier::new(tag, u32::from(*id % 24)), perm));
    }
    (entries, rest)
}

/// Names for the named ids, each distinct among users and among groups.
fn names(acl: &Acl, rest: &[u8]) -> (BTreeMap<u32, Vec<u8>>, BTreeMap<u32, Vec<u8>>) {
    let mut given = rest.split(|&byte| byte == 0xff).skip(1);
    let (mut users, mut groups) = (BTreeMap::new(), BTreeMap::new());
    for entry in acl.entries() {
        let (table, id) = match entry.qualifier {
            Qualifier::User(id) => (&mut users, id),
            Qualifier::Group(id) => (&mut groups, id),
            _ => continue,
        };
        let Some(name) = given.next() else { break };
        if !table.values().any(|taken: &Vec<u8>| taken == name) {
            table.insert(id, name.to_vec());
        }
    }
    (users, groups)
}

fuzz_target!(|input: &[u8]| {
    let (entries, rest) = entries(input);
    let acl = match Acl::new(entries.clone()) {
        Ok(acl) => acl,
        Err(error) => {
            let _ = error.to_string();
            match error {
                Invalid::Missing { tag } => {
                    assert!(entries.iter().all(|e| e.qualifier.tag() != tag))
                }
                Invalid::Repeated { qualifier } => {
                    assert!(entries.iter().filter(|e| e.qualifier == qualifier).count() > 1);
                }
                Invalid::UndefinedId { .. } => {}
                _ => {}
            }
            return;
        }
    };
    let mut sorted = entries;
    sorted.sort_by_key(|entry| entry.qualifier);
    assert_eq!(acl.entries(), sorted);
    assert_eq!(Acl::new(acl.entries().to_vec()).as_ref(), Ok(&acl));

    let value = xattr::encode(&acl);
    assert_eq!(xattr::decode(&value), Ok(Some(acl.clone())));

    let (users, groups) = names(&acl, rest);
    let user_id = |name: &[u8]| {
        users
            .iter()
            .find(|(_, n)| n.as_slice() == name)
            .map(|(id, _)| *id)
    };
    let group_id = |name: &[u8]| {
        groups
            .iter()
            .find(|(_, n)| n.as_slice() == name)
            .map(|(id, _)| *id)
    };
    for spelling in SPELLINGS {
        let numeric = text::write(&acl, spelling);
        let parsed = text::parse(&numeric)
            .expect("written text parses")
            .expect("a list");
        assert_eq!(
            parsed.resolve(|_| None, |_| None, Prefer::Name).as_ref(),
            Ok(&acl)
        );
        assert_eq!(parsed.narrowed(), Ok(acl.narrowed()));
        let computed = parsed
            .with_computed_mask()
            .resolve(|_| None, |_| None, Prefer::Name);
        assert_eq!(
            computed.ok(),
            Acl::with_computed_mask(acl.entries().to_vec()).ok()
        );

        let named = text::write_named(&acl, spelling, |id| users.get(&id), |id| groups.get(&id));
        let shown = String::from_utf8_lossy(&named);
        let parsed = text::parse(&named)
            .unwrap_or_else(|error| panic!("{shown:?}: {error}"))
            .expect("a list");
        assert_eq!(
            parsed.resolve(user_id, group_id, Prefer::Name).as_ref(),
            Ok(&acl),
            "{shown:?}"
        );
        // Some of the names answered: the ids the input's length picks.
        let picked = |id: u32| (id ^ input.len() as u32) % 3 != 0;
        let partial = parsed.resolve_partial(
            |name: &[u8]| user_id(name).filter(|&id| picked(id)),
            |name: &[u8]| group_id(name).filter(|&id| picked(id)),
            Prefer::Name,
        );
        if spelling.names == Names::WithIds {
            let partial = partial.expect("a list");
            assert_eq!((&partial.list, partial.left_out), (&acl, 0), "{shown:?}");
        } else {
            // An id the text spells needs no answer: only the ids whose names
            // were looked up can be left out.
            let (mut user_names, mut group_names) = (BTreeSet::new(), BTreeSet::new());
            let _ = parsed.resolve(
                |name: &[u8]| user_id(name).inspect(|&id| drop(user_names.insert(id))),
                |name: &[u8]| group_id(name).inspect(|&id| drop(group_names.insert(id))),
                Prefer::Name,
            );
            let uid = |id: u32| (!user_names.contains(&id) || picked(id)).then_some(id);
            let gid = |id: u32| (!group_names.contains(&id) || picked(id)).then_some(id);
            assert_eq!(partial, acl.map_ids_partial(uid, gid), "{shown:?}");
        }
        if spelling.names == Names::WithIds {
            assert_eq!(
                parsed.resolve(|_| None, |_| None, Prefer::Name).as_ref(),
                Ok(&acl),
                "{shown:?}"
            );
            assert_eq!(
                parsed
                    .resolve(|_| Some(7), |_| Some(7), Prefer::Id)
                    .as_ref(),
                Ok(&acl),
                "{shown:?}"
            );
        }
    }
});
