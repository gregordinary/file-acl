//! The mode rules: `mode::set` compared with the kernel on every kind of file,
//! on the scratch directory's filesystem and on a tmpfs; `with_mode` compared
//! with what `chmod` does to a stored list; the narrowing compared with the
//! kernel's access checks; and the mode bits, `from_mode` and the computed
//! mask compared with libacl.

mod support;

use std::collections::BTreeSet;
use std::path::Path;

use file_acl::mode::{self, FileKind, ListKind, Set, SetError};
use file_acl::{Acl, Entry, Invalid, Perm, Qualifier, UNDEFINED_ID, xattr};
use support::{Answer, Kind, Oracle, Reference, Rng, hex, unhex};

fn perm(bits: u16) -> Perm {
    Perm::from_bits(bits).expect("three bits at most")
}

fn entries(spec: &[(Qualifier, u16)]) -> Vec<Entry> {
    spec.iter()
        .map(|&(qualifier, bits)| Entry::new(qualifier, perm(bits)))
        .collect()
}

fn acl(spec: &[(Qualifier, u16)]) -> Acl {
    Acl::new(entries(spec)).expect("a valid list")
}

fn minimal(owner: u16, owning_group: u16, other: u16) -> Acl {
    acl(&[
        (Qualifier::UserObj, owner),
        (Qualifier::GroupObj, owning_group),
        (Qualifier::Other, other),
    ])
}

/// `entries` as libacl's long text form, numeric ids, one entry per line.
fn text(entries: &[Entry]) -> String {
    entries
        .iter()
        .map(|entry| {
            let who = match entry.qualifier {
                Qualifier::UserObj => "user:".to_owned(),
                Qualifier::User(id) => format!("user:{id}"),
                Qualifier::GroupObj => "group:".to_owned(),
                Qualifier::Group(id) => format!("group:{id}"),
                Qualifier::Mask => "mask:".to_owned(),
                Qualifier::Other => "other:".to_owned(),
            };
            format!("{who}:{}\n", entry.perm)
        })
        .collect()
}

/// A valid list naming users from `users` and groups from `groups`, with a
/// mask where it names anyone and at random otherwise.
fn generated(rng: &mut Rng, users: &[u32], groups: &[u32]) -> Acl {
    let perm = |rng: &mut Rng| perm(rng.below(8) as u16);
    let mut list = vec![
        Entry::new(Qualifier::UserObj, perm(rng)),
        Entry::new(Qualifier::GroupObj, perm(rng)),
        Entry::new(Qualifier::Other, perm(rng)),
    ];
    let mut named = false;
    for &id in users {
        if rng.below(3) == 0 {
            list.push(Entry::new(Qualifier::User(id), perm(rng)));
            named = true;
        }
    }
    for &id in groups {
        if rng.below(3) == 0 {
            list.push(Entry::new(Qualifier::Group(id), perm(rng)));
            named = true;
        }
    }
    if named || rng.below(3) == 0 {
        list.push(Entry::new(Qualifier::Mask, perm(rng)));
    }
    rng.shuffle(&mut list);
    Acl::new(list).expect("generated lists are valid")
}

#[test]
fn the_group_bits_are_the_masks_where_the_list_has_one() {
    let named = acl(&[
        (Qualifier::UserObj, 6),
        (Qualifier::User(1000), 4),
        (Qualifier::GroupObj, 4),
        (Qualifier::Mask, 6),
        (Qualifier::Other, 4),
    ]);
    assert_eq!(named.mode_bits(), 0o664);
    assert_eq!(minimal(7, 5, 0).mode_bits(), 0o750);
    let masked = acl(&[
        (Qualifier::UserObj, 7),
        (Qualifier::GroupObj, 7),
        (Qualifier::Mask, 1),
        (Qualifier::Other, 0),
    ]);
    assert_eq!(masked.mode_bits(), 0o710);
}

#[test]
fn only_a_list_with_no_mask_and_no_named_entry_is_minimal() {
    assert!(minimal(6, 4, 4).is_minimal());
    let masked = acl(&[
        (Qualifier::UserObj, 6),
        (Qualifier::GroupObj, 4),
        (Qualifier::Mask, 4),
        (Qualifier::Other, 4),
    ]);
    assert!(!masked.is_minimal());
    let named = acl(&[
        (Qualifier::UserObj, 6),
        (Qualifier::Group(27), 4),
        (Qualifier::GroupObj, 4),
        (Qualifier::Mask, 4),
        (Qualifier::Other, 4),
    ]);
    assert!(!named.is_minimal());
}

#[test]
fn a_mode_is_the_minimal_list_of_its_permission_bits() {
    assert_eq!(Acl::from_mode(0o754), minimal(7, 5, 4));
    assert_eq!(Acl::from_mode(0o177_754), minimal(7, 5, 4));
    assert_eq!(Acl::from_mode(0), minimal(0, 0, 0));
    for mode in 0..=0o777 {
        assert_eq!(Acl::from_mode(mode).mode_bits(), mode);
    }
}

#[test]
fn a_new_mode_replaces_the_owner_the_mask_and_other() {
    let list = acl(&[
        (Qualifier::UserObj, 6),
        (Qualifier::User(1000), 7),
        (Qualifier::GroupObj, 4),
        (Qualifier::Group(27), 2),
        (Qualifier::Mask, 7),
        (Qualifier::Other, 1),
    ]);
    let chmodded = list.with_mode(0o4751);
    assert_eq!(
        chmodded,
        acl(&[
            (Qualifier::UserObj, 7),
            (Qualifier::User(1000), 7),
            (Qualifier::GroupObj, 4),
            (Qualifier::Group(27), 2),
            (Qualifier::Mask, 5),
            (Qualifier::Other, 1),
        ])
    );
    assert_eq!(chmodded.mode_bits(), 0o751);
    // Without a mask, the owning group takes the group bits.
    for mode in [0, 0o640, 0o7777] {
        assert_eq!(minimal(7, 7, 7).with_mode(mode), Acl::from_mode(mode));
    }
}

#[test]
fn a_narrowed_list_gives_the_owning_group_what_the_mask_left_it() {
    // `group::---,mask::rw-` shows as group `rw-` in the mode, which is the
    // mask, not the group. Laid down without the list, the mode alone would
    // give the owning group `rw-`; narrowed, it keeps `---`.
    let list = acl(&[
        (Qualifier::UserObj, 6),
        (Qualifier::User(1000), 6),
        (Qualifier::GroupObj, 0),
        (Qualifier::Mask, 6),
        (Qualifier::Other, 0),
    ]);
    let set = |list: &Acl| {
        mode::set(
            0o4000,
            FileKind::Other,
            ListKind::Access,
            Some(list.clone()),
        )
    };
    assert_eq!(
        set(&list).unwrap().mode,
        0o4660,
        "the full list shows its mask"
    );
    let narrowed = list.narrowed();
    assert_eq!(narrowed, minimal(6, 0, 0));
    assert_eq!(set(&narrowed).unwrap().mode, 0o4600);
    // An owning group the mask allows more than keeps its own.
    let wider_mask = acl(&[
        (Qualifier::UserObj, 7),
        (Qualifier::GroupObj, 5),
        (Qualifier::Mask, 7),
        (Qualifier::Other, 5),
    ]);
    assert_eq!(wider_mask.narrowed().mode_bits(), 0o755);
    // A minimal list is its own narrowing.
    assert_eq!(minimal(5, 3, 1).narrowed(), minimal(5, 3, 1));
}

#[test]
fn a_stored_access_list_sets_the_modes_permission_bits() {
    // u::rw-,u:1000:r--,g::r--,m::rw-,o::r-- on a 0644 file leaves it 0664:
    // the group bits are the mask's. Set-user-ID survives.
    let list = acl(&[
        (Qualifier::UserObj, 6),
        (Qualifier::User(1000), 4),
        (Qualifier::GroupObj, 4),
        (Qualifier::Mask, 6),
        (Qualifier::Other, 4),
    ]);
    let set = mode::set(
        0o4644,
        FileKind::Other,
        ListKind::Access,
        Some(list.clone()),
    );
    assert_eq!(
        set,
        Ok(Set {
            mode: 0o4664,
            list: Some(list)
        })
    );
}

#[test]
fn a_minimal_access_list_is_not_stored_and_its_bits_become_the_mode() {
    let set = mode::set(
        0o1777,
        FileKind::Directory,
        ListKind::Access,
        Some(minimal(7, 5, 0)),
    );
    assert_eq!(
        set,
        Ok(Set {
            mode: 0o1750,
            list: None
        })
    );
    // The file type bits of a full `st_mode` are kept with the others.
    let set = mode::set(
        0o100_644,
        FileKind::Other,
        ListKind::Access,
        Some(minimal(6, 0, 0)),
    );
    assert_eq!(set.map(|set| set.mode), Ok(0o100_600));
}

#[test]
fn a_value_stating_no_list_is_not_stored_and_leaves_the_mode() {
    let none = xattr::decode(&2u32.to_le_bytes()).expect("a header alone");
    assert_eq!(none, None);
    for (file_kind, kind) in [
        (FileKind::Other, ListKind::Access),
        (FileKind::Other, ListKind::Default),
        (FileKind::Directory, ListKind::Access),
        (FileKind::Directory, ListKind::Default),
        (FileKind::SymbolicLink, ListKind::Access),
        (FileKind::SymbolicLink, ListKind::Default),
    ] {
        assert_eq!(
            mode::set(0o640, file_kind, kind, none.clone()),
            Ok(Set {
                mode: 0o640,
                list: None
            }),
            "{file_kind:?} {kind:?}"
        );
    }
}

#[test]
fn a_default_list_is_kept_on_a_directory_minimal_or_not() {
    // A minimal default list is stored, unlike an access list, and says
    // nothing about the directory's own mode.
    let default = minimal(7, 5, 5);
    let set = mode::set(
        0o700,
        FileKind::Directory,
        ListKind::Default,
        Some(default.clone()),
    );
    assert_eq!(
        set,
        Ok(Set {
            mode: 0o700,
            list: Some(default.clone())
        })
    );
    assert_eq!(
        mode::set(0o644, FileKind::Other, ListKind::Default, Some(default)),
        Err(SetError::NotADirectory)
    );
}

#[test]
fn no_list_is_held_by_a_symbolic_link() {
    for kind in [ListKind::Access, ListKind::Default] {
        assert_eq!(
            mode::set(0o777, FileKind::SymbolicLink, kind, Some(minimal(7, 7, 7))),
            Err(SetError::SymbolicLink)
        );
    }
}

/// A list of the owner, `named` named users from id 1, the owning group, a
/// mask and other: its value is `4 + 8 * (named + 4)` bytes long.
fn long_list(named: u32) -> Acl {
    let mut list = entries(&[
        (Qualifier::UserObj, 7),
        (Qualifier::GroupObj, 4),
        (Qualifier::Mask, 4),
        (Qualifier::Other, 0),
    ]);
    list.extend((1..=named).map(|id| Entry::new(Qualifier::User(id), perm(4))));
    Acl::new(list).unwrap()
}

/// Every kind of file, with every kind of list.
const EVERY_SETTING: [(FileKind, ListKind); 6] = [
    (FileKind::Directory, ListKind::Access),
    (FileKind::Directory, ListKind::Default),
    (FileKind::SymbolicLink, ListKind::Access),
    (FileKind::SymbolicLink, ListKind::Default),
    (FileKind::Other, ListKind::Access),
    (FileKind::Other, ListKind::Default),
];

#[test]
fn a_list_longer_than_the_kernel_takes_is_refused_on_any_file() {
    // 8,191 entries, 65,532 bytes: the most the kernel takes.
    let longest = long_list(8187);
    assert_eq!(xattr::encode(&longest).len(), 65_532);
    for (file_kind, kind) in EVERY_SETTING {
        let set = mode::set(0o640, file_kind, kind, Some(longest.clone()));
        assert!(
            !matches!(set, Err(SetError::TooLong)),
            "{file_kind:?} {kind:?}"
        );
    }
    // One entry more, 65,540 bytes, before any other refusal.
    let longer = long_list(8188);
    for (file_kind, kind) in EVERY_SETTING {
        assert_eq!(
            mode::set(0o640, file_kind, kind, Some(longer.clone())),
            Err(SetError::TooLong),
            "{file_kind:?} {kind:?}"
        );
        assert_eq!(
            mode::set(0o640, file_kind, kind, None),
            Ok(Set {
                mode: 0o640,
                list: None
            })
        );
    }
}

/// Sets the longest list the kernel takes, and one entry more, on each
/// kind of file with each kind of list: the kernel refuses the longer with
/// `E2BIG` wherever `set` says `TooLong`, changing nothing, and where it
/// takes the longest, leaves what `set` says, unless the filesystem has no
/// room for it (`ENOSPC`, as on ext4). Whether a list was stored.
fn length_agrees_with(mut oracle: Oracle, dir: &Path) -> bool {
    let mut stored = false;
    for named in [8187, 8188] {
        let list = long_list(named);
        let value = xattr::encode(&list);
        for (file_kind, kind) in EVERY_SETTING {
            let path = oracle.make(
                dir,
                match file_kind {
                    FileKind::Directory => Kind::Directory,
                    FileKind::SymbolicLink => Kind::Symlink,
                    FileKind::Other => Kind::File,
                },
            );
            let name = match kind {
                ListKind::Access => xattr::ACCESS,
                ListKind::Default => xattr::DEFAULT,
            };
            let before = oracle.mode(&path);
            let expected = mode::set(before, file_kind, kind, Some(list.clone()));
            let kernel = oracle.set(&path, name, &value);
            let context =
                format!("{named} named, {file_kind:?} {kind:?}: {expected:?}, {kernel:?}");
            match (&expected, &kernel) {
                (Err(SetError::TooLong), Err(errno)) => {
                    assert_eq!(errno, "E2BIG", "{context}");
                    assert_eq!(oracle.mode(&path), before, "{context}");
                    assert_eq!(held(&mut oracle, &path, name), None, "{context}");
                }
                (Ok(set), Ok(())) => {
                    assert_eq!(oracle.mode(&path), set.mode, "{context}");
                    let encoded = set.list.as_ref().map(xattr::encode);
                    assert_eq!(held(&mut oracle, &path, name), encoded, "{context}");
                    stored = true;
                }
                (Ok(_), Err(errno)) if errno == "ENOSPC" => {}
                (Err(SetError::NotADirectory), Err(errno)) => {
                    assert_eq!(errno, "EACCES", "{context}")
                }
                (Err(SetError::SymbolicLink), Err(errno)) => {
                    assert!(matches!(&**errno, "EOPNOTSUPP" | "ENOTSUP"), "{context}");
                }
                _ => panic!("{context}: they disagree"),
            }
        }
    }
    stored
}

#[test]
fn the_length_set_takes_agrees_with_the_kernel_on_the_scratch_filesystem() {
    let dir = support::scratch("mode-length-kernel");
    let Some(oracle) = support::kernel(&dir) else {
        return;
    };
    length_agrees_with(oracle, &dir);
}

#[test]
fn the_length_set_takes_agrees_with_the_kernel_on_tmpfs() {
    let dir = support::scratch("mode-length-tmpfs");
    let Some(oracle) = support::kernel_on_tmpfs(&dir) else {
        return;
    };
    // A tmpfs has room for the longest list the kernel takes.
    assert!(length_agrees_with(oracle, &dir));
}

#[test]
fn each_set_error_says_what_was_refused() {
    assert_eq!(
        SetError::TooLong.to_string(),
        "the list has more than 8191 entries, more than an extended attribute holds"
    );
    assert_eq!(
        SetError::NotADirectory.to_string(),
        "a default list is set on a file that is not a directory"
    );
    assert_eq!(
        SetError::SymbolicLink.to_string(),
        "a list is set on a symbolic link"
    );
}

/// `setfacl`'s answers, as `getfacl` read them back after each step
/// (measured with acl 2.3.2 on Linux 7.2.15).
#[test]
fn the_computed_mask_is_the_one_setfacl_computes() {
    // `--set u::rw,g::r,o::-`: no mask is added to a list naming no one.
    let set = Acl::with_computed_mask(entries(&[
        (Qualifier::UserObj, 6),
        (Qualifier::GroupObj, 4),
        (Qualifier::Other, 0),
    ]));
    assert_eq!(set, Ok(minimal(6, 4, 0)));
    // `--set u::rw,u:1000:r,g::x,o::-`: the mask is the group class's union.
    let set = Acl::with_computed_mask(entries(&[
        (Qualifier::UserObj, 6),
        (Qualifier::User(1000), 4),
        (Qualifier::GroupObj, 1),
        (Qualifier::Other, 0),
    ]));
    assert_eq!(set.unwrap().mask(), Some(perm(5)));
    // `-m u:1001:w` over `u::rw-,g::--x,m::r--,o::---`: the mask given
    // before is replaced.
    let set = Acl::with_computed_mask(entries(&[
        (Qualifier::UserObj, 6),
        (Qualifier::User(1001), 2),
        (Qualifier::GroupObj, 1),
        (Qualifier::Mask, 4),
        (Qualifier::Other, 0),
    ]));
    assert_eq!(set.unwrap().mask(), Some(perm(3)));
    // `-x u:1001,u:1002` over a list holding a mask: the mask stays,
    // recomputed from the owning group alone.
    let set = Acl::with_computed_mask(entries(&[
        (Qualifier::UserObj, 6),
        (Qualifier::GroupObj, 1),
        (Qualifier::Mask, 4),
        (Qualifier::Other, 0),
    ]));
    assert_eq!(set.unwrap().mask(), Some(perm(1)));
    // The owner and other have no part in it.
    let set = Acl::with_computed_mask(entries(&[
        (Qualifier::UserObj, 7),
        (Qualifier::Group(27), 2),
        (Qualifier::GroupObj, 0),
        (Qualifier::Other, 7),
    ]));
    assert_eq!(set.unwrap().mask(), Some(perm(2)));
}

#[test]
fn computing_the_mask_refuses_what_new_refuses() {
    let repeated_mask = entries(&[
        (Qualifier::UserObj, 6),
        (Qualifier::GroupObj, 4),
        (Qualifier::Mask, 4),
        (Qualifier::Mask, 6),
        (Qualifier::Other, 0),
    ]);
    assert_eq!(
        Acl::with_computed_mask(repeated_mask),
        Err(Invalid::Repeated {
            qualifier: Qualifier::Mask
        })
    );
    let no_other = entries(&[
        (Qualifier::UserObj, 6),
        (Qualifier::User(1000), 4),
        (Qualifier::GroupObj, 4),
    ]);
    assert_eq!(
        Acl::with_computed_mask(no_other),
        Err(Invalid::Missing {
            tag: file_acl::Tag::Other
        })
    );
    let undefined = entries(&[
        (Qualifier::UserObj, 6),
        (Qualifier::User(UNDEFINED_ID), 4),
        (Qualifier::GroupObj, 4),
        (Qualifier::Other, 0),
    ]);
    assert_eq!(
        Acl::with_computed_mask(undefined),
        Err(Invalid::UndefinedId {
            tag: file_acl::Tag::User
        })
    );
}

/// Ids the comparisons name, which a namespace with the default subordinate
/// range maps.
const USERS: [u32; 4] = [0, 1, 1000, 65534];
const GROUPS: [u32; 4] = [0, 2, 27, 1001];

#[test]
fn the_mode_bits_and_minimality_agree_with_libacl() {
    let Some(mut oracle) = support::libacl() else {
        return;
    };
    let mut rng = Rng::seeded(11);
    let mut seen = BTreeSet::new();
    for case in 0..2000 {
        let list = generated(&mut rng, &USERS, &GROUPS);
        let context = format!("seed {}, case {case}, {}", rng.seed(), text(list.entries()));
        let answer = oracle.ask("equivmode", &[&hex(text(list.entries()).as_bytes())]);
        let Answer::Ok(fields) = answer else {
            panic!("libacl read no list: {answer:?}, {context}");
        };
        let equivalent = fields[0] == "0";
        let bits = u32::from_str_radix(&fields[1], 8).unwrap();
        assert_eq!(list.is_minimal(), equivalent, "{context}");
        assert_eq!(list.mode_bits(), bits, "{context}");
        seen.insert((equivalent, list.mask().is_some(), list.names_anyone()));
    }
    // Minimal lists, lists with a mask alone, and lists naming someone.
    assert_eq!(
        seen,
        BTreeSet::from([
            (true, false, false),
            (false, true, false),
            (false, true, true)
        ])
    );
}

#[test]
fn from_mode_agrees_with_libacl_for_every_mode() {
    let Some(mut oracle) = support::libacl() else {
        return;
    };
    for mode in 0..=0o7777 {
        let answer = oracle.ask("frommode", &[&format!("{mode:o}")]);
        let Answer::Ok(fields) = answer else {
            panic!("acl_from_mode({mode:o}) answered {answer:?}");
        };
        let libacl = xattr::decode(&unhex(&fields[0])).unwrap();
        assert_eq!(libacl, Some(Acl::from_mode(mode)), "mode {mode:o}");
    }
}

#[test]
fn the_computed_mask_agrees_with_libacl_but_where_no_one_is_named() {
    let Some(mut oracle) = support::libacl() else {
        return;
    };
    let mut rng = Rng::seeded(12);
    let mut seen = BTreeSet::new();
    for case in 0..2000 {
        let mut list = generated(&mut rng, &USERS, &GROUPS).into_entries();
        // The mask dropped, kept, or given another value: the computed one
        // does not depend on it.
        match rng.below(3) {
            0 => list.retain(|entry| entry.qualifier != Qualifier::Mask),
            1 => {
                for entry in &mut list {
                    if entry.qualifier == Qualifier::Mask {
                        entry.perm = perm(rng.below(8) as u16);
                    }
                }
            }
            _ => {}
        }
        let context = format!("seed {}, case {case}, {}", rng.seed(), text(&list));
        let computed = Acl::with_computed_mask(list.clone()).expect("valid but for the mask");
        let answer = oracle.ask("calcmask", &[&hex(text(&list).as_bytes())]);
        let Answer::Ok(fields) = answer else {
            panic!("libacl read no list: {answer:?}, {context}");
        };
        let libacl = xattr::decode(&unhex(&fields[0])).unwrap().unwrap();
        let named = list.iter().any(|entry| entry.qualifier.id().is_some());
        let held = list.iter().any(|entry| entry.qualifier == Qualifier::Mask);
        if named || held {
            assert_eq!(computed, libacl, "{context}");
        } else {
            // The stated difference: libacl adds a mask equal to the owning
            // group's entry, which `setfacl` does not.
            assert!(computed.is_minimal(), "{context}");
            let mut masked = computed.clone().into_entries();
            masked.push(Entry::new(Qualifier::Mask, computed.owning_group()));
            assert_eq!(libacl, Acl::new(masked).unwrap(), "{context}");
        }
        seen.insert((named, held));
    }
    assert_eq!(
        seen.len(),
        4,
        "every combination of named entries and a mask"
    );
}

/// How the kernel answered a list set on a file, and how `set` did.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
enum Outcome {
    /// No list: none held, the mode as it was.
    NoList,
    /// A minimal access list: none held, the mode its bits.
    Minimal,
    /// A list held.
    Held,
    /// Refused, with this error.
    Refused(&'static str),
}

/// What `make` makes, as `set` is told of it.
fn file_kind(kind: Kind) -> FileKind {
    match kind {
        Kind::Directory => FileKind::Directory,
        Kind::Symlink => FileKind::SymbolicLink,
        Kind::File | Kind::Fifo | Kind::Socket | Kind::CharDevice => FileKind::Other,
    }
}

/// The list `path` holds as `name`, `None` where it holds none. A symbolic
/// link answers `EOPNOTSUPP` where another file answers `ENODATA`.
fn held(oracle: &mut Oracle, path: &str, name: &str) -> Option<Vec<u8>> {
    match oracle.get(path, name) {
        Ok(value) => Some(value),
        Err(errno) if matches!(&*errno, "ENODATA" | "EOPNOTSUPP" | "ENOTSUP") => None,
        Err(errno) => panic!("reading {name} failed: {errno}"),
    }
}

/// Sets generated lists, or none, on new files of every kind that may hold
/// lists already, and compares what the kernel leaves with what `set` says:
/// the mode, the list held, and the other list untouched; or the refusal,
/// with nothing changed.
///
/// The kinds include a character device where the kernel lets the caller
/// make one numbered 0:0; `reference` is reported missing where it does not.
fn set_agrees_with(
    mut oracle: Oracle,
    reference: Reference,
    dir: &Path,
    users: &[u32],
    groups: &[u32],
    seed: u64,
) {
    let mut rng = Rng::seeded(seed);
    let mut seen = BTreeSet::new();
    let mut kinds = vec![
        Kind::File,
        Kind::Directory,
        Kind::Fifo,
        Kind::Socket,
        Kind::Symlink,
    ];
    match oracle.try_make(dir, Kind::CharDevice) {
        Ok(_) => kinds.push(Kind::CharDevice),
        Err(errno) => reference.missing(&format!(
            "a character device numbered 0:0 cannot be made ({errno}), so none is compared"
        )),
    }
    let mut made = Vec::new();
    for case in 0..1500 {
        let kind = *rng.pick(&kinds);
        if !made.contains(&kind) {
            made.push(kind);
        }
        let path = oracle.make(dir, kind);
        if kind != Kind::Symlink {
            oracle.chmod(&path, rng.below(0o10000) as u32).unwrap();
            // Lists the file holds already, which the new one replaces or
            // which stay beside it.
            if rng.below(2) == 0 {
                let list = generated(&mut rng, users, groups);
                oracle
                    .set(&path, xattr::ACCESS, &xattr::encode(&list))
                    .unwrap();
            }
            if kind == Kind::Directory && rng.below(2) == 0 {
                let list = generated(&mut rng, users, groups);
                oracle
                    .set(&path, xattr::DEFAULT, &xattr::encode(&list))
                    .unwrap();
            }
        }
        let kind_of_list = *rng.pick(&[ListKind::Access, ListKind::Default]);
        let (name, other) = match kind_of_list {
            ListKind::Access => (xattr::ACCESS, xattr::DEFAULT),
            ListKind::Default => (xattr::DEFAULT, xattr::ACCESS),
        };
        let (list, value) = match rng.below(4) {
            0 => (
                None,
                if rng.below(2) == 0 {
                    vec![]
                } else {
                    2u32.to_le_bytes().to_vec()
                },
            ),
            1 => {
                let list = Acl::from_mode(rng.below(0o1000) as u32);
                let value = xattr::encode(&list);
                (Some(list), value)
            }
            _ => {
                let list = generated(&mut rng, users, groups);
                let value = xattr::encode(&list);
                (Some(list), value)
            }
        };
        let before = oracle.mode(&path);
        let other_before = held(&mut oracle, &path, other);
        let context = format!(
            "seed {}, case {case}: {kind:?} mode {before:o}, {name} {}",
            rng.seed(),
            hex(&value)
        );
        let expected = mode::set(before, file_kind(kind), kind_of_list, list.clone());
        let kernel = oracle.set(&path, name, &value);
        let outcome = match (&expected, &kernel) {
            (Ok(set), Ok(())) => {
                assert_eq!(oracle.mode(&path), set.mode, "{context}");
                let encoded = set.list.as_ref().map(xattr::encode);
                assert_eq!(held(&mut oracle, &path, name), encoded, "{context}");
                match (&set.list, &list) {
                    (Some(_), _) => Outcome::Held,
                    (None, Some(_)) => Outcome::Minimal,
                    (None, None) => Outcome::NoList,
                }
            }
            (Err(SetError::NotADirectory), Err(errno)) => {
                assert_eq!(errno, "EACCES", "{context}");
                assert_eq!(oracle.mode(&path), before, "{context}");
                Outcome::Refused("NotADirectory")
            }
            (Err(SetError::SymbolicLink), Err(errno)) => {
                assert!(matches!(&**errno, "EOPNOTSUPP" | "ENOTSUP"), "{context}");
                Outcome::Refused("SymbolicLink")
            }
            // The kernel refuses even the empty value that sets no list on a
            // symbolic link, which then holds none, as `set` says.
            (Ok(set), Err(errno)) if kind == Kind::Symlink && list.is_none() => {
                assert!(matches!(&**errno, "EOPNOTSUPP" | "ENOTSUP"), "{context}");
                assert_eq!(set.list, None, "{context}");
                assert_eq!(oracle.mode(&path), set.mode, "{context}");
                assert_eq!(held(&mut oracle, &path, name), None, "{context}");
                Outcome::NoList
            }
            _ => panic!("set answered {expected:?} and the kernel {kernel:?}, {context}"),
        };
        assert_eq!(held(&mut oracle, &path, other), other_before, "{context}");
        seen.insert((file_kind(kind) as u8, kind_of_list as u8, outcome));
    }
    for kind in &kinds {
        assert!(made.contains(kind), "no {kind:?} was made");
    }
    let mut expected = BTreeSet::new();
    for kind in [FileKind::Directory, FileKind::Other] {
        for outcome in [Outcome::NoList, Outcome::Minimal, Outcome::Held] {
            expected.insert((kind as u8, ListKind::Access as u8, outcome));
        }
    }
    expected.insert((
        FileKind::Directory as u8,
        ListKind::Default as u8,
        Outcome::NoList,
    ));
    expected.insert((
        FileKind::Directory as u8,
        ListKind::Default as u8,
        Outcome::Held,
    ));
    expected.insert((
        FileKind::Other as u8,
        ListKind::Default as u8,
        Outcome::NoList,
    ));
    expected.insert((
        FileKind::Other as u8,
        ListKind::Default as u8,
        Outcome::Refused("NotADirectory"),
    ));
    for kind in [ListKind::Access, ListKind::Default] {
        expected.insert((FileKind::SymbolicLink as u8, kind as u8, Outcome::NoList));
        expected.insert((
            FileKind::SymbolicLink as u8,
            kind as u8,
            Outcome::Refused("SymbolicLink"),
        ));
    }
    assert_eq!(seen, expected);
}

#[test]
fn set_agrees_with_the_kernel_on_the_scratch_filesystem() {
    let dir = support::scratch("mode-set-kernel");
    let _discard = support::Discard(&dir);
    let Some(oracle) = support::kernel(&dir) else {
        return;
    };
    set_agrees_with(
        oracle,
        Reference::Kernel,
        &dir,
        &[1000, 1001, 0x8000_0000],
        &[27, 1000, 0xFFFF_FFFE],
        13,
    );
}

#[test]
fn set_agrees_with_the_kernel_on_tmpfs() {
    let dir = support::scratch("mode-set-tmpfs");
    let Some(oracle) = support::kernel_on_tmpfs(&dir) else {
        return;
    };
    set_agrees_with(oracle, Reference::Tmpfs, &dir, &USERS, &GROUPS, 14);
}

/// Sets generated lists that the kernel stores on new files and directories,
/// a default list beside the directory's, then changes the mode: the access
/// list becomes `with_mode`'s, and the default list stays as it was.
fn chmod_agrees_with(mut oracle: Oracle, dir: &Path, seed: u64) {
    let mut rng = Rng::seeded(seed);
    for case in 0..500 {
        let kind = *rng.pick(&[Kind::File, Kind::Directory]);
        let path = oracle.make(dir, kind);
        let mut list = generated(&mut rng, &USERS, &GROUPS);
        while list.is_minimal() {
            list = generated(&mut rng, &USERS, &GROUPS);
        }
        oracle
            .set(&path, xattr::ACCESS, &xattr::encode(&list))
            .unwrap();
        let default = (kind == Kind::Directory).then(|| {
            let default = generated(&mut rng, &USERS, &GROUPS);
            oracle
                .set(&path, xattr::DEFAULT, &xattr::encode(&default))
                .unwrap();
            xattr::encode(&default)
        });
        let mode = rng.below(0o10000) as u32;
        let context = format!(
            "seed {}, case {case}: {kind:?} holding {}, chmod {mode:o}",
            rng.seed(),
            text(list.entries())
        );
        oracle.chmod(&path, mode).unwrap();
        assert_eq!(oracle.mode(&path), mode, "{context}");
        let access = oracle.get(&path, xattr::ACCESS).unwrap();
        assert_eq!(access, xattr::encode(&list.with_mode(mode)), "{context}");
        assert_eq!(
            held(&mut oracle, &path, xattr::DEFAULT),
            default,
            "{context}"
        );
    }
}

#[test]
fn chmod_agrees_with_with_mode_on_the_scratch_filesystem() {
    let dir = support::scratch("mode-chmod-kernel");
    let _discard = support::Discard(&dir);
    let Some(oracle) = support::kernel(&dir) else {
        return;
    };
    chmod_agrees_with(oracle, &dir, 15);
}

#[test]
fn chmod_agrees_with_with_mode_on_tmpfs() {
    let dir = support::scratch("mode-chmod-tmpfs");
    let Some(oracle) = support::kernel_on_tmpfs(&dir) else {
        return;
    };
    chmod_agrees_with(oracle, &dir, 16);
}

/// The ids the access comparison runs as: users and their groups, the first
/// group the primary one, 9 a group no list names.
const OWNER: u32 = 1;
const OWNING_GROUP: u32 = 2;
const CREDENTIALS: [(u32, &[u32]); 12] = [
    (1, &[9]),
    (1, &[2]),
    (1, &[4]),
    (1, &[2, 4]),
    (3, &[9]),
    (3, &[2]),
    (3, &[4]),
    (3, &[2, 4]),
    (5, &[9]),
    (5, &[2]),
    (5, &[4]),
    (5, &[2, 4]),
];

/// Whether `list`, on a file owned by [`OWNER`], names the process with
/// `uid` and `groups`: by a named user entry, or a named group entry for a
/// group it is in. The owner is granted its own entry's permissions whatever
/// else names it, so it is never named.
fn names(list: &Acl, uid: u32, groups: &[u32]) -> bool {
    uid != OWNER
        && (list.perm(Qualifier::User(uid)).is_some()
            || groups
                .iter()
                .any(|&gid| list.perm(Qualifier::Group(gid)).is_some()))
}

#[test]
fn a_narrowed_list_grants_whom_the_list_does_not_name_what_the_list_grants() {
    let dir = support::scratch("mode-narrowed-access");
    let Some(mut oracle) = support::kernel_on_tmpfs(&dir) else {
        return;
    };
    // The tmpfs is mounted for its root alone; the other users need to search
    // it to reach the files.
    oracle
        .chmod(&hex(dir.as_os_str().as_encoded_bytes()), 0o711)
        .unwrap();
    let mut rng = Rng::seeded(17);
    let mut named_differences = BTreeSet::new();
    let mut unnamed_answers = BTreeSet::new();
    for case in 0..120 {
        // Users 1 and 3, groups 2 and 4: the owner and the owning group can
        // be named too, as users and groups like any other.
        let list = generated(&mut rng, &[1, 3], &[2, 4]);
        let context = format!("seed {}, case {case}, {}", rng.seed(), text(list.entries()));
        let path = oracle.make(&dir, Kind::File);
        oracle.chown(&path, OWNER, OWNING_GROUP).unwrap();
        let granted = |oracle: &mut Oracle, list: &Acl| {
            let set =
                mode::set(0o600, FileKind::Other, ListKind::Access, Some(list.clone())).unwrap();
            let value = set.list.as_ref().map_or_else(Vec::new, xattr::encode);
            oracle.set(&path, xattr::ACCESS, &value).unwrap();
            oracle.chmod(&path, set.mode).unwrap();
            CREDENTIALS.map(|(uid, groups)| oracle.access(&path, uid, groups[0], groups))
        };
        let under_list = granted(&mut oracle, &list);
        let under_narrowing = granted(&mut oracle, &list.narrowed());
        for (((uid, groups), full), narrow) in
            CREDENTIALS.iter().zip(&under_list).zip(&under_narrowing)
        {
            if names(&list, *uid, groups) {
                for (n, f) in narrow.chars().zip(full.chars()) {
                    if n != f {
                        named_differences.insert(if n == '-' { "less" } else { "more" });
                    }
                }
            } else {
                assert_eq!(full, narrow, "user {uid}, groups {groups:?}: {context}");
                unnamed_answers.insert(full.clone());
            }
        }
    }
    // Every answer access(2) can give was compared, so no answer was the same
    // for want of reaching the file.
    assert_eq!(unnamed_answers.len(), 8, "{unnamed_answers:?}");
    // Those the list names are granted what their class is: less than the
    // list granted them, and also more.
    assert_eq!(named_differences, BTreeSet::from(["less", "more"]));
}
