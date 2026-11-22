//! The binary form: the kernel's verdicts as literal bytes, and `decode` and
//! `encode` compared with the kernel on the scratch directory's filesystem,
//! on a tmpfs, and across a user namespace.

mod support;

use std::collections::BTreeSet;
use std::path::Path;

use file_acl::xattr::{self, DecodeError};
use file_acl::{Acl, Entry, Invalid, Perm, Qualifier, Tag, UNDEFINED_ID};
use support::{Kind, Oracle, Rng, unhex};

const R: Perm = Perm::READ;
const W: Perm = Perm::WRITE;
const RW: Perm = Perm::READ.union(Perm::WRITE);
const NONE: Perm = Perm::NONE;

fn acl(entries: &[(Qualifier, Perm)]) -> Acl {
    Acl::new(entries.iter().map(|&(q, p)| Entry::new(q, p)).collect()).unwrap()
}

/// The owner, the owning group and everyone else.
fn minimal() -> Acl {
    acl(&[
        (Qualifier::UserObj, RW),
        (Qualifier::GroupObj, R),
        (Qualifier::Other, NONE),
    ])
}

/// The list of the table's first row.
fn full() -> Acl {
    acl(&[
        (Qualifier::UserObj, RW),
        (Qualifier::User(1000), R),
        (Qualifier::GroupObj, R),
        (Qualifier::Group(27), RW),
        (Qualifier::Mask, RW),
        (Qualifier::Other, NONE),
    ])
}

type Decoded = Result<Option<Acl>, DecodeError>;

/// A value the kernel was asked about, as `getfattr -e hex` would print it,
/// grouped by field: the version, then each entry's tag, permissions and id.
/// What the kernel does with it is in the label; what `decode` answers is
/// the third field.
fn kernel_table() -> Vec<(&'static str, &'static str, Decoded)> {
    let tag_order = |entry: usize, tag: Tag, previous: Tag| -> Decoded {
        Err(DecodeError::TagOrder {
            entry,
            tag,
            previous,
        })
    };
    let missing = |tag: Tag| -> Decoded { Err(Invalid::Missing { tag }.into()) };
    let repeated =
        |qualifier: Qualifier| -> Decoded { Err(Invalid::Repeated { qualifier }.into()) };
    vec![
        // The design's table, row by row.
        (
            "canonical list with named entries and mask: stored as given",
            "02000000 0100 0600 ffffffff 0200 0400 e8030000 0400 0400 ffffffff \
             0800 0600 1b000000 1000 0600 ffffffff 2000 0000 ffffffff",
            Ok(Some(full())),
        ),
        (
            "minimal list: accepted, not stored",
            "02000000 0100 0600 ffffffff 0400 0400 ffffffff 2000 0000 ffffffff",
            Ok(Some(minimal())),
        ),
        (
            "minimal list plus a mask: stored",
            "02000000 0100 0600 ffffffff 0400 0000 ffffffff 1000 0600 ffffffff \
             2000 0000 ffffffff",
            Ok(Some(acl(&[
                (Qualifier::UserObj, RW),
                (Qualifier::GroupObj, NONE),
                (Qualifier::Mask, RW),
                (Qualifier::Other, NONE),
            ]))),
        ),
        ("header only: removes the list", "02000000", Ok(None)),
        ("an empty value: removes the list", "", Ok(None)),
        (
            "other before the owning group: EINVAL",
            "02000000 0100 0600 ffffffff 2000 0000 ffffffff 0400 0400 ffffffff",
            tag_order(2, Tag::GroupObj, Tag::Other),
        ),
        (
            "mask before a named user: EINVAL",
            "02000000 0100 0600 ffffffff 1000 0600 ffffffff 0200 0400 e8030000 \
             0400 0400 ffffffff 2000 0000 ffffffff",
            tag_order(2, Tag::User, Tag::Mask),
        ),
        (
            "named users in descending id order: stored as given",
            "02000000 0100 0600 ffffffff 0200 0600 e9030000 0200 0400 e8030000 \
             0400 0400 ffffffff 1000 0600 ffffffff 2000 0000 ffffffff",
            Ok(Some(acl(&[
                (Qualifier::UserObj, RW),
                (Qualifier::User(1000), R),
                (Qualifier::User(1001), RW),
                (Qualifier::GroupObj, R),
                (Qualifier::Mask, RW),
                (Qualifier::Other, NONE),
            ]))),
        ),
        (
            "the same named user twice: stored as given (refused here, as libacl's checker does)",
            "02000000 0100 0600 ffffffff 0200 0400 e8030000 0200 0200 e8030000 \
             0400 0400 ffffffff 1000 0600 ffffffff 2000 0000 ffffffff",
            repeated(Qualifier::User(1000)),
        ),
        (
            "the same named group twice: stored as given (refused here, as libacl's checker does)",
            "02000000 0100 0600 ffffffff 0400 0400 ffffffff 0800 0400 1b000000 \
             0800 0200 1b000000 1000 0600 ffffffff 2000 0000 ffffffff",
            repeated(Qualifier::Group(27)),
        ),
        (
            "named entry without a mask: EINVAL",
            "02000000 0100 0600 ffffffff 0200 0400 e8030000 0400 0400 ffffffff \
             2000 0000 ffffffff",
            missing(Tag::Mask),
        ),
        (
            "permission bit outside rwx: EINVAL",
            "02000000 0100 0e00 ffffffff 0400 0400 ffffffff 2000 0000 ffffffff",
            Err(DecodeError::StrayPerm {
                entry: 0,
                bits: 0o16,
            }),
        ),
        (
            "named entry with id 0xFFFFFFFF: EINVAL",
            "02000000 0100 0600 ffffffff 0200 0400 ffffffff 0400 0400 ffffffff \
             1000 0600 ffffffff 2000 0000 ffffffff",
            Err(DecodeError::UnmappedId {
                entry: 1,
                tag: Tag::User,
            }),
        ),
        (
            "unknown tag: EINVAL",
            "02000000 0100 0600 ffffffff 0400 0400 ffffffff 4000 0400 ffffffff \
             2000 0000 ffffffff",
            Err(DecodeError::UnknownTag {
                entry: 2,
                raw: 0x40,
            }),
        ),
        (
            "version 1: EOPNOTSUPP",
            "01000000 0100 0600 ffffffff 0400 0400 ffffffff 2000 0000 ffffffff",
            Err(DecodeError::Version { version: 1 }),
        ),
        (
            "trailing partial entry: EINVAL",
            "02000000 0100 0600 ffffffff 0400 0400 ffffffff 2000 0000 ffffffff 0100",
            Err(DecodeError::Partial { len: 30 }),
        ),
        (
            "owner, owning group and other entries with id 0: accepted, ids ignored",
            "02000000 0100 0600 00000000 0400 0400 00000000 2000 0000 00000000",
            Ok(Some(minimal())),
        ),
        (
            "two owner entries, other missing: EINVAL",
            "02000000 0100 0600 ffffffff 0100 0400 ffffffff 0400 0400 ffffffff",
            repeated(Qualifier::UserObj),
        ),
        // The last three rows are about the file a list is set on, not the
        // value, which is the first row's or the second's.
        (
            "set-user-ID mode with a list set: set-user-ID kept",
            "02000000 0100 0600 ffffffff 0200 0400 e8030000 0400 0400 ffffffff \
             0800 0600 1b000000 1000 0600 ffffffff 2000 0000 ffffffff",
            Ok(Some(full())),
        ),
        (
            "default list on a regular file: EACCES",
            "02000000 0100 0600 ffffffff 0400 0400 ffffffff 2000 0000 ffffffff",
            Ok(Some(minimal())),
        ),
        (
            "minimal default list on a directory: stored",
            "02000000 0100 0600 ffffffff 0400 0400 ffffffff 2000 0000 ffffffff",
            Ok(Some(minimal())),
        ),
        // Measured with the table's, to settle what it leaves open.
        (
            "one byte of a header: EINVAL",
            "02",
            Err(DecodeError::Partial { len: 1 }),
        ),
        (
            "three bytes of a header: EINVAL",
            "020000",
            Err(DecodeError::Partial { len: 3 }),
        ),
        (
            "two bytes of a version-1 header: EINVAL",
            "0100",
            Err(DecodeError::Partial { len: 2 }),
        ),
        (
            "version 1, header only: EOPNOTSUPP",
            "01000000",
            Err(DecodeError::Version { version: 1 }),
        ),
        (
            "version 1 with a trailing partial entry: EOPNOTSUPP, the version first",
            "01000000 0100 0600 ffffffff 0400 0400 ffffffff 2000 0000 ffffffff 01",
            Err(DecodeError::Version { version: 1 }),
        ),
        (
            "version 2 big-endian: EOPNOTSUPP",
            "00000002 0100 0600 ffffffff 0400 0400 ffffffff 2000 0000 ffffffff",
            Err(DecodeError::Version {
                version: 0x0200_0000,
            }),
        ),
        (
            "an unknown tag and a trailing partial entry: EINVAL",
            "02000000 0100 0600 ffffffff 4000 0400 ffffffff 0400 0400 ffffffff \
             2000 0000 ffffffff 01",
            Err(DecodeError::Partial { len: 37 }),
        ),
        (
            "the owning group before the owner: EINVAL",
            "02000000 0400 0400 ffffffff 0100 0600 ffffffff 2000 0000 ffffffff",
            tag_order(1, Tag::UserObj, Tag::GroupObj),
        ),
        (
            "a named user after the owning group: EINVAL",
            "02000000 0100 0600 ffffffff 0400 0400 ffffffff 0200 0400 e8030000 \
             1000 0600 ffffffff 2000 0000 ffffffff",
            tag_order(2, Tag::User, Tag::GroupObj),
        ),
        (
            "a named group before a named user: EINVAL",
            "02000000 0100 0600 ffffffff 0800 0400 1b000000 0200 0400 e8030000 \
             0400 0400 ffffffff 1000 0600 ffffffff 2000 0000 ffffffff",
            tag_order(2, Tag::User, Tag::Group),
        ),
        (
            "the mask after other: EINVAL",
            "02000000 0100 0600 ffffffff 0400 0400 ffffffff 2000 0000 ffffffff \
             1000 0600 ffffffff",
            tag_order(3, Tag::Mask, Tag::Other),
        ),
        (
            "named groups in descending id order: stored as given",
            "02000000 0100 0600 ffffffff 0400 0400 ffffffff 0800 0400 1c000000 \
             0800 0200 1b000000 1000 0600 ffffffff 2000 0000 ffffffff",
            Ok(Some(acl(&[
                (Qualifier::UserObj, RW),
                (Qualifier::GroupObj, R),
                (Qualifier::Group(27), W),
                (Qualifier::Group(28), R),
                (Qualifier::Mask, RW),
                (Qualifier::Other, NONE),
            ]))),
        ),
        (
            "a user named twice, not side by side: stored as given (refused here)",
            "02000000 0100 0600 ffffffff 0200 0400 01000000 0200 0400 02000000 \
             0200 0200 01000000 0400 0400 ffffffff 1000 0600 ffffffff 2000 0000 ffffffff",
            repeated(Qualifier::User(1)),
        ),
        (
            "two owning group entries: EINVAL",
            "02000000 0100 0600 ffffffff 0400 0400 ffffffff 0400 0000 ffffffff \
             2000 0000 ffffffff",
            repeated(Qualifier::GroupObj),
        ),
        (
            "two masks: EINVAL",
            "02000000 0100 0600 ffffffff 0400 0400 ffffffff 1000 0600 ffffffff \
             1000 0400 ffffffff 2000 0000 ffffffff",
            repeated(Qualifier::Mask),
        ),
        (
            "two other entries: EINVAL",
            "02000000 0100 0600 ffffffff 0400 0400 ffffffff 2000 0000 ffffffff \
             2000 0400 ffffffff",
            repeated(Qualifier::Other),
        ),
        (
            "no owner: EINVAL",
            "02000000 0400 0400 ffffffff 2000 0000 ffffffff",
            missing(Tag::UserObj),
        ),
        (
            "no owning group: EINVAL",
            "02000000 0100 0600 ffffffff 2000 0000 ffffffff",
            missing(Tag::GroupObj),
        ),
        (
            "a mask alone: EINVAL",
            "02000000 1000 0600 ffffffff",
            missing(Tag::UserObj),
        ),
        (
            "a named group without a mask: EINVAL",
            "02000000 0100 0600 ffffffff 0400 0400 ffffffff 0800 0400 1b000000 \
             2000 0000 ffffffff",
            missing(Tag::Mask),
        ),
        (
            "unknown tag 0: EINVAL",
            "02000000 0100 0600 ffffffff 0000 0400 ffffffff 0400 0400 ffffffff \
             2000 0000 ffffffff",
            Err(DecodeError::UnknownTag { entry: 1, raw: 0 }),
        ),
        (
            "unknown tag 0x3, two tags' bits: EINVAL",
            "02000000 0100 0600 ffffffff 0300 0400 ffffffff 0400 0400 ffffffff \
             2000 0000 ffffffff",
            Err(DecodeError::UnknownTag { entry: 1, raw: 3 }),
        ),
        (
            "unknown tag 0xffff: EINVAL",
            "02000000 0100 0600 ffffffff 0400 0400 ffffffff ffff 0400 ffffffff \
             2000 0000 ffffffff",
            Err(DecodeError::UnknownTag {
                entry: 2,
                raw: 0xffff,
            }),
        ),
        (
            "permission bit 0x8000 on the mask: EINVAL",
            "02000000 0100 0600 ffffffff 0200 0400 e8030000 0400 0400 ffffffff \
             1000 0680 ffffffff 2000 0000 ffffffff",
            Err(DecodeError::StrayPerm {
                entry: 3,
                bits: 0x8006,
            }),
        ),
        (
            "permission bits 0x100 on other: EINVAL",
            "02000000 0100 0600 ffffffff 0400 0400 ffffffff 2000 0001 ffffffff",
            Err(DecodeError::StrayPerm {
                entry: 2,
                bits: 0x100,
            }),
        ),
        (
            "a named group with id 0xFFFFFFFF: EINVAL",
            "02000000 0100 0600 ffffffff 0400 0400 ffffffff 0800 0400 ffffffff \
             1000 0600 ffffffff 2000 0000 ffffffff",
            Err(DecodeError::UnmappedId {
                entry: 2,
                tag: Tag::Group,
            }),
        ),
        (
            "object entries with ids, the mask among them: accepted, read back as 0xFFFFFFFF",
            "02000000 0100 0600 e8030000 0200 0400 e8030000 0400 0400 07000000 \
             1000 0600 07000000 2000 0000 07000000",
            Ok(Some(acl(&[
                (Qualifier::UserObj, RW),
                (Qualifier::User(1000), R),
                (Qualifier::GroupObj, R),
                (Qualifier::Mask, RW),
                (Qualifier::Other, NONE),
            ]))),
        ),
        (
            "the same id named as a user and as a group: stored",
            "02000000 0100 0600 ffffffff 0200 0400 1b000000 0400 0400 ffffffff \
             0800 0400 1b000000 1000 0600 ffffffff 2000 0000 ffffffff",
            Ok(Some(acl(&[
                (Qualifier::UserObj, RW),
                (Qualifier::User(27), R),
                (Qualifier::GroupObj, R),
                (Qualifier::Group(27), R),
                (Qualifier::Mask, RW),
                (Qualifier::Other, NONE),
            ]))),
        ),
        (
            "named user 0 and the highest id there is: stored",
            "02000000 0100 0600 ffffffff 0200 0400 00000000 0200 0400 feffffff \
             0400 0400 ffffffff 1000 0600 ffffffff 2000 0000 ffffffff",
            Ok(Some(acl(&[
                (Qualifier::UserObj, RW),
                (Qualifier::User(0), R),
                (Qualifier::User(UNDEFINED_ID - 1), R),
                (Qualifier::GroupObj, R),
                (Qualifier::Mask, RW),
                (Qualifier::Other, NONE),
            ]))),
        ),
    ]
}

#[test]
fn every_value_the_kernel_was_asked_about_decodes_as_measured() {
    for (label, value, expected) in kernel_table() {
        assert_eq!(xattr::decode(&unhex(value)), expected, "{label}");
    }
}

#[test]
fn encode_writes_canonical_order_and_the_undefined_id_on_object_entries() {
    assert_eq!(
        xattr::encode(&full()),
        unhex(
            "02000000 0100 0600 ffffffff 0200 0400 e8030000 0400 0400 ffffffff \
             0800 0600 1b000000 1000 0600 ffffffff 2000 0000 ffffffff"
        )
    );
    // Values that differ only in what the kernel ignores or reorders write
    // the same bytes again.
    let descending = unhex(
        "02000000 0100 0700 00000000 0200 0400 e9030000 0200 0600 e8030000 \
         0400 0400 05000000 1000 0600 00000000 2000 0100 07000000",
    );
    assert_eq!(
        xattr::encode(&xattr::decode(&descending).unwrap().unwrap()),
        unhex(
            "02000000 0100 0700 ffffffff 0200 0600 e8030000 0200 0400 e9030000 \
             0400 0400 ffffffff 1000 0600 ffffffff 2000 0100 ffffffff"
        )
    );
}

#[test]
fn each_rule_a_value_breaks_says_what_breaks_it() {
    for (error, text) in [
        (
            DecodeError::TooLong { len: 65_537 },
            "the value is 65537 bytes long, longer than the 65536 bytes an extended attribute holds",
        ),
        (
            DecodeError::Version { version: 1 },
            "the value is of version 1, not 2",
        ),
        (
            DecodeError::Partial { len: 30 },
            "the value is 30 bytes long, which is not a 4-byte header and whole 8-byte entries",
        ),
        (
            DecodeError::UnknownTag {
                entry: 2,
                raw: 0x40,
            },
            "the entry at position 2 has tag 0x40, which POSIX.1e does not define",
        ),
        (
            DecodeError::StrayPerm {
                entry: 0,
                bits: 0o16,
            },
            "the entry at position 0 has permission bits 0o16, beyond read, write and execute",
        ),
        (
            DecodeError::TagOrder {
                entry: 2,
                tag: Tag::GroupObj,
                previous: Tag::Other,
            },
            "the owning group entry at position 2 follows the other entry, out of order",
        ),
        (
            DecodeError::UnmappedId {
                entry: 1,
                tag: Tag::User,
            },
            "the named user entry at position 1 has the undefined id 4294967295, \
             as read for an id the reader's user namespace does not map",
        ),
        (
            DecodeError::from(Invalid::Missing { tag: Tag::Mask }),
            "the list names a user or group but has no mask entry",
        ),
    ] {
        assert_eq!(error.to_string(), text);
    }
}

/// An entry as the binary form holds it: tag, permissions and id.
type Record = (u16, u16, u32);

/// The value of `records` under `version`.
fn pack(version: u32, records: &[Record]) -> Vec<u8> {
    let mut out = version.to_le_bytes().to_vec();
    for &(tag, perm, id) in records {
        out.extend_from_slice(&tag.to_le_bytes());
        out.extend_from_slice(&perm.to_le_bytes());
        out.extend_from_slice(&id.to_le_bytes());
    }
    out
}

/// The whole records of `value`, after its header.
fn unpack(value: &[u8]) -> Vec<Record> {
    let (records, _) = value.get(4..).unwrap_or_default().as_chunks::<8>();
    records
        .iter()
        .map(|&[t0, t1, p0, p1, i0, i1, i2, i3]| {
            (
                u16::from_le_bytes([t0, t1]),
                u16::from_le_bytes([p0, p1]),
                u32::from_le_bytes([i0, i1, i2, i3]),
            )
        })
        .collect()
}

/// A valid list's entries as records, in canonical order, the object
/// entries with `UNDEFINED_ID` as their id.
fn valid_records(rng: &mut Rng, ids: &[u32]) -> Vec<Record> {
    let perm = |rng: &mut Rng| rng.below(8) as u16;
    let named = |rng: &mut Rng| {
        let mut chosen: Vec<u32> = (0..rng.below(4)).map(|_| *rng.pick(ids)).collect();
        chosen.sort_unstable();
        chosen.dedup();
        chosen
    };
    let mut records = vec![(Tag::UserObj.to_raw(), perm(rng), UNDEFINED_ID)];
    let users = named(rng);
    let groups = named(rng);
    records.extend(users.iter().map(|&id| (Tag::User.to_raw(), perm(rng), id)));
    records.push((Tag::GroupObj.to_raw(), perm(rng), UNDEFINED_ID));
    records.extend(
        groups
            .iter()
            .map(|&id| (Tag::Group.to_raw(), perm(rng), id)),
    );
    if !users.is_empty() || !groups.is_empty() || rng.below(2) == 0 {
        records.push((Tag::Mask.to_raw(), perm(rng), UNDEFINED_ID));
    }
    records.push((Tag::Other.to_raw(), perm(rng), UNDEFINED_ID));
    records
}

/// A value from a valid list changed in up to two ways, each of which may
/// break one of the form's rules or keep the list valid.
fn generated(rng: &mut Rng, ids: &[u32]) -> Vec<u8> {
    let mut records = valid_records(rng, ids);
    let mut version = 2;
    let mut cut = 0;
    let mut extra = Vec::new();
    for _ in 0..rng.below(3) {
        let at = rng.below(records.len().max(1) as u64) as usize;
        match rng.below(12) {
            // Two entries swapped: out of order, or named ids reordered.
            0 if records.len() > 1 => {
                let at = at.min(records.len() - 2);
                records.swap(at, at + 1);
            }
            // The named entries in reverse order, which the kernel accepts.
            1 => reverse_named(&mut records),
            // An entry repeated.
            2 if !records.is_empty() => {
                let again = records[at];
                let to = rng.below(records.len() as u64 + 1) as usize;
                records.insert(to, again);
            }
            3 if !records.is_empty() => {
                records.remove(at);
            }
            4 if !records.is_empty() => {
                records[at].1 = match rng.below(4) {
                    0 => *rng.pick(&[0o10, 0o17, 0x100, 0x8000, 0xffff]),
                    _ => (rng.next_u64() as u16) | 0o10,
                };
            }
            5 if !records.is_empty() => {
                records[at].0 = *rng.pick(&[0, 3, 0x40, 0x80, 0x100, 0xffff]);
            }
            6 if !records.is_empty() => {
                if Tag::from_raw(records[at].0).is_some_and(Tag::is_named) {
                    records[at].2 = UNDEFINED_ID;
                }
            }
            // An object entry's id, which the kernel ignores.
            7 if !records.is_empty() => {
                if !Tag::from_raw(records[at].0).is_some_and(Tag::is_named) {
                    records[at].2 = *rng.pick(ids);
                }
            }
            8 => version = *rng.pick(&[0, 1, 3, 0x0200_0000, u32::MAX]),
            9 => cut = 1 + rng.below(7) as usize,
            10 => {
                extra = (0..1 + rng.below(7))
                    .map(|_| rng.next_u64() as u8)
                    .collect()
            }
            11 => records.clear(),
            _ => {}
        }
    }
    let mut out = pack(version, &records);
    out.truncate(out.len().saturating_sub(cut));
    out.extend_from_slice(&extra);
    out
}

/// Reverses the order of the named users among themselves, and of the named
/// groups, leaving every other entry where it is.
fn reverse_named(records: &mut [Record]) {
    for tag in [Tag::User, Tag::Group] {
        let at: Vec<usize> = (0..records.len())
            .filter(|&i| records[i].0 == tag.to_raw())
            .collect();
        let held: Vec<Record> = at.iter().map(|&i| records[i]).collect();
        for (&i, record) in at.iter().zip(held.into_iter().rev()) {
            records[i] = record;
        }
    }
}

/// Whether every id `value` names is among `ids`, so a namespace that maps
/// only those can take it.
fn names_within(value: &[u8], ids: &[u32]) -> bool {
    unpack(value).iter().all(|&(tag, _, id)| {
        !Tag::from_raw(tag).is_some_and(Tag::is_named) || id == UNDEFINED_ID || ids.contains(&id)
    })
}

/// What the kernel did with a value set as an extended attribute of a new
/// file or directory.
#[derive(Clone, PartialEq, Eq, Debug)]
enum Verdict {
    /// Accepted; the value it then held, if any.
    Accepted(Option<Vec<u8>>),
    /// Refused, with this errno.
    Refused(String),
}

fn kernel_verdict(
    oracle: &mut Oracle,
    dir: &Path,
    kind: Kind,
    name: &str,
    value: &[u8],
) -> Verdict {
    let path = oracle.make(dir, kind);
    if let Err(errno) = oracle.set(&path, name, value) {
        return Verdict::Refused(errno);
    }
    match oracle.get(&path, name) {
        Ok(held) => Verdict::Accepted(Some(held)),
        Err(errno) if errno == "ENODATA" => Verdict::Accepted(None),
        Err(errno) => panic!("reading back {name} failed: {errno}"),
    }
}

/// How `decode` and the kernel answered a value.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
enum Outcome {
    /// Both accept it, `decode` reading no list.
    NoList,
    /// Both accept it, `decode` reading a list.
    List,
    /// Both refuse it, `decode` with this kind of error.
    Refused(&'static str),
    /// The stated difference: the kernel accepts a user or group named
    /// twice; `decode` refuses it.
    NamedTwice,
    /// `decode` reads a list the kernel takes, and the filesystem has no
    /// room for it (`ENOSPC`).
    NoRoom,
}

fn kind_of(error: DecodeError) -> &'static str {
    match error {
        DecodeError::TooLong { .. } => "TooLong",
        DecodeError::Version { .. } => "Version",
        DecodeError::Partial { .. } => "Partial",
        DecodeError::UnknownTag { .. } => "UnknownTag",
        DecodeError::StrayPerm { .. } => "StrayPerm",
        DecodeError::TagOrder { .. } => "TagOrder",
        DecodeError::UnmappedId { .. } => "UnmappedId",
        DecodeError::Invalid(Invalid::Missing { .. }) => "Missing",
        DecodeError::Invalid(Invalid::Repeated { .. }) => "Repeated",
        other => panic!("decode answered {other:?}"),
    }
}

/// Compares `decode`'s verdict on `value` with the kernel's, the value set
/// as the access list of a new file and as the default list of a new
/// directory.
///
/// Where both accept, whatever the kernel holds decodes to the list `decode`
/// read, and a directory holds a default list exactly where `decode` reads
/// one, as the kernel stores even a minimal default list. Where both refuse,
/// the kernel's errno is `E2BIG` for a value too long, `EOPNOTSUPP` for a
/// wrong version and `EINVAL` for every other rule. Where they differ, it is
/// the stated difference, and the value without its repeated named entries
/// decodes; or a list longer than a 4 KiB block, which the filesystem may
/// have no room for.
fn compare(oracle: &mut Oracle, dir: &Path, value: &[u8], context: &str) -> Outcome {
    let ours = xattr::decode(value);
    let mut outcome = None;
    for (kind, name) in [
        (Kind::File, xattr::ACCESS),
        (Kind::Directory, xattr::DEFAULT),
    ] {
        let theirs = kernel_verdict(oracle, dir, kind, name, value);
        let context = format!("{context}, as {name}: decode {ours:?}, kernel {theirs:?}");
        let this = match (&ours, &theirs) {
            (Ok(list), Verdict::Accepted(held)) => {
                if let Some(held) = held {
                    assert_eq!(&xattr::decode(held), &Ok(list.clone()), "{context}");
                }
                if kind == Kind::Directory || list.is_none() {
                    assert_eq!(held.is_some(), list.is_some(), "{context}");
                }
                if list.is_some() {
                    Outcome::List
                } else {
                    Outcome::NoList
                }
            }
            (Err(error @ DecodeError::TooLong { .. }), Verdict::Refused(errno)) => {
                assert_eq!(errno, "E2BIG", "{context}");
                Outcome::Refused(kind_of(*error))
            }
            // A filesystem's own limit, below the kernel's: ext4 with 4 KiB
            // blocks has no room for a list of a thousand entries.
            (Ok(Some(_)), Verdict::Refused(errno)) if errno == "ENOSPC" && value.len() > 4096 => {
                Outcome::NoRoom
            }
            (Err(error @ DecodeError::Version { .. }), Verdict::Refused(errno)) => {
                // Linux gives EOPNOTSUPP and ENOTSUP one number.
                assert!(matches!(&**errno, "EOPNOTSUPP" | "ENOTSUP"), "{context}");
                Outcome::Refused(kind_of(*error))
            }
            (Err(error), Verdict::Refused(errno)) => {
                assert_eq!(errno, "EINVAL", "{context}");
                Outcome::Refused(kind_of(*error))
            }
            (
                Err(DecodeError::Invalid(Invalid::Repeated {
                    qualifier: Qualifier::User(_) | Qualifier::Group(_),
                })),
                Verdict::Accepted(Some(_)),
            ) => {
                let mut seen = BTreeSet::new();
                let mut once = unpack(value);
                once.retain(|&(tag, _, id)| {
                    !Tag::from_raw(tag).is_some_and(Tag::is_named) || seen.insert((tag, id))
                });
                assert!(
                    matches!(xattr::decode(&pack(2, &once)), Ok(Some(_))),
                    "{context}: refused for more than a name given twice"
                );
                Outcome::NamedTwice
            }
            _ => panic!("{context}: they disagree"),
        };
        assert!(
            outcome.is_none_or(|o| o == this),
            "{context}: the two attributes differ"
        );
        outcome = Some(this);
    }
    outcome.unwrap()
}

/// Compares `decode` with the kernel on the filesystem that holds `dir`,
/// over the table's values that name only ids from `ids`, and over values
/// generated from those ids, which reach every outcome.
fn decode_agrees_with(mut oracle: Oracle, dir: &Path, ids: &[u32], seed: u64) {
    for (label, value, _) in kernel_table() {
        let value = unhex(value);
        if names_within(&value, ids) {
            compare(&mut oracle, dir, &value, label);
        }
    }
    let mut seen = BTreeSet::new();
    let mut rng = Rng::seeded(seed);
    for case in 0..3000 {
        let value = generated(&mut rng, ids);
        let context = format!(
            "seed {}, case {case}, value {}",
            rng.seed(),
            support::hex(&value)
        );
        seen.insert(compare(&mut oracle, dir, &value, &context));
    }
    let expected = [
        Outcome::NoList,
        Outcome::List,
        Outcome::Refused("Version"),
        Outcome::Refused("Partial"),
        Outcome::Refused("UnknownTag"),
        Outcome::Refused("StrayPerm"),
        Outcome::Refused("TagOrder"),
        Outcome::Refused("UnmappedId"),
        Outcome::Refused("Missing"),
        Outcome::Refused("Repeated"),
        Outcome::NamedTwice,
    ];
    assert_eq!(seen, BTreeSet::from(expected));
}

/// Ids every comparison names, the table's among them: ids a namespace with
/// the default subordinate range maps.
const IDS: [u32; 8] = [0, 1, 2, 27, 28, 1000, 1001, 65534];

/// [`IDS`] and the highest ids, which only the initial namespace maps.
fn all_ids() -> Vec<u32> {
    [&IDS[..], &[0x8000_0000, UNDEFINED_ID - 1]].concat()
}

#[test]
fn decode_agrees_with_the_kernel_on_the_scratch_filesystem() {
    let dir = support::scratch("xattr-decode-kernel");
    let Some(oracle) = support::kernel(&dir) else {
        return;
    };
    decode_agrees_with(oracle, &dir, &all_ids(), 3);
}

#[test]
fn decode_agrees_with_the_kernel_on_tmpfs() {
    let dir = support::scratch("xattr-decode-tmpfs");
    let Some(oracle) = support::kernel_on_tmpfs(&dir) else {
        return;
    };
    decode_agrees_with(oracle, &dir, &IDS, 4);
}

/// A value of `version` holding the owner, `named` entries of tag `tag` with
/// ids from 1, the owning group, the mask and other, and then `trailing`
/// NULs.
fn long_value(named: u32, version: u32, tag: u16, trailing: usize) -> Vec<u8> {
    let mut records = vec![(0x01, 7, UNDEFINED_ID)];
    records.extend((1..=named).map(|id| (tag, 4, id)));
    records.extend([
        (0x04, 4, UNDEFINED_ID),
        (0x10, 4, UNDEFINED_ID),
        (0x20, 0, UNDEFINED_ID),
    ]);
    let mut value = pack(version, &records);
    value.resize(value.len() + trailing, 0);
    value
}

/// The values the kernel was asked about for their length, on ext4 and on
/// a tmpfs (Linux 7.2.15), and the kind of answer `decode` gives each. The
/// kernel takes a value of at most 65,536 bytes, so a list of at most 8,191
/// entries (65,532 bytes), and refuses a longer value with `E2BIG` before
/// any other check: a wrong version, a malformed entry, a default list on a
/// file, a symbolic link. ext4 has no room for the longest list (`ENOSPC`),
/// which tmpfs stores.
fn long_values() -> Vec<(&'static str, Vec<u8>, &'static str)> {
    vec![
        ("8,191 entries", long_value(8187, 2, 0x02, 0), "List"),
        (
            "8,191 entries, 1 byte after",
            long_value(8187, 2, 0x02, 1),
            "Partial",
        ),
        (
            "8,191 entries, 4 bytes after",
            long_value(8187, 2, 0x02, 4),
            "Partial",
        ),
        (
            "8,191 entries, 5 bytes after",
            long_value(8187, 2, 0x02, 5),
            "TooLong",
        ),
        ("8,192 entries", long_value(8188, 2, 0x02, 0), "TooLong"),
        (
            "8,192 entries, version 3",
            long_value(8188, 3, 0x02, 0),
            "TooLong",
        ),
        (
            "8,192 entries, version 3, 1 byte after",
            long_value(8188, 3, 0x02, 1),
            "TooLong",
        ),
        (
            "8,192 entries, an unknown tag",
            long_value(8188, 2, 0x40, 0),
            "TooLong",
        ),
        (
            "8,191 entries, version 3",
            long_value(8187, 3, 0x02, 0),
            "Version",
        ),
        ("20,004 entries", long_value(20000, 2, 0x02, 0), "TooLong"),
    ]
}

#[test]
fn a_value_longer_than_the_kernel_takes_is_refused_first() {
    for (label, value, expected) in long_values() {
        let decoded = xattr::decode(&value);
        let kind = match &decoded {
            Ok(Some(list)) => {
                assert_eq!(list.entries().len(), 8191, "{label}");
                "List"
            }
            Ok(None) => "NoList",
            Err(error) => kind_of(*error),
        };
        assert_eq!(kind, expected, "{label}: {decoded:?}");
        if let Err(DecodeError::TooLong { len }) = decoded {
            assert_eq!(len, value.len(), "{label}");
        }
    }
    // A list longer than the kernel takes is encoded, to a value `decode`
    // refuses, as the kernel does.
    let entries = |named: u32| {
        xattr::decode(&long_value(named, 2, 0x02, 0))
            .unwrap()
            .unwrap()
            .into_entries()
    };
    let mut longest = entries(8187);
    let value = xattr::encode(&Acl::new(longest.clone()).unwrap());
    assert_eq!(value.len(), 65_532);
    longest.push(Entry::new(Qualifier::User(8188), R));
    let value = xattr::encode(&Acl::new(longest).unwrap());
    assert_eq!(
        xattr::decode(&value),
        Err(DecodeError::TooLong { len: 65_540 })
    );
}

/// Compares `decode` with the kernel over [`long_values`] on the filesystem
/// that holds `dir`: every outcome but the longest list's is the
/// filesystem's to decide.
fn length_agrees_with(mut oracle: Oracle, dir: &Path) {
    let mut seen = BTreeSet::new();
    for (label, value, _) in long_values() {
        seen.insert(compare(&mut oracle, dir, &value, label));
    }
    for outcome in [
        Outcome::Refused("Partial"),
        Outcome::Refused("TooLong"),
        Outcome::Refused("Version"),
    ] {
        assert!(seen.remove(&outcome), "{outcome:?} not seen");
    }
    assert!(
        seen == BTreeSet::from([Outcome::List]) || seen == BTreeSet::from([Outcome::NoRoom]),
        "{seen:?}"
    );
}

#[test]
fn the_length_decode_takes_agrees_with_the_kernel_on_the_scratch_filesystem() {
    let dir = support::scratch("xattr-length-kernel");
    let Some(oracle) = support::kernel(&dir) else {
        return;
    };
    length_agrees_with(oracle, &dir);
}

#[test]
fn the_length_decode_takes_agrees_with_the_kernel_on_tmpfs() {
    let dir = support::scratch("xattr-length-tmpfs");
    let Some(oracle) = support::kernel_on_tmpfs(&dir) else {
        return;
    };
    length_agrees_with(oracle, &dir);
}

/// Sets `encode`'s value for generated lists as a file's access list and a
/// directory's default list: the kernel accepts each, and holds it byte for
/// byte, but for a minimal access list, which it does not store.
fn encode_is_held_unchanged(mut oracle: Oracle, dir: &Path, ids: &[u32], seed: u64) {
    let mut rng = Rng::seeded(seed);
    for case in 0..500 {
        let mut records = valid_records(&mut rng, ids);
        if rng.below(2) == 0 {
            reverse_named(&mut records);
        }
        let list = xattr::decode(&pack(2, &records)).unwrap().unwrap();
        let encoded = xattr::encode(&list);
        let context = format!(
            "seed {}, case {case}, value {}",
            rng.seed(),
            support::hex(&encoded)
        );
        assert_eq!(xattr::decode(&encoded), Ok(Some(list.clone())), "{context}");
        let minimal = list.entries().len() == 3;
        let file = kernel_verdict(&mut oracle, dir, Kind::File, xattr::ACCESS, &encoded);
        let held = (!minimal).then(|| encoded.clone());
        assert_eq!(file, Verdict::Accepted(held), "{context}");
        let directory = kernel_verdict(&mut oracle, dir, Kind::Directory, xattr::DEFAULT, &encoded);
        assert_eq!(directory, Verdict::Accepted(Some(encoded)), "{context}");
    }
}

#[test]
fn encode_is_held_unchanged_on_the_scratch_filesystem() {
    let dir = support::scratch("xattr-encode-kernel");
    let Some(oracle) = support::kernel(&dir) else {
        return;
    };
    encode_is_held_unchanged(oracle, &dir, &all_ids(), 5);
}

#[test]
fn encode_is_held_unchanged_on_tmpfs() {
    let dir = support::scratch("xattr-encode-tmpfs");
    let Some(oracle) = support::kernel_on_tmpfs(&dir) else {
        return;
    };
    encode_is_held_unchanged(oracle, &dir, &IDS, 6);
}

/// A list naming user 4242 and group 4243, neither mapped in a user
/// namespace that maps only its creator.
fn naming_unmapped_ids() -> Acl {
    acl(&[
        (Qualifier::UserObj, RW),
        (Qualifier::User(4242), R),
        (Qualifier::GroupObj, R),
        (Qualifier::Group(4243), RW),
        (Qualifier::Mask, RW),
        (Qualifier::Other, NONE),
    ])
}

#[test]
fn a_list_naming_an_id_a_user_namespace_does_not_map_is_refused_there() {
    let dir = support::scratch("xattr-user-namespace-set");
    let Some(mut inside) = support::kernel_in_user_namespace(&dir) else {
        return;
    };
    // The value is valid: the kernel refuses it for the namespace's map, which
    // `decode` knows nothing of.
    let value = xattr::encode(&naming_unmapped_ids());
    assert!(xattr::decode(&value).is_ok());
    let file = inside.make(&dir, Kind::File);
    assert_eq!(
        inside.set(&file, xattr::ACCESS, &value),
        Err("EINVAL".into())
    );
    // Naming the one id the namespace maps, its root, it is accepted.
    let mapped = acl(&[
        (Qualifier::UserObj, RW),
        (Qualifier::User(0), R),
        (Qualifier::GroupObj, R),
        (Qualifier::Group(0), RW),
        (Qualifier::Mask, RW),
        (Qualifier::Other, NONE),
    ]);
    let value = xattr::encode(&mapped);
    assert_eq!(inside.set(&file, xattr::ACCESS, &value), Ok(()));
    assert_eq!(inside.get(&file, xattr::ACCESS), Ok(value));
}

#[test]
fn an_id_a_user_namespace_does_not_map_reads_there_as_unmapped() {
    let dir = support::scratch("xattr-user-namespace-get");
    let Some(mut outside) = support::kernel(&dir) else {
        return;
    };
    let Some(mut inside) = support::kernel_in_user_namespace(&dir) else {
        return;
    };
    let file = outside.make(&dir, Kind::File);
    let value = xattr::encode(&naming_unmapped_ids());
    assert_eq!(outside.set(&file, xattr::ACCESS, &value), Ok(()));
    assert_eq!(outside.get(&file, xattr::ACCESS), Ok(value));

    let read = inside.get(&file, xattr::ACCESS).unwrap();
    // Each named entry reads with the undefined id; the rest as set.
    assert_eq!(
        read,
        unhex(
            "02000000 0100 0600 ffffffff 0200 0400 ffffffff 0400 0400 ffffffff \
             0800 0600 ffffffff 1000 0600 ffffffff 2000 0000 ffffffff"
        )
    );
    assert_eq!(
        xattr::decode(&read),
        Err(DecodeError::UnmappedId {
            entry: 1,
            tag: Tag::User
        })
    );
}

#[test]
fn whatever_decodes_encodes_to_a_value_that_decodes_to_it_again() {
    let mut rng = Rng::seeded(7);
    let ids = all_ids();
    for _ in 0..20_000 {
        let value = generated(&mut rng, &ids);
        if let Ok(Some(list)) = xattr::decode(&value) {
            let encoded = xattr::encode(&list);
            assert_eq!(encoded.len(), value.len());
            assert_eq!(xattr::decode(&encoded), Ok(Some(list)));
        }
    }
}
