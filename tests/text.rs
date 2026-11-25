//! The text form: `text::parse` and `Parsed::resolve` compared with libacl's
//! reader and checker, over every text libacl was measured reading and over
//! generated texts, names resolved through one account database on both
//! sides; the records GNU tar writes read, and written back as it writes
//! them; and the writer's text read back by the crate and by libacl.

mod support;

use std::collections::BTreeMap;

use file_acl::text::{
    self, Names, ParseError, Parsed, Prefer, ResolveError, Separator, Spelling, Tags,
};
use file_acl::{Acl, Entry, Invalid, Perm, Qualifier, Tag, UNDEFINED_ID, xattr};
use support::{Reading, Rng, libacl_with_accounts, scratch};

/// The users of the account database the comparisons resolve names
/// through: names that need escaping, names that look like numbers, and
/// plain ones. Every name is one glibc reads from a files database as it is
/// written there.
const USERS: &[(&[u8], u32)] = &[
    (b"root", 0),
    (b"lisa", 502),
    (b"a b", 4243),
    (b"back\\slash", 4250),
    ("caf\u{e9}".as_bytes(), 4260),
    (b"4242", 5000),
    (b"007", 5002),
    (b"99999999999", 5003),
    (b"4294967295", 5007),
];

/// The groups of the account database.
const GROUPS: &[(&[u8], u32)] = &[
    (b"root", 0),
    (b"wheel", 10),
    (b"domain users", 4242),
    (b"hash#g", 4245),
    (b"comma,g", 4246),
    (b"back\\slashg", 4251),
    (b"tab\tg", 4252),
    ("caf\u{e9}".as_bytes(), 4253),
    (b"del\x7fg", 4254),
    (b"ctl\x01g", 4255),
    (b"trail ", 4256),
    (b"hash #g", 4257),
    (b"eq=g", 4258),
    (b"4242", 5001),
    (b"x\\", 5010),
    (b"08", 5020),
    (b"0x", 5021),
    (b"3dg", 5022),
    (b"1e3", 5023),
    (b"0x1g", 5026),
    (b"a\\40b", 5030),
    (b"a\\4", 5031),
    (b"a\\8b", 5032),
    (b"a\\400", 5033),
    (b"a\\08b", 5034),
    (b"a\\nb", 5035),
    (b"a", 5036),
    (b"sp ace", 5037),
    (b"0b0", 5040),
];

fn user_id(name: &[u8]) -> Option<u32> {
    USERS.iter().find(|user| user.0 == name).map(|user| user.1)
}

fn group_id(name: &[u8]) -> Option<u32> {
    GROUPS
        .iter()
        .find(|group| group.0 == name)
        .map(|group| group.1)
}

fn user_name(id: u32) -> Option<&'static [u8]> {
    USERS.iter().find(|user| user.1 == id).map(|user| user.0)
}

fn group_name(id: u32) -> Option<&'static [u8]> {
    GROUPS
        .iter()
        .find(|group| group.1 == id)
        .map(|group| group.0)
}

/// The database as `/etc/passwd` and `/etc/group` hold it.
fn account_files() -> (Vec<u8>, Vec<u8>) {
    let mut passwd = Vec::new();
    for (name, id) in USERS {
        passwd.extend_from_slice(name);
        passwd.extend_from_slice(format!(":x:{id}:{id}::/:/bin/false\n").as_bytes());
    }
    let mut group = Vec::new();
    for (name, id) in GROUPS {
        group.extend_from_slice(name);
        group.extend_from_slice(format!(":x:{id}:\n").as_bytes());
    }
    (passwd, group)
}

/// libacl in namespaces whose account database is the one above, or `None`
/// where libacl or user namespaces are missing.
fn libacl_with_the_accounts(test: &str) -> Option<support::Oracle> {
    let (passwd, group) = account_files();
    libacl_with_accounts(&scratch(test), &passwd, &group)
}

fn perm(bits: u16) -> Perm {
    Perm::from_bits(bits).expect("three bits at most")
}

fn acl(spec: &[(Qualifier, u16)]) -> Acl {
    Acl::new(
        spec.iter()
            .map(|&(qualifier, bits)| Entry::new(qualifier, perm(bits)))
            .collect(),
    )
    .expect("a valid list")
}

/// The list `text` states, its names resolved through the database.
fn read(text: &[u8]) -> Acl {
    text::parse(text)
        .unwrap_or_else(|err| panic!("{:?}: {err}", String::from_utf8_lossy(text)))
        .unwrap_or_else(|| panic!("{:?} holds no list", String::from_utf8_lossy(text)))
        .resolve(user_id, group_id, Prefer::Name)
        .unwrap_or_else(|err| panic!("{:?}: {err}", String::from_utf8_lossy(text)))
}

/// The list as libacl renders it, abbreviated and with numeric ids.
fn rendered(acl: &Acl) -> String {
    String::from_utf8(text::write(
        acl,
        Spelling::new(Tags::Short, Separator::Comma, Names::Alone),
    ))
    .expect("numeric text is ASCII")
}

/// What the crate makes of `text`, its names resolved through the database,
/// in the measured table's notation: `valid` and the list rendered, `invalid`
/// and the rule broken, `unresolved`, `no list`, or the parse error.
fn outcome(text: &[u8]) -> String {
    match text::parse(text) {
        Ok(None) => "no list".to_owned(),
        Err(err) => format!("{err:?}"),
        Ok(Some(parsed)) => match parsed.resolve(user_id, group_id, Prefer::Name) {
            Ok(acl) => format!("valid {}", rendered(&acl)),
            Err(ResolveError::Unresolved { .. }) => "unresolved".to_owned(),
            Err(ResolveError::Invalid(invalid)) => format!("invalid {invalid:?}"),
            Err(other) => panic!("resolve answered {other:?}"),
        },
    }
}

/// libacl's reading in the measured table's notation: `refused`, `valid`
/// and the list rendered, or `invalid` and `acl_check`'s code.
fn libacl_notation(reading: &Reading) -> String {
    match reading {
        Reading::Unread => "refused".to_owned(),
        Reading::Valid(value) => {
            let acl = xattr::decode(value)
                .expect("libacl's list decodes")
                .expect("libacl's list holds entries");
            format!("valid {}", rendered(&acl))
        }
        Reading::Invalid { code, .. } => format!("invalid {code}"),
    }
}

/// Whether the crate's outcome and libacl's, in the table's notation, say
/// the same: both refuse the text, both read a list their checkers refuse,
/// or both read the same list.
fn agree(libacl: &str, crate_says: &str) -> bool {
    let refused = |said: &str| {
        !said.starts_with("valid") && !said.starts_with("invalid") && said != "no list"
    };
    match libacl.split(' ').next() {
        Some("refused") => refused(crate_says),
        Some("valid") => crate_says == libacl,
        Some("invalid") => crate_says.starts_with("invalid"),
        _ => false,
    }
}

/// The entries of a version-2 value, whatever rules they break: libacl's
/// reading of a text whose list `acl_check` refuses.
fn entries_of(value: &[u8]) -> Vec<Entry> {
    let (records, rest) = value
        .get(4..)
        .expect("a value has a header")
        .as_chunks::<8>();
    assert!(rest.is_empty(), "a partial entry in {value:02x?}");
    records
        .iter()
        .map(|&[t0, t1, p0, p1, i0, i1, i2, i3]| {
            let tag = Tag::from_raw(u16::from_le_bytes([t0, t1])).expect("a tag");
            let perm = Perm::from_bits(u16::from_le_bytes([p0, p1])).expect("permissions");
            Entry::new(
                Qualifier::new(tag, u32::from_le_bytes([i0, i1, i2, i3])),
                perm,
            )
        })
        .collect()
}

/// What the crate's rules make of entries that are no valid list: the rule
/// they break, and the list, or the rule, once the mask is computed.
///
/// Two readings of a text, each a list its checker refuses, agree only where
/// these are the same for both. A misread entry in a list that is invalid
/// for another reason shows in one or the other: where a mask is the only
/// fault, the two lists are compared whole.
#[derive(Clone, PartialEq, Debug)]
struct Judged {
    invalid: Invalid,
    masked: Result<Acl, Invalid>,
}

/// The crate's judgement of `entries`, where they make no valid list.
fn judged(entries: Vec<Entry>) -> Option<Judged> {
    let invalid = Acl::new(entries.clone()).err()?;
    Some(Judged {
        invalid,
        masked: Acl::with_computed_mask(entries),
    })
}

/// The crate's judgement of the entries it reads in `parsed`, their names
/// resolved through the database, where they make no valid list.
fn judged_parsed(parsed: &Parsed) -> Option<Judged> {
    let resolved = |parsed: &Parsed| match parsed.resolve(user_id, group_id, Prefer::Name) {
        Ok(acl) => Ok(acl),
        Err(ResolveError::Invalid(invalid)) => Err(invalid),
        Err(other) => panic!("resolve answered {other:?}"),
    };
    let invalid = resolved(parsed).err()?;
    Some(Judged {
        invalid,
        masked: resolved(&parsed.clone().with_computed_mask()),
    })
}

// The differences from libacl the text module's documentation states.

/// A qualifier libacl reads as a number in another form than a decimal id,
/// as C's `strtol` or `strtoul` reads one, or past the range of an id; or a
/// binary number, which libacl built against glibc 2.38 or later reads as a
/// number, and built against an earlier one looks up as a name.
const LOOSE_NUMBER: &str = "a number in another form than a decimal id";
/// An escape giving a NUL, or a value past a byte.
const ESCAPE: &str = "an escape giving a NUL or more than a byte";
/// Two entries with no comma or line end between them.
const NO_SEPARATOR: &str = "no comma or line end between entries";
/// A tag not followed directly by its colon: blanks or line ends after it,
/// or, after a mask's or other's, comments, and their colons left out.
const SPACE_AFTER_TAG: &str = "a tag not followed directly by its colon";
/// A comma that does not follow an entry on the entry's line.
const STRAY_COMMA: &str = "a comma off its entry's line";
/// An empty text, which libacl reads as an empty list.
const EMPTY: &str = "an empty text";
/// A fourth field, which libacl refuses.
const FOURTH_FIELD: &str = "a fourth field";
/// A name beginning with a line end or a carriage return, which libacl
/// keeps as part of the name. Only a name service other than glibc's files
/// database holds such a name, so the measured texts are in
/// [`ODD_READINGS`].
const LEADING_LINE_END: &str = "a name beginning with a line end";

/// A qualifier of digits past the last id (`4294967295` and more), which
/// libacl 2.4 looks up as a name, where libacl 2.3 reads it as a number.
const DIGITS_AS_NAME: &str = "digits past the last id, looked up as a name";

const STATED: [&str; 8] = [
    LOOSE_NUMBER,
    ESCAPE,
    NO_SEPARATOR,
    SPACE_AFTER_TAG,
    STRAY_COMMA,
    EMPTY,
    FOURTH_FIELD,
    LEADING_LINE_END,
];

/// Every text libacl's reader was asked about while the grammar was
/// measured, as libacl 2.3.2 read it under the account database above: the
/// text; libacl's reading; the crate's; and, where the two differ, the
/// stated difference that is why. The libacl was Ubuntu's, built against
/// glibc 2.39.
const MEASURED: &[(&[u8], &str, &str, Option<&str>)] = &[
    (
        b"#c\nu::rw-\ng::r--\no::---",
        "refused",
        "LeadingComment { at: 0 }",
        None,
    ),
    (
        b"u::rw-\ng::r--\no::---\n#c",
        "valid u::rw-,g::r--,o::---",
        "valid u::rw-,g::r--,o::---",
        None,
    ),
    (
        b"  #c\nu::rw-\ng::r--\no::---",
        "refused",
        "LeadingComment { at: 2 }",
        None,
    ),
    (
        b"\t#c\nu::rw-\ng::r--\no::---",
        "refused",
        "LeadingComment { at: 1 }",
        None,
    ),
    (
        b"#\nu::rw-\ng::r--\no::---",
        "refused",
        "LeadingComment { at: 0 }",
        None,
    ),
    (
        b"u::rw- #c\ng::r--\no::---",
        "valid u::rw-,g::r--,o::---",
        "valid u::rw-,g::r--,o::---",
        None,
    ),
    (
        b"u::rw-#c\ng::r--\no::---",
        "valid u::rw-,g::r--,o::---",
        "valid u::rw-,g::r--,o::---",
        None,
    ),
    (
        b"u::rw-\t#c\ng::r--\no::---",
        "valid u::rw-,g::r--,o::---",
        "valid u::rw-,g::r--,o::---",
        None,
    ),
    (
        b"u::rw-,#c\ng::r--\no::---",
        "valid u::rw-,g::r--,o::---",
        "valid u::rw-,g::r--,o::---",
        None,
    ),
    (
        b"u::rw-, #c,g::r--,o::---",
        "invalid 0x3000",
        "invalid Missing { tag: GroupObj }",
        None,
    ),
    (
        b"u::rw-,#c,g::r--,o::---",
        "invalid 0x3000",
        "invalid Missing { tag: GroupObj }",
        None,
    ),
    (
        b"u::r#w-\ng::r--\no::---",
        "valid u::r--,g::r--,o::---",
        "valid u::r--,g::r--,o::---",
        None,
    ),
    (
        b"u#c::rw-\ng::r--\no::---",
        "refused",
        "Tag { at: 0 }",
        None,
    ),
    (
        b"u:#c:rw-\ng::r--\no::---",
        "refused",
        "Qualifier { at: 2 }",
        None,
    ),
    (
        b"u::rw-\ng::r--\ng:hash#g:r--\nm::r--\no::---",
        "valid u::rw-,g::r--,g:4245:r--,m::r--,o::---",
        "valid u::rw-,g::r--,g:4245:r--,m::r--,o::---",
        None,
    ),
    (
        b"u::rw-\ng::r--\ng:hash #g:r--\nm::r--\no::---",
        "valid u::rw-,g::r--,g:4257:r--,m::r--,o::---",
        "valid u::rw-,g::r--,g:4257:r--,m::r--,o::---",
        None,
    ),
    (
        b"u::rw-\ng::r--\ng:4245:#c\nm::r--\no::---",
        "refused",
        "Perm { at: 21 }",
        None,
    ),
    (
        b"u::rw-\n\n#c\n\ng::r--\no::---",
        "valid u::rw-,g::r--,o::---",
        "valid u::rw-,g::r--,o::---",
        None,
    ),
    (
        b"u::rw-\ng::r--\t#effective:r--\nm::r--\no::---",
        "valid u::rw-,g::r--,m::r--,o::---",
        "valid u::rw-,g::r--,m::r--,o::---",
        None,
    ),
    (
        b"u::rw-\ng::r--\no::---  #c",
        "valid u::rw-,g::r--,o::---",
        "valid u::rw-,g::r--,o::---",
        None,
    ),
    (
        b"u::rw- #c #d\ng::r--\no::---",
        "valid u::rw-,g::r--,o::---",
        "valid u::rw-,g::r--,o::---",
        None,
    ),
    (
        b"u::rw-\n#c\ng::r--\no::---",
        "valid u::rw-,g::r--,o::---",
        "valid u::rw-,g::r--,o::---",
        None,
    ),
    (
        b"\n#c\nu::rw-\ng::r--\no::---",
        "refused",
        "LeadingComment { at: 1 }",
        None,
    ),
    (
        b"\n\n#c\nu::rw-\ng::r--\no::---",
        "refused",
        "LeadingComment { at: 2 }",
        None,
    ),
    (
        b" u::rw-\ng::r--\no::---",
        "valid u::rw-,g::r--,o::---",
        "valid u::rw-,g::r--,o::---",
        None,
    ),
    (
        b"\nu::rw-\ng::r--\no::---",
        "valid u::rw-,g::r--,o::---",
        "valid u::rw-,g::r--,o::---",
        None,
    ),
    (
        b"u::rw-\ng::r--\ng:back\\134slashg:r--\nm::r--\no::---",
        "valid u::rw-,g::r--,g:4251:r--,m::r--,o::---",
        "valid u::rw-,g::r--,g:4251:r--,m::r--,o::---",
        None,
    ),
    (
        b"u::rw-\ng::r--\ng:back\\slashg:r--\nm::r--\no::---",
        "valid u::rw-,g::r--,g:4251:r--,m::r--,o::---",
        "valid u::rw-,g::r--,g:4251:r--,m::r--,o::---",
        None,
    ),
    (
        b"u::rw-\ng::r--\ng:back\\\\slashg:r--\nm::r--\no::---",
        "valid u::rw-,g::r--,g:4251:r--,m::r--,o::---",
        "valid u::rw-,g::r--,g:4251:r--,m::r--,o::---",
        None,
    ),
    (
        b"u::rw-\ng::r--\nu:back\\\\slash:r--\nm::r--\no::---",
        "valid u::rw-,u:4250:r--,g::r--,m::r--,o::---",
        "valid u::rw-,u:4250:r--,g::r--,m::r--,o::---",
        None,
    ),
    (
        b"u::rw-\ng::r--\ng:tab\\011g:r--\nm::r--\no::---",
        "valid u::rw-,g::r--,g:4252:r--,m::r--,o::---",
        "valid u::rw-,g::r--,g:4252:r--,m::r--,o::---",
        None,
    ),
    (
        b"u::rw-\ng::r--\ng:tab\tg:r--\nm::r--\no::---",
        "valid u::rw-,g::r--,g:4252:r--,m::r--,o::---",
        "valid u::rw-,g::r--,g:4252:r--,m::r--,o::---",
        None,
    ),
    (
        b"u::rw-\ng::r--\ng:caf\xc3\xa9:r--\nm::r--\no::---",
        "valid u::rw-,g::r--,g:4253:r--,m::r--,o::---",
        "valid u::rw-,g::r--,g:4253:r--,m::r--,o::---",
        None,
    ),
    (
        b"u::rw-\ng::r--\ng:caf\\303\\251:r--\nm::r--\no::---",
        "valid u::rw-,g::r--,g:4253:r--,m::r--,o::---",
        "valid u::rw-,g::r--,g:4253:r--,m::r--,o::---",
        None,
    ),
    (
        b"u::rw-\ng::r--\ng:del\\177g:r--\nm::r--\no::---",
        "valid u::rw-,g::r--,g:4254:r--,m::r--,o::---",
        "valid u::rw-,g::r--,g:4254:r--,m::r--,o::---",
        None,
    ),
    (
        b"u::rw-\ng::r--\ng:del\x7fg:r--\nm::r--\no::---",
        "valid u::rw-,g::r--,g:4254:r--,m::r--,o::---",
        "valid u::rw-,g::r--,g:4254:r--,m::r--,o::---",
        None,
    ),
    (
        b"u::rw-\ng::r--\ng:ctl\\001g:r--\nm::r--\no::---",
        "valid u::rw-,g::r--,g:4255:r--,m::r--,o::---",
        "valid u::rw-,g::r--,g:4255:r--,m::r--,o::---",
        None,
    ),
    (
        b"u::rw-\ng::r--\ng:trail :r--\nm::r--\no::---",
        "valid u::rw-,g::r--,g:4256:r--,m::r--,o::---",
        "valid u::rw-,g::r--,g:4256:r--,m::r--,o::---",
        None,
    ),
    (
        b"u::rw-\ng::r--\ng:trail\\040:r--\nm::r--\no::---",
        "valid u::rw-,g::r--,g:4256:r--,m::r--,o::---",
        "valid u::rw-,g::r--,g:4256:r--,m::r--,o::---",
        None,
    ),
    (
        b"u::rw-\ng::r--\ng:\\400:r--\nm::r--\no::---",
        "valid u::rw-,g::r--,g:0:r--,m::r--,o::---",
        "Escape { at: 16 }",
        Some(ESCAPE),
    ),
    (
        b"u::rw-\ng::r--\ng:\\40:r--\nm::r--\no::---",
        "refused",
        "unresolved",
        None,
    ),
    (
        b"u::rw-\ng::r--\ng:\\domain users:r--\nm::r--\no::---",
        "refused",
        "unresolved",
        None,
    ),
    (
        b"u::rw-\ng::r--\ng:eq=g:r--\nm::r--\no::---",
        "valid u::rw-,g::r--,g:4258:r--,m::r--,o::---",
        "valid u::rw-,g::r--,g:4258:r--,m::r--,o::---",
        None,
    ),
    (
        b"u::rw-\ng::r--\nu:a b:r--\nm::r--\no::---",
        "valid u::rw-,u:4243:r--,g::r--,m::r--,o::---",
        "valid u::rw-,u:4243:r--,g::r--,m::r--,o::---",
        None,
    ),
    (
        b"u::rw-\ng::r--\nu:a\\040b:r--\nm::r--\no::---",
        "valid u::rw-,u:4243:r--,g::r--,m::r--,o::---",
        "valid u::rw-,u:4243:r--,g::r--,m::r--,o::---",
        None,
    ),
    (
        b"u::rw-,u:4242:r--,g::r--,m::rwx,o::---",
        "valid u::rw-,u:4242:r--,g::r--,m::rwx,o::---",
        "valid u::rw-,u:4242:r--,g::r--,m::rwx,o::---",
        None,
    ),
    (
        b"u::rw-,g:4242:r--,g::r--,m::rwx,o::---",
        "valid u::rw-,g::r--,g:4242:r--,m::rwx,o::---",
        "valid u::rw-,g::r--,g:4242:r--,m::rwx,o::---",
        None,
    ),
    (
        b"u::rw-,u:007:r--,g::r--,m::rwx,o::---",
        "valid u::rw-,u:7:r--,g::r--,m::rwx,o::---",
        "Number { at: 9 }",
        Some(LOOSE_NUMBER),
    ),
    (
        b"u::rw-,g:007:r--,g::r--,m::rwx,o::---",
        "valid u::rw-,g::r--,g:7:r--,m::rwx,o::---",
        "Number { at: 9 }",
        Some(LOOSE_NUMBER),
    ),
    (
        b"u::rw-,u:99999999999:r--,g::r--,m::rwx,o::---",
        "valid u::rw-,u:1215752191:r--,g::r--,m::rwx,o::---",
        "Number { at: 9 }",
        Some(LOOSE_NUMBER),
    ),
    (
        b"u::rw-,u:4294967295:r--,g::r--,m::rwx,o::---",
        "invalid 0x2000",
        "invalid UndefinedId { tag: User }",
        None,
    ),
    (
        b"u::rw-,u:+5:r--,g::r--,m::rwx,o::---",
        "valid u::rw-,u:5:r--,g::r--,m::rwx,o::---",
        "Number { at: 9 }",
        Some(LOOSE_NUMBER),
    ),
    (
        b"u::rw-,g:+5:r--,g::r--,m::rwx,o::---",
        "valid u::rw-,g::r--,g:5:r--,m::rwx,o::---",
        "Number { at: 9 }",
        Some(LOOSE_NUMBER),
    ),
    (
        b"u::rw-,us:502:r--,g::r--,m::rwx,o::---",
        "refused",
        "Tag { at: 7 }",
        None,
    ),
    (
        b"u::rw-,use:502:r--,g::r--,m::rwx,o::---",
        "refused",
        "Tag { at: 7 }",
        None,
    ),
    (
        b"u::rw-,usr:502:r--,g::r--,m::rwx,o::---",
        "refused",
        "Tag { at: 7 }",
        None,
    ),
    (
        b"u::rw-,gr:4245:r--,g::r--,m::rwx,o::---",
        "refused",
        "Tag { at: 7 }",
        None,
    ),
    (
        b"u::rw-,grou:4245:r--,g::r--,m::rwx,o::---",
        "refused",
        "Tag { at: 7 }",
        None,
    ),
    (
        b"u::rw-,U:502:r--,g::r--,m::rwx,o::---",
        "refused",
        "Tag { at: 7 }",
        None,
    ),
    (
        b"u::rw-,User:502:r--,g::r--,m::rwx,o::---",
        "refused",
        "Tag { at: 7 }",
        None,
    ),
    (
        b"u::rw-,g::r--,ma::rwx,o::---",
        "refused",
        "Tag { at: 14 }",
        None,
    ),
    (
        b"u::rw-,g::r--,mas::rwx,o::---",
        "refused",
        "Tag { at: 14 }",
        None,
    ),
    (b"u::rw-,g::r--,ot::---", "refused", "Tag { at: 14 }", None),
    (b"u::rw-,g::r--,oth::---", "refused", "Tag { at: 14 }", None),
    (
        b"u::rw-,g::r--,othe::---",
        "refused",
        "Tag { at: 14 }",
        None,
    ),
    (
        b"u::rw-,g::r--,m:5:rwx,o::---",
        "refused",
        "Perm { at: 16 }",
        None,
    ),
    (
        b"u::rw-,g::r--,m:lisa:rwx,o::---",
        "refused",
        "Perm { at: 16 }",
        None,
    ),
    (b"u::rw-,g::r--,o:5:---", "refused", "Perm { at: 16 }", None),
    (
        b"u::rw-,g::r--,m:rwx,o::---",
        "valid u::rw-,g::r--,m::rwx,o::---",
        "valid u::rw-,g::r--,m::rwx,o::---",
        None,
    ),
    (
        b"u::rw-,g::r--,o:---",
        "valid u::rw-,g::r--,o::---",
        "valid u::rw-,g::r--,o::---",
        None,
    ),
    (
        b"user::rw-,group::r--,mask:rwx,other:---",
        "valid u::rw-,g::r--,m::rwx,o::---",
        "valid u::rw-,g::r--,m::rwx,o::---",
        None,
    ),
    (
        b"u:rw-,g::r--,o::---",
        "refused",
        "Incomplete { at: 5 }",
        None,
    ),
    (
        b"u::rw-,g:r--,o::---",
        "refused",
        "Incomplete { at: 12 }",
        None,
    ),
    (
        b"d:u::rw-,d:g::r--,d:o::---",
        "refused",
        "Tag { at: 0 }",
        None,
    ),
    (
        b"default:user::rw-,default:group::r--,default:other::---",
        "refused",
        "Tag { at: 0 }",
        None,
    ),
    (
        b"u::rw-,g::r--,o::---,:502:r--",
        "refused",
        "Tag { at: 21 }",
        None,
    ),
    (
        b"\tu::rw-,g::r--,o::---",
        "valid u::rw-,g::r--,o::---",
        "valid u::rw-,g::r--,o::---",
        None,
    ),
    (
        b"\ru::rw-,g::r--,o::---",
        "valid u::rw-,g::r--,o::---",
        "valid u::rw-,g::r--,o::---",
        None,
    ),
    (
        b"\x0bu::rw-,g::r--,o::---",
        "refused",
        "Tag { at: 0 }",
        None,
    ),
    (
        b"\x0cu::rw-,g::r--,o::---",
        "refused",
        "Tag { at: 0 }",
        None,
    ),
    (
        b"u::rw-\n g::r--\no::---",
        "valid u::rw-,g::r--,o::---",
        "valid u::rw-,g::r--,o::---",
        None,
    ),
    (
        b"u::rw-,\tg::r--,o::---",
        "valid u::rw-,g::r--,o::---",
        "valid u::rw-,g::r--,o::---",
        None,
    ),
    (
        b"u::rw- ,g::r--,o::---",
        "valid u::rw-,g::r--,o::---",
        "valid u::rw-,g::r--,o::---",
        None,
    ),
    (
        b"u::rw-\t,g::r--,o::---",
        "valid u::rw-,g::r--,o::---",
        "valid u::rw-,g::r--,o::---",
        None,
    ),
    (
        b"u::rw-\r\ng::r--\r\no::---\r\n",
        "valid u::rw-,g::r--,o::---",
        "valid u::rw-,g::r--,o::---",
        None,
    ),
    (
        b"u::rw-\rg::r--\ro::---",
        "valid u::rw-,g::r--,o::---",
        "Separator { at: 7 }",
        Some(NO_SEPARATOR),
    ),
    (
        b"u ::rw-,g::r--,o::---",
        "valid u::rw-,g::r--,o::---",
        "Tag { at: 0 }",
        Some(SPACE_AFTER_TAG),
    ),
    (b"u: :rw-,g::r--,o::---", "refused", "unresolved", None),
    (b"u:: rw-,g::r--,o::---", "refused", "Perm { at: 3 }", None),
    (
        b"u::r w,g::r--,o::---",
        "refused",
        "Separator { at: 5 }",
        None,
    ),
    (
        b"u::rw-,g::r--,o::---   ",
        "valid u::rw-,g::r--,o::---",
        "valid u::rw-,g::r--,o::---",
        None,
    ),
    (
        b"u::rw- g::r--,o::---",
        "valid u::rw-,g::r--,o::---",
        "Separator { at: 7 }",
        Some(NO_SEPARATOR),
    ),
    (
        b"u::rw-\tg::r--,o::---",
        "valid u::rw-,g::r--,o::---",
        "Separator { at: 7 }",
        Some(NO_SEPARATOR),
    ),
    (
        b"u::rw-,u: 502:r--,g::r--,m::rwx,o::---",
        "valid u::rw-,u:502:r--,g::r--,m::rwx,o::---",
        "Number { at: 9 }",
        Some(LOOSE_NUMBER),
    ),
    (
        b"u::rw-,u:502 :r--,g::r--,m::rwx,o::---",
        "refused",
        "unresolved",
        None,
    ),
    (
        b"u::rw-,u:5 02:r--,g::r--,m::rwx,o::---",
        "refused",
        "unresolved",
        None,
    ),
    (
        b"u::rw-,g:hash\t#g:r--,g::r--,m::rwx,o::---",
        "refused",
        "unresolved",
        None,
    ),
    (
        b"u::rw-,u:lisa:rw- :502,g::r--,m::rwx,o::---",
        "refused",
        "Separator { at: 18 }",
        None,
    ),
    (b"u::rw-,,g::r--,o::---", "refused", "Tag { at: 7 }", None),
    (b",u::rw-,g::r--,o::---", "refused", "Tag { at: 0 }", None),
    (
        b"u::rw-,g::r--,o::---,",
        "valid u::rw-,g::r--,o::---",
        "valid u::rw-,g::r--,o::---",
        None,
    ),
    (
        b"u::rw-\n,\ng::r--\no::---",
        "valid u::rw-,g::r--,o::---",
        "Tag { at: 7 }",
        Some(STRAY_COMMA),
    ),
    (b"u::rw-, ,g::r--,o::---", "refused", "Tag { at: 8 }", None),
    (
        b"u::rw-\n\n\ng::r--\no::---\n\n",
        "valid u::rw-,g::r--,o::---",
        "valid u::rw-,g::r--,o::---",
        None,
    ),
    (
        b"u::rw-,g:0010:r--,g::r--,m::rwx,o::---",
        "valid u::rw-,g::r--,g:8:r--,m::rwx,o::---",
        "Number { at: 9 }",
        Some(LOOSE_NUMBER),
    ),
    (
        b"u::rw-,g:4294967294:r--,g::r--,m::rwx,o::---",
        "valid u::rw-,g::r--,g:4294967294:r--,m::rwx,o::---",
        "valid u::rw-,g::r--,g:4294967294:r--,m::rwx,o::---",
        None,
    ),
    (
        b"u::rw-,g:4294967295:r--,g::r--,m::rwx,o::---",
        "invalid 0x2000",
        "invalid UndefinedId { tag: Group }",
        None,
    ),
    (
        b"u::rw-,g:4294967296:r--,g::r--,m::rwx,o::---",
        "valid u::rw-,g::r--,g:0:r--,m::rwx,o::---",
        "Number { at: 9 }",
        Some(LOOSE_NUMBER),
    ),
    (
        b"u::rw-,g:4294967297:r--,g::r--,m::rwx,o::---",
        "valid u::rw-,g::r--,g:1:r--,m::rwx,o::---",
        "Number { at: 9 }",
        Some(LOOSE_NUMBER),
    ),
    (
        b"u::rw-,g:99999999999999999999:r--,g::r--,m::rwx,o::---",
        "invalid 0x2000",
        "Number { at: 9 }",
        Some(LOOSE_NUMBER),
    ),
    (
        b"u::rw-,g:-1:r--,g::r--,m::rwx,o::---",
        "valid u::rw-,g::r--,g:65535:r--,m::rwx,o::---",
        "Number { at: 9 }",
        Some(LOOSE_NUMBER),
    ),
    (
        b"u::rw-,g:-2:r--,g::r--,m::rwx,o::---",
        "valid u::rw-,g::r--,g:65534:r--,m::rwx,o::---",
        "Number { at: 9 }",
        Some(LOOSE_NUMBER),
    ),
    (
        b"u::rw-,g:0x10:r--,g::r--,m::rwx,o::---",
        "valid u::rw-,g::r--,g:16:r--,m::rwx,o::---",
        "Number { at: 9 }",
        Some(LOOSE_NUMBER),
    ),
    (
        b"u::rw-,g:010:r--,g::r--,m::rwx,o::---",
        "valid u::rw-,g::r--,g:8:r--,m::rwx,o::---",
        "Number { at: 9 }",
        Some(LOOSE_NUMBER),
    ),
    (
        b"u::rw-,g:0b0:r--,g::r--,m::rwx,o::---",
        "valid u::rw-,g::r--,g:0:r--,m::rwx,o::---",
        "Number { at: 9 }",
        Some(LOOSE_NUMBER),
    ),
    (
        b"u::rw-,g:0b1:r--,g::r--,m::rwx,o::---",
        "valid u::rw-,g::r--,g:1:r--,m::rwx,o::---",
        "Number { at: 9 }",
        Some(LOOSE_NUMBER),
    ),
    (
        b"u::rw-,g:0B11:r--,g::r--,m::rwx,o::---",
        "valid u::rw-,g::r--,g:3:r--,m::rwx,o::---",
        "Number { at: 9 }",
        Some(LOOSE_NUMBER),
    ),
    (
        b"u::rw-,g: 0b1:r--,g::r--,m::rwx,o::---",
        "valid u::rw-,g::r--,g:1:r--,m::rwx,o::---",
        "Number { at: 9 }",
        Some(LOOSE_NUMBER),
    ),
    (
        b"u::rw-,g:+0b101:r--,g::r--,m::rwx,o::---",
        "valid u::rw-,g::r--,g:5:r--,m::rwx,o::---",
        "Number { at: 9 }",
        Some(LOOSE_NUMBER),
    ),
    (
        b"u::rw-,g:-0b1:r--,g::r--,m::rwx,o::---",
        "valid u::rw-,g::r--,g:65535:r--,m::rwx,o::---",
        "Number { at: 9 }",
        Some(LOOSE_NUMBER),
    ),
    (
        b"u::rw-,u:0b1111101000:r--,g::r--,m::rwx,o::---",
        "valid u::rw-,u:1000:r--,g::r--,m::rwx,o::---",
        "Number { at: 9 }",
        Some(LOOSE_NUMBER),
    ),
    (
        b"u::rw-,g:\\060\\142\\060:r--,g::r--,m::rwx,o::---",
        "valid u::rw-,g::r--,g:0:r--,m::rwx,o::---",
        "Number { at: 9 }",
        Some(LOOSE_NUMBER),
    ),
    (
        b"u::rw-,g:0b:r--,g::r--,m::rwx,o::---",
        "refused",
        "unresolved",
        None,
    ),
    (
        b"u::rw-,g:0b2:r--,g::r--,m::rwx,o::---",
        "refused",
        "unresolved",
        None,
    ),
    (
        b"u::rw-,g:0b12:r--,g::r--,m::rwx,o::---",
        "refused",
        "unresolved",
        None,
    ),
    (
        b"u::rw-,g:1e3:r--,g::r--,m::rwx,o::---",
        "valid u::rw-,g::r--,g:5023:r--,m::rwx,o::---",
        "valid u::rw-,g::r--,g:5023:r--,m::rwx,o::---",
        None,
    ),
    (
        b"u::rw-,g:5x:r--,g::r--,m::rwx,o::---",
        "refused",
        "unresolved",
        None,
    ),
    (
        b"u::rw-,g:0:r--,g::r--,m::rwx,o::---",
        "valid u::rw-,g::r--,g:0:r--,m::rwx,o::---",
        "valid u::rw-,g::r--,g:0:r--,m::rwx,o::---",
        None,
    ),
    (
        b"u::rw-,g:\\043gstart:r--,g::r--,m::rwx,o::---",
        "refused",
        "unresolved",
        None,
    ),
    (
        b"u::rw-,g:#gstart:r--,g::r--,m::rwx,o::---",
        "refused",
        "Qualifier { at: 9 }",
        None,
    ),
    (
        b"u::rw-,g:\\040glead:r--,g::r--,m::rwx,o::---",
        "refused",
        "unresolved",
        None,
    ),
    (
        b"u::rw-,g: glead:r--,g::r--,m::rwx,o::---",
        "refused",
        "unresolved",
        None,
    ),
    (
        b"u::rw-,g:x\\:r--,g::r--,m::rwx,o::---",
        "valid u::rw-,g::r--,g:5010:r--,m::rwx,o::---",
        "valid u::rw-,g::r--,g:5010:r--,m::rwx,o::---",
        None,
    ),
    (
        b"u::rw-,g:x\\\\:r--,g::r--,m::rwx,o::---",
        "valid u::rw-,g::r--,g:5010:r--,m::rwx,o::---",
        "valid u::rw-,g::r--,g:5010:r--,m::rwx,o::---",
        None,
    ),
    (
        b"u::rw-,g:a\\4:r--,g::r--,m::rwx,o::---",
        "valid u::rw-,g::r--,g:5031:r--,m::rwx,o::---",
        "valid u::rw-,g::r--,g:5031:r--,m::rwx,o::---",
        None,
    ),
    (
        b"u::rw-,g:a\\40:r--,g::r--,m::rwx,o::---",
        "refused",
        "unresolved",
        None,
    ),
    (
        b"u::rw-,g:a\\40b:r--,g::r--,m::rwx,o::---",
        "valid u::rw-,g::r--,g:5030:r--,m::rwx,o::---",
        "valid u::rw-,g::r--,g:5030:r--,m::rwx,o::---",
        None,
    ),
    (
        b"u::rw-,g:a\\400:r--,g::r--,m::rwx,o::---",
        "valid u::rw-,g::r--,g:5036:r--,m::rwx,o::---",
        "Escape { at: 10 }",
        Some(ESCAPE),
    ),
    (
        b"u::rw-,g:a\\777:r--,g::r--,m::rwx,o::---",
        "refused",
        "Escape { at: 10 }",
        None,
    ),
    (
        b"u::rw-,g:a\\000b:r--,g::r--,m::rwx,o::---",
        "valid u::rw-,g::r--,g:5036:r--,m::rwx,o::---",
        "Escape { at: 10 }",
        Some(ESCAPE),
    ),
    (
        b"u::rw-,g:\\000:r--,g::r--,m::rwx,o::---",
        "valid u::rw-,g::r--,g:0:r--,m::rwx,o::---",
        "Escape { at: 9 }",
        Some(ESCAPE),
    ),
    (
        b"u::rw-,g:a\\08b:r--,g::r--,m::rwx,o::---",
        "valid u::rw-,g::r--,g:5034:r--,m::rwx,o::---",
        "valid u::rw-,g::r--,g:5034:r--,m::rwx,o::---",
        None,
    ),
    (
        b"u::rw-,g:a\\8b:r--,g::r--,m::rwx,o::---",
        "valid u::rw-,g::r--,g:5032:r--,m::rwx,o::---",
        "valid u::rw-,g::r--,g:5032:r--,m::rwx,o::---",
        None,
    ),
    (
        b"u::rw-,g:a\\072b:r--,g::r--,m::rwx,o::---",
        "refused",
        "unresolved",
        None,
    ),
    (
        b"u::rw-,g:4\\0642\\0642:r--,g::r--,m::rwx,o::---",
        "valid u::rw-,g::r--,g:44242:r--,m::rwx,o::---",
        "valid u::rw-,g::r--,g:44242:r--,m::rwx,o::---",
        None,
    ),
    (
        b"u::rw-,g:a\\nb:r--,g::r--,m::rwx,o::---",
        "valid u::rw-,g::r--,g:5035:r--,m::rwx,o::---",
        "valid u::rw-,g::r--,g:5035:r--,m::rwx,o::---",
        None,
    ),
    (
        b"\\165::rw-,g::r--,o::---",
        "refused",
        "Tag { at: 0 }",
        None,
    ),
    (
        b"u::\\162w-,g::r--,o::---",
        "refused",
        "Perm { at: 3 }",
        None,
    ),
    (
        b"u::rw-,u:lisa:rw-:\\06502,g::r--,m::rwx,o::---",
        "refused",
        "Id { at: 18 }",
        None,
    ),
    (
        b"u::-,g::r--,o::---",
        "valid u::---,g::r--,o::---",
        "valid u::---,g::r--,o::---",
        None,
    ),
    (
        b"u::x,g::r--,o::---",
        "valid u::--x,g::r--,o::---",
        "valid u::--x,g::r--,o::---",
        None,
    ),
    (
        b"u::rx-,g::r--,o::---",
        "valid u::r-x,g::r--,o::---",
        "valid u::r-x,g::r--,o::---",
        None,
    ),
    (
        b"u::--x,g::r--,o::---",
        "valid u::--x,g::r--,o::---",
        "valid u::--x,g::r--,o::---",
        None,
    ),
    (
        b"u::-x-,g::r--,o::---",
        "valid u::--x,g::r--,o::---",
        "valid u::--x,g::r--,o::---",
        None,
    ),
    (b"u::w-w,g::r--,o::---", "refused", "Perm { at: 3 }", None),
    (b"u::R,g::r--,o::---", "refused", "Perm { at: 3 }", None),
    (
        b"u::rw-,u:lisa:rw-:,g::r--,m::rwx,o::---",
        "refused",
        "Id { at: 18 }",
        None,
    ),
    (
        b"u::rw-,u:lisa:rw-::,g::r--,m::rwx,o::---",
        "refused",
        "Id { at: 18 }",
        None,
    ),
    (
        b"u::rw-,u:lisa:rw-:502:5,g::r--,m::rwx,o::---",
        "refused",
        "Id { at: 18 }",
        None,
    ),
    (b"u::rw-x,g::r--,o::---", "refused", "Perm { at: 3 }", None),
    (
        b"u::rwx#c\ng::r--\no::---",
        "valid u::rwx,g::r--,o::---",
        "valid u::rwx,g::r--,o::---",
        None,
    ),
    (
        b"u::rw#x\ng::r--\no::---",
        "valid u::rw-,g::r--,o::---",
        "valid u::rw-,g::r--,o::---",
        None,
    ),
    (
        b"u::rwx#c,g::r--,o::---",
        "invalid 0x3000",
        "invalid Missing { tag: GroupObj }",
        None,
    ),
    (
        b"u::rw-,g:08:r--,g::r--,m::rwx,o::---",
        "valid u::rw-,g::r--,g:5020:r--,m::rwx,o::---",
        "valid u::rw-,g::r--,g:5020:r--,m::rwx,o::---",
        None,
    ),
    (
        b"u::rw-,g:0x:r--,g::r--,m::rwx,o::---",
        "valid u::rw-,g::r--,g:5021:r--,m::rwx,o::---",
        "valid u::rw-,g::r--,g:5021:r--,m::rwx,o::---",
        None,
    ),
    (
        b"u::rw-,g:3dg:r--,g::r--,m::rwx,o::---",
        "valid u::rw-,g::r--,g:5022:r--,m::rwx,o::---",
        "valid u::rw-,g::r--,g:5022:r--,m::rwx,o::---",
        None,
    ),
    (
        b"u::rw-,g:+:r--,g::r--,m::rwx,o::---",
        "refused",
        "unresolved",
        None,
    ),
    (
        b"u::rw-,g:-:r--,g::r--,m::rwx,o::---",
        "refused",
        "unresolved",
        None,
    ),
    (
        b"u::rw-,g:0x1g:r--,g::r--,m::rwx,o::---",
        "valid u::rw-,g::r--,g:5026:r--,m::rwx,o::---",
        "valid u::rw-,g::r--,g:5026:r--,m::rwx,o::---",
        None,
    ),
    (
        b"u::rw-,g:+x:r--,g::r--,m::rwx,o::---",
        "refused",
        "unresolved",
        None,
    ),
    (
        b"u::rw-,g:comma,g:r--,g::r--,m::rwx,o::---",
        "refused",
        "Incomplete { at: 14 }",
        None,
    ),
    (
        b"u::rw-,g:a\nb:r--,g::r--,m::rwx,o::---",
        "refused",
        "LineEnd { at: 10 }",
        None,
    ),
    (
        b"u::rw-,g:sp ace:r--,g::r--,m::rwx,o::---",
        "valid u::rw-,g::r--,g:5037:r--,m::rwx,o::---",
        "valid u::rw-,g::r--,g:5037:r--,m::rwx,o::---",
        None,
    ),
    (
        b"u::rw-,g:cr\rg:r--,g::r--,m::rwx,o::---",
        "refused",
        "LineEnd { at: 11 }",
        None,
    ),
    (
        b"u::rw-,g::r--,m:rwx:,o::---",
        "refused",
        "Id { at: 19 }",
        None,
    ),
    (
        b"u::rw-,g::r--,m::rwx:,o::---",
        "refused",
        "Id { at: 20 }",
        None,
    ),
    (b"u::rw-,g::r--,o:r--:5", "refused", "Id { at: 19 }", None),
    (
        b"u::rw-,g::r--,o:r-- #c",
        "valid u::rw-,g::r--,o::r--",
        "valid u::rw-,g::r--,o::r--",
        None,
    ),
    (
        b"u::rw-,g::r--,m:,o::---",
        "refused",
        "Perm { at: 16 }",
        None,
    ),
    (b"u::rw-:5,g::r--,o::---", "refused", "Id { at: 7 }", None),
    (
        b"u::rw-,g::r--,o::---,\n",
        "valid u::rw-,g::r--,o::---",
        "valid u::rw-,g::r--,o::---",
        None,
    ),
    (
        b"u::rw-,g::r--,o::---\n,",
        "valid u::rw-,g::r--,o::---",
        "Tag { at: 21 }",
        Some(STRAY_COMMA),
    ),
    (b"u::rw-,\n,g::r--,o::---", "refused", "Tag { at: 8 }", None),
    (
        b"u\n::rw-,g::r--,o::---",
        "valid u::rw-,g::r--,o::---",
        "Tag { at: 0 }",
        Some(SPACE_AFTER_TAG),
    ),
    (
        b"u::rw-\n#c\n,g::r--,o::---",
        "refused",
        "Tag { at: 10 }",
        None,
    ),
    (
        b"u::rw-,g::r--,o::---,#c",
        "valid u::rw-,g::r--,o::---",
        "valid u::rw-,g::r--,o::---",
        None,
    ),
    (b"", "invalid 0x3000", "no list", Some(EMPTY)),
    (b"\n", "refused", "NoEntry", None),
    (b" ", "refused", "NoEntry", None),
    (b",", "refused", "Tag { at: 0 }", None),
    (b"#c", "refused", "LeadingComment { at: 0 }", None),
    (b"\n#c\n", "refused", "LeadingComment { at: 1 }", None),
    (
        b"u::rw- #c\rg::r--\ro::---",
        "invalid 0x3000",
        "invalid Missing { tag: GroupObj }",
        None,
    ),
    (
        b"u::rw-\r#c\rg::r--\ro::---",
        "invalid 0x3000",
        "invalid Missing { tag: GroupObj }",
        None,
    ),
    (
        b"u::rw-\r\n#c\r\ng::r--\r\no::---",
        "valid u::rw-,g::r--,o::---",
        "valid u::rw-,g::r--,o::---",
        None,
    ),
    (
        b"u::rw-\r",
        "invalid 0x3000",
        "invalid Missing { tag: GroupObj }",
        None,
    ),
    (
        b"u::rw-,\rg::r--,o::---",
        "valid u::rw-,g::r--,o::---",
        "valid u::rw-,g::r--,o::---",
        None,
    ),
    (b"u::rw-,\r,g::r--,o::---", "refused", "Tag { at: 8 }", None),
    (
        b"\ru::rw-",
        "invalid 0x3000",
        "invalid Missing { tag: GroupObj }",
        None,
    ),
    (
        b"u::rw-\x0b,g::r--,o::---",
        "refused",
        "Perm { at: 3 }",
        None,
    ),
    (
        b"u::rw-\x0c\ng::r--\no::---",
        "refused",
        "Perm { at: 3 }",
        None,
    ),
    (
        b"u::rw-\n\x0bg::r--\no::---",
        "refused",
        "Tag { at: 7 }",
        None,
    ),
    (
        b"u\t::rw-,g::r--,o::---",
        "valid u::rw-,g::r--,o::---",
        "Tag { at: 0 }",
        Some(SPACE_AFTER_TAG),
    ),
    (
        b"u::rw-,u:lisa:rw-:502,g::r--,m::rwx,o::---",
        "refused",
        "valid u::rw-,u:502:rw-,g::r--,m::rwx,o::---",
        Some(FOURTH_FIELD),
    ),
    (
        b"u::rw-,u:lisa:rw-:9000,g::r--,m::rwx,o::---",
        "refused",
        "valid u::rw-,u:502:rw-,g::r--,m::rwx,o::---",
        Some(FOURTH_FIELD),
    ),
    (
        b"u::rw-,u:nosuch:rw-:5000,g::r--,m::rwx,o::---",
        "refused",
        "valid u::rw-,u:5000:rw-,g::r--,m::rwx,o::---",
        Some(FOURTH_FIELD),
    ),
    (
        b"u::rw-,u:502:rw-:502,g::r--,m::rwx,o::---",
        "refused",
        "valid u::rw-,u:502:rw-,g::r--,m::rwx,o::---",
        Some(FOURTH_FIELD),
    ),
    (
        b"u::rw-,u:502:rw-:503,g::r--,m::rwx,o::---",
        "refused",
        "IdMismatch { at: 17 }",
        None,
    ),
    (
        b"u::rwx,u::rw-:502,g::r-x,m::rwx,o::r--",
        "refused",
        "Id { at: 14 }",
        None,
    ),
    (
        b"u::rw-,g::r--,g:wheel:r--:10,m::r--,o::---",
        "refused",
        "valid u::rw-,g::r--,g:10:r--,m::r--,o::---",
        Some(FOURTH_FIELD),
    ),
    (
        b"u::rw-,#c\n#d\ng::r--,o::---",
        "refused",
        "Comment { at: 7 }",
        None,
    ),
    (b"u::rw-,#c\n#d", "refused", "Comment { at: 7 }", None),
    (
        b"u::rw-\n#c\n#d\ng::r--,o::---",
        "refused",
        "Comment { at: 7 }",
        None,
    ),
    (
        b"u::rw-,#c\n\n#d\ng::r--",
        "refused",
        "Comment { at: 7 }",
        None,
    ),
    (
        b"u::rw- #c\n#d\ng::r--",
        "refused",
        "Comment { at: 7 }",
        None,
    ),
    (
        b"u::rw-\n#c\n\n#d\ng::r--",
        "refused",
        "Comment { at: 7 }",
        None,
    ),
    (
        b"u::rw-\n#c\ng::r--\n#d\no::---",
        "valid u::rw-,g::r--,o::---",
        "valid u::rw-,g::r--,o::---",
        None,
    ),
    (
        b"u::rw-,#c\ng::r--",
        "invalid 0x3000",
        "invalid Missing { tag: Other }",
        None,
    ),
    (
        b"u::rw-,#c\n #d\ng::r--",
        "refused",
        "Comment { at: 7 }",
        None,
    ),
    (b"u::rw-\n#c\n#d", "refused", "Comment { at: 7 }", None),
    (b"u::rw- #c\n#d", "refused", "Comment { at: 7 }", None),
    (b"u::rw-#c\n#d\n", "refused", "Comment { at: 6 }", None),
    (b"u::rw-\n#c\n\n", "refused", "Comment { at: 7 }", None),
    (
        b"u::rw-,\n#c\ng::r--",
        "invalid 0x3000",
        "invalid Missing { tag: Other }",
        None,
    ),
    (
        b"u::rw-,\n#c\n#d\ng::r--",
        "refused",
        "Comment { at: 8 }",
        None,
    ),
    (
        b"u::rw-\n\n#c\n#d\n\ng::r--",
        "refused",
        "Comment { at: 8 }",
        None,
    ),
    (b"u::rw-,#c\n,g::r--", "refused", "Tag { at: 10 }", None),
    (b"u::rw-\n#c\n", "refused", "Comment { at: 7 }", None),
    (b"u::rw-\n#c\n ", "refused", "Comment { at: 7 }", None),
    (b"u::rw-\n#c\r\n", "refused", "Comment { at: 7 }", None),
    (b"u::rw-\n#c\n\r", "refused", "Comment { at: 7 }", None),
    (b"u::rw- #c\n\n", "refused", "Comment { at: 7 }", None),
    (b"u::rw- #c\n", "refused", "Comment { at: 7 }", None),
    (
        b"u::rw-,g::r--,o::--- #c\n",
        "refused",
        "Comment { at: 21 }",
        None,
    ),
    (
        b"u::rw-,g::r--,o::---,#c\n",
        "refused",
        "Comment { at: 21 }",
        None,
    ),
    (
        b"u::rw-,g::r--,o::---\n#c\n",
        "refused",
        "Comment { at: 21 }",
        None,
    ),
    (
        b"u::rw-\n#c\n g::r--",
        "invalid 0x3000",
        "invalid Missing { tag: Other }",
        None,
    ),
    (
        b"u::rw-\n#c\n\t\ng::r--",
        "invalid 0x3000",
        "invalid Missing { tag: Other }",
        None,
    ),
    (b"u::rw-,#c\n", "refused", "Comment { at: 7 }", None),
    (
        b"u::rw-,#c",
        "invalid 0x3000",
        "invalid Missing { tag: GroupObj }",
        None,
    ),
    (
        b"u::rw-\n#c",
        "invalid 0x3000",
        "invalid Missing { tag: GroupObj }",
        None,
    ),
    (
        b"u::rw-\n #c\ng::r--",
        "invalid 0x3000",
        "invalid Missing { tag: Other }",
        None,
    ),
    (
        b"u::rw-,\n\n#c\ng::r--",
        "invalid 0x3000",
        "invalid Missing { tag: Other }",
        None,
    ),
    (
        b"u::rw-,\n #c\n\ng::r--",
        "invalid 0x3000",
        "invalid Missing { tag: Other }",
        None,
    ),
    (
        b"u::rw-,g::r--,m::rwx,o::---,g:\n4242:r--",
        "valid u::rw-,g::r--,g:4242:r--,m::rwx,o::---",
        "Number { at: 30 }",
        Some(LOOSE_NUMBER),
    ),
    (
        b"u::rw-,g::r--,m::rwx,o::---,g:4242\n:r--",
        "refused",
        "LineEnd { at: 34 }",
        None,
    ),
    (
        b"u::rw-,g::r--,m::rwx,o::---,g:,4242:r--",
        "refused",
        "Incomplete { at: 30 }",
        None,
    ),
    (
        b"u::rw-,g::r--,m::rwx,o::---,g:4242,:r--",
        "refused",
        "Incomplete { at: 34 }",
        None,
    ),
    (
        b"u::rw-,g::r--,m::rwx,o::---,g:\n,4242:r--",
        "refused",
        "LineEnd { at: 30 }",
        None,
    ),
    (
        b"u::rw-,g::r--,m::rwx,o::---,g: ,4242:r--",
        "refused",
        "Incomplete { at: 31 }",
        None,
    ),
    (
        b"u::rw-,g::r--,m::rwx,o::---,g:\t4242:r--",
        "valid u::rw-,g::r--,g:4242:r--,m::rwx,o::---",
        "Number { at: 30 }",
        Some(LOOSE_NUMBER),
    ),
    (
        b"u::rw-,g::r--,m::rwx,o::---,g:\r\n4242:r--",
        "valid u::rw-,g::r--,g:4242:r--,m::rwx,o::---",
        "Number { at: 30 }",
        Some(LOOSE_NUMBER),
    ),
    (
        b"u::rw-,g::r--,m::rwx,o::---,g:\n\n7:r--",
        "valid u::rw-,g::r--,g:7:r--,m::rwx,o::---",
        "Number { at: 30 }",
        Some(LOOSE_NUMBER),
    ),
    (
        b"u::rw-,g::r--,m::rwx,o::---,g:\n:r--",
        "refused",
        "LineEnd { at: 30 }",
        None,
    ),
    (
        b"u::rw-,g::r--,m::rwx,o::---,g:,:r--",
        "refused",
        "Incomplete { at: 30 }",
        None,
    ),
    (
        b"u::rw-,g::r--,m::rwx,o::---,g:\n\t5:r--",
        "valid u::rw-,g::r--,g:5:r--,m::rwx,o::---",
        "Number { at: 30 }",
        Some(LOOSE_NUMBER),
    ),
    (
        b"u::rw-,g::r--,m::rwx,o::---,g:5\n5:r--",
        "refused",
        "LineEnd { at: 31 }",
        None,
    ),
    (
        b"u::rw-,g::r--,m::rwx,o::---,g:#5:r--",
        "refused",
        "Qualifier { at: 30 }",
        None,
    ),
    (
        b"u::rw-,g::r--,m::rwx,o::---,g:\n#5:r--",
        "refused",
        "LineEnd { at: 30 }",
        None,
    ),
    (
        b"u::rw-,g::r--,m::rwx,o::---,g: #5:r--",
        "refused",
        "unresolved",
        None,
    ),
    (
        b"u::rw-,g::r--,m::rwx,o::---,g:5#:r--",
        "refused",
        "unresolved",
        None,
    ),
    (
        b"u::rw-,g::r--,m::rwx,o::---,g:\x0b5:r--",
        "valid u::rw-,g::r--,g:5:r--,m::rwx,o::---",
        "Number { at: 30 }",
        Some(LOOSE_NUMBER),
    ),
    (
        b"u::rw-,g::r--,m::rwx,o::---,g:\x0c5:r--",
        "valid u::rw-,g::r--,g:5:r--,m::rwx,o::---",
        "Number { at: 30 }",
        Some(LOOSE_NUMBER),
    ),
    (
        b"u::rw-,g::r--,m::rwx,o::---,g:\n+5:r--",
        "valid u::rw-,g::r--,g:5:r--,m::rwx,o::---",
        "Number { at: 30 }",
        Some(LOOSE_NUMBER),
    ),
    (
        b"u::rw-,g::r--,m::rwx,o::---,g:\n0x10:r--",
        "valid u::rw-,g::r--,g:16:r--,m::rwx,o::---",
        "Number { at: 30 }",
        Some(LOOSE_NUMBER),
    ),
    (
        b"u::rw-,g::r--,m: :rwx,o::---",
        "valid u::rw-,g::r--,m::rwx,o::---",
        "Perm { at: 16 }",
        Some(SPACE_AFTER_TAG),
    ),
    (
        b"u::rw-,g::r--,m:\t:rwx,o::---",
        "valid u::rw-,g::r--,m::rwx,o::---",
        "Perm { at: 16 }",
        Some(SPACE_AFTER_TAG),
    ),
    (
        b"u::rw-,g::r--,m:  :rwx,o::---",
        "valid u::rw-,g::r--,m::rwx,o::---",
        "Perm { at: 16 }",
        Some(SPACE_AFTER_TAG),
    ),
    (
        b"u::rw-,g::r--,m: rwx,o::---",
        "valid u::rw-,g::r--,m::rwx,o::---",
        "Perm { at: 16 }",
        Some(SPACE_AFTER_TAG),
    ),
    (
        b"u::rw-,g::r--,m:: rwx,o::---",
        "refused",
        "Perm { at: 17 }",
        None,
    ),
    (
        b"u::rw-,g::r--,m:\r:rwx,o::---",
        "valid u::rw-,g::r--,m::rwx,o::---",
        "Perm { at: 16 }",
        Some(SPACE_AFTER_TAG),
    ),
    (
        b"u::rw-,g::r--,m :rwx,o::---",
        "valid u::rw-,g::r--,m::rwx,o::---",
        "Tag { at: 14 }",
        Some(SPACE_AFTER_TAG),
    ),
    (
        b"u::rw-,g::r--,m: : rwx,o::---",
        "refused",
        "Perm { at: 16 }",
        None,
    ),
    (
        b"u::rw-,g::r--,m:\n:rwx,o::---",
        "valid u::rw-,g::r--,m::rwx,o::---",
        "Perm { at: 16 }",
        Some(SPACE_AFTER_TAG),
    ),
    (
        b"u::rw-,g::r--,m:\x0b:rwx,o::---",
        "refused",
        "Perm { at: 16 }",
        None,
    ),
    (
        b"u::rw-,g::r--,mask: :rwx,o::---",
        "valid u::rw-,g::r--,m::rwx,o::---",
        "Perm { at: 19 }",
        Some(SPACE_AFTER_TAG),
    ),
    (
        b"u::rw-,g::r--,m: x :rwx,o::---",
        "refused",
        "Perm { at: 16 }",
        None,
    ),
    (
        b"u::rw-,g::r--,o: :r--",
        "valid u::rw-,g::r--,o::r--",
        "Perm { at: 16 }",
        Some(SPACE_AFTER_TAG),
    ),
    (
        b"u::rw-,g::r--,o:\t:r--",
        "valid u::rw-,g::r--,o::r--",
        "Perm { at: 16 }",
        Some(SPACE_AFTER_TAG),
    ),
    (
        b"u::rw-,g::r--,o: r--",
        "valid u::rw-,g::r--,o::r--",
        "Perm { at: 16 }",
        Some(SPACE_AFTER_TAG),
    ),
    (
        b"u::rw-,g::r--,other: :r--",
        "valid u::rw-,g::r--,o::r--",
        "Perm { at: 20 }",
        Some(SPACE_AFTER_TAG),
    ),
    (
        b"u::rw-,g::r--,o -w-",
        "valid u::rw-,g::r--,o::-w-",
        "Tag { at: 14 }",
        Some(SPACE_AFTER_TAG),
    ),
    (
        b"u::rw-,g::r--,o\n-w-",
        "valid u::rw-,g::r--,o::-w-",
        "Tag { at: 14 }",
        Some(SPACE_AFTER_TAG),
    ),
    (
        b"u::rw-,g::r--,o-w-",
        "valid u::rw-,g::r--,o::-w-",
        "Tag { at: 14 }",
        Some(SPACE_AFTER_TAG),
    ),
    (
        b"u::rw-,g::r--,o\t-w-",
        "valid u::rw-,g::r--,o::-w-",
        "Tag { at: 14 }",
        Some(SPACE_AFTER_TAG),
    ),
    (
        b"u::rw-,g::r--,other -w-",
        "valid u::rw-,g::r--,o::-w-",
        "Tag { at: 14 }",
        Some(SPACE_AFTER_TAG),
    ),
    (
        b"u::rw-,g::r--,o #c\n-w-",
        "valid u::rw-,g::r--,o::-w-",
        "Tag { at: 14 }",
        Some(SPACE_AFTER_TAG),
    ),
    (
        b"u::rw-,g::r--,o #c\n:-w-",
        "valid u::rw-,g::r--,o::-w-",
        "Tag { at: 14 }",
        Some(SPACE_AFTER_TAG),
    ),
    (
        b"u::rw-,g::r--,o #c\n::-w-",
        "refused",
        "Tag { at: 14 }",
        None,
    ),
    (
        b"u::rw-,g::r--,o\n:\n-w-",
        "valid u::rw-,g::r--,o::-w-",
        "Tag { at: 14 }",
        Some(SPACE_AFTER_TAG),
    ),
    (
        b"u::rw-,g::r--,m rwx,o::---",
        "valid u::rw-,g::r--,m::rwx,o::---",
        "Tag { at: 14 }",
        Some(SPACE_AFTER_TAG),
    ),
    (
        b"u::rw-,g::r--,m #c\nrwx,o::---",
        "valid u::rw-,g::r--,m::rwx,o::---",
        "Tag { at: 14 }",
        Some(SPACE_AFTER_TAG),
    ),
    (
        b"u::rw-,g::r--,mrwx,o::---",
        "valid u::rw-,g::r--,m::rwx,o::---",
        "Tag { at: 14 }",
        Some(SPACE_AFTER_TAG),
    ),
    (
        b"u::rw-,g::r--,orwx",
        "valid u::rw-,g::r--,o::rwx",
        "Tag { at: 14 }",
        Some(SPACE_AFTER_TAG),
    ),
    (b"u::rw-,g::r--,o#::rw-", "refused", "Tag { at: 14 }", None),
    (b"u::rw-,g::r--,o#c::r--", "refused", "Tag { at: 14 }", None),
    (
        b"u::rw-,g::r--,m#::rwx,o::---",
        "refused",
        "Tag { at: 14 }",
        None,
    ),
    (b"u::rw-,g::r--,o#", "refused", "Tag { at: 14 }", None),
    (
        b"u::rw-,g::r--,o#\nm::rwx",
        "refused",
        "Tag { at: 14 }",
        None,
    ),
    (
        b"u::rw-,g::r--,other#::r--",
        "refused",
        "Tag { at: 14 }",
        None,
    ),
    (
        b"u::rw-,g::r--,mask#::rwx,o::---",
        "refused",
        "Tag { at: 14 }",
        None,
    ),
    (b"u::rw-,g::r--,o #::r--", "refused", "Tag { at: 14 }", None),
    (b"u::rw-,g::r--,o:#:r--", "refused", "Perm { at: 16 }", None),
    (
        b"u::rw-,g::r--,m:#:rwx,o::---",
        "refused",
        "Perm { at: 16 }",
        None,
    ),
    (b"u:\t:rw-,g::r--,o::---", "refused", "unresolved", None),
    (b"u::rw-,g: :r--,o::---", "refused", "unresolved", None),
    (b"u::rw-,g:\t:r--,o::---", "refused", "unresolved", None),
    (
        b"u #c\n::rw-,g::r--,o::---",
        "refused",
        "Tag { at: 0 }",
        None,
    ),
    (
        b"u #c\n:5:rw-,g::r--,m::rwx,o::---",
        "refused",
        "Tag { at: 0 }",
        None,
    ),
    (b"u#::rw-,g::r--,o::---", "refused", "Tag { at: 0 }", None),
    (b"u::rw-,g#::r--,o::---", "refused", "Tag { at: 7 }", None),
    (b"o#::rw-", "refused", "Tag { at: 0 }", None),
    (
        b"o#::rw-, user:lisa :\n-w-,g::w-r #c",
        "invalid 0x3000",
        "Tag { at: 0 }",
        Some(SPACE_AFTER_TAG),
    ),
];

/// libacl 2.4's readings of the texts in [`MEASURED`] it reads otherwise
/// than 2.3, measured with libacl 2.4.0 (Fedora 45) and the same account
/// database, with the difference each states. 2.4 looks a qualifier of
/// digits past the last id up as a name, and refuses one no account has; it
/// refuses an escape giving a NUL.
const MEASURED_2_4: &[(&[u8], &str, Option<&str>)] = &[
    (
        b"u::rw-\ng::r--\ng:\\400:r--\nm::r--\no::---",
        "refused",
        None,
    ),
    (
        b"u::rw-,u:99999999999:r--,g::r--,m::rwx,o::---",
        "valid u::rw-,u:5003:r--,g::r--,m::rwx,o::---",
        Some(DIGITS_AS_NAME),
    ),
    (
        b"u::rw-,u:4294967295:r--,g::r--,m::rwx,o::---",
        "valid u::rw-,u:5007:r--,g::r--,m::rwx,o::---",
        Some(DIGITS_AS_NAME),
    ),
    (
        b"u::rw-,g:4294967295:r--,g::r--,m::rwx,o::---",
        "refused",
        Some(DIGITS_AS_NAME),
    ),
    (
        b"u::rw-,g:4294967296:r--,g::r--,m::rwx,o::---",
        "refused",
        None,
    ),
    (
        b"u::rw-,g:4294967297:r--,g::r--,m::rwx,o::---",
        "refused",
        None,
    ),
    (
        b"u::rw-,g:99999999999999999999:r--,g::r--,m::rwx,o::---",
        "refused",
        None,
    ),
    (b"u::rw-,g:\\000:r--,g::r--,m::rwx,o::---", "refused", None),
];

/// Whether the libacl present reads a qualifier of digits past the last id
/// as a name, as 2.4 does, rather than as a number, as 2.3 does: the account
/// database holds a user named `4294967295`.
fn digits_past_the_last_id_are_names(libacl: &mut support::Oracle) -> bool {
    match libacl.read(b"u::rw-,u:4294967295:r--,g::r--,m::rwx,o::---") {
        Reading::Valid(_) => true,
        Reading::Invalid { .. } => false,
        Reading::Unread => panic!("libacl refuses a text naming user 4294967295"),
    }
}

/// The readings of libacl built against a glibc before 2.38 of the texts in
/// [`MEASURED`] it reads otherwise, measured with Debian 12's libacl 2.3.1
/// (built against glibc 2.36) and the same account database, with the
/// difference each states. Such a libacl calls `strtol` as C17 has it, which
/// reads no binary number, so it looks one up as a name. [`MEASURED`] holds
/// the readings of libacl built against glibc 2.38 or later, which calls the
/// C23 form, which reads `0b` and binary digits.
const MEASURED_BEFORE_GLIBC_2_38: &[(&[u8], &str, Option<&str>)] = &[
    (
        b"u::rw-,g:0b0:r--,g::r--,m::rwx,o::---",
        "valid u::rw-,g::r--,g:5040:r--,m::rwx,o::---",
        Some(LOOSE_NUMBER),
    ),
    (b"u::rw-,g:0b1:r--,g::r--,m::rwx,o::---", "refused", None),
    (b"u::rw-,g:0B11:r--,g::r--,m::rwx,o::---", "refused", None),
    (b"u::rw-,g: 0b1:r--,g::r--,m::rwx,o::---", "refused", None),
    (b"u::rw-,g:+0b101:r--,g::r--,m::rwx,o::---", "refused", None),
    (b"u::rw-,g:-0b1:r--,g::r--,m::rwx,o::---", "refused", None),
    (
        b"u::rw-,u:0b1111101000:r--,g::r--,m::rwx,o::---",
        "refused",
        None,
    ),
    (
        b"u::rw-,g:\\060\\142\\060:r--,g::r--,m::rwx,o::---",
        "valid u::rw-,g::r--,g:5040:r--,m::rwx,o::---",
        Some(LOOSE_NUMBER),
    ),
];

/// Whether the libacl present reads a binary number as a number, as libacl
/// built against glibc 2.38 or later does, rather than looking it up as a
/// name: the account database holds a group named `0b0`.
fn binary_is_a_number(libacl: &mut support::Oracle) -> bool {
    let named = group_id(b"0b0").expect("the database names a group 0b0");
    let read = match libacl.read(b"u::rw-,g::r--,g:0b0:r--,m::rwx,o::---") {
        Reading::Valid(value) => xattr::decode(&value).ok().flatten(),
        _ => None,
    };
    match read.map(|acl| {
        (
            acl.perm(Qualifier::Group(0)),
            acl.perm(Qualifier::Group(named)),
        )
    }) {
        Some((Some(_), None)) => true,
        Some((None, Some(_))) => false,
        other => panic!("libacl read a text naming the group 0b0 as {other:?}"),
    }
}

/// Whether a qualifier field, its `\ooo` escapes decoded, is digits past the
/// last id with no leading zero.
fn digits_past_the_last_id(field: &[u8]) -> bool {
    let mut decoded = Vec::new();
    let mut rest = field;
    while let Some((&byte, after)) = rest.split_first() {
        match after {
            [a @ b'0'..=b'7', b @ b'0'..=b'7', c @ b'0'..=b'7', tail @ ..] if byte == b'\\' => {
                decoded.push(((a - b'0') << 6) | ((b - b'0') << 3) | (c - b'0'));
                rest = tail;
            }
            _ => {
                decoded.push(byte);
                rest = after;
            }
        }
    }
    // Digits compare as numbers only at equal length: `5` is below the last
    // id, though `b"5" >= b"4294967295"`.
    decoded.first().is_some_and(|&d| d != b'0')
        && decoded.iter().all(u8::is_ascii_digit)
        && (decoded.len() > 10
            || (decoded.len() == 10 && decoded.as_slice() >= b"4294967295".as_slice()))
}

#[test]
fn only_digits_past_the_last_id_are_taken_for_them() {
    for (field, past) in [
        (&b"0"[..], false),
        (b"5", false),
        (b"99", false),
        (b"4242", false),
        (b"999999999", false),
        (b"4294967294", false),
        (b"4294967295", true),
        (b"4294967296", true),
        (b"9999999999", true),
        (b"99999999999", true),
        (b"04294967295", false),
        (b"\\064\\062\\071\\064\\071\\066\\067\\062\\071\\065", true),
        (b"\\065", false),
        (b"429496729x", false),
        (b"", false),
    ] {
        assert_eq!(
            digits_past_the_last_id(field),
            past,
            "{:?}",
            String::from_utf8_lossy(field)
        );
    }
}

#[test]
fn every_text_libacl_was_asked_about_parses_as_measured() {
    let mut seen = BTreeMap::new();
    for &(text, libacl, crate_says, stated) in MEASURED {
        let shown = String::from_utf8_lossy(text);
        assert_eq!(outcome(text), crate_says, "{shown:?}");
        assert_eq!(
            agree(libacl, crate_says),
            stated.is_none(),
            "{shown:?}: libacl {libacl}, the crate {crate_says}, stated {stated:?}"
        );
        if let Some(stated) = stated {
            assert!(STATED.contains(&stated), "{shown:?}: {stated}");
            *seen.entry(stated).or_insert(0) += 1;
        }
    }
    for &(_, _, stated) in ODD_READINGS {
        if let Some(stated) = stated {
            *seen.entry(stated).or_insert(0) += 1;
        }
    }
    for stated in STATED {
        assert!(seen.contains_key(stated), "no measured text shows {stated}");
    }
    for &(text, libacl, stated) in MEASURED_2_4 {
        let shown = String::from_utf8_lossy(text);
        let &(_, _, crate_says, _) = MEASURED
            .iter()
            .find(|row| row.0 == text)
            .unwrap_or_else(|| panic!("{shown:?} is not in MEASURED"));
        assert_eq!(
            agree(libacl, crate_says),
            stated.is_none(),
            "{shown:?}: libacl 2.4 {libacl}, the crate {crate_says}, stated {stated:?}"
        );
        assert!(stated.is_none_or(|s| s == DIGITS_AS_NAME), "{shown:?}");
    }
    for &(text, libacl, stated) in MEASURED_BEFORE_GLIBC_2_38 {
        let shown = String::from_utf8_lossy(text);
        let &(_, _, crate_says, _) = MEASURED
            .iter()
            .find(|row| row.0 == text)
            .unwrap_or_else(|| panic!("{shown:?} is not in MEASURED"));
        assert_eq!(
            agree(libacl, crate_says),
            stated.is_none(),
            "{shown:?}: libacl before glibc 2.38 {libacl}, the crate {crate_says}, \
             stated {stated:?}"
        );
        assert!(stated.is_none_or(|s| s == LOOSE_NUMBER), "{shown:?}");
    }

    // libacl still reads each as recorded, where it can be asked. Where both
    // read a list their checkers refuse, the crate's rules make the same of
    // libacl's entries as of its own.
    let Some(mut libacl) = libacl_with_the_accounts("text-measured") else {
        return;
    };
    let names = digits_past_the_last_id_are_names(&mut libacl);
    let binary = binary_is_a_number(&mut libacl);
    let mut invalid_to_both = 0;
    for &(text, recorded, crate_says, _) in MEASURED {
        let shown = String::from_utf8_lossy(text);
        let recorded = MEASURED_2_4
            .iter()
            .find(|row| names && row.0 == text)
            .map(|row| row.1)
            .or_else(|| {
                MEASURED_BEFORE_GLIBC_2_38
                    .iter()
                    .find(|row| !binary && row.0 == text)
                    .map(|row| row.1)
            })
            .unwrap_or(recorded);
        let reading = libacl.read(text);
        assert_eq!(
            libacl_notation(&reading),
            recorded,
            "{shown:?}, libacl reading digits past the last id as a name: {names}, \
             binary as a number: {binary}"
        );
        if let (Reading::Invalid { value, .. }, true) =
            (&reading, crate_says.starts_with("invalid"))
        {
            let parsed = text::parse(text).expect("parsed").expect("a list");
            assert_eq!(
                judged(entries_of(value)),
                judged_parsed(&parsed),
                "{shown:?}"
            );
            invalid_to_both += 1;
        }
    }
    assert!(
        invalid_to_both > 10,
        "too few invalid to both: {invalid_to_both}"
    );
}

/// One entry of a generated text, field by field as it is written.
#[derive(Clone, Debug)]
struct Written {
    tag: Vec<u8>,
    /// The qualifier field; `None` where a mask's or other's entry leaves
    /// it out.
    qualifier: Option<Vec<u8>>,
    perm: Vec<u8>,
    /// A fourth field, after its colon.
    fourth: Option<Vec<u8>>,
    /// What follows the entry: blanks, a separator, comments.
    after: Vec<u8>,
}

/// A generated text: what comes before the first entry, and the entries.
#[derive(Clone, Debug)]
struct Generated {
    leading: Vec<u8>,
    entries: Vec<Written>,
}

impl Generated {
    /// The text, with its fourth fields or without them.
    fn text(&self, fourth: bool) -> Vec<u8> {
        let mut out = self.leading.clone();
        for entry in &self.entries {
            out.extend_from_slice(&entry.tag);
            out.push(b':');
            if let Some(qualifier) = &entry.qualifier {
                out.extend_from_slice(qualifier);
                out.push(b':');
            }
            out.extend_from_slice(&entry.perm);
            if let (true, Some(field)) = (fourth, &entry.fourth) {
                out.push(b':');
                out.extend_from_slice(field);
            }
            out.extend_from_slice(&entry.after);
        }
        out
    }

    fn has_fourth(&self) -> bool {
        self.entries.iter().any(|entry| entry.fourth.is_some())
    }

    fn names_digits_past_the_last_id(&self) -> bool {
        self.entries.iter().any(|entry| {
            entry
                .qualifier
                .as_deref()
                .is_some_and(digits_past_the_last_id)
        })
    }
}

fn pick<'a>(rng: &mut Rng, items: &'a [&'a [u8]]) -> Vec<u8> {
    rng.pick(items).to_vec()
}

/// A permission field granting `bits`, its letters in any order, with up to
/// three characters.
fn spelled_perm(rng: &mut Rng, bits: u16) -> Vec<u8> {
    if rng.below(2) == 0 {
        return perm(bits).to_string().into_bytes();
    }
    let mut field: Vec<u8> = [(4, b'r'), (2, b'w'), (1, b'x')]
        .into_iter()
        .filter(|&(bit, _)| bits & bit != 0)
        .map(|(_, letter)| letter)
        .collect();
    let dashes = rng.below(4 - field.len() as u64) as usize;
    field.extend(std::iter::repeat_n(
        b'-',
        dashes.max(usize::from(field.is_empty())),
    ));
    rng.shuffle(&mut field);
    field
}

/// A permission field granting anything.
fn random_perm(rng: &mut Rng) -> Vec<u8> {
    let bits = rng.below(8) as u16;
    spelled_perm(rng, bits)
}

/// `name` escaped as libacl escapes names, or every byte as `\ooo`, or as
/// it is.
fn spelled_name(rng: &mut Rng, name: &[u8]) -> Vec<u8> {
    let raw_unsafe = name
        .iter()
        .any(|b| matches!(b, b',' | b':' | b'\n' | b'\r'));
    match rng.below(4) {
        0 if !raw_unsafe => name.to_vec(),
        1 => name
            .iter()
            .flat_map(|b| format!("\\{b:03o}").into_bytes())
            .collect(),
        _ => {
            let mut out = Vec::new();
            for &byte in name {
                match byte {
                    b' ' | b',' | b'\t' | b'\n' | b'\r' | b':' => {
                        out.extend_from_slice(format!("\\{byte:03o}").as_bytes());
                    }
                    b'\\' => out.extend_from_slice(b"\\\\"),
                    _ => out.push(byte),
                }
            }
            out
        }
    }
}

fn tag_word(rng: &mut Rng, long: &'static [u8], short: &'static [u8]) -> Vec<u8> {
    if rng.below(2) == 0 { long } else { short }.to_vec()
}

fn generated_entry(rng: &mut Rng, tag: Tag) -> Written {
    let (long, short): (&[u8], &[u8]) = match tag {
        Tag::UserObj | Tag::User => (b"user", b"u"),
        Tag::GroupObj | Tag::Group => (b"group", b"g"),
        Tag::Mask => (b"mask", b"m"),
        Tag::Other => (b"other", b"o"),
    };
    let mut entry = Written {
        tag: tag_word(rng, long, short),
        qualifier: Some(Vec::new()),
        perm: random_perm(rng),
        fourth: None,
        after: Vec::new(),
    };
    if matches!(tag, Tag::Mask | Tag::Other) && rng.below(5) == 0 {
        entry.qualifier = None;
    }
    if tag.is_named() {
        let table = if tag == Tag::User { USERS } else { GROUPS };
        let (qualifier, id) = match rng.below(10) {
            0..=2 => {
                let id = *rng.pick(&[0, 1, 502, 4242, 4243, 5000, 65534, 4_294_967_294]);
                let id = if rng.below(4) == 0 {
                    rng.below(70_000) as u32
                } else {
                    id
                };
                let id = if rng.below(40) == 0 { UNDEFINED_ID } else { id };
                (id.to_string().into_bytes(), id)
            }
            3..=7 => {
                let (name, id) = *rng.pick(table);
                (spelled_name(rng, name), id)
            }
            _ => (
                pick(rng, &[b"nosuch", b"lisa2", b"Root", b"nobody-here", b"x"]),
                4300,
            ),
        };
        entry.qualifier = Some(qualifier);
        if rng.below(6) == 0 {
            let recorded = if rng.below(2) == 0 {
                id
            } else {
                rng.below(70_000) as u32
            };
            entry.fourth = Some(recorded.to_string().into_bytes());
        }
    }
    entry
}

/// One mutation, of the kinds the measured texts reach: a tag, permission
/// field, qualifier or fourth field replaced; a byte put between fields; a
/// separator replaced; a mask's or other's empty qualifier field left out
/// or put back; an entry dropped or repeated; a comment before the first
/// entry; or the whole text one holding no entry.
fn mutate(rng: &mut Rng, generated: &mut Generated) {
    if generated.entries.is_empty() {
        return;
    }
    let at = rng.below(generated.entries.len() as u64) as usize;
    match rng.below(12) {
        0 => {
            generated.entries[at].tag = pick(
                rng,
                &[
                    b"U",
                    b"User",
                    b"us",
                    b"grou",
                    b"ma",
                    b"oth",
                    b"d:u",
                    b"default:user",
                    b"",
                    b"u ",
                    b"u\t",
                    b"u\n",
                    b"M",
                    b"x",
                    b"g\r",
                ],
            );
        }
        1 => {
            generated.entries[at].perm = pick(
                rng,
                &[
                    b"", b"rwx-", b"rr-", b"w-w", b"R", b"X", b"r w", b"--", b"-", b"x", b"rw#x",
                    b"r#", b"----", b"rwxx", b" rw-", b"rw- ", b"\\162w-",
                ],
            );
        }
        2 | 3 => {
            generated.entries[at].qualifier = Some(pick(
                rng,
                &[
                    b"-1",
                    b"+5",
                    b"0x10",
                    b"010",
                    b"0010",
                    b"00",
                    b" 5",
                    b"\t5",
                    b"4294967296",
                    b"99999999999",
                    b"-0",
                    b"0x",
                    b"08",
                    b"0b0",
                    b"0b1",
                    b"0B11",
                    b"+0b1",
                    b" 0b1",
                    b"0b",
                    b"0b12",
                    b"1e3",
                    b"3dg",
                    b"0x1g",
                    b"5x",
                    b"+",
                    b"-",
                    b"a\\000b",
                    b"\\000",
                    b"\\400",
                    b"a\\777",
                    b"\\101",
                    b"\\\\",
                    b"a\\4",
                    b"a\\40b",
                    b"#x",
                    b" lisa",
                    b"lisa ",
                    b"trail\\040",
                    b"trail ",
                    b"",
                    b"\\043x",
                    b"5 02",
                    b"0",
                    b"4294967295",
                    b"\\064\\062\\064\\062",
                ],
            ));
        }
        4 => {
            generated.entries[at].fourth = Some(pick(
                rng,
                &[
                    b"",
                    b"x",
                    b"05",
                    b"4294967295",
                    b"4294967296",
                    b"502",
                    b"1",
                    b"502:5",
                    b"0",
                    b"10",
                    b"4243 ",
                ],
            ));
        }
        5 | 6 => {
            let byte = *rng.pick(b" \t\r\x0b\x0c\n,#");
            let entry = &mut generated.entries[at];
            match rng.below(6) {
                0 => entry.tag.push(byte),
                1 => entry.qualifier.get_or_insert_with(Vec::new).insert(0, byte),
                2 => entry.qualifier.get_or_insert_with(Vec::new).push(byte),
                3 => entry.perm.insert(0, byte),
                4 => entry.after.insert(0, byte),
                _ => entry.after.push(byte),
            }
        }
        7 => {
            generated.entries[at].after = pick(
                rng,
                &[b"", b" ", b",,", b"\n,\n", b", ,", b"\r", b"\t", b",\n,"],
            );
        }
        8 => {
            let entry = &mut generated.entries[at];
            entry.qualifier = match entry.qualifier.take() {
                None => Some(Vec::new()),
                Some(_) => None,
            };
        }
        9 => {
            if rng.below(2) == 0 {
                generated.entries.remove(at);
            } else {
                let mut repeated = generated.entries[at].clone();
                repeated.perm = random_perm(rng);
                repeated.after = b",".to_vec();
                generated.entries.insert(at, repeated);
            }
        }
        10 => generated
            .leading
            .splice(0..0, b"#c\n".iter().copied())
            .for_each(drop),
        _ => {
            if rng.below(4) == 0 {
                generated.entries.clear();
                generated.leading = pick(rng, &[b"", b"\n", b" ", b",", b"#c", b"\n#c\n", b"\r\n"]);
            }
        }
    }
}

/// A generated text: a list's entries, valid or nearly so, in any order and
/// spelling, separated as the measured texts are, then mutated or not.
fn generated_text(rng: &mut Rng) -> Generated {
    let mut entries = vec![
        generated_entry(rng, Tag::UserObj),
        generated_entry(rng, Tag::GroupObj),
        generated_entry(rng, Tag::Other),
    ];
    let named = rng.below(5);
    for _ in 0..named {
        let tag = if rng.below(2) == 0 {
            Tag::User
        } else {
            Tag::Group
        };
        entries.push(generated_entry(rng, tag));
    }
    if named > 0 && rng.below(10) != 0 || rng.below(4) == 0 {
        entries.push(generated_entry(rng, Tag::Mask));
    }
    rng.shuffle(&mut entries);
    let commas = rng.below(2) == 0;
    let count = entries.len();
    for (index, entry) in entries.iter_mut().enumerate() {
        entry.after = if index + 1 == count {
            pick(
                rng,
                &[b"", b"", b"\n", b",", b",\n", b" #c", b"\n\n", b"\r\n"],
            )
        } else if commas {
            pick(rng, &[b",", b",", b", ", b",\t", b" , ", b",\n", b",#c\n"])
        } else {
            pick(
                rng,
                &[
                    b"\n",
                    b"\n",
                    b"\r\n",
                    b"\n\n",
                    b"\t#effective:r--\n",
                    b" #c\n",
                    b"\n#c\n",
                    b"  \n",
                ],
            )
        };
    }
    let leading = pick(rng, &[b"", b"", b"", b" ", b"\n", b"\t", b"\r\n"]);
    let mut generated = Generated { leading, entries };
    if rng.below(2) == 0 {
        for _ in 0..=rng.below(3) {
            mutate(rng, &mut generated);
        }
    }
    generated
}

/// The stated difference that explains a crate refusing `text` with
/// `error` where libacl reads it, if one does.
fn stated_refusal(text: &[u8], error: ParseError) -> Option<&'static str> {
    let before = |at: usize| at.checked_sub(1).and_then(|at| text.get(at)).copied();
    match error {
        ParseError::Number { .. } => Some(LOOSE_NUMBER),
        ParseError::Escape { .. } => Some(ESCAPE),
        ParseError::Separator { at }
            if matches!(before(at), Some(b' ' | b'\t' | b'\r'))
                && text.get(at).is_some_and(u8::is_ascii_lowercase) =>
        {
            Some(NO_SEPARATOR)
        }
        // A permission field run straight into the next entry's tag.
        ParseError::Perm { at }
            if {
                let field = text[at..]
                    .iter()
                    .take_while(|b| b"rwx-".contains(b))
                    .count();
                let letters = text[at..at + field].iter().filter(|b| **b != b'-');
                let mut seen = letters.clone().collect::<Vec<_>>();
                seen.sort();
                seen.dedup();
                (1..=3).contains(&field)
                    && seen.len() == letters.count()
                    && text.get(at + field).is_some_and(u8::is_ascii_lowercase)
            } =>
        {
            Some(NO_SEPARATOR)
        }
        ParseError::Tag { at } if text.get(at) == Some(&b',') => {
            let line = text[..at]
                .iter()
                .rposition(|b| !matches!(b, b' ' | b'\t' | b'\r'));
            (line.map(|end| text[end]) == Some(b'\n')).then_some(STRAY_COMMA)
        }
        ParseError::Perm { at } if matches!(text.get(at), Some(b' ' | b'\t' | b'\r' | b'\n')) => {
            let entry = &text[..at];
            [&b"m:"[..], b"mask:", b"o:", b"other:"]
                .iter()
                .any(|tag| {
                    entry.ends_with(tag)
                        && entry.len().checked_sub(tag.len() + 1).is_none_or(|before| {
                            matches!(text[before], b',' | b'\n' | b' ' | b'\t' | b'\r')
                        })
                })
                .then_some(SPACE_AFTER_TAG)
        }
        // libacl reads a tag as a prefix of what follows, and passes over
        // blanks, line ends and, after a mask's or other's, comments and
        // colons.
        ParseError::Tag { at } => {
            let tags: [&[u8]; 8] = [b"user", b"u", b"group", b"g", b"mask", b"m", b"other", b"o"];
            tags.iter()
                .any(|tag| text[at..].starts_with(tag))
                .then_some(SPACE_AFTER_TAG)
        }
        _ => None,
    }
}

/// What the crate makes of a text, for the corpus comparison.
#[derive(Clone, Debug, PartialEq)]
enum Crate {
    NoList,
    Refused(Option<ParseError>),
    Invalid(Judged),
    List(Acl),
}

fn crate_reading(text: &[u8]) -> Crate {
    match text::parse(text) {
        Ok(None) => Crate::NoList,
        Err(err) => Crate::Refused(Some(err)),
        Ok(Some(parsed)) => match parsed.resolve(user_id, group_id, Prefer::Name) {
            Ok(acl) => Crate::List(acl),
            Err(ResolveError::Unresolved { .. }) => Crate::Refused(None),
            Err(ResolveError::Invalid(_)) => {
                Crate::Invalid(judged_parsed(&parsed).expect("the entries are invalid"))
            }
            Err(other) => panic!("resolve answered {other:?}"),
        },
    }
}

/// Whether the crate and libacl say the same of a text: both refuse it, both
/// read the same list, or both read a list their checkers refuse, which the
/// crate's rules judge alike.
fn agrees(ours: &Crate, libacl: &Reading) -> bool {
    match (ours, libacl) {
        (Crate::Refused(_), Reading::Unread) => true,
        (Crate::Invalid(ours), Reading::Invalid { value, .. }) => {
            judged(entries_of(value)).as_ref() == Some(ours)
        }
        (Crate::List(acl), Reading::Valid(value)) => {
            xattr::decode(value).ok().flatten().as_ref() == Some(acl)
        }
        _ => false,
    }
}

#[test]
fn parse_agrees_with_libacl_over_generated_texts() {
    let Some(mut libacl) = libacl_with_the_accounts("text-generated") else {
        return;
    };
    let names = digits_past_the_last_id_are_names(&mut libacl);
    let mut rng = Rng::seeded(5);
    let mut agreed = BTreeMap::new();
    let mut stated = BTreeMap::new();
    // Texts invalid to both whose lists are compared whole once the mask is
    // computed.
    let mut whole = 0;
    for case in 0..8000 {
        let generated = generated_text(&mut rng);
        let text = generated.text(true);
        let ours = crate_reading(&text);
        let theirs = libacl.read(&text);
        let shown = String::from_utf8_lossy(&text);
        let context = || {
            format!(
                "case {case} (seed {}): {shown:?}: ours {ours:?}, libacl's {theirs:?}",
                rng.seed()
            )
        };
        if agrees(&ours, &theirs) {
            whole += usize::from(matches!(&ours, Crate::Invalid(judged) if judged.masked.is_ok()));
            let class = match ours {
                Crate::Refused(_) => "refused by both",
                Crate::Invalid(_) => "invalid to both",
                _ => "the same list",
            };
            *agreed.entry(class).or_insert(0) += 1;
            continue;
        }
        let reason = match (&ours, &theirs) {
            (Crate::Refused(Some(error)), Reading::Valid(_) | Reading::Invalid { .. }) => {
                stated_refusal(&text, *error)
            }
            (Crate::NoList, Reading::Invalid { .. }) if text.is_empty() => Some(EMPTY),
            // libacl refuses every fourth field; the crate reads the entry
            // as libacl reads it without the field, or, where its name has
            // no answer, as the id the field records.
            (Crate::List(_) | Crate::Invalid(_), Reading::Unread) if generated.has_fourth() => {
                let stripped = generated.text(false);
                let without = libacl.read(&stripped);
                let rescued = crate_reading(&stripped) == Crate::Refused(None);
                (agrees(&ours, &without) || rescued).then_some(FOURTH_FIELD)
            }
            _ => None,
        };
        // libacl 2.4 looks such a qualifier up as a name, where the crate
        // reads it as the undefined id or refuses it as a number.
        let reason = reason.or_else(|| {
            (names
                && matches!(ours, Crate::Invalid(_) | Crate::Refused(_))
                && generated.names_digits_past_the_last_id())
            .then_some(DIGITS_AS_NAME)
        });
        let reason = reason.unwrap_or_else(|| panic!("an unstated difference: {}", context()));
        *stated.entry(reason).or_insert(0) += 1;
    }
    eprintln!(
        "agreed {agreed:?}, {whole} invalid to both compared whole with the mask computed; \
         stated differences {stated:?}"
    );
    assert!(whole >= 50, "too few compared whole: {whole}");
    for (class, least) in [
        ("refused by both", 1000),
        ("invalid to both", 200),
        ("the same list", 1000),
    ] {
        let count = agreed.get(class).copied().unwrap_or(0);
        assert!(count >= least, "too few {class}: {agreed:?}");
    }
    // The files database holds no name beginning with a line end, so libacl
    // reads none here; `ODD_READINGS` shows that class.
    for reason in STATED.into_iter().filter(|&r| r != LEADING_LINE_END) {
        assert!(
            stated.contains_key(reason),
            "no generated text showed {reason}: {stated:?}"
        );
    }
    assert_eq!(
        stated.contains_key(DIGITS_AS_NAME),
        names,
        "libacl reading digits past the last id as a name: {names}; {stated:?}"
    );
}

/// GNU tar 1.35's records, written with `--acls --xattrs` under the account
/// database above for lists `setfacl` set: the member, its
/// `SCHILY.acl.access` and `SCHILY.acl.default` texts, and
/// its `SCHILY.xattr.system.posix_acl_access` and `..._default` values.
type Records = (
    &'static str,
    Option<&'static [u8]>,
    Option<&'static [u8]>,
    Option<&'static [u8]>,
    Option<&'static [u8]>,
);

const GNU_TAR: &[Records] = &[
    (
        "named",
        Some(b"user::rw-\nuser:lisa:r--\nuser:4300:r-x\ngroup::r--\ngroup:domain\\040users:rw-\nmask::rwx\nother::---\n"),
        None,
        Some(b"\x02\x00\x00\x00\x01\x00\x06\x00\xff\xff\xff\xff\x02\x00\x04\x00\xf6\x01\x00\x00\x02\x00\x05\x00\xcc\x10\x00\x00\x04\x00\x04\x00\xff\xff\xff\xff\x08\x00\x06\x00\x92\x10\x00\x00\x10\x00\x07\x00\xff\xff\xff\xff \x00\x00\x00\xff\xff\xff\xff"),
        None,
    ),
    (
        "escaped",
        Some(b"user::rwx\nuser:a\\040b:r--\nuser:back\\\\slash:rw-\nuser:caf\xc3\xa9:--x\ngroup::r-x\ngroup:comma\\054g:r--\ngroup:back\\\\slashg:r--\ngroup:tab\\011g:-w-\ngroup:caf\xc3\xa9:r--\ngroup:trail\\040:rw-\ngroup:eq=g:--x\nmask::rwx\nother::r--\n"),
        None,
        Some(b"\x02\x00\x00\x00\x01\x00\x07\x00\xff\xff\xff\xff\x02\x00\x04\x00\x93\x10\x00\x00\x02\x00\x06\x00\x9a\x10\x00\x00\x02\x00\x01\x00\xa4\x10\x00\x00\x04\x00\x05\x00\xff\xff\xff\xff\x08\x00\x04\x00\x96\x10\x00\x00\x08\x00\x04\x00\x9b\x10\x00\x00\x08\x00\x02\x00\x9c\x10\x00\x00\x08\x00\x04\x00\x9d\x10\x00\x00\x08\x00\x06\x00\xa0\x10\x00\x00\x08\x00\x01\x00\xa2\x10\x00\x00\x10\x00\x07\x00\xff\xff\xff\xff \x00\x04\x00\xff\xff\xff\xff"),
        None,
    ),
    (
        "hash",
        Some(b"user::rw-\ngroup::r--\ngroup:hash\nmask::r--\nother::---\n"),
        None,
        Some(b"\x02\x00\x00\x00\x01\x00\x06\x00\xff\xff\xff\xff\x04\x00\x04\x00\xff\xff\xff\xff\x08\x00\x04\x00\x95\x10\x00\x00\x10\x00\x04\x00\xff\xff\xff\xff \x00\x00\x00\xff\xff\xff\xff"),
        None,
    ),
    (
        "maskonly",
        Some(b"user::rw-\ngroup::r--\nmask::r--\nother::---\n"),
        None,
        Some(b"\x02\x00\x00\x00\x01\x00\x06\x00\xff\xff\xff\xff\x04\x00\x04\x00\xff\xff\xff\xff\x10\x00\x04\x00\xff\xff\xff\xff \x00\x00\x00\xff\xff\xff\xff"),
        None,
    ),
    (
        "dir-access",
        Some(b"user::rwx\nuser:lisa:r-x\ngroup::r-x\nmask::r-x\nother::---\n"),
        Some(b""),
        Some(b"\x02\x00\x00\x00\x01\x00\x07\x00\xff\xff\xff\xff\x02\x00\x05\x00\xf6\x01\x00\x00\x04\x00\x05\x00\xff\xff\xff\xff\x10\x00\x05\x00\xff\xff\xff\xff \x00\x00\x00\xff\xff\xff\xff"),
        None,
    ),
    (
        "dir-both",
        Some(b"user::rwx\ngroup::r-x\ngroup:domain\\040users:rwx\nmask::rwx\nother::r-x\n"),
        Some(b"user::rwx\nuser:lisa:rwx\ngroup::r-x\nmask::rwx\nother::---\n"),
        Some(b"\x02\x00\x00\x00\x01\x00\x07\x00\xff\xff\xff\xff\x04\x00\x05\x00\xff\xff\xff\xff\x08\x00\x07\x00\x92\x10\x00\x00\x10\x00\x07\x00\xff\xff\xff\xff \x00\x05\x00\xff\xff\xff\xff"),
        Some(b"\x02\x00\x00\x00\x01\x00\x07\x00\xff\xff\xff\xff\x02\x00\x07\x00\xf6\x01\x00\x00\x04\x00\x05\x00\xff\xff\xff\xff\x10\x00\x07\x00\xff\xff\xff\xff \x00\x00\x00\xff\xff\xff\xff"),
    ),
    (
        "dir-default",
        Some(b"user::rwx\ngroup::r-x\nother::r-x\n"),
        Some(b"user::rwx\ngroup::r-x\nother::r-x\n"),
        None,
        Some(b"\x02\x00\x00\x00\x01\x00\x07\x00\xff\xff\xff\xff\x04\x00\x05\x00\xff\xff\xff\xff \x00\x05\x00\xff\xff\xff\xff"),
    ),
];

/// The list a record states, read as text, or `None` for no list.
fn text_record(text: &[u8]) -> Result<Option<Acl>, String> {
    match text::parse(text) {
        Ok(None) => Ok(None),
        Ok(Some(parsed)) => parsed
            .resolve(user_id, group_id, Prefer::Name)
            .map(Some)
            .map_err(|err| err.to_string()),
        Err(err) => Err(err.to_string()),
    }
}

#[test]
fn gnu_tars_text_records_state_the_lists_its_binary_records_hold() {
    for &(member, access, default, binary_access, binary_default) in GNU_TAR {
        // GNU tar cuts a name at its `#`, writing a group `hash#g` as
        // `group:hash`, with no permissions: the qualifier runs on into the
        // next line, and a name holds no line end. No reader reads it.
        if member == "hash" {
            assert_eq!(
                text::parse(access.expect("an access record")),
                Err(ParseError::LineEnd { at: 31 })
            );
            continue;
        }
        let access = text_record(access.expect("an access record")).expect(member);
        match binary_access {
            Some(value) => assert_eq!(access, xattr::decode(value).expect(member), "{member}"),
            // The kernel stores no minimal access list, and GNU tar writes the
            // mode's as text.
            None => assert!(access.expect(member).is_minimal(), "{member}"),
        }
        let default = default.and_then(|text| text_record(text).expect(member));
        let binary_default =
            binary_default.map(|value| xattr::decode(value).expect(member).expect(member));
        assert_eq!(default, binary_default, "{member}");
    }
}

#[test]
fn write_named_spells_a_list_as_gnu_tar_does() {
    for &(member, access, default, binary_access, binary_default) in GNU_TAR {
        for (text, value) in [(access, binary_access), (default, binary_default)] {
            let (Some(text), Some(value)) = (text, value) else {
                continue;
            };
            let acl = xattr::decode(value).expect(member).expect(member);
            let written = text::write_named(&acl, Spelling::GNU_TAR, user_name, group_name);
            if member == "hash" {
                // The crate escapes the `#` GNU tar cuts the name at.
                assert_eq!(
                    written,
                    b"user::rw-\ngroup::r--\ngroup:hash\\043g:r--\nmask::r--\nother::---\n"
                );
                assert_eq!(read(&written), acl);
            } else {
                assert_eq!(
                    String::from_utf8_lossy(&written),
                    String::from_utf8_lossy(text),
                    "{member}"
                );
            }
        }
    }
}

/// A member, the list set, and the access and default records written.
type LibarchiveRecords = (
    &'static str,
    &'static [u8],
    Option<&'static [u8]>,
    Option<&'static [u8]>,
);

/// libarchive 3.8.11's records (bsdtar `--format=pax`), written under the
/// account database above for lists `setfacl` set: the member, the list set
/// (abbreviated, numeric), and its `SCHILY.acl.access` and
/// `SCHILY.acl.default` texts. Ubuntu's libarchive 3.7.2 writes the same.
const LIBARCHIVE: &[LibarchiveRecords] = &[
    (
        "named",
        b"u::rw-,u:502:r--,u:4300:r-x,g::r--,g:4242:rw-,m::rwx,o::---",
        Some(b"user::rw-,group::r--,other::---,user:lisa:r--:502,user:4300:r-x,group:domain users:rw-:4242,mask::rwx"),
        None,
    ),
    (
        "dir-both",
        b"u::rwx,u:502:r-x,g::r-x,g:4242:rwx,m::rwx,o::r-x",
        Some(b"user::rwx,group::r-x,other::r-x,user:lisa:r-x:502,group:domain users:rwx:4242,mask::rwx"),
        Some(b"user::rwx,user:lisa:rwx:502,group::r-x,mask::rwx,other::---"),
    ),
    (
        "dir-default",
        b"u::rwx,u:502:r-x,g::r-x,m::r-x,o::r-x",
        None,
        Some(b"user::rwx,user:lisa:r-x:502,group::r-x,mask::r-x,other::r-x"),
    ),
];

#[test]
fn libarchives_records_state_the_lists_set() {
    for &(member, set, access, default) in LIBARCHIVE {
        let set = read(set);
        let text = access.or(default).expect(member);
        // Named or not by the destination, each entry is the list set: the
        // names answer, or the recorded ids stand.
        let parsed = text::parse(text).expect(member).expect(member);
        assert_eq!(
            parsed.resolve(user_id, group_id, Prefer::Name),
            Ok(set.clone()),
            "{member}"
        );
        assert_eq!(
            parsed.resolve(|_| None, |_| None, Prefer::Name),
            Ok(set.clone()),
            "{member}"
        );
        // star's spelling holds the same entries, in canonical order, with
        // names escaped.
        let written = text::write_named(&set, Spelling::STAR, user_name, group_name);
        assert_eq!(read(&written), set, "{member}");
    }
    let named = read(b"u::rw-,u:502:r--,u:4300:r-x,g::r--,g:4242:rw-,m::rwx,o::---");
    assert_eq!(
        text::write_named(&named, Spelling::STAR, user_name, group_name),
        b"user::rw-,user:lisa:r--:502,user:4300:r-x,group::r--,group:domain\\040users:rw-:4242,mask::rwx,other::---"
    );

    // libarchive writes names as they are. A comma in one ends the entry,
    // for every reader: GNU tar refuses the list, and libarchive drops the
    // entry and sets the rest.
    assert_eq!(
        text::parse(b"user::rwx,group::r-x,other::r--,group:comma,g:r--:4246,mask::rwx"),
        Err(ParseError::Incomplete { at: 43 })
    );
    // A user named by digits is written with them, which GNU tar and libacl
    // read as the id and libarchive looks up as a name: refused, as the id
    // recorded beside them is another.
    assert_eq!(
        text::parse(b"user::rw-,group::r--,other::---,user:4242:r--:5000,mask::rw-"),
        Err(ParseError::IdMismatch { at: 46 })
    );
}

/// star 1.7.0's records (`-c -acl H=exustar`), written under the account
/// database above for lists `setfacl` set, as [`LIBARCHIVE`]'s are.
const STAR: &[LibarchiveRecords] = &[
    (
        "named",
        b"u::rw-,u:502:r--,u:4300:r-x,g::r--,g:4242:rw-,m::rwx,o::---",
        Some(b"user::rw-,user:lisa:r--:502,user:4300:r-x,group::r--,group:domain\\040users:rw-,mask::rwx,other::---"),
        None,
    ),
    (
        "escaped",
        b"u::rwx,u:4243:r--,u:4250:rw-,u:4260:--x,g::r-x,g:4245:r--,g:4246:r--,g:4251:r--,g:4252:-w-,g:4253:r--,g:4254:r--,g:4255:r--,g:4256:rw-,g:4257:r--,g:4258:--x,m::rwx,o::r--",
        Some(b"user::rwx,user:a\\040b:r--,user:back\\\\slash:rw-,user:caf\xc3\xa9:--x:4260,group::r-x,group:hash#g:r--:4245,group:comma\\054g:r--,group:back\\\\slashg:r--,group:tab\\011g:-w-,group:caf\xc3\xa9:r--:4253,group:del\x7fg:r--:4254,group:ctl\x01g:r--:4255,group:trail\\040:rw-,group:hash\\040#g:r--,group:eq=g:--x:4258,mask::rwx,other::r--"),
        None,
    ),
    (
        "dir-both",
        b"u::rwx,u:502:r-x,g::r-x,g:4242:rwx,m::rwx,o::r-x",
        Some(b"user::rwx,user:lisa:r-x:502,group::r-x,group:domain\\040users:rwx,mask::rwx,other::r-x"),
        Some(b"user::rwx,user:lisa:rwx:502,group::r-x,mask::rwx,other::---"),
    ),
    (
        "dir-default",
        b"u::rwx,u:502:r-x,g::r-x,m::r-x,o::r-x",
        None,
        Some(b"user::rwx,user:lisa:r-x:502,group::r-x,mask::r-x,other::r-x"),
    ),
];

#[test]
fn stars_records_state_the_lists_set() {
    for &(member, set, access, default) in STAR {
        let set = read(set);
        let text = access.or(default).expect(member);
        // Names resolved through the database, the escaped ones star records
        // no id for included, and a `#` inside a name read as part of it, as
        // libacl and GNU tar read it.
        assert_eq!(read(text), set, "{member}");
        // star's spelling and this one share their form; they differ where
        // star records no id after a name it escapes, and where it writes a
        // `#`, DEL or control byte as it is.
        let written = text::write_named(&set, Spelling::STAR, user_name, group_name);
        assert_eq!(read(&written), set, "{member}");
        if member == "dir-default" {
            assert_eq!(written, text, "{member}");
        }
    }
    let named = read(b"u::rw-,u:502:r--,u:4300:r-x,g::r--,g:4242:rw-,m::rwx,o::---");
    assert_eq!(
        text::write_named(&named, Spelling::STAR, user_name, group_name),
        b"user::rw-,user:lisa:r--:502,user:4300:r-x,group::r--,group:domain\\040users:rw-:4242,mask::rwx,other::---"
    );
    // star writes names of digits as they are, with no id: `4242` is read as
    // the id, and `007`, which libacl reads as 7, is refused.
    assert_eq!(
        text::parse(b"user::rw-,user:4242:r--,user:007:-w-,group::r--,mask::rw-,other::---"),
        Err(ParseError::Number { at: 29 })
    );
}

/// A case, the crate's text, and the list star set from it with the account
/// database and with root alone.
type StarReading = (&'static str, &'static [u8], &'static [u8], &'static [u8]);

/// The crate's [`Spelling::STAR`] text of 22 lists, each naming one user or
/// group of the account database above (a name of digits by its id), beside
/// the list star 1.7.0 set from it (`-x -acl -p`, as root in user and mount
/// namespaces), under that database and under one holding root alone. star
/// reads an id after a name only in this form, so the text is held byte for
/// byte: a change to what the crate writes is a change to what star reads.
const STAR_READS: &[StarReading] = &[
    (
        "user `lisa`",
        b"user::rw-,user:lisa:r--:502,group::r--,mask::r--,other::---",
        b"u::rw-,u:502:r--,g::r--,m::r--,o::---",
        b"u::rw-,u:502:r--,g::r--,m::r--,o::---",
    ),
    (
        "user `a b`",
        b"user::rw-,user:a\\040b:r--:4243,group::r--,mask::r--,other::---",
        b"u::rw-,u:4243:r--,g::r--,m::r--,o::---",
        b"u::rw-,u:4243:r--,g::r--,m::r--,o::---",
    ),
    (
        "user `back\\slash`",
        b"user::rw-,user:back\\\\slash:r--:4250,group::r--,mask::r--,other::---",
        b"u::rw-,u:4250:r--,g::r--,m::r--,o::---",
        b"u::rw-,u:4250:r--,g::r--,m::r--,o::---",
    ),
    (
        "user `café`",
        b"user::rw-,user:caf\xc3\xa9:r--:4260,group::r--,mask::r--,other::---",
        b"u::rw-,u:4260:r--,g::r--,m::r--,o::---",
        b"u::rw-,u:4260:r--,g::r--,m::r--,o::---",
    ),
    (
        "user `4242`",
        b"user::rw-,user:5000:r--,group::r--,mask::r--,other::---",
        b"u::rw-,u:5000:r--,g::r--,m::r--,o::---",
        b"u::rw-,u:5000:r--,g::r--,m::r--,o::---",
    ),
    (
        "user `007`",
        b"user::rw-,user:5002:r--,group::r--,mask::r--,other::---",
        b"u::rw-,u:5002:r--,g::r--,m::r--,o::---",
        b"u::rw-,u:5002:r--,g::r--,m::r--,o::---",
    ),
    (
        "user `99999999999`",
        b"user::rw-,user:5003:r--,group::r--,mask::r--,other::---",
        b"u::rw-,u:5003:r--,g::r--,m::r--,o::---",
        b"u::rw-,u:5003:r--,g::r--,m::r--,o::---",
    ),
    (
        "user `4294967295`",
        b"user::rw-,user:5007:r--,group::r--,mask::r--,other::---",
        b"u::rw-,u:5007:r--,g::r--,m::r--,o::---",
        b"u::rw-,u:5007:r--,g::r--,m::r--,o::---",
    ),
    (
        "group `wheel`",
        b"user::rw-,group::r--,group:wheel:r--:10,mask::rw-,other::---",
        b"u::rw-,g::r--,g:10:r--,m::rw-,o::---",
        b"u::rw-,g::r--,g:10:r--,m::rw-,o::---",
    ),
    (
        "group `domain users`",
        b"user::rw-,group::r--,group:domain\\040users:r--:4242,mask::rw-,other::---",
        b"u::rw-,g::r--,g:4242:r--,m::rw-,o::---",
        b"u::rw-,g::r--,g:4242:r--,m::rw-,o::---",
    ),
    (
        "group `hash#g`",
        b"user::rw-,group::r--,group:hash\\043g:r--:4245,mask::rw-,other::---",
        b"u::rw-,g::r--,g:4245:r--,m::rw-,o::---",
        b"u::rw-,g::r--,g:4245:r--,m::rw-,o::---",
    ),
    (
        "group `comma,g`",
        b"user::rw-,group::r--,group:comma\\054g:r--:4246,mask::rw-,other::---",
        b"u::rw-,g::r--,g:4246:r--,m::rw-,o::---",
        b"u::rw-,g::r--,g:4246:r--,m::rw-,o::---",
    ),
    (
        "group `back\\slashg`",
        b"user::rw-,group::r--,group:back\\\\slashg:r--:4251,mask::rw-,other::---",
        b"u::rw-,g::r--,g:4251:r--,m::rw-,o::---",
        b"u::rw-,g::r--,g:4251:r--,m::rw-,o::---",
    ),
    (
        "group `tab\\tg`",
        b"user::rw-,group::r--,group:tab\\011g:r--:4252,mask::rw-,other::---",
        b"u::rw-,g::r--,g:4252:r--,m::rw-,o::---",
        b"u::rw-,g::r--,g:4252:r--,m::rw-,o::---",
    ),
    (
        "group `café`",
        b"user::rw-,group::r--,group:caf\xc3\xa9:r--:4253,mask::rw-,other::---",
        b"u::rw-,g::r--,g:4253:r--,m::rw-,o::---",
        b"u::rw-,g::r--,g:4253:r--,m::rw-,o::---",
    ),
    (
        "group `del\\x7fg`",
        b"user::rw-,group::r--,group:del\\177g:r--:4254,mask::rw-,other::---",
        b"u::rw-,g::r--,g:4254:r--,m::rw-,o::---",
        b"u::rw-,g::r--,g:4254:r--,m::rw-,o::---",
    ),
    (
        "group `ctl\\x01g`",
        b"user::rw-,group::r--,group:ctl\\001g:r--:4255,mask::rw-,other::---",
        b"u::rw-,g::r--,g:4255:r--,m::rw-,o::---",
        b"u::rw-,g::r--,g:4255:r--,m::rw-,o::---",
    ),
    (
        "group `trail `",
        b"user::rw-,group::r--,group:trail\\040:r--:4256,mask::rw-,other::---",
        b"u::rw-,g::r--,g:4256:r--,m::rw-,o::---",
        b"u::rw-,g::r--,g:4256:r--,m::rw-,o::---",
    ),
    (
        "group `hash #g`",
        b"user::rw-,group::r--,group:hash\\040\\043g:r--:4257,mask::rw-,other::---",
        b"u::rw-,g::r--,g:4257:r--,m::rw-,o::---",
        b"u::rw-,g::r--,g:4257:r--,m::rw-,o::---",
    ),
    (
        "group `eq=g`",
        b"user::rw-,group::r--,group:eq=g:r--:4258,mask::rw-,other::---",
        b"u::rw-,g::r--,g:4258:r--,m::rw-,o::---",
        b"u::rw-,g::r--,g:4258:r--,m::rw-,o::---",
    ),
    (
        "group `4242`",
        b"user::rw-,group::r--,group:5001:r--,mask::rw-,other::---",
        b"u::rw-,g::r--,g:5001:r--,m::rw-,o::---",
        b"u::rw-,g::r--,g:5001:r--,m::rw-,o::---",
    ),
    (
        "a name of digits written as the id",
        b"user::rw-,user:5000:r--,group::r--,mask::r--,other::---",
        b"u::rw-,u:5000:r--,g::r--,m::r--,o::---",
        b"u::rw-,u:5000:r--,g::r--,m::r--,o::---",
    ),
];

#[test]
fn star_reads_the_crates_star_text_as_the_list() {
    for &(case, written, with_names, without) in STAR_READS {
        let set = read(with_names);
        assert_eq!(read(without), set, "{case}");
        assert_eq!(
            text::write_named(&set, Spelling::STAR, user_name, group_name),
            written,
            "{case}"
        );
    }
}

/// A list naming up to four users and four groups, ids drawn from `users`
/// and `groups` and from anywhere.
fn generated_list(rng: &mut Rng, users: &[u32], groups: &[u32]) -> Acl {
    let mut entries = vec![
        Entry::new(Qualifier::UserObj, perm(rng.below(8) as u16)),
        Entry::new(Qualifier::GroupObj, perm(rng.below(8) as u16)),
        Entry::new(Qualifier::Other, perm(rng.below(8) as u16)),
    ];
    let mut named = BTreeMap::new();
    for _ in 0..rng.below(9) {
        let user = rng.below(2) == 0;
        let id = match rng.below(3) {
            0 => rng.below(u64::from(UNDEFINED_ID)) as u32,
            _ if user => *rng.pick(users),
            _ => *rng.pick(groups),
        };
        let qualifier = if user {
            Qualifier::User(id)
        } else {
            Qualifier::Group(id)
        };
        named.insert(qualifier, perm(rng.below(8) as u16));
    }
    if !named.is_empty() || rng.below(3) == 0 {
        entries.push(Entry::new(Qualifier::Mask, perm(rng.below(8) as u16)));
    }
    entries.extend(
        named
            .into_iter()
            .map(|(qualifier, perm)| Entry::new(qualifier, perm)),
    );
    Acl::new(entries).expect("a valid list")
}

/// Every spelling: tags, separator, and named entries with their ids or
/// without.
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

/// A name for each id, of bytes a text cannot hold as they are: blanks,
/// separators, `#`, backslashes, control bytes, digits, UTF-8 and bytes that
/// are not UTF-8; empty, holding a NUL, or reading as a number, now and
/// then.
fn generated_names(rng: &mut Rng, ids: &[u32]) -> BTreeMap<u32, Vec<u8>> {
    let alphabet: &[u8] = b" \t\r\n,:#\\\x01\x7f0123456789xab-+\xc3\xa9\xff";
    let mut names = BTreeMap::new();
    let mut taken = std::collections::BTreeSet::new();
    for &id in ids {
        let name: Vec<u8> = match rng.below(12) {
            0 => Vec::new(),
            1 => b"a\0b".to_vec(),
            2 => rng
                .pick(&[&b"4242"[..], b"0x10", b"010", b" 7", b"+5"])
                .to_vec(),
            _ => (0..=rng.below(8)).map(|_| *rng.pick(alphabet)).collect(),
        };
        if taken.insert(name.clone()) {
            names.insert(id, name);
        }
    }
    names
}

#[test]
fn a_written_list_reads_back_as_itself() {
    let mut rng = Rng::seeded(7);
    let users: Vec<u32> = USERS.iter().map(|user| user.1).collect();
    let groups: Vec<u32> = GROUPS.iter().map(|group| group.1).collect();
    for _ in 0..2000 {
        let acl = generated_list(&mut rng, &users, &groups);
        for spelling in SPELLINGS {
            let numeric = text::write(&acl, spelling);
            let parsed = text::parse(&numeric)
                .expect("the text parses")
                .expect("a list");
            assert_eq!(
                parsed.resolve(|_| None, |_| None, Prefer::Name),
                Ok(acl.clone())
            );
            let named = text::write_named(&acl, spelling, user_name, group_name);
            assert_eq!(read(&named), acl);
            if spelling.names == Names::WithIds {
                // Each name's id is recorded beside it, so the text reads
                // back with no lookup, and preferring the ids.
                let parsed = text::parse(&named)
                    .expect("the text parses")
                    .expect("a list");
                assert_eq!(
                    parsed.resolve(|_| None, |_| None, Prefer::Name),
                    Ok(acl.clone())
                );
                assert_eq!(
                    parsed.resolve(user_id, group_id, Prefer::Id),
                    Ok(acl.clone())
                );
            }
        }
        // Names of any bytes, each read back through the same table.
        let ids: Vec<u32> = acl
            .entries()
            .iter()
            .filter_map(|entry| entry.qualifier.id())
            .collect();
        let names = generated_names(&mut rng, &ids);
        let ids_of: BTreeMap<&[u8], u32> = names
            .iter()
            .map(|(id, name)| (name.as_slice(), *id))
            .collect();
        let lookup = |name: &[u8]| ids_of.get(name).copied();
        for spelling in SPELLINGS {
            let written =
                text::write_named(&acl, spelling, |id| names.get(&id), |id| names.get(&id));
            let shown = String::from_utf8_lossy(&written);
            let parsed = text::parse(&written)
                .unwrap_or_else(|err| panic!("{shown:?}: {err}"))
                .expect("a list");
            assert_eq!(
                parsed.resolve(lookup, lookup, Prefer::Name),
                Ok(acl.clone()),
                "{shown:?}"
            );
        }
    }
}

#[test]
fn libacl_reads_written_text_as_the_list() {
    let Some(mut libacl) = libacl_with_the_accounts("text-written") else {
        return;
    };
    let mut rng = Rng::seeded(11);
    let users: Vec<u32> = USERS.iter().map(|user| user.1).collect();
    let groups: Vec<u32> = GROUPS.iter().map(|group| group.1).collect();
    let mut named = 0;
    for _ in 0..1500 {
        let acl = generated_list(&mut rng, &users, &groups);
        // libacl reads no fourth field.
        for spelling in SPELLINGS.into_iter().filter(|s| s.names == Names::Alone) {
            for written in [
                text::write(&acl, spelling),
                text::write_named(&acl, spelling, user_name, group_name),
            ] {
                let shown = String::from_utf8_lossy(&written);
                match libacl.read(&written) {
                    Reading::Valid(value) => {
                        assert_eq!(xattr::decode(&value), Ok(Some(acl.clone())), "{shown:?}");
                    }
                    other => panic!("{shown:?}: libacl answered {other:?}"),
                }
                named += usize::from(
                    written.iter().any(u8::is_ascii_lowercase) && written.contains(&b'\\'),
                );
            }
        }
    }
    assert!(named > 100, "too few written texts escaped a name: {named}");
}

/// Users and groups whose names glibc's files database cannot hold: they
/// begin with `#`, `+`, `-`, a blank, a line end or a carriage return, or
/// hold a line end, a carriage return or a colon. libacl was measured
/// reading them through a name service of another source.
const ODD_USERS: &[(&[u8], u32)] = &[
    (b"#hashfirst", 6001),
    (b"+plus", 6002),
    (b"-minus", 6003),
    (b"x\ny", 6014),
];

const ODD_GROUPS: &[(&[u8], u32)] = &[
    (b" lead", 6004),
    (b"nl\nx", 6005),
    (b"co:lon", 6006),
    (b"cr\rx", 6007),
    (b"-", 6008),
    (b"+", 6009),
    (b"nl", 6010),
    (b"cr", 6011),
    (b"\nlead", 6012),
    (b" ", 6013),
    (b"\rlead", 6015),
];

/// How libacl 2.3.2 read an entry beside `u::rw-`, `g::r--`, `m::rwx` and
/// `o::---`, the names above answered: the id it gave the entry, or `None`
/// where it refused the text; and what the crate says where it differs, the
/// stated class.
const ODD_READINGS: &[(&[u8], Option<u32>, Option<&str>)] = &[
    (b"user:#hashfirst:r--", None, None),
    (b"user:\\043hashfirst:r--", Some(6001), None),
    (b"user:+plus:r--", Some(6002), None),
    (b"user:-minus:r--", Some(6003), None),
    (b"group: lead:r--", Some(6004), None),
    (b"group:\\040lead:r--", Some(6004), None),
    (b"group:nl\nx:r--", None, None),
    (b"group:nl\\012x:r--", Some(6005), None),
    (b"group:co:lon:r--", None, None),
    (b"group:co\\072lon:r--", Some(6006), None),
    (b"group:cr\rx:r--", None, None),
    (b"group:cr\\015x:r--", Some(6007), None),
    (b"group:-:r--", Some(6008), None),
    (b"group:+:r--", Some(6009), None),
    (b"group:\nlead:r--", Some(6012), Some(LEADING_LINE_END)),
    (b"group:\\012lead:r--", Some(6012), None),
    (b"group: :r--", Some(6013), None),
    (b"group:\\040:r--", Some(6013), None),
    (b"group:\rlead:r--", Some(6015), Some(LEADING_LINE_END)),
    (b"group:\\015lead:r--", Some(6015), None),
    (b"user:x\ny:r--", None, None),
    (b"group:nl\n:r--", None, None),
    (b"group:cr\r:r--", None, None),
    (b"group:nl\r\n:r--", None, None),
    (b"group:\n6010:r--", Some(6010), Some(LOOSE_NUMBER)),
    (b"group:\r6010:r--", Some(6010), Some(LOOSE_NUMBER)),
];

#[test]
fn names_the_files_database_cannot_hold_read_as_libacl_reads_them() {
    let user = |name: &[u8]| ODD_USERS.iter().find(|u| u.0 == name).map(|u| u.1);
    let group = |name: &[u8]| ODD_GROUPS.iter().find(|g| g.0 == name).map(|g| g.1);
    for &(entry, libacl, stated) in ODD_READINGS {
        let mut text = b"u::rw-\ng::r--\nm::rwx\no::---\n".to_vec();
        text.extend_from_slice(entry);
        let shown = String::from_utf8_lossy(entry);
        let ours = text::parse(&text)
            .map(|parsed| parsed.expect("a list"))
            .map_err(|error| error.to_string())
            .and_then(|parsed| {
                parsed
                    .resolve(user, group, Prefer::Name)
                    .map_err(|error| error.to_string())
            });
        let named = ours
            .as_ref()
            .ok()
            .and_then(|acl| acl.entries().iter().find_map(|entry| entry.qualifier.id()));
        match (libacl, stated) {
            (Some(id), None) => assert_eq!(named, Some(id), "{shown:?}: {ours:?}"),
            (None, None) => assert!(ours.is_err(), "{shown:?}: {ours:?}"),
            (Some(_), Some(class)) => {
                assert!(STATED.contains(&class), "{shown:?}");
                assert!(ours.is_err(), "{shown:?}: {ours:?}");
            }
            (None, Some(_)) => panic!("{shown:?}: a refusal needs no stated class"),
        }
    }
    // The writer escapes each, so libacl and the crate read them back.
    let acl = Acl::new(
        [
            (Qualifier::UserObj, 6),
            (Qualifier::GroupObj, 4),
            (Qualifier::Mask, 7),
            (Qualifier::Other, 0),
        ]
        .into_iter()
        .chain(ODD_USERS.iter().map(|u| (Qualifier::User(u.1), 4)))
        .chain(ODD_GROUPS.iter().map(|g| (Qualifier::Group(g.1), 4)))
        .map(|(qualifier, bits)| Entry::new(qualifier, perm(bits)))
        .collect(),
    )
    .expect("a valid list");
    let user_name = |id: u32| ODD_USERS.iter().find(|u| u.1 == id).map(|u| u.0);
    let group_name = |id: u32| ODD_GROUPS.iter().find(|g| g.1 == id).map(|g| g.0);
    for spelling in SPELLINGS {
        let written = text::write_named(&acl, spelling, user_name, group_name);
        assert!(!written.contains(&b'#') && !written.contains(&b'\r'));
        let parsed = text::parse(&written)
            .expect("the text parses")
            .expect("a list");
        assert_eq!(parsed.resolve(user, group, Prefer::Name), Ok(acl.clone()));
    }
}

#[test]
fn each_fault_is_named_where_it_is_found() {
    let cases: &[(&[u8], ParseError)] = &[
        (b"u::rw-\0,g::r--,o::---", ParseError::Nul { at: 6 }),
        (b"\n# a list\nu::rw-", ParseError::LeadingComment { at: 1 }),
        (b"u::rw- #c\n", ParseError::Comment { at: 7 }),
        (b"u::rw-\n#c\n#d\ng::r--", ParseError::Comment { at: 7 }),
        (b" \r\n\t", ParseError::NoEntry),
        (b"u::rw-,U::r--", ParseError::Tag { at: 7 }),
        (b"u::rw-,g::r--,,o::---", ParseError::Tag { at: 14 }),
        (b"u::rw-,g:4242,o::---", ParseError::Incomplete { at: 13 }),
        (b"u::rw-,g:4242", ParseError::Incomplete { at: 13 }),
        (b"u::rw-,g:#x:r--", ParseError::Qualifier { at: 9 }),
        (b"u::rw-,g:a\nb:r--", ParseError::LineEnd { at: 10 }),
        (b"u::rw-,g:\rab:r--", ParseError::LineEnd { at: 9 }),
        // The first fault: the line end, before the escape.
        (b"u::rw-,g:a\n\\400:r--", ParseError::LineEnd { at: 10 }),
        (b"u::rw-,g:a\\400\n:r--", ParseError::Escape { at: 10 }),
        // A number after a line end is loose, not a name.
        (b"u::rw-,g:\n42:r--", ParseError::Number { at: 9 }),
        (b"u::rw-,g:ab\\000:r--", ParseError::Escape { at: 11 }),
        (b"u::rw-,g:ab\\400:r--", ParseError::Escape { at: 11 }),
        (b"u::rw-,g:010:r--", ParseError::Number { at: 9 }),
        (b"u::rw-,g:4294967296:r--", ParseError::Number { at: 9 }),
        (b"u::rw-,g::rwxr", ParseError::Perm { at: 10 }),
        (b"u::rw-,g::", ParseError::Perm { at: 10 }),
        (b"u::rw-,g:lisa:r--:x", ParseError::Id { at: 18 }),
        (b"u::rw-,g:lisa:r--:4294967295", ParseError::Id { at: 18 }),
        (b"u::rw-:5", ParseError::Id { at: 7 }),
        (b"u::rw-,m::r--:5", ParseError::Id { at: 13 }),
        (b"u::rw-,g:5:r--:6", ParseError::IdMismatch { at: 15 }),
        (b"u::rw- x", ParseError::Separator { at: 7 }),
    ];
    for &(text, error) in cases {
        assert_eq!(
            text::parse(text),
            Err(error),
            "{:?}",
            String::from_utf8_lossy(text)
        );
    }
}

#[test]
fn each_error_says_what_failed() {
    let messages: &[(ParseError, &str)] = &[
        (ParseError::Nul { at: 6 }, "the text holds a NUL at byte 6"),
        (
            ParseError::LeadingComment { at: 1 },
            "the comment at byte 1 comes before the first entry",
        ),
        (
            ParseError::Comment { at: 7 },
            "the comment at byte 7 is followed by another comment or by blank lines alone",
        ),
        (ParseError::NoEntry, "the text holds no entry"),
        (
            ParseError::Tag { at: 7 },
            "the entry at byte 7 does not begin with a tag and a colon",
        ),
        (
            ParseError::Incomplete { at: 13 },
            "the entry ends at byte 13, before its permissions",
        ),
        (
            ParseError::Qualifier { at: 9 },
            "the qualifier at byte 9 begins with #",
        ),
        (
            ParseError::LineEnd { at: 10 },
            "the name holds a line end or carriage return at byte 10",
        ),
        (
            ParseError::Escape { at: 11 },
            "the escape at byte 11 gives a NUL or more than a byte",
        ),
        (
            ParseError::Number { at: 9 },
            "the qualifier at byte 9 is a number in another form than a decimal id",
        ),
        (
            ParseError::Perm { at: 10 },
            "the permissions at byte 10 are not one to three of r, w, x and -",
        ),
        (
            ParseError::Id { at: 18 },
            "the field at byte 18, after the permissions, is not a decimal id, \
             or is on an entry naming no one",
        ),
        (
            ParseError::IdMismatch { at: 15 },
            "the id field at byte 15 states another id than its entry names",
        ),
        (
            ParseError::Separator { at: 7 },
            "an entry is followed at byte 7 by something other than a separator",
        ),
    ];
    for (error, message) in messages {
        assert_eq!(error.to_string(), *message);
    }
    let unresolved = |tag, name: &[u8]| ResolveError::Unresolved {
        tag,
        name: name.to_vec(),
    };
    assert_eq!(
        unresolved(Tag::User, "caf\u{e9}".as_bytes()).to_string(),
        "the user named \"caf\u{e9}\" has no id"
    );
    assert_eq!(
        unresolved(Tag::Group, b"tab\t\xff\"").to_string(),
        "the group named \"tab\\t\\xff\\\"\" has no id"
    );
    assert_eq!(
        ResolveError::Invalid(Invalid::Missing { tag: Tag::Mask }).to_string(),
        Invalid::Missing { tag: Tag::Mask }.to_string()
    );
}

#[test]
fn a_name_is_resolved_and_a_recorded_id_is_its_fallback_or_its_answer() {
    let parsed = text::parse(b"u::rw-,u:lisa:rw-:502,g::r--,g:wheel:r--,m::rw-,o::---")
        .unwrap()
        .unwrap();
    let with = |user: u32, group: u32| {
        acl(&[
            (Qualifier::UserObj, 6),
            (Qualifier::User(user), 6),
            (Qualifier::GroupObj, 4),
            (Qualifier::Group(group), 4),
            (Qualifier::Mask, 6),
            (Qualifier::Other, 0),
        ])
    };
    // The lookup's answer over the recorded id.
    let users = |_: &[u8]| Some(1000);
    assert_eq!(
        parsed.resolve(users, group_id, Prefer::Name),
        Ok(with(1000, 10))
    );
    // The recorded id where the lookup has none.
    assert_eq!(
        parsed.resolve(|_| None, group_id, Prefer::Name),
        Ok(with(502, 10))
    );
    // The recorded id without asking, given `Prefer::Id`.
    let mut asked = Vec::new();
    let users = |name: &[u8]| {
        asked.push(name.to_vec());
        Some(1000)
    };
    assert_eq!(
        parsed.resolve(users, group_id, Prefer::Id),
        Ok(with(502, 10))
    );
    assert!(asked.is_empty());
    // A name with no answer and no recorded id stops the list, and nothing
    // after it is asked.
    let mut asked = Vec::new();
    let groups = |name: &[u8]| {
        asked.push(name.to_vec());
        None
    };
    let parsed = text::parse(b"u::rw-,g:nosuch:r--,g:wheel:r--,g::r--,m::r--,o::---")
        .unwrap()
        .unwrap();
    assert_eq!(
        parsed.resolve(user_id, groups, Prefer::Name),
        Err(ResolveError::Unresolved {
            tag: Tag::Group,
            name: b"nosuch".to_vec()
        })
    );
    assert_eq!(asked, [b"nosuch".to_vec()]);
    // Names that stand for one id name it twice.
    let parsed = text::parse(b"u::rw-,u:a:r--,u:b:r--,g::r--,m::r--,o::---")
        .unwrap()
        .unwrap();
    assert_eq!(
        parsed.resolve(|_| Some(7), |_| None, Prefer::Name),
        Err(ResolveError::Invalid(Invalid::Repeated {
            qualifier: Qualifier::User(7)
        }))
    );
    // A name is passed with its escapes decoded; an id is never looked up.
    let parsed = text::parse(b"u::rw-,u:a\\040b:r--,u:4242:r--,g::r--,m::r--,o::---")
        .unwrap()
        .unwrap();
    assert!(parsed.holds_names());
    let mut asked = Vec::new();
    let users = |name: &[u8]| {
        asked.push(name.to_vec());
        user_id(name)
    };
    let resolved = parsed.resolve(users, |_| None, Prefer::Name).unwrap();
    assert_eq!(asked, [b"a b".to_vec()]);
    assert_eq!(resolved.perm(Qualifier::User(4242)), Some(Perm::READ));
    // A text naming everyone by id, a recorded id beside it or not, holds no
    // name a lookup must answer; a name with a recorded id still is one.
    for (text, named) in [
        (
            &b"u::rw-,u:4242:r--:4242,g::r--,g:7:r--,m::r--,o::---"[..],
            false,
        ),
        (b"u::rw-,g::r--,o::---", false),
        (b"u::rw-,g::r--,g:wheel:r--:10,m::r--,o::---", true),
    ] {
        assert_eq!(text::parse(text).unwrap().unwrap().holds_names(), named);
    }
}

#[test]
fn a_name_nobody_answers_is_left_out_and_everyone_else_keeps_their_entry() {
    let parsed = text::parse(
        b"u::rw-,u:alice:---,u:bob:rw-,u:carol:r--:77,g::r--,g:staff:rw-,g:nosuch:rwx,m::rw-,o::r--",
    )
    .unwrap()
    .unwrap();
    let mut asked = Vec::new();
    let users = |name: &[u8]| {
        asked.push(name.to_vec());
        (name == b"alice").then_some(1000)
    };
    let groups = |name: &[u8]| (name == b"staff").then_some(50);
    let partial = parsed.resolve_partial(users, groups, Prefer::Name).unwrap();
    // bob and nosuch are left out; carol falls back on her recorded id.
    assert_eq!(
        partial.list,
        acl(&[
            (Qualifier::UserObj, 6),
            (Qualifier::User(77), 4),
            (Qualifier::User(1000), 0),
            (Qualifier::GroupObj, 4),
            (Qualifier::Group(50), 6),
            (Qualifier::Mask, 6),
            (Qualifier::Other, 4),
        ])
    );
    assert_eq!(partial.left_out, 2);
    // Every name is asked about, in the text's order, past one without an
    // answer.
    assert_eq!(
        asked,
        [b"alice".to_vec(), b"bob".to_vec(), b"carol".to_vec()]
    );

    // With every name answered, it is `resolve`.
    let every = |name: &[u8]| Some(name.iter().map(|&byte| u32::from(byte)).sum());
    let partial = parsed.resolve_partial(every, every, Prefer::Name).unwrap();
    assert_eq!(Ok(partial.list), parsed.resolve(every, every, Prefer::Name));
    assert_eq!(partial.left_out, 0);

    // With none, the entries naming no one, the mask among them, and the
    // recorded id.
    let partial = parsed
        .resolve_partial(|_| None, |_| None, Prefer::Name)
        .unwrap();
    assert_eq!(
        partial.list,
        acl(&[
            (Qualifier::UserObj, 6),
            (Qualifier::User(77), 4),
            (Qualifier::GroupObj, 4),
            (Qualifier::Mask, 6),
            (Qualifier::Other, 4),
        ])
    );
    assert_eq!(partial.left_out, 4);

    // A text naming someone with no mask states no list, whoever is left
    // out, as the narrowing judges it.
    let unmasked = text::parse(b"u::rw-,u:nosuch:rwx,g::r--,o::r--")
        .unwrap()
        .unwrap();
    assert_eq!(
        unmasked.resolve_partial(|_| None, |_| None, Prefer::Name),
        Err(Invalid::Missing { tag: Tag::Mask })
    );
    // Names that stand for one id name it twice; two left out are not
    // judged.
    let twice = text::parse(b"u::rw-,u:a:r--,u:b:r--,g::r--,m::r--,o::---")
        .unwrap()
        .unwrap();
    assert_eq!(
        twice.resolve_partial(|_| Some(7), |_| None, Prefer::Name),
        Err(Invalid::Repeated {
            qualifier: Qualifier::User(7)
        })
    );
    assert_eq!(
        twice
            .resolve_partial(|_| None, |_| None, Prefer::Name)
            .map(|partial| partial.left_out),
        Ok(2)
    );
    // `Prefer::Id` takes a recorded id without asking.
    let mut asked = 0;
    let users = |_: &[u8]| {
        asked += 1;
        None
    };
    let partial = parsed.resolve_partial(users, |_| None, Prefer::Id).unwrap();
    assert_eq!(partial.list.perm(Qualifier::User(77)), Some(Perm::READ));
    assert_eq!(asked, 2);
}

#[test]
fn a_text_resolved_in_part_states_the_list_mapped_in_part() {
    // A list written with a name for each id, then read back through a
    // lookup that answers some of the names, is the list with the same ids
    // left out by a translation.
    let mut rng = Rng::seeded(0x7061_7274);
    for _ in 0..2_000 {
        let mut entries = vec![
            Entry::new(Qualifier::UserObj, perm(rng.below(8) as u16)),
            Entry::new(Qualifier::GroupObj, perm(rng.below(8) as u16)),
            Entry::new(Qualifier::Other, perm(rng.below(8) as u16)),
        ];
        for id in 0..6 {
            if rng.below(2) == 0 {
                entries.push(Entry::new(Qualifier::User(id), perm(rng.below(8) as u16)));
            }
            if rng.below(2) == 0 {
                entries.push(Entry::new(Qualifier::Group(id), perm(rng.below(8) as u16)));
            }
        }
        if entries.len() > 3 || rng.below(2) == 0 {
            entries.push(Entry::new(Qualifier::Mask, perm(rng.below(8) as u16)));
        }
        let list = Acl::new(entries).unwrap();
        let known: Vec<u32> = (0..6).filter(|_| rng.below(2) == 0).collect();
        let answered = |id: u32| known.contains(&id).then_some(id);
        let name = |id: u32| Some(format!("n{id}"));
        let written = text::write_named(&list, Spelling::GNU_TAR, name, name);
        let parsed = text::parse(&written).unwrap().unwrap();
        let lookup = |name: &[u8]| {
            let id = std::str::from_utf8(name)
                .ok()?
                .strip_prefix('n')?
                .parse()
                .ok()?;
            answered(id)
        };
        let resolved = parsed
            .resolve_partial(lookup, lookup, Prefer::Name)
            .unwrap();
        let mapped = list.map_ids_partial(answered, answered).unwrap();
        assert_eq!(resolved, mapped, "{}", String::from_utf8_lossy(&written));
    }
}

#[test]
fn the_narrowing_needs_no_names() {
    let parsed = text::parse(b"u::rw-,u:nosuch:rwx,g::rwx,g:other:r--,m::r-x,o::r--")
        .unwrap()
        .unwrap();
    assert_eq!(parsed.narrowed(), Ok(Acl::from_mode(0o654)));
    for (text, invalid) in [
        (
            &b"u::rw-,u:nosuch:rwx,g::r--,o::r--"[..],
            Invalid::Missing { tag: Tag::Mask },
        ),
        (
            b"u::rw-,u:nosuch:rwx,m::r--,o::r--",
            Invalid::Missing { tag: Tag::GroupObj },
        ),
        (
            b"u::rw-,g::r--,m::r--,m::rw-,o::r--",
            Invalid::Repeated {
                qualifier: Qualifier::Mask,
            },
        ),
    ] {
        assert_eq!(text::parse(text).unwrap().unwrap().narrowed(), Err(invalid));
    }
    // Named entries are not judged among themselves: the same name twice
    // may stand for one id, but needs no answer to narrow.
    let twice = text::parse(b"u::rw-,u:a:r--,u:a:rw-,g::r--,m::r--,o::---")
        .unwrap()
        .unwrap();
    assert_eq!(twice.narrowed(), Ok(Acl::from_mode(0o640)));
}

#[test]
fn a_computed_mask_is_the_one_acl_with_computed_mask_computes() {
    let mut rng = Rng::seeded(13);
    for _ in 0..2000 {
        let acl = generated_list(&mut rng, &[1, 2, 3], &[1, 2, 3]);
        let mut entries = acl.into_entries();
        if rng.below(2) == 0 {
            entries.retain(|entry| entry.qualifier != Qualifier::Mask);
        }
        let spelled = Acl::new(entries.clone())
            .map(|acl| text::write(&acl, Spelling::GNU_TAR))
            .unwrap_or_else(|_| {
                // A list missing its mask: spelled by hand.
                let mut text = Vec::new();
                for entry in &entries {
                    let (tag, id) = match entry.qualifier {
                        Qualifier::UserObj => ("u", String::new()),
                        Qualifier::User(id) => ("u", id.to_string()),
                        Qualifier::GroupObj => ("g", String::new()),
                        Qualifier::Group(id) => ("g", id.to_string()),
                        Qualifier::Mask => ("m", String::new()),
                        Qualifier::Other => ("o", String::new()),
                    };
                    text.extend_from_slice(format!("{tag}:{id}:{}\n", entry.perm).as_bytes());
                }
                text
            });
        let parsed: Parsed = text::parse(&spelled).unwrap().unwrap();
        let computed = parsed
            .with_computed_mask()
            .resolve(|_| None, |_| None, Prefer::Name);
        assert_eq!(
            computed,
            Acl::with_computed_mask(entries).map_err(ResolveError::from)
        );
    }
}

#[test]
fn the_text_form_reads_as_libacl_does_where_libacl_is_strict() {
    // Read: separators, spellings, orders and comments libacl reads.
    for text in [
        &b"u::rw-,g::r--,o::---"[..],
        b"user::rw-,group::r--,other::---",
        b"u::wr-,g::r,o::-",
        b"u::rw-,g::r--,o::---,",
        b"u::rw-\ng::r--\no::---\n",
        b"u::rw-, g::r--, o::---",
        b"o::---,g::r--,u::rw-",
        b"u::rw-\r\ng::r--\r\no::---\r\n",
        b"u::rw-,u:4242:r-- #effective:r--\ng::r--,m::r--,o::---",
        b"user::rw-\nuser:root:r--\ngroup::r--\nmask:r--\nother:---\n",
    ] {
        assert!(
            matches!(text::parse(text), Ok(Some(_))),
            "{:?}",
            String::from_utf8_lossy(text)
        );
    }
    // Refused, as libacl refuses them.
    for text in [
        &b"u::rw-,g::r--,o::"[..],
        b"u:: rw-,g::r--,o::---",
        b" u : : rw- ,g::r--,o::---",
        b"U::rw-,G::r--,O::---",
        b"u::rwX,g::r--,o::---",
        b"u::rw-,g::r--,o::---,d:u::rwx",
        b"u::rw-,g::r--,m:x:rw-,o::---",
        b"u::rw-,g::r--,o::r--:5",
        b"u::rw-,u:1:r--:5:6,g::r--,m::rw-,o::---",
        b"u:1000,g::r--,o::---",
        b"u::rw-,mask,g::r--,o::---",
        b"\n",
        b" , ",
        b"# nothing\n",
    ] {
        assert!(
            text::parse(text).is_err(),
            "{:?}",
            String::from_utf8_lossy(text)
        );
    }
    // Only an empty text is no list, as GNU tar writes a directory's default
    // record when it has none.
    assert_eq!(text::parse(b""), Ok(None));
    // A comment runs to the end of its line, entries after it included: an
    // owner and a named user alone, which make no list.
    assert_eq!(
        text::parse(b"u::rw-,u:4242:r-- #effective:r--,g::r--,m::r--,o::---")
            .unwrap()
            .unwrap()
            .resolve(|_| None, |_| None, Prefer::Name),
        Err(ResolveError::Invalid(Invalid::Missing {
            tag: Tag::GroupObj
        }))
    );
    // A comment ends a comma-separated text: three entries, not four.
    assert_eq!(
        read(b"u::rw-,g::r--,o::r--#c,u:1000:r--").entries().len(),
        3
    );
    // Duplicates and a missing mask are invalid, as libacl's checker says.
    for text in [
        &b"u::rw-,u:1000:r--,u:1000:r--,g::r--,m::rw-,o::r--"[..],
        b"u::rw-,u:1000:r--,g::r--,o::r--",
    ] {
        assert!(matches!(
            text::parse(text)
                .unwrap()
                .unwrap()
                .resolve(|_| None, |_| None, Prefer::Name),
            Err(ResolveError::Invalid(_))
        ));
    }
    // The two spellings of a list read alike.
    assert_eq!(
        read(b"u::rwx,u:1000:rw-,g::r-x,m::rwx,o::r--"),
        read(b"user::rwx,user:1000:rw-,group::r-x,mask::rwx,other::r--")
    );
}

#[test]
fn a_list_is_written_as_gnu_tar_writes_its_text_and_read_back() {
    let acl = acl(&[
        (Qualifier::UserObj, 6),
        (Qualifier::User(0), 4),
        (Qualifier::User(4242), 5),
        (Qualifier::GroupObj, 4),
        (Qualifier::Group(4243), 6),
        (Qualifier::Mask, 7),
        (Qualifier::Other, 0),
    ]);
    let written = text::write(&acl, Spelling::GNU_TAR);
    assert_eq!(
        written,
        b"user::rw-\nuser:0:r--\nuser:4242:r-x\ngroup::r--\ngroup:4243:rw-\nmask::rwx\nother::---\n"
    );
    assert_eq!(read(&written), acl);
    // Named as the database names them, and read back through it.
    let named = text::write_named(&acl, Spelling::GNU_TAR, user_name, group_name);
    assert_eq!(
        named,
        b"user::rw-\nuser:root:r--\nuser:4242:r-x\ngroup::r--\ngroup:4243:rw-\nmask::rwx\nother::---\n"
    );
    assert_eq!(read(&named), acl);
    // A name a text could not say, or that a reader could take for another
    // id, is written as the id.
    for name in [
        &b""[..],
        b"a\0b",
        b"4242",
        b"0x10",
        b" 12",
        b"0b1",
        b"0B11",
        b"+0b101",
        b" 0b1",
    ] {
        let written = text::write_named(
            &acl,
            Spelling::new(Tags::Short, Separator::Comma, Names::WithIds),
            |id| (id == 0).then_some(name),
            |_| None::<&[u8]>,
        );
        // An entry written by id records no id beside it.
        assert!(written.starts_with(b"u::rw-,u:0:r--,"), "{name:?}");
    }
    let escaped = text::write_named(
        &acl,
        Spelling::new(Tags::Short, Separator::Comma, Names::Alone),
        |id| (id == 0).then_some(&b"a b,c:d#e\\f\x01\x7f\n\xff"[..]),
        |_| None::<&[u8]>,
    );
    assert!(
        escaped.starts_with(b"u::rw-,u:a\\040b\\054c\\072d\\043e\\\\f\\001\\177\\012\xff:r--,")
    );
}
