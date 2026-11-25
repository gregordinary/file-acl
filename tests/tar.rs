//! The text form in tar archives: text the crate writes, extracted by GNU tar
//! and bsdtar to the list it states, and the records each tar writes for a
//! file's lists, read by the crate as those lists.
//!
//! Each tar runs as root in user and mount namespaces that map the user's
//! subordinate ids, so it sets lists naming any of them, with an account
//! database of the test's own, whose names need escaping in a text: a blank,
//! a comma, a `#`, a backslash, a control byte. The lists are generated, and
//! a failure names its seed (`FILE_ACL_SEED`).

mod support;

use std::collections::BTreeMap;
use std::ffi::OsStr;
use std::path::{Path, PathBuf};

use file_acl::text::{self, Names, Prefer, Separator, Spelling, Tags};
use file_acl::{Acl, Entry, Perm, Qualifier, xattr};
use support::pax::{self, Member};
use support::{Oracle, Reference, Rng, hex, scratch, tar_with_accounts};

/// The users of the account database, root among them.
const USERS: &[(&[u8], u32)] = &[
    (b"root", 0),
    (b"lisa", 502),
    (b"a b", 4243),
    (b"back\\slash", 4250),
    ("caf\u{e9}".as_bytes(), 4260),
    (b"tab\tu", 4261),
    (b"ctl\x01u", 4262),
    (b"hash#u", 4263),
    (b"trail ", 4264),
    (b"4242", 5000),
];

/// The groups of the account database.
const GROUPS: &[(&[u8], u32)] = &[
    (b"root", 0),
    (b"wheel", 10),
    (b"domain users", 4242),
    (b"comma,g", 4246),
    (b"back\\slashg", 4251),
    ("caf\u{e9}".as_bytes(), 4253),
    (b"del\x7fg", 4254),
    (b"hash #g", 4257),
    (b"eq=g", 4258),
];

/// Names the writing system gives that the tars' database lacks, each one a
/// reader takes for a number where its system lacks the name: binary numbers,
/// which libacl built against glibc 2.38 or later reads as numbers. The crate
/// writes each entry naming one by its id, which every tar sets.
const NUMBER_LIKE: &[(&[u8], u32)] = &[(b"0b0", 7000), (b"0B11", 7003), (b"+0b101", 7005)];

/// Every spelling.
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

const ACCESS_RECORD: &[u8] = b"SCHILY.acl.access";
const DEFAULT_RECORD: &[u8] = b"SCHILY.acl.default";

fn user_id(name: &[u8]) -> Option<u32> {
    USERS.iter().find(|user| user.0 == name).map(|user| user.1)
}

fn group_id(name: &[u8]) -> Option<u32> {
    GROUPS
        .iter()
        .find(|group| group.0 == name)
        .map(|group| group.1)
}

/// The name the writing system gives user `id`: the database's, or one of
/// [`NUMBER_LIKE`].
fn user_name(id: u32) -> Option<&'static [u8]> {
    USERS
        .iter()
        .chain(NUMBER_LIKE)
        .find(|user| user.1 == id)
        .map(|user| user.0)
}

/// The name the writing system gives group `id`: the database's, or one of
/// [`NUMBER_LIKE`].
fn group_name(id: u32) -> Option<&'static [u8]> {
    GROUPS
        .iter()
        .chain(NUMBER_LIKE)
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

/// The tars' namespaces, with the database, holding lists in `dir`.
fn namespace(dir: &Path, reference: Reference) -> Option<Oracle> {
    let (passwd, group) = account_files();
    tar_with_accounts(dir, &passwd, &group, reference)
}

fn perm(bits: u64) -> Perm {
    Perm::from_bits(u16::try_from(bits).expect("three bits")).expect("three bits at most")
}

/// A list naming up to six users and groups, from the database where
/// `named` allows, and otherwise by ids the database names no one: ids the
/// writing system names as a reader takes for a number ([`NUMBER_LIKE`]), and
/// ids no name answers. Now and then, a minimal one.
fn generated_list(rng: &mut Rng, named: impl Fn(&[u8]) -> bool) -> Acl {
    let mut entries = vec![
        Entry::new(Qualifier::UserObj, perm(rng.below(8))),
        Entry::new(Qualifier::GroupObj, perm(rng.below(8))),
        Entry::new(Qualifier::Other, perm(rng.below(8))),
    ];
    if rng.below(5) == 0 {
        return Acl::new(entries).expect("a minimal list");
    }
    let users: Vec<u32> = USERS.iter().filter(|u| named(u.0)).map(|u| u.1).collect();
    let groups: Vec<u32> = GROUPS.iter().filter(|g| named(g.0)).map(|g| g.1).collect();
    let mut seen = BTreeMap::new();
    for _ in 0..=rng.below(6) {
        let user = rng.below(2) == 0;
        let id = if rng.below(12) == 0 {
            rng.pick(NUMBER_LIKE).1
        } else if rng.below(4) == 0 {
            // An id no name answers, below the subordinate ids mapped.
            6000 + rng.below(50_000) as u32
        } else if user {
            *rng.pick(&users)
        } else {
            *rng.pick(&groups)
        };
        let qualifier = if user {
            Qualifier::User(id)
        } else {
            Qualifier::Group(id)
        };
        seen.insert(qualifier, perm(rng.below(8)));
    }
    entries.extend(seen.into_iter().map(|(q, p)| Entry::new(q, p)));
    entries.push(Entry::new(Qualifier::Mask, perm(rng.below(8))));
    Acl::new(entries).expect("a valid list")
}

/// A member, its lists, and its mode as the kernel shows it.
struct Case {
    name: String,
    directory: bool,
    access: Acl,
    default: Option<Acl>,
}

impl Case {
    fn generated(rng: &mut Rng, index: usize, named: &impl Fn(&[u8]) -> bool) -> Case {
        let directory = index % 2 == 1;
        Case {
            name: format!("{}{index}", if directory { "d" } else { "f" }),
            directory,
            access: generated_list(rng, named),
            default: (directory && rng.below(3) != 0).then(|| generated_list(rng, named)),
        }
    }

    /// The member, with records in `spelling`: an access record always, as
    /// GNU tar writes one beside a default list, and for a directory a
    /// default record, empty where it has no default list.
    fn member(&self, spelling: Spelling) -> Member {
        let write = |acl: &Acl| text::write_named(acl, spelling, user_name, group_name);
        let mut records = vec![(ACCESS_RECORD.to_vec(), write(&self.access))];
        if self.directory {
            let default = self.default.as_ref().map(write).unwrap_or_default();
            records.push((DEFAULT_RECORD.to_vec(), default));
        }
        Member {
            name: self.name.clone().into_bytes(),
            directory: self.directory,
            mode: self.access.mode_bits(),
            records,
        }
    }
}

/// The list `path` holds as `name`, or `None` where it holds none.
fn held(oracle: &mut Oracle, path: &Path, name: &str) -> Option<Acl> {
    let path = hex(path.as_os_str().as_encoded_bytes());
    match oracle.get(&path, name) {
        Ok(value) => Some(
            xattr::decode(&value)
                .expect("the kernel holds a list it accepted")
                .expect("a list"),
        ),
        Err(errno) if errno == "ENODATA" => None,
        Err(errno) => panic!("{path} could not be read: {errno}"),
    }
}

/// Checks that `case` was extracted into `dir` with its lists and mode.
fn check_extracted(oracle: &mut Oracle, dir: &Path, case: &Case, context: &str) {
    let path = dir.join(&case.name);
    let access = held(oracle, &path, xattr::ACCESS);
    let expected = (!case.access.is_minimal()).then(|| case.access.clone());
    assert_eq!(access, expected, "{context}: {} access", case.name);
    let mode = oracle.mode(&hex(path.as_os_str().as_encoded_bytes())) & 0o777;
    assert_eq!(
        mode,
        case.access.mode_bits(),
        "{context}: {} mode",
        case.name
    );
    if case.directory {
        let default = held(oracle, &path, xattr::DEFAULT);
        assert_eq!(default, case.default, "{context}: {} default", case.name);
    }
}

/// Runs `command` and `args` in `dir`, in the oracle's namespaces.
fn run(oracle: &mut Oracle, dir: &Path, command: &[&OsStr], args: &[&OsStr]) -> (i32, String) {
    let (program, options) = command.split_first().expect("a program");
    let mut all = options.to_vec();
    all.extend_from_slice(args);
    oracle.run(dir, program, &all)
}

/// Makes `path` a new, empty directory. What a tar extracted there may
/// carry any mode, so it is removed by root in the oracle's namespaces.
fn fresh(oracle: &mut Oracle, path: &Path) {
    let parent = path.parent().expect("a parent");
    let args = [OsStr::new("-rf"), path.as_os_str()];
    let (status, errors) = oracle.run(parent, OsStr::new("rm"), &args);
    assert_eq!(status, 0, "{errors}");
    std::fs::create_dir(path).expect("the directory is made");
}

/// GNU tar, applying lists as it extracts.
const GNU_TAR: [&str; 2] = ["tar", "--acls"];

/// `bsdtar` in a UTF-8 locale, as a pax archive's names are UTF-8, whatever
/// the environment's.
fn bsdtar_command(bsdtar: &Path) -> [&OsStr; 3] {
    [
        OsStr::new("env"),
        OsStr::new("LC_ALL=C.UTF-8"),
        bsdtar.as_os_str(),
    ]
}

/// Writes an archive of `cases` in `spelling` to `dir`, has `command`
/// extract it there into a new directory, and checks each member's lists.
fn extract_and_check(
    oracle: &mut Oracle,
    dir: &Path,
    command: &[&OsStr],
    cases: &[Case],
    spelling: Spelling,
    context: &str,
) {
    let members: Vec<Member> = cases.iter().map(|case| case.member(spelling)).collect();
    let archive = dir.join("archive.tar");
    std::fs::write(&archive, pax::archive(&members)).expect("the archive is written");
    let into = dir.join("x");
    fresh(oracle, &into);
    let args = [OsStr::new("-xpf"), archive.as_os_str()];
    let (status, errors) = run(oracle, &into, command, &args);
    assert_eq!(status, 0, "{context}: {errors}");
    for case in cases {
        check_extracted(oracle, &into, case, context);
    }
}

/// Whether a name is one the text spells as it is.
fn plain(name: &[u8]) -> bool {
    !name
        .iter()
        .any(|&byte| byte < 0x20 || byte == 0x7f || b" ,:#\\".contains(&byte))
}

/// Whether `acl` names anyone the writing system names as a reader takes for
/// a number.
fn names_number_like(acl: &Acl) -> bool {
    acl.entries().iter().any(|entry| {
        entry
            .qualifier
            .id()
            .is_some_and(|id| NUMBER_LIKE.iter().any(|named| named.1 == id))
    })
}

/// Whether the database names anyone in `acl` with a name a text escapes.
fn escapes(acl: &Acl) -> bool {
    acl.entries().iter().any(|entry| match entry.qualifier {
        Qualifier::User(id) => user_name(id).is_some_and(|name| !plain(name)),
        Qualifier::Group(id) => group_name(id).is_some_and(|name| !plain(name)),
        _ => false,
    })
}

#[test]
fn gnu_tar_extracts_written_text_as_the_list() {
    if support::gnu_tar().is_none() {
        return;
    }
    let dir = scratch("tar-gnu-extracts");
    let Some(mut oracle) = namespace(&dir, Reference::GnuTar) else {
        return;
    };
    let mut rng = Rng::seeded(61);
    let seed = rng.seed();
    let (mut escaped, mut number_like) = (0, 0);
    for spelling in SPELLINGS {
        for round in 0..6 {
            let cases: Vec<Case> = (0..40)
                .map(|index| Case::generated(&mut rng, index, &|_| true))
                .collect();
            escaped += cases.iter().filter(|case| escapes(&case.access)).count();
            number_like += cases
                .iter()
                .filter(|case| names_number_like(&case.access))
                .count();
            let context = format!("seed {seed}, {spelling:?}, round {round}");
            let command = GNU_TAR.map(OsStr::new);
            extract_and_check(&mut oracle, &dir, &command, &cases, spelling, &context);
        }
    }
    assert!(
        escaped > 200,
        "too few lists named someone escaped: {escaped}"
    );
    assert!(
        number_like > 100,
        "too few lists named someone by a number's name: {number_like}"
    );
    tidy(&mut oracle, &dir);
}

/// Removes what the tests extracted and archived in `dir`.
fn tidy(oracle: &mut Oracle, dir: &Path) {
    let args = ["-rf", "x", "tree", "probe", "escaped"].map(OsStr::new);
    let (status, errors) = oracle.run(dir, OsStr::new("rm"), &args);
    assert_eq!(status, 0, "{errors}");
}

/// The bsdtar to compare with, where it applies lists: it extracts an
/// archive whose member names one user, in `dir`, and sets the list.
fn bsdtar_applying_lists(oracle: &mut Oracle, dir: &Path) -> Option<PathBuf> {
    let bsdtar = support::bsdtar()?;
    let case = Case {
        name: "probe".to_owned(),
        directory: false,
        access: Acl::new(vec![
            Entry::new(Qualifier::UserObj, Perm::READ | Perm::WRITE),
            Entry::new(Qualifier::User(502), Perm::READ),
            Entry::new(Qualifier::GroupObj, Perm::READ),
            Entry::new(Qualifier::Mask, Perm::READ),
            Entry::new(Qualifier::Other, Perm::NONE),
        ])
        .expect("a valid list"),
        default: None,
    };
    let archive = dir.join("probe.tar");
    std::fs::write(&archive, pax::archive(&[case.member(Spelling::STAR)])).expect("written");
    let into = dir.join("probe");
    fresh(oracle, &into);
    let args = [OsStr::new("-xpf"), archive.as_os_str()];
    let (status, errors) = run(oracle, &into, &bsdtar_command(&bsdtar), &args);
    if status != 0
        || held(oracle, &into.join("probe"), xattr::ACCESS).as_ref() != Some(&case.access)
    {
        Reference::Bsdtar.missing(&format!(
            "{} sets no access control list (built without them?): exit {status}, {errors}",
            bsdtar.display()
        ));
        return None;
    }
    Some(bsdtar)
}

#[test]
fn bsdtar_extracts_written_text_as_the_list() {
    let dir = scratch("tar-bsdtar-extracts");
    let Some(mut oracle) = namespace(&dir, Reference::Bsdtar) else {
        return;
    };
    let Some(bsdtar) = bsdtar_applying_lists(&mut oracle, &dir) else {
        return;
    };
    let mut rng = Rng::seeded(62);
    let seed = rng.seed();
    let (mut escaped, mut number_like) = (0, 0);
    for spelling in SPELLINGS {
        // libarchive looks a name up as the text spells it, escapes and all,
        // and falls back on the id recorded beside it: so it reads a name
        // that needs escaping only where the spelling records ids.
        let named = |name: &[u8]| spelling.names == Names::WithIds || plain(name);
        for round in 0..6 {
            let cases: Vec<Case> = (0..40)
                .map(|index| Case::generated(&mut rng, index, &named))
                .collect();
            escaped += cases.iter().filter(|case| escapes(&case.access)).count();
            number_like += cases
                .iter()
                .filter(|case| names_number_like(&case.access))
                .count();
            let context = format!("seed {seed}, {spelling:?}, round {round}");
            let command = bsdtar_command(&bsdtar);
            extract_and_check(&mut oracle, &dir, &command, &cases, spelling, &context);
        }
    }
    assert!(
        escaped > 100,
        "too few lists named someone escaped: {escaped}"
    );
    assert!(
        number_like > 100,
        "too few lists named someone by a number's name: {number_like}"
    );

    // A name escaped without its id is one libarchive cannot resolve: it
    // sets no list.
    let case = Case {
        name: "escaped".to_owned(),
        directory: false,
        access: Acl::new(vec![
            Entry::new(Qualifier::UserObj, Perm::READ | Perm::WRITE),
            Entry::new(Qualifier::GroupObj, Perm::READ),
            Entry::new(Qualifier::Group(4242), Perm::READ),
            Entry::new(Qualifier::Mask, Perm::READ),
            Entry::new(Qualifier::Other, Perm::NONE),
        ])
        .expect("a valid list"),
        default: None,
    };
    let archive = dir.join("escaped.tar");
    std::fs::write(&archive, pax::archive(&[case.member(Spelling::GNU_TAR)])).expect("written");
    let into = dir.join("escaped");
    fresh(&mut oracle, &into);
    let args = [OsStr::new("-xpf"), archive.as_os_str()];
    let (status, _) = run(&mut oracle, &into, &bsdtar_command(&bsdtar), &args);
    assert_ne!(status, 0);
    assert_eq!(
        held(&mut oracle, &into.join("escaped"), xattr::ACCESS),
        None
    );
    tidy(&mut oracle, &dir);
}

/// Makes `cases` in a new directory under `dir` with their lists and modes,
/// has `command` archive them, and gives each member's records.
fn archived(
    oracle: &mut Oracle,
    dir: &Path,
    command: &[&OsStr],
    cases: &[Case],
) -> BTreeMap<String, pax::Records> {
    let tree = dir.join("tree");
    fresh(oracle, &tree);
    for case in cases {
        let path = tree.join(&case.name);
        if case.directory {
            std::fs::create_dir(&path).expect("made");
        } else {
            std::fs::write(&path, b"").expect("made");
        }
        let path = hex(path.as_os_str().as_encoded_bytes());
        oracle
            .chmod(&path, case.access.mode_bits())
            .expect("the mode is set");
        if !case.access.is_minimal() {
            oracle
                .set(&path, xattr::ACCESS, &xattr::encode(&case.access))
                .expect("the access list is set");
        }
        if let Some(default) = &case.default {
            oracle
                .set(&path, xattr::DEFAULT, &xattr::encode(default))
                .expect("the default list is set");
        }
    }
    let archive = dir.join("written.tar");
    let mut args = vec![OsStr::new("-cf"), archive.as_os_str()];
    args.extend(cases.iter().map(|case| OsStr::new(&case.name)));
    let (status, errors) = run(oracle, &tree, command, &args);
    assert_eq!(status, 0, "{errors}");
    let bytes = std::fs::read(&archive).expect("the archive is read");
    pax::records(&bytes)
        .into_iter()
        .map(|(name, records)| (String::from_utf8(name).expect("ASCII"), records))
        .collect()
}

/// The list a record holds, read as text with `lookups`.
fn read_record(text: &[u8], lookups: bool) -> Option<Acl> {
    let parsed = text::parse(text).unwrap_or_else(|err| {
        panic!("{:?}: {err}", String::from_utf8_lossy(text));
    })?;
    let resolved = if lookups {
        parsed.resolve(user_id, group_id, Prefer::Name)
    } else {
        parsed.resolve(|_| None, |_| None, Prefer::Name)
    };
    Some(resolved.unwrap_or_else(|err| panic!("{:?}: {err}", String::from_utf8_lossy(text))))
}

fn record<'a>(records: &'a [(Vec<u8>, Vec<u8>)], keyword: &[u8]) -> Option<&'a [u8]> {
    records
        .iter()
        .find(|(key, _)| key == keyword)
        .map(|(_, value)| value.as_slice())
}

#[test]
fn gnu_tar_writes_text_the_crate_reads_as_the_list() {
    if support::gnu_tar().is_none() {
        return;
    }
    let dir = scratch("tar-gnu-writes");
    let Some(mut oracle) = namespace(&dir, Reference::GnuTar) else {
        return;
    };
    let mut rng = Rng::seeded(63);
    let seed = rng.seed();
    // GNU tar cuts a name at its `#` (`tests/text.rs` holds such a record),
    // and writes a name of digits as it is, which every reader of its text
    // takes as an id.
    let named = |name: &[u8]| !name.contains(&b'#') && !name.iter().all(u8::is_ascii_digit);
    let mut escaped = 0;
    for round in 0..8 {
        let cases: Vec<Case> = (0..40)
            .map(|index| Case::generated(&mut rng, index, &named))
            .collect();
        escaped += cases.iter().filter(|case| escapes(&case.access)).count();
        let command = ["tar", "--acls", "--xattrs", "--format=posix"].map(OsStr::new);
        let members = archived(&mut oracle, &dir, &command, &cases);
        for case in &cases {
            let context = format!("seed {seed}, round {round}, {}", case.name);
            let records = &members[&case.name];
            // The access list as text, where the file holds one or a default
            // list; and as the binary record beside it, where it is stored.
            match record(records, ACCESS_RECORD) {
                Some(text) => assert_eq!(
                    read_record(text, true).as_ref(),
                    Some(&case.access),
                    "{context}"
                ),
                None => assert!(
                    case.access.is_minimal() && case.default.is_none(),
                    "{context}"
                ),
            }
            let binary = record(records, b"SCHILY.xattr.system.posix_acl_access")
                .map(|value| xattr::decode(value).expect("a list"));
            let stored = (!case.access.is_minimal()).then(|| case.access.clone());
            assert_eq!(binary.flatten(), stored, "{context}");
            if case.directory {
                let default =
                    record(records, DEFAULT_RECORD).and_then(|text| read_record(text, true));
                assert_eq!(default, case.default, "{context}");
            }
        }
    }
    assert!(
        escaped > 100,
        "too few lists named someone escaped: {escaped}"
    );
    tidy(&mut oracle, &dir);
}

#[test]
fn bsdtar_writes_text_the_crate_reads_as_the_list() {
    let dir = scratch("tar-bsdtar-writes");
    let Some(mut oracle) = namespace(&dir, Reference::Bsdtar) else {
        return;
    };
    let Some(bsdtar) = bsdtar_applying_lists(&mut oracle, &dir) else {
        return;
    };
    let mut rng = Rng::seeded(64);
    let seed = rng.seed();
    // libarchive writes names as they are, so a comma in one ends its entry,
    // and a name of digits, which GNU tar reads as an id and libarchive as a
    // name, is refused beside another id (`tests/text.rs` holds both).
    let named = |name: &[u8]| !name.contains(&b',') && !name.iter().all(u8::is_ascii_digit);
    let mut escaped = 0;
    for round in 0..8 {
        let cases: Vec<Case> = (0..40)
            .map(|index| Case::generated(&mut rng, index, &named))
            .collect();
        escaped += cases.iter().filter(|case| escapes(&case.access)).count();
        let [env, locale, program] = bsdtar_command(&bsdtar);
        let command = [env, locale, program, OsStr::new("--format=pax")];
        let members = archived(&mut oracle, &dir, &command, &cases);
        for case in &cases {
            let context = format!("seed {seed}, round {round}, {}", case.name);
            let records = &members[&case.name];
            // Each name is followed by its id, so the text reads as the list
            // whether or not the reader's database names anyone.
            for lookups in [true, false] {
                match record(records, ACCESS_RECORD) {
                    Some(text) => {
                        assert_eq!(
                            read_record(text, lookups).as_ref(),
                            Some(&case.access),
                            "{context}"
                        );
                    }
                    None => assert!(case.access.is_minimal(), "{context}"),
                }
                if case.directory {
                    let default =
                        record(records, DEFAULT_RECORD).and_then(|text| read_record(text, lookups));
                    assert_eq!(default, case.default, "{context}");
                }
            }
        }
    }
    assert!(
        escaped > 100,
        "too few lists named someone escaped: {escaped}"
    );
    tidy(&mut oracle, &dir);
}
