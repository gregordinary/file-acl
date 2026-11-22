//! What the comparison tests share: the reference oracle, and how a test
//! skips where a reference it compares with is missing.
//!
//! The references are the kernel, libacl, GNU tar and bsdtar. The kernel and
//! libacl are asked through `tests/oracle.py`, which a test runs as a child
//! process (inside a user namespace where the test needs one, or user and
//! mount namespaces holding a tmpfs or an account database); GNU tar and
//! bsdtar are run as themselves, by the oracle where they must run in its
//! namespaces. A reference that is missing skips the test with a line on
//! standard error, unless the reference's environment variable is set, which
//! turns the skip into a failure. CI sets every one, so a green run there is
//! one in which every comparison ran.

#![allow(dead_code, reason = "each test binary uses a part of this module")]

pub(crate) mod pax;

use std::ffi::OsStr;
use std::fmt::Write as _;
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};

/// A reference implementation a comparison test needs.
#[derive(Clone, Copy, Debug)]
pub(crate) enum Reference {
    /// The kernel, holding lists on the filesystem the tests' scratch
    /// directories are on.
    Kernel,
    /// libacl, loaded by the oracle.
    Libacl,
    /// The kernel inside an unprivileged user namespace.
    UserNamespace,
    /// The kernel holding lists on a tmpfs, mounted in user and mount
    /// namespaces of the test's own that map the user's subordinate ids.
    Tmpfs,
    /// GNU tar.
    GnuTar,
    /// The kernel across a user namespace whose map holds the user's
    /// subordinate ids out of order.
    IdMap,
    /// bsdtar, built with access control list support: the program
    /// `FILE_ACL_BSDTAR` names, or `bsdtar`.
    Bsdtar,
}

impl Reference {
    /// The environment variable that turns this reference's absence into a
    /// failure.
    pub(crate) fn variable(self) -> &'static str {
        match self {
            Reference::Kernel => "FILE_ACL_REQUIRE_KERNEL",
            Reference::Libacl => "FILE_ACL_REQUIRE_LIBACL",
            Reference::UserNamespace => "FILE_ACL_REQUIRE_USERNS",
            Reference::Tmpfs => "FILE_ACL_REQUIRE_TMPFS",
            Reference::GnuTar => "FILE_ACL_REQUIRE_GNU_TAR",
            Reference::IdMap => "FILE_ACL_REQUIRE_ID_MAP",
            Reference::Bsdtar => "FILE_ACL_REQUIRE_BSDTAR",
        }
    }

    /// Reports that this reference is missing: a failure where its variable
    /// is set, and otherwise a skip, said on standard error.
    pub(crate) fn missing(self, reason: &str) {
        let variable = self.variable();
        let required = std::env::var_os(variable).is_some_and(|v| !v.is_empty() && v != "0");
        assert!(
            !required,
            "{self:?} is required ({variable} is set), but {reason}"
        );
        // Written to standard error itself: the test harness captures what
        // `eprintln!` writes, and shows it only for a test that fails, so a
        // skip would pass in silence.
        let _ = writeln!(
            std::io::stderr(),
            "skipped: {self:?}: {reason}; set {variable} to make this a failure"
        );
    }
}

/// The oracle's answer to a request.
#[derive(Clone, PartialEq, Eq, Debug)]
pub(crate) enum Answer {
    /// The question was answered, with these fields.
    Ok(Vec<String>),
    /// The reference refused, the word naming how: an errno name, or a word
    /// the operation defines.
    Err(String),
}

/// A running oracle.
pub(crate) struct Oracle {
    child: Child,
    input: ChildStdin,
    output: BufReader<ChildStdout>,
}

impl Oracle {
    /// Starts the oracle in this process's namespaces, or reports `reference`
    /// missing where it cannot be started.
    pub(crate) fn start(reference: Reference) -> Option<Oracle> {
        let mut command = Command::new("python3");
        command.arg("-I").arg(oracle_path());
        Oracle::spawn(command, reference)
    }

    /// Starts the oracle in a new user namespace that maps only the caller,
    /// to root, or reports user namespaces missing where it cannot be.
    pub(crate) fn start_in_user_namespace() -> Option<Oracle> {
        let mut command = Command::new("unshare");
        command
            .args(["--user", "--map-root-user", "python3", "-I"])
            .arg(oracle_path());
        Oracle::spawn(command, Reference::UserNamespace)
    }

    /// Starts the oracle in new user and mount namespaces, the user namespace
    /// mapping the caller to root and the subordinate ids `/etc/subuid` and
    /// `/etc/subgid` give the caller from 1 up, or reports `reference`
    /// missing where it cannot be.
    fn start_with_subordinate_ids(reference: Reference) -> Option<Oracle> {
        let mut command = Command::new("unshare");
        command
            .args([
                "--user",
                "--map-root-user",
                "--map-auto",
                "--mount",
                "python3",
                "-I",
            ])
            .arg(oracle_path());
        Oracle::spawn(command, reference)
    }

    fn spawn(mut command: Command, reference: Reference) -> Option<Oracle> {
        let mut child = match command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
        {
            Ok(child) => child,
            Err(err) => {
                reference.missing(&format!("{command:?} could not be started: {err}"));
                return None;
            }
        };
        let input = child.stdin.take().expect("the oracle's input is piped");
        let output = BufReader::new(child.stdout.take().expect("the oracle's output is piped"));
        let mut oracle = Oracle {
            child,
            input,
            output,
        };
        match oracle.try_ask("ping", &[]) {
            Some(_) => Some(oracle),
            None => {
                reference.missing(&format!("{command:?} did not answer"));
                None
            }
        }
    }

    /// Asks `op` with `fields`, each already in the protocol's form ([`hex`]
    /// for bytes). Panics on an answer the oracle could not give.
    pub(crate) fn ask(&mut self, op: &str, fields: &[&str]) -> Answer {
        self.try_ask(op, fields)
            .unwrap_or_else(|| panic!("the oracle stopped answering, asked {op} {fields:?}"))
    }

    /// Makes a new, empty file or directory in `dir`: its path, in the
    /// protocol's form.
    pub(crate) fn make(&mut self, dir: &Path, kind: Kind) -> String {
        self.try_make(dir, kind)
            .unwrap_or_else(|errno| panic!("making a {kind:?} failed: {errno}"))
    }

    /// Makes a new, empty file or directory in `dir`, as [`make`](Self::make)
    /// does, or the errno the kernel refused it with.
    pub(crate) fn try_make(&mut self, dir: &Path, kind: Kind) -> Result<String, String> {
        let name = match kind {
            Kind::File => "file",
            Kind::Directory => "dir",
            Kind::Fifo => "fifo",
            Kind::Socket => "socket",
            Kind::CharDevice => "chardev",
            Kind::Symlink => "symlink",
        };
        match self.ask("make", &[&hex(dir.as_os_str().as_encoded_bytes()), name]) {
            Answer::Ok(fields) if fields.len() == 1 => Ok(fields[0].clone()),
            Answer::Err(errno) => Err(errno),
            other => panic!("make answered {other:?}"),
        }
    }

    /// Sets the extended attribute `name` of `path` (from
    /// [`make`](Self::make)) to `value`, or the errno the kernel refused it
    /// with.
    pub(crate) fn set(&mut self, path: &str, name: &str, value: &[u8]) -> Result<(), String> {
        match self.ask("set", &[path, &hex(name.as_bytes()), &hex(value)]) {
            Answer::Ok(fields) if fields.is_empty() => Ok(()),
            Answer::Ok(fields) => panic!("set answered {fields:?}"),
            Answer::Err(errno) => Err(errno),
        }
    }

    /// The value of the extended attribute `name` of `path`, or the errno
    /// the kernel answered with (`ENODATA` where there is none).
    pub(crate) fn get(&mut self, path: &str, name: &str) -> Result<Vec<u8>, String> {
        match self.ask("get", &[path, &hex(name.as_bytes())]) {
            Answer::Ok(fields) if fields.len() == 1 => Ok(unhex(&fields[0])),
            Answer::Ok(fields) => panic!("get answered {fields:?}"),
            Answer::Err(errno) => Err(errno),
        }
    }

    /// The permission, set-user-ID, set-group-ID and sticky bits of `path`'s
    /// mode, not following a symbolic link.
    pub(crate) fn mode(&mut self, path: &str) -> u32 {
        match self.ask("mode", &[path]) {
            Answer::Ok(fields) if fields.len() == 1 => u32::from_str_radix(&fields[0], 8)
                .unwrap_or_else(|_| panic!("mode answered {fields:?}")),
            other => panic!("mode answered {other:?}"),
        }
    }

    /// Sets `path`'s mode, or the errno the kernel refused it with.
    pub(crate) fn chmod(&mut self, path: &str, mode: u32) -> Result<(), String> {
        match self.ask("chmod", &[path, &format!("{mode:o}")]) {
            Answer::Ok(fields) if fields.is_empty() => Ok(()),
            Answer::Ok(fields) => panic!("chmod answered {fields:?}"),
            Answer::Err(errno) => Err(errno),
        }
    }

    /// Sets `path`'s owner and group, or the errno the kernel refused it
    /// with.
    pub(crate) fn chown(&mut self, path: &str, uid: u32, gid: u32) -> Result<(), String> {
        match self.ask("chown", &[path, &uid.to_string(), &gid.to_string()]) {
            Answer::Ok(fields) if fields.is_empty() => Ok(()),
            Answer::Ok(fields) => panic!("chown answered {fields:?}"),
            Answer::Err(errno) => Err(errno),
        }
    }

    /// What `access(2)` grants a process with user `uid`, group `gid` and
    /// the supplementary `groups` on `path`, as `rwx` with a `-` for each
    /// permission refused. The oracle must be able to take those ids: run as
    /// root in a user namespace mapping them.
    pub(crate) fn access(&mut self, path: &str, uid: u32, gid: u32, groups: &[u32]) -> String {
        let groups = if groups.is_empty() {
            "-".to_owned()
        } else {
            groups
                .iter()
                .map(u32::to_string)
                .collect::<Vec<_>>()
                .join(",")
        };
        match self.ask(
            "access",
            &[path, &uid.to_string(), &gid.to_string(), &groups],
        ) {
            Answer::Ok(fields) if fields.len() == 1 => fields[0].clone(),
            other => panic!("access answered {other:?}"),
        }
    }

    /// Runs `program` with `args` in `dir`, inside the oracle's namespaces:
    /// its exit status and its standard error. Panics where it cannot be
    /// started.
    pub(crate) fn run(&mut self, dir: &Path, program: &OsStr, args: &[&OsStr]) -> (i32, String) {
        let mut argv = program.as_encoded_bytes().to_vec();
        for arg in args {
            argv.push(0);
            argv.extend_from_slice(arg.as_encoded_bytes());
        }
        match self.ask(
            "run",
            &[&hex(dir.as_os_str().as_encoded_bytes()), &hex(&argv)],
        ) {
            Answer::Ok(fields) if fields.len() == 2 => (
                fields[0]
                    .parse()
                    .unwrap_or_else(|_| panic!("run answered {fields:?}")),
                String::from_utf8_lossy(&unhex(&fields[1])).into_owned(),
            ),
            other => panic!("{program:?} could not be run: {other:?}"),
        }
    }

    /// As [`ask`](Self::ask), or `None` where the oracle has exited.
    fn try_ask(&mut self, op: &str, fields: &[&str]) -> Option<Answer> {
        let mut line = String::from(op);
        for field in fields {
            line.push('\t');
            line.push_str(field);
        }
        line.push('\n');
        self.input.write_all(line.as_bytes()).ok()?;
        self.input.flush().ok()?;
        let mut reply = String::new();
        if self.output.read_line(&mut reply).ok()? == 0 {
            return None;
        }
        let mut words = reply.trim_end_matches('\n').split('\t');
        let answer = match words.next() {
            Some("ok") => Answer::Ok(words.map(String::from).collect()),
            Some("err") => Answer::Err(words.next().unwrap_or_default().to_owned()),
            _ => panic!("the oracle could not answer {op} {fields:?}: {reply}"),
        };
        Some(answer)
    }
}

impl Drop for Oracle {
    fn drop(&mut self) {
        // The oracle holds nothing that needs an orderly exit.
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn oracle_path() -> &'static str {
    concat!(env!("CARGO_MANIFEST_DIR"), "/tests/oracle.py")
}

/// `bytes` as the protocol carries them: lower-case hexadecimal.
pub(crate) fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(out, "{byte:02x}");
    }
    out
}

/// The bytes `text` spells as pairs of hexadecimal digits, whitespace between
/// pairs ignored, so a value can be written grouped as `getfattr -e hex`
/// prints it, field by field.
pub(crate) fn unhex(text: &str) -> Vec<u8> {
    let digits: Vec<u8> = text.bytes().filter(|b| !b.is_ascii_whitespace()).collect();
    assert!(
        digits.len().is_multiple_of(2),
        "{text:?} is not whole bytes"
    );
    digits
        .chunks(2)
        .map(|pair| {
            let pair = std::str::from_utf8(pair).expect("hexadecimal is ASCII");
            u8::from_str_radix(pair, 16).unwrap_or_else(|_| panic!("{text:?} is not hexadecimal"))
        })
        .collect()
}

/// What [`Oracle::make`] makes.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum Kind {
    /// A regular file.
    File,
    /// A directory.
    Directory,
    /// A FIFO.
    Fifo,
    /// A socket, bound and closed.
    Socket,
    /// A character device numbered 0:0, the one device a user without
    /// privilege may make (Linux 5.8 and later).
    CharDevice,
    /// A symbolic link, to a name that does not exist.
    Symlink,
}

/// A small, seeded source of pseudo-random numbers (SplitMix64), for tests
/// that compare over generated cases. A failure names its seed, and
/// `FILE_ACL_SEED` runs a test again from it.
#[derive(Debug)]
pub(crate) struct Rng {
    state: u64,
    seed: u64,
}

impl Rng {
    /// A generator seeded from `FILE_ACL_SEED` where it is set, and from
    /// `default` otherwise, so a run is the same each time unless asked.
    pub(crate) fn seeded(default: u64) -> Rng {
        let seed = std::env::var("FILE_ACL_SEED")
            .ok()
            .map(|text| text.parse().expect("FILE_ACL_SEED is a decimal number"))
            .unwrap_or(default);
        Rng { state: seed, seed }
    }

    /// The seed this generator started from.
    pub(crate) fn seed(&self) -> u64 {
        self.seed
    }

    pub(crate) fn next_u64(&mut self) -> u64 {
        self.state = self.state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    /// A number below `bound`, which is not zero.
    pub(crate) fn below(&mut self, bound: u64) -> u64 {
        self.next_u64() % bound
    }

    /// One of `items`, which is not empty.
    pub(crate) fn pick<'a, T>(&mut self, items: &'a [T]) -> &'a T {
        &items[self.below(items.len() as u64) as usize]
    }

    /// `items` in an order of the generator's choosing.
    pub(crate) fn shuffle<T>(&mut self, items: &mut [T]) {
        for i in (1..items.len()).rev() {
            items.swap(i, self.below(i as u64 + 1) as usize);
        }
    }
}

/// An empty scratch directory for the test `name`, under Cargo's directory
/// for integration tests' temporary files. What an earlier run left there is
/// removed first, directories it left unreadable included.
pub(crate) fn scratch(name: &str) -> PathBuf {
    let path = Path::new(env!("CARGO_TARGET_TMPDIR")).join(name);
    if let Err(err) = remove_tree(&path) {
        panic!(
            "{} cannot be removed ({err}). A tar comparison that failed leaves files \
             owned by subordinate ids, which \
             `unshare --user --map-root-user --map-auto rm -rf {}` removes",
            path.display(),
            path.display()
        );
    }
    std::fs::create_dir_all(&path).expect("the scratch directory is created");
    path
}

/// Removes `path` and everything under it, where it exists, giving its owner
/// read, write and search on each directory first: the kernel comparisons
/// leave directories of any mode. Symbolic links are not followed.
fn remove_tree(path: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt as _;

    let mut directories = vec![path.to_path_buf()];
    while let Some(directory) = directories.pop() {
        let metadata = match std::fs::symlink_metadata(&directory) {
            Ok(metadata) => metadata,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => continue,
            Err(err) => return Err(err),
        };
        if !metadata.is_dir() {
            continue;
        }
        let mode = metadata.permissions().mode();
        if mode & 0o700 != 0o700 {
            std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(mode | 0o700))?;
        }
        for entry in std::fs::read_dir(&directory)? {
            let entry = entry?;
            if entry.file_type()?.is_dir() {
                directories.push(entry.path());
            }
        }
    }
    match std::fs::remove_dir_all(path) {
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
        done => done,
    }
}

/// Removes a scratch directory when dropped, as [`scratch`] removes one
/// before a test, so a comparison that leaves directories their owner cannot
/// read leaves nothing behind, where it passes and where it fails; `cargo
/// clean` cannot remove such a directory.
pub(crate) struct Discard<'a>(pub(crate) &'a Path);

impl Drop for Discard<'_> {
    fn drop(&mut self) {
        // What cannot be removed here, the next run's `scratch` reports.
        let _ = remove_tree(self.0);
    }
}

/// An oracle whose kernel holds lists in `dir`, or the kernel reported
/// missing.
pub(crate) fn kernel(dir: &Path) -> Option<Oracle> {
    let oracle = Oracle::start(Reference::Kernel)?;
    holding_lists(oracle, dir, Reference::Kernel)
}

/// An oracle inside a user namespace mapping only the caller, whose kernel
/// holds lists in `dir`, or user namespaces reported missing.
pub(crate) fn kernel_in_user_namespace(dir: &Path) -> Option<Oracle> {
    let oracle = Oracle::start_in_user_namespace()?;
    holding_lists(oracle, dir, Reference::UserNamespace)
}

/// An oracle whose kernel holds lists on a new tmpfs mounted on `dir`, in
/// user and mount namespaces of its own, or tmpfs reported missing.
///
/// Its user namespace maps the caller to root and the caller's subordinate
/// ids from 1 up, so a list there may name 0 and as many ids after it as the
/// subordinate range holds (65,536 by default). The tmpfs is visible to the
/// oracle alone, and goes when it exits; outside, `dir` stays as it was.
pub(crate) fn kernel_on_tmpfs(dir: &Path) -> Option<Oracle> {
    let mut oracle = Oracle::start_with_subordinate_ids(Reference::Tmpfs)?;
    match oracle.ask("tmpfs", &[&hex(dir.as_os_str().as_encoded_bytes())]) {
        Answer::Ok(_) => holding_lists(oracle, dir, Reference::Tmpfs),
        Answer::Err(said) => {
            Reference::Tmpfs.missing(&format!("a tmpfs cannot be mounted: {said}"));
            None
        }
    }
}

fn holding_lists(mut oracle: Oracle, dir: &Path, reference: Reference) -> Option<Oracle> {
    match oracle.ask("acls", &[&hex(dir.as_os_str().as_encoded_bytes())]) {
        Answer::Ok(_) => Some(oracle),
        Answer::Err(errno) => {
            reference.missing(&format!(
                "{} holds no POSIX access control lists ({errno})",
                dir.display()
            ));
            None
        }
    }
}

/// A user namespace's map: for each id inside, the id outside, for users and
/// for groups.
#[derive(Clone, Debug)]
pub(crate) struct IdMap {
    pub(crate) users: Vec<(u32, u32)>,
    pub(crate) groups: Vec<(u32, u32)>,
}

impl IdMap {
    /// The id outside that `inside` is, among `pairs`.
    fn outward(pairs: &[(u32, u32)], inside: u32) -> Option<u32> {
        pairs
            .iter()
            .find(|pair| pair.0 == inside)
            .map(|pair| pair.1)
    }

    /// The id inside that `outside` is, among `pairs`.
    fn inward(pairs: &[(u32, u32)], outside: u32) -> Option<u32> {
        pairs
            .iter()
            .find(|pair| pair.1 == outside)
            .map(|pair| pair.0)
    }

    pub(crate) fn user_outside(&self, inside: u32) -> Option<u32> {
        IdMap::outward(&self.users, inside)
    }

    pub(crate) fn group_outside(&self, inside: u32) -> Option<u32> {
        IdMap::outward(&self.groups, inside)
    }

    pub(crate) fn user_inside(&self, outside: u32) -> Option<u32> {
        IdMap::inward(&self.users, outside)
    }

    pub(crate) fn group_inside(&self, outside: u32) -> Option<u32> {
        IdMap::inward(&self.groups, outside)
    }
}

/// The output of `command` with `args`, trimmed, where it runs and succeeds.
fn output_of(command: &str, args: &[&str]) -> Option<String> {
    let done = Command::new(command).args(args).output().ok()?;
    done.status
        .success()
        .then(|| String::from_utf8_lossy(&done.stdout).trim().to_owned())
}

/// The first subordinate id and their number `file` (`/etc/subuid` or
/// `/etc/subgid`) gives the user named `name`, with id `id`.
fn subordinate(file: &str, name: &str, id: u32) -> Option<(u32, u32)> {
    let text = std::fs::read_to_string(file).ok()?;
    text.lines().find_map(|line| {
        let mut fields = line.split(':');
        let owner = fields.next()?;
        if owner != name && owner != id.to_string() {
            return None;
        }
        Some((fields.next()?.parse().ok()?, fields.next()?.parse().ok()?))
    })
}

/// How many subordinate ids [`kernel_across_an_id_map`] maps from.
const SUBORDINATE_IDS_USED: u32 = 53;

/// An oracle in a user namespace, whose kernel holds lists in `dir` (on a
/// filesystem of the initial namespace), and the namespace's map; or the id
/// map reported missing.
///
/// The map takes the caller to 0, its first nine subordinate ids to 1 to 9
/// in order, and its subordinate ids 52, 51 and 50 to 20, 21 and 22, so it
/// does not keep the order of ids. Groups are mapped alike.
pub(crate) fn kernel_across_an_id_map(dir: &Path) -> Option<(Oracle, IdMap)> {
    let ids = (|| {
        let name = output_of("id", &["-un"])?;
        let uid: u32 = output_of("id", &["-u"])?.parse().ok()?;
        let gid: u32 = output_of("id", &["-g"])?.parse().ok()?;
        Some((name, uid, gid))
    })();
    let Some((name, uid, gid)) = ids else {
        Reference::IdMap.missing("`id` does not say who the user is");
        return None;
    };
    let pairs = |caller: u32, file: &str| {
        let (first, count) = subordinate(file, &name, caller)?;
        if count < SUBORDINATE_IDS_USED {
            return None;
        }
        let mut pairs = vec![(0, caller)];
        pairs.extend((0..9).map(|n| (n + 1, first + n)));
        pairs.extend([(20, first + 52), (21, first + 51), (22, first + 50)]);
        Some(pairs)
    };
    let (Some(users), Some(groups)) = (pairs(uid, "/etc/subuid"), pairs(gid, "/etc/subgid")) else {
        Reference::IdMap.missing(&format!(
            "/etc/subuid and /etc/subgid do not give {name} {SUBORDINATE_IDS_USED} subordinate ids"
        ));
        return None;
    };
    let map = IdMap { users, groups };
    let mut command = Command::new("unshare");
    command.arg("--user");
    for (option, pairs) in [("--map-users", &map.users), ("--map-groups", &map.groups)] {
        for (inside, outside) in pairs {
            command.arg(format!("{option}={inside}:{outside}:1"));
        }
    }
    command.args(["python3", "-I"]).arg(oracle_path());
    let oracle = Oracle::spawn(command, Reference::IdMap)?;
    let oracle = holding_lists(oracle, dir, Reference::IdMap)?;
    Some((oracle, map))
}

/// An oracle that has loaded libacl, or libacl reported missing.
pub(crate) fn libacl() -> Option<Oracle> {
    let mut oracle = Oracle::start(Reference::Libacl)?;
    match oracle.ask("libacl", &[]) {
        Answer::Ok(_) => Some(oracle),
        Answer::Err(reason) => {
            Reference::Libacl.missing(&format!("libacl cannot be loaded: {reason}"));
            None
        }
    }
}

/// The first line of `tar --version` where it is GNU tar, or GNU tar
/// reported missing.
pub(crate) fn gnu_tar() -> Option<String> {
    let found = Command::new("tar").arg("--version").output();
    let version = match &found {
        Ok(output) if output.status.success() => String::from_utf8_lossy(&output.stdout)
            .lines()
            .next()
            .unwrap_or_default()
            .to_owned(),
        Ok(output) => {
            Reference::GnuTar.missing(&format!("`tar --version` failed: {}", output.status));
            return None;
        }
        Err(err) => {
            Reference::GnuTar.missing(&format!("`tar` could not be run: {err}"));
            return None;
        }
    };
    if version.contains("GNU tar") {
        Some(version)
    } else {
        Reference::GnuTar.missing(&format!("`tar` is not GNU tar: {version}"));
        None
    }
}

/// An oracle in user and mount namespaces of its own, mapping the caller's
/// subordinate ids as [`kernel_on_tmpfs`]'s does, whose kernel holds lists
/// in `dir` and whose account database is `passwd` and `group`, mounted
/// over the system's; or `reference`, the tar a test compares with, reported
/// missing.
///
/// A tar the oracle [runs](Oracle::run) resolves names through that
/// database, and sets lists naming any id up to the number of subordinate
/// ids.
pub(crate) fn tar_with_accounts(
    dir: &Path,
    passwd: &[u8],
    group: &[u8],
    reference: Reference,
) -> Option<Oracle> {
    let mut oracle = Oracle::start_with_subordinate_ids(reference)?;
    let accounts = dir.join("accounts");
    std::fs::create_dir_all(&accounts).expect("the account directory is created");
    let accounts = hex(accounts.as_os_str().as_encoded_bytes());
    if let Answer::Err(said) = oracle.ask("accounts", &[&accounts, &hex(passwd), &hex(group)]) {
        reference.missing(&format!("an account database cannot be mounted: {said}"));
        return None;
    }
    holding_lists(oracle, dir, reference)
}

/// The bsdtar to compare with: the program `FILE_ACL_BSDTAR` names, or
/// `bsdtar`, where it runs and says it is bsdtar; or bsdtar reported
/// missing. Whether it applies access control lists, which a build may
/// leave out, the test that runs it finds.
pub(crate) fn bsdtar() -> Option<PathBuf> {
    let program = std::env::var_os("FILE_ACL_BSDTAR")
        .filter(|path| !path.is_empty())
        .map_or_else(|| PathBuf::from("bsdtar"), PathBuf::from);
    let program = if program.components().count() > 1 {
        std::path::absolute(&program).unwrap_or(program)
    } else {
        program
    };
    match Command::new(&program).arg("--version").output() {
        Ok(output) if String::from_utf8_lossy(&output.stdout).starts_with("bsdtar") => {
            Some(program)
        }
        Ok(output) => {
            Reference::Bsdtar.missing(&format!(
                "`{} --version` does not say bsdtar: {}",
                program.display(),
                String::from_utf8_lossy(&output.stdout).trim()
            ));
            None
        }
        Err(err) => {
            Reference::Bsdtar.missing(&format!("`{}` could not be run: {err}", program.display()));
            None
        }
    }
}

/// What libacl's text reader makes of a text: whether `acl_from_text` reads
/// it, and whether `acl_check` passes the list it reads.
#[derive(Clone, PartialEq, Eq, Debug)]
pub(crate) enum Reading {
    /// `acl_from_text` refuses the text.
    Unread,
    /// The list read, which `acl_check` passes: its version-2 attribute
    /// value.
    Valid(Vec<u8>),
    /// A list read, which `acl_check` refuses with this code (in
    /// hexadecimal, as `0x2000`).
    Invalid(String),
}

impl Oracle {
    /// What libacl makes of `text`, its names resolved through the account
    /// database the oracle sees.
    pub(crate) fn read(&mut self, text: &[u8]) -> Reading {
        match self.ask("read", &[&hex(text)]) {
            Answer::Ok(fields) if fields.len() == 2 && fields[0] == "valid" => {
                Reading::Valid(unhex(&fields[1]))
            }
            Answer::Ok(fields) if fields.len() == 3 && fields[0] == "invalid" => {
                Reading::Invalid(fields[1].clone())
            }
            Answer::Err(word) if word == "unread" => Reading::Unread,
            other => panic!("read answered {other:?}"),
        }
    }
}

/// An oracle that has loaded libacl, in user and mount namespaces of its own
/// where `passwd` and `group` (written to `dir`) are the whole account
/// database, or libacl or user namespaces reported missing.
///
/// The namespace maps only the caller, to root; the names resolve to the ids
/// the files give, whether or not the namespace maps them, since libacl's
/// text reader does not ask the kernel.
pub(crate) fn libacl_with_accounts(dir: &Path, passwd: &[u8], group: &[u8]) -> Option<Oracle> {
    let mut command = Command::new("unshare");
    command
        .args(["--user", "--map-root-user", "--mount", "python3", "-I"])
        .arg(oracle_path());
    let mut oracle = Oracle::spawn(command, Reference::UserNamespace)?;
    if let Answer::Err(reason) = oracle.ask("libacl", &[]) {
        Reference::Libacl.missing(&format!("libacl cannot be loaded: {reason}"));
        return None;
    }
    let dir = hex(dir.as_os_str().as_encoded_bytes());
    match oracle.ask("accounts", &[&dir, &hex(passwd), &hex(group)]) {
        Answer::Ok(_) => Some(oracle),
        Answer::Err(said) => {
            Reference::UserNamespace.missing(&format!(
                "an account database cannot be mounted in a user namespace: {said}"
            ));
            None
        }
    }
}
