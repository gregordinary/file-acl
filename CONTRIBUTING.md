# Contributing

file-acl is maintained in spare time. This document sets out how changes are
handled, and what you need to build and test the code.

## Reporting a security issue

Report a security issue privately, through the channel
[SECURITY.md](SECURITY.md) describes. Security issues include a list read as
granting what its input does not, and a panic or runaway work on hostile
input. Please do not open a public issue for one.

## Proposing a change

Open an issue before writing code, so the design can be agreed before anyone
spends time on it. The lists file-acl accepts, and the bytes and text it
writes, are as much a part of its contract as its public API. A change to
either is recorded in the changelog with what it changes, even one that
fixes a difference from a reference implementation.

## Matching the references

file-acl's rules are those of five reference implementations, as observed:

- The Linux kernel, for the binary form and what a list does to a file's mode.
- libacl, for the text form and what a valid list is.
- GNU tar, libarchive's bsdtar and star, for the records an archive holds and
  how each reads them.

Each rule is specified by measurement, and a question about what a reference
does is answered by running it.

The kernel and GNU tar are GPL-licensed, libacl is LGPL-licensed, libarchive
is BSD-licensed, star is CDDL-licensed, and file-acl is MIT or Apache-2.0. No
part of any of them is translated into file-acl. Their source is not read
while file-acl's code is written. Please follow the same rule in any
contribution.

A difference between file-acl and a reference on any input is a defect,
unless the documentation states it.

### The comparison tests

The integration tests compare file-acl with the references directly.
Neither the library nor its tests need `unsafe` code or a dependency to do
it. Each reference is asked as follows:

- The kernel and libacl are asked through `tests/oracle.py`, a small Python
  program the tests run as a child process. It calls the extended-attribute
  system calls, and loads libacl with `ctypes`.
- The kernel is asked on two filesystems. One holds Cargo's temporary
  directory for tests, and the other is a tmpfs the oracle mounts in user and
  mount namespaces of its own. It is also asked across a user namespace whose
  map does not keep the order of ids, for the translation of a list's ids.
- libacl reads the text form's names through an account database the oracle
  mounts over `/etc/passwd` and `/etc/group`, in namespaces of its own. The
  tests' names therefore mean the same to libacl as to the crate.
- The oracle runs GNU tar and bsdtar themselves, in user and mount
  namespaces mapping the user's subordinate ids, with the tests' account
  database. They extract archives the tests write, and archive files the
  tests give lists.
- star, which few systems have, is compared through the records it was
  measured writing and its measured readings of the crate's text, which
  `tests/text.rs` holds.

A test whose reference is missing skips, saying why on standard error. Each
reference has a variable that turns its skip into a failure:

| Variable | Fails where |
| --- | --- |
| `FILE_ACL_REQUIRE_KERNEL` | `python3` cannot be run, or the filesystem of Cargo's temporary directory for tests holds no POSIX access control lists, or a character device numbered 0:0 cannot be made there (Linux before 5.8) |
| `FILE_ACL_REQUIRE_LIBACL` | `python3` cannot load libacl |
| `FILE_ACL_REQUIRE_USERNS` | `unshare --user --map-root-user` cannot enter a user namespace |
| `FILE_ACL_REQUIRE_TMPFS` | `unshare --user --map-root-user --map-auto --mount` cannot enter namespaces mapping the user's subordinate ids, or a tmpfs mounted there holds no POSIX access control lists, or a character device numbered 0:0 cannot be made on it |
| `FILE_ACL_REQUIRE_GNU_TAR` | `tar` is not GNU tar, or cannot be run in namespaces mapping the user's subordinate ids |
| `FILE_ACL_REQUIRE_ID_MAP` | `/etc/subuid` and `/etc/subgid` do not give the user 53 subordinate ids, or `unshare --user` with `--map-users` and `--map-groups` cannot enter a user namespace mapping them |
| `FILE_ACL_REQUIRE_BSDTAR` | the program `FILE_ACL_BSDTAR` names, or `bsdtar` where it is unset, is not bsdtar, sets no access control list as it extracts, or cannot be run in namespaces mapping the user's subordinate ids |

CI sets every one, so a green run there is one in which every comparison
ran. To run them all locally:

```sh
FILE_ACL_REQUIRE_KERNEL=1 FILE_ACL_REQUIRE_LIBACL=1 FILE_ACL_REQUIRE_USERNS=1 \
    FILE_ACL_REQUIRE_TMPFS=1 FILE_ACL_REQUIRE_GNU_TAR=1 FILE_ACL_REQUIRE_ID_MAP=1 \
    FILE_ACL_REQUIRE_BSDTAR=1 cargo test
```

bsdtar applies lists only where libarchive was built with support for
them. Ubuntu's `libarchive-tools` package has it, and a static build can
lack it. Set `FILE_ACL_BSDTAR` to the path of one that has it, where
`bsdtar` does not. CI compares with Ubuntu's bsdtar. A weekly workflow,
`drift.yml`, runs the same comparisons with libarchive's newest release,
built from its release tarball.

The libacl comparisons hold the readings of libacl 2.3 and 2.4, and use
whichever the system has. CI compares with Ubuntu's libacl. `drift.yml` also
runs the libacl comparisons with libacl's newest release, built from its
signed release tarball. It loads that release in place of the system's
through `LD_LIBRARY_PATH`. To compare with a libacl of your own build:

```sh
cargo test --test mode --test model --test text --test references --no-run
LD_LIBRARY_PATH=<its lib directory> FILE_ACL_REQUIRE_LIBACL=1 \
    cargo test --test mode --test model --test text --test references libacl
```

Ubuntu 23.10 and later restrict unprivileged user namespaces.
`sysctl -w kernel.apparmor_restrict_unprivileged_userns=0` lifts the
restriction. The tmpfs, id mapping and tar comparisons map the user's
subordinate ids, so a list there can name more than one id. They need
`newuidmap` and `newgidmap` (the `uidmap` package on Debian and Ubuntu), and
entries for the user in `/etc/subuid` and `/etc/subgid`. `useradd` makes
those by default, and `usermod --add-subuids` and `--add-subgids` make them
for an existing user.

## Building and testing

The toolchain is pinned in `rust-toolchain.toml`, so `rustup` provisions the
right version, components, and targets automatically.

```sh
cargo build
cargo test
```

The library has no dependencies. The fuzzing harness in `fuzz/` has its own
(see "Fuzzing").

## Before opening a pull request

CI runs all of these, and running them locally first is faster than a round
trip.

```sh
cargo fmt --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo fmt --check --manifest-path fuzz/Cargo.toml
cargo clippy --manifest-path fuzz/Cargo.toml --all-targets -- -D warnings
cargo test --workspace --all-features
cargo doc --workspace --all-features --no-deps    # RUSTDOCFLAGS='-D warnings'
cargo build --lib --target thumbv7em-none-eabihf
cargo +1.88 check --workspace --all-targets --all-features    # RUSTFLAGS='-D warnings'
cargo deny check licenses advisories sources
cargo deny --manifest-path fuzz/Cargo.toml check licenses advisories sources
```

The third and fourth format and lint the fuzzing harness, a workspace of its
own. The seventh builds the library for a target with no standard library.
The eighth checks the minimum supported Rust version, which sits below the
pinned toolchain, and needs that toolchain installed. The last two check the
licenses, advisories and sources of two dependency graphs: the library's,
and the fuzzing harness's, which holds the only third-party crates. They
need [cargo-deny](https://github.com/EmbarkStudios/cargo-deny).

CI also runs the tests on s390x, a big-endian target, under qemu-user. The
binary form is little-endian on every host. Only a big-endian build shows a
value read or written in the host's byte order. On Debian or Ubuntu, with
`gcc-s390x-linux-gnu`, `libc6-dev-s390x-cross` and `qemu-user` installed:

```sh
rustup target add s390x-unknown-linux-gnu
CARGO_TARGET_S390X_UNKNOWN_LINUX_GNU_LINKER=s390x-linux-gnu-gcc \
    CARGO_TARGET_S390X_UNKNOWN_LINUX_GNU_RUNNER='qemu-s390x -L /usr/s390x-linux-gnu' \
    cargo test --target s390x-unknown-linux-gnu
```

The public API is recorded in `public-api.txt`, and CI fails on any change to
it that the file does not show. A change that adds to or alters the API
regenerates it with
[cargo-public-api](https://github.com/cargo-public-api/cargo-public-api),
under the nightly the CI job pins:

```sh
RUSTUP_TOOLCHAIN=nightly-2026-07-09 cargo public-api -p file-acl --all-features \
    --omit blanket-impls,auto-derived-impls > public-api.txt
```

CI's `semver` job documents the newest release tag and the tree, and runs
[cargo-semver-checks](https://github.com/obi1kenobi/cargo-semver-checks)
between them. While `version` still names the last release, the job fails on
a breaking change and lists the items it breaks. Bumping the version to the
next breaking release, such as 0.1.x to 0.2.0, turns it green. Each item it
listed then takes a **Breaking.** entry in CHANGELOG.md.

The job sees only the API's signatures. A change in the lists file-acl
accepts, or in what it writes, passes it, and is still recorded in the
changelog. Run locally, `cargo semver-checks` compares the tree with the
newest release on crates.io.

## Fuzzing

`fuzz/` holds [cargo-fuzz](https://github.com/rust-fuzz/cargo-fuzz) targets,
in a workspace of their own, so the harness never joins the library's build:

- `decode` decodes arbitrary input as an attribute value. It checks that
  only an empty value or a header alone is no list, and that a refusal names
  an entry the value holds. It checks that a list read encodes canonically,
  and decodes and encodes again unchanged. The canonical form is the input
  with its named entries sorted by id, and the other entries' ids set to
  `UNDEFINED_ID`.
- `text` parses arbitrary input as a list's text. It checks that only an
  empty text is no list, and that a refusal names an offset within the text.
  It checks that a parsed text resolves, narrows and computes its mask
  without panicking. It checks that a list resolved, then written in every
  spelling with numeric ids and with generated names, reads back as itself.
- `round_trip` builds entries from arbitrary input, with names of any bytes.
  It checks that a list is its entries in canonical order, and that its
  binary form decodes to it and encodes again unchanged. It checks that the
  list's text in every spelling, with numeric ids and with the names, reads
  back as the list. Where the spelling records ids, the text also reads back
  with no lookup. It checks that the narrowing and the computed mask of its
  text are the list's. It also checks that entries making no list break the
  rule named.

The targets need a nightly toolchain. CI builds them and runs each for a
fixed number of runs. After changing the binary or the text form, run its
target for a while before opening the pull request:

```sh
cd fuzz
cargo +nightly fuzz run text
cargo +nightly fuzz run text -- -jobs=4 -workers=4
```

`cargo fuzz list` names the targets. With `-jobs`, libFuzzer writes each
job's log to `fuzz-<n>.log` in the directory it runs in. Running from
`fuzz/` keeps those logs beside the corpus and out of the repository's
status. An input that fails is saved under `fuzz/artifacts/` and replays
with `cargo +nightly fuzz run <target> <file>`.

## Code conventions

- **No `unsafe`.** The crate forbids it, its tests included.
- **No panics in library code.** Attribute values and archive records come
  from files and archives the caller does not control, so a reachable panic
  is a denial of service. Outside tests, the lints at the top of `src/lib.rs`
  deny the common ways to panic or to compute a wrong length silently. Those
  are indexing, unchecked arithmetic, truncating casts, `unwrap`, `expect`
  and the panicking macros. Where a site cannot fail and is clearer written
  directly, mark the smallest item that holds it with
  `#[expect(lint, reason = "...")]`. The reason states the invariant that
  makes it safe.
- **Bounded work.** Reading and writing are linear in their input, but for
  sorting a list's entries, which is `O(n log n)`. Nothing recurses on the
  input.
- **`no_std` with `alloc`.** The library needs an allocator and nothing else
  from its platform.
- **Errors are typed and say what.** An error names the rule broken and the
  entry that broke it, as structured fields rather than strings. Error enums
  are `#[non_exhaustive]`, so a new kind of failure is not a breaking change,
  and their `Display` is written by hand.
- **Types a caller matches on are exhaustive.** `Tag` and `Qualifier` name
  what POSIX.1e defines, and a caller's match on them names every case.
- **Documentation is part of the change.** Public items have rustdoc, and
  internal items have it wherever the behavior is not obvious. Comments
  explain *why*, not *what*. A rule taken from a reference's behavior names
  the test that compares with it.
- **No emoji** in code, comments, documentation, or commit messages.

## Commit messages

Write in the imperative mood, describing the change in the repository's own
terms. A body explaining the reasoning is welcome where the reasoning is not
obvious.

## License

The project is dual-licensed under Apache-2.0 and MIT. Unless you state
otherwise, any contribution you intentionally submit for inclusion, as defined
in the Apache-2.0 license, is dual-licensed the same way, with no additional
terms or conditions.
