# Changelog

All notable changes to file-acl are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project
follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html): while the
major version is 0, a breaking change bumps the minor version. An entry a
caller must act on is prefixed **Breaking.**

The lists file-acl accepts and refuses, and the bytes and text it writes for
them, are part of its contract. A change to either is recorded, with what it
changes, even when no signature of the public API does.

## [0.1.0] - 2026-11-25

The first release, measured against Linux 7.2, libacl 2.3.2 and GNU tar 1.35
as Ubuntu 24.04 packages them, libacl 2.4.0, bsdtar 3.8.11 and star 1.7.0.

### Added

- The model of a POSIX.1e access control list: `Acl`, its `Entry`s, each a
  `Qualifier` (a `Tag`, and an id for a named user or group) and a `Perm`.
- `Acl::new`, which puts entries in canonical order. It accepts a list where
  the kernel accepts it and libacl's `acl_check` passes it. It refuses the
  rest with `Invalid`, which names the rule broken: a required entry
  `Missing`, an entry `Repeated`, or a named entry with the `UNDEFINED_ID`.
- The binary form, in `xattr`: the value of the `system.posix_acl_access` and
  `system.posix_acl_default` extended attributes (`ACCESS`, `DEFAULT`).
- `xattr::decode`, which accepts a value where the kernel accepts it in the
  initial user namespace. The one exception is a value naming the same user
  or group twice. The kernel stores such a value, and `decode` refuses it, as
  `Acl::new` does. An empty value, or a header alone, is no list
  (`Ok(None)`), as the kernel takes either as removing one. Named users, and
  named groups, are accepted in any order among themselves, and read in
  canonical order. The ids of the owner, owning group, mask and other entries
  are ignored.
- `DecodeError`, which names the rule a refused value breaks. A value longer
  than the 65,536 bytes the kernel takes, a list of more than 8,191 entries,
  is `TooLong`. The kernel refuses it before anything else, and so does
  `decode`. The other refusals are a `Version` other than 2, a `Partial`
  entry, an `UnknownTag`, a `StrayPerm` bit, entries out of `TagOrder`, and an
  `Invalid` list. A named entry with the `UNDEFINED_ID` is `UnmappedId`. The
  kernel gives such a value to a process whose user namespace does not map
  the entry's id.
- `xattr::encode`, which writes a list's entries in canonical order. The
  owner, owning group, mask and other entries have the `UNDEFINED_ID` as their
  id.
- `xattr::MAX_LEN` and `xattr::MAX_ENTRIES`: the longest value the kernel
  takes, 65,536 bytes, and the most entries such a value holds, 8,191.
  `encode` writes a value for a longer list, which the kernel refuses.
- The rules that tie a list to a file's mode, in `mode` and on `Acl`.
  `mode_bits` is the permission bits a file with a list as its access list
  shows. The group bits are the mask's where there is one. `is_minimal` says
  whether a list has no mask and names no one, and so is not stored as an
  access list. `from_mode` is the minimal list of a mode, and `with_mode` the
  access list after `chmod`.
- `Acl::narrowed`, the minimal list granting the owner, and anyone the list
  does not name, what the list grants them.
- `Acl::with_computed_mask`, which makes a list from entries with the mask
  computed as `setfacl --mask` computes it, replacing any the entries hold.
  It adds none to entries that name no one and hold none, where libacl's
  `acl_calc_mask` adds one.
- `mode::set`, which says what setting an access or default list
  (`ListKind`), or none, leaves on a file. A `FileKind` is a directory, a
  symbolic link or another kind of file. It gives the mode, and the list the
  file has (`Set`). `SetError` names what the kernel refuses. `TooLong` is a
  list of more than 8,191 entries, on any file. The others are a default list
  on a file that is not a directory, and a list on a symbolic link.
- Id mapping: `Acl::map_ids` restates a list with its named users' and
  groups' ids read through a caller's translations, as across a user
  namespace's map. The result is in canonical order whatever the translation
  does to it. `MapError` names the first named entry, in canonical order,
  whose id has no answer (`Unmapped`). Otherwise it names the rule the
  translated list breaks (`Invalid`), as when two ids are translated to one.
- `Acl::map_ids_partial`, which restates a list the same way but leaves out
  each named entry whose id has no answer. It says how many it left out
  (`Partial`). Everyone the translation answers for keeps what the list
  granted them. The narrowing instead gives a named user or group what their
  class is granted.
- The text form, in `text`. `parse` reads a list's text as libacl's
  `acl_from_text` reads it. It reads entries separated by commas or line
  ends, with long or short tags. Permissions are one to three of `r`, `w`,
  `x` and `-`. It reads comments where libacl reads them, and names with
  `\ooo` and `\\` escapes.
- `parse` refuses what libacl reads where libacl is loose. It refuses a
  qualifier libacl reads as a number in a form other than a decimal id.
  Those forms are a sign, hexadecimal, binary, a leading zero (octal to
  libacl) and leading whitespace. libacl reads binary (`0b1`) as a number
  where it is built against glibc 2.38 or later, and as a name otherwise. It
  refuses a number past the range of an id, which libacl 2.3 wraps and
  libacl 2.4 looks up as a name. It refuses an escape giving a NUL or more
  than a byte.
- `parse` also refuses entries with no comma or line end between them, and a
  tag not followed directly by its colon. It refuses a comma that does not
  follow an entry on its line. It refuses a name beginning with a line end or
  a carriage return, which libacl keeps as part of the name, and a NUL. As
  libacl does, it refuses a line end or a carriage return later in a name.
- `parse` reads a fourth field, the id star and libarchive record beside a
  name, which libacl refuses. An empty text is no list (`Ok(None)`), as GNU
  tar writes an empty `SCHILY.acl.default` record. `ParseError` names the
  fault and the byte offset it is found at.
- `Parsed::resolve`, which asks the caller's lookups for each name's id.
  `Prefer` says whether a name or its recorded id is taken where an entry
  holds both. `ResolveError` names a name with no answer (`Unresolved`), or
  the rule the list breaks (`Invalid`).
- `Parsed::resolve_partial`, which leaves out each entry naming someone with
  no answer and no recorded id, as `Acl::map_ids_partial` leaves out an id.
  `Parsed::holds_names` says whether a text holds a name, and so needs a
  lookup at all. `Parsed::with_computed_mask` computes the mask as
  `Acl::with_computed_mask` does, and `Parsed::narrowed` gives the narrowing,
  which needs no names.
- `write`, which spells a list with numeric ids, and `write_named`, which
  spells it with the names the caller's lookups give. Names are escaped so
  that libacl and `parse` read them back. A name a reader could take for a
  number is written as its id. Such a name is one libacl reads as a number,
  such as `0x10` or `0b1`. It is also one of digits alone, such as `08`,
  which libarchive reads as a decimal id where its system lacks the name. A
  `Spelling` sets long or short `Tags`, a newline or comma `Separator`, and
  `Names` alone or followed by their ids.
- `Spelling::GNU_TAR`, GNU tar's spelling, and `Spelling::STAR`, star's, which
  libarchive writes too. `Spelling::STAR` records every name's id and escapes
  names. star, GNU tar and libarchive read it as the list, names that need
  escaping included.

### Agreement with the references

- 50 values the kernel was measured answering, and 3,000 generated values on
  each of two filesystems, one a tmpfs. `decode` gives each the kernel's
  verdict, but for a value naming a user or group twice, which the kernel
  stores. The kernel holds `encode`'s value for 500 generated lists on each,
  byte for byte.
- 1,500 generated cases of `mode::set` on each filesystem, on files,
  directories, FIFOs, sockets, symbolic links and character devices. Each
  gives the mode and the lists the kernel leaves, or the kernel's refusal.
  `with_mode` gives the access list `chmod` leaves, for 500 generated lists
  on each.
- 120 generated lists, with `access(2)` asked for 12 credentials under each.
  For the owner, and for anyone the list does not name, it answers the same
  under `Acl::narrowed`.
- 1,000 generated lists, set or read across a user namespace whose map does
  not keep the order of ids. The kernel translates each as `map_ids` does.
  Where the namespace does not map an id, `decode` and `map_ids` name the
  same entry.
- 6,000 generated lists, 3,000 of them with one fault. `Acl::new` accepts
  each where libacl's `acl_check` passes it, and names the fault
  `acl_check` reports.
- All 4,096 modes, and 4,000 generated lists, through libacl's rules for a
  mode. `from_mode` gives `acl_from_mode`'s list, and `mode_bits` and
  `is_minimal` give `acl_equiv_mode`'s answers. `with_computed_mask` gives
  `acl_calc_mask`'s list, but for entries naming no one and holding no mask.
- 339 texts libacl 2.3.2 was measured reading, 26 of them naming users and
  groups a files database cannot hold. `parse` reads 261 as libacl does, and
  the other 78 differ as the `text` module states. libacl 2.4.0 reads 8 of
  them otherwise, and 3 of those differ as stated.
- 8,000 generated texts, read by libacl and by `parse` through the same
  account database. Each is read alike, or differs as the `text` module
  states.
- 1,500 generated lists, written by id and by name in the four spellings that
  record no ids. libacl reads each text as the list.
- 1,920 files and directories in archives of the crate's text, 240 in each
  spelling. GNU tar extracts each with the lists the text states, and the
  mode they give. bsdtar extracts 1,920 more the same way, with names that
  need escaping only where the spelling records ids.
- 320 files and directories archived by GNU tar, and 320 by bsdtar. `parse`
  reads each record as the list set.
- The records GNU tar 1.35 was measured writing for 7 members, libarchive
  3.8.11 for 3 and star 1.7.0 for 4. `parse` reads each as the list set, but
  one GNU tar cut at a `#` in a name, which no reader reads. For GNU tar's
  other 6, `write_named` spells each stored list as GNU tar's text, byte for
  byte.
- The crate's `Spelling::STAR` text of 22 lists, from which star 1.7.0 sets
  each list.

[0.1.0]: https://github.com/gregordinary/file-acl/releases/tag/v0.1.0
