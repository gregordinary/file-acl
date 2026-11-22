# Changelog

All notable changes to this project are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project
follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html): while the
major version is 0, a breaking change bumps the minor version. An entry a
caller must act on is prefixed **Breaking.**

Which lists file-acl accepts and refuses, and the bytes and text it writes for
them, are part of its contract. A change to either is recorded, with what it
changes, even when no signature of the public API does.

## [Unreleased]

### Added

- The model of a POSIX.1e access control list: `Acl`, its `Entry`s, each a
  `Qualifier` (a `Tag`, and an id for a named user or group) and a `Perm`.
  `Acl::new` puts entries in canonical order and accepts a list where the
  kernel accepts it and libacl's `acl_check` passes it, refusing the rest with
  `Invalid`, which names the rule broken: a required entry `Missing`, an entry
  `Repeated`, or a named entry carrying the `UNDEFINED_ID`.
- The binary form, in `xattr`: the value of the `system.posix_acl_access` and
  `system.posix_acl_default` extended attributes (`ACCESS`, `DEFAULT`).
  `decode` accepts a value where the kernel accepts it, but for a value naming
  the same user or group twice, which the kernel stores and `decode` refuses,
  as `Acl::new` does. An empty value, or a header alone, is no list
  (`Ok(None)`), as the kernel takes either as removing one. Named users, and
  named groups, are accepted in any order among themselves and read in
  canonical order; the ids of the owner, owning group, mask and other entries
  are ignored. Any other value is refused with a `DecodeError` naming the rule
  it breaks: a value longer than the 65,536 bytes the kernel takes for an
  extended attribute, a list of more than 8,191 entries (`TooLong`), which the
  kernel refuses before anything else; a `Version` other than 2, a `Partial`
  entry, an `UnknownTag`, a `StrayPerm` bit, entries out of `TagOrder`, a
  named entry carrying the `UNDEFINED_ID` (`UnmappedId`, which is how a
  process reads an id its user namespace does not map), or an `Invalid` list.
  `encode` writes a list's entries in canonical order, the owner, owning
  group, mask and other entries carrying the `UNDEFINED_ID`.
- The rules that tie a list to a file's mode, in `mode` and on `Acl`.
  `mode_bits` is the permission bits a file carrying a list as its access list
  shows, the group bits the mask's where there is one; `is_minimal` says
  whether a list has no mask and names no one, and so is not stored as an
  access list; `from_mode` is the minimal list of a mode; `with_mode` is the
  access list after `chmod`; `narrowed` is the minimal list granting the
  owner, and anyone the list does not name, what the list grants them; and
  `with_computed_mask` makes a list from entries with the mask `setfacl`
  computes, adding none to entries that name no one and hold none, where
  libacl's `acl_calc_mask` adds one. `mode::set` says what setting an access
  or default list (`ListKind`), or none, on a directory, a symbolic link or
  another kind of file (`FileKind`) leaves: the mode, and the list the file
  holds (`Set`), or that the kernel refuses it (`SetError`: a list of more
  than 8,191 entries, `TooLong`, on any file; a default list on a file that is
  not a directory; or a list on a symbolic link).
- Id mapping: `Acl::map_ids` restates a list with its named users' and
  groups' ids read through a caller's translations, as across a user
  namespace's map, in canonical order whatever the translation does to it.
  `MapError` names the first named entry, in canonical order, whose id has no
  answer (`Unmapped`), or the rule the translated list breaks (`Invalid`), as
  when two ids are translated to one. `Acl::map_ids_partial` restates a list
  the same way but leaves out each named entry whose id has no answer, and
  says how many it left out (`Partial`): everyone the translation answers for
  keeps what the list granted them, where the narrowing gives a named user or
  group what their class is granted.
- The text form, in `text`. `parse` reads a list's text as libacl's
  `acl_from_text` reads it: entries separated by commas or line ends, long or
  short tags, permissions of one to three of `r`, `w`, `x` and `-`, comments
  where libacl reads them, and names with `\ooo` and `\\` escapes. Where
  libacl is loose, `parse` refuses what libacl reads: a qualifier libacl reads
  as a number in another form than a decimal id (a sign, hexadecimal, a
  leading zero, which libacl reads as octal, leading whitespace) or past the
  range of an id, which libacl 2.3 wraps and libacl 2.4 looks up as a name; an
  escape giving a NUL or more than a byte; entries with no comma or line end
  between them; a tag not followed directly by its colon; a comma that does
  not follow an entry on its line; a name beginning with a line end or a
  carriage return, which libacl keeps as part of the name; and a NUL. As
  libacl does, it refuses a line end or a carriage return later in a name. It
  reads a fourth field, the id star and libarchive record beside a name, which
  libacl refuses. An empty text is no list (`Ok(None)`), as GNU tar writes an
  empty `SCHILY.acl.default` record. `ParseError` names the fault and the byte
  offset it is found at. `Parsed::resolve` asks the caller's lookups for each
  name's id, and `Prefer` says whether a name or its recorded id is taken
  where an entry holds both; `ResolveError` names a name with no answer
  (`Unresolved`), or the rule the list breaks (`Invalid`).
  `Parsed::resolve_partial` leaves out each entry naming someone with no
  answer and no recorded id, as `Acl::map_ids_partial` leaves out an id, and
  `Parsed::holds_names` says whether a text holds a name, and so needs a
  lookup at all. `Parsed::with_computed_mask` computes the mask `setfacl`
  does, and `Parsed::narrowed` gives the narrowing, which needs no names.
  `write` spells a list with numeric ids, and `write_named` with the names the
  caller's lookups give, escaped so that libacl and `parse` read them back, in
  a `Spelling` of long or short `Tags`, a newline or comma `Separator`, and
  `Names` alone or followed by their ids. `Spelling::GNU_TAR` is GNU tar's;
  `Spelling::STAR` is star's, which libarchive writes too, with every name's
  id recorded and names escaped, and is read as the list by star, GNU tar and
  libarchive, names that need escaping included.
