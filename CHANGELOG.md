# Changelog

All notable changes to file-acl are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project
follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html): while the
major version is 0, a breaking change bumps the minor version. An entry a
caller must act on is prefixed **Breaking.**

The lists file-acl accepts and refuses, and the bytes and text it writes for
them, are part of its contract. A change to either is recorded, with what it
changes, even when no signature of the public API does.

## [Unreleased]

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
  `setfacl` computes. It adds none to entries that name no one and hold none,
  where libacl's `acl_calc_mask` adds one.
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
  Those forms are a sign, hexadecimal, a leading zero (octal to libacl) and
  leading whitespace. It refuses a number past the range of an id, which
  libacl 2.3 wraps and libacl 2.4 looks up as a name. It refuses an escape
  giving a NUL or more than a byte.
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
  lookup at all. `Parsed::with_computed_mask` computes the mask `setfacl`
  does, and `Parsed::narrowed` gives the narrowing, which needs no names.
- `write`, which spells a list with numeric ids, and `write_named`, which
  spells it with the names the caller's lookups give. Names are escaped so
  that libacl and `parse` read them back. A `Spelling` sets long or short
  `Tags`, a newline or comma `Separator`, and `Names` alone or followed by
  their ids.
- `Spelling::GNU_TAR`, GNU tar's spelling, and `Spelling::STAR`, star's, which
  libarchive writes too. `Spelling::STAR` records every name's id and escapes
  names. star, GNU tar and libarchive read it as the list, names that need
  escaping included.
