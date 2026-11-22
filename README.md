# file-acl

POSIX.1e access control lists as data, in safe Rust.

file-acl is in early development. Its API is not yet stable.

It holds the model of a POSIX access control list: its entries, the rules a
valid list keeps, and the canonical order of its entries. The rules and the
order are the kernel's and libacl's. Around that model, it covers:

- The version-2 binary form the `system.posix_acl_access` and
  `system.posix_acl_default` extended attributes hold. It accepts a value
  where the kernel accepts one in the initial user namespace, but for one
  naming a user or group twice. It names the rule a refused value breaks.
- The text form tar's `SCHILY.acl.*` records hold and `getfacl --omit-header`
  prints. It reads the text as libacl does, but for the differences its
  `text` module lists, and resolves names through lookups the caller gives.
  It writes the text as GNU tar does, with names where the caller has them.
  It can also write each name's id beside it, as star and libarchive do, and
  star, GNU tar and libarchive all read that form.
- The rules that tie a list to a file's mode, as the kernel keeps them. They
  say what setting a list does to the mode, whether the list is stored, and
  what `chmod` does to it. They also give the list to set in place of one a
  file cannot have. They serve a program writing files with no kernel to
  ask, such as one building a filesystem image.
- The restatement of a list's ids through a caller's translation, as across
  a user namespace's map.

It does no I/O: reading and writing extended attributes, and looking up user
and group names, are the caller's. It contains no `unsafe` code, has no
dependencies, and needs nothing from its platform but an allocator. Its rules
are the kernel's, libacl's, GNU tar's, libarchive's and star's as measured,
and its tests compare it with them.

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT license ([LICENSE-MIT](LICENSE-MIT))

at your option.
