# file-acl

POSIX.1e access control lists as data, in safe Rust.

file-acl is in early development, and its API is not yet stable. It holds the
model of a POSIX access control list: its entries, the rules a valid list
keeps, as the kernel and libacl judge one, and the canonical order they hold a
list's entries in. It reads and writes the version-2 binary form the
`system.posix_acl_access` and `system.posix_acl_default` extended attributes
carry. It accepts a value where the kernel accepts one in the initial user
namespace, but for one naming a user or group twice. It names the rule a
refused value breaks. It keeps a list and a file's mode in step as the kernel
does, for a program that writes files without a kernel to ask, such as one
building a filesystem image: what setting a list does to the mode, whether the
list is stored, what `chmod` does to it, and the list a file is given in place
of one it cannot carry. It restates a list's ids through a caller's
translation, as across a user namespace's map.
It reads the text form tar's `SCHILY.acl.*` records carry and
`getfacl --omit-header` prints, as libacl reads it, but for the differences its
`text` module lists. It resolves names through lookups the caller gives. It
writes the text as GNU tar writes it, with names where the caller has them. It
can also write each name's id beside it, as star and libarchive write it,
which star, GNU tar and libarchive all read.

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
