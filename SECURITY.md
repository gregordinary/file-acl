# Security policy

file-acl decides what an access control list means. It reads attribute values
from files, and list texts from archives, that its caller does not control.
What it answers says who may read, write and execute a file. A defect can
grant access a list does not, or let crafted input stop it answering.
Security reports are therefore handled separately from ordinary bugs.

## Reporting a vulnerability

**Do not open a public issue.** Report privately through GitHub's [private
vulnerability reporting](https://github.com/gregordinary/file-acl/security/advisories/new)
for this repository, which opens a draft advisory visible only to you and the
maintainers.

Please include, as far as you can:

- The input: the attribute value as hexadecimal, or the list's text, and the
  call that read it.
- What file-acl returned, and what it should have returned. If the kernel,
  `getfacl` or GNU tar reads the input otherwise, what they report, and their
  versions.
- The commit or version of file-acl.

You will get an acknowledgement within a few days. Once a fix exists, the
advisory names the reporter unless you ask otherwise.

## Scope

- **A list read as granting what its input does not.** A value or text read
  to a list whose entries, ids or permissions differ from what it states. A
  list written to bytes or text that read back as a different list, here or
  by the kernel, libacl or GNU tar.
- **A list accepted that the kernel refuses**, or one refused that it
  accepts, other than as the documentation states.
- **Panics and runaway work on hostile input.** The library is written not to
  panic. Its time and memory are linear in its input, but for sorting a list's
  entries, which takes `O(n log n)` time in their number. A panic, or time or
  memory that grows faster than that, on any value or text, is a
  vulnerability. Values and texts come from outside the caller's control.

## Out of scope

- **The documented differences from libacl and GNU tar.** The `text` module's
  documentation lists where file-acl reads or writes otherwise than they do,
  on purpose. A difference it does not list is a defect, welcome as an
  ordinary issue unless it is one of the cases above.
- **What a name means.** file-acl looks up no user or group name: the caller
  answers each one. A lookup that answers wrongly is the caller's.

If you are unsure which side of the line a finding falls on, report it
privately, and the maintainers will decide.

## Supported versions

Security fixes are made to the newest release, and published as a release of
their own. Earlier releases are not patched, so receiving a fix means
upgrading to the newest release. While the major version is 0, a fix that
breaks the public API is published as a new minor version, such as 0.2.0
after 0.1.x. Any other fix is published as a new patch version.
