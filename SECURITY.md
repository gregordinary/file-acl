# Security policy

file-acl decides what an access control list means. It reads attribute values
from files and list texts from archives its caller does not control, and what
it answers says who may read, write and execute a file. A defect can grant
access a list does not, or let input crafted for it stop it answering, so
security reports are handled separately from ordinary bugs.

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

## What is in scope

- **A list read as granting what its input does not.** A value or text read
  to a list whose entries, ids or permissions differ from what it states, or
  a list written to bytes or text that read back, here or by the kernel,
  libacl or GNU tar, as a different list.
- **A list accepted that the kernel refuses**, or one refused that it
  accepts, other than as the documentation states.
- **Panics and runaway work on hostile input.** The library is written not to
  panic, and its work is linear in its input. A panic, or time or memory that
  grows faster than that, on any value or text, is a vulnerability, since
  values and texts come from outside the caller's control.

## What is not in scope

- **The documented differences from libacl and GNU tar.** The documentation
  lists where file-acl reads or writes otherwise than they do, on purpose. A
  difference it does not list is a defect, welcome as an ordinary issue unless
  it is one of the cases above.
- **What a name means.** file-acl looks up no user or group name: the caller
  answers each one. A lookup that answers wrongly is the caller's.

If you are unsure which side of the line a finding falls on, report it
privately and we will work it out.

## Supported versions

Security fixes are made to the newest release, and published as a release of
their own; earlier releases are not patched, so receiving a fix means
upgrading to the newest release. While the major version is 0, a fix that
breaks compatibility with the public API is published as a new minor version,
such as 0.2.0 after 0.1.x, and any other as a new patch version.
