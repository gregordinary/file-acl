//! POSIX.1e access control lists as data, in safe Rust.
//!
//! file-acl holds the model of a POSIX access control list, its validity
//! rules, the binary form Linux's extended attributes carry it in, the text
//! form tar archives carry and `getfacl --omit-header` writes, the rules that
//! tie a list to a file's mode, and the restatement of a list's ids through a translation
//! ([`Acl::map_ids`]), with no I/O: reading and writing extended attributes,
//! and looking up user and group names, are the caller's. It contains no
//! `unsafe` code, has no dependencies, and needs nothing from its platform but
//! an allocator. It is in early development.
//!
//! An [`Acl`] is a list of [`Entry`]s, each granting a [`Perm`] to the user or
//! group its [`Qualifier`] names. An `Acl` is always valid, as the kernel and
//! libacl judge a list, and always in the order they hold its entries in, so
//! two lists holding the same entries, in any order, are equal:
//!
//! ```
//! use file_acl::{Acl, Entry, Perm, Qualifier};
//!
//! let acl = Acl::new(vec![
//!     Entry::new(Qualifier::Other, Perm::NONE),
//!     Entry::new(Qualifier::User(1000), Perm::READ | Perm::WRITE),
//!     Entry::new(Qualifier::UserObj, Perm::READ | Perm::WRITE),
//!     Entry::new(Qualifier::GroupObj, Perm::READ),
//!     Entry::new(Qualifier::Mask, Perm::READ | Perm::WRITE),
//! ])?;
//! assert_eq!(acl.entries()[1].qualifier, Qualifier::User(1000));
//! assert_eq!(acl.mask(), Some(Perm::READ | Perm::WRITE));
//! # Ok::<(), file_acl::Invalid>(())
//! ```
//!
//! [`xattr`] reads and writes the value of the `system.posix_acl_access` and
//! `system.posix_acl_default` extended attributes. It accepts a value where
//! the kernel accepts one, but for a value naming a user or group twice, and
//! names the rule a refused value breaks:
//!
//! ```
//! use file_acl::xattr::{self, DecodeError};
//! use file_acl::{Acl, Entry, Perm, Qualifier};
//!
//! let acl = Acl::new(vec![
//!     Entry::new(Qualifier::UserObj, Perm::ALL),
//!     Entry::new(Qualifier::GroupObj, Perm::READ),
//!     Entry::new(Qualifier::Other, Perm::NONE),
//! ])?;
//! let value = xattr::encode(&acl);
//! assert_eq!(xattr::decode(&value), Ok(Some(acl)));
//!
//! // A header alone holds no list: the kernel takes it as removing one.
//! assert_eq!(xattr::decode(&value[..4]), Ok(None));
//! // A value that ends partway through an entry holds none either.
//! assert_eq!(
//!     xattr::decode(&value[..7]),
//!     Err(DecodeError::Partial { len: 7 })
//! );
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```
//!
//! [`text`] reads and writes the text form, as libacl reads it and GNU tar
//! writes it in its `SCHILY.acl.access` and `SCHILY.acl.default` records. A
//! text names users and groups by id or by name; the caller says what each
//! name stands for:
//!
//! ```
//! use file_acl::text::{self, Prefer, Spelling};
//! use file_acl::{Perm, Qualifier};
//!
//! let parsed = text::parse(b"user::rw-\ngroup::r--\ngroup:staff:rw-\nmask::rw-\nother::---\n")?
//!     .expect("the text holds a list");
//! let groups = |name: &[u8]| (name == b"staff").then_some(50);
//! let acl = parsed.resolve(|_| None, groups, Prefer::Name)?;
//! assert_eq!(acl.perm(Qualifier::Group(50)), Some(Perm::READ | Perm::WRITE));
//! assert_eq!(
//!     text::write(&acl, Spelling::GNU_TAR),
//!     b"user::rw-\ngroup::r--\ngroup:50:rw-\nmask::rw-\nother::---\n"
//! );
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```
//!
//! [`mode`] keeps a list and a file's mode in step as the kernel does: what
//! setting a list does to the mode, and whether the list is stored at all;
//! what `chmod` does to a list; and the list a file is given in place of one
//! it cannot carry:
//!
//! ```
//! use file_acl::mode::{self, FileKind, ListKind};
//! use file_acl::{Acl, Entry, Perm, Qualifier};
//!
//! let acl = Acl::new(vec![
//!     Entry::new(Qualifier::UserObj, Perm::ALL),
//!     Entry::new(Qualifier::User(1000), Perm::READ | Perm::WRITE),
//!     Entry::new(Qualifier::GroupObj, Perm::READ),
//!     Entry::new(Qualifier::Mask, Perm::READ | Perm::WRITE),
//!     Entry::new(Qualifier::Other, Perm::NONE),
//! ])?;
//! // Set on a file of mode 0644, the list leaves it 0760: the group bits are
//! // the mask's.
//! let set = mode::set(0o644, FileKind::Other, ListKind::Access, Some(acl.clone()))?;
//! assert_eq!(set.mode, 0o760);
//!
//! // Without the list, the mode alone would give the owning group the mask's
//! // `rw-`; its narrowing gives it what the list did.
//! assert_eq!(acl.narrowed().mode_bits(), 0o740);
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

#![no_std]
// The manifest forbids `unsafe` code too; the attribute holds wherever the
// crate is built, Cargo or not. Doctests are crates of their own, which
// neither reaches, so they carry it as well, beside the `allow(unused)`
// rustdoc gives them only where no attribute is named.
#![forbid(unsafe_code)]
#![doc(test(attr(allow(unused), forbid(unsafe_code))))]
// Attribute values and archive records come from files and archives this crate
// does not control, so a panic in library code is a decision made where the
// code is written rather than a finding a fuzzer reports later. Each lint below
// names a way to panic, or to compute a wrong length silently; a site that
// genuinely cannot fail and is clearer written directly carries
// `#[expect(..., reason = "...")]` on the smallest item that holds it, with the
// reason stating the invariant. Tests are exempt: there a panic is how a check
// fails.
#![cfg_attr(
    not(test),
    deny(
        clippy::alloc_instead_of_core,
        clippy::arithmetic_side_effects,
        clippy::cast_possible_truncation,
        clippy::cast_possible_wrap,
        clippy::cast_sign_loss,
        clippy::expect_used,
        clippy::indexing_slicing,
        clippy::panic,
        clippy::std_instead_of_alloc,
        clippy::std_instead_of_core,
        clippy::string_slice,
        clippy::todo,
        clippy::unimplemented,
        clippy::unreachable,
        clippy::unwrap_used,
    )
)]

extern crate alloc;
#[cfg(test)]
extern crate std;

mod acl;
mod map;
pub mod mode;
pub mod text;
pub mod xattr;

pub use acl::{Acl, Entry, Invalid, Perm, Qualifier, Tag, UNDEFINED_ID};
pub use map::{MapError, Partial};
