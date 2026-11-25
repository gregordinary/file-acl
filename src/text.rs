//! The text form: a list as libacl's `acl_from_text` reads it,
//! `getfacl --omit-header` prints it, and tar's `SCHILY.acl.access` and
//! `SCHILY.acl.default` records hold it.
//!
//! A list's text is one entry per line or per comma: a tag, a qualifier and
//! the permissions, separated by colons, as `user:1000:rw-` or `u:1000:rw`.
//! The qualifier of a user or group entry names whom it is for, by id or by
//! name. The owner's, owning group's, mask's and other's entries leave it
//! empty.
//!
//! Reading a text takes two steps, since a name means different users to
//! different systems. [`parse`] reads the text, names and all, and
//! [`Parsed::resolve`] asks the caller what each name stands for. The crate
//! reads no account database.
//!
//! ```
//! use file_acl::text::{self, Prefer};
//! use file_acl::{Perm, Qualifier};
//!
//! let parsed = text::parse(b"user::rw-\nuser:alice:r--\ngroup::r--\nmask::r--\nother::---\n")?
//!     .expect("the text holds a list");
//! let users = |name: &[u8]| (name == b"alice").then_some(1000);
//! let acl = parsed.resolve(users, |_| None, Prefer::Name)?;
//! assert_eq!(acl.perm(Qualifier::User(1000)), Some(Perm::READ));
//!
//! // Written back as GNU tar writes it, with names where the caller has them.
//! let names = |id: u32| (id == 1000).then_some("alice");
//! let written = text::write_named(&acl, text::Spelling::GNU_TAR, names, |_| None::<&str>);
//! assert_eq!(written, b"user::rw-\nuser:alice:r--\ngroup::r--\nmask::r--\nother::---\n");
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```
//!
//! # The grammar
//!
//! The text form is libacl's (`acl_from_text`), which GNU tar reads its
//! records with. [`parse`] reads a text where libacl reads it, and reads it
//! as libacl does, but for the differences below. The grammar they share:
//!
//! - Entries are separated by a comma or a line end (`\n`). Spaces, tabs and
//!   carriage returns may come before an entry and after one, so lines may end
//!   with `\r\n`. A comma may also follow the last entry.
//! - The tags are `user`, `group`, `mask` and `other`, or `u`, `g`, `m` and
//!   `o`, in lower case. The mask's and other's entries may leave out their
//!   empty qualifier field: `mask:rwx` is `mask::rwx`.
//! - The permissions are one to three of `r`, `w`, `x` and `-`, in any order,
//!   with each of `r`, `w` and `x` at most once. `rw-`, `wr`, `-` and `--x`
//!   are all read.
//! - A qualifier of decimal digits is an id, never looked up as a name. A
//!   qualifier libacl does not read as a number is a name. libacl 2.4 looks a
//!   qualifier of digits past the last id (`4294967295` and more) up as a
//!   name. [`parse`] reads `4294967295` as the undefined id, which
//!   [`Parsed::resolve`] finds invalid, and refuses more, as below.
//! - A name may hold any byte but a colon, a comma, a NUL, a line end and a
//!   carriage return. It may not begin with `#`. In a name, `\` and three
//!   octal digits stand for the byte they give, and `\\` for one backslash.
//!   A backslash before anything else is itself.
//! - An escape can give any byte but a NUL. The name a lookup is given can
//!   therefore hold a colon, a comma, a line end or a carriage return, or
//!   begin with `#`. libacl's lookups are given the same name:
//!   `group:co\072lon:r--` names the group `co:lon`.
//! - `#` begins a comment, which runs to the end of the line. A comment
//!   begins where an entry has ended: after its permissions, after the comma
//!   that ends it, or on a line of its own. `getfacl` writes `#effective:`
//!   after the permissions. As libacl reads comments, a comment before the
//!   first entry is refused, and at most one comment comes between two
//!   entries. A comment that ends its line is followed by another entry:
//!   `u::rw- #c` ends a text, and `u::rw- #c\n` does not.
//! - `getfacl`'s output is a list's text only with `--omit-header`, which
//!   leaves out its `# file:` comments. For a directory with a default list,
//!   it also needs `--access`, which leaves out the `default:` entries.
//! - A user or group entry may hold a fourth field: the id of the user or
//!   group its qualifier names (`user:alice:rw-:1000`). star and libarchive
//!   write it. On an entry naming an id, it must be that id.
//! - An empty text is no list: GNU tar writes an empty
//!   `SCHILY.acl.default` record for a directory with no default list. A
//!   text holding no entry but blanks or a comment is refused, as libacl
//!   refuses it.
//!
//! Where libacl is loose, [`parse`] refuses what libacl reads:
//!
//! - A qualifier libacl reads as a number in a form other than decimal
//!   digits. libacl reads it as C's `strtol` (libacl 2.3) or `strtoul`
//!   (libacl 2.4) does: signed (`-1`, `+5`), hexadecimal (`0x10`), or octal
//!   after a leading zero (`010` is 8). It also reads a number after leading
//!   whitespace. Built against glibc 2.38 or later, libacl reads binary too
//!   (`0b101` is 5). Built against an earlier glibc, it looks a binary
//!   number up as a name. [`parse`] refuses it either way.
//! - A number past the range of an id, which libacl 2.3 wraps (`4294967296`
//!   is 0) and libacl 2.4 looks up as a name.
//! - An escape that gives a NUL, or a value past a byte (`\400`). libacl 2.3
//!   reads either as the end of the name, and libacl 2.4 refuses `\000` and
//!   `\400`.
//! - Entries with no comma or line end between them (`u::rw- g::r--`, and
//!   even `u::rw-g::r--`).
//! - A comma that does not follow an entry on its own line
//!   (`u::rw-\n,\ng::r--`).
//! - A tag not followed directly by its colon. libacl passes over blanks and
//!   line ends after a tag (`u ::rw-`), and over comments too after a mask's
//!   or other's tag. It reads a mask's or other's permissions with two
//!   colons, one or none, and blanks around them (`m: :rwx`, `o r--`, even
//!   `orwx`).
//! - A name beginning with a line end or a carriage return, which libacl
//!   reads as part of the name (`group:\nstaff:r--` names the group
//!   `\nstaff`). libacl refuses one later in a name, and so does [`parse`].
//! - A NUL byte, which ends the text for libacl.
//!
//! And [`parse`] reads the fourth field, which libacl refuses.
//!
//! The tests compare [`parse`] and [`Parsed::resolve`] with libacl 2.3 or
//! 2.4, whichever is present. They hold every text libacl was measured
//! reading, with 2.4's reading where it differs. They also read a generated
//! corpus with libacl beside the crate, names resolved through the same
//! account database.
//!
//! # Other readers
//!
//! GNU tar reads its records with libacl, after dropping a fourth field. A
//! name it cannot resolve makes it drop the whole list.
//!
//! libarchive (bsdtar) reads the text with a reader of its own. It decodes no
//! escape, and looks a name up as the text spells it. Where the lookup has no
//! answer, it takes the recorded id. It looks a qualifier of digits up as a
//! name before reading it as an id. Where that lookup has no answer, it reads
//! the digits as a decimal id, leading zeros included (`08` is 8), and not
//! the recorded id.
//!
//! star reads a fourth field only in [`Spelling::STAR`]'s form: long tags, and
//! commas with no blanks after them. It takes the name where the reader's
//! system has it, and the id where it does not. It refuses a text holding a
//! `#`, a comment's included.
//!
//! A name that needs escaping is therefore read by all three only in
//! [`Spelling::STAR`], which records each name's id. GNU tar resolves the
//! name, libarchive falls back on the id, and star does either. The tests
//! extract text written in each spelling with GNU tar and bsdtar.

use alloc::string::ToString as _;
use alloc::vec::Vec;
use core::fmt;

use crate::acl::{Acl, Entry, Invalid, LETTERS, Perm, Qualifier, Tag, UNDEFINED_ID};
use crate::map::Partial;
use crate::mode::computed_mask;

/// The list `text` states, its names not yet resolved, or `None` where the
/// text is empty.
///
/// The text is read as the module's documentation describes. Its entries
/// may come in any order. [`Parsed::resolve`] judges the list it states once
/// its names stand for ids, so a text that parses can still state no valid
/// list.
///
/// # Errors
///
/// [`ParseError`] naming the first fault in the text, and the byte offset it
/// is found at.
pub fn parse(text: &[u8]) -> Result<Option<Parsed>, ParseError> {
    // Each rule is libacl's as measured, or one of the differences the
    // module's documentation states. `tests/text.rs` compares them with it:
    // `every_text_libacl_was_asked_about_parses_as_measured` holds the
    // measured texts, and `parse_agrees_with_libacl_over_generated_texts`
    // reads generated ones with both.
    if text.is_empty() {
        return Ok(None);
    }
    // `contains` finds a NUL a word at a time, and `position` a byte at a
    // time, so `position` is asked only where there is one.
    if text.contains(&0)
        && let Some(at) = text.iter().position(|&byte| byte == 0)
    {
        return Err(ParseError::Nul { at });
    }
    // The text is read twice: once to count its entries, then again to hold
    // them in a list of exactly that many. A list grown as it is read has up
    // to twice the room its entries need, and holds its old room and its new
    // at once while it grows: up to three times what the entries take. An
    // entry held already takes several times the room of its text. The
    // first reading holds nothing, so it allocates nothing but the room to
    // decode an escaped name in.
    let count = read_entries(text, |_| {})?;
    if count == 0 {
        return Err(ParseError::NoEntry);
    }
    let mut entries = Vec::with_capacity(count);
    read_entries(text, |entry| entries.push(entry.held()))?;
    Ok(Some(Parsed { entries }))
}

/// Reads the entries of `text`, which holds no NUL, giving each to `each` in
/// order, and returns how many there are. An entry's name is borrowed, from
/// the text or from the room its escapes are decoded in, until the next
/// entry is read.
fn read_entries(text: &[u8], mut each: impl FnMut(TextEntry<&[u8]>)) -> Result<usize, ParseError> {
    let mut cursor = Cursor { text, rest: text };
    let mut decoded = Vec::new();
    let mut count: usize = 0;
    loop {
        cursor.skip_space();
        match cursor.peek() {
            None => return Ok(count),
            // `end_of_entry` reads every comment after the first entry.
            Some(b'#') => return Err(ParseError::LeadingComment { at: cursor.at() }),
            Some(_) => {
                each(cursor.entry(&mut decoded)?);
                cursor.end_of_entry()?;
                // An entry is at least one byte of the text, so the count
                // stays below its length.
                count = count.saturating_add(1);
            }
        }
    }
}

/// A list's text, read: its entries as the text states them, before its
/// names stand for ids.
#[derive(Clone, PartialEq, Eq, Hash, Debug)]
pub struct Parsed {
    /// The entries, in the order the text gives them.
    entries: Vec<TextEntry>,
}

/// One entry of a list's text, its name held as `N`: a `Vec<u8>` in a
/// [`Parsed`], and borrowed while the text is read.
#[derive(Clone, PartialEq, Eq, Hash, Debug)]
struct TextEntry<N = Vec<u8>> {
    /// The entry's tag: [`Tag::User`] or [`Tag::Group`] where `who` names
    /// someone, and otherwise the tag of an entry naming no one.
    tag: Tag,
    who: Who<N>,
    perm: Perm,
}

/// Whom an entry is for, as its text says.
#[derive(Clone, PartialEq, Eq, Hash, Debug)]
enum Who<N = Vec<u8>> {
    /// The owner, the owning group, the mask or other.
    Nobody,
    /// The user or group with this id.
    Id(u32),
    /// The user or group with this name, its escapes decoded, and the id a
    /// fourth field records beside it, where it has one.
    Name { name: N, recorded: Option<u32> },
}

impl TextEntry<&[u8]> {
    /// The entry with its name held, in exactly the room it takes.
    fn held(self) -> TextEntry {
        let who = match self.who {
            Who::Nobody => Who::Nobody,
            Who::Id(id) => Who::Id(id),
            Who::Name { name, recorded } => Who::Name {
                name: name.to_vec(),
                recorded,
            },
        };
        TextEntry {
            tag: self.tag,
            who,
            perm: self.perm,
        }
    }
}

/// Which id [`Parsed::resolve`] gives an entry that holds both a name and,
/// in its fourth field, an id.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum Prefer {
    /// The id the caller's lookup gives the name, and the recorded id where
    /// the lookup has no answer, as star and libarchive read the two.
    Name,
    /// The recorded id, without asking the lookup. A name with no recorded
    /// id is looked up all the same.
    Id,
}

impl Parsed {
    /// The list the text states, each name read through `user` or `group`:
    /// the id the caller's account database gives it.
    ///
    /// The lookups are asked in the order the text gives its entries. They
    /// stop at the first name with neither an answer nor a recorded id. A
    /// name is passed as the text holds it, its escapes decoded. An entry
    /// naming an id asks neither lookup. Where an entry holds both a name
    /// and, in a fourth field, an id, `prefer` says which it is given.
    ///
    /// A text can state a list of more entries than
    /// [`xattr::MAX_ENTRIES`](crate::xattr::MAX_ENTRIES), which the kernel
    /// refuses to set. A caller that sets the list compares its length first,
    /// as [`xattr::encode`](crate::xattr::encode) says.
    ///
    /// ```
    /// use file_acl::text::{self, Prefer, ResolveError};
    /// use file_acl::{Qualifier, Tag};
    ///
    /// let parsed = text::parse(b"u::rw-,u:alice:rw-:1000,g::r--,m::rw-,o::---")?
    ///     .expect("the text holds a list");
    ///
    /// // The name is asked first, and the recorded id is its fallback.
    /// let acl = parsed.resolve(|_| Some(1001), |_| None, Prefer::Name)?;
    /// assert!(acl.perm(Qualifier::User(1001)).is_some());
    /// let acl = parsed.resolve(|_| None, |_| None, Prefer::Name)?;
    /// assert!(acl.perm(Qualifier::User(1000)).is_some());
    ///
    /// // Without a recorded id, a name with no answer stops the list.
    /// let parsed = text::parse(b"u::rw-,u:bob:r--,g::r--,m::r--,o::---")?
    ///     .expect("the text holds a list");
    /// assert_eq!(
    ///     parsed.resolve(|_| None, |_| None, Prefer::Name),
    ///     Err(ResolveError::Unresolved { tag: Tag::User, name: b"bob".to_vec() })
    /// );
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    ///
    /// # Errors
    ///
    /// - [`ResolveError::Unresolved`] naming the first name, in the text's
    ///   order, that has no answer and no recorded id to fall back on.
    /// - [`ResolveError::Invalid`] where the entries make no valid list once
    ///   their names stand for ids, as [`Acl::new`] names it.
    pub fn resolve(
        &self,
        mut user: impl FnMut(&[u8]) -> Option<u32>,
        mut group: impl FnMut(&[u8]) -> Option<u32>,
        prefer: Prefer,
    ) -> Result<Acl, ResolveError> {
        let mut entries = Vec::with_capacity(self.entries.len());
        for entry in &self.entries {
            let id = entry.id(&mut user, &mut group, prefer).map_err(|name| {
                ResolveError::Unresolved {
                    tag: entry.tag,
                    name: name.to_vec(),
                }
            })?;
            entries.push(Entry::new(Qualifier::new(entry.tag, id), entry.perm));
        }
        Ok(Acl::new(entries)?)
    }

    /// Whether an entry holds a name, which only a lookup can answer. A text
    /// naming everyone by id resolves without one, though the list it states
    /// can name users and groups, as [`Acl::names_anyone`] says.
    ///
    /// ```
    /// use file_acl::text;
    ///
    /// let by_id = text::parse(b"u::rw-,u:1000:r--,g::r--,m::r--,o::---")?;
    /// assert!(!by_id.expect("the text holds a list").holds_names());
    /// let by_name = text::parse(b"u::rw-,u:alice:r--:1000,g::r--,m::r--,o::---")?;
    /// assert!(by_name.expect("the text holds a list").holds_names());
    /// # Ok::<(), file_acl::text::ParseError>(())
    /// ```
    #[must_use]
    pub fn holds_names(&self) -> bool {
        self.entries
            .iter()
            .any(|entry| matches!(entry.who, Who::Name { .. }))
    }

    /// The list the text states, each name read through `user` or `group` as
    /// [`resolve`](Self::resolve) reads it. An entry whose name has no answer
    /// and no recorded id is left out.
    ///
    /// Leaving an entry out takes nothing from anyone the lookups answer
    /// for. Each keeps what the list granted them. The mask, which bounds the
    /// owning group and every named entry, is kept too. The entry left out
    /// granted or denied something to someone the caller's system has no
    /// account for.
    ///
    /// Where the list cannot be given at all, [`narrowed`](Self::narrowed) is
    /// the answer. It gives a named user or group what their class is
    /// granted, which can be more than the list granted them.
    ///
    /// The lookups are asked about every name, in the text's order, save a
    /// name with a recorded id under [`Prefer::Id`]. Two entries left out are
    /// not judged for naming the same user, since neither stands for an id.
    ///
    /// ```
    /// use file_acl::text::{self, Prefer};
    /// use file_acl::{Perm, Qualifier};
    ///
    /// let parsed = text::parse(b"u::rw-,u:alice:---,u:bob:rw-,g::r--,m::rw-,o::r--")?
    ///     .expect("the text holds a list");
    /// let users = |name: &[u8]| (name == b"alice").then_some(1000);
    /// let partial = parsed.resolve_partial(users, |_| None, Prefer::Name)?;
    /// // alice is still denied what everyone else may read.
    /// assert_eq!(partial.list.perm(Qualifier::User(1000)), Some(Perm::NONE));
    /// assert_eq!(partial.left_out, 1);
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    ///
    /// # Errors
    ///
    /// [`Invalid`] where the entries make no valid list, naming the rule they
    /// break. The entries naming no one are judged first, as
    /// [`narrowed`](Self::narrowed) judges them. The entries kept are then
    /// judged as [`Acl::new`] judges them, once their names stand for ids.
    pub fn resolve_partial(
        &self,
        mut user: impl FnMut(&[u8]) -> Option<u32>,
        mut group: impl FnMut(&[u8]) -> Option<u32>,
        prefer: Prefer,
    ) -> Result<Partial, Invalid> {
        self.objects()?;
        let mut entries = Vec::with_capacity(self.entries.len());
        let mut left_out = 0usize;
        for entry in &self.entries {
            match entry.id(&mut user, &mut group, prefer) {
                Ok(id) => entries.push(Entry::new(Qualifier::new(entry.tag, id), entry.perm)),
                Err(_) => left_out = left_out.saturating_add(1),
            }
        }
        Ok(Partial {
            list: Acl::new(entries)?,
            left_out,
        })
    }

    /// The text's entries with a computed mask, as
    /// [`Acl::with_computed_mask`] computes it.
    ///
    /// The mask is the union of what the owning group's entry and every named
    /// entry grant. It replaces any mask the text states, as `setfacl --mask`
    /// does, and is added where the text names someone and states none.
    ///
    /// It needs no names, since a mask is computed from permissions alone.
    ///
    /// ```
    /// use file_acl::text::{self, Prefer};
    /// use file_acl::Perm;
    ///
    /// // `setfacl -m` text, which names a user and states no mask.
    /// let parsed = text::parse(b"u::rw-,u:1000:r,g::x,o::-")?.expect("the text holds a list");
    /// let acl = parsed.with_computed_mask().resolve(|_| None, |_| None, Prefer::Name)?;
    /// assert_eq!(acl.mask(), Some(Perm::READ | Perm::EXECUTE));
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    #[must_use]
    pub fn with_computed_mask(mut self) -> Parsed {
        let (mask, named) = computed_mask(self.entries.iter().map(|entry| (entry.tag, entry.perm)));
        let mut held = false;
        for entry in &mut self.entries {
            if entry.tag == Tag::Mask {
                entry.perm = mask;
                held = true;
            }
        }
        if named && !held {
            // Room for the one entry, where `push` alone would double it.
            self.entries.reserve_exact(1);
            self.entries.push(TextEntry {
                tag: Tag::Mask,
                who: Who::Nobody,
                perm: mask,
            });
        }
        self
    }

    /// The [narrowing] of the list the text states, which needs no names. It
    /// keeps the owner's and other's entries, and the owning group's cut back
    /// by the mask.
    ///
    /// It is the list to give a file that cannot have the list at all, as on
    /// a filesystem that stores no lists. Where a name in the text has no
    /// answer, [`resolve_partial`](Self::resolve_partial) keeps everyone
    /// else's entries instead.
    ///
    /// ```
    /// use file_acl::text;
    ///
    /// let parsed = text::parse(b"u::rw-,u:nobody-here:rw-,g::rw-,m::r--,o::---")?
    ///     .expect("the text holds a list");
    /// assert_eq!(parsed.narrowed()?.mode_bits(), 0o640);
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    ///
    /// # Errors
    ///
    /// [`Invalid`] where the entries naming no one break a rule whatever the
    /// named entries stand for:
    ///
    /// - The owner's, owning group's or other's entry is missing or repeated.
    /// - The mask is repeated.
    /// - A named entry has no mask beside it.
    ///
    /// The named entries are not judged among themselves, since whether they
    /// are valid depends on whom their names stand for.
    ///
    /// [narrowing]: Acl::narrowed
    pub fn narrowed(&self) -> Result<Acl, Invalid> {
        Ok(self.objects()?.narrowed())
    }

    /// The entries naming no one, as a list, held to the rules that apply
    /// whatever the named entries stand for. Those include a mask wherever the
    /// text names someone.
    fn objects(&self) -> Result<Acl, Invalid> {
        let objects = self
            .entries
            .iter()
            .filter(|entry| entry.who == Who::Nobody)
            .map(|entry| Entry::new(Qualifier::new(entry.tag, UNDEFINED_ID), entry.perm))
            .collect();
        let objects = Acl::new(objects)?;
        let named = self.entries.iter().any(|entry| entry.who != Who::Nobody);
        if named && objects.mask().is_none() {
            return Err(Invalid::Missing { tag: Tag::Mask });
        }
        Ok(objects)
    }
}

impl TextEntry {
    /// The id the entry stands for, or the name where it stands for none:
    ///
    /// - [`UNDEFINED_ID`] for an entry naming no one.
    /// - Its id, for an entry naming an id.
    /// - For a name, the id `user` or `group` gives it or the one recorded
    ///   beside it, as `prefer` orders them.
    /// - The name, for a name with neither.
    fn id(
        &self,
        user: &mut impl FnMut(&[u8]) -> Option<u32>,
        group: &mut impl FnMut(&[u8]) -> Option<u32>,
        prefer: Prefer,
    ) -> Result<u32, &[u8]> {
        match &self.who {
            Who::Nobody => Ok(UNDEFINED_ID),
            Who::Id(id) => Ok(*id),
            Who::Name {
                recorded: Some(id), ..
            } if prefer == Prefer::Id => Ok(*id),
            Who::Name { name, recorded } => {
                let answer = if self.tag == Tag::User {
                    user(name)
                } else {
                    group(name)
                };
                answer.or(*recorded).ok_or(name)
            }
        }
    }
}

/// Why a text states no list: the first fault in it, and the byte offset
/// it is found at.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
#[non_exhaustive]
pub enum ParseError {
    /// The text holds a NUL byte, which ends a text for libacl.
    Nul {
        /// The offset of the NUL.
        at: usize,
    },
    /// A comment comes before the first entry.
    LeadingComment {
        /// The offset of the `#`.
        at: usize,
    },
    /// A comment that ends its line is followed by another comment, or by
    /// blanks and line ends alone, rather than by an entry.
    Comment {
        /// The offset of the comment's `#`.
        at: usize,
    },
    /// The text, not empty, holds no entry: only blanks and line ends.
    NoEntry,
    /// An entry does not begin with a tag and a colon. Its tag is none of the
    /// text form's, or is followed by anything but a colon, or the entry is
    /// empty, as between two commas.
    Tag {
        /// The offset the entry begins at.
        at: usize,
    },
    /// A user or group entry ends before its permissions: its qualifier
    /// runs into a comma or the end of the text.
    Incomplete {
        /// The offset the qualifier ends at.
        at: usize,
    },
    /// A qualifier begins with `#`.
    Qualifier {
        /// The offset of the qualifier.
        at: usize,
    },
    /// A name holds a line end or a carriage return, which a text spells
    /// as `\012` and `\015`.
    LineEnd {
        /// The offset of the line end or carriage return.
        at: usize,
    },
    /// An escape in a qualifier gives a NUL, or a value past a byte.
    Escape {
        /// The offset of the escape's backslash.
        at: usize,
    },
    /// A qualifier libacl reads as a number, written otherwise than as
    /// decimal digits with no leading zero, or past the range of an id. A
    /// binary number (`0b1`) is one too, though only libacl built against
    /// glibc 2.38 or later reads it as a number.
    Number {
        /// The offset of the qualifier.
        at: usize,
    },
    /// The permissions are not one to three of `r`, `w`, `x` and `-`, with
    /// each of `r`, `w` and `x` at most once.
    Perm {
        /// The offset of the permission field.
        at: usize,
    },
    /// The fourth field is not a decimal id short of [`UNDEFINED_ID`], or is
    /// on an entry that names no one.
    ///
    /// A mask's or other's entry may leave out its empty qualifier field, so
    /// the field after its tag's colon is its permissions. `mask:x:rwx` is
    /// therefore read as the permissions `x` and a fourth field `rwx`, and
    /// refused here.
    Id {
        /// The offset of the field.
        at: usize,
    },
    /// The fourth field states an id other than the one its entry's
    /// qualifier names.
    IdMismatch {
        /// The offset of the field.
        at: usize,
    },
    /// An entry is followed by something other than blanks and then a
    /// comma, a line end, a comment or the end of the text.
    Separator {
        /// The offset of what follows.
        at: usize,
    },
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ParseError::Nul { at } => write!(f, "the text holds a NUL at byte {at}"),
            ParseError::LeadingComment { at } => {
                write!(f, "the comment at byte {at} comes before the first entry")
            }
            ParseError::Comment { at } => write!(
                f,
                "the comment at byte {at} is followed by another comment or by blank lines alone"
            ),
            ParseError::NoEntry => f.write_str("the text holds no entry"),
            ParseError::Tag { at } => {
                write!(
                    f,
                    "the entry at byte {at} does not begin with a tag and a colon"
                )
            }
            ParseError::Incomplete { at } => {
                write!(f, "the entry ends at byte {at}, before its permissions")
            }
            ParseError::Qualifier { at } => {
                write!(f, "the qualifier at byte {at} begins with #")
            }
            ParseError::LineEnd { at } => {
                write!(
                    f,
                    "the name holds a line end or carriage return at byte {at}"
                )
            }
            ParseError::Escape { at } => {
                write!(f, "the escape at byte {at} gives a NUL or more than a byte")
            }
            ParseError::Number { at } => write!(
                f,
                "the qualifier at byte {at} is a number in another form than a decimal id"
            ),
            ParseError::Perm { at } => write!(
                f,
                "the permissions at byte {at} are not one to three of r, w, x and -"
            ),
            ParseError::Id { at } => write!(
                f,
                "the field at byte {at}, after the permissions, is not a decimal id, \
                 or is on an entry naming no one"
            ),
            ParseError::IdMismatch { at } => write!(
                f,
                "the id field at byte {at} states another id than its entry names"
            ),
            ParseError::Separator { at } => write!(
                f,
                "an entry is followed at byte {at} by something other than a separator"
            ),
        }
    }
}

impl core::error::Error for ParseError {}

/// Why a parsed text gives no list.
#[derive(Clone, PartialEq, Eq, Hash, Debug)]
#[non_exhaustive]
pub enum ResolveError {
    /// A name has no answer from the caller's lookup, and no recorded id to
    /// fall back on.
    Unresolved {
        /// [`Tag::User`] or [`Tag::Group`].
        tag: Tag,
        /// The name, its escapes decoded.
        name: Vec<u8>,
    },
    /// The entries make no valid list once their names stand for ids.
    Invalid(Invalid),
}

impl From<Invalid> for ResolveError {
    fn from(invalid: Invalid) -> ResolveError {
        ResolveError::Invalid(invalid)
    }
}

impl fmt::Display for ResolveError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ResolveError::Unresolved { tag, name } => {
                let kind = if *tag == Tag::User { "user" } else { "group" };
                write!(f, "the {kind} named \"")?;
                for chunk in name.utf8_chunks() {
                    write!(f, "{}", chunk.valid().escape_debug())?;
                    for byte in chunk.invalid() {
                        write!(f, "\\x{byte:02x}")?;
                    }
                }
                f.write_str("\" has no id")
            }
            ResolveError::Invalid(invalid) => invalid.fmt(f),
        }
    }
}

impl core::error::Error for ResolveError {}

/// How [`write()`] and [`write_named`] spell a list.
///
/// ```
/// use file_acl::text::{self, Names, Separator, Spelling, Tags};
/// use file_acl::Acl;
///
/// let acl = Acl::from_mode(0o640);
/// assert_eq!(text::write(&acl, Spelling::GNU_TAR), b"user::rw-\ngroup::r--\nother::---\n");
/// let compact = Spelling::new(Tags::Short, Separator::Comma, Names::Alone);
/// assert_eq!(text::write(&acl, compact), b"u::rw-,g::r--,o::---");
/// ```
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
#[non_exhaustive]
pub struct Spelling {
    /// The tags' spelling.
    pub tags: Tags,
    /// What separates the entries.
    pub separator: Separator,
    /// What an entry written by name holds.
    pub names: Names,
}

impl Spelling {
    /// GNU tar's spelling of its `SCHILY.acl.*` records, and `getfacl`'s:
    /// long tags, one entry per line, each line ended, and a name alone.
    pub const GNU_TAR: Spelling = Spelling::new(Tags::Long, Separator::Newline, Names::Alone);

    /// star's spelling of its `SCHILY.acl.*` records, which libarchive
    /// (bsdtar) writes too: long tags, a comma between entries, and each name
    /// followed by its id. Names are escaped as in
    /// [`GNU_TAR`](Self::GNU_TAR).
    ///
    /// Text in this spelling is read as the list by three readers:
    ///
    /// - star takes the name where the reader's system has it, and the id
    ///   where it does not.
    /// - GNU tar drops the id and resolves the name.
    /// - libarchive resolves the name, and falls back on the id where a name
    ///   has no answer or needs escaping.
    ///
    /// libacl refuses it, since it reads no fourth field.
    ///
    /// It differs from what star and libarchive write themselves where that
    /// would not be read so. star records no id after a name it escapes, and
    /// writes `#`, DEL and other control bytes as they are. libarchive
    /// escapes no name. Both write a name of digits as it is, which readers
    /// take as an id, where this spelling writes the id.
    ///
    /// ```
    /// use file_acl::text::{self, Prefer, Spelling};
    /// use file_acl::{Acl, Entry, Perm, Qualifier};
    ///
    /// let acl = Acl::new(vec![
    ///     Entry::new(Qualifier::UserObj, Perm::READ | Perm::WRITE),
    ///     Entry::new(Qualifier::User(1000), Perm::READ),
    ///     Entry::new(Qualifier::GroupObj, Perm::READ),
    ///     Entry::new(Qualifier::Mask, Perm::READ),
    ///     Entry::new(Qualifier::Other, Perm::NONE),
    /// ])?;
    /// let names = |id: u32| (id == 1000).then_some("alice");
    /// let written = text::write_named(&acl, Spelling::STAR, names, |_| None::<&str>);
    /// assert_eq!(
    ///     written,
    ///     b"user::rw-,user:alice:r--:1000,group::r--,mask::r--,other::---"
    /// );
    ///
    /// // Where `alice` has no answer, the recorded id stands.
    /// let parsed = text::parse(&written)?.expect("the text holds a list");
    /// assert_eq!(parsed.resolve(|_| None, |_| None, Prefer::Name)?, acl);
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    pub const STAR: Spelling = Spelling::new(Tags::Long, Separator::Comma, Names::WithIds);

    /// The spelling with these tags, separator and named entries.
    #[must_use]
    pub const fn new(tags: Tags, separator: Separator, names: Names) -> Spelling {
        Spelling {
            tags,
            separator,
            names,
        }
    }
}

/// How a tag is spelled.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum Tags {
    /// `user`, `group`, `mask`, `other`.
    Long,
    /// `u`, `g`, `m`, `o`.
    Short,
}

/// What separates a list's entries.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum Separator {
    /// One entry per line, each line ended with `\n`, the last included.
    Newline,
    /// A comma between entries, and none after the last.
    Comma,
}

/// What an entry for a user or group written by name holds. An entry written
/// by id holds the id alone either way.
///
/// star reads the recorded ids only in [`Spelling::STAR`]'s form: long tags,
/// and commas between entries.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum Names {
    /// The name alone: `user:alice:rw-`.
    Alone,
    /// The name, and its id as a fourth field after the permissions:
    /// `user:alice:rw-:1000`.
    WithIds,
}

/// The text of `acl` in `spelling`, every user and group named by id.
///
/// [`parse`] reads it back as `acl`, and so does libacl.
#[must_use]
pub fn write(acl: &Acl, spelling: Spelling) -> Vec<u8> {
    write_named(acl, spelling, |_| None::<&[u8]>, |_| None::<&[u8]>)
}

/// The text of `acl` in `spelling`, each user and group named by the name
/// `user` or `group` gives its id. Where the lookup has no answer, the entry
/// is written by id.
///
/// GNU tar names users and groups the same way, by name where the writing
/// system has one. A name is written with each control byte, space, comma,
/// colon and `#` escaped as `\` and three octal digits. A backslash is
/// written as `\\`. The escapes keep the text's entries apart.
///
/// libacl escapes the same bytes but `#`, DEL and the control bytes other
/// than tab, line end and carriage return. GNU tar drops what follows a `#`
/// in its own records, so a name holding one is cut short there, and not in
/// this text.
///
/// Where `spelling` writes [`Names::WithIds`], each entry written by name is
/// followed by its id.
///
/// The id is written in place of a name the text could not say, or that a
/// reader could take for another id. Such a name is empty, holds a NUL, or is
/// one libacl would read as a number (`4242`, `0x10`, `0b1`). It is also a
/// name of digits alone (`08`), which libarchive reads as a decimal id where
/// its system lacks the name. The lookups are asked about the named entries
/// in canonical order.
///
/// [`parse`] and [`Parsed::resolve`], with lookups that give each name its
/// id, read the text back as `acl`. libacl reads it back as `acl` too, given
/// the same account database, where `spelling` writes [`Names::Alone`]. It
/// refuses a fourth field.
#[must_use]
pub fn write_named<U: AsRef<[u8]>, G: AsRef<[u8]>>(
    acl: &Acl,
    spelling: Spelling,
    mut user: impl FnMut(u32) -> Option<U>,
    mut group: impl FnMut(u32) -> Option<G>,
) -> Vec<u8> {
    let mut out = Vec::new();
    for (index, entry) in acl.entries().iter().enumerate() {
        if index > 0 && spelling.separator == Separator::Comma {
            out.push(b',');
        }
        let tag = entry.qualifier.tag();
        out.extend_from_slice(match (tag, spelling.tags) {
            (Tag::UserObj | Tag::User, Tags::Long) => b"user:".as_slice(),
            (Tag::GroupObj | Tag::Group, Tags::Long) => b"group:",
            (Tag::Mask, Tags::Long) => b"mask:",
            (Tag::Other, Tags::Long) => b"other:",
            (Tag::UserObj | Tag::User, Tags::Short) => b"u:",
            (Tag::GroupObj | Tag::Group, Tags::Short) => b"g:",
            (Tag::Mask, Tags::Short) => b"m:",
            (Tag::Other, Tags::Short) => b"o:",
        });
        let named = match entry.qualifier {
            Qualifier::User(id) => {
                write_qualifier(&mut out, id, user(id).as_ref().map(AsRef::as_ref)).then_some(id)
            }
            Qualifier::Group(id) => {
                write_qualifier(&mut out, id, group(id).as_ref().map(AsRef::as_ref)).then_some(id)
            }
            Qualifier::UserObj | Qualifier::GroupObj | Qualifier::Mask | Qualifier::Other => None,
        };
        out.push(b':');
        out.extend_from_slice(&entry.perm.letters());
        if let (Some(id), Names::WithIds) = (named, spelling.names) {
            out.push(b':');
            out.extend_from_slice(id.to_string().as_bytes());
        }
        if spelling.separator == Separator::Newline {
            out.push(b'\n');
        }
    }
    out
}

/// Writes a named entry's qualifier: `name`, escaped, where the text can say
/// it, and `id` otherwise. Whether it wrote the name.
fn write_qualifier(out: &mut Vec<u8>, id: u32, name: Option<&[u8]>) -> bool {
    // libarchive reads a name of digits alone, leading zeros included, as a
    // decimal id where its system lacks the name, though libacl reads `08`
    // as a name.
    let name = name.filter(|name| {
        !name.is_empty()
            && !name.contains(&0)
            && reading(name) == Reading::Name
            && !name.iter().all(u8::is_ascii_digit)
    });
    let Some(name) = name else {
        out.extend_from_slice(id.to_string().as_bytes());
        return false;
    };
    for &byte in name {
        match byte {
            b'\\' => out.extend_from_slice(b"\\\\"),
            0x00..=0x1f | 0x7f | b' ' | b',' | b':' | b'#' => {
                // `\` and the byte's three octal digits, the first its top
                // two bits.
                out.push(b'\\');
                for shift in [6, 3, 0] {
                    out.push(b'0' | (byte.checked_shr(shift).unwrap_or(0) & 0o7));
                }
            }
            _ => out.push(byte),
        }
    }
    true
}

/// How libacl reads a qualifier: as an id, as a number in a form the crate
/// does not read, or as a name.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Reading {
    /// Decimal digits with no leading zero, in the range of an id.
    Id(u32),
    /// A number to libacl in any other form, or past the range.
    Loose,
    /// Not a number: a name.
    Name,
}

/// How libacl reads the qualifier `qualifier`, its escapes decoded.
///
/// libacl reads a qualifier as a number where C's `strtol` (libacl 2.3) or
/// `strtoul` (libacl 2.4), in base 0, reads all of it. Either reads optional
/// whitespace and a sign, then `0x` and hexadecimal digits, `0` and octal
/// digits, or decimal digits. Built against glibc 2.38 or later, libacl
/// calls the C23 forms, which also read `0b` and binary digits.
///
/// Measured: `08`, `0x` and `0b` are names, `010` is 8, `0x10` is 16, `+5` is
/// 5 and ` 5` is 5. `0b101` is 5, or a name where libacl is built against an
/// earlier glibc. Only decimal digits with no whitespace, sign or leading
/// zero, in the range of an id, are read as an id here. A binary number is
/// [`Reading::Loose`] whichever glibc libacl was built against.
fn reading(qualifier: &[u8]) -> Reading {
    // The common case first: an id, which the rules below read as one too.
    if let Some(id) = decimal(qualifier) {
        return Reading::Id(id);
    }
    // C's `isspace`, which `strtol` and `strtoul` pass over first.
    let space = |byte: &u8| matches!(byte, b' ' | b'\t' | b'\n' | b'\x0b' | b'\x0c' | b'\r');
    let start = qualifier
        .iter()
        .position(|byte| !space(byte))
        .unwrap_or(qualifier.len());
    let body = qualifier
        .split_at_checked(start)
        .map_or(qualifier, |(_, body)| body);
    let body = body
        .strip_prefix(b"+")
        .or_else(|| body.strip_prefix(b"-"))
        .unwrap_or(body);
    // Whether `body` is all digits after a radix prefix, where the prefix
    // is followed by at least one digit; `None` where it is not.
    let prefixed = |lower: &[u8], upper: &[u8], digit: fn(&u8) -> bool| {
        body.strip_prefix(lower)
            .or_else(|| body.strip_prefix(upper))
            .filter(|digits| digits.first().is_some_and(digit))
            .map(|digits| digits.iter().all(digit))
    };
    let binary = |digit: &u8| matches!(digit, b'0' | b'1');
    let whole = prefixed(b"0x", b"0X", u8::is_ascii_hexdigit)
        .or_else(|| prefixed(b"0b", b"0B", binary))
        .unwrap_or_else(|| match body.first() {
            Some(b'0') => body.iter().all(|digit| matches!(digit, b'0'..=b'7')),
            Some(_) => body.iter().all(u8::is_ascii_digit),
            None => false,
        });
    if whole { Reading::Loose } else { Reading::Name }
}

/// The id `digits` spells as decimal digits with no leading zero, where it
/// fits in an id.
fn decimal(digits: &[u8]) -> Option<u32> {
    if digits.is_empty() || (digits.len() > 1 && digits.first() == Some(&b'0')) {
        return None;
    }
    digits.iter().try_fold(0u32, |id, &digit| {
        // An ASCII digit's value is its low four bits.
        let value = digit.is_ascii_digit().then_some(u32::from(digit & 0x0f))?;
        id.checked_mul(10)?.checked_add(value)
    })
}

/// A reading position in a text.
struct Cursor<'a> {
    /// The whole text, for offsets.
    text: &'a [u8],
    /// What is left to read.
    rest: &'a [u8],
}

impl<'a> Cursor<'a> {
    /// The offset of what is left to read.
    fn at(&self) -> usize {
        self.text.len().saturating_sub(self.rest.len())
    }

    fn peek(&self) -> Option<u8> {
        self.rest.first().copied()
    }

    fn bump(&mut self) {
        if let Some((_, rest)) = self.rest.split_first() {
            self.rest = rest;
        }
    }

    /// Reads `byte` where it comes next.
    fn eat(&mut self, byte: u8) -> bool {
        let next = self.peek() == Some(byte);
        if next {
            self.bump();
        }
        next
    }

    /// Reads the bytes that come next and meet `wanted`.
    fn take_while(&mut self, wanted: impl Fn(u8) -> bool) -> &'a [u8] {
        let end = self
            .rest
            .iter()
            .position(|&byte| !wanted(byte))
            .unwrap_or(self.rest.len());
        let (taken, rest) = self.rest.split_at_checked(end).unwrap_or((self.rest, &[]));
        self.rest = rest;
        taken
    }

    /// Reads spaces, tabs and carriage returns, which libacl passes over
    /// around entries.
    fn skip_blanks(&mut self) {
        self.take_while(|byte| matches!(byte, b' ' | b'\t' | b'\r'));
    }

    /// Reads blanks and line ends.
    fn skip_space(&mut self) {
        self.take_while(|byte| matches!(byte, b' ' | b'\t' | b'\r' | b'\n'));
    }

    /// Reads an entry, from its tag to the end of its permissions or its
    /// fourth field. A name is borrowed from the text, or from `decoded`
    /// where its escapes are decoded there.
    fn entry<'d>(&mut self, decoded: &'d mut Vec<u8>) -> Result<TextEntry<&'d [u8]>, ParseError>
    where
        'a: 'd,
    {
        let start = self.at();
        let (object, named) = match self.take_while(|byte| byte.is_ascii_lowercase()) {
            b"user" | b"u" => (Tag::UserObj, Some(Tag::User)),
            b"group" | b"g" => (Tag::GroupObj, Some(Tag::Group)),
            b"mask" | b"m" => (Tag::Mask, None),
            b"other" | b"o" => (Tag::Other, None),
            _ => return Err(ParseError::Tag { at: start }),
        };
        if !self.eat(b':') {
            return Err(ParseError::Tag { at: start });
        }
        let Some(named) = named else {
            // The mask's and other's empty qualifier field may be left out.
            self.eat(b':');
            let perm = self.perm()?;
            if self.peek() == Some(b':') {
                return Err(ParseError::Id { at: self.at() });
            }
            return Ok(TextEntry {
                tag: object,
                who: Who::Nobody,
                perm,
            });
        };
        let qualifier_at = self.at();
        let raw = self.take_while(|byte| !matches!(byte, b':' | b','));
        let who = qualifier(raw, qualifier_at, decoded)?;
        if !self.eat(b':') {
            return Err(ParseError::Incomplete { at: self.at() });
        }
        let perm = self.perm()?;
        let recorded = if self.eat(b':') {
            Some(self.id_field()?)
        } else {
            None
        };
        let (tag, who) = match (who, recorded) {
            (None, None) => (object, Who::Nobody),
            (None, Some((_, at))) => return Err(ParseError::Id { at }),
            (Some(Who::Id(id)), Some((recorded, at))) if recorded != id => {
                return Err(ParseError::IdMismatch { at });
            }
            (Some(Who::Name { name, .. }), recorded) => (
                named,
                Who::Name {
                    name,
                    recorded: recorded.map(|(id, _)| id),
                },
            ),
            (Some(who), _) => (named, who),
        };
        Ok(TextEntry { tag, who, perm })
    }

    /// Reads a permission field.
    fn perm(&mut self) -> Result<Perm, ParseError> {
        let at = self.at();
        let field = self.take_while(|byte| matches!(byte, b'r' | b'w' | b'x' | b'-'));
        let ended = matches!(
            self.peek(),
            None | Some(b':' | b',' | b'\n' | b' ' | b'\t' | b'\r' | b'#')
        );
        if field.is_empty() || field.len() > 3 || !ended {
            return Err(ParseError::Perm { at });
        }
        let mut perm = Perm::NONE;
        for letter in field {
            // A `-` grants nothing.
            let Some(&(granted, _)) = LETTERS.iter().find(|(_, spelled)| spelled == letter) else {
                continue;
            };
            if perm.contains(granted) {
                return Err(ParseError::Perm { at });
            }
            perm |= granted;
        }
        Ok(perm)
    }

    /// Reads a fourth field, after its colon: the id, and the field's offset.
    fn id_field(&mut self) -> Result<(u32, usize), ParseError> {
        let at = self.at();
        let digits = self.take_while(|byte| byte.is_ascii_digit());
        let ended = matches!(
            self.peek(),
            None | Some(b',' | b'\n' | b' ' | b'\t' | b'\r' | b'#')
        );
        match decimal(digits) {
            Some(id) if ended && id != UNDEFINED_ID => Ok((id, at)),
            _ => Err(ParseError::Id { at }),
        }
    }

    /// Reads what may follow an entry: blanks, and then a comma, a line end,
    /// a comment or the end of the text. After that come any blanks and line
    /// ends, and at most one comment.
    ///
    /// A comment ending its line is followed by another entry, after blanks
    /// and line ends. After such a comment, libacl refuses a second comment,
    /// or nothing but blanks and line ends.
    fn end_of_entry(&mut self) -> Result<(), ParseError> {
        self.skip_blanks();
        match self.peek() {
            None | Some(b'\n' | b'#') => {}
            Some(b',') => self.bump(),
            Some(_) => return Err(ParseError::Separator { at: self.at() }),
        }
        self.skip_space();
        if self.peek() != Some(b'#') {
            return Ok(());
        }
        let at = self.at();
        self.take_while(|byte| byte != b'\n');
        if self.peek().is_none() {
            return Ok(());
        }
        self.skip_space();
        match self.peek() {
            None | Some(b'#') => Err(ParseError::Comment { at }),
            Some(_) => Ok(()),
        }
    }
}

/// Whom a user or group entry's qualifier names: `None` where it is empty,
/// for the owner or the owning group. A name is borrowed from `raw` where it
/// holds no escape, and otherwise decoded into `decoded` and borrowed from it.
fn qualifier<'d>(
    raw: &'d [u8],
    at: usize,
    decoded: &'d mut Vec<u8>,
) -> Result<Option<Who<&'d [u8]>>, ParseError> {
    if raw.is_empty() {
        return Ok(None);
    }
    if raw.first() == Some(&b'#') {
        return Err(ParseError::Qualifier { at });
    }
    // libacl refuses a line end or a carriage return in a name but before
    // its first byte, where it keeps it; both are refused here. A number may
    // follow either, as `strtol` and `strtoul` pass over them, and is loose.
    let line_end = raw
        .iter()
        .position(|byte| matches!(byte, b'\n' | b'\r'))
        .map(|offset| at.saturating_add(offset));
    let name = if raw.contains(&b'\\') {
        unescape(raw, at, decoded).map_err(|error| match (error, line_end) {
            (ParseError::Escape { at: escape }, Some(end)) if end < escape => {
                ParseError::LineEnd { at: end }
            }
            (error, _) => error,
        })?;
        decoded.as_slice()
    } else {
        raw
    };
    match (reading(name), line_end) {
        (Reading::Id(id), _) => Ok(Some(Who::Id(id))),
        (Reading::Loose, _) => Err(ParseError::Number { at }),
        (Reading::Name, Some(end)) => Err(ParseError::LineEnd { at: end }),
        (Reading::Name, None) => Ok(Some(Who::Name {
            name,
            recorded: None,
        })),
    }
}

/// Writes `raw` with its escapes decoded into `decoded`, in place of what it
/// held: `\` and three octal digits as the byte they give, `\\` as one
/// backslash, and any other backslash as itself.
fn unescape(raw: &[u8], at: usize, decoded: &mut Vec<u8>) -> Result<(), ParseError> {
    decoded.clear();
    decoded.reserve(raw.len());
    let mut rest = raw;
    while let Some((&byte, after)) = rest.split_first() {
        if byte != b'\\' {
            decoded.push(byte);
            rest = after;
        } else if let Some(after) = after.strip_prefix(b"\\") {
            decoded.push(b'\\');
            rest = after;
        } else if let Some((digits, after)) = after
            .split_first_chunk::<3>()
            .filter(|(digits, _)| digits.iter().all(|digit| matches!(digit, b'0'..=b'7')))
        {
            // An octal digit's value is its low three bits. A value past a
            // byte overflows.
            let value = digits.iter().try_fold(0u8, |value, &digit| {
                value.checked_mul(8)?.checked_add(digit & 0o7)
            });
            match value {
                Some(value) if value != 0 => decoded.push(value),
                _ => {
                    let offset = raw.len().saturating_sub(rest.len());
                    return Err(ParseError::Escape {
                        at: at.saturating_add(offset),
                    });
                }
            }
            rest = after;
        } else {
            decoded.push(b'\\');
            rest = after;
        }
    }
    Ok(())
}

// What `parse` holds is private, so its bound is checked here rather than in
// `tests/`.
#[cfg(test)]
mod tests {
    use alloc::vec::Vec;

    use super::{Parsed, Who, parse};

    /// The room `parsed` holds its names in, in bytes.
    fn name_room(parsed: &Parsed) -> usize {
        parsed
            .entries
            .iter()
            .map(|entry| match &entry.who {
                Who::Name { name, .. } => name.capacity(),
                Who::Nobody | Who::Id(_) => 0,
            })
            .sum()
    }

    /// A text's entries are held with no room to spare, and its names in no
    /// more room than the text takes. What `parse` keeps is therefore one
    /// `TextEntry` per entry and at most the text's length again. That holds
    /// at every count, one just past a power of two among them.
    #[test]
    fn a_parsed_text_holds_its_entries_and_no_more() {
        let mut texts: Vec<Vec<u8>> = Vec::new();
        for count in [
            1, 2, 3, 4, 5, 7, 8, 9, 63, 64, 65, 1_000, 1_024, 1_025, 65_537,
        ] {
            texts.push(b"m:r,".repeat(count));
            let mut named = b"u::rw-\ng::r--\nm::rwx\no::---\n".to_vec();
            for at in 0..count {
                named.extend_from_slice(alloc::format!("u:n{at}\\072x:r--:{at}\n").as_bytes());
            }
            texts.push(named);
        }
        texts.push(b"  u::rw- #c\n\n g::r--,o::---,".to_vec());
        for text in &texts {
            let parsed = parse(text)
                .expect("the text parses")
                .expect("the text holds a list");
            assert_eq!(parsed.entries.capacity(), parsed.entries.len());
            assert!(name_room(&parsed) <= text.len());
        }
        let parsed = parse(b"u::rw-,u:1:r,g::r,o::-")
            .expect("the text parses")
            .expect("the text holds a list")
            .with_computed_mask();
        assert_eq!(parsed.entries.len(), 5);
        assert_eq!(parsed.entries.capacity(), parsed.entries.len());
    }
}
