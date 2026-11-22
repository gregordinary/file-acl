//! The text form: a list as libacl's `acl_from_text` reads it,
//! `getfacl --omit-header` prints it, and tar archives carry it in their
//! `SCHILY.acl.access` and `SCHILY.acl.default` records.
//!
//! A list's text is one entry per line or per comma: a tag, a qualifier and
//! the permissions, separated by colons, as `user:1000:rw-` or `u:1000:rw`.
//! The qualifier of a user or group entry names whom it is for, by id or by
//! name; the owner's, owning group's, mask's and other's entries leave it
//! empty.
//!
//! Reading a text is two steps, since a name means different users to
//! different systems: [`parse`] reads the text, names and all, and
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
//! as libacl does, but for the differences below.
//!
//! - Entries are separated by a comma or a line end (`\n`). Spaces, tabs and
//!   carriage returns may come before an entry and after one, so lines may end
//!   with `\r\n`. A comma may also follow the last entry.
//! - The tags are `user`, `group`, `mask` and `other`, or `u`, `g`, `m` and
//!   `o`, in lower case. The mask's and other's entries may leave out their
//!   empty qualifier field: `mask:rwx` is `mask::rwx`.
//! - The permissions are one to three of `r`, `w`, `x` and `-`, in any order,
//!   each letter at most once: `rw-`, `wr`, `-` and `--x` are all read.
//! - A qualifier of decimal digits is an id, never looked up as a name, and
//!   one libacl does not read as a number is a name. libacl 2.4 looks a
//!   qualifier of digits past the last id (`4294967295` and more) up as a
//!   name; [`parse`] reads `4294967295` as the undefined id, which
//!   [`Parsed::resolve`] finds invalid, and refuses more, as below. A name
//!   may hold any byte but a colon, a comma, a NUL, a line end and a carriage
//!   return, and may not begin with `#`. In it, `\` and three octal digits
//!   stand for the byte they give, and `\\` for one backslash; a backslash
//!   before anything else is itself.
//! - `#` begins a comment, which runs to the end of the line, wherever an
//!   entry has ended: after its permissions (as `getfacl` writes
//!   `#effective:` there), after the comma that ends it, or on a line of its
//!   own. As libacl reads them, a comment before the first entry is refused,
//!   at most one comment comes between two entries, and a comment that ends
//!   its line is followed by another entry: `u::rw- #c` ends a text, and
//!   `u::rw- #c\n` does not. So `getfacl`'s output is a list's text only
//!   with `--omit-header`, which leaves out its `# file:` comments, and for
//!   a directory with a default list, `--access`, which leaves out the
//!   `default:` entries.
//! - A user or group entry may hold a fourth field, the id of the user or
//!   group its qualifier names, as star and libarchive write it
//!   (`user:alice:rw-:1000`). On an entry naming an id, it must be that id.
//! - An empty text is no list: GNU tar writes an empty
//!   `SCHILY.acl.default` record for a directory with no default list. A
//!   text holding no entry but blanks or a comment is refused, as libacl
//!   refuses it.
//!
//! Where libacl is loose, [`parse`] refuses what libacl reads:
//!
//! - A qualifier libacl reads as a number in another form than decimal
//!   digits, as C's `strtoul` reads one: with a sign (`-1`, `+5`), in
//!   hexadecimal (`0x10`), with a leading zero, which libacl reads as octal
//!   (`010` is 8), or after leading whitespace; and a number past the range
//!   of an id, which libacl 2.3 wraps (`4294967296` is 0) and libacl 2.4
//!   looks up as a name.
//! - An escape that gives a NUL, or a value past a byte (`\400`), which
//!   libacl 2.3 reads as the end of the name; libacl 2.4 refuses `\000` and
//!   `\400`.
//! - Entries with no comma or line end between them (`u::rw- g::r--`, and
//!   even `u::rw-g::r--`), and a comma that does not follow an entry on its
//!   own line (`u::rw-\n,\ng::r--`).
//! - A tag not followed directly by its colon. libacl passes over blanks and
//!   line ends after a tag (`u ::rw-`), and after a mask's or other's tag
//!   over comments too; it reads their permissions with their colons, one,
//!   or none, blanks around them (`m: :rwx`, `o r--`, even `orwx`).
//! - A name beginning with a line end or a carriage return, which libacl
//!   reads as part of the name (`group:\nstaff:r--` names the group
//!   `\nstaff`). libacl refuses one later in a name, and so does [`parse`].
//! - A NUL byte, which ends the text for libacl.
//!
//! And [`parse`] reads the fourth field, which libacl refuses.
//!
//! The tests compare [`parse`] and [`Parsed::resolve`] with libacl, 2.3 or
//! 2.4, whichever is present: `tests/text.rs` holds every text libacl was
//! measured reading, with 2.4's reading where it differs, and reads a
//! generated corpus with libacl beside the crate, names resolved through the
//! same account database.
//!
//! # Other readers
//!
//! GNU tar reads its records with libacl, after dropping a fourth field; a
//! name it cannot resolve costs the whole list. libarchive (bsdtar) reads the
//! text with a reader of its own, which differs from libacl's: it decodes no
//! escape, looking a name up as the text spells it, and takes the recorded id
//! where the lookup has no answer; and it looks a qualifier of digits up as a
//! name before reading it as an id. star reads a fourth field only in
//! [`Spelling::STAR`]'s form (long tags, and commas with no blanks after
//! them), taking the name where the reader's system has it and the id where it
//! does not, and refuses a text holding a `#`, a comment's included. So a name
//! that needs escaping is read by all three only in [`Spelling::STAR`], which
//! records each name's id: GNU tar resolves the name, libarchive falls back on
//! the id, and star does either. `tests/tar.rs` extracts text written in each
//! spelling with GNU tar and bsdtar.

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
/// may come in any order, and the list it states is judged by
/// [`Parsed::resolve`], once its names stand for ids: a text that parses
/// may still state no valid list.
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
    if let Some(at) = text.iter().position(|&byte| byte == 0) {
        return Err(ParseError::Nul { at });
    }
    let mut cursor = Cursor { text, rest: text };
    let mut entries = Vec::new();
    loop {
        cursor.skip_space();
        match cursor.peek() {
            None => break,
            // `end_of_entry` reads every comment after the first entry.
            Some(b'#') => return Err(ParseError::LeadingComment { at: cursor.at() }),
            Some(_) => {
                entries.push(cursor.entry()?);
                cursor.end_of_entry()?;
            }
        }
    }
    if entries.is_empty() {
        Err(ParseError::NoEntry)
    } else {
        Ok(Some(Parsed { entries }))
    }
}

/// A list's text, read: its entries as the text states them, before its
/// names stand for ids.
#[derive(Clone, PartialEq, Eq, Hash, Debug)]
pub struct Parsed {
    /// The entries, in the order the text gives them.
    entries: Vec<TextEntry>,
}

/// One entry of a list's text.
#[derive(Clone, PartialEq, Eq, Hash, Debug)]
struct TextEntry {
    /// The entry's tag: [`Tag::User`] or [`Tag::Group`] where `who` names
    /// someone, and otherwise the tag of an entry naming no one.
    tag: Tag,
    who: Who,
    perm: Perm,
}

/// Whom an entry is for, as its text says.
#[derive(Clone, PartialEq, Eq, Hash, Debug)]
enum Who {
    /// The owner, the owning group, the mask or other.
    Nobody,
    /// The user or group with this id.
    Id(u32),
    /// The user or group with this name, its escapes decoded, and the id a
    /// fourth field records beside it, where it has one.
    Name {
        name: Vec<u8>,
        recorded: Option<u32>,
    },
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
    /// The lookups are asked in the order the text gives its entries, and no
    /// further once one has no answer. A name is passed as the text holds it,
    /// its escapes decoded; an entry naming an id asks neither. Where an
    /// entry holds both a name and, in a fourth field, an id, `prefer` says
    /// which it is given.
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
    /// [`ResolveError::Unresolved`] naming the first name, in the text's
    /// order, that has no answer and no recorded id to fall back on; and
    /// [`ResolveError::Invalid`] where the entries make no valid list, as
    /// [`Acl::new`] names it, once their names stand for ids.
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
    /// may name users and groups, as [`Acl::names_anyone`] says.
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
    /// [`resolve`](Self::resolve) reads it, and each entry naming someone
    /// with no answer and no recorded id left out.
    ///
    /// Leaving an entry out takes nothing from anyone the lookups answer
    /// for: each keeps what the list granted them, and the mask, which bounds
    /// the owning group and every named entry, is kept. The entry left out
    /// granted or denied something to someone the caller's system has no
    /// account for. [`narrowed`](Self::narrowed) is the answer for a list
    /// that cannot be given at all, and gives a named user or group what
    /// their class is granted, which can be more than the list granted them.
    ///
    /// The lookups are asked about every name, in the text's order, save a
    /// name with a recorded id under [`Prefer::Id`]. Whether two entries left
    /// out name the same user is not judged, since neither stands for an id.
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
    /// [`Invalid`] where the entries make no valid list: where the entries
    /// naming no one break a rule whatever the named entries stand for, as
    /// [`narrowed`](Self::narrowed) judges them, and otherwise where the
    /// entries given make none once their names stand for ids, as
    /// [`Acl::new`] names it.
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

    /// The text's entries with the mask `setfacl` computes, as
    /// [`Acl::with_computed_mask`] computes it: the union of what the owning
    /// group's entry and every named entry grant, replacing any mask the
    /// text states, and added where it names someone and states none.
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
            self.entries.push(TextEntry {
                tag: Tag::Mask,
                who: Who::Nobody,
                perm: mask,
            });
        }
        self
    }

    /// The [narrowing](Acl::narrowed) of the list the text states, which
    /// needs no names: the owner's and other's entries, and the owning
    /// group's cut back by the mask.
    ///
    /// It is the list to give a file that cannot carry the list at all, as on
    /// a filesystem that holds no lists. Where a name in the text has no
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
    /// named entries stand for: the owner's, owning group's or other's entry
    /// missing or repeated, the mask repeated, or no mask beside a named
    /// entry. Whether the named entries are valid among themselves depends on
    /// whom their names stand for, and is not judged.
    pub fn narrowed(&self) -> Result<Acl, Invalid> {
        Ok(self.objects()?.narrowed())
    }

    /// The entries naming no one, as a list, held to the rules they keep
    /// whatever the named entries stand for: a mask wherever the text names
    /// someone.
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
    /// The id the entry stands for: [`UNDEFINED_ID`] for an entry naming no
    /// one, its id, or for a name the id `user` or `group` gives it or the
    /// one recorded beside it, as `prefer` orders them. The name, for a name
    /// with neither.
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
    /// An entry does not begin with a tag and a colon: the tag is none of
    /// the text form's, or is followed by anything but a colon, or the entry
    /// is empty, as between two commas.
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
    /// decimal digits with no leading zero, or past the range of an id.
    Number {
        /// The offset of the qualifier.
        at: usize,
    },
    /// The permissions are not one to three of `r`, `w`, `x` and `-`, each
    /// letter at most once.
    Perm {
        /// The offset of the permission field.
        at: usize,
    },
    /// The fourth field is not a decimal id short of [`UNDEFINED_ID`], or is
    /// on an entry that names no one.
    ///
    /// A mask's or other's entry may leave out its empty qualifier field, so
    /// the field after its tag's colon is its permissions: `mask:x:rwx` is
    /// read as the permissions `x` and a fourth field `rwx`, and refused here.
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
    /// Text in this spelling is read as the list by star, which takes the
    /// name where the reader's system has it and the id where it does not;
    /// by GNU tar, which drops the id and resolves the name; and by
    /// libarchive, which resolves the name and falls back on the id, where a
    /// name has no answer or needs escaping. libacl refuses it, since it
    /// reads no fourth field.
    ///
    /// It differs from what star and libarchive write themselves where that
    /// would not be read so. star records no id after a name it escapes, and
    /// writes `#`, DEL and other control bytes as they are; libarchive
    /// escapes no name. Both write a name of digits as it is, which readers
    /// take as an id; this spelling writes the id.
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
/// `user` or `group` gives its id, and by its id where that has no answer.
///
/// This is how GNU tar names them: by name where the writing system has
/// one. A name is written with each control byte, space, comma, colon and
/// `#` escaped as `\` and three octal digits, and a backslash as `\\`, so
/// that the text holds its entries apart; libacl escapes the same bytes but
/// `#`, DEL and the control bytes other than tab, line end and carriage
/// return. GNU tar drops what follows a `#` in its own records, so a name
/// holding one is cut short in them, and not in this text.
///
/// Where `spelling` writes [`Names::WithIds`], each entry written by name is
/// followed by its id.
///
/// A name is not written, and the id is, where the text could not say it: a
/// name that is empty, holds a NUL, or would be read as a number (`4242`,
/// `0x10`), since an all-digit qualifier is read as an id before any name.
/// The lookups are asked about the named entries in canonical order.
///
/// [`parse`] and [`Parsed::resolve`], with lookups that give each name its
/// id, read the text back as `acl`. So does libacl, given the same account
/// database, where `spelling` writes [`Names::Alone`]: it refuses a fourth
/// field.
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
    let name = name
        .filter(|name| !name.is_empty() && !name.contains(&0) && reading(name) == Reading::Name);
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
/// libacl reads a qualifier as a number where C's `strtoul`, in base 0,
/// reads all of it: after optional whitespace and a sign, `0x` and
/// hexadecimal digits, `0` and octal digits, or decimal digits (measured: `08`
/// and `0x` are names, `010` is 8, `0x10` is 16, `+5` is 5 and ` 5` is 5).
/// Only the first form, as plain decimal digits, is read as an id here.
fn reading(qualifier: &[u8]) -> Reading {
    // C's `isspace`, which `strtoul` passes over first.
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
    let hex = body
        .strip_prefix(b"0x")
        .or_else(|| body.strip_prefix(b"0X"))
        .filter(|digits| digits.first().is_some_and(u8::is_ascii_hexdigit));
    let whole = match (hex, body.first()) {
        (Some(digits), _) => digits.iter().all(u8::is_ascii_hexdigit),
        (None, Some(b'0')) => body.iter().all(|digit| matches!(digit, b'0'..=b'7')),
        (None, Some(_)) => body.iter().all(u8::is_ascii_digit),
        (None, None) => false,
    };
    if !whole {
        return Reading::Name;
    }
    decimal(qualifier).map_or(Reading::Loose, Reading::Id)
}

/// The id `digits` spells as decimal digits with no leading zero, where it
/// fits in an id.
fn decimal(digits: &[u8]) -> Option<u32> {
    let plain = !digits.is_empty()
        && digits.iter().all(u8::is_ascii_digit)
        && (digits.len() == 1 || digits.first() != Some(&b'0'));
    if !plain {
        return None;
    }
    core::str::from_utf8(digits).ok()?.parse().ok()
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
    /// fourth field.
    fn entry(&mut self) -> Result<TextEntry, ParseError> {
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
        let who = qualifier(raw, qualifier_at)?;
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
    /// a comment or the end of the text; then any blanks and line ends, and
    /// at most one comment.
    ///
    /// A comment ending its line is followed by another entry, after blanks
    /// and line ends: libacl refuses a second comment, or nothing but blanks
    /// and line ends, after one.
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
/// for the owner or the owning group.
fn qualifier(raw: &[u8], at: usize) -> Result<Option<Who>, ParseError> {
    if raw.is_empty() {
        return Ok(None);
    }
    if raw.first() == Some(&b'#') {
        return Err(ParseError::Qualifier { at });
    }
    // libacl refuses a line end or a carriage return in a name but before
    // its first byte, where it keeps it; both are refused here. A number may
    // follow either, as `strtoul` passes over them, and is loose.
    let line_end = raw
        .iter()
        .position(|byte| matches!(byte, b'\n' | b'\r'))
        .map(|offset| at.saturating_add(offset));
    let decoded = unescape(raw, at).map_err(|error| match (error, line_end) {
        (ParseError::Escape { at: escape }, Some(end)) if end < escape => {
            ParseError::LineEnd { at: end }
        }
        (error, _) => error,
    })?;
    match (reading(&decoded), line_end) {
        (Reading::Id(id), _) => Ok(Some(Who::Id(id))),
        (Reading::Loose, _) => Err(ParseError::Number { at }),
        (Reading::Name, Some(end)) => Err(ParseError::LineEnd { at: end }),
        (Reading::Name, None) => Ok(Some(Who::Name {
            name: decoded,
            recorded: None,
        })),
    }
}

/// `raw` with its escapes decoded: `\` and three octal digits as the byte
/// they give, `\\` as one backslash, and any other backslash as itself.
fn unescape(raw: &[u8], at: usize) -> Result<Vec<u8>, ParseError> {
    let mut decoded = Vec::with_capacity(raw.len());
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
            let value = core::str::from_utf8(digits)
                .ok()
                .and_then(|digits| u8::from_str_radix(digits, 8).ok());
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
    Ok(decoded)
}
