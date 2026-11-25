//! The model: an access control list, its entries, and the rules a valid one
//! keeps.

use alloc::vec::Vec;
use core::fmt::{self, Write as _};
use core::ops::{BitAnd, BitAndAssign, BitOr, BitOrAssign};

/// The id an entry has where it names no particular user or group
/// (`ACL_UNDEFINED_ID`).
///
/// The binary form writes it in the id field of the owner, owning group, mask
/// and other entries. A named entry never has it: the kernel refuses such a
/// list. A process in a user namespace reads it as the id of a named entry
/// whose id its namespace does not map.
pub const UNDEFINED_ID: u32 = u32::MAX;

/// The kind of an entry, as POSIX.1e defines them.
///
/// The order of the variants is the order a list holds its entries in, which
/// is the order `Ord` gives.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub enum Tag {
    /// The file's owner (`ACL_USER_OBJ`).
    UserObj,
    /// A user named by id (`ACL_USER`).
    User,
    /// The file's owning group (`ACL_GROUP_OBJ`).
    GroupObj,
    /// A group named by id (`ACL_GROUP`).
    Group,
    /// The mask (`ACL_MASK`): the most a named entry or the owning group is
    /// granted.
    Mask,
    /// Everyone else (`ACL_OTHER`).
    Other,
}

impl Tag {
    /// The value the binary form stores for this tag.
    #[must_use]
    pub const fn to_raw(self) -> u16 {
        match self {
            Tag::UserObj => 0x01,
            Tag::User => 0x02,
            Tag::GroupObj => 0x04,
            Tag::Group => 0x08,
            Tag::Mask => 0x10,
            Tag::Other => 0x20,
        }
    }

    /// The tag `raw` stores, or `None` for a value POSIX.1e defines no tag
    /// for.
    #[must_use]
    pub const fn from_raw(raw: u16) -> Option<Tag> {
        Some(match raw {
            0x01 => Tag::UserObj,
            0x02 => Tag::User,
            0x04 => Tag::GroupObj,
            0x08 => Tag::Group,
            0x10 => Tag::Mask,
            0x20 => Tag::Other,
            _ => return None,
        })
    }

    /// Whether an entry with this tag names a user or group by id.
    #[must_use]
    pub const fn is_named(self) -> bool {
        matches!(self, Tag::User | Tag::Group)
    }
}

impl fmt::Display for Tag {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Tag::UserObj => "owner",
            Tag::User => "named user",
            Tag::GroupObj => "owning group",
            Tag::Group => "named group",
            Tag::Mask => "mask",
            Tag::Other => "other",
        })
    }
}

/// Whom an entry is for: its tag, and the id of the user or group a named
/// entry names.
///
/// The order `Ord` gives is the order a list holds its entries in: by tag,
/// and named users, and named groups, by ascending id.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub enum Qualifier {
    /// The file's owner.
    UserObj,
    /// The user with this id.
    User(u32),
    /// The file's owning group.
    GroupObj,
    /// The group with this id.
    Group(u32),
    /// The mask.
    Mask,
    /// Everyone else.
    Other,
}

impl Qualifier {
    /// The qualifier of an entry with `tag`, naming `id` where the tag names
    /// someone. `id` is ignored for the other tags, as the kernel ignores the
    /// id field of their entries.
    #[must_use]
    pub const fn new(tag: Tag, id: u32) -> Qualifier {
        match tag {
            Tag::UserObj => Qualifier::UserObj,
            Tag::User => Qualifier::User(id),
            Tag::GroupObj => Qualifier::GroupObj,
            Tag::Group => Qualifier::Group(id),
            Tag::Mask => Qualifier::Mask,
            Tag::Other => Qualifier::Other,
        }
    }

    /// The qualifier's tag.
    #[must_use]
    pub const fn tag(self) -> Tag {
        match self {
            Qualifier::UserObj => Tag::UserObj,
            Qualifier::User(_) => Tag::User,
            Qualifier::GroupObj => Tag::GroupObj,
            Qualifier::Group(_) => Tag::Group,
            Qualifier::Mask => Tag::Mask,
            Qualifier::Other => Tag::Other,
        }
    }

    /// The id of the user or group a named entry names, `None` for the
    /// others.
    #[must_use]
    pub const fn id(self) -> Option<u32> {
        match self {
            Qualifier::User(id) | Qualifier::Group(id) => Some(id),
            _ => None,
        }
    }
}

impl fmt::Display for Qualifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Qualifier::User(id) => write!(f, "user {id}"),
            Qualifier::Group(id) => write!(f, "group {id}"),
            other => other.tag().fmt(f),
        }
    }
}

/// The permissions an entry grants: any of read, write and execute.
///
/// A `Perm` holds no other bit, so a list's permissions are valid once they
/// are `Perm`s. It displays as the text form spells it, `rw-`.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct Perm(u16);

impl Perm {
    /// No permission.
    pub const NONE: Perm = Perm(0);
    /// Read (`ACL_READ`).
    pub const READ: Perm = Perm(0o4);
    /// Write (`ACL_WRITE`).
    pub const WRITE: Perm = Perm(0o2);
    /// Execute, or search for a directory (`ACL_EXECUTE`).
    pub const EXECUTE: Perm = Perm(0o1);
    /// Read, write and execute.
    pub const ALL: Perm = Perm(0o7);

    /// The permissions `bits` holds, as the binary form stores them, or
    /// `None` where it holds a bit other than the three.
    #[must_use]
    pub const fn from_bits(bits: u16) -> Option<Perm> {
        if bits & !Perm::ALL.0 == 0 {
            Some(Perm(bits))
        } else {
            None
        }
    }

    /// The permissions as the binary form stores them: read `4`, write `2`,
    /// execute `1`.
    #[must_use]
    pub const fn bits(self) -> u16 {
        self.0
    }

    /// Whether every permission in `other` is in `self`.
    #[must_use]
    pub const fn contains(self, other: Perm) -> bool {
        self.0 & other.0 == other.0
    }

    /// The permissions in either.
    #[must_use]
    pub const fn union(self, other: Perm) -> Perm {
        Perm(self.0 | other.0)
    }

    /// The permissions in both.
    #[must_use]
    pub const fn intersection(self, other: Perm) -> Perm {
        Perm(self.0 & other.0)
    }

    /// The permissions as the text form spells them, `rw-`: read, write
    /// and execute, in that order, each as its letter or `-`.
    pub(crate) fn letters(self) -> [u8; 3] {
        let mut letters = *b"---";
        for (slot, (perm, letter)) in letters.iter_mut().zip(LETTERS) {
            if self.contains(perm) {
                *slot = letter;
            }
        }
        letters
    }
}

/// Each permission and the letter the text form spells it with, in the
/// order it spells them.
pub(crate) const LETTERS: [(Perm, u8); 3] = [
    (Perm::READ, b'r'),
    (Perm::WRITE, b'w'),
    (Perm::EXECUTE, b'x'),
];

impl BitOr for Perm {
    type Output = Perm;
    fn bitor(self, other: Perm) -> Perm {
        self.union(other)
    }
}

impl BitOrAssign for Perm {
    fn bitor_assign(&mut self, other: Perm) {
        *self = self.union(other);
    }
}

impl BitAnd for Perm {
    type Output = Perm;
    fn bitand(self, other: Perm) -> Perm {
        self.intersection(other)
    }
}

impl BitAndAssign for Perm {
    fn bitand_assign(&mut self, other: Perm) {
        *self = self.intersection(other);
    }
}

impl fmt::Display for Perm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for letter in self.letters() {
            f.write_char(char::from(letter))?;
        }
        Ok(())
    }
}

impl fmt::Debug for Perm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Perm({self})")
    }
}

/// One entry of a list: whom it is for, and what it grants them.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct Entry {
    /// Whom the entry is for.
    pub qualifier: Qualifier,
    /// What it grants them.
    pub perm: Perm,
}

impl Entry {
    /// The entry granting `perm` to `qualifier`.
    #[must_use]
    pub const fn new(qualifier: Qualifier, perm: Perm) -> Entry {
        Entry { qualifier, perm }
    }
}

/// A POSIX.1e access control list, valid and in canonical order.
///
/// A list is valid when the kernel accepts it and libacl's checker
/// (`acl_check`) passes it. A valid list holds exactly one owner, owning
/// group and other entry, and at most one mask. It has a mask wherever it
/// names a user or group. It names no user or group twice, and no named
/// entry has [`UNDEFINED_ID`] as its id.
///
/// A list holds its entries in the order the kernel requires and libacl
/// writes. The order is the owner, named users by ascending id, the owning
/// group, named groups by ascending id, the mask, then other.
///
/// An `Acl` cannot name the same user twice, though the kernel stores such a
/// list: libacl's checker refuses it, and no tool writes one.
#[derive(Clone, PartialEq, Eq, Hash, Debug)]
pub struct Acl {
    entries: Vec<Entry>,
    owner: Perm,
    owning_group: Perm,
    mask: Option<Perm>,
    other: Perm,
}

impl Acl {
    /// The list of `entries`, in any order, put in canonical order.
    ///
    /// A list can hold more entries than
    /// [`xattr::MAX_ENTRIES`](crate::xattr::MAX_ENTRIES), which the kernel
    /// refuses to set. A caller that sets the list compares its length first,
    /// as [`xattr::encode`](crate::xattr::encode) says.
    ///
    /// # Errors
    ///
    /// [`Invalid`] naming the first rule the entries break, found in this
    /// order:
    ///
    /// - The first entry, in canonical order, that repeats another or names
    ///   the undefined id.
    /// - The first required entry missing: the owner's, the owning group's,
    ///   other's, then the mask a named entry requires.
    pub fn new(mut entries: Vec<Entry>) -> Result<Acl, Invalid> {
        entries.sort_unstable_by_key(|entry| entry.qualifier);
        let mut owner = None;
        let mut owning_group = None;
        let mut mask = None;
        let mut other = None;
        let mut named = false;
        let mut previous = None;
        for entry in &entries {
            if previous == Some(entry.qualifier) {
                return Err(Invalid::Repeated {
                    qualifier: entry.qualifier,
                });
            }
            previous = Some(entry.qualifier);
            match entry.qualifier {
                Qualifier::UserObj => owner = Some(entry.perm),
                Qualifier::GroupObj => owning_group = Some(entry.perm),
                Qualifier::Mask => mask = Some(entry.perm),
                Qualifier::Other => other = Some(entry.perm),
                Qualifier::User(id) | Qualifier::Group(id) => {
                    if id == UNDEFINED_ID {
                        return Err(Invalid::UndefinedId {
                            tag: entry.qualifier.tag(),
                        });
                    }
                    named = true;
                }
            }
        }
        let missing = |tag| Invalid::Missing { tag };
        let owner = owner.ok_or(missing(Tag::UserObj))?;
        let owning_group = owning_group.ok_or(missing(Tag::GroupObj))?;
        let other = other.ok_or(missing(Tag::Other))?;
        if named && mask.is_none() {
            return Err(missing(Tag::Mask));
        }
        Ok(Acl {
            entries,
            owner,
            owning_group,
            mask,
            other,
        })
    }

    /// The minimal list granting these: the owner's, the owning group's and
    /// other's entries alone, which is always valid.
    pub(crate) fn minimal(owner: Perm, owning_group: Perm, other: Perm) -> Acl {
        Acl {
            entries: alloc::vec![
                Entry::new(Qualifier::UserObj, owner),
                Entry::new(Qualifier::GroupObj, owning_group),
                Entry::new(Qualifier::Other, other),
            ],
            owner,
            owning_group,
            mask: None,
            other,
        }
    }

    /// This list with its owner's, owning group's, mask's and other's
    /// entries granting these instead, its named entries as they are. It
    /// stays valid, since no entry's qualifier changes. `mask` is ignored
    /// where the list has none.
    pub(crate) fn with_object_perms(
        &self,
        owner: Perm,
        owning_group: Perm,
        mask: Perm,
        other: Perm,
    ) -> Acl {
        let entries = self
            .entries
            .iter()
            .map(|entry| {
                let perm = match entry.qualifier {
                    Qualifier::UserObj => owner,
                    Qualifier::GroupObj => owning_group,
                    Qualifier::Mask => mask,
                    Qualifier::Other => other,
                    Qualifier::User(_) | Qualifier::Group(_) => entry.perm,
                };
                Entry::new(entry.qualifier, perm)
            })
            .collect();
        Acl {
            entries,
            owner,
            owning_group,
            mask: self.mask.map(|_| mask),
            other,
        }
    }

    /// The entries, in canonical order.
    #[must_use]
    pub fn entries(&self) -> &[Entry] {
        &self.entries
    }

    /// The entries, in canonical order, to change and make a list of again.
    #[must_use]
    pub fn into_entries(self) -> Vec<Entry> {
        self.entries
    }

    /// What the list grants `qualifier`'s entry, `None` where it has none.
    #[must_use]
    pub fn perm(&self, qualifier: Qualifier) -> Option<Perm> {
        self.entries
            .binary_search_by_key(&qualifier, |entry| entry.qualifier)
            .ok()
            .and_then(|at| self.entries.get(at))
            .map(|entry| entry.perm)
    }

    /// What the owner's entry grants.
    #[must_use]
    pub fn owner(&self) -> Perm {
        self.owner
    }

    /// What the owning group's entry grants, before the mask.
    #[must_use]
    pub fn owning_group(&self) -> Perm {
        self.owning_group
    }

    /// The mask, where the list has one.
    #[must_use]
    pub fn mask(&self) -> Option<Perm> {
        self.mask
    }

    /// What the entry for everyone else grants.
    #[must_use]
    pub fn other(&self) -> Perm {
        self.other
    }

    /// Whether the list names a user or group.
    #[must_use]
    pub fn names_anyone(&self) -> bool {
        self.entries
            .iter()
            .any(|entry| entry.qualifier.tag().is_named())
    }
}

/// Why entries make no valid list: the rule they break.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
#[non_exhaustive]
pub enum Invalid {
    /// A required entry is absent: the owner's, the owning group's or
    /// other's, or the mask, where the list names a user or group.
    Missing {
        /// The tag of the entry that is absent.
        tag: Tag,
    },
    /// Two entries are for the same qualifier: the owner, the owning group,
    /// the mask or other twice, or the same user or group named twice.
    Repeated {
        /// Whom both entries are for.
        qualifier: Qualifier,
    },
    /// A named entry's id is [`UNDEFINED_ID`], which names no one.
    UndefinedId {
        /// [`Tag::User`] or [`Tag::Group`].
        tag: Tag,
    },
}

impl fmt::Display for Invalid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Invalid::Missing { tag: Tag::Mask } => {
                f.write_str("the list names a user or group but has no mask entry")
            }
            Invalid::Missing { tag: Tag::Other } => {
                f.write_str("the list has no entry for everyone else")
            }
            Invalid::Missing { tag } => write!(f, "the list has no {tag} entry"),
            Invalid::Repeated {
                qualifier: qualifier @ (Qualifier::User(_) | Qualifier::Group(_)),
            } => write!(f, "the list names {qualifier} twice"),
            Invalid::Repeated {
                qualifier: Qualifier::Other,
            } => f.write_str("the list has more than one entry for everyone else"),
            Invalid::Repeated { qualifier } => {
                write!(f, "the list has more than one {qualifier} entry")
            }
            Invalid::UndefinedId { tag } => {
                write!(f, "a {tag} entry has the undefined id {UNDEFINED_ID}")
            }
        }
    }
}

impl core::error::Error for Invalid {}
