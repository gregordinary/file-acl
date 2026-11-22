//! Id mapping: a list restated with its named entries' ids read through a
//! caller's translation, as from one user namespace to another.

use alloc::vec::Vec;
use core::fmt;

use crate::{Acl, Entry, Invalid, Qualifier, Tag};

impl Acl {
    /// The list with each named user's id read through `uid` and each named
    /// group's through `gid`, in canonical order.
    ///
    /// This is the restatement a list needs where the ids it names mean
    /// other users on the side it is carried to: across a user namespace's
    /// map, or from one system's accounts to another's. The kernel translates
    /// a list's ids itself when a process reads or sets it through a user
    /// namespace, but keeps the entries in the order they were stored, so the
    /// value it gives can name ids out of order; [`xattr::decode`] reads that
    /// value as this method answers.
    ///
    /// The translations are asked about the named entries in canonical
    /// order, and no further once one has no answer. The owner's, owning
    /// group's, mask's and other's entries name no id and are as they were.
    ///
    /// ```
    /// use file_acl::{Acl, Entry, MapError, Perm, Qualifier, Tag};
    ///
    /// let acl = Acl::new(vec![
    ///     Entry::new(Qualifier::UserObj, Perm::ALL),
    ///     Entry::new(Qualifier::User(1), Perm::READ),
    ///     Entry::new(Qualifier::GroupObj, Perm::READ),
    ///     Entry::new(Qualifier::Group(27), Perm::READ),
    ///     Entry::new(Qualifier::Mask, Perm::READ),
    ///     Entry::new(Qualifier::Other, Perm::NONE),
    /// ])?;
    /// // A namespace mapping its ids from 1 to 100000 on.
    /// let outside = |id: u32| id.checked_add(99_999);
    /// let mapped = acl.map_ids(outside, outside)?;
    /// assert_eq!(mapped.perm(Qualifier::User(100_000)), Some(Perm::READ));
    /// assert_eq!(mapped.perm(Qualifier::Group(100_026)), Some(Perm::READ));
    ///
    /// // A translation without an answer for user 1.
    /// assert_eq!(
    ///     acl.map_ids(|_| None, Some),
    ///     Err(MapError::Unmapped { tag: Tag::User, id: 1 })
    /// );
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    ///
    /// [`xattr::decode`]: crate::xattr::decode
    ///
    /// # Errors
    ///
    /// [`MapError::Unmapped`] naming the first named entry, in canonical
    /// order, whose id a translation has no answer for; and
    /// [`MapError::Invalid`] where the translated entries make no valid list:
    /// two ids translated to one, or an id translated to
    /// [`UNDEFINED_ID`](crate::UNDEFINED_ID).
    pub fn map_ids(
        &self,
        mut uid: impl FnMut(u32) -> Option<u32>,
        mut gid: impl FnMut(u32) -> Option<u32>,
    ) -> Result<Acl, MapError> {
        let mut entries = Vec::with_capacity(self.entries().len());
        for entry in self.entries() {
            let qualifier = match entry.qualifier {
                Qualifier::User(id) => {
                    Qualifier::User(uid(id).ok_or(MapError::Unmapped { tag: Tag::User, id })?)
                }
                Qualifier::Group(id) => Qualifier::Group(gid(id).ok_or(MapError::Unmapped {
                    tag: Tag::Group,
                    id,
                })?),
                object => object,
            };
            entries.push(Entry::new(qualifier, entry.perm));
        }
        Ok(Acl::new(entries)?)
    }

    /// The list with each named entry's id read through `uid` or `gid`, as
    /// [`map_ids`](Self::map_ids) reads it, and each named entry whose id a
    /// translation has no answer for left out.
    ///
    /// Leaving an entry out takes nothing from anyone a translation answers
    /// for: each keeps what the list granted them, and the mask, which bounds
    /// the owning group and every named entry, is kept. The entry left out
    /// granted or denied something to someone the other side has no id for.
    /// [`narrowed`](Self::narrowed) is the answer for a list that cannot be
    /// given at all, and gives a named user or group what their class is
    /// granted, which can be more than the list granted them.
    ///
    /// The translations are asked about every named entry, in canonical
    /// order.
    ///
    /// ```
    /// use file_acl::{Acl, Entry, Perm, Qualifier};
    ///
    /// let acl = Acl::new(vec![
    ///     Entry::new(Qualifier::UserObj, Perm::ALL),
    ///     Entry::new(Qualifier::User(1), Perm::NONE),
    ///     Entry::new(Qualifier::User(2), Perm::READ),
    ///     Entry::new(Qualifier::GroupObj, Perm::READ),
    ///     Entry::new(Qualifier::Mask, Perm::READ),
    ///     Entry::new(Qualifier::Other, Perm::READ),
    /// ])?;
    /// // A namespace mapping user 1 to 100000, and no one else.
    /// let partial = acl.map_ids_partial(|id| (id == 1).then_some(100_000), |_| None)?;
    /// // User 1's denial is kept for the id it is carried to.
    /// assert_eq!(partial.list.perm(Qualifier::User(100_000)), Some(Perm::NONE));
    /// assert_eq!(partial.left_out, 1);
    /// # Ok::<(), file_acl::Invalid>(())
    /// ```
    ///
    /// # Errors
    ///
    /// [`Invalid`] where the entries translated make no valid list: two ids
    /// were translated to one, or an id to [`UNDEFINED_ID`](crate::UNDEFINED_ID).
    pub fn map_ids_partial(
        &self,
        mut uid: impl FnMut(u32) -> Option<u32>,
        mut gid: impl FnMut(u32) -> Option<u32>,
    ) -> Result<Partial, Invalid> {
        let mut entries = Vec::with_capacity(self.entries().len());
        let mut left_out = 0usize;
        for entry in self.entries() {
            let qualifier = match entry.qualifier {
                Qualifier::User(id) => uid(id).map(Qualifier::User),
                Qualifier::Group(id) => gid(id).map(Qualifier::Group),
                object => Some(object),
            };
            match qualifier {
                Some(qualifier) => entries.push(Entry::new(qualifier, entry.perm)),
                None => left_out = left_out.saturating_add(1),
            }
        }
        Ok(Partial {
            list: Acl::new(entries)?,
            left_out,
        })
    }
}

/// A list given without the named entries nobody answers for, by
/// [`Acl::map_ids_partial`] and
/// [`Parsed::resolve_partial`](crate::text::Parsed::resolve_partial).
#[derive(Clone, PartialEq, Eq, Hash, Debug)]
#[non_exhaustive]
pub struct Partial {
    /// The list, with every entry that had an answer.
    pub list: Acl,
    /// How many named entries had none, and are left out.
    pub left_out: usize,
}

/// Why a list's ids cannot be restated through a translation.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
#[non_exhaustive]
pub enum MapError {
    /// A translation has no answer for a named entry's id: the first such
    /// entry, in canonical order.
    Unmapped {
        /// [`Tag::User`] or [`Tag::Group`].
        tag: Tag,
        /// The id the translation has no answer for.
        id: u32,
    },
    /// The translated entries make no valid list: two ids were translated to
    /// one, which the list then names twice, or an id was translated to the
    /// undefined id.
    Invalid(Invalid),
}

impl From<Invalid> for MapError {
    fn from(invalid: Invalid) -> MapError {
        MapError::Invalid(invalid)
    }
}

impl fmt::Display for MapError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MapError::Unmapped { tag, id } => {
                write!(f, "{} has no id in the map", Qualifier::new(*tag, *id))
            }
            MapError::Invalid(invalid) => invalid.fmt(f),
        }
    }
}

impl core::error::Error for MapError {}
