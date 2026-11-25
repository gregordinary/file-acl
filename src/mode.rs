//! The rules that tie a list to a file's mode, as the kernel keeps them.
//!
//! A file's access list and its mode are two views of one set of
//! permissions, and the kernel keeps them in step. Setting an access list sets
//! the mode's permission bits from it, and `chmod` sets the list's entries
//! from the mode. An access list that says no more than a mode does, the
//! [minimal] one, is not stored at all.
//!
//! [`set`] applies these rules for a caller with no kernel to ask, such as a
//! program writing a filesystem image. The program then writes what the
//! kernel would have left. The methods on [`Acl`] this module adds are the
//! parts it is made of.
//!
//! A file's default list, which a directory's new entries inherit, has no
//! bearing on its mode.
//!
//! [minimal]: Acl::is_minimal

use alloc::vec::Vec;
use core::fmt;

use crate::xattr::MAX_ENTRIES;
use crate::{Acl, Entry, Invalid, Perm, Qualifier, Tag};

/// A mode's permission bits: the owner's, the group's and other's read,
/// write and execute.
const PERMISSION_BITS: u32 = 0o777;

/// The mode bits granting one class read, write and execute, in that order.
type Class = [u32; 3];

const OWNER: Class = [0o400, 0o200, 0o100];
const GROUP: Class = [0o040, 0o020, 0o010];
const OTHER: Class = [0o004, 0o002, 0o001];

/// The three permissions, in the order a [`Class`] holds their bits.
const PERMS: [Perm; 3] = [Perm::READ, Perm::WRITE, Perm::EXECUTE];

/// What `mode` grants `class`.
fn perm_in(mode: u32, class: Class) -> Perm {
    let mut perm = Perm::NONE;
    for (bit, granted) in class.into_iter().zip(PERMS) {
        if mode & bit != 0 {
            perm |= granted;
        }
    }
    perm
}

/// The mode bits granting `class` what `perm` grants.
fn bits_of(perm: Perm, class: Class) -> u32 {
    let mut bits = 0;
    for (bit, granted) in class.into_iter().zip(PERMS) {
        if perm.contains(granted) {
            bits |= bit;
        }
    }
    bits
}

impl Acl {
    /// The permission bits of the mode a file with this access list shows.
    ///
    /// The owner's bits come from the owner entry, and other's from the other
    /// entry. The group's come from the mask, or from the owning group's entry
    /// where the list has no mask. The kernel sets a file's permission bits to
    /// these when the list is set as its access list. `stat` reports them
    /// while the list stands.
    ///
    /// ```
    /// use file_acl::{Acl, Entry, Perm, Qualifier};
    ///
    /// let acl = Acl::new(vec![
    ///     Entry::new(Qualifier::UserObj, Perm::READ | Perm::WRITE),
    ///     Entry::new(Qualifier::User(1000), Perm::READ | Perm::WRITE),
    ///     Entry::new(Qualifier::GroupObj, Perm::READ),
    ///     Entry::new(Qualifier::Mask, Perm::READ | Perm::WRITE),
    ///     Entry::new(Qualifier::Other, Perm::NONE),
    /// ])?;
    /// // The group bits are the mask's, not the owning group's.
    /// assert_eq!(acl.mode_bits(), 0o660);
    /// # Ok::<(), file_acl::Invalid>(())
    /// ```
    #[must_use]
    pub fn mode_bits(&self) -> u32 {
        bits_of(self.owner(), OWNER)
            | bits_of(self.mask().unwrap_or(self.owning_group()), GROUP)
            | bits_of(self.other(), OTHER)
    }

    /// Whether the list says no more than a mode does. A minimal list holds
    /// the owner's, the owning group's and other's entries, with no mask and
    /// no named entry.
    ///
    /// Set as an access list, a minimal list is not stored: the kernel sets
    /// the mode from it and removes any list the file had. A list with a
    /// mask is not minimal, even naming no one, and is stored.
    #[must_use]
    pub fn is_minimal(&self) -> bool {
        self.mask().is_none() && !self.names_anyone()
    }

    /// The minimal list `mode`'s permission bits are, the list a file
    /// without an access list is read as. Bits of `mode` above the
    /// permission bits are ignored.
    ///
    /// ```
    /// use file_acl::{Acl, Perm};
    ///
    /// let acl = Acl::from_mode(0o4750);
    /// assert!(acl.is_minimal());
    /// assert_eq!(acl.owning_group(), Perm::READ | Perm::EXECUTE);
    /// assert_eq!(acl.mode_bits(), 0o750);
    /// ```
    #[must_use]
    pub fn from_mode(mode: u32) -> Acl {
        Acl::minimal(
            perm_in(mode, OWNER),
            perm_in(mode, GROUP),
            perm_in(mode, OTHER),
        )
    }

    /// The access list after `chmod` sets a file's mode to `mode`.
    ///
    /// The owner's, the mask's and other's entries grant what `mode`'s
    /// permission bits grant each class. The named entries and the owning
    /// group's are as they were. In a list with no mask, the owning group's
    /// entry takes the group bits. Bits of `mode` above the permission bits
    /// are ignored.
    ///
    /// `chmod` leaves a directory's default list as it is.
    ///
    /// ```
    /// use file_acl::{Acl, Entry, Perm, Qualifier};
    ///
    /// let acl = Acl::new(vec![
    ///     Entry::new(Qualifier::UserObj, Perm::ALL),
    ///     Entry::new(Qualifier::User(1000), Perm::ALL),
    ///     Entry::new(Qualifier::GroupObj, Perm::READ),
    ///     Entry::new(Qualifier::Mask, Perm::ALL),
    ///     Entry::new(Qualifier::Other, Perm::READ),
    /// ])?;
    /// let chmodded = acl.with_mode(0o640);
    /// assert_eq!(chmodded.mask(), Some(Perm::READ));
    /// assert_eq!(chmodded.perm(Qualifier::User(1000)), Some(Perm::ALL));
    /// assert_eq!(chmodded.mode_bits(), 0o640);
    /// # Ok::<(), file_acl::Invalid>(())
    /// ```
    #[must_use]
    pub fn with_mode(&self, mode: u32) -> Acl {
        let group = perm_in(mode, GROUP);
        let owning_group = if self.mask().is_some() {
            self.owning_group()
        } else {
            group
        };
        self.with_object_perms(
            perm_in(mode, OWNER),
            owning_group,
            group,
            perm_in(mode, OTHER),
        )
    }

    /// The minimal list granting the owner, and anyone this list does not
    /// name, what this list grants them. It keeps the owner's and other's
    /// entries as they are, and the owning group's cut back by the mask.
    ///
    /// It is for a file that cannot have the list, as on a filesystem that
    /// stores no lists. The list's mode bits alone would not do. Where the
    /// list has a mask, the group bits are the mask's. A list granting the
    /// owning group `---` beside a mask of `rw-` would then give that group
    /// `rw-`.
    /// Where an id or a name the list holds has no answer,
    /// [`Acl::map_ids_partial`] and
    /// [`Parsed::resolve_partial`](crate::text::Parsed::resolve_partial) keep
    /// everyone else's entries instead.
    ///
    /// Under the narrowing, a named user, or a member of a named group, gets
    /// their class's permissions: the owning group's, or other's. Their
    /// class's permissions can be less than the list granted them, or more. A
    /// list can deny one user what everyone else has, and a mode cannot.
    ///
    /// ```
    /// use file_acl::{Acl, Entry, Perm, Qualifier};
    ///
    /// let acl = Acl::new(vec![
    ///     Entry::new(Qualifier::UserObj, Perm::READ | Perm::WRITE),
    ///     Entry::new(Qualifier::User(1000), Perm::READ | Perm::WRITE),
    ///     Entry::new(Qualifier::GroupObj, Perm::NONE),
    ///     Entry::new(Qualifier::Mask, Perm::READ | Perm::WRITE),
    ///     Entry::new(Qualifier::Other, Perm::NONE),
    /// ])?;
    /// assert_eq!(acl.mode_bits(), 0o660);
    /// assert_eq!(acl.narrowed().mode_bits(), 0o600);
    /// # Ok::<(), file_acl::Invalid>(())
    /// ```
    #[must_use]
    pub fn narrowed(&self) -> Acl {
        Acl::minimal(
            self.owner(),
            self.owning_group() & self.mask().unwrap_or(Perm::ALL),
            self.other(),
        )
    }

    /// The list of `entries`, in any order, with a computed mask: the union
    /// of what the owning group's entry and every named entry grant.
    ///
    /// The computed mask replaces any mask the entries hold, as
    /// `setfacl --mask` does. Without `--mask`, `setfacl` keeps a mask it is
    /// given and computes one only where it is given none. The mask is added
    /// where the entries name a user or group and hold none. Entries naming no
    /// one and holding no mask get none, as `setfacl` leaves them. libacl's
    /// `acl_calc_mask` adds one to them too, so the kernel stores a list it
    /// would otherwise not.
    ///
    /// ```
    /// use file_acl::{Acl, Entry, Perm, Qualifier};
    ///
    /// // A user named without a mask, as `setfacl -m u:1000:r` adds one.
    /// let acl = Acl::with_computed_mask(vec![
    ///     Entry::new(Qualifier::UserObj, Perm::READ | Perm::WRITE),
    ///     Entry::new(Qualifier::User(1000), Perm::READ),
    ///     Entry::new(Qualifier::GroupObj, Perm::EXECUTE),
    ///     Entry::new(Qualifier::Other, Perm::NONE),
    /// ])?;
    /// assert_eq!(acl.mask(), Some(Perm::READ | Perm::EXECUTE));
    /// # Ok::<(), file_acl::Invalid>(())
    /// ```
    ///
    /// # Errors
    ///
    /// [`Invalid`] where the entries make no valid list once the mask is
    /// computed, as [`Acl::new`] names it. The rule broken is a required entry
    /// missing, or an entry repeated (the mask among them) or naming the
    /// undefined id.
    pub fn with_computed_mask(mut entries: Vec<Entry>) -> Result<Acl, Invalid> {
        let (mask, named) = computed_mask(
            entries
                .iter()
                .map(|entry| (entry.qualifier.tag(), entry.perm)),
        );
        // Each mask the entries hold takes the computed value, so a repeated
        // mask is still found, and reported, where `Acl::new` would find it.
        let mut held = false;
        for entry in &mut entries {
            if entry.qualifier == Qualifier::Mask {
                entry.perm = mask;
                held = true;
            }
        }
        if named && !held {
            // Room for the one entry, where `push` alone would double it.
            entries.reserve_exact(1);
            entries.push(Entry::new(Qualifier::Mask, mask));
        }
        Acl::new(entries)
    }
}

/// The mask `setfacl` computes for entries of these tags and permissions,
/// and whether any entry names a user or group. The mask is the union of the
/// owning group's and every named entry's permissions.
pub(crate) fn computed_mask(entries: impl IntoIterator<Item = (Tag, Perm)>) -> (Perm, bool) {
    let mut mask = Perm::NONE;
    let mut named = false;
    for (tag, perm) in entries {
        match tag {
            Tag::GroupObj => mask |= perm,
            Tag::User | Tag::Group => {
                mask |= perm;
                named = true;
            }
            Tag::UserObj | Tag::Mask | Tag::Other => {}
        }
    }
    (mask, named)
}

/// What a list is set on, as far as the kernel's rules for lists tell kinds
/// of file apart.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum FileKind {
    /// A directory, which can have an access list and a default list.
    Directory,
    /// A symbolic link, which can have neither.
    SymbolicLink,
    /// Any other kind of file, which can have an access list but no default
    /// list. Regular files, FIFOs, sockets and character devices are among
    /// them.
    Other,
}

/// Which of a file's two lists is set.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum ListKind {
    /// The access list, which governs access to the file itself and is
    /// tied to its mode (`system.posix_acl_access`).
    Access,
    /// The default list, which a directory's new entries inherit
    /// (`system.posix_acl_default`).
    Default,
}

/// What setting a list leaves: the file's mode, and the list it has.
#[derive(Clone, PartialEq, Eq, Hash, Debug)]
pub struct Set {
    /// The file's mode.
    pub mode: u32,
    /// The list the file has, `None` where it has none. The caller stores
    /// it, and removes any the file had where this is `None`.
    pub list: Option<Acl>,
}

/// Why a list cannot be set on a file.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
#[non_exhaustive]
pub enum SetError {
    /// A list of more than 8,191 entries, whose value is
    /// [longer than the kernel takes](crate::xattr#length). The kernel
    /// answers `E2BIG`, on any file, before any other refusal.
    TooLong,
    /// A default list on a file that is not a directory. The kernel answers
    /// `EACCES`.
    NotADirectory,
    /// A list on a symbolic link. The kernel answers `EOPNOTSUPP`.
    SymbolicLink,
}

impl fmt::Display for SetError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SetError::TooLong => write!(
                f,
                "the list has more than {MAX_ENTRIES} entries, \
                 more than an extended attribute holds"
            ),
            SetError::NotADirectory => {
                f.write_str("a default list is set on a file that is not a directory")
            }
            SetError::SymbolicLink => f.write_str("a list is set on a symbolic link"),
        }
    }
}

impl core::error::Error for SetError {}

/// What setting `list` as `kind` of list on a file of `file_kind` with mode
/// `mode` leaves, as the kernel does it. `None` sets no list, as an empty
/// attribute value or `removexattr` does. Each case leaves the file as
/// follows:
///
/// - An access list sets the mode's permission bits to its [`mode_bits`],
///   and is stored unless it is [minimal]. A minimal list leaves the file
///   with no access list, removing any it had.
/// - A default list is stored, minimal or not, and leaves the mode as it was.
/// - No list leaves the file with none, and the mode as it was. Where a list
///   stood, the mode's group bits are still its mask's.
///
/// The bits of `mode` above the permission bits, set-user-ID, set-group-ID,
/// sticky and any file type bits, are kept. The kernel keeps set-group-ID
/// where the process setting the list is in the file's owning group or has
/// `CAP_FSETID`. Otherwise it clears it, as `chmod` does. A caller setting
/// lists for a process outside the owning group and without `CAP_FSETID`
/// clears set-group-ID itself.
///
/// ```
/// use file_acl::mode::{self, FileKind, ListKind};
/// use file_acl::{Acl, Entry, Perm, Qualifier};
///
/// let acl = Acl::new(vec![
///     Entry::new(Qualifier::UserObj, Perm::READ | Perm::WRITE),
///     Entry::new(Qualifier::User(1000), Perm::READ),
///     Entry::new(Qualifier::GroupObj, Perm::READ),
///     Entry::new(Qualifier::Mask, Perm::READ | Perm::WRITE),
///     Entry::new(Qualifier::Other, Perm::READ),
/// ])?;
/// let set = mode::set(0o4644, FileKind::Other, ListKind::Access, Some(acl.clone()))?;
/// assert_eq!(set.mode, 0o4664);
/// assert_eq!(set.list, Some(acl));
///
/// // A minimal list is the mode alone.
/// let set = mode::set(0o644, FileKind::Other, ListKind::Access, Some(Acl::from_mode(0o750)))?;
/// assert_eq!(set.mode, 0o750);
/// assert_eq!(set.list, None);
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
///
/// # Errors
///
/// - [`SetError::TooLong`] for a list of more than 8,191 entries, on any
///   file.
/// - [`SetError::NotADirectory`] for a default list on a file that is not a
///   directory.
/// - [`SetError::SymbolicLink`] for any list on a symbolic link.
///
/// The first is checked before the others. Setting no list fails on none of
/// these. The kernel refuses even an empty value on a symbolic link, which
/// leaves the link with no list, as `Ok` says.
///
/// A filesystem can also refuse a shorter list with `ENOSPC`, as
/// [the binary form](crate::xattr#length) describes, which `set` cannot
/// know.
///
/// [`mode_bits`]: Acl::mode_bits
/// [minimal]: Acl::is_minimal
pub fn set(
    mode: u32,
    file_kind: FileKind,
    kind: ListKind,
    list: Option<Acl>,
) -> Result<Set, SetError> {
    let Some(list) = list else {
        return Ok(Set { mode, list: None });
    };
    // The kernel refuses a value longer than it takes before it reads the
    // value, or asks what it is set on, as measured:
    // `the_length_set_takes_agrees_with_the_kernel_*` in `tests/mode.rs`
    // compares the two.
    if list.entries().len() > MAX_ENTRIES {
        return Err(SetError::TooLong);
    }
    match (file_kind, kind) {
        (FileKind::SymbolicLink, _) => Err(SetError::SymbolicLink),
        (FileKind::Directory | FileKind::Other, ListKind::Access) => Ok(Set {
            mode: (mode & !PERMISSION_BITS) | list.mode_bits(),
            list: (!list.is_minimal()).then_some(list),
        }),
        (FileKind::Directory, ListKind::Default) => Ok(Set {
            mode,
            list: Some(list),
        }),
        (FileKind::Other, ListKind::Default) => Err(SetError::NotADirectory),
    }
}
