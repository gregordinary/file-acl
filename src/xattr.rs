//! The binary form: the value of the `system.posix_acl_access` and
//! `system.posix_acl_default` extended attributes.
//!
//! A value is a 4-byte header holding the version, 2, and then one 8-byte
//! record per entry. A record holds the entry's tag ([`Tag::to_raw`]), its
//! permissions ([`Perm::bits`]) and its id, as 16-, 16- and 32-bit
//! little-endian integers. It is the form Linux's `getxattr` and `setxattr`
//! give and take.
//!
//! ```
//! use file_acl::{Perm, Qualifier, xattr};
//!
//! let value = [
//!     2, 0, 0, 0, // version 2
//!     0x01, 0, 6, 0, 0xff, 0xff, 0xff, 0xff, // owner: rw-
//!     0x02, 0, 4, 0, 0xe8, 0x03, 0, 0, // user 1000: r--
//!     0x04, 0, 4, 0, 0xff, 0xff, 0xff, 0xff, // owning group: r--
//!     0x10, 0, 4, 0, 0xff, 0xff, 0xff, 0xff, // mask: r--
//!     0x20, 0, 0, 0, 0xff, 0xff, 0xff, 0xff, // other: ---
//! ];
//! let acl = xattr::decode(&value)?.expect("the value holds a list");
//! assert_eq!(acl.perm(Qualifier::User(1000)), Some(Perm::READ));
//! assert_eq!(xattr::encode(&acl), value);
//! # Ok::<(), xattr::DecodeError>(())
//! ```
//!
//! # Length
//!
//! The kernel takes an extended attribute's value of at most 65,536 bytes. A
//! value therefore holds at most 8,191 entries: a 4-byte header and 8,191
//! 8-byte records make 65,532 bytes. [`decode`] refuses a longer value, and
//! [`mode::set`](crate::mode::set) a longer list, before anything else, as
//! the kernel does.
//!
//! A filesystem can refuse a shorter list, with `ENOSPC`, which the crate
//! cannot know. ext4 with 4 KiB blocks refuses a list of a thousand entries,
//! which tmpfs stores.

use alloc::vec::Vec;
use core::fmt;

use crate::acl::{Acl, Entry, Invalid, Perm, Qualifier, Tag, UNDEFINED_ID};

/// The name of the extended attribute that holds a file's access list.
pub const ACCESS: &str = "system.posix_acl_access";

/// The name of the extended attribute that holds a directory's default list:
/// the list a file or directory created in it starts from.
pub const DEFAULT: &str = "system.posix_acl_default";

/// The only version of the form.
const VERSION: u32 = 2;

/// The length of the header, which holds the version.
const HEADER: usize = 4;

/// The length of an entry: tag, permissions and id.
const ENTRY: usize = 8;

/// The length of the longest value the kernel takes for any extended
/// attribute (`XATTR_SIZE_MAX`).
const MAX_LEN: usize = 65_536;

/// The most entries a value the kernel takes holds: `4 + 8 * 8,191` is
/// 65,532 bytes.
pub(crate) const MAX_ENTRIES: usize = (MAX_LEN - HEADER) / ENTRY;

/// The list `value` holds, or `None` where it holds none.
///
/// `decode` accepts a value where the kernel accepts it from a process in the
/// initial user namespace, with one exception. The kernel stores a value
/// naming the same user or group twice, and `decode` refuses it, as libacl's
/// checker and [`Acl`] do. From another user namespace, the kernel also
/// refuses a value naming an id that namespace does not map, which `decode`
/// cannot know. It reads a value as follows:
///
/// - A value [longer than the kernel takes](crate::xattr#length), a list of
///   more than 8,191 entries, is refused before anything else, as the kernel
///   refuses it.
/// - An empty value, or a header alone, is `None`: the kernel takes either as
///   removing the list.
/// - Named users, and named groups, may come in any order within their run,
///   as the kernel accepts them. The list returned holds them in canonical
///   order, so [`encode`] can write them in another order than `value` did.
/// - The id fields of the owner, owning group, mask and other entries are
///   ignored, as the kernel ignores them.
///
/// # Errors
///
/// [`DecodeError`] naming the first rule `value` breaks, checked in this
/// order:
///
/// 1. Its length, if it is [`TooLong`].
/// 2. Its length, if it is shorter than a header.
/// 3. Its version.
/// 4. Its length again, if it does not end with a whole entry.
/// 5. Entry by entry, an [`UnknownTag`], [`StrayPerm`], [`TagOrder`] or
///    [`UnmappedId`].
/// 6. The list's own rules, as [`Acl::new`] names them.
///
/// The kernel refuses the same values, but for a user or group named twice.
/// It answers `E2BIG` for a value too long, `EOPNOTSUPP` for a wrong version,
/// and `EINVAL` for every other.
///
/// [`TooLong`]: DecodeError::TooLong
/// [`UnknownTag`]: DecodeError::UnknownTag
/// [`StrayPerm`]: DecodeError::StrayPerm
/// [`TagOrder`]: DecodeError::TagOrder
/// [`UnmappedId`]: DecodeError::UnmappedId
pub fn decode(value: &[u8]) -> Result<Option<Acl>, DecodeError> {
    // Each rule, and the order the errors are found in where it decides the
    // kernel's errno, is the kernel's as measured. `tests/xattr.rs` compares
    // them with it: `every_value_the_kernel_was_asked_about_decodes_as_measured`
    // holds the measured values, and `decode_agrees_with_the_kernel_*` sets
    // them and generated values on a file and a directory, and
    // `the_length_decode_takes_agrees_with_the_kernel_*` sets the values
    // about its length.
    if value.len() > MAX_LEN {
        return Err(DecodeError::TooLong { len: value.len() });
    }
    if value.is_empty() {
        return Ok(None);
    }
    let partial = DecodeError::Partial { len: value.len() };
    let (header, rest) = value.split_first_chunk::<HEADER>().ok_or(partial)?;
    let version = u32::from_le_bytes(*header);
    if version != VERSION {
        return Err(DecodeError::Version { version });
    }
    let (records, trailing) = rest.as_chunks::<ENTRY>();
    if !trailing.is_empty() {
        return Err(partial);
    }
    if records.is_empty() {
        return Ok(None);
    }
    let mut entries = Vec::with_capacity(records.len());
    let mut previous = None;
    for (at, record) in records.iter().enumerate() {
        let [tag_lo, tag_hi, perm_lo, perm_hi, id_0, id_1, id_2, id_3] = *record;
        let raw = u16::from_le_bytes([tag_lo, tag_hi]);
        let tag = Tag::from_raw(raw).ok_or(DecodeError::UnknownTag { entry: at, raw })?;
        let bits = u16::from_le_bytes([perm_lo, perm_hi]);
        let perm = Perm::from_bits(bits).ok_or(DecodeError::StrayPerm { entry: at, bits })?;
        // Equal tags are not out of order: named entries share a tag, and an
        // object entry given twice is the list's fault, which `Acl::new`
        // names.
        if let Some(previous) = previous
            && tag < previous
        {
            return Err(DecodeError::TagOrder {
                entry: at,
                tag,
                previous,
            });
        }
        previous = Some(tag);
        let id = u32::from_le_bytes([id_0, id_1, id_2, id_3]);
        if tag.is_named() && id == UNDEFINED_ID {
            return Err(DecodeError::UnmappedId { entry: at, tag });
        }
        entries.push(Entry::new(Qualifier::new(tag, id), perm));
    }
    Acl::new(entries).map(Some).map_err(DecodeError::Invalid)
}

/// The value that holds `acl`.
///
/// The entries are written in canonical order, and the owner, owning group,
/// mask and other entries have [`UNDEFINED_ID`] as their id. The value is
/// therefore a function of the list alone, and [`decode`] reads it back as
/// `acl`.
///
/// For a list of at most 8,191 entries, the kernel accepts the value and,
/// where it stores it, reads it back byte for byte. A longer list's value is
/// [longer than the kernel takes](crate::xattr#length). [`decode`] refuses it
/// ([`DecodeError::TooLong`]), as [`mode::set`](crate::mode::set) refuses to
/// set the list.
#[must_use]
pub fn encode(acl: &Acl) -> Vec<u8> {
    let entries = acl.entries();
    let mut value = Vec::with_capacity(entries.len().saturating_mul(ENTRY).saturating_add(HEADER));
    value.extend_from_slice(&VERSION.to_le_bytes());
    for entry in entries {
        let id = entry.qualifier.id().unwrap_or(UNDEFINED_ID);
        value.extend_from_slice(&entry.qualifier.tag().to_raw().to_le_bytes());
        value.extend_from_slice(&entry.perm.bits().to_le_bytes());
        value.extend_from_slice(&id.to_le_bytes());
    }
    value
}

/// Why a value holds no list: the rule it breaks.
///
/// An entry is named by its position in the value, counting from 0. Its
/// record starts at byte `4 + 8 * entry`.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
#[non_exhaustive]
pub enum DecodeError {
    /// The value is longer than 65,536 bytes,
    /// [the most the kernel takes](crate::xattr#length): a list of more than
    /// 8,191 entries. The kernel refuses it with `E2BIG`, before any other
    /// check.
    TooLong {
        /// The value's length, in bytes.
        len: usize,
    },
    /// The value is of a version other than 2. The kernel refuses it with
    /// `EOPNOTSUPP`.
    Version {
        /// The version the value states.
        version: u32,
    },
    /// The value ends partway through its header or an entry: its length is
    /// not a 4-byte header and whole 8-byte entries.
    Partial {
        /// The value's length, in bytes.
        len: usize,
    },
    /// An entry's tag is none POSIX.1e defines.
    UnknownTag {
        /// The entry's position in the value.
        entry: usize,
        /// The tag as the value stores it.
        raw: u16,
    },
    /// An entry's permissions hold a bit other than read, write and execute.
    StrayPerm {
        /// The entry's position in the value.
        entry: usize,
        /// The permissions as the value stores them.
        bits: u16,
    },
    /// An entry comes after one whose tag the canonical order puts later:
    /// the owner, named users, the owning group, named groups, the mask,
    /// other. Named users, and named groups, may come in any order among
    /// themselves.
    TagOrder {
        /// The entry's position in the value.
        entry: usize,
        /// The entry's tag.
        tag: Tag,
        /// The tag of the entry before it.
        previous: Tag,
    },
    /// A named entry has [`UNDEFINED_ID`] as its id.
    ///
    /// A process in a user namespace reads this for a named entry whose id
    /// its namespace does not map. The kernel reports the id as
    /// `UNDEFINED_ID`, not as the overflow id `stat` reports for an unmapped
    /// owner. The list cannot be set again as read, since the kernel refuses
    /// a named entry with `UNDEFINED_ID` as its id.
    UnmappedId {
        /// The entry's position in the value.
        entry: usize,
        /// [`Tag::User`] or [`Tag::Group`].
        tag: Tag,
    },
    /// The entries make no valid list: a required entry is missing, or an
    /// entry is repeated.
    Invalid(Invalid),
}

impl From<Invalid> for DecodeError {
    fn from(invalid: Invalid) -> DecodeError {
        DecodeError::Invalid(invalid)
    }
}

impl fmt::Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DecodeError::TooLong { len } => write!(
                f,
                "the value is {len} bytes long, \
                 longer than the {MAX_LEN} bytes an extended attribute holds"
            ),
            DecodeError::Version { version } => {
                write!(f, "the value is of version {version}, not {VERSION}")
            }
            DecodeError::Partial { len } => write!(
                f,
                "the value is {len} bytes long, \
                 which is not a {HEADER}-byte header and whole {ENTRY}-byte entries"
            ),
            DecodeError::UnknownTag { entry, raw } => write!(
                f,
                "the entry at position {entry} has tag {raw:#x}, which POSIX.1e does not define"
            ),
            DecodeError::StrayPerm { entry, bits } => write!(
                f,
                "the entry at position {entry} has permission bits {bits:#o}, \
                 beyond read, write and execute"
            ),
            DecodeError::TagOrder {
                entry,
                tag,
                previous,
            } => write!(
                f,
                "the {tag} entry at position {entry} follows the {previous} entry, out of order"
            ),
            DecodeError::UnmappedId { entry, tag } => write!(
                f,
                "the {tag} entry at position {entry} carries the undefined id {UNDEFINED_ID}, \
                 as read for an id the reader's user namespace does not map"
            ),
            DecodeError::Invalid(invalid) => invalid.fmt(f),
        }
    }
}

impl core::error::Error for DecodeError {}
