//! The binary form over arbitrary input: decoding never panics, and what it
//! reads, it writes back canonically.
//!
//! The input is decoded as an attribute value. Checked:
//!
//! - no list is read only from an empty value or a version-2 header alone;
//! - a list read encodes to a value of the input's length, which is the
//!   input with its named users, and its named groups, sorted by id and the
//!   ids of its other entries set to `UNDEFINED_ID`, so the encoding is
//!   canonical; that value decodes to the same list, and encoding that list
//!   again gives the same bytes;
//! - a value longer than 65,536 bytes is refused as `TooLong`, and only such
//!   a value;
//! - a refusal names an entry the value holds, a `Partial` length only where
//!   the value is not a header and whole entries, and a `Version` only where
//!   the header states another; and it displays.

#![no_main]
#![forbid(unsafe_code)]

use file_acl::UNDEFINED_ID;
use file_acl::xattr::{self, DecodeError};
use libfuzzer_sys::fuzz_target;

const HEADER: usize = 4;
const ENTRY: usize = 8;
const MAX_LEN: usize = 65_536;

/// The entries of a value of whole entries, as (tag, permissions, id).
fn records(value: &[u8]) -> Vec<(u16, u16, u32)> {
    let (records, _) = value[HEADER..].as_chunks::<ENTRY>();
    records
        .iter()
        .map(|&[t0, t1, p0, p1, i0, i1, i2, i3]| {
            (
                u16::from_le_bytes([t0, t1]),
                u16::from_le_bytes([p0, p1]),
                u32::from_le_bytes([i0, i1, i2, i3]),
            )
        })
        .collect()
}

/// The value of version 2 holding `records`.
fn value(records: &[(u16, u16, u32)]) -> Vec<u8> {
    let mut out = 2u32.to_le_bytes().to_vec();
    for &(tag, perm, id) in records {
        out.extend_from_slice(&tag.to_le_bytes());
        out.extend_from_slice(&perm.to_le_bytes());
        out.extend_from_slice(&id.to_le_bytes());
    }
    out
}

fuzz_target!(|input: &[u8]| {
    let whole = input.len() >= HEADER && (input.len() - HEADER).is_multiple_of(ENTRY);
    let entries = if whole {
        (input.len() - HEADER) / ENTRY
    } else {
        0
    };
    let decoded = xattr::decode(input);
    assert_eq!(
        matches!(decoded, Err(DecodeError::TooLong { .. })),
        input.len() > MAX_LEN
    );
    match decoded {
        Ok(None) => assert!(input.is_empty() || input == 2u32.to_le_bytes()),
        Ok(Some(acl)) => {
            assert!(whole && entries == acl.entries().len());
            let encoded = xattr::encode(&acl);
            assert_eq!(encoded.len(), input.len());

            // The tag values ascend in canonical order, so sorting by tag
            // and id is the canonical order, once the ids the form ignores
            // are made the one it writes.
            let mut canonical = records(input);
            for record in &mut canonical {
                if record.0 != 0x02 && record.0 != 0x08 {
                    record.2 = UNDEFINED_ID;
                }
            }
            canonical.sort_by_key(|&(tag, _, id)| (tag, id));
            assert_eq!(encoded, value(&canonical));

            let again = xattr::decode(&encoded).expect("an encoded list decodes");
            assert_eq!(again.as_ref(), Some(&acl));
            assert_eq!(xattr::encode(&acl), encoded);
        }
        Err(error) => {
            let _ = error.to_string();
            match error {
                DecodeError::TooLong { len } => assert_eq!(len, input.len()),
                DecodeError::Partial { len } => {
                    assert_eq!(len, input.len());
                    assert!(!whole);
                }
                DecodeError::Version { version } => {
                    assert!(input.len() >= HEADER);
                    assert_eq!(version.to_le_bytes(), input[..HEADER]);
                    assert_ne!(version, 2);
                }
                DecodeError::UnknownTag { entry, .. }
                | DecodeError::StrayPerm { entry, .. }
                | DecodeError::TagOrder { entry, .. }
                | DecodeError::UnmappedId { entry, .. } => {
                    assert!(whole && entry < entries);
                }
                DecodeError::Invalid(_) => assert!(whole),
                _ => {}
            }
        }
    }
});
