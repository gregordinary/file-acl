//! The text form over arbitrary input: parsing never panics, and what it
//! reads, it writes back.
//!
//! The input's first byte chooses a prefix for generated names, of up to
//! seven of the bytes after it, and the rest is parsed as a list's text.
//! Checked:
//!
//! - only an empty text is no list;
//! - a refusal names an offset within the text, and displays;
//! - a parsed text resolves through lookups that answer some names and not
//!   others, preferring either id, without panicking, and so do its
//!   narrowing and its computed mask;
//! - a list resolved is written in every spelling, with numeric ids and with
//!   generated names, and each text reads back as the list; where the
//!   spelling records ids, with no lookup too.

#![no_main]
#![forbid(unsafe_code)]

use file_acl::Acl;
use file_acl::text::{self, Names, ParseError, Prefer, Separator, Spelling, Tags};
use libfuzzer_sys::fuzz_target;

const SPELLINGS: [Spelling; 8] = [
    Spelling::GNU_TAR,
    Spelling::new(Tags::Short, Separator::Comma, Names::Alone),
    Spelling::new(Tags::Long, Separator::Comma, Names::Alone),
    Spelling::new(Tags::Short, Separator::Newline, Names::Alone),
    Spelling::STAR,
    Spelling::new(Tags::Short, Separator::Comma, Names::WithIds),
    Spelling::new(Tags::Long, Separator::Newline, Names::WithIds),
    Spelling::new(Tags::Short, Separator::Newline, Names::WithIds),
];

/// An answer for some names: an id from the name's bytes, where its last
/// byte is even.
fn lookup(name: &[u8]) -> Option<u32> {
    match name.last() {
        Some(last) if last % 2 == 0 => {
            Some(name.iter().fold(0u32, |id, &b| id.wrapping_mul(31).wrapping_add(u32::from(b))) % 1_000_000)
        }
        _ => None,
    }
}

/// Where a refusal says the fault is.
fn offset(error: ParseError) -> Option<usize> {
    match error {
        ParseError::Nul { at }
        | ParseError::LeadingComment { at }
        | ParseError::Comment { at }
        | ParseError::Tag { at }
        | ParseError::Incomplete { at }
        | ParseError::Qualifier { at }
        | ParseError::LineEnd { at }
        | ParseError::Escape { at }
        | ParseError::Number { at }
        | ParseError::Perm { at }
        | ParseError::Id { at }
        | ParseError::IdMismatch { at }
        | ParseError::Separator { at } => Some(at),
        _ => None,
    }
}

/// Checks that `acl`, written in every spelling, reads back as itself.
fn round_trip(acl: &Acl, prefix: &[u8]) {
    let name = |id: u32| {
        let mut name = prefix.to_vec();
        name.extend_from_slice(format!("{id:x}").as_bytes());
        Some(name)
    };
    let id_of = |name: &[u8]| {
        let digits = name.strip_prefix(prefix)?;
        let digits = std::str::from_utf8(digits).ok()?;
        let id = u32::from_str_radix(digits, 16).ok()?;
        (format!("{id:x}") == digits).then_some(id)
    };
    for spelling in SPELLINGS {
        let numeric = text::write(acl, spelling);
        let parsed = text::parse(&numeric).expect("written text parses").expect("a list");
        assert_eq!(parsed.resolve(|_| None, |_| None, Prefer::Name).as_ref(), Ok(acl));

        let named = text::write_named(acl, spelling, name, name);
        let parsed = text::parse(&named).expect("written names parse").expect("a list");
        assert_eq!(parsed.resolve(id_of, id_of, Prefer::Name).as_ref(), Ok(acl));
        if spelling.names == Names::WithIds {
            assert_eq!(parsed.resolve(|_| None, |_| None, Prefer::Name).as_ref(), Ok(acl));
        }
    }
}

fuzz_target!(|input: &[u8]| {
    let Some((&first, rest)) = input.split_first() else {
        return;
    };
    let length = usize::from(first % 8).min(rest.len());
    let (prefix, text) = rest.split_at(length);
    match text::parse(text) {
        Ok(None) => assert!(text.is_empty()),
        Err(error) => {
            let _ = error.to_string();
            if let Some(at) = offset(error) {
                assert!(at <= text.len());
            }
        }
        Ok(Some(parsed)) => {
            assert!(!text.is_empty());
            for prefer in [Prefer::Name, Prefer::Id] {
                if let Ok(acl) = parsed.resolve(lookup, lookup, prefer) {
                    round_trip(&acl, prefix);
                }
            }
            let _ = parsed.narrowed();
            let _ = parsed.clone().with_computed_mask().resolve(lookup, lookup, Prefer::Name);
            if let Err(error) = parsed.resolve(|_| None, |_| None, Prefer::Name) {
                let _ = error.to_string();
            }
        }
    }
});
