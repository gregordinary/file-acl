//! Just enough of the pax archive format for the tar comparisons: archives
//! of empty files and directories carrying records, and the records a tar
//! wrote for each member of its archive.

/// A member of an archive [`archive`] writes.
#[derive(Clone, Debug)]
pub(crate) struct Member {
    /// The member's name, a directory's without its trailing `/`.
    pub(crate) name: Vec<u8>,
    /// Whether the member is a directory; otherwise it is an empty file.
    pub(crate) directory: bool,
    /// The permission bits its header states.
    pub(crate) mode: u32,
    /// The pax records before it.
    pub(crate) records: Records,
}

/// A member's pax records, as keywords and values, in the order written.
pub(crate) type Records = Vec<(Vec<u8>, Vec<u8>)>;

const BLOCK: usize = 512;

/// `value` as `width - 1` octal digits and a NUL.
fn octal(field: &mut [u8], value: u64) {
    let digits = format!("{value:0width$o}", width = field.len() - 1);
    assert_eq!(digits.len(), field.len() - 1, "{value} fits its field");
    field[..digits.len()].copy_from_slice(digits.as_bytes());
    field[digits.len()] = 0;
}

/// A POSIX header for `name`, of `typeflag` and `size`, owned by root.
fn header(name: &[u8], typeflag: u8, size: usize, mode: u32) -> [u8; BLOCK] {
    assert!(name.len() <= 100, "{name:?} fits a header");
    let mut block = [0u8; BLOCK];
    block[..name.len()].copy_from_slice(name);
    octal(&mut block[100..108], u64::from(mode));
    octal(&mut block[108..116], 0);
    octal(&mut block[116..124], 0);
    octal(&mut block[124..136], size as u64);
    octal(&mut block[136..148], 1_700_000_000);
    block[148..156].fill(b' ');
    block[156] = typeflag;
    block[257..263].copy_from_slice(b"ustar\0");
    block[263..265].copy_from_slice(b"00");
    let sum: u32 = block.iter().map(|&byte| u32::from(byte)).sum();
    let checksum = format!("{sum:06o}\0 ");
    block[148..156].copy_from_slice(checksum.as_bytes());
    block
}

/// `data` padded with NULs to whole blocks.
fn padded(out: &mut Vec<u8>, data: &[u8]) {
    out.extend_from_slice(data);
    out.resize(out.len().next_multiple_of(BLOCK), 0);
}

/// A record, `length keyword=value\n`, its length counting itself.
fn record(keyword: &[u8], value: &[u8]) -> Vec<u8> {
    let body = keyword.len() + value.len() + 3;
    let mut length = body + 1;
    while length.to_string().len() + body != length {
        length += 1;
    }
    let mut out = format!("{length} ").into_bytes();
    out.extend_from_slice(keyword);
    out.push(b'=');
    out.extend_from_slice(value);
    out.push(b'\n');
    out
}

/// A pax archive of `members`, each after its records, if it has any.
pub(crate) fn archive(members: &[Member]) -> Vec<u8> {
    let mut out = Vec::new();
    for member in members {
        if !member.records.is_empty() {
            let body: Vec<u8> = member
                .records
                .iter()
                .flat_map(|(keyword, value)| record(keyword, value))
                .collect();
            let mut name = b"PaxHeaders/".to_vec();
            name.extend_from_slice(&member.name);
            out.extend_from_slice(&header(&name, b'x', body.len(), 0o644));
            padded(&mut out, &body);
        }
        let mut name = member.name.clone();
        if member.directory {
            name.push(b'/');
        }
        let typeflag = if member.directory { b'5' } else { b'0' };
        out.extend_from_slice(&header(&name, typeflag, 0, member.mode));
    }
    out.resize(out.len() + 2 * BLOCK, 0);
    out
}

/// The number an octal header field holds.
fn number(field: &[u8]) -> usize {
    let digits: Vec<u8> = field
        .iter()
        .copied()
        .filter(|byte| byte.is_ascii_digit())
        .collect();
    usize::from_str_radix(std::str::from_utf8(&digits).expect("digits"), 8).unwrap_or(0)
}

/// Each member of a POSIX archive, its name without a trailing `/`, with the
/// records of the extended header before it.
pub(crate) fn records(archive: &[u8]) -> Vec<(Vec<u8>, Records)> {
    let mut members = Vec::new();
    let mut pending = Vec::new();
    let mut at = 0;
    while let Some(block) = archive.get(at..at + BLOCK) {
        if block.iter().all(|&byte| byte == 0) {
            break;
        }
        let name_field = &block[..100];
        let mut name =
            name_field[..name_field.iter().position(|&b| b == 0).unwrap_or(100)].to_vec();
        let prefix = &block[345..500];
        let prefix = &prefix[..prefix.iter().position(|&b| b == 0).unwrap_or(155)];
        if !prefix.is_empty() {
            let mut joined = prefix.to_vec();
            joined.push(b'/');
            joined.extend_from_slice(&name);
            name = joined;
        }
        let size = number(&block[124..136]);
        let body = &archive[at + BLOCK..at + BLOCK + size];
        at += BLOCK + size.next_multiple_of(BLOCK);
        match block[156] {
            b'x' => {
                let mut rest = body;
                while !rest.is_empty() {
                    let space = rest.iter().position(|&b| b == b' ').expect("a length");
                    let length: usize = std::str::from_utf8(&rest[..space])
                        .expect("digits")
                        .parse()
                        .expect("a length");
                    let text = &rest[space + 1..length - 1];
                    let equals = text.iter().position(|&b| b == b'=').expect("a keyword");
                    pending.push((text[..equals].to_vec(), text[equals + 1..].to_vec()));
                    rest = &rest[length..];
                }
            }
            b'g' => {}
            _ => {
                if let Some((_, path)) = pending.iter().find(|(keyword, _)| keyword == b"path") {
                    name = path.clone();
                }
                while name.last() == Some(&b'/') {
                    name.pop();
                }
                members.push((name, std::mem::take(&mut pending)));
            }
        }
    }
    members
}
