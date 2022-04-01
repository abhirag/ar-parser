//
//
//                                             ar file format (Common Variant)
//
//
//
//   Archive File Signature (8 bytes)                                                      File Entry Data
//
//                  │                                                                             │
//                  │                                                                             │
//                  │                                                                             │
//                  │                                                                             │
//                  ▼                                                                             ▼
//
//               ▽──────▽                                                               ▽────────────────────────────▽
//
//               ┌──────┬──────────────────────────────────────────────────────────┬────────────────────────────┐
//               │▓▓▓▓▓▓│░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░│▐▐▐▐▐▐▐▐▐▐▐▐▐▐▐▐▐▐▐▐▐▐▐▐▐▐▐▐│ ....
//               │▓▓▓▓▓▓│░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░│▐▐▐▐▐▐▐▐▐▐▐▐▐▐▐▐▐▐▐▐▐▐▐▐▐▐▐▐│
//               └──────┴──────────────────────────────────────────────────────────┴────────────────────────────┘
//
//                      △──────────────────────────────────────────────────────────△
//                                                   ▲
//                                                   │
//                                                   │
//                                                   │
//                                                   │
//                                                   │
//
//                                     File Entry Header (60 bytes)
//
//
use nom::{
    bytes::complete::{tag, take},
    combinator::{eof, map},
    multi::{many0, many_till},
    IResult,
};
use std::str;

//______________________________ Archive File Signature ______________________________

fn parse_file_signature(input: &[u8]) -> IResult<&[u8], &[u8]> {
    tag(b"!<arch>\n")(input)
}

#[test]
fn test_parse_file_signature() {
    let input = "\
        !<arch>\n\
        foo.txt         1487552916  501   20    100644  7         `\n\
        foobar\n\n\
        bar.awesome.txt 1487552919  501   20    100644  22        `\n\
        This file is awesome!\n\
        baz.txt         1487552349  42    12345 100664  4         `\n\
        baz\n";
    let (_, file_sig) =
        parse_file_signature(input.as_bytes()).expect("failed in parsing file signature");
    assert_eq!(file_sig, b"!<arch>\n");
}

//
//                      +--------------+----------+----+----+------+--------++
//                      |              |          |    |    |      |        ||
//                      |              |          |    |    |      |        ||
//                      +--------------+----------+----+----+------+--------++
//                              ^            ^       ^    ^     ^       ^    ^
//                              |            |       |    |     |       |    |
//                              |            |       |    |     |       |    |
//                              |            |       |    |     |       |    +-----------+
//                  +-----------+  +---------+ +-----+    |     |       |                |
//                  |              |           |          |     +----+  +--------+       |
//                  |              |           |          |          |           |       |
//                  |              |           |          |          |           |
//                  |              |           |          |          |           |  Terminating
//                                             |          |          |           |  Characters
//                File           File                                |           |   (2 bytes)
//             Identifier    Modification    Owner      Group                    |
//             (16 bytes)     Timestamp       id         id        File
//                            (12 bytes)   (6 bytes)  (6 bytes)    Mode        File
//                                                               (8 bytes)     Size
//                                                                          (10 bytes)
//
//
//______________________________ Entry Header ______________________________

#[derive(Debug, PartialEq)]
struct EntryHeader {
    identifier: Vec<u8>,
    mtime: u64,
    uid: u32,
    gid: u32,
    mode: u32,
    size: u64,
}

fn parse_identifier(input: &[u8]) -> IResult<&[u8], Vec<u8>> {
    map(take(16usize), |identifier_padded: &[u8]| {
        let mut identifier: Vec<u8> = identifier_padded.to_vec();
        while identifier.last() == Some(&b' ') {
            identifier.pop();
        }
        identifier
    })(input)
}

#[test]
fn test_parse_identifier() {
    let input = "\
        !<arch>\n\
        foo.txt         1487552916  501   20    100644  7         `\n\
        foobar\n\n\
        bar.awesome.txt 1487552919  501   20    100644  22        `\n\
        This file is awesome!\n\
        baz.txt         1487552349  42    12345 100664  4         `\n\
        baz\n";
    let (i, file_sig) =
        parse_file_signature(input.as_bytes()).expect("failed in parsing file signature");
    assert_eq!(file_sig, b"!<arch>\n");
    let (_, identifier) = parse_identifier(i).expect("failed in parsing entry identifier");
    assert_eq!(identifier, b"foo.txt");
}

fn byte_slice_to_number(byte_slice: &[u8], radix: u32) -> u64 {
    let s = str::from_utf8(byte_slice).expect("failed in converting byte slice to string slice");
    let num = u64::from_str_radix(s.trim_end(), radix)
        .unwrap_or_else(|_| panic!("failed in converting: {} to number", s));
    num
}

fn parse_number(input: &[u8], length: usize, radix: u32) -> IResult<&[u8], u64> {
    map(take(length), |byte_slice| {
        byte_slice_to_number(byte_slice, radix)
    })(input)
}

fn parse_mtime(input: &[u8]) -> IResult<&[u8], u64> {
    parse_number(input, 12, 10)
}

fn parse_uid(input: &[u8]) -> IResult<&[u8], u64> {
    parse_number(input, 6, 10)
}

fn parse_gid(input: &[u8]) -> IResult<&[u8], u64> {
    parse_number(input, 6, 10)
}

fn parse_mode(input: &[u8]) -> IResult<&[u8], u64> {
    parse_number(input, 8, 8)
}

fn parse_size(input: &[u8]) -> IResult<&[u8], u64> {
    parse_number(input, 10, 10)
}

#[test]
fn test_parse_header_numbers() {
    let input = "\
        !<arch>\n\
        foo.txt         1487552916  501   20    100644  7         `\n\
        foobar\n\n\
        bar.awesome.txt 1487552919  501   20    100644  22        `\n\
        This file is awesome!\n\
        baz.txt         1487552349  42    12345 100664  4         `\n\
        baz\n";
    let (i, file_sig) =
        parse_file_signature(input.as_bytes()).expect("failed in parsing file signature");
    assert_eq!(file_sig, b"!<arch>\n");
    let (i, identifier) = parse_identifier(i).expect("failed in parsing entry identifier");
    assert_eq!(identifier, b"foo.txt");
    let (i, mtime) = parse_mtime(i).expect("failed in parsing mtime");
    assert_eq!(mtime, 1487552916);
    let (i, uid) = parse_uid(i).expect("failed in parsing uid");
    assert_eq!(uid, 501);
    let (i, gid) = parse_gid(i).expect("failed in parsing gid");
    assert_eq!(gid, 20);
    let (i, mode) = parse_mode(i).expect("failed in parsing mode");
    assert_eq!(mode, 0o100644);
    let (_, size) = parse_size(i).expect("failed in parsing size");
    assert_eq!(size, 7);
}

fn parse_entry_header_terminator(input: &[u8]) -> IResult<&[u8], &[u8]> {
    tag(b"`\n")(input)
}

fn parse_entry_header(input: &[u8]) -> IResult<&[u8], EntryHeader> {
    let (i, identifier) = parse_identifier(input).expect("failed in parsing entry identifier");
    let (i, mtime) = parse_mtime(i).expect("failed in parsing mtime");
    let (i, uid) = parse_uid(i).expect("failed in parsing uid");
    let (i, gid) = parse_gid(i).expect("failed in parsing gid");
    let (i, mode) = parse_mode(i).expect("failed in parsing mode");
    let (i, size) = parse_size(i).expect("failed in parsing size");
    let (i, _) =
        parse_entry_header_terminator(i).expect("failed in parsing entry header terminator");
    let entry_header = EntryHeader {
        identifier,
        mtime,
        uid: uid as u32,
        gid: gid as u32,
        mode: mode as u32,
        size,
    };
    Ok((i, entry_header))
}

#[test]
fn test_parse_entry_header() {
    let input = "\
        !<arch>\n\
        foo.txt         1487552916  501   20    100644  7         `\n\
        foobar\n\n\
        bar.awesome.txt 1487552919  501   20    100644  22        `\n\
        This file is awesome!\n\
        baz.txt         1487552349  42    12345 100664  4         `\n\
        baz\n";
    let (i, file_sig) =
        parse_file_signature(input.as_bytes()).expect("failed in parsing file signature");
    assert_eq!(file_sig, b"!<arch>\n");
    let (_, entry_header) = parse_entry_header(i).expect("failed in parsing entry header");
    assert_eq!(entry_header.identifier, b"foo.txt");
    assert_eq!(entry_header.mtime, 1487552916);
    assert_eq!(entry_header.uid, 501);
    assert_eq!(entry_header.gid, 20);
    assert_eq!(entry_header.mode, 0o100644);
    assert_eq!(entry_header.size, 7);
}

//______________________________ Entry Data ______________________________

fn parse_entry_data(input: &[u8], size: u64) -> IResult<&[u8], &[u8]> {
    take(size)(input)
}

#[test]
fn test_parse_entry_data() {
    let input = "\
        !<arch>\n\
        foo.txt         1487552916  501   20    100644  7         `\n\
        foobar\n\n\
        bar.awesome.txt 1487552919  501   20    100644  22        `\n\
        This file is awesome!\n\
        baz.txt         1487552349  42    12345 100664  4         `\n\
        baz\n";
    let (i, file_sig) =
        parse_file_signature(input.as_bytes()).expect("failed in parsing file signature");
    assert_eq!(file_sig, b"!<arch>\n");
    let (i, entry_header) = parse_entry_header(i).expect("failed in parsing entry header");
    assert_eq!(entry_header.identifier, b"foo.txt");
    assert_eq!(entry_header.mtime, 1487552916);
    assert_eq!(entry_header.uid, 501);
    assert_eq!(entry_header.gid, 20);
    assert_eq!(entry_header.mode, 0o100644);
    assert_eq!(entry_header.size, 7);
    let (_, data) = parse_entry_data(i, entry_header.size).expect("failed in parsing entry data");
    assert_eq!(data, "foobar\n".as_bytes());
}

//______________________________ Entry ______________________________

#[derive(Debug, PartialEq)]
struct Entry {
    header: EntryHeader,
    data: Vec<u8>,
}

fn parse_newline_padding(input: &[u8]) -> IResult<&[u8], Vec<&[u8]>> {
    many0(tag(b"\n"))(input)
}

fn parse_entry(input: &[u8]) -> IResult<&[u8], Entry> {
    let (i, header) = parse_entry_header(input).expect("failed in parsing entry header");
    let (i, data) = parse_entry_data(i, header.size).expect("failed in parsing entry data");
    let (i, _) = parse_newline_padding(i).expect("failed in parsing newline padding");
    let entry = Entry {
        header,
        data: data.to_vec(),
    };
    Ok((i, entry))
}

//______________________________ Complete Parser ______________________________

fn parser(input: &[u8]) -> IResult<&[u8], (Vec<Entry>, &[u8])> {
    let (i, _) = parse_file_signature(input).expect("failed in parsing file signature");
    many_till(parse_entry, eof)(i)
}

#[test]
fn test_parser() {
    let input = "\
        !<arch>\n\
        foo.txt         1487552916  501   20    100644  7         `\n\
        foobar\n\n\
        bar.awesome.txt 1487552919  501   20    100644  22        `\n\
        This file is awesome!\n\
        baz.txt         1487552349  42    12345 100664  4         `\n\
        baz\n";
    let (i, (entries, empty)) =
        parser(input.as_bytes()).expect("failed in parsing the archive file");
    assert_eq!(i, b"");
    assert_eq!(empty, b"");

    assert_eq!(entries[0].header.identifier, b"foo.txt");
    assert_eq!(entries[0].header.mtime, 1487552916);
    assert_eq!(entries[0].header.uid, 501);
    assert_eq!(entries[0].header.gid, 20);
    assert_eq!(entries[0].header.mode, 0o100644);
    assert_eq!(entries[0].header.size, 7);
    assert_eq!(entries[0].data, "foobar\n".as_bytes());

    assert_eq!(entries[1].header.identifier, b"bar.awesome.txt");
    assert_eq!(entries[1].header.mtime, 1487552919);
    assert_eq!(entries[1].header.uid, 501);
    assert_eq!(entries[1].header.gid, 20);
    assert_eq!(entries[1].header.mode, 0o100644);
    assert_eq!(entries[1].header.size, 22);
    assert_eq!(entries[1].data, "This file is awesome!\n".as_bytes());
}
