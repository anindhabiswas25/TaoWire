//! cargo fuzz target on the SSE parser (spec 9.2: it reads untrusted bytes):
//! arbitrary bytes split at an arbitrary point. It must never panic, and two
//! feeds must give the same events as one; the chunk decoder must never
//! panic either.
#![no_main]

use libfuzzer_sys::fuzz_target;
use taowire_btauth::sse::{decode_chunk, Parser};

fuzz_target!(|input: (u16, &[u8])| {
    let (cut, data) = input;
    let at = usize::from(cut) % (data.len() + 1);
    let mut whole = Parser::new();
    let mut want = whole.feed(data);
    want.extend(whole.finish());
    let mut split = Parser::new();
    let mut got = split.feed(&data[..at]);
    got.extend(split.feed(&data[at..]));
    got.extend(split.finish());
    assert_eq!(got, want);
    let _ = decode_chunk(data);
});
