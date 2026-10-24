//! cargo fuzz target on the tw-end parser (spec 9.2): arbitrary data never
//! panics; it is either a well-formed trailer that re-encodes to the same
//! one, or a `TrailerError` (fail closed).
#![no_main]

use libfuzzer_sys::fuzz_target;
use tensorwire_btauth::sse::{encode_trailer, parse_trailer};

fuzz_target!(|data: &[u8]| {
    if let Ok(t) = parse_trailer(data) {
        assert_eq!(t.digest.len(), 64);
        assert_eq!(parse_trailer(&encode_trailer(&t)).as_ref(), Ok(&t));
    }
});
