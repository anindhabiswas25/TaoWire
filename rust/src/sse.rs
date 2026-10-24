//! Streaming responses over SSE with a signed trailer (spec 9.2, D29, D35):
//! what the miner ([`crate::axum::stream_response`]) and the client
//! ([`crate::client::Client::stream`]) share. The same rules as the Python
//! reference (`taowire.extensions.streaming`):
//!
//! ```text
//! event: chunk
//! data: {"token": "Hel"}
//!
//! event: tw-end
//! data: {"digest": "<sha256 hex>", "count": 1, "signature": "0x..."}
//! ```
//!
//! `digest` is sha256 over the concatenation of every chunk's exact `data`
//! bytes; the trailer signature is the twresp/1 payload with status 200 and
//! the digest as the body hash. Chunks are JSON objects or arrays: they are
//! self-delimiting, so a relay cannot move chunk boundaries under a valid
//! signature.

use std::collections::HashMap;
use std::fmt;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde::de::{self, Deserializer, IgnoredAny, MapAccess, Visitor};
use serde::Deserialize as _;
use sha2::{Digest as _, Sha256};

use crate::error::{codes, Error};

/// `Content-Type` of a stream.
pub const CONTENT_TYPE: &str = "text/event-stream";
/// Event name of a chunk.
pub const EVENT_CHUNK: &str = "chunk";
/// Event name of the trailer.
pub const EVENT_END: &str = "tw-end";
/// Deepest JSON nesting accepted in a chunk, on both sides. Python refuses
/// deep chunks only through its recursion limit (about 1000); Go, Rust and
/// TypeScript use 128, the stricter value.
pub const MAX_CHUNK_DEPTH: usize = 128;

/// Per-stream limits (spec 9.2); both the miner and the client enforce them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StreamLimits {
    max_duration: Duration,
    max_bytes: u64,
    idle: Duration,
}

impl Default for StreamLimits {
    /// `TW_STREAM_MAX_S` 60 s, `TW_STREAM_MAX_BYTES` 4 MiB, `TW_STREAM_IDLE_S` 10 s.
    fn default() -> Self {
        Self {
            max_duration: Duration::from_secs(60),
            max_bytes: 4 << 20,
            idle: Duration::from_secs(10),
        }
    }
}

impl StreamLimits {
    /// Limits checked against the ranges of spec 12.1: `max_duration` 1–600 s
    /// (the whole stream), `max_bytes` 1 KiB–64 MiB (on the wire), `idle`
    /// 1–120 s (the longest gap between two events).
    pub fn new(max_duration: Duration, max_bytes: u64, idle: Duration) -> Result<Self, String> {
        if !(Duration::from_secs(1)..=Duration::from_secs(600)).contains(&max_duration) {
            return Err("stream max_duration must be between 1 s and 600 s".into());
        }
        if !(1024..=64 << 20).contains(&max_bytes) {
            return Err("stream max_bytes must be between 1 KiB and 64 MiB".into());
        }
        if !(Duration::from_secs(1)..=Duration::from_secs(120)).contains(&idle) {
            return Err("stream idle must be between 1 s and 120 s".into());
        }
        Ok(Self { max_duration, max_bytes, idle })
    }

    /// The whole stream.
    pub fn max_duration(&self) -> Duration {
        self.max_duration
    }

    /// Bytes on the wire.
    pub fn max_bytes(&self) -> u64 {
        self.max_bytes
    }

    /// The longest gap between two events.
    pub fn idle(&self) -> Duration {
        self.idle
    }
}

/// A chunk is not a JSON object or array (or not JSON at all).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("chunk: {0}")]
pub struct ChunkError(pub &'static str);

/// The `tw-end` data is not a well-formed trailer.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("tw-end: {0}")]
pub struct TrailerError(pub String);

fn first_non_space(data: &[u8], set: &[u8]) -> Option<u8> {
    data.iter().copied().find(|b| !set.contains(b))
}

/// The deepest nesting of valid JSON text (strings skipped).
fn json_depth(data: &[u8]) -> usize {
    let (mut depth, mut deepest) = (0usize, 0usize);
    let (mut in_string, mut escaped) = (false, false);
    for &b in data {
        if in_string {
            if escaped {
                escaped = false;
            } else if b == b'\\' {
                escaped = true;
            } else if b == b'"' {
                in_string = false;
            }
            continue;
        }
        match b {
            b'"' => in_string = true,
            b'{' | b'[' => {
                depth += 1;
                deepest = deepest.max(depth);
            }
            b'}' | b']' => depth = depth.saturating_sub(1),
            _ => {}
        }
    }
    deepest
}

/// Check one chunk's `data` (client side): UTF-8, valid JSON, an object or
/// array, no deeper than [`MAX_CHUNK_DEPTH`]. Numbers are never decoded (no
/// range check).
pub fn decode_chunk(data: &[u8]) -> Result<(), ChunkError> {
    if std::str::from_utf8(data).is_err() {
        return Err(ChunkError("chunk is not valid JSON"));
    }
    if !matches!(first_non_space(data, b" \t\r\n"), Some(b'{' | b'[')) {
        return Err(ChunkError("chunk must be a JSON object or array"));
    }
    // Depth first: serde_json's own recursion limit must not decide it.
    if json_depth(data) > MAX_CHUNK_DEPTH {
        return Err(ChunkError("chunk is nested too deeply"));
    }
    let mut de = serde_json::Deserializer::from_slice(data);
    de.disable_recursion_limit();
    IgnoredAny::deserialize(&mut de)
        .and_then(|_| de.end())
        .map_err(|_| ChunkError("chunk is not valid JSON"))
}

/// The `data` bytes of one chunk (miner side): bytes holding a JSON object or
/// array, sent as they are. Line breaks are refused.
pub fn encode_chunk(data: &[u8]) -> Result<&[u8], ChunkError> {
    if data.contains(&b'\n') || data.contains(&b'\r') {
        return Err(ChunkError("chunk contains a line break"));
    }
    if !matches!(first_non_space(data, b" \t"), Some(b'{' | b'[')) {
        return Err(ChunkError("chunk must be a JSON object or array"));
    }
    decode_chunk(data)?;
    Ok(data)
}

/// Running sha256 over the chunks' `data` bytes, and their count.
#[derive(Debug, Clone, Default)]
pub struct StreamDigest {
    hash: Sha256,
    count: u64,
}

impl StreamDigest {
    /// An empty digest.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add one chunk's exact `data` bytes.
    pub fn update(&mut self, data: &[u8]) {
        self.hash.update(data);
        self.count += 1;
    }

    /// Chunks so far.
    pub fn count(&self) -> u64 {
        self.count
    }

    /// The digest so far, lowercase hex (the running hash continues).
    pub fn hex(&self) -> String {
        hex::encode(self.hash.clone().finalize())
    }
}

/// The `tw-end` event's data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Trailer {
    /// sha256 of the chunks, lowercase hex.
    pub digest: String,
    /// Number of chunks.
    pub count: u64,
    /// `0x` + hex; `None` when the miner does not sign responses.
    pub signature: Option<String>,
}

/// The `tw-end` data bytes (compact JSON, the Python reference's key order).
pub fn encode_trailer(t: &Trailer) -> Vec<u8> {
    let quote = |s: &str| serde_json::Value::from(s).to_string();
    let mut out = format!(r#"{{"digest":{},"count":{}"#, quote(&t.digest), t.count);
    if let Some(sig) = &t.signature {
        out.push_str(&format!(r#","signature":{}"#, quote(sig)));
    }
    out.push('}');
    out.into_bytes()
}

struct Count(u64);

impl<'de> de::Deserialize<'de> for Count {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct V;
        impl Visitor<'_> for V {
            type Value = Count;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("an integer >= 0")
            }
            // Only a plain non-negative integer literal arrives here: "-0",
            // floats, exponents and integers above u64 come as i64 / f64.
            fn visit_u64<E: de::Error>(self, v: u64) -> Result<Count, E> {
                Ok(Count(v))
            }
        }
        d.deserialize_u64(V)
    }
}

struct RawTrailer(Trailer);

impl<'de> de::Deserialize<'de> for RawTrailer {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct V;
        impl<'de> Visitor<'de> for V {
            type Value = RawTrailer;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a tw-end object")
            }
            fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<RawTrailer, A::Error> {
                let (mut digest, mut count, mut signature) = (None, None, None);
                while let Some(key) = map.next_key::<String>()? {
                    let dup = match key.as_str() {
                        "digest" => digest.replace(map.next_value::<String>()?).is_some(),
                        "count" => count.replace(map.next_value::<Count>()?.0).is_some(),
                        "signature" => signature.replace(map.next_value::<String>()?).is_some(),
                        _ => return Err(de::Error::custom("unknown key")),
                    };
                    if dup {
                        return Err(de::Error::custom("duplicate key"));
                    }
                }
                match (digest, count) {
                    (Some(digest), Some(count)) => {
                        Ok(RawTrailer(Trailer { digest, count, signature }))
                    }
                    _ => Err(de::Error::custom("digest and count are required")),
                }
            }
        }
        d.deserialize_map(V)
    }
}

/// Parse `tw-end` data strictly: a JSON object with exactly `digest` (64
/// lowercase hex), `count` (an integer literal >= 0 that fits a u64) and
/// optionally `signature` (a string), no other key, no key twice.
pub fn parse_trailer(data: &[u8]) -> Result<Trailer, TrailerError> {
    let t = serde_json::from_slice::<RawTrailer>(data)
        .map_err(|e| TrailerError(format!("not a well-formed tw-end object ({e})")))?
        .0;
    if t.digest.len() != 64 || !t.digest.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
        return Err(TrailerError("digest must be 64 lowercase hex characters".into()));
    }
    Ok(t)
}

/// One SSE frame: `event: <event>`, one `data:` line, a blank line. Line
/// breaks in either are refused.
pub fn encode_event(event: &str, data: &[u8]) -> Result<Vec<u8>, Error> {
    let has_break = |b: &[u8]| b.contains(&b'\n') || b.contains(&b'\r');
    if has_break(event.as_bytes()) || has_break(data) {
        return Err(Error::new(
            codes::INTERNAL,
            "SSE event names and data must not contain line breaks",
        ));
    }
    let mut out = Vec::with_capacity(event.len() + data.len() + 17);
    out.extend_from_slice(b"event: ");
    out.extend_from_slice(event.as_bytes());
    out.extend_from_slice(b"\ndata: ");
    out.extend_from_slice(data);
    out.extend_from_slice(b"\n\n");
    Ok(out)
}

/// Bytes the miner keeps free under `max_bytes` for the `tw-end` frame: the
/// largest possible one (a 20-digit count, a 64-byte signature), so a stream
/// the miner finishes always fits a client using the same limit.
pub const TRAILER_RESERVE: u64 = 273;

/// One dispatched event: its type and its data bytes (lines joined by LF).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Event {
    /// The event type (`message` when none or an empty one was given).
    pub event: String,
    /// The data bytes.
    pub data: Vec<u8>,
}

const BOM: &[u8] = b"\xef\xbb\xbf";

/// Incremental SSE parser over raw bytes (WHATWG "event stream" rules), the
/// same as the Python reference's `SSEParser`. Lines end with CRLF, LF or CR;
/// `:` lines are comments; `field[: value]` with one leading space removed; a
/// line without a colon is a field with an empty value; `data` lines are
/// joined with LF; `event` sets the type (empty or absent: `message`); `id`,
/// `retry` and unknown fields are ignored; a blank line dispatches an event
/// that has data. A UTF-8 BOM at the very start is skipped. [`Parser::feed`]
/// never fails; [`Parser::finish`] drops an unfinished event. Each byte is
/// scanned once.
#[derive(Debug, Default)]
pub struct Parser {
    buf: Vec<u8>,
    scanned: usize,
    started: bool,
    event: Option<String>,
    data: Vec<Vec<u8>>,
    has_data: bool,
}

impl Parser {
    /// An empty parser.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add bytes; the events they complete, in order.
    pub fn feed(&mut self, chunk: &[u8]) -> Vec<Event> {
        self.buf.extend_from_slice(chunk);
        if !self.started {
            if self.buf.len() < BOM.len() && BOM.starts_with(&self.buf) {
                return Vec::new();
            }
            if self.buf.starts_with(BOM) {
                self.buf.drain(..BOM.len());
            }
            self.started = true;
        }
        self.lines(false)
    }

    /// End of stream: a final CR ends its line; an unfinished event is
    /// dropped. The parser is reset.
    pub fn finish(&mut self) -> Vec<Event> {
        let events = self.lines(true);
        *self = Self::default();
        events
    }

    fn lines(&mut self, last: bool) -> Vec<Event> {
        let mut events = Vec::new();
        let (mut start, mut i) = (0, self.scanned);
        while let Some(j) = self.buf[i..].iter().position(|&b| b == b'\r' || b == b'\n') {
            i += j;
            let mut end = i + 1;
            if self.buf[i] == b'\r' {
                if end == self.buf.len() && !last {
                    break; // may be the first half of a CRLF split across feeds
                }
                if self.buf.get(end) == Some(&b'\n') {
                    end += 1;
                }
            }
            let line = self.buf[start..i].to_vec();
            if let Some(ev) = self.line(&line) {
                events.push(ev);
            }
            start = end;
            i = end;
        }
        self.buf.drain(..start);
        // Scan only new bytes next time; a trailing CR is looked at again.
        self.scanned = self.buf.len() - usize::from(self.buf.last() == Some(&b'\r'));
        events
    }

    fn line(&mut self, line: &[u8]) -> Option<Event> {
        if line.is_empty() {
            return self.dispatch();
        }
        if line[0] == b':' {
            return None; // comment
        }
        let (name, value) = match line.iter().position(|&b| b == b':') {
            None => (line, &[][..]),
            Some(k) => {
                let v = &line[k + 1..];
                (&line[..k], v.strip_prefix(b" ").unwrap_or(v))
            }
        };
        match name {
            b"data" => {
                self.data.push(value.to_vec());
                self.has_data = true;
            }
            b"event" => self.event = Some(String::from_utf8_lossy(value).into_owned()),
            _ => {}
        }
        None
    }

    fn dispatch(&mut self) -> Option<Event> {
        let event = self.event.take().filter(|e| !e.is_empty());
        let data = std::mem::take(&mut self.data);
        if !std::mem::take(&mut self.has_data) {
            return None;
        }
        Some(Event { event: event.unwrap_or_else(|| "message".into()), data: data.join(&b'\n') })
    }
}

/// Range of [`StreamSlots`] limits (`TW_STREAM_MAX_PER_CALLER`, spec 12.1, D36).
pub const STREAMS_PER_CALLER_RANGE: std::ops::RangeInclusive<usize> = 1..=256;
/// Default open streams per caller.
pub const DEFAULT_STREAMS_PER_CALLER: usize = 16;

/// Open streams per caller hotkey in this process (spec 9.2, D36). Streams
/// live up to `max_duration`, far longer than a plain request, so without it
/// one permitted validator could fill the server's connections and starve the
/// others.
#[derive(Debug)]
pub struct StreamSlots {
    limit: usize,
    open: Mutex<HashMap<String, usize>>,
}

impl Default for StreamSlots {
    /// 16 open streams per caller.
    fn default() -> Self {
        Self { limit: DEFAULT_STREAMS_PER_CALLER, open: Mutex::default() }
    }
}

/// A taken stream slot; dropping it gives the slot back.
#[derive(Debug)]
pub struct StreamSlot {
    slots: Arc<StreamSlots>,
    hotkey: String,
}

impl Drop for StreamSlot {
    fn drop(&mut self) {
        let mut open = self.slots.open.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(n) = open.get_mut(&self.hotkey) {
            *n -= 1;
            if *n == 0 {
                open.remove(&self.hotkey);
            }
        }
    }
}

impl StreamSlots {
    /// Slots allowing `limit` open streams per caller (1..=256).
    pub fn new(limit: usize) -> Result<Self, String> {
        if !STREAMS_PER_CALLER_RANGE.contains(&limit) {
            return Err("streams per caller must be between 1 and 256".into());
        }
        Ok(Self { limit, open: Mutex::default() })
    }

    /// Take a slot for `hotkey`, or `tw.rate_limited` (429).
    pub fn acquire(self: &Arc<Self>, hotkey: &str) -> Result<StreamSlot, Error> {
        let mut open = self.open.lock().unwrap_or_else(|p| p.into_inner());
        let n = open.entry(hotkey.to_owned()).or_insert(0);
        if *n >= self.limit {
            return Err(Error::new(codes::RATE_LIMITED, "open streams per caller"));
        }
        *n += 1;
        Ok(StreamSlot { slots: Arc::clone(self), hotkey: hotkey.to_owned() })
    }

    /// How many streams `hotkey` holds now.
    pub fn open(&self, hotkey: &str) -> usize {
        self.open.lock().unwrap_or_else(|p| p.into_inner()).get(hotkey).copied().unwrap_or(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trailer_reserve_is_the_largest_trailer_frame() {
        let t = Trailer {
            digest: "0".repeat(64),
            count: u64::MAX,
            signature: Some(format!("0x{}", "0".repeat(128))),
        };
        assert_eq!(
            encode_event(EVENT_END, &encode_trailer(&t)).unwrap().len() as u64,
            TRAILER_RESERVE
        );
    }
}
