use blake2::{Blake2b512, Digest};

/// Bittensor's SS58 network prefix.
pub const SS58_PREFIX: u8 = 42;

const SS58_LEN: usize = 48;

fn checksum(raw: &[u8]) -> [u8; 2] {
    let mut h = Blake2b512::new();
    h.update(b"SS58PRE");
    h.update(raw);
    let out = h.finalize();
    [out[0], out[1]]
}

/// The 32-byte public key of a prefix-42 SS58 address (spec Appendix D), or
/// `None` for other prefixes, lengths, bad base58 or a bad checksum.
pub fn decode_ss58(address: &str) -> Option<[u8; 32]> {
    // Every prefix-42 address is 48 characters. Longer input is refused before
    // decoding: base58 decoding is quadratic and runs before any signature check.
    if address.len() != SS58_LEN {
        return None;
    }
    let raw = bs58::decode(address).into_vec().ok()?;
    if raw.len() != 35 || raw[0] != SS58_PREFIX || checksum(&raw[..33]) != raw[33..] {
        return None;
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(&raw[1..33]);
    Some(key)
}

/// The prefix-42 SS58 address of a public key.
pub fn encode_ss58(public_key: &[u8; 32]) -> String {
    let mut raw = Vec::with_capacity(35);
    raw.push(SS58_PREFIX);
    raw.extend_from_slice(public_key);
    let c = checksum(&raw);
    raw.extend_from_slice(&c);
    bs58::encode(raw).into_string()
}
