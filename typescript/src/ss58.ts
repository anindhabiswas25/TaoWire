/**
 * SS58 addresses, Bittensor prefix 42 only (spec Appendix D).
 *
 * @module
 */
import { base58Decode, base58Encode, blake2AsU8a } from "@polkadot/util-crypto";

/** Bittensor's SS58 network prefix. */
export const SS58_PREFIX = 42;

/**
 * Length of every prefix-42 address of a 32-byte key. Anything else is
 * refused **before** base58 decoding, which is quadratic in the input length
 * and runs on the sender header before any signature check (spec 4.3
 * step 1, D19).
 */
export const SS58_LENGTH = 48;

const CONTEXT = new TextEncoder().encode("SS58PRE");

/** The input is not a prefix-42 SS58 address. */
export class SS58Error extends Error {
    constructor() {
        super("not a Bittensor SS58 address (prefix 42)");
        this.name = "SS58Error";
    }
}

function checksum(raw: Uint8Array): Uint8Array {
    const input = new Uint8Array(CONTEXT.length + raw.length);
    input.set(CONTEXT);
    input.set(raw, CONTEXT.length);
    return blake2AsU8a(input, 512).subarray(0, 2);
}

/**
 * The 32-byte public key of a prefix-42 address. Throws {@link SS58Error}
 * for any other length, prefix, alphabet or checksum.
 */
export function decodeSS58(address: string): Uint8Array {
    if (address.length !== SS58_LENGTH) {
        throw new SS58Error();
    }
    let raw: Uint8Array;
    try {
        raw = base58Decode(address);
    } catch {
        throw new SS58Error();
    }
    if (raw.length !== 35 || raw[0] !== SS58_PREFIX) {
        throw new SS58Error();
    }
    const sum = checksum(raw.subarray(0, 33));
    if (sum[0] !== raw[33] || sum[1] !== raw[34]) {
        throw new SS58Error();
    }
    return raw.slice(1, 33);
}

/** The prefix-42 address of a 32-byte public key. */
export function encodeSS58(publicKey: Uint8Array): string {
    if (publicKey.length !== 32) {
        throw new RangeError("a public key is 32 bytes");
    }
    const raw = new Uint8Array(35);
    raw[0] = SS58_PREFIX;
    raw.set(publicKey, 1);
    raw.set(checksum(raw.subarray(0, 33)), 33);
    return base58Encode(raw);
}
