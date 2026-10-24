/**
 * Hotkeys and signature verification: sr25519 (schnorrkel, context
 * `b"substrate"`) through `@polkadot/wasm-crypto` (WASM; `@polkadot/util-crypto`
 * 14 routes sr25519 through a pure-JS implementation about six times slower),
 * and ed25519 (RFC 8032) through `@polkadot/util-crypto` (WASM when ready).
 *
 * @module
 */
import { closeSync, fstatSync, openSync, readFileSync } from "node:fs";
import { hexToU8a, isHex } from "@polkadot/util";
import {
    cryptoIsReady,
    cryptoWaitReady,
    ed25519PairFromSeed,
    ed25519Sign,
    ed25519Verify,
    mnemonicToMiniSecret,
} from "@polkadot/util-crypto";
import {
    isReady as wasmIsReady,
    sr25519KeypairFromSeed,
    sr25519Sign,
    sr25519Verify,
} from "@polkadot/wasm-crypto";
import type { Scheme } from "./payload.js";
import { encodeSS58 } from "./ss58.js";

/**
 * Load the WASM crypto. Call (and await) it once at startup, before any
 * {@link Keypair} or verifier is used.
 */
export async function initCrypto(): Promise<void> {
    await cryptoWaitReady();
}

function requireCrypto(): void {
    if (!cryptoIsReady() || !wasmIsReady()) {
        throw new Error("btauth: call `await initCrypto()` once before signing or verifying");
    }
}

interface RawPair {
    publicKey: Uint8Array;
    secretKey: Uint8Array;
}

/**
 * A hotkey that can sign. Key material never leaves the object:
 * `toString()` and `JSON.stringify` show the address only.
 */
export class Keypair {
    /** The signature scheme. */
    readonly scheme: Scheme;
    /** The raw 32-byte public key. */
    readonly publicKey: Uint8Array;
    /** The key's prefix-42 SS58 address. */
    readonly ss58: string;
    readonly #pair: RawPair;

    private constructor(scheme: Scheme, pair: RawPair) {
        this.scheme = scheme;
        this.#pair = pair;
        this.publicKey = pair.publicKey;
        this.ss58 = encodeSS58(pair.publicKey);
    }

    /** An sr25519 hotkey from its 32-byte mini secret (`secretSeed` of a hotkey file). */
    static sr25519FromSeed(seed: Uint8Array): Keypair {
        requireCrypto();
        checkSeed(seed);
        const pair = sr25519KeypairFromSeed(seed); // 64-byte secret, then the 32-byte public key
        return new Keypair("sr25519", { secretKey: pair.slice(0, 64), publicKey: pair.slice(64) });
    }

    /** An ed25519 hotkey from its 32-byte RFC 8032 seed. */
    static ed25519FromSeed(seed: Uint8Array): Keypair {
        requireCrypto();
        checkSeed(seed);
        return new Keypair("ed25519", ed25519PairFromSeed(seed));
    }

    /** A hotkey from a 32-byte seed under `scheme`. */
    static fromSeed(scheme: Scheme, seed: Uint8Array): Keypair {
        return scheme === "ed25519" ? Keypair.ed25519FromSeed(seed) : Keypair.sr25519FromSeed(seed);
    }

    /**
     * A hotkey from a Bittensor hotkey JSON file: `secretSeed` (hex), or else
     * `secretPhrase` (a mnemonic). The file must not be readable by group or
     * others (`chmod 600`). If the file has `ss58Address`, it must match.
     * Errors name the file, never its contents.
     */
    static fromHotkeyFile(path: string, scheme: Scheme = "sr25519"): Keypair {
        // One descriptor for the mode check and the read: the file checked is the file read.
        const fd = openSync(path, "r");
        let text: string;
        try {
            if (process.platform !== "win32" && (fstatSync(fd).mode & 0o044) !== 0) {
                throw new Error(`hotkey file ${path} is readable by group or others; run: chmod 600 ${path}`);
            }
            text = readFileSync(fd, "utf8");
        } finally {
            closeSync(fd);
        }
        let data: unknown;
        try {
            data = JSON.parse(text);
        } catch {
            throw new Error(`hotkey file ${path} is not JSON`);
        }
        const fields = (typeof data === "object" && data !== null ? data : {}) as Record<string, unknown>;
        let seed: Uint8Array;
        if (typeof fields.secretSeed === "string" && isHex(fields.secretSeed, 256)) {
            seed = hexToU8a(fields.secretSeed);
        } else if (typeof fields.secretPhrase === "string") {
            requireCrypto();
            try {
                seed = mnemonicToMiniSecret(fields.secretPhrase);
            } catch {
                throw new Error(`hotkey file ${path}: secretPhrase is not a valid mnemonic`);
            }
        } else {
            throw new Error(`hotkey file ${path} has no secretSeed (0x + 64 hex) or secretPhrase`);
        }
        const key = Keypair.fromSeed(scheme, seed);
        if (fields.ss58Address !== undefined && fields.ss58Address !== key.ss58) {
            throw new Error(`hotkey file ${path}: the seed does not match its ss58Address under ${scheme}`);
        }
        return key;
    }

    /**
     * Sign exactly `message`, never a wrapped form. ed25519 signatures are
     * deterministic; sr25519 signatures are randomized.
     */
    sign(message: Uint8Array): Uint8Array {
        requireCrypto();
        return this.scheme === "ed25519"
            ? ed25519Sign(message, this.#pair)
            : sr25519Sign(this.#pair.publicKey, this.#pair.secretKey, message);
    }

    /** The address and scheme only. */
    toString(): string {
        return `Keypair(${this.ss58}, ${this.scheme})`;
    }

    /** The address and scheme only. */
    toJSON(): { ss58: string; scheme: Scheme } {
        return { ss58: this.ss58, scheme: this.scheme };
    }
}

/** A signature as sent in headers: `0x` + lowercase hex. */
export function signatureHex(signature: Uint8Array): string {
    return `0x${Buffer.from(signature).toString("hex")}`;
}

function checkSeed(seed: Uint8Array): void {
    if (seed.length !== 32) {
        throw new RangeError("a seed is 32 bytes");
    }
}

/**
 * Every ed25519 public key whose point has order 1, 2, 4 or 8 under the rule of
 * Python's `crypto.is_weak_public_key` (the sign bit is ignored and y is
 * reduced mod p): y = 0 (order 4), 1 (identity), p − 1 (order 2), the two
 * order-8 y values, and the non-canonical y = p, p + 1, each with either sign
 * bit. Generated from that function; `test/weakkey.test.ts` checks it against
 * the same field arithmetic. A lookup costs nothing next to the ~250 µs of
 * BigInt arithmetic per ed25519 request.
 */
const WEAK_ED25519: ReadonlySet<string> = new Set([
    "0000000000000000000000000000000000000000000000000000000000000000",
    "0000000000000000000000000000000000000000000000000000000000000080",
    "0100000000000000000000000000000000000000000000000000000000000000",
    "0100000000000000000000000000000000000000000000000000000000000080",
    "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
    "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85",
    "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
    "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa",
    "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
    "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
    "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
    "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
    "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
    "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
]);

/**
 * Whether a public key has a signature that verifies for every message: the
 * sr25519 (ristretto) identity, or an ed25519 point of order 1, 2, 4 or 8.
 * Verifiers refuse such keys as a bad signature (spec 4.3 step 4, D20,
 * ADR-0010). Keys that are not curve points are not weak (they never verify).
 */
export function isWeakPublicKey(scheme: Scheme, publicKey: Uint8Array): boolean {
    if (publicKey.length !== 32) {
        throw new RangeError("a public key is 32 bytes");
    }
    if (scheme === "sr25519") {
        return publicKey.every((b) => b === 0);
    }
    return WEAK_ED25519.has(Buffer.from(publicKey).toString("hex"));
}

/**
 * Verify `signature` (64 bytes) over exactly `message` under `scheme` only
 * (spec 11.2 rules 6–8): `sr25519Verify` / `ed25519Verify`, never
 * `signatureVerify`, which also tries `<Bytes>`-wrapped forms. Weak public
 * keys never verify. Never throws for a key or signature that does not decode.
 */
export function verifySignature(
    scheme: Scheme,
    publicKey: Uint8Array,
    message: Uint8Array,
    signature: Uint8Array,
): boolean {
    requireCrypto();
    if (publicKey.length !== 32 || signature.length !== 64) {
        return false;
    }
    let ok: boolean;
    try {
        ok =
            scheme === "ed25519"
                ? ed25519Verify(message, signature, publicKey)
                : sr25519Verify(signature, message, publicKey);
    } catch {
        return false;
    }
    return ok && !isWeakPublicKey(scheme, publicKey);
}
