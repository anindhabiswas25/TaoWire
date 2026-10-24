// Unit tests: payload, nonces, SS58, keys and the weak-key rule, errors, headers.
import { chmodSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { beforeAll, describe, expect, it } from "vitest";
import {
    Keypair,
    NonceSource,
    SS58Error,
    TWError,
    buildPayload,
    decodeSS58,
    encodeSS58,
    errorBody,
    initCrypto,
    isWeakPublicKey,
    statusOf,
    TokenBuckets,
    verifySignature,
} from "@taowire/btauth";
import { headerMap } from "../src/headers.js";
import { devKeys, keypair } from "./helpers.js";

beforeAll(initCrypto);

describe("buildPayload", () => {
    it("keeps nonces above 2^53 exact", () => {
        const nonce = 2n ** 63n + 12345n;
        const text = new TextDecoder().decode(
            buildPayload({
                scheme: "sr25519",
                method: "get",
                target: "/x",
                body: new Uint8Array(),
                nonceNs: nonce,
                sender: "a",
                receiver: null,
            }),
        );
        expect(text.split("\n")).toEqual([
            "btauth/1",
            "sr25519",
            "GET",
            "/x",
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "9223372036854788153",
            "a",
            "-",
        ]);
    });
});

describe("NonceSource", () => {
    it("is strictly increasing when the clock stands still or goes back", () => {
        let now = 1_000n;
        const n = new NonceSource(() => now);
        expect(n.next()).toBe(1_000n);
        expect(n.next()).toBe(1_001n);
        now = 10n;
        expect(n.next()).toBe(1_002n);
        now = 5_000n;
        expect(n.next()).toBe(5_000n);
    });
    it("uses nanoseconds of the wall clock by default", () => {
        const v = new NonceSource().next();
        expect(typeof v).toBe("bigint");
        expect(v > 1_700_000_000_000_000_000n).toBe(true);
    });
});

describe("SS58", () => {
    const alice = devKeys().alice_sr25519!;
    it("round-trips", () => {
        const key = decodeSS58(alice.ss58);
        expect(encodeSS58(key)).toBe(alice.ss58);
    });
    it.each([
        ["empty", ""],
        ["47 chars", alice.ss58.slice(0, 47)],
        ["49 chars", `${alice.ss58}1`],
        ["bad alphabet", `0${alice.ss58.slice(1)}`],
        ["bad checksum", `${alice.ss58.slice(0, 47)}${alice.ss58.endsWith("Y") ? "Z" : "Y"}`],
        ["polkadot prefix", "15oF4uVJwmo4TdGW7VfQxNLavjCXviqxT9S1MgbjMNHr6Sp5"],
    ])("refuses %s", (_name, address) => {
        expect(() => decodeSS58(address)).toThrow(SS58Error);
    });
    it("refuses a long sender before decoding (D19)", () => {
        const long = "5".repeat(64 * 1024);
        const start = performance.now();
        for (let i = 0; i < 100; i++) {
            expect(() => decodeSS58(long)).toThrow(SS58Error);
        }
        expect((performance.now() - start) / 100).toBeLessThan(1);
    });
    it("encode refuses a key that is not 32 bytes", () => {
        expect(() => encodeSS58(new Uint8Array(31))).toThrow(RangeError);
    });
});

// The eight small-order ed25519 points (orders 1, 2, 4, 8), canonical encodings.
const SMALL_ORDER = [
    "0100000000000000000000000000000000000000000000000000000000000000",
    "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
    "0000000000000000000000000000000000000000000000000000000000000080",
    "0000000000000000000000000000000000000000000000000000000000000000",
    "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
    "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa",
    "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
    "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85",
];

describe("isWeakPublicKey (ADR-0010)", () => {
    it.each(SMALL_ORDER)("ed25519 small-order point %s is weak", (hex) => {
        expect(isWeakPublicKey("ed25519", Buffer.from(hex, "hex"))).toBe(true);
    });
    it("real keys are not weak", () => {
        for (const k of Object.values(devKeys())) {
            expect(isWeakPublicKey(k.scheme, Buffer.from(k.public_key_hex, "hex"))).toBe(false);
        }
    });
    it("sr25519: only the identity", () => {
        expect(isWeakPublicKey("sr25519", new Uint8Array(32))).toBe(true);
        expect(isWeakPublicKey("sr25519", Buffer.from(SMALL_ORDER[0]!, "hex"))).toBe(false);
    });
    it("a non-point is not weak", () => {
        // y = 2 is not on the curve
        const notPoint = new Uint8Array(32);
        notPoint[0] = 2;
        expect(isWeakPublicKey("ed25519", notPoint)).toBe(false);
    });
    it("refuses other lengths", () => {
        expect(() => isWeakPublicKey("ed25519", new Uint8Array(31))).toThrow(RangeError);
    });
    it("the universal signature of the identity never verifies", () => {
        const identity = Buffer.from(SMALL_ORDER[0]!, "hex");
        const sig = Buffer.concat([identity, Buffer.alloc(32)]);
        expect(verifySignature("ed25519", identity, new TextEncoder().encode("any"), sig)).toBe(false);
    });
});

describe("Keypair", () => {
    it("signs and verifies under its scheme only", () => {
        const msg = new TextEncoder().encode("hello");
        for (const name of ["alice_sr25519", "alice_ed25519"] as const) {
            const k = keypair(name);
            const sig = k.sign(msg);
            expect(verifySignature(k.scheme, k.publicKey, msg, sig)).toBe(true);
            const other = k.scheme === "ed25519" ? "sr25519" : "ed25519";
            expect(verifySignature(other, k.publicKey, msg, sig)).toBe(false);
            expect(verifySignature(k.scheme, k.publicKey, msg, sig.subarray(0, 63))).toBe(false);
            expect(verifySignature(k.scheme, k.publicKey.subarray(0, 31), msg, sig)).toBe(false);
        }
    });
    it("never shows key material", () => {
        const k = keypair("alice_sr25519");
        expect(String(k)).toBe(`Keypair(${k.ss58}, sr25519)`);
        expect(JSON.stringify(k)).toBe(JSON.stringify({ ss58: k.ss58, scheme: "sr25519" }));
    });
    it("refuses seeds that are not 32 bytes", () => {
        expect(() => Keypair.sr25519FromSeed(new Uint8Array(31))).toThrow(RangeError);
        expect(() => Keypair.ed25519FromSeed(new Uint8Array(33))).toThrow(RangeError);
    });

    describe("fromHotkeyFile", () => {
        const dir = mkdtempSync(join(tmpdir(), "tw-hotkey-"));
        const alice = devKeys().alice_sr25519!;
        const write = (name: string, content: string, mode = 0o600): string => {
            const path = join(dir, name);
            writeFileSync(path, content);
            chmodSync(path, mode);
            return path;
        };
        it("reads secretSeed", () => {
            const path = write(
                "seed",
                JSON.stringify({ secretSeed: `0x${alice.secret_seed_hex}`, ss58Address: alice.ss58 }),
            );
            expect(Keypair.fromHotkeyFile(path).ss58).toBe(alice.ss58);
        });
        it("reads secretPhrase", () => {
            const phrase = "bottom drive obey lake curtain smoke basket hold race lonely fit walk";
            const path = write("phrase", JSON.stringify({ secretPhrase: phrase }));
            // the substrate dev phrase: its sr25519 root key
            expect(Keypair.fromHotkeyFile(path).ss58).toBe(
                "5DfhGyQdFobKM8NsWvEeAKk5EQQgYe9AydgJ7rMB6E1EqRzV",
            );
        });
        it("refuses a group- or world-readable file", () => {
            const path = write("open", JSON.stringify({ secretSeed: `0x${alice.secret_seed_hex}` }), 0o644);
            expect(() => Keypair.fromHotkeyFile(path)).toThrow(/readable by group or others/);
        });
        it("refuses a mismatched address, bad JSON, no secret, bad phrase", () => {
            const bob = devKeys().bob_sr25519!;
            expect(() =>
                Keypair.fromHotkeyFile(
                    write(
                        "mismatch",
                        JSON.stringify({ secretSeed: `0x${alice.secret_seed_hex}`, ss58Address: bob.ss58 }),
                    ),
                ),
            ).toThrow(/does not match/);
            expect(() => Keypair.fromHotkeyFile(write("bad", "{"))).toThrow(/not JSON/);
            expect(() => Keypair.fromHotkeyFile(write("none", "{}"))).toThrow(/no secretSeed/);
            expect(() => Keypair.fromHotkeyFile(write("null", "null"))).toThrow(/no secretSeed/);
            expect(() =>
                Keypair.fromHotkeyFile(write("phrase2", JSON.stringify({ secretPhrase: "not a mnemonic" }))),
            ).toThrow(/not a valid mnemonic/);
        });
        it("error messages never contain the secret", () => {
            const path = write(
                "leak",
                JSON.stringify({ secretSeed: `0x${alice.secret_seed_hex}`, ss58Address: "x" }),
            );
            try {
                Keypair.fromHotkeyFile(path);
            } catch (err) {
                expect(String(err)).not.toContain(alice.secret_seed_hex);
            }
        });
    });
});

describe("errors (Appendix A)", () => {
    it.each([
        ["tw.auth_malformed", 401],
        ["tw.payload_too_large", 413],
        ["tw.rate_limited", 429],
        ["tw.forbidden_not_validator", 403],
        ["tw.invalid_request", 422],
        ["tw.handler_error", 500],
        ["tw.metagraph_stale", 503],
        ["tw.replay_store_unavailable", 503],
        ["tw.handler_timeout", 504],
        ["tw.legacy_disabled", 410],
    ])("%s is %i", (code, status) => {
        expect(new TWError(code).status).toBe(status);
        expect(statusOf(code)).toBe(status);
    });
    it("unknown codes become tw.internal 500", () => {
        const e = new TWError("tw.typo", "x");
        expect([e.code, e.status]).toEqual(["tw.internal", 500]);
        expect(statusOf("tw.typo")).toBe(500);
    });
    it("client codes have no status", () => {
        const e = new TWError("tw.timeout");
        expect([e.code, e.status, e.message]).toEqual(["tw.timeout", 0, "tw.timeout: tw.timeout"]);
    });
    it("error bodies carry the public message only", () => {
        const e = new TWError("tw.auth_stale", "secret detail");
        expect(JSON.parse(errorBody(e, "r1"))).toEqual({
            error: {
                code: "tw.auth_stale",
                message: "request nonce is outside the freshness window",
                request_id: "r1",
            },
        });
        expect(errorBody(e)).not.toContain("secret detail");
    });
});

describe("headerMap", () => {
    it("accepts pairs, raw headers and records", () => {
        expect([
            ...headerMap([
                ["A", "1"],
                ["a", "2"],
            ]),
        ]).toEqual([["a", ["1", "2"]]]);
        expect([...headerMap(["A", "1", "B", "2"])]).toEqual([
            ["a", ["1"]],
            ["b", ["2"]],
        ]);
        expect([...headerMap({ A: ["1", "2"], B: "3", C: undefined })]).toEqual([
            ["a", ["1", "2"]],
            ["b", ["3"]],
        ]);
        expect([...headerMap([])]).toEqual([]);
    });
    it("refuses a raw header list of odd length", () => {
        expect(() => headerMap(["A"])).toThrow(TypeError);
    });
});

describe("TokenBuckets", () => {
    it("refills at perS up to burst and reports Retry-After seconds", () => {
        let now = 0n;
        const b = new TokenBuckets({ perS: 2, burst: 2 }, () => now);
        expect([b.take("k"), b.take("k")]).toEqual([0, 0]);
        expect(b.take("k")).toBe(1);
        now += 500_000_000n;
        expect(b.take("k")).toBe(0);
        expect(b.take("other")).toBe(0);
    });
    it("drops full buckets when the map grows", () => {
        let now = 0n;
        const b = new TokenBuckets({ perS: 1000, burst: 1 }, () => now);
        for (let i = 0; i < 10_001; i++) {
            b.take(`k${i}`);
        }
        now += 1_000_000_000n;
        expect(b.take("last")).toBe(0);
    });
    it("refuses bad limits", () => {
        expect(() => new TokenBuckets({ perS: 0, burst: 1 })).toThrow(RangeError);
        expect(() => new TokenBuckets({ perS: 1, burst: 0.5 })).toThrow(RangeError);
        expect(() => new TokenBuckets({ perS: Infinity, burst: 1 })).toThrow(RangeError);
    });
});
