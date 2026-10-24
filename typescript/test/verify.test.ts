// Verifier, stores and the clock-step guard (spec 4.3, 8.4.3-8.4.4, D21).
import { beforeAll, describe, expect, it } from "vitest";
import {
    MemoryStore,
    type NonceStore,
    Signer,
    StepGuard,
    TWError,
    Verifier,
    initCrypto,
    verifyRequest,
} from "@tensorwire/btauth";
import { keypair } from "./helpers.js";

beforeAll(initCrypto);

const S = 1_000_000_000n;
const T0 = 1_752_076_800n * S;

function setup(opts: { store?: NonceStore; now?: () => bigint; mono?: () => bigint } = {}) {
    const alice = keypair("alice_sr25519");
    const bob = keypair("bob_sr25519");
    let now = T0;
    const clock = opts.now ?? (() => now);
    const verifier = new Verifier({
        selfHotkey: bob.ss58,
        store: opts.store ?? new MemoryStore(60, { wallNs: clock, monoNs: opts.mono ?? clock }),
        nowNs: clock,
        ...(opts.mono === undefined ? {} : { monotonicNs: opts.mono }),
    });
    const signer = new Signer(alice, { next: () => now } as never);
    const body = new TextEncoder().encode('{"a":1}');
    const req = (target = "/v1/x") => {
        const { headers } = signer.sign("POST", target, body, bob.ss58);
        return { headers: Object.entries(headers), body, method: "POST", target };
    };
    return { alice, bob, verifier, req, setNow: (n: bigint) => (now = n), body };
}

async function code(p: Promise<unknown>): Promise<string> {
    try {
        await p;
        return "accepted";
    } catch (err) {
        expect(err).toBeInstanceOf(TWError);
        return (err as TWError).code;
    }
}

describe("Verifier", () => {
    it("accepts a fresh request once, then refuses the replay", async () => {
        const { verifier, req, alice } = setup();
        const r = req();
        const caller = await verifyRequest(verifier, r);
        expect(caller).toEqual({ hotkey: alice.ss58, nonce: T0, scheme: "sr25519" });
        expect(await code(verifier.verify(r))).toBe("tw.auth_replayed");
    });

    it("accepts ed25519 and Node rawHeaders input", async () => {
        const bob = keypair("bob_sr25519");
        const verifier = new Verifier({ selfHotkey: bob.ss58, store: new MemoryStore(60) });
        const signer = new Signer(keypair("alice_ed25519"));
        const body = new Uint8Array([1, 2, 3]);
        const { headers } = signer.sign("PUT", "/a%20b?x=%2F", body, bob.ss58);
        const raw = Object.entries(headers).flat();
        const caller = await verifier.verify({ headers: raw, body, method: "put", target: "/a%20b?x=%2F" });
        expect(caller.scheme).toBe("ed25519");
    });

    it("checks freshness against the clock", async () => {
        const { verifier, req, setNow } = setup();
        const r = req();
        setNow(T0 + 11n * S);
        expect(await code(verifier.verify(r))).toBe("tw.auth_stale");
        setNow(T0 - 3n * S);
        expect(await code(verifier.verify(r))).toBe("tw.auth_stale");
    });

    it("refuses a duplicated record header value given as an array", async () => {
        const { verifier, req } = setup();
        const r = req();
        const record: Record<string, string | string[]> = Object.fromEntries(r.headers);
        record["X-Bittensor-Nonce"] = [
            String(record["X-Bittensor-Nonce"]),
            String(record["X-Bittensor-Nonce"]),
        ];
        expect(await code(verifier.verify({ ...r, headers: record }))).toBe("tw.auth_malformed");
    });

    it("fails closed when the store fails", async () => {
        const failing: NonceStore = {
            retentionS: 60,
            checkAndStore: () => Promise.reject(new Error("down")),
        };
        const { verifier, req } = setup({ store: failing });
        const err = (await verifier.verify(req()).then(
            () => null,
            (e: unknown) => e,
        )) as TWError;
        expect([err.code, err.status]).toEqual(["tw.replay_store_unavailable", 503]);
    });

    it("refuses short retention, bad windows and a bad self hotkey at construction (D21)", () => {
        const self = keypair("bob_sr25519").ss58;
        expect(() => new Verifier({ selfHotkey: self, store: new MemoryStore(23.9) })).toThrow(
            /retention too short/,
        );
        expect(() => new Verifier({ selfHotkey: self, store: new MemoryStore(24) })).not.toThrow();
        expect(() => new Verifier({ selfHotkey: self, store: new MemoryStore(60), maxAgeS: 0 })).toThrow(
            RangeError,
        );
        expect(
            () => new Verifier({ selfHotkey: self, store: new MemoryStore(60), allowedSkewS: Number.NaN }),
        ).toThrow(RangeError);
        expect(() => new Verifier({ selfHotkey: "nope", store: new MemoryStore(60) })).toThrow(/prefix-42/);
        expect(() => new MemoryStore(0)).toThrow(RangeError);
    });

    it("accepts fractional windows", async () => {
        const bob = keypair("bob_sr25519");
        let now = T0;
        const verifier = new Verifier({
            selfHotkey: bob.ss58,
            store: new MemoryStore(60),
            maxAgeS: 2,
            allowedSkewS: 0.5,
            nowNs: () => now,
        });
        const signer = new Signer(keypair("alice_sr25519"), { next: () => T0 } as never);
        const body = new Uint8Array();
        const r = () => ({
            headers: signer.sign("GET", "/", body, bob.ss58).headers,
            body,
            method: "GET",
            target: "/",
        });
        now = T0 - 500_000_001n;
        expect(await code(verifier.verify(r()))).toBe("tw.auth_stale");
        now = T0 - 500_000_000n;
        expect(await code(verifier.verify(r()))).toBe("accepted");
    });
});

describe("clock-step guard (D21)", () => {
    it("fails closed for the retention after a backwards step larger than the margin", async () => {
        let wall = T0;
        let mono = 1_000n * S;
        const { verifier, req, setNow } = setup({ now: () => wall, mono: () => mono });
        setNow(wall);
        await verifier.verify(req());
        // margin = 60 - 12 = 48 s; a 49 s step back opens the window
        wall -= 49n * S;
        setNow(wall);
        expect(await code(verifier.verify(req()))).toBe("tw.replay_store_unavailable");
        expect(verifier.failingClosed()).toBe(true);
        expect(verifier.lastClockStepNs()).toBe(49n * S);
        mono += 59n * S;
        wall += 59n * S;
        expect(verifier.failingClosed()).toBe(true);
        mono += 2n * S;
        wall += 2n * S;
        setNow(wall);
        expect(verifier.failingClosed()).toBe(false);
        expect(await code(verifier.verify(req("/v1/y")))).toBe("accepted");
    });

    it("ignores a step within the margin", () => {
        let wall = T0;
        const mono = 0n;
        const guard = new StepGuard(
            48n * S,
            60n * S,
            () => wall,
            () => mono,
        );
        wall -= 48n * S;
        expect(guard.check()).toBe(false);
        expect(guard.lastStepNs).toBe(0n);
    });
});

describe("MemoryStore (D21)", () => {
    it("forgets only when both clocks say the pair is old", async () => {
        let wall = T0;
        let mono = 0n;
        const store = new MemoryStore(60, { wallNs: () => wall, monoNs: () => mono });
        expect(await store.checkAndStore("a", T0)).toBe(true);
        expect(await store.checkAndStore("a", T0)).toBe(false);
        expect(await store.checkAndStore("b", T0)).toBe(true);
        // monotonic retention passed, but the wall clock stepped back: keep it
        mono += 61n * S;
        wall = T0 + 30n * S;
        expect(store.size).toBe(2);
        expect(await store.checkAndStore("a", T0)).toBe(false);
        // both clocks agree: forgotten
        wall = T0 + 61n * S;
        expect(store.size).toBe(0);
        expect(await store.checkAndStore("a", T0)).toBe(true);
    });

    it("compacts its queue under load", async () => {
        let wall = T0;
        let mono = 0n;
        const store = new MemoryStore(1, { wallNs: () => wall, monoNs: () => mono });
        for (let i = 0n; i < 3000n; i++) {
            await store.checkAndStore("k", wall + i);
        }
        wall += 10n * S;
        mono += 10n * S;
        expect(await store.checkAndStore("k", wall)).toBe(true);
        expect(store.size).toBe(1);
    });
});
