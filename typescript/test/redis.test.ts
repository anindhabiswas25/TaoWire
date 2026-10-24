// RedisNonceStore against a real Redis (TAOWIRE_TEST_REDIS_URL; skipped without it).
import { Redis } from "ioredis";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { Signer, TWError, Verifier, initCrypto } from "@taowire/btauth";
import { DEFAULT_PREFIX, RedisNonceStore } from "@taowire/btauth/redis";
import { keypair } from "./helpers.js";

const url = process.env.TAOWIRE_TEST_REDIS_URL;
const prefix = `tw:test-ts:${process.pid}:${Date.now()}:`;

describe.skipIf(url === undefined)("RedisNonceStore (real Redis)", () => {
    let client: Redis;
    beforeAll(async () => {
        await initCrypto();
        client = new Redis(url!, { lazyConnect: true, maxRetriesPerRequest: 0 });
        await client.connect();
    });
    afterAll(async () => {
        const keys = await client.keys(`${prefix}*`);
        if (keys.length > 0) {
            await client.del(...keys);
        }
        client.disconnect();
    });

    it("uses the Python kit's key format and expiry", async () => {
        const store = new RedisNonceStore(client, 60, { prefix });
        expect(await store.checkAndStore("5Abc", 1752076800000000000n)).toBe(true);
        expect(await store.checkAndStore("5Abc", 1752076800000000000n)).toBe(false);
        const ttl = await client.pttl(`${prefix}5Abc:1752076800000000000`);
        expect(ttl).toBeGreaterThan(59_000);
        expect(ttl).toBeLessThanOrEqual(60_000);
        expect(DEFAULT_PREFIX).toBe("tw:n:");
    });

    it("a verifier on it refuses replays", async () => {
        const bob = keypair("bob_sr25519");
        const verifier = new Verifier({
            selfHotkey: bob.ss58,
            store: new RedisNonceStore(client, 60, { prefix }),
        });
        const body = new Uint8Array();
        const { headers } = new Signer(keypair("alice_sr25519")).sign("GET", "/r", body, bob.ss58);
        const req = { headers, body, method: "GET", target: "/r" };
        await verifier.verify(req);
        await expect(verifier.verify(req)).rejects.toMatchObject({ code: "tw.auth_replayed" });
    });
});

describe("RedisNonceStore (no server)", () => {
    it("fails closed when Redis is unreachable", async () => {
        await initCrypto();
        const store = RedisNonceStore.fromUrl("redis://127.0.0.1:1/0", 60);
        const bob = keypair("bob_sr25519");
        const verifier = new Verifier({ selfHotkey: bob.ss58, store });
        const body = new Uint8Array();
        const { headers } = new Signer(keypair("alice_sr25519")).sign("GET", "/d", body, bob.ss58);
        const err = await verifier.verify({ headers, body, method: "GET", target: "/d" }).then(
            () => null,
            (e: unknown) => e,
        );
        expect(err).toBeInstanceOf(TWError);
        expect([(err as TWError).code, (err as TWError).status]).toEqual([
            "tw.replay_store_unavailable",
            503,
        ]);
        store.client.emit("error", new Error("connection lost")); // swallowed: commands fail on their own
        store.client.disconnect();
    });
    it("refuses a retention below 1 ms and a bad timeout", () => {
        expect(() => new RedisNonceStore({} as Redis, 0)).toThrow(RangeError);
        expect(() => new RedisNonceStore({} as Redis, 60, { timeoutMs: 0 })).toThrow(RangeError);
    });

    it("a Redis that never answers fails closed within the timeout", async () => {
        const hung = { set: () => new Promise(() => undefined) } as unknown as Redis;
        await initCrypto();
        const bob = keypair("bob_sr25519");
        const verifier = new Verifier({
            selfHotkey: bob.ss58,
            store: new RedisNonceStore(hung, 60, { timeoutMs: 50 }),
        });
        const body = new Uint8Array();
        const { headers } = new Signer(keypair("alice_sr25519")).sign("GET", "/h", body, bob.ss58);
        const start = Date.now();
        await expect(verifier.verify({ headers, body, method: "GET", target: "/h" })).rejects.toMatchObject({
            code: "tw.replay_store_unavailable",
        });
        expect(Date.now() - start).toBeLessThan(1000);
    });

    it("answers from a working client", async () => {
        const ok = { set: () => Promise.resolve("OK") } as unknown as Redis;
        const nx = { set: () => Promise.resolve(null) } as unknown as Redis;
        expect(await new RedisNonceStore(ok, 60).checkAndStore("h", 1n)).toBe(true);
        expect(await new RedisNonceStore(nx, 60).checkAndStore("h", 1n)).toBe(false);
    });
});
