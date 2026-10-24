// Fastify adapter and fetch client (spec 11.3, 5.3, 9.1, Appendix A).
import { Readable } from "node:stream";
import Fastify, { type FastifyInstance } from "fastify";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import {
    Client,
    ClientError,
    MemoryStore,
    Signer,
    TWError,
    Verifier,
    initCrypto,
    requestTarget,
    verifyResponse,
} from "@taowire/btauth";
import { type BtauthOptions, btauth, rawBody } from "@taowire/btauth/fastify";
import { keypair } from "./helpers.js";

beforeAll(initCrypto);

const streams: Readable[] = [];

async function miner(extra: Partial<BtauthOptions> = {}): Promise<FastifyInstance> {
    const bob = keypair("bob_sr25519");
    const app = Fastify({ logger: false, forceCloseConnections: true });
    await app.register(btauth, {
        verifier: new Verifier({ selfHotkey: bob.ss58, store: new MemoryStore(60) }),
        responseKey: bob,
        bodyLimit: 1024,
        routes: (scope) => {
            scope.post("/v1/echo", async (req, reply) => {
                const body = rawBody(req);
                return reply
                    .type("application/octet-stream")
                    .send(Buffer.concat([Buffer.from(`${req.btauthCaller?.hotkey}:`), body]));
            });
            scope.get("/v1/get", () => ({ ok: true }));
            scope.post("/v1/boom", () => {
                throw new Error("handler bug");
            });
            scope.post("/v1/teapot", () => {
                throw new TWError("tw.invalid_request", "bad field");
            });
            scope.post("/v1/stream", (_req, reply) => {
                const stream = Readable.from(["a", "b"]);
                streams.push(stream);
                return reply.send(stream);
            });
            scope.post("/v1/empty", (_req, reply) => reply.code(204).send());
            scope.addHook("onRequest", (req, _reply, done) => {
                done(
                    req.headers["x-test-fail"] === undefined
                        ? undefined
                        : new Error("failed before the body was read"),
                );
            });
            scope.post("/v1/upstream", () => {
                throw new ClientError("tw.timeout", "upstream call timed out");
            });
            scope.post(
                "/v1/schema",
                {
                    schema: {
                        querystring: {
                            type: "object",
                            required: ["q"],
                            properties: { q: { type: "string" } },
                        },
                    },
                },
                () => "ok",
            );
        },
        ...extra,
    });
    app.get("/healthz", () => "ok");
    return app;
}

const alice = () => keypair("alice_sr25519");
const bobSS58 = () => keypair("bob_sr25519").ss58;

function signed(method: string, target: string, body: Uint8Array, signer = new Signer(alice())) {
    const s = signer.sign(method, target, body, bobSS58());
    return { headers: s.headers, nonce: s.nonce, signer };
}

function checkSigned(
    res: { headers: Record<string, unknown>; statusCode: number; rawPayload: Buffer },
    nonce: bigint,
) {
    const headers = Object.entries(res.headers).map(([k, v]) => [k, String(v)] as [string, string]);
    return verifyResponse(
        headers,
        { expectedResponder: bobSS58(), requestNonce: nonce, sender: alice().ss58, status: res.statusCode },
        res.rawPayload,
    );
}

describe("btauth Fastify plugin", () => {
    it.each([
        ["application/json", '{"a": 1}'],
        ["text/plain", "hello"],
        ["application/octet-stream", "\u0000\u0001"],
        [undefined, '{"no":"type"}'],
    ])("hands the raw body to the handler (content type %s)", async (type, text) => {
        const app = await miner();
        const body = Buffer.from(text);
        const s = signed("POST", "/v1/echo", body);
        const res = await app.inject({
            method: "POST",
            url: "/v1/echo",
            payload: body,
            headers: { ...s.headers, ...(type === undefined ? {} : { "content-type": type }) },
        });
        expect(res.statusCode).toBe(200);
        expect(res.rawPayload.toString()).toBe(`${alice().ss58}:${text}`);
        expect(checkSigned(res, s.nonce)).toBe("sr25519");
    });

    it("verifies GET without a body and a percent-encoded target", async () => {
        const app = await miner();
        const s = signed("GET", "/v1/get?q=%2F%20x", new Uint8Array());
        const res = await app.inject({ method: "GET", url: "/v1/get?q=%2F%20x", headers: s.headers });
        expect(res.statusCode).toBe(200);
        checkSigned(res, s.nonce);
    });

    it("refuses before authentication without signing (401, 413)", async () => {
        const app = await miner();
        const s = signed("POST", "/v1/echo", Buffer.from("a"));
        const tampered = await app.inject({
            method: "POST",
            url: "/v1/echo",
            payload: "b",
            headers: s.headers,
        });
        expect(tampered.statusCode).toBe(401);
        expect(tampered.json()).toEqual({
            error: { code: "tw.auth_bad_signature", message: "signature does not verify", request_id: null },
        });
        expect(tampered.headers["x-tw-resp-signature"]).toBeUndefined();
        const big = Buffer.alloc(2048, 1);
        const s2 = signed("POST", "/v1/echo", big);
        const tooBig = await app.inject({
            method: "POST",
            url: "/v1/echo",
            payload: big,
            headers: s2.headers,
        });
        expect(tooBig.statusCode).toBe(413);
        expect(tooBig.json<{ error: { code: string } }>().error.code).toBe("tw.payload_too_large");
        expect(tooBig.headers["x-tw-resp-signature"]).toBeUndefined();
        const none = await app.inject({ method: "POST", url: "/v1/echo", payload: "x" });
        expect(none.json<{ error: { code: string } }>().error.code).toBe("tw.auth_malformed");
    });

    it("signs errors after authentication: 500 handler_error, 422, 403 policy, 429", async () => {
        const app = await miner({
            policy: (caller) => {
                if (caller.nonce % 2n === 1n) {
                    throw new TWError("tw.forbidden_not_validator");
                }
            },
            hotkeyRateLimit: { perS: 0.001, burst: 1 },
        });
        const nonces = { value: 1_752_076_800_000_000_000n };
        const fixed = new Signer(alice(), { next: () => (nonces.value += 2n) } as never);
        const now = BigInt(Date.now()) * 1_000_000n;
        nonces.value = now - (now % 2n);
        const send = async (url: string) => {
            const s = signed("POST", url, Buffer.from("{}"), fixed);
            const res = await app.inject({ method: "POST", url, payload: "{}", headers: s.headers });
            checkSigned(res, s.nonce);
            return res;
        };
        const boom = await send("/v1/boom");
        expect([boom.statusCode, boom.json<{ error: { code: string } }>().error.code]).toEqual([
            500,
            "tw.handler_error",
        ]);
        const teapot = await send("/v1/teapot");
        expect([teapot.statusCode, teapot.json<{ error: { code: string } }>().error.code]).toEqual([
            422,
            "tw.invalid_request",
        ]);
        const limited = await send("/v1/boom");
        expect([limited.statusCode, limited.headers["retry-after"]]).toEqual([429, expect.any(String)]);
        // odd nonce: the policy refuses
        nonces.value += 1n;
        const s = signed("POST", "/v1/echo", Buffer.from("{}"), fixed);
        const denied = await app.inject({
            method: "POST",
            url: "/v1/echo",
            payload: "{}",
            headers: s.headers,
        });
        expect([denied.statusCode, denied.json<{ error: { code: string } }>().error.code]).toEqual([
            403,
            "tw.forbidden_not_validator",
        ]);
        checkSigned(denied, s.nonce);
    });

    it("a stream reply is refused (500, signed) and a schema failure is 422", async () => {
        const app = await miner();
        const s = signed("POST", "/v1/stream", Buffer.from("{}"));
        const res = await app.inject({
            method: "POST",
            url: "/v1/stream",
            payload: "{}",
            headers: s.headers,
        });
        expect([res.statusCode, res.json<{ error: { code: string } }>().error.code]).toEqual([
            500,
            "tw.handler_error",
        ]);
        checkSigned(res, s.nonce);
        expect(streams.at(-1)?.destroyed).toBe(true);
        const s3 = signed("POST", "/v1/upstream", Buffer.from("{}"));
        const up = await app.inject({
            method: "POST",
            url: "/v1/upstream",
            payload: "{}",
            headers: s3.headers,
        });
        expect([up.statusCode, up.json<{ error: { code: string } }>().error.code]).toEqual([
            500,
            "tw.handler_error",
        ]);
        checkSigned(up, s3.nonce);
        const s2 = signed("POST", "/v1/schema", Buffer.from("{}"));
        const bad = await app.inject({
            method: "POST",
            url: "/v1/schema",
            payload: "{}",
            headers: s2.headers,
        });
        expect([bad.statusCode, bad.json<{ error: { code: string } }>().error.code]).toEqual([
            422,
            "tw.invalid_request",
        ]);
        checkSigned(bad, s2.nonce);
    });

    it("refuses an absolute-form target", async () => {
        const app = await miner();
        await app.listen({ host: "127.0.0.1", port: 0 });
        const { port } = app.server.address() as { port: number };
        const { request } = await import("node:http");
        const s = signed("POST", "/v1/echo", new Uint8Array());
        const status = await new Promise<number>((resolve, reject) => {
            const req = request(
                {
                    host: "127.0.0.1",
                    port,
                    method: "POST",
                    path: `http://127.0.0.1:${port}/v1/echo`,
                    headers: s.headers,
                },
                (res) => {
                    res.resume();
                    resolve(res.statusCode ?? 0);
                },
            );
            req.on("error", reject);
            req.end();
        });
        await app.close();
        expect(status).toBe(401);
    });

    it("signs an empty 204 and refuses a pre-auth failure unsigned", async () => {
        const app = await miner();
        const s = signed("POST", "/v1/empty", new Uint8Array());
        const res = await app.inject({ method: "POST", url: "/v1/empty", headers: s.headers });
        expect(res.statusCode).toBe(204);
        checkSigned(res, s.nonce);
        const fail = await app.inject({
            method: "POST",
            url: "/v1/empty",
            headers: { ...s.headers, "x-test-fail": "1" },
        });
        expect([fail.statusCode, fail.json<{ error: { code: string } }>().error.code]).toEqual([
            401,
            "tw.auth_malformed",
        ]);
        expect(fail.headers["x-tw-resp-signature"]).toBeUndefined();
    });

    it("a verifier that throws something else fails closed (500, unsigned)", async () => {
        const broken = {
            selfHotkey: bobSS58(),
            verify: () => Promise.reject(new Error("bug")),
        } as unknown as Verifier;
        const app = Fastify();
        await app.register(btauth, {
            verifier: broken,
            routes: (scope) => void scope.post("/x", () => "ok"),
        });
        const res = await app.inject({ method: "POST", url: "/x" });
        expect([res.statusCode, res.json<{ error: { code: string } }>().error.code]).toEqual([
            500,
            "tw.internal",
        ]);
    });

    it("verifies the original target when the app rewrites URLs", async () => {
        const bob = keypair("bob_sr25519");
        const app = Fastify({ rewriteUrl: (req) => (req.url ?? "/").replace("/old/", "/v1/") });
        await app.register(btauth, {
            verifier: new Verifier({ selfHotkey: bob.ss58, store: new MemoryStore(60) }),
            routes: (scope) => void scope.post("/v1/x", () => "ok"),
        });
        const s = signed("POST", "/old/x", new Uint8Array());
        const res = await app.inject({ method: "POST", url: "/old/x", headers: s.headers });
        expect(res.statusCode).toBe(200);
    });

    it("a policy bug fails closed (500, unsigned like Python's tw.internal)", async () => {
        const app = await miner({
            policy: () => {
                throw new Error("policy bug");
            },
        });
        const s = signed("POST", "/v1/echo", Buffer.from("{}"));
        const res = await app.inject({ method: "POST", url: "/v1/echo", payload: "{}", headers: s.headers });
        expect([res.statusCode, res.json<{ error: { code: string } }>().error.code]).toEqual([
            500,
            "tw.internal",
        ]);
        expect(res.headers["x-tw-resp-signature"]).toBeUndefined();
    });

    it("a stale metagraph from the policy is 503 and unsigned (Appendix A)", async () => {
        const app = await miner({
            policy: () => {
                throw new TWError("tw.metagraph_stale");
            },
        });
        const s = signed("POST", "/v1/echo", Buffer.from("{}"));
        const res = await app.inject({ method: "POST", url: "/v1/echo", payload: "{}", headers: s.headers });
        expect([res.statusCode, res.json<{ error: { code: string } }>().error.code]).toEqual([
            503,
            "tw.metagraph_stale",
        ]);
        expect(res.headers["x-tw-resp-signature"]).toBeUndefined();
    });

    it("works without response signing and without the rate limit", async () => {
        const bob = keypair("bob_sr25519");
        const app = Fastify();
        await app.register(btauth, {
            verifier: new Verifier({ selfHotkey: bob.ss58, store: new MemoryStore(60) }),
            hotkeyRateLimit: false,
            routes: (scope) => {
                scope.post("/x", () => "ok");
            },
        });
        const s = signed("POST", "/x", new Uint8Array());
        const res = await app.inject({ method: "POST", url: "/x", headers: s.headers });
        expect(res.statusCode).toBe(200);
        expect(res.headers["x-tw-resp-signature"]).toBeUndefined();
    });

    it("refuses a response key that is not the verifier's hotkey", async () => {
        const app = Fastify();
        await expect(
            app.register(btauth, {
                verifier: new Verifier({ selfHotkey: bobSS58(), store: new MemoryStore(60) }),
                responseKey: alice(),
                routes: () => undefined,
            }),
        ).rejects.toThrow(/responseKey/);
    });
});

describe("Client (fetch)", () => {
    let app: FastifyInstance;
    let base: string;
    beforeAll(async () => {
        app = await miner();
        app.get("/plain", () => ({ unsigned: true }));
        app.get("/slow", async () => {
            await new Promise((r) => setTimeout(r, 2000));
            return "late";
        });
        app.get("/huge", () => "x".repeat(4096));
        base = await app.listen({ host: "127.0.0.1", port: 0 });
    });
    afterAll(() => app.close());

    const client = (opts: { timeoutMs?: number; maxResponseBytes?: number; attempts?: number } = {}) =>
        new Client({ signer: new Signer(alice()), ...opts });

    it("sends signed requests and verifies the answer", async () => {
        const c = client();
        for (let i = 0; i < 3; i++) {
            const res = await c.request("POST", `${base}/v1/echo`, Buffer.from(`n${i}`), bobSS58());
            expect([res.status, Buffer.from(res.body).toString(), res.scheme]).toEqual([
                200,
                `${alice().ss58}:n${i}`,
                "sr25519",
            ]);
        }
        // the signed target must be what undici sends, byte for byte
        for (const target of ["/v1/get?q=%2F", "/v1/get?", "/v1/get?a=b%20c&d", "/v1/get?x=caf%C3%A9"]) {
            const get = await c.request("GET", `${base}${target}`, new Uint8Array(), bobSS58());
            expect(get.status, target).toBe(200);
        }
    });

    it("refuses an unsigned or wrongly bound answer", async () => {
        const err = await client()
            .request("GET", `${base}/plain`, new Uint8Array(), bobSS58())
            .catch((e: unknown) => e);
        expect(err).toBeInstanceOf(ClientError);
        expect([(err as ClientError).code, (err as ClientError).responseStatus]).toEqual([
            "tw.bad_response_signature",
            200,
        ]);
        const wrong = await client()
            .request("POST", `${base}/v1/echo`, new Uint8Array(), alice().ss58)
            .catch((e: unknown) => e as ClientError);
        expect(wrong).toBeInstanceOf(ClientError);
        // signed for another receiver: the miner refuses unsigned (401), the client reports the bad answer
        expect((wrong as ClientError).code).toBe("tw.bad_response_signature");
    });

    it("maps timeouts, connect errors and oversized answers", async () => {
        const slow = await client({ timeoutMs: 200 })
            .request("GET", `${base}/slow`, new Uint8Array(), bobSS58())
            .catch((e: unknown) => e);
        expect((slow as ClientError).code).toBe("tw.timeout");
        const huge = await client({ maxResponseBytes: 100 })
            .request("GET", `${base}/huge`, new Uint8Array(), bobSS58())
            .catch((e: unknown) => e);
        expect((huge as ClientError).code).toBe("tw.response_too_large");
        let calls = 0;
        const refusing = new Client({
            signer: new Signer(alice()),
            attempts: 3,
            fetch: () => {
                calls++;
                return Promise.reject(new TypeError("fetch failed", { cause: { code: "ECONNREFUSED" } }));
            },
        });
        const down = await refusing
            .request("POST", "http://127.0.0.1:1/x", new Uint8Array(), bobSS58())
            .catch((e: unknown) => e);
        expect([(down as ClientError).code, calls]).toEqual(["tw.connect_error", 3]);
    });

    it("signs each retry with a fresh nonce", async () => {
        const seen: string[] = [];
        let first = true;
        const flaky = new Client({
            signer: new Signer(alice()),
            attempts: 2,
            fetch: ((input: URL, init: RequestInit) => {
                seen.push((init.headers as Record<string, string>)["X-Bittensor-Nonce"]!);
                if (first) {
                    first = false;
                    return Promise.reject(new TypeError("fetch failed", { cause: { code: "ECONNREFUSED" } }));
                }
                return fetch(input, init);
            }) as typeof fetch,
        });
        const res = await flaky.request("POST", `${base}/v1/echo`, Buffer.from("r"), bobSS58());
        expect(res.status).toBe(200);
        expect(new Set(seen).size).toBe(2);
    });

    it("reads a body without Content-Type over a real socket, capped at bodyLimit", async () => {
        const { request } = await import("node:http");
        const send = (body: Buffer) => {
            const s = signed("POST", "/v1/echo", body);
            return new Promise<{ status: number; text: string }>((resolve, reject) => {
                const url = new URL(`${base}/v1/echo`);
                const req = request(
                    {
                        host: url.hostname,
                        port: url.port,
                        method: "POST",
                        path: "/v1/echo",
                        headers: s.headers,
                    },
                    (res) => {
                        const parts: Buffer[] = [];
                        res.on("data", (c: Buffer) => parts.push(c));
                        res.on("end", () => {
                            resolve({ status: res.statusCode ?? 0, text: Buffer.concat(parts).toString() });
                        });
                    },
                );
                req.on("error", reject);
                req.end(body);
            });
        };
        const small = await send(Buffer.from('{"text":"hello"}'));
        expect(small).toEqual({ status: 200, text: `${alice().ss58}:{"text":"hello"}` });
        const big = await send(Buffer.alloc(4096, 0x61));
        expect(big.status).toBe(413);
        expect(big.text).toContain("tw.payload_too_large");
    });

    it("never retries a failure after delivery (the handler may have run)", async () => {
        let calls = 0;
        const reset = new Client({
            signer: new Signer(alice()),
            attempts: 3,
            fetch: () => {
                calls++;
                return Promise.reject(new TypeError("fetch failed", { cause: { code: "UND_ERR_SOCKET" } }));
            },
        });
        const err = await reset
            .request("POST", `${base}/v1/echo`, new Uint8Array(), bobSS58())
            .catch((e: unknown) => e);
        expect([(err as ClientError).code, calls]).toEqual(["tw.connect_error", 1]);
    });

    it("refuses a body on GET/HEAD and upper-cases the method", async () => {
        await expect(client().request("get", `${base}/v1/get`, Buffer.from("x"), bobSS58())).rejects.toThrow(
            RangeError,
        );
        const res = await client().request("get", `${base}/v1/get`, new Uint8Array(), bobSS58());
        expect(res.status).toBe(200);
    });

    it("verifies a HEAD answer (signed over the empty body that is sent)", async () => {
        const res = await client().request("HEAD", `${base}/v1/get`, new Uint8Array(), bobSS58());
        expect([res.status, res.body.length]).toEqual([200, 0]);
    });

    it("refuses bad options", () => {
        expect(() => client({ attempts: 0 })).toThrow(RangeError);
        expect(() => client({ timeoutMs: 0 })).toThrow(RangeError);
    });
});

describe("requestTarget", () => {
    it.each([
        ["http://h/a%20b?x=%2F", "/a%20b?x=%2F"],
        ["http://h/p?", "/p?"],
        ["http://h/p", "/p"],
        ["http://h/p?q=1#frag", "/p?q=1"],
        ["http://h/a b", "/a%20b"],
    ])("%s -> %s", (url, target) => {
        expect(requestTarget(new URL(url))).toBe(target);
    });
});
