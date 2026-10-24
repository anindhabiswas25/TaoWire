// SSE streaming with a signed trailer (spec 9.2, D29, D35, D36): the shared
// pieces, streamReply on the Fastify adapter and Client.stream.
import { type IncomingMessage, type ServerResponse, createServer } from "node:http";
import { type AddressInfo, connect } from "node:net";
import Fastify, { type FastifyInstance } from "fastify";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import {
    ChunkError,
    Client,
    ClientError,
    MAX_CHUNK_DEPTH,
    MemoryStore,
    type SSEEvent,
    SSEParser,
    Signer,
    StreamDigest,
    StreamLimits,
    StreamSlots,
    TRAILER_RESERVE,
    TWError,
    TrailerError,
    Verifier,
    decodeChunk,
    encodeChunk,
    encodeEvent,
    encodeTrailer,
    initCrypto,
    parseTrailer,
    responsePayload,
    signResponse,
    signatureHex,
} from "@taowire/btauth";
import { type AbortReason, type StreamReplyOptions, btauth, streamReply } from "@taowire/btauth/fastify";
import { keypair } from "./helpers.js";

beforeAll(initCrypto);

const enc = (s: string) => new TextEncoder().encode(s);
const show = (evs: SSEEvent[]) =>
    evs.map((e) => `${e.event}=${JSON.stringify(Buffer.from(e.data).toString("latin1"))};`).join("");

function parseAll(input: Uint8Array): string {
    const p = new SSEParser();
    return show([...p.feed(input), ...p.finish()]);
}

describe("SSE parser", () => {
    it("follows the WHATWG rules like the Python reference", () => {
        const cases: [string, string][] = [
            ["event: chunk\ndata: {}\n\n", 'chunk="{}";'],
            ["event: chunk\r\ndata: {}\r\n\r\n", 'chunk="{}";'],
            ["event: chunk\rdata: {}\r\r", 'chunk="{}";'],
            ["data: a\ndata: b\n\n", 'message="a\\nb";'],
            ["data:a\n\n", 'message="a";'],
            ["data:  a\n\n", 'message=" a";'],
            ["data\n\n", 'message="";'],
            [": c\ndata: x\n\n", 'message="x";'],
            ["event:\ndata: x\n\n", 'message="x";'],
            ["event: e\n\n", ""],
            ["id: 1\nretry: 5\nfoo: bar\ndata: x\n\n", 'message="x";'],
            ["data: unfinished", ""],
            ["data: x\r", ""],
            ["data: x\r\r", 'message="x";'],
            ["\ufeffdata: x\n\n", 'message="x";'],
            ["data: x\n\n\ufeffdata: y\n\n", 'message="x";'],
            ["event: a\ndata: 1\n\nevent: b\ndata: 2\n\n", 'a="1";b="2";'],
        ];
        for (const [input, want] of cases) {
            expect(parseAll(enc(input)), JSON.stringify(input)).toBe(want);
        }
        let p = new SSEParser();
        expect(show([...p.feed(enc("data: x\r")), ...p.feed(enc("\n\r\n"))])).toBe('message="x";');
        p = new SSEParser();
        const raw = [
            ...p.feed(Uint8Array.of(0xef)),
            ...p.feed(Uint8Array.of(0xbb)),
            ...p.feed(Buffer.from("bf646174613a20790a0a", "hex")),
        ];
        expect(show(raw)).toBe('message="y";');
    });

    it("gives the same events for any split", () => {
        const tokens = [
            "event: chunk",
            "event: tw-end",
            "data: ",
            "data:",
            '{"a":1}',
            ":",
            " ",
            "\n",
            "\r",
            "\r\n",
            "\ufeff",
            "x",
            "id: 3",
            "é",
            "\0",
        ];
        let state = 1;
        const rnd = (n: number) => {
            state = (state * 1103515245 + 12345) % 2 ** 31;
            return state % n;
        };
        for (let n = 0; n < 2000; n++) {
            const input = enc(Array.from({ length: rnd(30) }, () => tokens[rnd(tokens.length)]).join(""));
            const want = parseAll(input);
            const p = new SSEParser();
            const got: SSEEvent[] = [];
            for (let rest = input; rest.length > 0;) {
                const cut = 1 + rnd(rest.length);
                got.push(...p.feed(rest.subarray(0, cut)));
                rest = rest.subarray(cut);
            }
            got.push(...p.finish());
            expect(show(got)).toBe(want);
        }
    });

    it("is linear on a 4 MiB line fed in small pieces", () => {
        const line = new Uint8Array(4 << 20).fill(0x78);
        for (const step of [1, 7]) {
            const p = new SSEParser();
            const started = performance.now();
            p.feed(enc("data: "));
            for (let i = 0; i < line.length; i += step) {
                p.feed(line.subarray(i, i + step));
            }
            const got = p.feed(enc("\n\n"));
            expect(performance.now() - started).toBeLessThan(10_000);
            expect(got.length).toBe(1);
            expect(got[0]?.data.length).toBe(line.length);
        }
    });
});

describe("chunks, trailers, framing", () => {
    const deep = (n: number) => "[".repeat(n) + "]".repeat(n);

    it("decodes only JSON objects and arrays", () => {
        for (const ok of [
            '{"a":1}',
            "[1,2]",
            ' {"a":"\\n"}\n',
            '{"s":"[[[["}',
            "[1e400]",
            deep(MAX_CHUNK_DEPTH),
        ]) {
            expect(() => decodeChunk(enc(ok)), ok).not.toThrow();
        }
        for (const bad of [
            "1",
            '"s"',
            "null",
            "true",
            "{",
            "NaN",
            "[NaN]",
            "[Infinity]",
            '{"a":1}x',
            "",
            "\ufeff{}",
            deep(MAX_CHUNK_DEPTH + 1),
            deep(100_000),
        ]) {
            expect(() => decodeChunk(enc(bad)), bad.slice(0, 20)).toThrow(ChunkError);
        }
        expect(() => decodeChunk(Uint8Array.of(0x5b, 0x22, 0xff, 0x22, 0x5d))).toThrow(ChunkError);
    });

    it("encodes only JSON objects and arrays without line breaks", () => {
        expect(Buffer.from(encodeChunk({ a: 1 })).toString()).toBe('{"a":1}');
        expect(Buffer.from(encodeChunk([1])).toString()).toBe("[1]");
        expect(Buffer.from(encodeChunk(enc(" [3]"))).toString()).toBe(" [3]");
        const nested: unknown[] = [];
        let cur = nested;
        for (let i = 0; i < MAX_CHUNK_DEPTH; i++) {
            const next: unknown[] = [];
            cur.push(next);
            cur = next;
        }
        for (const bad of [
            1,
            "s",
            null,
            undefined,
            enc('{"a":\n1}'),
            enc('"s"'),
            enc('{"a"'),
            { toJSON: () => undefined },
            { toJSON: () => 5 },
            nested,
            { n: 1n },
        ]) {
            expect(() => encodeChunk(bad)).toThrow(ChunkError);
        }
    });

    it("parses trailers strictly", () => {
        const d = "ab".repeat(32);
        const good = `{"digest":"${d}","count":3,"signature":"0x00"}`;
        const t = parseTrailer(enc(good));
        expect(t).toEqual({ digest: d, count: 3n, signature: "0x00" });
        expect(Buffer.from(encodeTrailer(t)).toString()).toBe(good);
        expect(parseTrailer(enc(`{"count":0,"digest":"${d}"}`)).signature).toBeNull();
        expect(parseTrailer(enc(`{"digest":"${d}","count":18446744073709551615}`)).count).toBe(
            2n ** 64n - 1n,
        );
        for (const bad of [
            "",
            "[]",
            '"x"',
            "{}",
            `{"digest":"${d}"}`,
            '{"count":1}',
            `{"digest":"${d.toUpperCase()}","count":1}`,
            '{"digest":"ab","count":1}',
            `{"digest":"${d}","count":1.0}`,
            `{"digest":"${d}","count":1e2}`,
            `{"digest":"${d}","count":-1}`,
            `{"digest":"${d}","count":-0}`,
            `{"digest":"${d}","count":true}`,
            `{"digest":"${d}","count":"1"}`,
            `{"digest":"${d}","count":18446744073709551616}`,
            `{"digest":"${d}","count":1,"signature":1}`,
            `{"digest":"${d}","count":1,"x":1}`,
            `{"digest":"${d}","count":1,"count":1}`,
            `{"digest":"${d}","d\\u0069gest":"${d}","count":1}`,
            `{"digest":"${d}","count":1}x`,
            '{"digest":{},"count":1}',
            ` { "digest" : "${d}" , "count" : [1] } `,
            // D43: no lone UTF-16 surrogate escape in any string.
            `{"digest":"${d}","count":1,"signature":"0x\\ud800"}`,
            `{"digest":"${d}","count":1,"signature":"\\uDFFF0x"}`,
            `{"digest":"${d}","count":1,"signature":"\\ude00\\ud83d"}`,
            `{"digest":"${d}","count":1,"\\ud800":"x"}`,
        ]) {
            expect(() => parseTrailer(enc(bad)), bad).toThrow(TrailerError);
        }
        expect(() => parseTrailer(Uint8Array.of(0xff))).toThrow(TrailerError);
        expect(parseTrailer(enc(` { "digest" : "${d}" , "count" : 2 } `)).count).toBe(2n);
        // An escaped pair is one code point, not a lone surrogate.
        const pair = `{"digest":"${d}","count":1,"signature":"\\ud83d\\ude00"}`;
        expect(parseTrailer(enc(pair)).signature).toBe("\u{1F600}");
    });

    it("frames events, reserves the trailer and checks the limits", () => {
        expect(Buffer.from(encodeEvent("chunk", enc("{}"))).toString()).toBe("event: chunk\ndata: {}\n\n");
        expect(() => encodeEvent("a\nb", new Uint8Array(0))).toThrow(RangeError);
        expect(() => encodeEvent("a", enc("\r"))).toThrow(RangeError);
        expect(TRAILER_RESERVE).toBe(273); // the Python reference's value
        expect(new StreamLimits()).toMatchObject({ maxS: 60, maxBytes: 4 << 20, idleS: 10 });
        for (const bad of [
            { maxS: 0.5 },
            { maxS: 601 },
            { maxBytes: 1023 },
            { maxBytes: (64 << 20) + 1 },
            { maxBytes: 2048.5 },
            { idleS: 0 },
            { idleS: 121 },
            { maxS: Number.NaN },
        ]) {
            expect(() => new StreamLimits(bad)).toThrow(RangeError);
        }
        const d = new StreamDigest();
        d.update(enc("{}"));
        expect(d.hexdigest()).toBe(d.hexdigest());
        expect(d.count).toBe(1);
    });

    it("counts open streams per caller", () => {
        expect(() => new StreamSlots(0)).toThrow(RangeError);
        expect(() => new StreamSlots(257)).toThrow(RangeError);
        expect(() => new StreamSlots(1.5)).toThrow(RangeError);
        const s = new StreamSlots(2);
        const r1 = s.acquire("a");
        const r2 = s.acquire("a");
        expect(() => s.acquire("a")).toThrow(
            expect.objectContaining({ code: "tw.rate_limited", status: 429 }) as Error,
        );
        s.acquire("b")();
        r1();
        r1();
        expect(s.open("a")).toBe(1);
        r2();
        expect(s.open("a")).toBe(0);
    });
});

// ---------------------------------------------------------------- miner + client

const bob = () => keypair("bob_sr25519");
const alice = () => keypair("alice_sr25519");
const apps: FastifyInstance[] = [];
const servers: ReturnType<typeof createServer>[] = [];

afterAll(async () => {
    await Promise.all(apps.map((a) => a.close()));
    for (const s of servers) s.closeAllConnections();
    await Promise.all(servers.map((s) => new Promise((r) => s.close(r))));
});

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

async function* list(...items: unknown[]): AsyncGenerator {
    await Promise.resolve();
    for (const item of items) {
        if (item instanceof Error) throw item;
        yield item;
    }
}

async function streamMiner(
    source: () => AsyncIterable<unknown>,
    options: StreamReplyOptions = {},
    key = bob(),
): Promise<string> {
    const app = Fastify({ logger: false, forceCloseConnections: true });
    await app.register(btauth, {
        verifier: new Verifier({ selfHotkey: key.ss58, store: new MemoryStore(60) }),
        responseKey: key,
        hotkeyRateLimit: false,
        routes: (scope) => {
            scope.all("/*", (req, reply) => streamReply(req, reply, source(), options));
        },
    });
    apps.push(app);
    return app.listen({ host: "127.0.0.1", port: 0 });
}

function client(key = alice()): Client {
    return new Client({ signer: new Signer(key) });
}

async function codeOf(p: Promise<unknown>): Promise<string> {
    try {
        await p;
        return "ok";
    } catch (err) {
        return err instanceof TWError ? err.code : String(err);
    }
}

describe("streamReply and Client.stream", () => {
    it("round-trips with sr25519 and ed25519 miners", async () => {
        for (const key of [bob(), keypair("bob_ed25519")]) {
            const url = await streamMiner(() => list({ t: "Hel" }, enc('{"t":"lo ☃"}'), [1]), {}, key);
            const s = await client().stream("POST", `${url}/v1/s?x=1`, enc("{}"), key.ss58);
            const seen: unknown[] = [];
            for await (const c of s) {
                expect(c.verified).toBe(false);
                seen.push(c.data);
            }
            expect(seen).toEqual([{ t: "Hel" }, { t: "lo ☃" }, [1]]);
            expect(await s.result()).toEqual(seen);
        }
        const url = await streamMiner(() => list());
        const s = await client().stream("GET", `${url}/`, new Uint8Array(0), bob().ss58);
        expect(await s.result()).toEqual([]);
    });

    it("answers errors before the first byte as signed JSON", async () => {
        const cases: [() => AsyncIterable<unknown>, string][] = [
            [() => list(new Error("boom")), "tw.handler_error"],
            [() => list(new TWError("tw.forbidden_not_validator")), "tw.forbidden_not_validator"],
            [
                () =>
                    (async function* () {
                        await sleep(5_000);
                        yield [1];
                    })(),
                "tw.handler_timeout",
            ],
        ];
        for (const [source, code] of cases) {
            const url = await streamMiner(source, { firstChunkTimeoutMs: 100 });
            expect(await codeOf(client().stream("POST", `${url}/`, enc("{}"), bob().ss58))).toBe(code);
        }
    });

    it("ends without tw-end on every abort, and releases the slot", async () => {
        const forever = async function* () {
            for (;;) {
                await sleep(200);
                yield [1];
            }
        };
        const stall = async function* () {
            yield [1];
            await sleep(60_000);
        };
        const cases: [AbortReason, () => AsyncIterable<unknown>, StreamLimits][] = [
            ["handler_error", () => list([1], new Error("boom")), new StreamLimits()],
            ["bad_chunk", () => list([1], 5), new StreamLimits()],
            ["bad_chunk", () => list([1], enc('{"a":\n1}')), new StreamLimits()],
            ["idle_timeout", stall, new StreamLimits({ idleS: 1 })],
            ["max_bytes", () => list({ x: "a".repeat(900) }), new StreamLimits({ maxBytes: 1024 })],
            ["max_duration", forever, new StreamLimits({ maxS: 1 })],
        ];
        await Promise.all(
            cases.map(async ([reason, source, limits]) => {
                const aborts: string[] = [];
                const slots = new StreamSlots(1);
                const url = await streamMiner(source, {
                    limits,
                    slots,
                    route: "/v1/s",
                    onAbort: (_route, r) => aborts.push(r),
                });
                const s = await client().stream("POST", `${url}/`, enc("{}"), bob().ss58, {
                    timeoutMs: 30_000,
                });
                expect(await codeOf(s.result()), reason).toBe("tw.bad_response_signature");
                for (let i = 0; aborts.length === 0 && i < 300; i++) await sleep(10);
                expect(aborts).toEqual([reason]);
                for (let i = 0; slots.open(alice().ss58) > 0 && i < 300; i++) await sleep(10);
                expect(slots.open(alice().ss58)).toBe(0);
            }),
        );
    });

    it("limits open streams per caller (D36)", async () => {
        const slots = new StreamSlots(1);
        let open: () => void = () => undefined;
        const gate = new Promise<void>((r) => (open = r));
        const url = await streamMiner(
            () =>
                (async function* () {
                    yield [1];
                    await gate;
                    yield [2];
                })(),
            { slots },
        );
        const first = await client().stream("POST", `${url}/`, enc("{}"), bob().ss58);
        expect(await first.next()).not.toBeNull();
        const refused = await fetch(`${url}/`, {
            method: "POST",
            body: enc("{}"),
            headers: new Signer(alice()).sign("POST", "/", enc("{}"), bob().ss58).headers,
        });
        expect(refused.status).toBe(429);
        expect(refused.headers.get("retry-after")).toBe("1");
        expect(refused.headers.get("x-tw-resp-signature")).not.toBeNull();
        expect(await codeOf(client().stream("POST", `${url}/`, enc("{}"), bob().ss58))).toBe(
            "tw.rate_limited",
        );
        const other = await client(keypair("alice_ed25519")).stream("POST", `${url}/`, enc("{}"), bob().ss58);
        open();
        expect(await first.result()).toEqual([[1], [2]]);
        expect(await other.result()).toEqual([[1], [2]]);
        expect(slots.open(alice().ss58)).toBe(0);
    });

    it("cuts a client that stops reading at maxS", async () => {
        const aborts: string[] = [];
        const slots = new StreamSlots(1);
        const big = { x: "a".repeat(60_000) };
        const url = await streamMiner(
            async function* () {
                for (;;) {
                    await Promise.resolve();
                    yield big;
                }
            },
            {
                limits: new StreamLimits({ maxS: 1, maxBytes: 64 << 20 }),
                slots,
                onAbort: (_r, reason) => aborts.push(reason),
            },
        );
        const { hostname, port } = new URL(url);
        const signed = new Signer(alice()).sign("POST", "/", enc("{}"), bob().ss58);
        const socket = connect(Number(port), hostname);
        socket.pause(); // never reads the answer
        const head = Object.entries(signed.headers)
            .map(([k, v]) => `${k}: ${v}\r\n`)
            .join("");
        socket.write(`POST / HTTP/1.1\r\nHost: ${hostname}\r\n${head}Content-Length: 2\r\n\r\n{}`);
        for (let i = 0; aborts.length === 0 && i < 500; i++) await sleep(10);
        expect(aborts).toEqual(["max_duration"]);
        for (let i = 0; slots.open(alice().ss58) > 0 && i < 300; i++) await sleep(10);
        expect(slots.open(alice().ss58)).toBe(0);
        socket.destroy();
    });

    it("refuses streamReply outside the plugin", async () => {
        const app = Fastify({ logger: false });
        app.get("/", (req, reply) => streamReply(req, reply, list()));
        const r = await app.inject({ method: "GET", url: "/" });
        expect(r.statusCode).toBe(500);
        await app.close();
    });
});

// ---------------------------------------------------------------- client against a fake miner

interface Fake {
    chunks: string[];
    before: string;
    extra: string;
    trailer: ((digest: string, count: number, sig: string) => string) | null;
    headers: Record<string, string>;
    drop: string[];
    delayMs: number;
}

const stdTrailer = (d: string, n: number, s: string) => `{"digest":"${d}","count":${n},"signature":"${s}"}`;

function fake(change: Partial<Fake> = {}): Fake {
    return {
        chunks: ['{"i":0}', '{"i":1}', '{"i":2}'],
        before: "",
        extra: "",
        trailer: stdTrailer,
        headers: {},
        drop: [],
        delayMs: 0,
        ...change,
    };
}

async function listen(
    handler: (req: IncomingMessage, res: ServerResponse) => void | Promise<void>,
): Promise<string> {
    const server = createServer((req, res) => void handler(req, res));
    servers.push(server);
    await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
    return `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
}

async function fakeMiner(f: Fake): Promise<string> {
    return listen(async (req, res) => {
        const nonce = BigInt(String(req.headers["x-bittensor-nonce"]));
        const sender = String(req.headers["x-bittensor-hotkey"]);
        const d = new StreamDigest();
        for (const c of f.chunks) d.update(enc(c));
        const sig = signatureHex(
            bob().sign(
                responsePayload(
                    "sr25519",
                    { requestNonce: nonce, sender, status: 200 },
                    bob().ss58,
                    d.hexdigest(),
                ),
            ),
        );
        const headers: Record<string, string> = {
            "content-type": "text/event-stream; charset=utf-8",
            "x-tw-resp-version": "1",
            "x-tw-resp-hotkey": bob().ss58,
            ...f.headers,
        };
        for (const k of f.drop) Reflect.deleteProperty(headers, k);
        res.writeHead(200, headers);
        const frames = [f.before, ...f.chunks.map((c) => `event: chunk\ndata: ${c}\n\n`)];
        if (f.trailer !== null)
            frames.push(`event: tw-end\ndata: ${f.trailer(d.hexdigest(), d.count, sig)}\n\n`);
        frames.push(f.extra);
        for (const frame of frames) {
            if (f.delayMs > 0) await sleep(f.delayMs);
            if (res.destroyed) return;
            res.write(frame);
        }
        res.end();
    });
}

async function runFake(f: Fake, options = {}): Promise<unknown[]> {
    const url = await fakeMiner(f);
    const s = await client().stream("POST", `${url}/s`, enc("{}"), bob().ss58, options);
    return s.result();
}

describe("Client.stream rules", () => {
    it("accepts valid streams and ignores comments and unknown events", async () => {
        expect(await runFake(fake())).toHaveLength(3);
        expect(await runFake(fake({ before: ": hi\n\nevent: ping\ndata: x\n\nid: 4\n\n" }))).toHaveLength(3);
        expect(await runFake(fake({ chunks: [] }))).toEqual([]);
    });

    it("rejects every rule violation with its code", async () => {
        const bad = "tw.bad_response_signature";
        const cases: [Partial<Fake>, string][] = [
            [{ extra: "event: chunk\ndata: {}\n\n" }, bad],
            [{ extra: "event: other\ndata: x\n\n" }, bad],
            [{ extra: `event: tw-end\ndata: ${stdTrailer("0", 0, "0x")}\n\n` }, bad],
            [{ trailer: null }, bad],
            [{ trailer: (d, n, s) => stdTrailer(d, n + 1, s) }, bad],
            [{ trailer: (_d, n, s) => stdTrailer("0".repeat(64), n, s) }, bad],
            [{ trailer: (d, n) => stdTrailer(d, n, `0x${"00".repeat(64)}`) }, bad],
            [{ trailer: (d, n) => `{"digest":"${d}","count":${n}}` }, bad],
            [{ trailer: () => '{"digest":1}' }, bad],
            [{ drop: ["x-tw-resp-version"] }, bad],
            [{ drop: ["x-tw-resp-hotkey"] }, bad],
            [{ headers: { "x-tw-resp-signature": "0x00" } }, bad],
            [{ headers: { "x-tw-resp-hotkey": alice().ss58 } }, bad],
            [{ headers: { "content-encoding": "gzip" } }, "tw.invalid_response"],
            [{ chunks: ["[1]", "5"] }, "tw.invalid_response"],
            [{ chunks: ["{x"] }, "tw.invalid_response"],
        ];
        for (const [change, code] of cases) {
            expect(await codeOf(runFake(fake(change))), JSON.stringify(Object.keys(change))).toBe(code);
        }
    });

    it("detects tampering in transit", async () => {
        const upstream = await streamMiner(() => list(enc('{"i":0}'), enc('{"i":1}'), enc('{"i":2}')));
        const edits: ((b: string) => string)[] = [
            (b) => b.replace('{"i":1}', '{"i":7}'),
            (b) => b.replace('{"i":0}', "#").replace('{"i":1}', '{"i":0}').replace("#", '{"i":1}'),
            (b) => b.replace('event: chunk\ndata: {"i":1}\n\n', ""),
            (b) => b.replace("event: tw-end", "event: chunk\ndata: {}\n\nevent: tw-end"),
        ];
        for (const edit of edits) {
            const relay = await listen(async (req, res) => {
                const body: Buffer[] = [];
                for await (const piece of req) body.push(piece as Buffer);
                const headers = Object.fromEntries(
                    Object.entries(req.headers).filter(([k]) => k.startsWith("x-bittensor-")),
                ) as Record<string, string>;
                const r = await fetch(`${upstream}${req.url ?? "/"}`, {
                    method: req.method ?? "POST",
                    headers,
                    body: Buffer.concat(body),
                });
                const text = edit(await r.text());
                const out: Record<string, string> = {};
                r.headers.forEach((v, k) => {
                    if (k !== "content-length" && k !== "transfer-encoding") out[k] = v;
                });
                res.writeHead(r.status, out);
                res.end(text);
            });
            const s = await client().stream("POST", `${relay}/`, enc("{}"), bob().ss58);
            expect(await codeOf(s.result())).toBe("tw.bad_response_signature");
        }
    });

    it("applies the limits; the caller's own time is not idle", async () => {
        const [idle, deadline, big] = await Promise.all([
            codeOf(
                runFake(fake({ delayMs: 1500 }), {
                    limits: new StreamLimits({ idleS: 1 }),
                    timeoutMs: 30_000,
                }),
            ),
            codeOf(runFake(fake({ delayMs: 400 }), { timeoutMs: 1200 })),
            codeOf(
                runFake(fake({ chunks: [`{"x":"${"a".repeat(2000)}"}`] }), {
                    limits: new StreamLimits({ maxBytes: 1024 }),
                }),
            ),
        ]);
        expect([idle, deadline, big]).toEqual(["tw.timeout", "tw.timeout", "tw.response_too_large"]);
        const url = await fakeMiner(fake());
        const s = await client().stream("POST", `${url}/`, enc("{}"), bob().ss58, {
            limits: new StreamLimits({ idleS: 1 }),
            timeoutMs: 10_000,
        });
        while ((await s.next()) !== null) {
            await sleep(1300);
        }
        expect(s.values).toHaveLength(3);
    });

    it("turns other answers into their codes", async () => {
        const answer = (status: number, body: string, sign: boolean) =>
            listen((req, res) => {
                const headers: Record<string, string> = {};
                if (sign) {
                    Object.assign(
                        headers,
                        signResponse(
                            bob(),
                            {
                                requestNonce: BigInt(String(req.headers["x-bittensor-nonce"])),
                                sender: String(req.headers["x-bittensor-hotkey"]),
                                status,
                            },
                            enc(body),
                        ),
                    );
                }
                res.writeHead(status, headers);
                res.end(body);
            });
        const cases: [number, string, boolean, string][] = [
            [
                403,
                '{"error":{"code":"tw.forbidden_not_validator","message":"x","request_id":null}}',
                true,
                "tw.forbidden_not_validator",
            ],
            [
                401,
                '{"error":{"code":"tw.auth_stale","message":"x","request_id":null}}',
                false,
                "tw.auth_stale",
            ],
            [502, "bad gateway", false, "tw.http_502"],
            [200, '{"a":1}', true, "tw.invalid_response"],
            [200, '{"a":1}', false, "tw.bad_response_signature"],
            [500, "x".repeat(100), false, "tw.response_too_large"],
        ];
        for (const [status, body, sign, code] of cases) {
            const url = await answer(status, body, sign);
            const c = new Client({ signer: new Signer(alice()), maxResponseBytes: 90 });
            expect(
                await codeOf(c.stream("POST", `${url}/`, enc("{}"), bob().ss58)),
                `${status} ${body}`,
            ).toBe(code);
        }
        expect(await codeOf(client().stream("POST", "http://127.0.0.1:1/", enc("{}"), bob().ss58))).toBe(
            "tw.connect_error",
        );
        await expect(client().stream("GET", "http://127.0.0.1:1/", enc("x"), bob().ss58)).rejects.toThrow(
            RangeError,
        );
        const slow = await listen(async (_req, res) => {
            await sleep(2000);
            res.end();
        });
        expect(
            await codeOf(client().stream("POST", `${slow}/`, enc("{}"), bob().ss58, { timeoutMs: 200 })),
        ).toBe("tw.timeout");
        const cut = await listen((_req, res) => {
            res.writeHead(200, {
                "content-type": "text/event-stream",
                "x-tw-resp-version": "1",
                "x-tw-resp-hotkey": bob().ss58,
                "content-length": "100",
            });
            res.write("event: chunk\ndata: {}\n\n");
            setTimeout(() => res.destroy(), 50);
        });
        const s = await client().stream("POST", `${cut}/`, enc("{}"), bob().ss58);
        expect(await codeOf(s.result())).toBe("tw.bad_response_signature");
        expect(await codeOf(s.next())).toBe("tw.bad_response_signature");
        expect(new ClientError("tw.http_404", "").code).toBe("tw.http_404");
    });
});
