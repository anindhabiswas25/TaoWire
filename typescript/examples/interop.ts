// The TypeScript side of the live interop check (conformance/interop/live_check.py,
// spec 13.5 without a chain). Same command line as go/cmd/btauth-interop:
//
//   node build/examples/interop.js serve --addr 127.0.0.3:8097 --seed <hex> [--scheme sr25519]
//   node build/examples/interop.js sign --url http://127.0.0.2:8094/v1/upper --seed <hex> \
//       --receiver <ss58> [--scheme ed25519] [--count 200] [--body '{"text":"hello"}']
//   node build/examples/interop.js stream --url http://127.0.0.2:8094/v1/stream --seed <hex> \
//       --receiver <ss58> [--scheme ed25519] [--count 1] [--body '{"text":"hello"}']
//
// serve answers POST /v1/upper ({"text": s} -> {"result": upper(s)}) behind the Fastify
// adapter with twresp/1 signing, and POST /v1/stream with five SSE chunks
// {"i": n, "text": upper(s)} and a signed tw-end (spec 9.2). sign sends count requests
// with a fresh signature each and prints one JSON summary line; stream reads count
// streams the same way (conformance/interop/stream_check.py). Seeds are public dev keys
// only.
import { parseArgs } from "node:util";
import Fastify from "fastify";
import {
    Client,
    ClientError,
    Keypair,
    MemoryStore,
    type Scheme,
    Signer,
    TWError,
    Verifier,
    initCrypto,
} from "@tensorwire/btauth";
import { btauth, rawBody, streamReply } from "@tensorwire/btauth/fastify";

function textOf(body: Buffer): string {
    let text: unknown;
    try {
        text = (JSON.parse(body.toString("utf8")) as { text?: unknown }).text;
    } catch {
        throw new TWError("tw.invalid_request", "body is not JSON");
    }
    if (typeof text !== "string") {
        throw new TWError("tw.invalid_request", "text must be a string");
    }
    return text;
}

function key(seedHex: string, scheme: Scheme): Keypair {
    const seed = Buffer.from(seedHex.replace(/^0x/, ""), "hex");
    if (seed.length !== 32) {
        throw new Error("--seed must be 32 bytes of hex");
    }
    return Keypair.fromSeed(scheme, seed);
}

async function serve(addr: string, k: Keypair): Promise<void> {
    const [host, port] = addr.split(":");
    const app = Fastify({ logger: false });
    await app.register(btauth, {
        verifier: new Verifier({ selfHotkey: k.ss58, store: new MemoryStore(60) }),
        responseKey: k,
        hotkeyRateLimit: false,
        routes: (scope) => {
            scope.post("/v1/upper", (request) => ({ result: textOf(rawBody(request)).toUpperCase() }));
            scope.post("/v1/stream", (request, reply) => {
                const text = textOf(rawBody(request)).toUpperCase();
                async function* chunks() {
                    for (let i = 0; i < 5; i++) {
                        await Promise.resolve();
                        yield { i, text };
                    }
                }
                return streamReply(request, reply, chunks(), { route: "/v1/stream" });
            });
        },
    });
    app.get("/healthz", () => "ok");
    await app.listen({ host: host ?? "127.0.0.3", port: Number(port) });
    console.log(`serving ${addr} as ${k.ss58}`);
}

async function sign(
    url: string,
    receiver: string,
    body: string,
    count: number,
    k: Keypair,
): Promise<boolean> {
    const client = new Client({ signer: new Signer(k), timeoutMs: 10_000 });
    const statuses: Record<number, number> = {};
    const errors: Record<string, number> = {};
    let ok = 0;
    for (let i = 0; i < count; i++) {
        try {
            const res = await client.request("POST", url, Buffer.from(body), receiver);
            statuses[res.status] = (statuses[res.status] ?? 0) + 1;
            if (res.status === 200) {
                ok++;
            }
        } catch (err) {
            if (err instanceof ClientError && err.responseStatus !== null) {
                statuses[err.responseStatus] = (statuses[err.responseStatus] ?? 0) + 1;
            }
            const code = err instanceof TWError ? err.code : "exception";
            errors[code] = (errors[code] ?? 0) + 1;
        }
    }
    const summary = { language: "typescript", signer: k.ss58, scheme: k.scheme, count, ok, statuses, errors };
    console.log(JSON.stringify(summary));
    return ok === count;
}

async function stream(
    url: string,
    receiver: string,
    body: string,
    count: number,
    k: Keypair,
): Promise<boolean> {
    const client = new Client({ signer: new Signer(k), timeoutMs: 12_000 });
    const errors: Record<string, number> = {};
    let ok = 0;
    let chunks: unknown[] = [];
    for (let i = 0; i < count; i++) {
        try {
            const s = await client.stream("POST", url, Buffer.from(body), receiver);
            chunks = await s.result();
            ok++;
        } catch (err) {
            const code = err instanceof TWError ? err.code : "exception";
            errors[code] = (errors[code] ?? 0) + 1;
        }
    }
    const summary = { language: "typescript", signer: k.ss58, scheme: k.scheme, count, ok, errors, chunks };
    console.log(JSON.stringify(summary));
    return ok === count;
}

async function main(): Promise<number> {
    const [mode, ...rest] = process.argv.slice(2);
    const { values } = parseArgs({
        args: rest,
        options: {
            addr: { type: "string", default: "127.0.0.3:8097" },
            seed: { type: "string", default: "" },
            scheme: { type: "string", default: "sr25519" },
            url: { type: "string", default: "" },
            receiver: { type: "string", default: "" },
            count: { type: "string" },
            body: { type: "string", default: '{"text":"hello"}' },
        },
    });
    await initCrypto();
    const k = key(values.seed, values.scheme === "ed25519" ? "ed25519" : "sr25519");
    if (mode === "serve") {
        await serve(values.addr, k);
        return -1; // keep serving
    }
    if (mode === "sign") {
        return (await sign(values.url, values.receiver, values.body, Number(values.count ?? "200"), k))
            ? 0
            : 1;
    }
    if (mode === "stream") {
        return (await stream(values.url, values.receiver, values.body, Number(values.count ?? "1"), k))
            ? 0
            : 1;
    }
    console.error("usage: interop.js serve|sign|stream [flags]");
    return 2;
}

main().then(
    (code) => {
        if (code >= 0) {
            process.exit(code);
        }
    },
    (err: unknown) => {
        console.error(err);
        process.exit(1);
    },
);
