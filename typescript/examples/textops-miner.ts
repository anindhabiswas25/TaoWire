// The text-ops example subnet's miner in TypeScript (spec 10, 11.1): the same routes and
// byte-identical answers as the Python miner in examples/text-ops-subnet, on the Fastify
// adapter, with caller policy and serve-axon from the TaoWire sidecar (`taowire
// sidecar`, spec 11.6).
//
//   POST /v1/transform         {"text": s, "op": "upper"|"reverse"|"sha256"} -> {"result": ...}
//   POST /v1/transform/stream  the same, as an SSE stream of {"i": n, "piece": ...} (32 characters)
//   GET  /healthz, /readyz
//
// Every request runs, in order: the per-IP limit (429, unsigned), btauth/1 verification,
// the caller policy from the sidecar's metagraph (403 / 503), the per-hotkey limit (429,
// signed), then the handler; answers after authentication are signed with twresp/1.
// Configuration is the TW_* variables of the Python miner that apply
// (examples/text-ops-miners/README.md).
//
//   npm run build:examples && node build/examples/textops-miner.js
import { createHash } from "node:crypto";
import { homedir } from "node:os";
import { join } from "node:path";
import Fastify from "fastify";
import {
    Keypair,
    MemoryStore,
    type NonceStore,
    StreamLimits,
    StreamSlots,
    TWError,
    TokenBuckets,
    Verifier,
    errorBody,
    initCrypto,
} from "@taowire/btauth";
import { btauth, rawBody, streamReply } from "@taowire/btauth/fastify";
import { RedisNonceStore } from "@taowire/btauth/redis";
import { CallerPolicy, SidecarChainError, SidecarClient } from "@taowire/btauth/sidecar";

const ROUTE = "/v1/transform";
const STREAM_ROUTE = "/v1/transform/stream";
const PIECE_CHARS = 32;
const MAX_BODY = 64_000;
const MAX_TEXT = 4096;
const TIMEOUT_MS = 5_000; // the Python route's timeout_s

/** The one correct answer (Python's str.upper, [::-1], sha256 of UTF-8); identical for ASCII. */
function expected(text: string, op: string): string {
    if (op === "upper") return text.toUpperCase();
    if (op === "reverse") return Array.from(text).reverse().join("");
    return createHash("sha256").update(text, "utf8").digest("hex");
}

/** The body like the Python model: text (1-4096 characters) and op; other keys ignored. */
function parse(body: Buffer): { text: string; op: string } {
    let value: unknown;
    try {
        value = JSON.parse(body.toString("utf8"));
    } catch {
        throw new TWError("tw.invalid_request", "body is not JSON");
    }
    if (typeof value !== "object" || value === null || Array.isArray(value)) {
        throw new TWError("tw.invalid_request", "body is not a JSON object");
    }
    const { text, op } = value as { text?: unknown; op?: unknown };
    if (typeof text !== "string" || typeof op !== "string") {
        throw new TWError("tw.invalid_request", "text and op must be strings");
    }
    const n = Array.from(text).length;
    if (n < 1 || n > MAX_TEXT) throw new TWError("tw.invalid_request", "text must be 1-4096 characters");
    if (op !== "upper" && op !== "reverse" && op !== "sha256")
        throw new TWError("tw.invalid_request", "unknown op");
    return { text, op };
}

// ---------------------------------------------------------------- settings

const problems: string[] = [];
const str = (name: string, def: string) => process.env[name] || def;
const required = (name: string) => {
    const v = process.env[name] ?? "";
    if (v === "") problems.push(name);
    return v;
};
const num = (name: string, def: number) => {
    const v = process.env[name];
    if (v === undefined || v === "") return def;
    const n = Number(v);
    if (!Number.isFinite(n)) problems.push(`${name} (not a number)`);
    return n;
};
const flag = (name: string, def: boolean) => {
    const v = process.env[name] ?? "";
    if (v === "") return def;
    if (v === "1" || v === "true") return true;
    if (v === "0" || v === "false") return false;
    problems.push(`${name} (0 or 1)`);
    return def;
};
const list = (name: string) =>
    (process.env[name] ?? "")
        .split(",")
        .map((v) => v.trim())
        .filter((v) => v !== "");
const home = (p: string) => (p.startsWith("~/") ? join(homedir(), p.slice(2)) : p);

function log(event: string, fields: Record<string, unknown> = {}): void {
    console.log(JSON.stringify({ event, ...fields }));
}

async function main(): Promise<void> {
    const netuid = num("TW_NETUID", -1);
    if (!Number.isInteger(netuid) || netuid < 0) problems.push("TW_NETUID");
    const wallet = required("TW_WALLET_NAME");
    const hotkeyFile = join(
        home(str("TW_WALLET_PATH", "~/.bittensor/wallets")),
        wallet,
        "hotkeys",
        str("TW_WALLET_HOTKEY", "default"),
    );
    const port = num("TW_BIND_PORT", 8091);
    const host = str("TW_BIND_HOST", "0.0.0.0");
    const externalIp = required("TW_EXTERNAL_IP");
    const externalPort = num("TW_EXTERNAL_PORT", port);
    const autoServe = flag("TW_AUTO_SERVE_AXON", true);
    const state = str("TW_STATE_DIR", "~/.taowire");
    const tokenFile = home(str("TW_SIDECAR_TOKEN_FILE", `${state}/sidecar.token`));
    const sidecarUrl = `http://127.0.0.1:${String(num("TW_SIDECAR_PORT", 9910))}`;
    const retention = num("TW_NONCE_RETENTION_S", 60);
    const softAgeS = num("TW_METAGRAPH_SOFT_AGE_S", 0);
    const maxAgeS = num("TW_METAGRAPH_MAX_AGE_S", 0);
    const policyOptions = {
        requirePermit: flag("TW_REQUIRE_PERMIT", true),
        minStakeTao: num("TW_MIN_CALLER_STAKE_TAO", 0),
        allowHotkeys: list("TW_ALLOW_HOTKEYS"),
        denyHotkeys: list("TW_DENY_HOTKEYS"),
    };
    const ipLimit = { perS: num("TW_RATE_IP_PER_S", 50), burst: num("TW_RATE_IP_BURST", 100) };
    const hotkeyLimit = { perS: num("TW_RATE_HOTKEY_PER_S", 20), burst: num("TW_RATE_HOTKEY_BURST", 40) };
    if (problems.length > 0) throw new Error(`settings: ${problems.join(", ")}`);

    await initCrypto();
    const key = Keypair.fromHotkeyFile(hotkeyFile);
    const redisUrl = process.env.TW_REDIS_URL;
    const store: NonceStore =
        redisUrl === undefined || redisUrl === ""
            ? new MemoryStore(retention)
            : RedisNonceStore.fromUrl(redisUrl, retention);
    const verifier = new Verifier({
        selfHotkey: key.ss58,
        store,
        maxAgeS: num("TW_AUTH_MAX_AGE_S", 10),
        allowedSkewS: num("TW_AUTH_ALLOWED_SKEW_S", 2),
    });
    const sidecar = new SidecarClient({
        netuid,
        url: sidecarUrl,
        tokenFile,
        expectedHotkey: key.ss58,
        policy: new CallerPolicy(policyOptions),
        strict: flag("TW_METAGRAPH_STRICT", false),
        ...(softAgeS > 0 ? { softAgeS } : {}),
        ...(maxAgeS > 0 ? { maxAgeS } : {}),
    });
    try {
        await sidecar.start();
    } catch (err) {
        throw new Error(`sidecar at ${sidecarUrl}: ${String(err)}`);
    }
    if (autoServe) await publish(sidecar, key.ss58, externalIp, externalPort);
    const streamOptions = {
        limits: new StreamLimits({
            maxS: num("TW_STREAM_MAX_S", 60),
            maxBytes: num("TW_STREAM_MAX_BYTES", 4 * 1024 * 1024),
            idleS: num("TW_STREAM_IDLE_S", 10),
        }),
        slots: new StreamSlots(num("TW_STREAM_MAX_PER_CALLER", 16)),
        firstChunkTimeoutMs: TIMEOUT_MS,
        route: STREAM_ROUTE,
        onAbort: (route: string, reason: string) => {
            log("stream_aborted", { route, reason });
        },
    };
    const ips = new TokenBuckets(ipLimit);

    const app = Fastify({
        logger: false,
        requestTimeout: 10_000, // receiving the request only; never a running stream
        keepAliveTimeout: 5_000,
        maxParamLength: 200,
    });
    // The pre-auth per-IP limit (spec 8.6.2 layer 1): 429, unsigned.
    app.addHook("onRequest", async (request, reply) => {
        const wait = ips.take(request.ip);
        if (wait > 0) {
            const tw = new TWError("tw.rate_limited", "per-IP limit");
            await reply
                .code(tw.status)
                .header("Retry-After", String(wait))
                .type("application/json")
                .send(errorBody(tw));
        }
    });
    app.get("/healthz", () => "ok");
    app.get("/readyz", async (_request, reply) => {
        const reasons = [
            ...(sidecar.stage() === "known_callers_only" ? ["metagraph_stale"] : []),
            ...(verifier.failingClosed() ? ["clock_step"] : []),
        ];
        return reply
            .code(reasons.length === 0 ? 200 : 503)
            .send({ ready: reasons.length === 0, reasons, stage: sidecar.stage() });
    });
    await app.register(btauth, {
        verifier,
        responseKey: key,
        bodyLimit: MAX_BODY,
        policy: sidecar.policyHook(),
        hotkeyRateLimit: hotkeyLimit,
        routes: (scope) => {
            scope.post(ROUTE, (request) => {
                const { text, op } = parse(rawBody(request));
                return { result: expected(text, op) };
            });
            scope.post(STREAM_ROUTE, (request, reply) => {
                const { text, op } = parse(rawBody(request));
                const chars = Array.from(expected(text, op));
                async function* pieces() {
                    for (let i = 0; i * PIECE_CHARS < chars.length; i++) {
                        await Promise.resolve();
                        yield { i, piece: chars.slice(i * PIECE_CHARS, (i + 1) * PIECE_CHARS).join("") };
                    }
                }
                return streamReply(request, reply, pieces(), streamOptions);
            });
        },
    });
    await app.listen({ host, port });
    log("miner_started", { bind: `${host}:${String(port)}`, hotkey: key.ss58, netuid, sidecar: sidecarUrl });
    const stop = () => {
        sidecar.stop();
        void app.close().then(() => process.exit(0));
    };
    process.once("SIGTERM", stop);
    process.once("SIGINT", stop);
}

/** Serve the axon through the sidecar unless the snapshot already shows it; a refusal is logged. */
async function publish(sidecar: SidecarClient, hotkey: string, ip: string, port: number): Promise<void> {
    const want = `${ip}:${String(port)}`;
    if (sidecar.snapshot()?.byHotkey.get(hotkey)?.axon === want) {
        log("axon_in_sync", { external: want });
        return;
    }
    try {
        log("axon_published", { external: want, block_hash: await sidecar.serveAxon({ ip, port }) });
    } catch (err) {
        if (err instanceof SidecarChainError)
            log("serve_axon_rejected", { code: err.code, remediation: err.remediation });
        else log("serve_axon_failed", { error: String(err) });
    }
}

main().catch((err: unknown) => {
    log("startup_refused", { reason: err instanceof Error ? err.message : String(err) });
    process.exit(1);
});
