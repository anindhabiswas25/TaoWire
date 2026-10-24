/**
 * Fastify adapter (spec 11.3): `@taowire/btauth/fastify`.
 *
 * ```ts
 * await app.register(btauth, {
 *   verifier, responseKey: minerKey,
 *   routes: (scope) => { scope.post("/v1/echo", async (req) => ({ from: req.btauthCaller?.hotkey })); },
 * });
 * ```
 *
 * Every route registered in `routes` gets, in order (Fastify's
 * `preValidation` stage, before any route schema): the raw body as a
 * `Buffer` for every content type (none included), capped at `bodyLimit`
 * (413); btauth/1 verification with `request.raw.url` (the target exactly
 * as sent, `request.originalUrl`) as the target; the `policy` hook (e.g. the sidecar caller
 * policy); the per-hotkey token bucket (429 with `Retry-After`); the
 * handler. Every reply after authentication is signed with twresp/1 when
 * `responseKey` is set, errors included; refusals before authentication are
 * not (spec 9.1, Appendix A).
 *
 * @module
 */
import type {
    FastifyError,
    FastifyInstance,
    FastifyPluginAsync,
    FastifyReply,
    FastifyRequest,
} from "fastify";
import { TWError, errorBody } from "./errors.js";
import { type Keypair, initCrypto } from "./keys.js";
import { DEFAULT_HOTKEY_LIMIT, type RateLimit, TokenBuckets } from "./ratelimit.js";
import {
    CONTENT_TYPE,
    EVENT_CHUNK,
    EVENT_END,
    StreamDigest,
    StreamLimits,
    StreamSlots,
    TRAILER_RESERVE,
    after,
    encodeChunk,
    encodeEvent,
    encodeTrailer,
} from "./streaming.js";
import { identityHeaders, signDigest, signResponse } from "./twresp.js";
import type { Caller, Verifier } from "./verify.js";

declare module "fastify" {
    interface FastifyRequest {
        /** The verified caller on a protected route (`null` before verification). */
        btauthCaller: Caller | null;
        /** The key answers are signed with (`null` when signing is off). */
        btauthResponseKey: Keypair | null;
    }
}

/** The caller-policy hook: throw a {@link TWError} (e.g. 403) to refuse. */
export type PolicyHook = (caller: Caller, request: FastifyRequest) => void | Promise<void>;

/** Options of the {@link btauth} plugin. */
export interface BtauthOptions {
    /** Verifies every request; its `selfHotkey` is the miner's hotkey. */
    verifier: Verifier;
    /** Signs answers with twresp/1; must be the verifier's hotkey. Omit only to disable signing. */
    responseKey?: Keypair;
    /** Body cap in bytes (default 1 MiB, `TW_MAX_BODY_BYTES`). */
    bodyLimit?: number;
    /** Caller policy, run after verification. */
    policy?: PolicyHook;
    /** Per-hotkey, per-route limit (default 20/s, burst 40); `false` disables it. */
    hotkeyRateLimit?: RateLimit | false;
    /** Registers the protected routes on the plugin's scope. */
    routes: (scope: FastifyInstance) => void | Promise<void>;
}

/** Default body cap (1 MiB, spec 8.6.1). */
export const DEFAULT_BODY_LIMIT = 1024 * 1024;

/** The raw body of a protected request (empty when there was none). */
export function rawBody(request: FastifyRequest): Buffer {
    return Buffer.isBuffer(request.body) ? request.body : Buffer.alloc(0);
}

/**
 * Codes answered unsigned even after authentication (Appendix A "Response
 * signed? no"), as in the Python pipeline: e.g. a policy's 503
 * `tw.metagraph_stale`.
 */
export const UNSIGNED_CODES: ReadonlySet<string> = new Set([
    "tw.internal",
    "tw.metagraph_stale",
    "tw.replay_store_unavailable",
]);

const unsigned = new WeakSet<FastifyRequest>();

function refuse(reply: FastifyReply, error: TWError): FastifyReply {
    // A client-side code (e.g. a ClientError from an upstream call) has no
    // HTTP status: it is a handler failure here.
    const tw = error.status === 0 ? new TWError("tw.handler_error", error.message) : error;
    if (UNSIGNED_CODES.has(tw.code)) unsigned.add(reply.request);
    return reply.code(tw.status).type("application/json").send(errorBody(tw));
}

function asTWError(error: unknown, authenticated: boolean, request: FastifyRequest): TWError {
    if (error instanceof TWError) {
        return error;
    }
    const fe = error as Partial<FastifyError>;
    const message = String(fe.message);
    if (fe.statusCode === 413) {
        return new TWError("tw.payload_too_large", message);
    }
    if (!authenticated) {
        // The body or request could not be read; nothing is known about the caller.
        return new TWError("tw.auth_malformed", "request could not be read");
    }
    if (fe.validation !== undefined) {
        return new TWError("tw.invalid_request", message);
    }
    request.log.error({ err: error }, "handler_error");
    return new TWError("tw.handler_error");
}

/** A thrown value as a TWError; anything else is `tw.internal` (fail closed). */
function asInternal(err: unknown): TWError {
    return err instanceof TWError ? err : new TWError("tw.internal", String(err));
}

/**
 * Protect the routes registered in `options.routes` with btauth/1 (see the
 * module docs). Awaits {@link initCrypto}. Throws at registration when
 * `responseKey` is not the verifier's hotkey.
 */
export const btauth: FastifyPluginAsync<BtauthOptions> = async (scope, options) => {
    const { verifier, responseKey, policy } = options;
    if (responseKey !== undefined && responseKey.ss58 !== verifier.selfHotkey) {
        throw new Error("btauth: responseKey must be the verifier's selfHotkey");
    }
    await initCrypto();
    const buckets =
        options.hotkeyRateLimit === false
            ? null
            : new TokenBuckets(options.hotkeyRateLimit ?? DEFAULT_HOTKEY_LIMIT);

    scope.removeAllContentTypeParsers();
    scope.addContentTypeParser(
        "*",
        { parseAs: "buffer", bodyLimit: options.bodyLimit ?? DEFAULT_BODY_LIMIT },
        (_request, body, done) => {
            done(null, body);
        },
    );
    scope.decorateRequest("btauthCaller", null);
    scope.decorateRequest("btauthResponseKey", null);

    scope.setErrorHandler((error, request, reply) => {
        const tw = asTWError(error, request.btauthCaller !== null, request);
        return refuse(reply, tw);
    });

    // preValidation: after the body is read, before any route schema runs, so
    // nothing parses or validates the body of an unauthenticated request.
    scope.addHook("preValidation", async (request, reply) => {
        // originalUrl: the target exactly as received, also when the app sets rewriteUrl
        const target = request.originalUrl;
        if (!target.startsWith("/")) {
            return refuse(reply, new TWError("tw.auth_malformed", "request target must be origin-form"));
        }
        let caller: Caller;
        try {
            caller = await verifier.verify({
                headers: request.raw.rawHeaders,
                body: rawBody(request),
                method: request.method,
                target,
            });
        } catch (err) {
            const tw = asInternal(err);
            request.log.info({ code: tw.code, detail: tw.detail }, "btauth_refused");
            return refuse(reply, tw);
        }
        request.btauthCaller = caller;
        request.btauthResponseKey = responseKey ?? null;
        if (policy !== undefined) {
            try {
                await policy(caller, request);
            } catch (err) {
                return refuse(reply, asInternal(err));
            }
        }
        if (buckets !== null) {
            const wait = buckets.take(`${caller.hotkey} ${String(request.routeOptions.url)}`);
            if (wait > 0) {
                void reply.header("Retry-After", String(wait));
                return refuse(reply, new TWError("tw.rate_limited", "per-hotkey limit"));
            }
        }
        return undefined;
    });

    if (responseKey !== undefined) {
        scope.addHook("onSend", async (request, reply, payload: unknown) => {
            const caller = request.btauthCaller;
            if (caller === null || unsigned.has(request)) {
                return payload; // refused before authentication, or an unsigned code
            }
            let bytes: Buffer;
            if (payload === null || payload === undefined) {
                bytes = Buffer.alloc(0);
            } else if (typeof payload === "string") {
                bytes = Buffer.from(payload, "utf8");
            } else if (Buffer.isBuffer(payload)) {
                bytes = payload;
            } else {
                // A stream cannot be signed as a whole: streaming routes use the
                // streaming helper. Release it (file descriptor, socket) at once.
                (payload as { destroy?: () => void }).destroy?.();
                request.log.error("btauth: a stream reply on a signed route; use the streaming helper");
                const tw = new TWError("tw.handler_error");
                void reply.code(tw.status).type("application/json");
                bytes = Buffer.from(errorBody(tw));
            }
            // HEAD answers carry no body on the wire: sign what the client receives.
            const signed = request.raw.method === "HEAD" ? Buffer.alloc(0) : bytes;
            const headers = signResponse(
                responseKey,
                { requestNonce: caller.nonce, sender: caller.hotkey, status: reply.statusCode },
                signed,
            );
            for (const [name, value] of Object.entries(headers)) {
                void reply.header(name, value);
            }
            return bytes;
        });
    }

    await options.routes(scope);
};

/** Abort reasons of a stream that ended without `tw-end` (spec 9.2, D29). */
export type AbortReason =
    "handler_error" | "idle_timeout" | "max_duration" | "max_bytes" | "bad_chunk" | "cancelled";

/** Options of {@link streamReply}. */
export interface StreamReplyOptions {
    /** Stream limits (spec 12.1 defaults). */
    limits?: StreamLimits;
    /** Wait for the first chunk at most this long, ms (default 10 000, `TW_HANDLER_TIMEOUT_S`). */
    firstChunkTimeoutMs?: number;
    /** Open streams per caller (D36); default: one process-wide set of 16 per caller. */
    slots?: StreamSlots;
    /** Names the route for `onAbort` and logs. */
    route?: string;
    /** Called once for every stream that ended without `tw-end`. */
    onAbort?: (route: string, reason: AbortReason) => void;
}

/** The process-wide default {@link StreamSlots} (16 per caller). */
export const DEFAULT_STREAM_SLOTS = new StreamSlots();

const CLOSE_MS = 1000;

async function closeIterator(it: AsyncIterator<unknown>): Promise<void> {
    const [late, cancel] = after(CLOSE_MS, undefined);
    try {
        await Promise.race([it.return?.(), late]);
    } catch {
        // a handler failing while it is closed changes nothing
    } finally {
        cancel();
    }
}

/**
 * Answer a protected request with an SSE stream and a signed `tw-end`
 * trailer (spec 9.2). Call it from a route registered in the {@link btauth}
 * plugin and return its result. Each chunk of `chunks` is a plain object or
 * array (sent as compact JSON) or bytes holding a JSON object or array. In
 * order:
 *
 * 1. a stream slot for the caller (D36): when the caller holds the maximum,
 *    it throws 429 `tw.rate_limited` (with `Retry-After: 1`), answered and
 *    signed by the plugin, and nothing is streamed;
 * 2. the first chunk within `firstChunkTimeoutMs`: an error is thrown as the
 *    signed JSON 500 `tw.handler_error` (a `TWError` with a status as it is),
 *    a stall as the signed JSON 504 `tw.handler_timeout`;
 * 3. `200 text/event-stream` (the reply is hijacked) with the `X-TW-Resp-*`
 *    identity headers, one `chunk` event per item, then `tw-end`.
 *
 * After the first byte, a handler error, a bad chunk, the idle limit, `maxS`
 * (writes to a client that stopped reading included: the socket is destroyed
 * at the deadline), `maxBytes` ({@link TRAILER_RESERVE} kept for the trailer)
 * or a client disconnect ends the stream without `tw-end`.
 */
export async function streamReply(
    request: FastifyRequest,
    reply: FastifyReply,
    chunks: AsyncIterable<unknown>,
    options: StreamReplyOptions = {},
): Promise<FastifyReply> {
    const caller = request.btauthCaller;
    if (caller === null) {
        throw new TWError("tw.internal", "streamReply needs a route of the btauth plugin");
    }
    const limits = options.limits ?? new StreamLimits();
    const route = options.route ?? String(request.routeOptions.url);
    let release: () => void;
    try {
        release = (options.slots ?? DEFAULT_STREAM_SLOTS).acquire(caller.hotkey);
    } catch (err) {
        void reply.header("Retry-After", "1");
        throw err;
    }
    const it = chunks[Symbol.asyncIterator]();
    let first: IteratorResult<unknown>;
    try {
        const [late, cancel] = after(options.firstChunkTimeoutMs ?? 10_000, "timeout" as const);
        let got: IteratorResult<unknown> | "timeout";
        try {
            got = await Promise.race([it.next(), late]);
        } finally {
            cancel();
        }
        if (got === "timeout") {
            void closeIterator(it);
            request.log.warn({ route }, "handler_timeout");
            throw new TWError("tw.handler_timeout");
        }
        first = got;
    } catch (err) {
        release();
        if (err instanceof TWError && err.status !== 0) {
            throw err;
        }
        request.log.error({ err, route }, "handler_error");
        throw new TWError("tw.handler_error");
    }
    void reply.hijack();
    const res = reply.raw;
    const key = request.btauthResponseKey;
    res.writeHead(200, {
        "Content-Type": CONTENT_TYPE,
        "Cache-Control": "no-store",
        "X-Accel-Buffering": "no",
        ...(key === null ? {} : identityHeaders(key)),
    });
    const deadline = Date.now() + limits.maxS * 1000;
    const closed = new Promise<"cancelled">((resolve) => {
        res.once("close", () => {
            resolve("cancelled");
        });
    });
    const write = async (frame: Uint8Array): Promise<AbortReason | null> => {
        if (res.destroyed) return "cancelled";
        if (res.write(frame)) return null;
        const [late, cancel] = after(deadline - Date.now(), "max_duration" as const);
        const drained = new Promise<null>((resolve) =>
            res.once("drain", () => {
                resolve(null);
            }),
        );
        try {
            return await Promise.race([drained, late, closed]);
        } finally {
            cancel();
        }
    };
    let reason: AbortReason | null = null;
    let delivered = false;
    let stalled = false; // the trailer did not leave before maxS
    try {
        const budget = limits.maxBytes - TRAILER_RESERVE;
        const digest = new StreamDigest();
        let sent = 0;
        let item = first;
        while (!item.done) {
            let data: Uint8Array;
            try {
                data = encodeChunk(item.value);
            } catch (err) {
                request.log.error({ route, reason: String(err) }, "stream_bad_chunk");
                reason = "bad_chunk";
                break;
            }
            const frame = encodeEvent(EVENT_CHUNK, data);
            if (sent + frame.length > budget) {
                reason = "max_bytes";
                break;
            }
            reason = await write(frame);
            if (reason !== null) break;
            sent += frame.length;
            digest.update(data);
            const [idle, cancelIdle] = after(limits.idleS * 1000, "idle_timeout" as const);
            const [total, cancelTotal] = after(deadline - Date.now(), "max_duration" as const);
            try {
                const next = await Promise.race([it.next(), idle, total, closed]);
                if (typeof next === "string") {
                    reason = next;
                    break;
                }
                item = next;
            } catch (err) {
                request.log.error({ err, route }, "handler_error");
                reason = "handler_error";
                break;
            } finally {
                cancelIdle();
                cancelTotal();
            }
        }
        if (reason === null) {
            const signature =
                key === null
                    ? null
                    : signDigest(
                          key,
                          { requestNonce: caller.nonce, sender: caller.hotkey, status: 200 },
                          digest.hexdigest(),
                      );
            const trailer = encodeTrailer({
                digest: digest.hexdigest(),
                count: BigInt(digest.count),
                signature,
            });
            delivered = true; // handed over: a disconnect from here on is no abort
            stalled = (await write(encodeEvent(EVENT_END, trailer))) !== null;
        }
    } finally {
        release();
        void closeIterator(it);
        if (reason !== null && !delivered) {
            request.log.warn(
                { route, reason, hint: "ended without tw-end; the client rejects the stream" },
                "stream_aborted",
            );
            options.onAbort?.(route, reason);
        }
        if (stalled || reason === "max_duration" || reason === "cancelled") {
            res.destroy();
        } else {
            res.end();
        }
    }
    return reply;
}
