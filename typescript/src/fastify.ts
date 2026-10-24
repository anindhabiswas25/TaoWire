/**
 * Fastify adapter (spec 11.3): `@tensorwire/btauth/fastify`.
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
import { signResponse } from "./twresp.js";
import type { Caller, Verifier } from "./verify.js";

declare module "fastify" {
    interface FastifyRequest {
        /** The verified caller on a protected route (`null` before verification). */
        btauthCaller: Caller | null;
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

function refuse(reply: FastifyReply, error: TWError): FastifyReply {
    // A client-side code (e.g. a ClientError from an upstream call) has no
    // HTTP status: it is a handler failure here.
    const tw = error.status === 0 ? new TWError("tw.handler_error", error.message) : error;
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
            if (caller === null) {
                return payload; // refused before authentication: never signed
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
