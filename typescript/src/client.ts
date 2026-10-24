/**
 * The validator side: signed requests and verified answers over `fetch`
 * (Node's undici).
 *
 * @module
 */
import { TWError } from "./errors.js";
import { type Keypair, signatureHex } from "./keys.js";
import { NonceSource } from "./nonce.js";
import { type Scheme, buildPayload } from "./payload.js";
import { verifyResponse } from "./twresp.js";
import { HEADER } from "./verify.js";

/** Headers and nonce of one signed request. */
export interface SignedRequest {
    /** The btauth/1 headers to send. */
    headers: Record<string, string>;
    /** The nonce used (the twresp/1 answer is bound to it). */
    nonce: bigint;
}

/** Signs outgoing requests with a hotkey. */
export class Signer {
    /** The signing hotkey. */
    readonly key: Keypair;
    readonly #nonces: NonceSource;

    constructor(key: Keypair, nonces: NonceSource = new NonceSource()) {
        this.key = key;
        this.#nonces = nonces;
    }

    /**
     * The btauth/1 headers for one request. `target` is the request target
     * exactly as it will be sent. Every call takes a fresh nonce: sign again
     * for every retry (spec 4.3).
     */
    sign(method: string, target: string, body: Uint8Array, receiver: string): SignedRequest {
        const nonce = this.#nonces.next();
        const sig = this.key.sign(
            buildPayload({
                scheme: this.key.scheme,
                method,
                target,
                body,
                nonceNs: nonce,
                sender: this.key.ss58,
                receiver,
            }),
        );
        const headers: Record<string, string> = {
            [HEADER.version]: "1",
            [HEADER.hotkey]: this.key.ss58,
            [HEADER.receiver]: receiver,
            [HEADER.nonce]: nonce.toString(10),
            [HEADER.signature]: signatureHex(sig),
        };
        if (this.key.scheme === "ed25519") {
            headers[HEADER.crypto] = "ed25519";
        }
        return { headers, nonce };
    }
}

/**
 * The request target `fetch` sends for `url`: the serialized path and query
 * (percent-encoding as the WHATWG URL parser writes it), without the fragment.
 */
export function requestTarget(url: URL): string {
    const href = url.href.slice(url.origin.length);
    const hash = href.indexOf("#");
    return hash === -1 ? href : href.slice(0, hash);
}

/** Options of a {@link Client}. */
export interface ClientOptions {
    /** Signs every attempt anew. */
    signer: Signer;
    /** One time budget for all attempts, ms (default 12 000, spec 8.8). */
    timeoutMs?: number;
    /** Cap on the answer body (default 8 MiB). */
    maxResponseBytes?: number;
    /** Attempts when the connection could not be made (default 1), each with a fresh signature. */
    attempts?: number;
    /** Replaces the global `fetch` (tests). */
    fetch?: typeof fetch;
}

/** A miner's answer whose twresp/1 signature verified. */
export interface MinerResponse {
    /** HTTP status. */
    status: number;
    /** Response headers as `[name, value]` pairs. */
    headers: [string, string][];
    /** Raw body bytes (what the signature covers). */
    body: Uint8Array;
    /** Scheme of the miner's signature. */
    scheme: Scheme;
}

/**
 * A client error (`tw.timeout`, `tw.connect_error`, `tw.response_too_large`,
 * `tw.bad_response_signature`). When an answer arrived but did not verify,
 * `status` / `body` hold it for logs; never score from them.
 */
export class ClientError extends TWError {
    /** HTTP status of an answer that arrived, else `null`. */
    readonly responseStatus: number | null;
    /** Body of an answer that arrived but did not verify, else `null`. */
    readonly responseBody: Uint8Array | null;

    constructor(code: string, detail: string, status: number | null = null, body: Uint8Array | null = null) {
        super(code, detail);
        this.name = "ClientError";
        this.responseStatus = status;
        this.responseBody = body;
    }
}

const DEFAULT_MAX_RESPONSE = 8 * 1024 * 1024;

/** Read `response`'s body, refusing more than `limit` bytes. */
export async function readLimited(response: Response, limit: number): Promise<Uint8Array> {
    if (response.body === null) {
        return new Uint8Array(0);
    }
    const parts: Uint8Array[] = [];
    let size = 0;
    // Leaving the loop early cancels the stream.
    for await (const chunk of response.body as AsyncIterable<Uint8Array>) {
        size += chunk.byteLength;
        if (size > limit) {
            throw new ClientError("tw.response_too_large", "answer exceeds maxResponseBytes");
        }
        parts.push(chunk);
    }
    return Buffer.concat(parts);
}

/**
 * Error codes of undici / Node that mean the connection was never made, so the
 * request was not delivered and may be sent again.
 */
const NOT_DELIVERED = new Set([
    "ECONNREFUSED",
    "ENOTFOUND",
    "EAI_AGAIN",
    "EHOSTUNREACH",
    "ENETUNREACH",
    "UND_ERR_CONNECT_TIMEOUT",
]);

/** Map a `fetch` failure to a client error. */
export function transportError(err: unknown, signal: AbortSignal): ClientError {
    if (err instanceof ClientError) {
        return err;
    }
    if (signal.aborted) {
        return new ClientError("tw.timeout", "time budget exhausted");
    }
    return new ClientError("tw.connect_error", err instanceof Error ? err.message : String(err));
}

/** Whether a `fetch` failure happened before the request reached the miner. */
export function notDelivered(err: unknown): boolean {
    const cause = (err as { cause?: { code?: unknown } } | null)?.cause;
    return typeof cause?.code === "string" && NOT_DELIVERED.has(cause.code);
}

/** Sends signed requests to miners and verifies their twresp/1 answers. */
export class Client {
    readonly #signer: Signer;
    readonly #timeoutMs: number;
    readonly #maxBytes: number;
    readonly #attempts: number;
    readonly #fetch: typeof fetch;

    constructor(options: ClientOptions) {
        this.#signer = options.signer;
        this.#timeoutMs = options.timeoutMs ?? 12_000;
        this.#maxBytes = options.maxResponseBytes ?? DEFAULT_MAX_RESPONSE;
        this.#attempts = options.attempts ?? 1;
        this.#fetch = options.fetch ?? fetch;
        if (
            !(this.#timeoutMs > 0) ||
            !(this.#maxBytes > 0) ||
            !Number.isInteger(this.#attempts) ||
            this.#attempts < 1
        ) {
            throw new RangeError("timeoutMs and maxResponseBytes must be > 0, attempts an integer >= 1");
        }
    }

    /**
     * Send `body` to `url` signed for the miner hotkey `receiver`, read the
     * answer and verify its twresp/1 signature. Rejects with a
     * {@link ClientError}. Only failures to connect (the request never left)
     * are retried, with a fresh signature, within the one time budget.
     */
    async request(
        method: string,
        url: string | URL,
        body: Uint8Array,
        receiver: string,
    ): Promise<MinerResponse> {
        method = method.toUpperCase();
        if ((method === "GET" || method === "HEAD") && body.length > 0) {
            throw new RangeError(`${method} requests carry no body`);
        }
        const parsed = new URL(url);
        const target = requestTarget(parsed);
        const signal = AbortSignal.timeout(this.#timeoutMs);
        let last: ClientError = new ClientError("tw.connect_error", "no attempt made");
        for (let attempt = 0; attempt < this.#attempts; attempt++) {
            const signed = this.#signer.sign(method, target, body, receiver);
            let response: Response;
            try {
                response = await this.#fetch(parsed, {
                    method,
                    headers: signed.headers,
                    body: method === "GET" || method === "HEAD" ? null : body,
                    signal,
                    redirect: "manual",
                });
            } catch (err) {
                last = transportError(err, signal);
                // Retry only when the request surely never arrived: a failure after
                // delivery (reset before the answer) may have run the handler.
                if (last.code !== "tw.connect_error" || !notDelivered(err)) {
                    throw last;
                }
                continue;
            }
            let data: Uint8Array;
            try {
                data = await readLimited(response, this.#maxBytes);
            } catch (err) {
                throw transportError(err, signal);
            }
            const headers = [...response.headers] as [string, string][];
            try {
                const scheme = verifyResponse(
                    headers,
                    {
                        expectedResponder: receiver,
                        requestNonce: signed.nonce,
                        sender: this.#signer.key.ss58,
                        status: response.status,
                    },
                    data,
                );
                return { status: response.status, headers, body: data, scheme };
            } catch (err) {
                const detail = err instanceof Error ? err.message : String(err);
                throw new ClientError("tw.bad_response_signature", detail, response.status, data);
            }
        }
        throw last;
    }
}
