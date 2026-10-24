/**
 * The validator side: signed requests and verified answers over `fetch`
 * (Node's undici).
 *
 * @module
 */
import { TWError, isServerCode } from "./errors.js";
import { type Keypair, signatureHex } from "./keys.js";
import { NonceSource } from "./nonce.js";
import { type Scheme, buildPayload } from "./payload.js";
import {
    CONTENT_TYPE,
    ChunkError,
    EVENT_CHUNK,
    EVENT_END,
    type SSEEvent,
    SSEParser,
    StreamDigest,
    StreamLimits,
    TrailerError,
    after,
    decodeChunk,
    parseTrailer,
} from "./streaming.js";
import { RESP_HEADER, verifyResponse, verifyResponseDigest } from "./twresp.js";
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

    /**
     * Start one streaming query (spec 9.2) and resolve the open stream once
     * its head arrived (see {@link MinerStream}). An answer that is not a 200
     * event stream is read whole and rejected: the miner's `tw.*` code from
     * its error body (verified when signed), `tw.http_<status>` otherwise,
     * `tw.invalid_response` for a verified 200 that is not a stream,
     * `tw.bad_response_signature` for a bad signature. Not retried.
     */
    async stream(
        method: string,
        url: string | URL,
        body: Uint8Array,
        receiver: string,
        options: StreamOptions = {},
    ): Promise<MinerStream> {
        method = method.toUpperCase();
        if ((method === "GET" || method === "HEAD") && body.length > 0) {
            throw new RangeError(`${method} requests carry no body`);
        }
        const limits = options.limits ?? new StreamLimits();
        const budget = options.timeoutMs ?? this.#timeoutMs;
        const started = Date.now();
        const parsed = new URL(url);
        const signed = this.#signer.sign(method, requestTarget(parsed), body, receiver);
        const abort = new AbortController();
        const head = setTimeout(() => {
            abort.abort();
        }, budget);
        let response: Response;
        try {
            response = await this.#fetch(parsed, {
                method,
                headers: {
                    ...signed.headers,
                    Accept: CONTENT_TYPE,
                    "Accept-Encoding": "identity",
                    ...(body.length > 0 ? { "Content-Type": "application/json" } : {}),
                },
                body: method === "GET" || method === "HEAD" ? null : body,
                signal: abort.signal,
                redirect: "manual",
            });
        } catch (err) {
            clearTimeout(head);
            throw transportError(err, abort.signal);
        }
        const media = (response.headers.get("content-type") ?? "").split(";")[0]?.trim().toLowerCase();
        const expect = { responder: receiver, nonce: signed.nonce, sender: this.#signer.key.ss58 };
        if (response.status !== 200 || media !== CONTENT_TYPE) {
            try {
                return await this.#notAStream(response, abort.signal, expect);
            } finally {
                clearTimeout(head);
            }
        }
        clearTimeout(head);
        const headers = response.headers;
        const fail = (code: string, detail: string): never => {
            abort.abort();
            throw new ClientError(code, detail);
        };
        if (headers.get("content-encoding") !== null) fail("tw.invalid_response", "encoded event stream");
        if (headers.get(RESP_HEADER.signature) !== null) {
            fail("tw.bad_response_signature", "signature header at stream start");
        }
        if (headers.get(RESP_HEADER.version) !== "1" || headers.get(RESP_HEADER.hotkey) === null) {
            fail("tw.bad_response_signature", "X-TW-Resp-* missing at stream start");
        }
        const left = Math.min(budget - (Date.now() - started), limits.maxS * 1000);
        return new MinerStream(response, abort, limits, Date.now() + left, expect);
    }

    async #notAStream(
        response: Response,
        signal: AbortSignal,
        expect: { responder: string; nonce: bigint; sender: string },
    ): Promise<never> {
        let data: Uint8Array;
        try {
            data = await readLimited(response, this.#maxBytes);
        } catch (err) {
            throw err instanceof ClientError && err.code === "tw.response_too_large"
                ? err
                : signal.aborted
                  ? new ClientError("tw.timeout", "time budget exhausted")
                  : new ClientError("tw.invalid_response", String(err));
        }
        const headers = [...response.headers] as [string, string][];
        if (response.headers.get(RESP_HEADER.signature) !== null || response.status === 200) {
            try {
                verifyResponse(
                    headers,
                    {
                        expectedResponder: expect.responder,
                        requestNonce: expect.nonce,
                        sender: expect.sender,
                        status: response.status,
                    },
                    data,
                );
            } catch (err) {
                const detail = err instanceof Error ? err.message : String(err);
                throw new ClientError("tw.bad_response_signature", detail, response.status, data);
            }
        }
        if (response.status === 200) {
            throw new ClientError("tw.invalid_response", "answer is not an event stream", 200, data);
        }
        throw new ClientError(
            answerCode(response.status, data),
            "answered by the miner",
            response.status,
            data,
        );
    }
}

/** Options of {@link Client.stream}. */
export interface StreamOptions {
    /** Stream limits (spec 12.1 defaults). */
    limits?: StreamLimits;
    /** The query's time budget, ms (default: the client's `timeoutMs`). */
    timeoutMs?: number;
}

/** One chunk as it arrived. **Not verified**: wait for the stream's result. */
export interface UnverifiedChunk {
    /** Position in the stream. */
    index: number;
    /** The parsed JSON object or array. */
    data: unknown;
    /** The chunk's exact `data` bytes (what the digest covers). */
    raw: Uint8Array;
    /** Always `false`: only {@link MinerStream.result} can be trusted. */
    verified: false;
}

/** The miner's `tw.*` code from an error body, else `tw.http_<status>`. */
function answerCode(status: number, body: Uint8Array): string {
    try {
        const parsed = JSON.parse(Buffer.from(body).toString("utf8")) as { error?: { code?: unknown } };
        const code = parsed.error?.code;
        if (typeof code === "string" && isServerCode(code)) {
            return code;
        }
    } catch {
        // not a JSON error body
    }
    return `tw.http_${String(status)}`;
}

/**
 * One streaming query (spec 9.2), from {@link Client.stream}.
 *
 * ```ts
 * const stream = await client.stream("POST", url, body, minerHotkey);
 * for await (const chunk of stream) { ... } // unverified chunks
 * const values = await stream.result(); // throws a ClientError unless tw-end verified
 * ```
 *
 * The rules: at most `maxBytes` on the wire (`tw.response_too_large`); the
 * deadline and `idleS` between two complete events (`tw.timeout`) — the
 * idle clock restarts when the next chunk is asked for, so the caller's own
 * time with a chunk does not count, and no other read timeout applies; every
 * chunk a JSON object or array (`tw.invalid_response`); and
 * `tw.bad_response_signature` for the whole stream when `tw-end` is
 * missing, malformed, repeated or followed by another event, when count or
 * digest do not match, or when its signature does not verify for this
 * request. Unknown events and comments are ignored.
 */
export class MinerStream implements AsyncIterable<UnverifiedChunk> {
    readonly #reader: ReadableStreamDefaultReader<Uint8Array>;
    readonly #abort: AbortController;
    readonly #limits: StreamLimits;
    readonly #deadline: number;
    readonly #headers: [string, string][];
    readonly #expect: { responder: string; nonce: bigint; sender: string };
    readonly #parser = new SSEParser();
    readonly #pending: SSEEvent[] = [];
    readonly #digest = new StreamDigest();
    #received = 0;
    #ended = false;
    #eof = false;
    #failure: ClientError | null = null;
    /** The chunk values so far, in order; trust them only after {@link result}. */
    readonly values: unknown[] = [];

    /** @internal */
    constructor(
        response: Response,
        abort: AbortController,
        limits: StreamLimits,
        deadline: number,
        expect: { responder: string; nonce: bigint; sender: string },
    ) {
        this.#reader = (response.body as ReadableStream<Uint8Array>).getReader();
        this.#abort = abort;
        this.#limits = limits;
        this.#deadline = deadline;
        this.#headers = [...response.headers] as [string, string][];
        this.#expect = expect;
    }

    /** The next chunk (unverified), or `null` at the verified end. Throws a {@link ClientError}. */
    async next(): Promise<UnverifiedChunk | null> {
        if (this.#failure !== null) throw this.#failure;
        try {
            return await this.#advance();
        } catch (err) {
            this.#failure =
                err instanceof ClientError ? err : new ClientError("tw.bad_response_signature", String(err));
            this.close();
            throw this.#failure;
        }
    }

    async *[Symbol.asyncIterator](): AsyncIterator<UnverifiedChunk> {
        for (;;) {
            const chunk = await this.next();
            if (chunk === null) return;
            yield chunk;
        }
    }

    /** Read to the end; the chunk values once `tw-end` verified. */
    async result(): Promise<unknown[]> {
        while ((await this.next()) !== null) {
            // drain
        }
        return this.values;
    }

    /** Release the connection. */
    close(): void {
        this.#abort.abort();
    }

    async #advance(): Promise<UnverifiedChunk | null> {
        // The idle clock starts now: the caller's time is not the miner's.
        let idleAt = Date.now() + this.#limits.idleS * 1000;
        for (;;) {
            let ev: SSEEvent | undefined;
            while ((ev = this.#pending.shift()) !== undefined) {
                const chunk = this.#event(ev);
                if (chunk !== null) return chunk;
                idleAt = Date.now() + this.#limits.idleS * 1000;
            }
            if (this.#eof) {
                if (!this.#ended) {
                    throw new ClientError("tw.bad_response_signature", "stream ended without tw-end");
                }
                this.close();
                return null;
            }
            await this.#read(Math.min(idleAt, this.#deadline));
        }
    }

    async #read(until: number): Promise<void> {
        const wait = until - Date.now();
        if (wait <= 0) {
            throw new ClientError("tw.timeout", "stream limit reached");
        }
        const [late, cancel] = after(wait, "timeout" as const);
        let got: Awaited<ReturnType<ReadableStreamDefaultReader<Uint8Array>["read"]>> | "timeout";
        try {
            got = await Promise.race([this.#reader.read(), late]);
        } catch {
            // Cut mid-stream (e.g. the miner aborted): no valid tw-end.
            throw new ClientError("tw.bad_response_signature", "stream broken before tw-end");
        } finally {
            cancel();
        }
        if (got === "timeout") {
            throw new ClientError("tw.timeout", "stream limit reached");
        }
        if (got.done) {
            this.#eof = true;
            this.#pending.push(...this.#parser.finish());
            return;
        }
        this.#received += got.value.byteLength;
        if (this.#received > this.#limits.maxBytes) {
            throw new ClientError("tw.response_too_large", "stream over maxBytes");
        }
        this.#pending.push(...this.#parser.feed(got.value));
    }

    #event(ev: SSEEvent): UnverifiedChunk | null {
        if (this.#ended) {
            throw new ClientError("tw.bad_response_signature", "event after tw-end");
        }
        if (ev.event === EVENT_CHUNK) {
            let data: unknown;
            try {
                data = decodeChunk(ev.data);
            } catch (err) {
                throw new ClientError("tw.invalid_response", (err as ChunkError).message);
            }
            const index = this.#digest.count;
            this.#digest.update(ev.data);
            this.values.push(data);
            return { index, data, raw: ev.data, verified: false };
        }
        if (ev.event === EVENT_END) {
            this.#end(ev.data);
        }
        return null; // unknown events are ignored
    }

    #end(data: Uint8Array): void {
        const bad = (detail: string) => new ClientError("tw.bad_response_signature", detail);
        let trailer;
        try {
            trailer = parseTrailer(data);
        } catch (err) {
            throw bad((err as TrailerError).message);
        }
        if (trailer.count !== BigInt(this.#digest.count)) throw bad("chunk count mismatch");
        if (trailer.digest !== this.#digest.hexdigest()) throw bad("stream digest mismatch");
        if (trailer.signature === null) throw bad("tw-end is not signed");
        try {
            verifyResponseDigest(
                [...this.#headers, [RESP_HEADER.signature, trailer.signature]],
                {
                    expectedResponder: this.#expect.responder,
                    requestNonce: this.#expect.nonce,
                    sender: this.#expect.sender,
                    status: 200,
                },
                trailer.digest,
            );
        } catch (err) {
            throw bad(err instanceof Error ? err.message : String(err));
        }
        this.#ended = true;
    }
}
