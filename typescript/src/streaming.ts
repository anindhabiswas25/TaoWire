/**
 * Streaming responses over SSE with a signed trailer (spec 9.2, D29): what the
 * miner and the client share. The same rules as the Python reference
 * (`taowire.extensions.streaming`):
 *
 * ```
 * event: chunk
 * data: {"token": "Hel"}
 *
 * event: tw-end
 * data: {"digest": "<sha256 hex>", "count": 1, "signature": "0x..."}
 * ```
 *
 * `digest` is sha256 over the concatenation of every chunk's exact `data`
 * bytes; the trailer signature is the twresp/1 payload with status 200 and
 * the digest as the body hash. Chunks are JSON objects or arrays: they are
 * self-delimiting, so a relay cannot move chunk boundaries under a valid
 * signature.
 *
 * @module
 */
import { createHash, type Hash } from "node:crypto";
import { TWError } from "./errors.js";

/** `Content-Type` of a stream. */
export const CONTENT_TYPE = "text/event-stream";
/** Event name of a chunk. */
export const EVENT_CHUNK = "chunk";
/** Event name of the trailer. */
export const EVENT_END = "tw-end";

/** Allowed ranges (spec 12.1). */
export const MAX_S_RANGE = [1, 600] as const;
/** Allowed range of `maxBytes`: 1 KiB to 64 MiB. */
export const MAX_BYTES_RANGE = [1024, 64 * 1024 * 1024] as const;
/** Allowed range of `idleS`. */
export const IDLE_S_RANGE = [1, 120] as const;

/**
 * Deepest JSON nesting accepted in a chunk. The Python reference refuses
 * deep chunks through its recursion limit (about 1000, environment-dependent);
 * Rust's serde_json stops at 128. Every non-Python package uses 128, the
 * stricter of the two (logged as a spec question).
 */
export const MAX_CHUNK_DEPTH = 128;

/** A chunk is not a JSON object or array (or not valid JSON at all). */
export class ChunkError extends Error {
    constructor(message: string) {
        super(message);
        this.name = "ChunkError";
    }
}

/** The `tw-end` data is not a well-formed trailer. */
export class TrailerError extends Error {
    constructor(message: string) {
        super(message);
        this.name = "TrailerError";
    }
}

/** Per-stream limits (spec 9.2); both the miner and the client enforce them. */
export class StreamLimits {
    /** Whole stream, seconds (default 60, `TW_STREAM_MAX_S`). */
    readonly maxS: number;
    /** Bytes on the wire (default 4 MiB, `TW_STREAM_MAX_BYTES`). */
    readonly maxBytes: number;
    /** Longest gap between two events, seconds (default 10, `TW_STREAM_IDLE_S`). */
    readonly idleS: number;

    /** Throws `RangeError` outside the ranges of spec 12.1. */
    constructor(limits: { maxS?: number; maxBytes?: number; idleS?: number } = {}) {
        this.maxS = check("maxS", limits.maxS ?? 60, MAX_S_RANGE);
        this.maxBytes = check("maxBytes", limits.maxBytes ?? 4 * 1024 * 1024, MAX_BYTES_RANGE);
        this.idleS = check("idleS", limits.idleS ?? 10, IDLE_S_RANGE);
        if (!Number.isInteger(this.maxBytes)) {
            throw new RangeError("maxBytes must be an integer");
        }
    }
}

function check(name: string, value: number, [low, high]: readonly [number, number]): number {
    if (!Number.isFinite(value) || value < low || value > high) {
        throw new RangeError(`${name} must be between ${low} and ${high}`);
    }
    return value;
}

// JSON.stringify returns undefined for some values (e.g. a toJSON giving undefined).
const stringify: (value: unknown) => string | undefined = JSON.stringify;
const utf8 = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true });
const encoder = new TextEncoder();

function depthOf(value: unknown): number {
    // Iterative, so a hostile chunk cannot exhaust the stack here either.
    let max = 0;
    const stack: [unknown, number][] = [[value, 1]];
    while (stack.length > 0) {
        const [v, d] = stack.pop() as [unknown, number];
        if (typeof v !== "object" || v === null) {
            continue;
        }
        max = Math.max(max, d);
        if (max > MAX_CHUNK_DEPTH) {
            return max;
        }
        for (const child of Array.isArray(v) ? v : Object.values(v)) {
            stack.push([child, d + 1]);
        }
    }
    return max;
}

/**
 * Parse one chunk's `data` (client side): UTF-8 JSON, an object or array,
 * no deeper than {@link MAX_CHUNK_DEPTH}. Throws {@link ChunkError}.
 */
export function decodeChunk(data: Uint8Array): unknown {
    let value: unknown;
    try {
        value = JSON.parse(utf8.decode(data));
    } catch {
        throw new ChunkError("chunk is not valid JSON");
    }
    if (typeof value !== "object" || value === null) {
        throw new ChunkError("chunk must be a JSON object or array");
    }
    if (depthOf(value) > MAX_CHUNK_DEPTH) {
        throw new ChunkError("chunk is nested too deeply");
    }
    return value;
}

/**
 * The `data` bytes of one chunk (miner side): a plain object or array as
 * compact JSON, or bytes holding a JSON object or array, sent as they are.
 * Throws {@link ChunkError} for anything else or a line break in the bytes.
 */
export function encodeChunk(item: unknown): Uint8Array {
    let data: Uint8Array;
    if (item instanceof Uint8Array) {
        data = item;
        decodeChunk(data);
    } else if (typeof item === "object" && item !== null) {
        let text: string | undefined;
        try {
            text = stringify(item);
        } catch {
            throw new ChunkError("chunk is not JSON-serialisable");
        }
        if (text === undefined || !(text.startsWith("{") || text.startsWith("["))) {
            throw new ChunkError("chunk must be a JSON object or array");
        }
        if (depthOf(JSON.parse(text)) > MAX_CHUNK_DEPTH) {
            throw new ChunkError("chunk is nested too deeply");
        }
        data = encoder.encode(text);
    } else {
        throw new ChunkError(`chunk of type ${typeof item} is not supported`);
    }
    if (data.includes(0x0a) || data.includes(0x0d)) {
        throw new ChunkError("chunk contains a line break");
    }
    const first = data.find((b) => b !== 0x20 && b !== 0x09);
    if (first !== 0x7b && first !== 0x5b) {
        throw new ChunkError("chunk must be a JSON object or array");
    }
    return data;
}

/** Running sha256 over the chunks' `data` bytes, and their count. */
export class StreamDigest {
    #hash: Hash = createHash("sha256");
    /** Chunks so far. */
    count = 0;

    /** Add one chunk's exact `data` bytes. */
    update(data: Uint8Array): void {
        this.#hash.update(data);
        this.count++;
    }

    /** The digest so far, lowercase hex (the running hash continues). */
    hexdigest(): string {
        return this.#hash.copy().digest("hex");
    }
}

/** The `tw-end` event's data. */
export interface Trailer {
    /** sha256 of the chunks, lowercase hex. */
    digest: string;
    /** Number of chunks. */
    count: bigint;
    /** `0x` + hex; `null` when the miner does not sign responses. */
    signature: string | null;
}

/** The `tw-end` data bytes (compact JSON, keys in the Python reference's order). */
export function encodeTrailer(trailer: Trailer): Uint8Array {
    let text = `{"digest":"${trailer.digest}","count":${trailer.count.toString(10)}`;
    if (trailer.signature !== null) {
        text += `,"signature":${JSON.stringify(trailer.signature)}`;
    }
    return encoder.encode(`${text}}`);
}

const HEX_DIGEST = /^[0-9a-f]{64}$/;
const INTEGER = /^(?:0|[1-9][0-9]*)$/;
const U64_MAX = 2n ** 64n - 1n;

/**
 * The top-level keys of a JSON object text (already known to be valid JSON)
 * with each value's raw text: `JSON.parse` keeps the last of two equal keys
 * silently, and turns `1.0` into an integer, so the trailer rules need both.
 */
function topLevelMembers(text: string): [string, string][] {
    const members: [string, string][] = [];
    let i = text.indexOf("{") + 1;
    const skipSpace = () => {
        while (i < text.length && " \t\n\r".includes(text[i] as string)) i++;
    };
    const stringEnd = (start: number): number => {
        let j = start + 1;
        while (text[j] !== '"') j += text[j] === "\\" ? 2 : 1;
        return j + 1;
    };
    for (;;) {
        skipSpace();
        if (text[i] !== '"') return members; // "}" of an empty or finished object
        const keyEnd = stringEnd(i);
        const key = JSON.parse(text.slice(i, keyEnd)) as string;
        i = keyEnd;
        skipSpace();
        i++; // ":"
        skipSpace();
        const start = i;
        let depth = 0;
        while (i < text.length) {
            const c = text[i] as string;
            if (c === '"') {
                i = stringEnd(i);
                continue;
            }
            if (c === "{" || c === "[") depth++;
            else if (c === "}" || c === "]") {
                if (depth === 0) break;
                depth--;
            } else if (c === "," && depth === 0) break;
            i++;
        }
        members.push([key, text.slice(start, i).trim()]);
        if (text[i] === ",") i++;
    }
}

/**
 * Parse `tw-end` data strictly (the Python reference's `parse_trailer`): a
 * JSON object with exactly `digest` (64 lowercase hex), `count` (an integer
 * literal ≥ 0 that fits a u64; no sign, fraction or exponent) and optionally
 * `signature` (a string), no other key, no key twice. Throws
 * {@link TrailerError}.
 */
export function parseTrailer(data: Uint8Array): Trailer {
    let text: string;
    let value: unknown;
    try {
        text = utf8.decode(data);
        value = JSON.parse(text);
    } catch {
        throw new TrailerError("tw-end data is not valid JSON");
    }
    if (typeof value !== "object" || value === null || Array.isArray(value)) {
        throw new TrailerError("tw-end data must be a JSON object");
    }
    const members = topLevelMembers(text);
    const keys = members.map(([k]) => k);
    if (new Set(keys).size !== keys.length) {
        throw new TrailerError("duplicate key in tw-end");
    }
    if (
        !keys.includes("digest") ||
        !keys.includes("count") ||
        keys.some((k) => !["digest", "count", "signature"].includes(k))
    ) {
        throw new TrailerError("tw-end needs digest and count, and nothing but signature");
    }
    const fields = value as Record<string, unknown>;
    if (typeof fields.digest !== "string" || !HEX_DIGEST.test(fields.digest)) {
        throw new TrailerError("tw-end digest must be 64 lowercase hex characters");
    }
    const rawCount = members.find(([k]) => k === "count")?.[1] ?? "";
    if (!INTEGER.test(rawCount)) {
        throw new TrailerError("tw-end count must be an integer >= 0");
    }
    if (BigInt(rawCount) > U64_MAX) {
        throw new TrailerError("tw-end count is out of range");
    }
    if ("signature" in fields && typeof fields.signature !== "string") {
        throw new TrailerError("tw-end signature must be a string");
    }
    return {
        digest: fields.digest,
        count: BigInt(rawCount),
        signature: typeof fields.signature === "string" ? fields.signature : null,
    };
}

/** One SSE frame: `event: <event>`, one `data:` line, a blank line. */
export function encodeEvent(event: string, data: Uint8Array): Uint8Array {
    if (/[\r\n]/.test(event) || data.includes(0x0a) || data.includes(0x0d)) {
        throw new RangeError("SSE event names and data must not contain line breaks");
    }
    return Buffer.concat([encoder.encode(`event: ${event}\ndata: `), data, encoder.encode("\n\n")]);
}

/**
 * Bytes the miner keeps free under `maxBytes` for the `tw-end` frame: the
 * largest possible one (a 20-digit count, a 64-byte signature), so a stream
 * the miner finishes always fits a client using the same limit.
 */
export const TRAILER_RESERVE = encodeEvent(
    EVENT_END,
    encodeTrailer({ digest: "0".repeat(64), count: 2n ** 64n - 1n, signature: `0x${"0".repeat(128)}` }),
).length;

/** One dispatched event: its type and its data bytes (lines joined by LF). */
export interface SSEEvent {
    /** The event type (`message` when none was given). */
    event: string;
    /** The data bytes. */
    data: Uint8Array;
}

const CR = 0x0d;
const LF = 0x0a;
const BOM = [0xef, 0xbb, 0xbf];

/**
 * Incremental SSE parser over raw bytes (WHATWG "event stream" rules), the
 * same as the Python reference's `SSEParser`. Lines end with CRLF, LF or CR;
 * `:` lines are comments; `field[: value]` with one leading space removed; a
 * line without a colon is a field with an empty value; `data` lines are
 * joined with LF; `event` sets the type (empty or absent: `message`); `id`,
 * `retry` and unknown fields are ignored; a blank line dispatches an event
 * that has data. A UTF-8 BOM at the very start is skipped. `feed` never
 * throws; {@link finish} drops an unfinished event. Each byte is scanned
 * once, and the buffer grows by doubling, so the work is linear in the input.
 */
export class SSEParser {
    #buf = new Uint8Array(1024);
    #start = 0; // first unconsumed byte
    #end = 0; // end of the bytes held
    #scanned = 0; // no line end in [#start, #scanned)
    #started = false;
    #event: string | null = null;
    #data: Uint8Array[] = [];
    #hasData = false;

    /** Add bytes; the events they complete, in order. */
    feed(chunk: Uint8Array): SSEEvent[] {
        this.#append(chunk);
        if (!this.#started) {
            const held = this.#end - this.#start;
            const b = this.#buf;
            const s = this.#start;
            const prefix = (n: number) => BOM.slice(0, n).every((x, i) => b[s + i] === x);
            if (held < 3 && prefix(held)) {
                return [];
            }
            if (held >= 3 && prefix(3)) {
                this.#start += 3;
                this.#scanned = Math.max(this.#scanned, this.#start);
            }
            this.#started = true;
        }
        return this.#lines(false);
    }

    /** End of stream: a final CR ends its line; an unfinished event is dropped. */
    finish(): SSEEvent[] {
        const events = this.#lines(true);
        this.#start = this.#end = this.#scanned = 0;
        this.#started = false;
        this.#reset();
        return events;
    }

    #append(chunk: Uint8Array): void {
        const held = this.#end - this.#start;
        if (this.#end + chunk.length > this.#buf.length) {
            if (held + chunk.length <= this.#buf.length / 2) {
                this.#buf.copyWithin(0, this.#start, this.#end);
            } else {
                const grown = new Uint8Array(Math.max(this.#buf.length * 2, held + chunk.length));
                grown.set(this.#buf.subarray(this.#start, this.#end));
                this.#buf = grown;
            }
            this.#scanned -= this.#start;
            this.#start = 0;
            this.#end = held;
        }
        this.#buf.set(chunk, this.#end);
        this.#end += chunk.length;
    }

    #lines(final: boolean): SSEEvent[] {
        const b = this.#buf;
        const events: SSEEvent[] = [];
        let i = Math.max(this.#scanned, this.#start);
        while (i < this.#end) {
            const c = b[i] as number;
            if (c !== CR && c !== LF) {
                i++;
                continue;
            }
            let next = i + 1;
            if (c === CR) {
                if (next === this.#end && !final) {
                    break; // may be the first half of a CRLF split across feeds
                }
                if (next < this.#end && b[next] === LF) next++;
            }
            const event = this.#line(b.subarray(this.#start, i));
            if (event !== null) events.push(event);
            this.#start = next;
            i = next;
        }
        // Scan only new bytes next time; a trailing CR is looked at again.
        this.#scanned = this.#end > this.#start && b[this.#end - 1] === CR ? this.#end - 1 : this.#end;
        return events;
    }

    #line(line: Uint8Array): SSEEvent | null {
        if (line.length === 0) {
            return this.#dispatch();
        }
        if (line[0] === 0x3a) {
            return null; // comment
        }
        const colon = line.indexOf(0x3a);
        const name = Buffer.from(colon === -1 ? line : line.subarray(0, colon)).toString("latin1");
        let value = colon === -1 ? new Uint8Array(0) : line.subarray(colon + 1);
        if (value[0] === 0x20) {
            value = value.subarray(1);
        }
        if (name === "data") {
            this.#data.push(Uint8Array.from(value));
            this.#hasData = true;
        } else if (name === "event") {
            this.#event = lenient.decode(value);
        }
        return null;
    }

    #dispatch(): SSEEvent | null {
        if (!this.#hasData) {
            this.#reset();
            return null;
        }
        const parts: Uint8Array[] = [];
        this.#data.forEach((d, i) => {
            if (i > 0) parts.push(Uint8Array.of(LF));
            parts.push(d);
        });
        const event = { event: this.#event || "message", data: Uint8Array.from(Buffer.concat(parts)) };
        this.#reset();
        return event;
    }

    #reset(): void {
        this.#event = null;
        this.#data = [];
        this.#hasData = false;
    }
}

const lenient = new TextDecoder("utf-8");

/** Range of {@link StreamSlots} limits (`TW_STREAM_MAX_PER_CALLER`, spec 12.1, D36). */
export const STREAMS_PER_CALLER_RANGE = [1, 256] as const;
/** Default open streams per caller. */
export const DEFAULT_STREAMS_PER_CALLER = 16;

/**
 * Open streams per caller hotkey in this process (spec 9.2, D36). Streams
 * live up to `maxS`, far longer than a plain request, so without it one
 * permitted validator could fill the server's connections and starve the
 * others.
 */
export class StreamSlots {
    /** Open streams allowed per caller. */
    readonly limit: number;
    readonly #open = new Map<string, number>();

    /** Throws `RangeError` outside 1..256. */
    constructor(limit = DEFAULT_STREAMS_PER_CALLER) {
        const [low, high] = STREAMS_PER_CALLER_RANGE;
        if (!Number.isInteger(limit) || limit < low || limit > high) {
            throw new RangeError(`streams per caller must be between ${low} and ${high}`);
        }
        this.limit = limit;
    }

    /**
     * Take a slot for `hotkey`, or throw `tw.rate_limited` (429). Returns its
     * release; calling it more than once is harmless.
     */
    acquire(hotkey: string): () => void {
        const n = this.#open.get(hotkey) ?? 0;
        if (n >= this.limit) {
            throw new TWError("tw.rate_limited", "open streams per caller");
        }
        this.#open.set(hotkey, n + 1);
        let released = false;
        return () => {
            if (released) return;
            released = true;
            const left = (this.#open.get(hotkey) ?? 1) - 1;
            if (left > 0) this.#open.set(hotkey, left);
            else this.#open.delete(hotkey);
        };
    }

    /** How many streams `hotkey` holds now. */
    open(hotkey: string): number {
        return this.#open.get(hotkey) ?? 0;
    }
}

/**
 * A promise that resolves with `value` after `ms`, and its cancel (internal:
 * the stream limits race it against reads and writes).
 */
export function after<T>(ms: number, value: T): [Promise<T>, () => void] {
    let timer: ReturnType<typeof setTimeout> | undefined;
    const p = new Promise<T>((resolve) => {
        timer = setTimeout(resolve, Math.max(0, ms), value);
    });
    return [
        p,
        () => {
            clearTimeout(timer);
        },
    ];
}
