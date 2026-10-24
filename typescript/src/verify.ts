/**
 * btauth/1 request verification in the order of spec 4.3.
 *
 * @module
 */
import { StepGuard, monotonicNs } from "./clockstep.js";
import { TWError } from "./errors.js";
import { type HeaderInput, duplicateWithPrefix, headerMap, single } from "./headers.js";
import { verifySignature } from "./keys.js";
import { wallClockNs } from "./nonce.js";
import { type Scheme, buildPayload } from "./payload.js";
import { decodeSS58 } from "./ss58.js";
import { type NonceStore, secondsToNs } from "./store.js";

/** Request header names (spec 4.1). */
export const HEADER = {
    version: "X-Bittensor-Version",
    hotkey: "X-Bittensor-Hotkey",
    receiver: "X-Bittensor-Receiver",
    nonce: "X-Bittensor-Nonce",
    crypto: "X-Bittensor-Crypto",
    signature: "X-Bittensor-Signature",
} as const;

/** Defaults of spec 4.3, in seconds. */
export const DEFAULT_MAX_AGE_S = 10;
/** Default allowed clock skew into the future, in seconds. */
export const DEFAULT_ALLOWED_SKEW_S = 2;

const U64_MAX = 2n ** 64n - 1n;
const NONCE_RE = /^[0-9]{1,20}$/;
const HEX_RE = /^(?:[0-9a-fA-F]{2})*$/;

/** The verified sender of one request. */
export interface Caller {
    /** Canonical prefix-42 SS58 address. */
    readonly hotkey: string;
    /** Unix time in nanoseconds, from `X-Bittensor-Nonce`. */
    readonly nonce: bigint;
    /** The scheme the signature verified under. */
    readonly scheme: Scheme;
}

/** Configuration of a {@link Verifier}. */
export interface VerifierConfig {
    /** This server's hotkey; requests must be addressed to it. */
    selfHotkey: string;
    /** Remembers accepted nonces; `retentionS ≥ 2 × (maxAgeS + allowedSkewS)` (D21). */
    store: NonceStore;
    /** Oldest accepted nonce, seconds (default 10). */
    maxAgeS?: number;
    /** Furthest accepted nonce into the future, seconds (default 2). */
    allowedSkewS?: number;
    /** Replaces the wall clock (Unix ns; tests). The clock-step guard reads it too. */
    nowNs?: () => bigint;
    /** Replaces the monotonic clock of the clock-step guard (ns; tests). */
    monotonicNs?: () => bigint;
}

/** One request as received. */
export interface RequestInput {
    /** Headers; pairs or Node `rawHeaders` keep duplicates visible. */
    headers: HeaderInput;
    /** The raw body bytes, before any parsing. */
    body: Uint8Array;
    /** The HTTP method as received. */
    method: string;
    /** The request target as received (percent-encoded path + `?query`). */
    target: string;
}

function malformed(detail: string): TWError {
    return new TWError("tw.auth_malformed", detail);
}

function positiveSeconds(name: string, value: number): number {
    if (!Number.isFinite(value) || value <= 0) {
        throw new RangeError(`${name} must be a positive number of seconds`);
    }
    return value;
}

/** Checks btauth/1 requests addressed to one hotkey. */
export class Verifier {
    /** The hotkey requests must be addressed to. */
    readonly selfHotkey: string;
    readonly #store: NonceStore;
    readonly #maxAgeNs: bigint;
    readonly #skewNs: bigint;
    readonly #nowNs: () => bigint;
    readonly #steps: StepGuard;

    /**
     * Throws for a self hotkey that is not a prefix-42 address, or a store
     * whose retention is shorter than twice the freshness window (spec 8.4.3,
     * 11.2 rule 10, D21): such a miner must not start.
     */
    constructor(config: VerifierConfig) {
        try {
            decodeSS58(config.selfHotkey);
        } catch {
            throw new Error("btauth: selfHotkey is not a prefix-42 SS58 address");
        }
        const maxAgeS = positiveSeconds("maxAgeS", config.maxAgeS ?? DEFAULT_MAX_AGE_S);
        const skewS = positiveSeconds("allowedSkewS", config.allowedSkewS ?? DEFAULT_ALLOWED_SKEW_S);
        const retentionNs = secondsToNs(config.store.retentionS);
        const windowNs = secondsToNs(maxAgeS) + secondsToNs(skewS);
        if (retentionNs < 2n * windowNs) {
            throw new Error(
                "btauth: nonce store retention too short: it must be at least 2 x (maxAgeS + allowedSkewS)",
            );
        }
        this.selfHotkey = config.selfHotkey;
        this.#store = config.store;
        this.#maxAgeNs = secondsToNs(maxAgeS);
        this.#skewNs = secondsToNs(skewS);
        this.#nowNs = config.nowNs ?? wallClockNs;
        this.#steps = new StepGuard(
            retentionNs - windowNs,
            retentionNs,
            this.#nowNs,
            config.monotonicNs ?? monotonicNs,
        );
    }

    /**
     * Whether a backwards wall-clock step larger than the store's margin
     * happened less than the retention ago (D21). Requests that pass the
     * signature check are refused with `tw.replay_store_unavailable`
     * meanwhile; report the server not ready (reason `clock_step`).
     */
    failingClosed(): boolean {
        return this.#steps.check();
    }

    /** Size of the last backwards step that opened the window, ns (for `tw_clock_step_seconds`). */
    lastClockStepNs(): bigint {
        return this.#steps.lastStepNs;
    }

    /**
     * Authenticate one request (spec 4.3): 1 shape (`tw.auth_malformed`),
     * 2 receiver (`tw.auth_wrong_receiver`), 3 freshness (`tw.auth_stale`),
     * 4 signature (`tw.auth_bad_signature`; `tw.auth_malformed` for a
     * signature that is not 64 bytes), 5 replay (`tw.auth_replayed`, or
     * `tw.replay_store_unavailable`). Rejects with a {@link TWError}.
     */
    async verify(request: RequestInput): Promise<Caller> {
        // 1. shape
        const headers = headerMap(request.headers);
        const dup = duplicateWithPrefix(headers, "x-bittensor-");
        if (dup !== null) {
            throw malformed(`duplicate ${dup} header`);
        }
        if (single(headers, HEADER.version) !== "1") {
            throw malformed(`missing or unsupported ${HEADER.version}`);
        }
        const sender = single(headers, HEADER.hotkey);
        if (sender === undefined || sender === "") {
            throw malformed(`missing ${HEADER.hotkey}`);
        }
        let senderKey: Uint8Array;
        try {
            senderKey = decodeSS58(sender);
        } catch {
            throw malformed(`${HEADER.hotkey} is not a Bittensor address (SS58 prefix 42)`);
        }
        const nonceText = single(headers, HEADER.nonce);
        if (nonceText === undefined || !NONCE_RE.test(nonceText)) {
            throw malformed(`${HEADER.nonce} is not a decimal integer`);
        }
        const nonce = BigInt(nonceText);
        let scheme: Scheme = "sr25519";
        const declared = single(headers, HEADER.crypto);
        if (declared !== undefined) {
            if (declared !== "sr25519" && declared !== "ed25519") {
                throw malformed(`unsupported ${HEADER.crypto}`);
            }
            scheme = declared;
        }
        let sigText = single(headers, HEADER.signature);
        if (sigText === undefined) {
            throw malformed(`missing ${HEADER.signature}`);
        }
        if (sigText.startsWith("0x")) {
            sigText = sigText.slice(2);
        }
        if (!HEX_RE.test(sigText)) {
            throw malformed(`${HEADER.signature} is not hex`);
        }

        // 2. receiver (always required)
        const receiver = single(headers, HEADER.receiver);
        if (receiver === undefined) {
            throw new TWError("tw.auth_wrong_receiver", `missing ${HEADER.receiver}`);
        }
        if (receiver !== this.selfHotkey) {
            throw new TWError(
                "tw.auth_wrong_receiver",
                "request was signed for a different receiving hotkey",
            );
        }

        // 3. freshness (20 digits above u64::MAX are well-formed but far in the future)
        const now = this.#nowNs();
        if (nonce > U64_MAX || nonce - now > this.#skewNs) {
            throw new TWError("tw.auth_stale", "nonce is in the future");
        }
        if (now - nonce > this.#maxAgeNs) {
            throw new TWError("tw.auth_stale", "nonce is too old");
        }

        // 4. signature, under the declared scheme only
        if (sigText.length !== 128) {
            throw malformed("signature is not 64 bytes");
        }
        const signature = Buffer.from(sigText, "hex");
        const payload = buildPayload({
            scheme,
            method: request.method,
            target: request.target,
            body: request.body,
            nonceNs: nonce,
            sender,
            receiver,
        });
        if (!verifySignature(scheme, senderKey, payload, signature)) {
            throw new TWError(
                "tw.auth_bad_signature",
                "signature does not verify against the claimed hotkey",
            );
        }

        // 5. replay, only after the signature verified; never while a wall-clock
        // step could have reopened forgotten nonces (D21)
        if (this.#steps.check()) {
            throw new TWError("tw.replay_store_unavailable", "clock stepped back: failing closed");
        }
        let fresh: boolean;
        try {
            fresh = await this.#store.checkAndStore(sender, nonce);
        } catch (err) {
            throw new TWError("tw.replay_store_unavailable", String(err));
        }
        if (!fresh) {
            throw new TWError("tw.auth_replayed", "this nonce was already accepted from this hotkey");
        }
        return { hotkey: sender, nonce, scheme };
    }
}

/** One-shot form of {@link Verifier.verify} (spec 11.3 sketch). */
export function verifyRequest(verifier: Verifier, request: RequestInput): Promise<Caller> {
    return verifier.verify(request);
}
