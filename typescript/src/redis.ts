/**
 * A Redis-backed replay store (`@tensorwire/btauth/redis`) for miners that
 * run more than one process or host for one hotkey.
 *
 * @module
 */
import { Redis } from "ioredis";
import type { NonceStore } from "./store.js";

/** Key prefix of the Python kit's `RedisNonceStore` (and Go's / Rust's). */
export const DEFAULT_PREFIX = "tw:n:";

/** Longest wait for Redis per request, ms (the Python kit's socket timeout). */
export const DEFAULT_TIMEOUT_MS = 250;

/** Options of a {@link RedisNonceStore}. */
export interface RedisStoreOptions {
    /** Key prefix (default `tw:n:`, shared with the Python kit). */
    prefix?: string;
    /** Longest wait per check, ms (default 250); slower answers fail closed. */
    timeoutMs?: number;
}

/**
 * `SET tw:n:<hotkey>:<nonce> 1 PX <retention> NX`: the Python kit's keys, so
 * TypeScript, Python, Go and Rust miners can share one Redis. A Redis error
 * or an answer slower than `timeoutMs` rejects; the verifier then refuses
 * the request with `tw.replay_store_unavailable` (fail closed). Redis
 * expires keys on its own clock; the verifier's clock-step guard covers a
 * step on the miner (D21).
 */
export class RedisNonceStore implements NonceStore {
    readonly retentionS: number;
    readonly #client: Redis;
    readonly #retentionMs: number;
    readonly #prefix: string;
    readonly #timeoutMs: number;

    constructor(client: Redis, retentionS: number, options: RedisStoreOptions = {}) {
        if (!Number.isFinite(retentionS) || retentionS < 0.001) {
            throw new RangeError("retentionS must be at least 1 ms");
        }
        const timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;
        if (!(timeoutMs > 0)) {
            throw new RangeError("timeoutMs must be > 0");
        }
        this.#client = client;
        this.retentionS = retentionS;
        this.#retentionMs = Math.ceil(retentionS * 1000);
        this.#prefix = options.prefix ?? DEFAULT_PREFIX;
        this.#timeoutMs = timeoutMs;
    }

    /**
     * A store on a new client for `url` that fails fast: no offline queue, no
     * retries per command, 500 ms connect timeout.
     */
    static fromUrl(url: string, retentionS: number, options: RedisStoreOptions = {}): RedisNonceStore {
        const client = new Redis(url, {
            enableOfflineQueue: false,
            maxRetriesPerRequest: 0,
            connectTimeout: 500,
            commandTimeout: options.timeoutMs ?? DEFAULT_TIMEOUT_MS,
        });
        client.on("error", () => undefined); // each failed command rejects on its own
        return new RedisNonceStore(client, retentionS, options);
    }

    /** The underlying client (to close it). */
    get client(): Redis {
        return this.#client;
    }

    /** `true` when the pair is new (and now stored). */
    async checkAndStore(hotkey: string, nonce: bigint): Promise<boolean> {
        const key = `${this.#prefix}${hotkey}:${nonce.toString(10)}`;
        let timer: NodeJS.Timeout | undefined;
        const timeout = new Promise<never>((_resolve, reject) => {
            timer = setTimeout(() => {
                reject(new Error(`redis did not answer within ${this.#timeoutMs} ms`));
            }, this.#timeoutMs);
        });
        try {
            const result = await Promise.race([
                this.#client.set(key, "1", "PX", this.#retentionMs, "NX"),
                timeout,
            ]);
            return result === "OK";
        } finally {
            clearTimeout(timer);
        }
    }
}
