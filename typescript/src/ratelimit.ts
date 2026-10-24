/**
 * Post-auth per-hotkey token bucket (spec 8.6.2, layer 2).
 *
 * @module
 */
import { monotonicNs } from "./clockstep.js";

/** Rate and burst of a bucket. */
export interface RateLimit {
    /** Tokens added per second (default 20, `TW_RATE_HOTKEY_PER_S`). */
    perS: number;
    /** Bucket size (default 40, `TW_RATE_HOTKEY_BURST`). */
    burst: number;
}

/** The defaults of spec 12.2. */
export const DEFAULT_HOTKEY_LIMIT: RateLimit = { perS: 20, burst: 40 };

/** Map size at which full buckets are first dropped. */
const SWEEP_MIN = 10_000;

interface Bucket {
    tokens: number;
    atNs: bigint;
}

/**
 * In-memory token buckets keyed by a string (hotkey and route). Full buckets
 * are dropped, so the map holds only keys that spent tokens recently.
 */
export class TokenBuckets {
    readonly #limit: RateLimit;
    readonly #nowNs: () => bigint;
    readonly #buckets = new Map<string, Bucket>();
    #sweepAt = SWEEP_MIN;

    constructor(limit: RateLimit = DEFAULT_HOTKEY_LIMIT, nowNs: () => bigint = monotonicNs) {
        if (!(limit.perS > 0) || !(limit.burst >= 1) || !Number.isFinite(limit.perS + limit.burst)) {
            throw new RangeError("perS must be > 0 and burst >= 1");
        }
        this.#limit = limit;
        this.#nowNs = nowNs;
    }

    /** Take one token: 0 when allowed, else the seconds until one is available (≥ 1, for `Retry-After`). */
    take(key: string): number {
        const now = this.#nowNs();
        const bucket = this.#buckets.get(key) ?? { tokens: this.#limit.burst, atNs: now };
        const elapsedS = Number(now - bucket.atNs) / 1e9;
        const tokens = Math.min(this.#limit.burst, bucket.tokens + elapsedS * this.#limit.perS);
        if (tokens < 1) {
            this.#buckets.set(key, { tokens, atNs: now });
            return Math.max(1, Math.ceil((1 - tokens) / this.#limit.perS));
        }
        this.#buckets.set(key, { tokens: tokens - 1, atNs: now });
        if (this.#buckets.size > this.#sweepAt) {
            this.#sweep(now);
            // Next sweep only after the map has doubled: O(1) amortised per take.
            this.#sweepAt = Math.max(SWEEP_MIN, this.#buckets.size * 2);
        }
        return 0;
    }

    #sweep(now: bigint): void {
        for (const [key, b] of this.#buckets) {
            if (b.tokens + (Number(now - b.atNs) / 1e9) * this.#limit.perS >= this.#limit.burst) {
                this.#buckets.delete(key);
            }
        }
    }
}
