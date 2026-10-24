/**
 * Strictly increasing request nonces (spec 11.2 rules 4 and 5).
 *
 * @module
 */

/** The wall clock in Unix nanoseconds (millisecond resolution). */
export function wallClockNs(): bigint {
    return BigInt(Date.now()) * 1_000_000n;
}

/**
 * Hands out nonces `max(now_ns, last + 1)`: every call returns a value
 * larger than every earlier one, as a `bigint` (nanosecond times are about
 * 1.7 × 10^18, far above `Number.MAX_SAFE_INTEGER`).
 */
export class NonceSource {
    #last = 0n;
    readonly #nowNs: () => bigint;

    /** `nowNs` replaces the wall clock (tests). */
    constructor(nowNs: () => bigint = wallClockNs) {
        this.#nowNs = nowNs;
    }

    /** The next nonce. */
    next(): bigint {
        const now = this.#nowNs();
        this.#last = now > this.#last ? now : this.#last + 1n;
        return this.#last;
    }
}
