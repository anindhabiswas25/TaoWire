/**
 * Clock-step guard (spec 8.4.3–8.4.4, D21).
 *
 * @module
 */

/** A monotonic clock in nanoseconds from an arbitrary origin. */
export function monotonicNs(): bigint {
    return process.hrtime.bigint();
}

/**
 * Detects backwards wall-clock steps.
 *
 * Freshness is judged on the wall clock, but a nonce store forgets pairs on
 * its own clock (the monotonic clock for `MemoryStore`, Redis' clock for
 * `RedisNonceStore`). If the wall clock steps back by more than the store's
 * margin, `retention − (maxAge + allowedSkew)`, a forgotten nonce could look
 * fresh again. The guard compares `wall − monotonic` with its previous value
 * on every request that reaches the replay check; a drop larger than the
 * margin opens a fail-closed window of `retention`, during which those
 * requests get `tw.replay_store_unavailable` instead of reaching the store.
 */
export class StepGuard {
    readonly #marginNs: bigint;
    readonly #holdNs: bigint;
    readonly #wallNs: () => bigint;
    readonly #monoNs: () => bigint;
    #offset: bigint;
    #until: bigint | null = null;
    #lastStep = 0n;

    constructor(marginNs: bigint, holdNs: bigint, wallNs: () => bigint, monoNs: () => bigint) {
        this.#marginNs = marginNs;
        this.#holdNs = holdNs;
        this.#wallNs = wallNs;
        this.#monoNs = monoNs;
        this.#offset = wallNs() - monoNs();
    }

    /** Measure now; whether the fail-closed window is open. */
    check(): boolean {
        const mono = this.#monoNs();
        const offset = this.#wallNs() - mono;
        const step = this.#offset - offset;
        this.#offset = offset;
        if (step > this.#marginNs) {
            this.#until = mono + this.#holdNs;
            this.#lastStep = step;
        }
        return this.#until !== null && mono < this.#until;
    }

    /** Size of the last step that opened the window (0 before the first). */
    get lastStepNs(): bigint {
        return this.#lastStep;
    }
}
