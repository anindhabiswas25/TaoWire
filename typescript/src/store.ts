/**
 * Replay stores (spec 8.4.3, D21).
 *
 * @module
 */
import { monotonicNs } from "./clockstep.js";
import { wallClockNs } from "./nonce.js";

/**
 * Remembers accepted `(hotkey, nonce)` pairs for `retentionS` seconds.
 * `checkAndStore` resolves `true` when the pair is new (and records it),
 * `false` on a replay, and rejects when the store cannot be reached (the
 * request is then refused with `tw.replay_store_unavailable`: fail closed).
 */
export interface NonceStore {
    /** How long accepted pairs are remembered, in seconds. */
    readonly retentionS: number;
    /** Record the pair; `false` if it was already recorded. */
    checkAndStore(hotkey: string, nonce: bigint): Promise<boolean>;
}

/** Clocks of a {@link MemoryStore} (tests replace them). */
export interface StoreClocks {
    /** Wall clock, Unix nanoseconds. */
    wallNs?: () => bigint;
    /** Monotonic clock, nanoseconds from any origin. */
    monoNs?: () => bigint;
}

interface Entry {
    key: string;
    nonce: bigint;
    forgetAtMono: bigint;
}

/** Seconds as nanoseconds (fractions kept to the nanosecond). */
export function secondsToNs(seconds: number): bigint {
    return BigInt(Math.round(seconds * 1e9));
}

/**
 * A {@link NonceStore} for one process. Several processes or hosts serving
 * one hotkey need a shared store (`@tensorwire/btauth/redis`).
 *
 * A pair is forgotten only when the retention has passed on the monotonic
 * clock **and** its nonce is older than the retention on the wall clock, so a
 * backwards wall-clock step cannot make a forgotten nonce fresh again.
 */
export class MemoryStore implements NonceStore {
    readonly retentionS: number;
    readonly #retentionNs: bigint;
    readonly #wallNs: () => bigint;
    readonly #monoNs: () => bigint;
    readonly #seen = new Set<string>();
    // Insertion order is expiry order on the monotonic clock.
    #queue: Entry[] = [];
    #head = 0;

    constructor(retentionS: number, clocks: StoreClocks = {}) {
        if (!Number.isFinite(retentionS) || retentionS <= 0) {
            throw new RangeError("retentionS must be a positive number");
        }
        this.retentionS = retentionS;
        this.#retentionNs = secondsToNs(retentionS);
        this.#wallNs = clocks.wallNs ?? wallClockNs;
        this.#monoNs = clocks.monoNs ?? monotonicNs;
    }

    /** The number of pairs remembered now. */
    get size(): number {
        this.#expire();
        return this.#seen.size;
    }

    #expire(): void {
        const mono = this.#monoNs();
        const wall = this.#wallNs();
        while (this.#head < this.#queue.length) {
            const entry = this.#queue[this.#head] as Entry;
            if (entry.forgetAtMono > mono || wall - entry.nonce <= this.#retentionNs) {
                break;
            }
            this.#seen.delete(entry.key);
            this.#head++;
        }
        if (this.#head > 1024 && this.#head * 2 > this.#queue.length) {
            this.#queue = this.#queue.slice(this.#head);
            this.#head = 0;
        }
    }

    /** Record `(hotkey, nonce)`; `false` if it was already recorded. */
    checkAndStore(hotkey: string, nonce: bigint): Promise<boolean> {
        this.#expire();
        const key = `${hotkey}:${nonce.toString()}`;
        if (this.#seen.has(key)) {
            return Promise.resolve(false);
        }
        this.#seen.add(key);
        this.#queue.push({ key, nonce, forgetAtMono: this.#monoNs() + this.#retentionNs });
        return Promise.resolve(true);
    }
}
