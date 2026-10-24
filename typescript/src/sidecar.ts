/**
 * Sidecar client (spec 11.6): `@tensorwire/btauth/sidecar`.
 *
 * A TypeScript miner gets its caller policy and its chain writes from the
 * Python sidecar (`tensorwire sidecar`, loopback only, bearer token):
 *
 * ```ts
 * const sidecar = new SidecarClient({ netuid: 2, expectedHotkey: key.ss58 });
 * await sidecar.start(); // first metagraph, then a refresh every 60 s
 * await app.register(btauth, { verifier, responseKey: key, policy: sidecar.policyHook(), routes });
 * await sidecar.serveAxon({ ip: "203.0.113.7", port: 8091 });
 * ```
 *
 * The snapshot is cached locally and judged with the three staleness stages
 * of spec 8.5.1 from the age and tempo the sidecar reports; the caller
 * policy is the Python kit's (`CallerPolicy`, `CallerGate`). Every answer of
 * the sidecar is parsed strictly and fails closed: anything unexpected
 * rejects the answer, and never admits a caller. The wire shapes are in
 * `docs/multi-language.md` ("Sidecar API").
 *
 * @module
 */
import { closeSync, fstatSync, openSync, readFileSync } from "node:fs";
import { ClientError, readLimited } from "./client.js";
import { TWError } from "./errors.js";
import { decodeSS58 } from "./ss58.js";

/** Default sidecar URL (`TW_SIDECAR_PORT` 9910 on loopback). */
export const DEFAULT_SIDECAR_URL = "http://127.0.0.1:9910";
/** Default refresh of the cached metagraph, seconds (spec 11.6). */
export const DEFAULT_REFRESH_S = 60;
/** Block time used to turn a tempo into seconds (spec 8.5.1). */
export const BLOCK_TIME_S = 12;
/** Default `TW_METAGRAPH_SOFT_AGE_S`. */
export const DEFAULT_SOFT_AGE_S = 900;
/** Most neurons accepted in one snapshot. */
export const MAX_NEURONS = 65_536;
/** Most remembered known callers (Python `DEFAULT_MAX_KNOWN_CALLERS`). */
export const MAX_KNOWN_CALLERS = 65_536;
/** Largest sidecar answer read. */
export const MAX_ANSWER_BYTES = 32 * 1024 * 1024;

const FORBIDDEN_CODES = [
    "tw.forbidden_denied",
    "tw.forbidden_not_registered",
    "tw.forbidden_not_validator",
    "tw.forbidden_low_stake",
    "tw.metagraph_stale",
] as const;

/** Staleness stages of a snapshot (spec 8.5.1). */
export type Stage = "fresh" | "degraded" | "known_callers_only";

/** One neuron of a sidecar snapshot. */
export interface Neuron {
    /** UID on the subnet. */
    uid: number;
    /** SS58 hotkey. */
    hotkey: string;
    /** Whether it holds a validator permit. */
    validatorPermit: boolean;
    /** TAO value of its stake at spot price (approximate, D2). */
    totalStakeTao: number;
    /** Published endpoint (`host:port`, `[v6]:port`) or `null`. */
    axon: string | null;
}

/** A metagraph snapshot as the sidecar reported it. */
export interface Snapshot {
    /** Subnet. */
    netuid: number;
    /** Block the snapshot was read at. */
    block: number;
    /** Subnet tempo in blocks. */
    tempo: number;
    /** Age of the snapshot when the sidecar answered, seconds. */
    ageS: number;
    /** Neurons in UID order. */
    neurons: readonly Neuron[];
    /** Neurons by hotkey. */
    byHotkey: ReadonlyMap<string, Neuron>;
}

/** What `/v1/health` reports. */
export interface Health {
    /** False when there is no snapshot or it is past the max age. */
    ok: boolean;
    /** The sidecar's hotkey (it publishes the axon for it). */
    hotkey: string;
    /** Its subnet. */
    netuid: number;
    /** Snapshot block, `null` before the first. */
    block: number | null;
    /** Snapshot age, `null` before the first. */
    metagraphAgeS: number | null;
    /** The sidecar's own stage. */
    stage: Stage;
}

/** `/v1/caller` decision. */
export type CallerDecision = { allowed: true } | { allowed: false; code: ForbiddenCode };

/** A refusal code `/v1/caller` may answer. */
export type ForbiddenCode = (typeof FORBIDDEN_CODES)[number];

/** The chain refused a write (`/v1/serve-axon` 409 / 503). `code` is the `bt.ErrorCode` value. */
export class SidecarChainError extends Error {
    /** `bt.ErrorCode` value, or `chain_unavailable`. */
    readonly code: string;
    /** The chain's own error name, if any. */
    readonly errorName: string | null;
    /** The SDK's hint, if any. */
    readonly remediation: string | null;

    constructor(code: string, errorName: string | null, remediation: string | null) {
        super(`serve-axon refused by the chain: ${code}`);
        this.name = "SidecarChainError";
        this.code = code;
        this.errorName = errorName;
        this.remediation = remediation;
    }
}

// ---------------------------------------------------------------- token

/** Shortest and longest accepted token. */
export const TOKEN_LENGTH = [16, 1024] as const;

/**
 * Read the bearer token from `path` (`TW_SIDECAR_TOKEN_FILE`): a regular file
 * that only its owner can read or write (the TLS key rule), 16–1024
 * printable ASCII characters after one trailing newline is removed. Errors
 * name the file, never its contents. One descriptor is used for the mode
 * check and the read.
 */
export function readTokenFile(path: string): string {
    let fd: number;
    try {
        fd = openSync(path, "r");
    } catch (err) {
        throw new Error(
            `cannot open sidecar token file ${path}: ${(err as NodeJS.ErrnoException).code ?? "error"}`,
        );
    }
    try {
        const st = fstatSync(fd);
        if (!st.isFile()) {
            throw new Error(`sidecar token file ${path} is not a regular file`);
        }
        if ((st.mode & 0o077) !== 0) {
            throw new Error(
                `sidecar token file ${path} must not be readable or writable by group or others (chmod 600)`,
            );
        }
        if (st.size > TOKEN_LENGTH[1] + 2) {
            throw new Error(`sidecar token file ${path} is too large`);
        }
        const text = readFileSync(fd, "latin1").replace(/\r?\n$/, "");
        return checkToken(text, path);
    } finally {
        closeSync(fd);
    }
}

function checkToken(token: string, where: string): string {
    if (token.length < TOKEN_LENGTH[0] || token.length > TOKEN_LENGTH[1] || !/^[\x21-\x7e]+$/.test(token)) {
        throw new Error(
            `sidecar token from ${where} must be ${TOKEN_LENGTH[0]}-${TOKEN_LENGTH[1]} printable ASCII characters`,
        );
    }
    return token;
}

/** Whether `url` points at this host (the token travels in clear otherwise). */
export function isLoopbackUrl(url: URL): boolean {
    const host = url.hostname.replace(/^\[|\]$/g, "");
    return host === "localhost" || host === "::1" || /^127\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(host);
}

// ---------------------------------------------------------------- policy

/** Options of a {@link CallerPolicy}; the defaults are the strict policy. */
export interface CallerPolicyOptions {
    /** `TW_REQUIRE_PERMIT` (default true). */
    requirePermit?: boolean;
    /** `TW_MIN_CALLER_STAKE_TAO` (default 0 = off). */
    minStakeTao?: number;
    /** `TW_ALLOW_HOTKEYS`: always allowed, even unregistered. */
    allowHotkeys?: Iterable<string>;
    /** `TW_DENY_HOTKEYS`: always denied, checked first. */
    denyHotkeys?: Iterable<string>;
}

/**
 * Who may call a route (spec 8.5), the Python kit's order: deny list, allow
 * list, registered, validator permit, minimum stake.
 */
export class CallerPolicy {
    /** Validator permit required. */
    readonly requirePermit: boolean;
    /** Minimum `totalStakeTao`; 0 disables the check. */
    readonly minStakeTao: number;
    /** Always allowed. */
    readonly allowHotkeys: ReadonlySet<string>;
    /** Always denied. */
    readonly denyHotkeys: ReadonlySet<string>;

    /** Throws `RangeError` for a negative or NaN stake or a hotkey in both lists. */
    constructor(options: CallerPolicyOptions = {}) {
        this.requirePermit = options.requirePermit ?? true;
        this.minStakeTao = options.minStakeTao ?? 0;
        this.allowHotkeys = new Set(options.allowHotkeys ?? []);
        this.denyHotkeys = new Set(options.denyHotkeys ?? []);
        if (!(this.minStakeTao >= 0) || !Number.isFinite(this.minStakeTao)) {
            throw new RangeError("minStakeTao must be a finite number >= 0");
        }
        for (const h of this.allowHotkeys) {
            if (this.denyHotkeys.has(h)) throw new RangeError("a hotkey cannot be both allowed and denied");
        }
    }

    /** Throw `TWError` 403 unless `hotkey` may call; its neuron (`null` for an allow-listed unregistered hotkey). */
    check(hotkey: string, snapshot: Snapshot): Neuron | null {
        if (this.denyHotkeys.has(hotkey)) throw new TWError("tw.forbidden_denied");
        const n = snapshot.byHotkey.get(hotkey) ?? null;
        if (this.allowHotkeys.has(hotkey)) return n;
        if (n === null) throw new TWError("tw.forbidden_not_registered");
        if (this.requirePermit && !n.validatorPermit) throw new TWError("tw.forbidden_not_validator");
        if (this.minStakeTao > 0 && n.totalStakeTao < this.minStakeTao)
            throw new TWError("tw.forbidden_low_stake");
        return n;
    }
}

// ---------------------------------------------------------------- strict JSON

/** Whether valid JSON text has an object with the same key twice (at any depth). */
export function hasDuplicateKeys(text: string): boolean {
    const stack: (Set<string> | null)[] = [];
    let expectKey = false;
    for (let i = 0; i < text.length; i++) {
        const c = text[i];
        if (c === '"') {
            let j = i + 1;
            while (text[j] !== '"') j += text[j] === "\\" ? 2 : 1;
            if (expectKey) {
                const key = JSON.parse(text.slice(i, j + 1)) as string;
                const keys = stack[stack.length - 1] as Set<string>;
                if (keys.has(key)) return true;
                keys.add(key);
                expectKey = false;
            }
            i = j;
        } else if (c === "{") {
            stack.push(new Set());
            expectKey = true;
        } else if (c === "[") {
            stack.push(null);
        } else if (c === "}" || c === "]") {
            stack.pop();
            expectKey = false;
        } else if (c === ",") {
            expectKey = stack[stack.length - 1] instanceof Set;
        }
    }
    return false;
}

const fatal = new TextDecoder("utf-8", { fatal: true });

function bad(detail: string): ClientError {
    return new ClientError("tw.invalid_response", `sidecar: ${detail}`);
}

/** Parse a sidecar answer strictly: UTF-8 JSON, an object, no duplicate keys. */
function strictObject(body: Uint8Array): Record<string, unknown> {
    let text: string;
    let value: unknown;
    try {
        text = fatal.decode(body);
        value = JSON.parse(text);
    } catch {
        throw bad("answer is not JSON");
    }
    if (typeof value !== "object" || value === null || Array.isArray(value))
        throw bad("answer is not an object");
    if (hasDuplicateKeys(text)) throw bad("duplicate key");
    return value as Record<string, unknown>;
}

const isInt = (v: unknown, low: number, high: number): v is number =>
    typeof v === "number" && Number.isInteger(v) && v >= low && v <= high;
const isNonNegative = (v: unknown): v is number => typeof v === "number" && Number.isFinite(v) && v >= 0;

function isSS58(v: unknown): v is string {
    if (typeof v !== "string") return false;
    try {
        decodeSS58(v);
        return true;
    } catch {
        return false;
    }
}

/**
 * Parse a `/v1/metagraph` answer for `netuid`; any deviation from the
 * documented shape throws `tw.invalid_response` (the whole answer is
 * rejected).
 */
export function parseSnapshot(body: Uint8Array, netuid: number): Snapshot {
    const o = strictObject(body);
    if (o.netuid !== netuid) throw bad("snapshot for another netuid");
    if (!isInt(o.block, 0, Number.MAX_SAFE_INTEGER)) throw bad("block");
    if (!isInt(o.tempo, 1, 65_535)) throw bad("tempo");
    if (!isNonNegative(o.age_s)) throw bad("age_s");
    if (!Array.isArray(o.neurons) || o.neurons.length > MAX_NEURONS) throw bad("neurons");
    const neurons: Neuron[] = [];
    const byHotkey = new Map<string, Neuron>();
    const uids = new Set<number>();
    for (const raw of o.neurons as unknown[]) {
        if (typeof raw !== "object" || raw === null || Array.isArray(raw)) throw bad("neuron");
        const r = raw as Record<string, unknown>;
        if (!isInt(r.uid, 0, 65_535) || uids.has(r.uid)) throw bad("neuron uid");
        if (!isSS58(r.hotkey) || byHotkey.has(r.hotkey)) throw bad("neuron hotkey");
        if (typeof r.validator_permit !== "boolean") throw bad("neuron validator_permit");
        if (!isNonNegative(r.total_stake_tao)) throw bad("neuron total_stake_tao");
        if (r.axon !== null && typeof r.axon !== "string") throw bad("neuron axon");
        const n: Neuron = {
            uid: r.uid,
            hotkey: r.hotkey,
            validatorPermit: r.validator_permit,
            totalStakeTao: r.total_stake_tao,
            axon: r.axon,
        };
        uids.add(n.uid);
        byHotkey.set(n.hotkey, n);
        neurons.push(n);
    }
    return { netuid, block: o.block, tempo: o.tempo, ageS: o.age_s, neurons, byHotkey };
}

/** Parse a `/v1/caller` answer: allowed only for exactly `{"allowed": true}`. */
export function parseCallerDecision(body: Uint8Array): CallerDecision {
    const o = strictObject(body);
    const keys = Object.keys(o);
    if (o.allowed === true && keys.length === 1) return { allowed: true };
    if (
        o.allowed === false &&
        keys.length === 2 &&
        (FORBIDDEN_CODES as readonly unknown[]).includes(o.code)
    ) {
        return { allowed: false, code: o.code as ForbiddenCode };
    }
    throw bad("caller decision");
}

const STAGES: readonly string[] = ["fresh", "degraded", "known_callers_only"];

/** Parse a `/v1/health` answer. */
export function parseHealth(body: Uint8Array): Health {
    const o = strictObject(body);
    if (typeof o.ok !== "boolean" || !isSS58(o.hotkey) || !isInt(o.netuid, 0, 65_535)) throw bad("health");
    if (o.block !== null && !isInt(o.block, 0, Number.MAX_SAFE_INTEGER)) throw bad("health block");
    if (o.metagraph_age_s !== null && !isNonNegative(o.metagraph_age_s)) throw bad("health age");
    if (typeof o.stage !== "string" || !STAGES.includes(o.stage)) throw bad("health stage");
    return {
        ok: o.ok,
        hotkey: o.hotkey,
        netuid: o.netuid,
        block: o.block,
        metagraphAgeS: o.metagraph_age_s,
        stage: o.stage as Stage,
    };
}

// ---------------------------------------------------------------- client

/** Options of a {@link SidecarClient}. */
export interface SidecarClientOptions {
    /** The subnet (`TW_NETUID`). */
    netuid: number;
    /** Sidecar base URL (default `http://127.0.0.1:9910`); must be loopback unless `unsafeAllowRemote`. */
    url?: string;
    /** Token file (`TW_SIDECAR_TOKEN_FILE`); ignored when `token` is given. */
    tokenFile?: string;
    /** The token itself (tests; prefer `tokenFile`). */
    token?: string;
    /** Refuse a sidecar whose hotkey is not this one (the miner's hotkey). */
    expectedHotkey?: string;
    /** Caller policy (default: the strict one). */
    policy?: CallerPolicy;
    /** `TW_METAGRAPH_STRICT`: 503 for everyone past the max age. */
    strict?: boolean;
    /** `TW_METAGRAPH_SOFT_AGE_S` (default `min(900, maxAge / 2)`). */
    softAgeS?: number;
    /** `TW_METAGRAPH_MAX_AGE_S` (default 2 tempos in seconds). */
    maxAgeS?: number;
    /** Metagraph refresh, seconds (default 60). */
    refreshS?: number;
    /** Per-call timeout, ms (default 5 000). */
    timeoutMs?: number;
    /** Allow a non-loopback URL (the token then crosses a network in clear). */
    unsafeAllowRemote?: boolean;
    /** Replaces `fetch` (tests). */
    fetch?: typeof fetch;
    /** Monotonic clock in ms (tests). */
    monotonicMs?: () => number;
}

interface Held {
    snapshot: Snapshot;
    /** Monotonic ms at which the snapshot was read by the sidecar. */
    at: number;
}

/** The sidecar client: cached metagraph, caller policy, serve-axon (see the module docs). */
export class SidecarClient {
    /** The subnet. */
    readonly netuid: number;
    /** The policy applied by {@link check}. */
    readonly policy: CallerPolicy;
    readonly #url: URL;
    readonly #token: string;
    readonly #expectedHotkey: string | null;
    readonly #strict: boolean;
    readonly #softAgeS: number | undefined;
    readonly #maxAgeS: number | undefined;
    readonly #refreshMs: number;
    readonly #timeoutMs: number;
    readonly #fetch: typeof fetch;
    readonly #now: () => number;
    readonly #known = new Map<string, number>();
    #held: Held | null = null;
    #timer: ReturnType<typeof setTimeout> | null = null;
    #stopped = false;

    /** Throws for a remote URL (without `unsafeAllowRemote`), a bad token or bad settings. */
    constructor(options: SidecarClientOptions) {
        if (!Number.isInteger(options.netuid) || options.netuid < 0 || options.netuid > 65_535) {
            throw new RangeError("netuid must be an integer 0-65535");
        }
        this.netuid = options.netuid;
        this.#url = new URL(options.url ?? DEFAULT_SIDECAR_URL);
        if (this.#url.protocol !== "http:" && this.#url.protocol !== "https:") {
            throw new RangeError("the sidecar URL must be http(s)");
        }
        if (!isLoopbackUrl(this.#url) && options.unsafeAllowRemote !== true) {
            throw new RangeError("the sidecar URL must be on loopback (127.0.0.0/8, ::1, localhost)");
        }
        if (options.token !== undefined) {
            this.#token = checkToken(options.token, "options.token");
        } else {
            const file = options.tokenFile ?? process.env.TW_SIDECAR_TOKEN_FILE;
            if (file === undefined || file === "") {
                throw new RangeError("give tokenFile (or TW_SIDECAR_TOKEN_FILE) or token");
            }
            this.#token = readTokenFile(file);
        }
        this.#expectedHotkey = options.expectedHotkey ?? null;
        this.policy = options.policy ?? new CallerPolicy();
        this.#strict = options.strict ?? false;
        this.#softAgeS = options.softAgeS;
        this.#maxAgeS = options.maxAgeS;
        if (
            this.#softAgeS !== undefined &&
            this.#maxAgeS !== undefined &&
            !(this.#softAgeS < this.#maxAgeS)
        ) {
            throw new RangeError("softAgeS must be below maxAgeS");
        }
        this.#refreshMs = (options.refreshS ?? DEFAULT_REFRESH_S) * 1000;
        this.#timeoutMs = options.timeoutMs ?? 5_000;
        if (!(this.#refreshMs > 0) || !(this.#timeoutMs > 0)) {
            throw new RangeError("refreshS and timeoutMs must be > 0");
        }
        this.#fetch = options.fetch ?? fetch;
        this.#now = options.monotonicMs ?? (() => performance.now());
    }

    /** Never shows the token. */
    toString(): string {
        return `SidecarClient(${this.#url.origin}, netuid ${this.netuid})`;
    }

    /** Never shows the token. */
    toJSON(): string {
        return this.toString();
    }

    async #call(method: "GET" | "POST", path: string, body?: unknown): Promise<[number, Uint8Array]> {
        const signal = AbortSignal.timeout(this.#timeoutMs);
        let response: Response;
        try {
            response = await this.#fetch(new URL(path, this.#url), {
                method,
                headers: {
                    Authorization: `Bearer ${this.#token}`,
                    ...(body === undefined ? {} : { "Content-Type": "application/json" }),
                },
                body: body === undefined ? null : JSON.stringify(body),
                signal,
                redirect: "manual",
            });
        } catch (err) {
            if (signal.aborted) throw new ClientError("tw.timeout", "sidecar did not answer in time");
            throw new ClientError(
                "tw.connect_error",
                `sidecar: ${err instanceof Error ? err.message : String(err)}`,
            );
        }
        try {
            return [response.status, await readLimited(response, MAX_ANSWER_BYTES)];
        } catch (err) {
            if (err instanceof ClientError) throw err;
            if (signal.aborted) throw new ClientError("tw.timeout", "sidecar did not answer in time");
            throw bad("answer could not be read");
        }
    }

    /** A non-200 answer as the sidecar's own `tw.*` code (Appendix A body), else `tw.invalid_response`. */
    static #errorOf(status: number, body: Uint8Array): ClientError {
        try {
            const o = strictObject(body);
            const code = (o.error as { code?: unknown } | undefined)?.code;
            if (typeof code === "string") {
                const tw = new TWError(code);
                if (tw.code === code && tw.status === status)
                    return new ClientError(code, "answered by the sidecar", status);
            }
        } catch {
            // not an error body
        }
        return new ClientError("tw.invalid_response", `sidecar answered ${String(status)}`, status);
    }

    /** `GET /v1/health`. */
    async health(): Promise<Health> {
        const [status, body] = await this.#call("GET", "/v1/health");
        if (status !== 200) throw SidecarClient.#errorOf(status, body);
        return parseHealth(body);
    }

    /** `GET /v1/metagraph`: the snapshot, also stored for {@link check}. */
    async metagraph(): Promise<Snapshot> {
        const [status, body] = await this.#call("GET", `/v1/metagraph?netuid=${String(this.netuid)}`);
        if (status !== 200) throw SidecarClient.#errorOf(status, body);
        const snapshot = parseSnapshot(body, this.netuid);
        const at = this.#now() - snapshot.ageS * 1000;
        // Only a newer snapshot replaces the held one and clears the known
        // callers: a sidecar repeating its own stale snapshot changes nothing.
        // The block decides; the derived time only when the chain stalls (the
        // answer's own delay, up to the timeout, must not make it look newer).
        const held = this.#held;
        if (held === null || snapshot.block > held.snapshot.block || at > held.at + this.#timeoutMs + 1000) {
            this.#known.clear();
            this.#held = { snapshot, at };
        }
        return snapshot;
    }

    /** `GET /v1/caller/{hotkey}`: the sidecar's own decision. */
    async caller(hotkey: string): Promise<CallerDecision> {
        const path = `/v1/caller/${encodeURIComponent(hotkey)}?netuid=${String(this.netuid)}`;
        const [status, body] = await this.#call("GET", path);
        if (status !== 200) throw SidecarClient.#errorOf(status, body);
        return parseCallerDecision(body);
    }

    /**
     * `POST /v1/serve-axon`: publish `ip:port` (and a TLS key, ADR-0011) for
     * the sidecar's hotkey. Sent once (a chain write is never resent blindly).
     * Resolves the block hash; rejects with {@link SidecarChainError} when the
     * chain refuses.
     */
    async serveAxon(axon: { ip: string; port: number; tlsCertHex?: string | null }): Promise<string> {
        const [status, body] = await this.#call("POST", "/v1/serve-axon", {
            netuid: this.netuid,
            ip: axon.ip,
            port: axon.port,
            tls_cert_hex: axon.tlsCertHex ?? null,
        });
        if (status === 200) {
            const o = strictObject(body);
            if (o.ok !== true || typeof o.block_hash !== "string" || !/^0x[0-9a-f]{64}$/.test(o.block_hash)) {
                throw bad("serve-axon answer");
            }
            return o.block_hash;
        }
        if (status === 409 || status === 503) {
            let o: Record<string, unknown> | null = null;
            try {
                o = strictObject(body);
            } catch {
                // falls through to the generic error
            }
            if (o !== null && o.ok === false && typeof o.code === "string") {
                const str = (v: unknown) => (typeof v === "string" ? v : null);
                throw new SidecarChainError(o.code, str(o.error_name), str(o.remediation));
            }
        }
        throw SidecarClient.#errorOf(status, body);
    }

    /**
     * Check the sidecar (its netuid, and its hotkey when `expectedHotkey` is
     * set), fetch the first snapshot (rejects if it cannot), then refresh
     * every `refreshS` (±10%) in the background.
     */
    async start(): Promise<void> {
        const h = await this.health();
        if (h.netuid !== this.netuid)
            throw new Error(`sidecar follows netuid ${String(h.netuid)}, not ${String(this.netuid)}`);
        if (this.#expectedHotkey !== null && h.hotkey !== this.#expectedHotkey) {
            throw new Error("the sidecar's hotkey is not this miner's hotkey");
        }
        await this.metagraph();
        this.stop(); // a second start replaces the running refresh, never adds one
        this.#stopped = false;
        this.#schedule();
    }

    #schedule(): void {
        if (this.#stopped) return;
        const delay = this.#refreshMs * (0.9 + Math.random() * 0.2);
        this.#timer = setTimeout(() => {
            this.metagraph().then(
                () => {
                    this.#schedule();
                },
                () => {
                    this.#schedule(); // keep the old snapshot; it keeps aging
                },
            );
        }, delay);
        this.#timer.unref();
    }

    /** Stop the background refresh. */
    stop(): void {
        this.#stopped = true;
        if (this.#timer !== null) clearTimeout(this.#timer);
        this.#timer = null;
    }

    /** The cached snapshot, or `null`. */
    snapshot(): Snapshot | null {
        return this.#held?.snapshot ?? null;
    }

    /** Age of the cached snapshot in seconds now, or `null`. */
    ageS(): number | null {
        return this.#held === null ? null : (this.#now() - this.#held.at) / 1000;
    }

    /** Thresholds in force: `[softAgeS, maxAgeS]` (8.5.1; from the snapshot's tempo). */
    thresholds(): [number, number] {
        const tempo = this.#held?.snapshot.tempo ?? 360;
        const max = this.#maxAgeS ?? 2 * tempo * BLOCK_TIME_S;
        const soft = this.#softAgeS ?? Math.min(DEFAULT_SOFT_AGE_S, max / 2);
        return [soft, max];
    }

    /** The current stage; no snapshot is `known_callers_only` (fail closed). */
    stage(): Stage {
        const age = this.ageS();
        const [soft, max] = this.thresholds();
        if (age === null || age > max) return "known_callers_only";
        return age >= soft ? "degraded" : "fresh";
    }

    /**
     * Admit `hotkey` for `scope` (e.g. the route), or throw `TWError` 403 /
     * 503 `tw.metagraph_stale` (the Python `CallerGate.admit`). Returns its
     * neuron (`null` when unknown to the snapshot).
     */
    check(hotkey: string, scope = "*"): Neuron | null {
        if (this.policy.denyHotkeys.has(hotkey)) throw new TWError("tw.forbidden_denied");
        const held = this.#held;
        const key = `${scope}\n${hotkey}`;
        if (held === null || this.stage() === "known_callers_only") {
            if (this.#strict || !this.#known.has(key)) throw new TWError("tw.metagraph_stale");
            return held?.snapshot.byHotkey.get(hotkey) ?? null;
        }
        const n = this.policy.check(hotkey, held.snapshot);
        this.#known.delete(key);
        this.#known.set(key, this.#now());
        if (this.#known.size > MAX_KNOWN_CALLERS) {
            const oldest = this.#known.keys().next().value as string;
            this.#known.delete(oldest);
        }
        return n;
    }

    /** The Fastify plugin's `policy` hook, with the route path as scope. */
    policyHook(): (
        caller: { hotkey: string },
        request: { routeOptions: { url?: string | undefined } },
    ) => void {
        return (caller, request) => {
            this.check(caller.hotkey, request.routeOptions.url ?? "*");
        };
    }
}
