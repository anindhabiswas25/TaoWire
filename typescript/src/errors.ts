/**
 * Error codes and HTTP statuses of spec Appendix A, with the fixed public
 * messages of the Python kit (`taowire.errors`).
 *
 * @module
 */

/** Server-side Appendix A rows: status and public message. */
const CATALOGUE = {
    "tw.internal": [500, "internal error"],
    "tw.rate_limited": [429, "rate limit exceeded"],
    "tw.payload_too_large": [413, "request body exceeds the size limit"],
    "tw.auth_malformed": [401, "malformed authentication headers"],
    "tw.auth_wrong_receiver": [401, "request was signed for a different receiver"],
    "tw.auth_stale": [401, "request nonce is outside the freshness window"],
    "tw.auth_bad_signature": [401, "signature does not verify"],
    "tw.auth_replayed": [401, "request was already accepted"],
    "tw.forbidden_denied": [403, "caller is denied"],
    "tw.forbidden_not_registered": [403, "caller is not registered on this subnet"],
    "tw.forbidden_not_validator": [403, "caller has no validator permit"],
    "tw.forbidden_low_stake": [403, "caller stake is below the minimum"],
    "tw.forbidden_blacklisted": [403, "caller is blacklisted"],
    "tw.invalid_request": [422, "request body does not match the route model"],
    "tw.handler_error": [500, "handler failed"],
    "tw.metagraph_stale": [503, "metagraph snapshot is too old to admit this caller"],
    "tw.replay_store_unavailable": [503, "replay protection store is unavailable"],
    "tw.handler_timeout": [504, "handler timed out"],
    "tw.legacy_auth_failed": [401, "legacy v10 authentication failed"],
    "tw.legacy_disabled": [410, "legacy v10 requests are no longer accepted"],
    "tw.sidecar_unauthorized": [401, "sidecar token missing or wrong"],
} as const satisfies Record<string, readonly [number, string]>;

/** A server-side code of Appendix A. */
export type ServerCode = keyof typeof CATALOGUE;

/** Client-side codes (validator side, Appendix A): they have no HTTP status. */
export const CLIENT_CODES = [
    "tw.timeout",
    "tw.connect_error",
    "tw.bad_response_signature",
    "tw.response_too_large",
    "tw.invalid_response",
] as const;

/** A client-side code of Appendix A; `tw.http_<status>` is an answer without a known `tw.*` code. */
export type ClientCode = (typeof CLIENT_CODES)[number] | `tw.http_${number}`;

/** Any code this package raises. */
export type Code = ServerCode | ClientCode;

/** Whether `code` is a server-side code of Appendix A. */
export function isServerCode(code: string): code is ServerCode {
    return Object.hasOwn(CATALOGUE, code);
}

function isClientCode(code: string): code is ClientCode {
    return (CLIENT_CODES as readonly string[]).includes(code) || /^tw\.http_[1-9][0-9]{2}$/.test(code);
}

/**
 * A refusal with a stable `tw.*` code.
 *
 * `status` is the HTTP status (0 for client-side codes). `publicMessage` is
 * the fixed message, safe to send to an unauthenticated caller; `detail`
 * says more and is for logs only.
 */
export class TWError extends Error {
    /** The `tw.*` code. */
    readonly code: Code;
    /** The HTTP status of the code (0 for client-side codes). */
    readonly status: number;
    /** The fixed public message of the code. */
    readonly publicMessage: string;
    /** More detail, for logs only. */
    readonly detail: string;

    /**
     * An unknown code becomes `tw.internal` (500), so a typo can never produce
     * a 2xx.
     */
    constructor(code: string, detail = "") {
        let known: Code;
        let status: number;
        let message: string;
        if (isServerCode(code)) {
            known = code;
            [status, message] = CATALOGUE[code];
        } else if (isClientCode(code)) {
            known = code;
            status = 0;
            message = code;
        } else {
            known = "tw.internal";
            [status, message] = CATALOGUE["tw.internal"];
        }
        super(detail === "" ? `${known}: ${message}` : `${known}: ${detail}`);
        this.name = "TWError";
        this.code = known;
        this.status = status;
        this.publicMessage = message;
        this.detail = detail;
    }
}

/** The HTTP status of a server-side code (500 if unknown). */
export function statusOf(code: string): number {
    return isServerCode(code) ? CATALOGUE[code][0] : 500;
}

/**
 * The JSON body of every error response, in every language:
 * `{"error": {"code": ..., "message": ..., "request_id": ...}}`.
 */
export function errorBody(error: TWError, requestId: string | null = null): string {
    return JSON.stringify({
        error: { code: error.code, message: error.publicMessage, request_id: requestId },
    });
}
