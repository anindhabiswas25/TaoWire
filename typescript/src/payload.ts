/**
 * The btauth/1 signed payload (spec 4.2).
 *
 * @module
 */
import { createHash } from "node:crypto";

/** A signature scheme. Absent `X-Bittensor-Crypto` means sr25519. */
export type Scheme = "sr25519" | "ed25519";

/** First line of every btauth/1 payload. */
export const PROTOCOL = "btauth/1";

/** Input of {@link buildPayload}. */
export interface PayloadInput {
    /** Signature scheme line. */
    scheme: Scheme;
    /** HTTP method (upper-cased in the payload). */
    method: string;
    /** Request target exactly as sent: percent-encoded path plus `?query`. */
    target: string;
    /** The raw body bytes. */
    body: Uint8Array;
    /** Nonce, Unix time in nanoseconds (never a `Number`, spec 11.2 rule 4). */
    nonceNs: bigint;
    /** Sender hotkey, SS58. */
    sender: string;
    /** Receiver hotkey, SS58, or `null` for unbound (`-`). */
    receiver: string | null;
}

/** sha256 of `body`, lowercase hex. */
export function bodySha256(body: Uint8Array): string {
    return createHash("sha256").update(body).digest("hex");
}

/**
 * The UTF-8 bytes of the eight `\n`-joined lines of spec 4.2, with no
 * trailing newline. The body hash is always recomputed from the raw bytes.
 */
export function buildPayload(p: PayloadInput): Uint8Array {
    const lines = [
        PROTOCOL,
        p.scheme,
        p.method.toUpperCase(),
        p.target,
        bodySha256(p.body),
        p.nonceNs.toString(10),
        p.sender,
        p.receiver ?? "-",
    ];
    return new TextEncoder().encode(lines.join("\n"));
}
