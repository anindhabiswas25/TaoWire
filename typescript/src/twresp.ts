/**
 * twresp/1 signed responses (spec 9.1; the digest form is the stream
 * trailer of 9.2).
 *
 * @module
 */
import { TWError } from "./errors.js";
import { type HeaderInput, duplicateWithPrefix, headerMap, single } from "./headers.js";
import { type Keypair, signatureHex, verifySignature } from "./keys.js";
import { type Scheme, bodySha256 } from "./payload.js";
import { decodeSS58 } from "./ss58.js";

/** Response header names of twresp/1. */
export const RESP_HEADER = {
    version: "X-TW-Resp-Version",
    hotkey: "X-TW-Resp-Hotkey",
    crypto: "X-TW-Resp-Crypto",
    signature: "X-TW-Resp-Signature",
} as const;

/** First line of every twresp/1 payload. */
export const RESP_PROTOCOL = "twresp/1";

const SIGNATURE_RE = /^0x[0-9a-fA-F]{128}$/;

/** Fields of a twresp/1 payload. */
export interface ResponseBinding {
    /** Nonce of the request answered (`X-Bittensor-Nonce`). */
    requestNonce: bigint;
    /** Hotkey of the request's sender (the validator). */
    sender: string;
    /** HTTP status of the answer. */
    status: number;
}

/** The twresp/1 payload; `digest` is the body sha256 hex or a stream digest. */
export function responsePayload(
    scheme: Scheme,
    binding: ResponseBinding,
    responder: string,
    digest: string,
): Uint8Array {
    const lines = [
        RESP_PROTOCOL,
        scheme,
        binding.requestNonce.toString(10),
        binding.sender,
        responder,
        String(binding.status),
        digest,
    ];
    return new TextEncoder().encode(lines.join("\n"));
}

/** The identity headers sent at stream start: version, hotkey and crypto, no signature. */
export function identityHeaders(key: Keypair): Record<string, string> {
    const headers: Record<string, string> = {
        [RESP_HEADER.version]: "1",
        [RESP_HEADER.hotkey]: key.ss58,
    };
    if (key.scheme === "ed25519") {
        headers[RESP_HEADER.crypto] = "ed25519";
    }
    return headers;
}

/** The `0x` signature over a response digest (the `tw-end` signature of 9.2). */
export function signDigest(key: Keypair, binding: ResponseBinding, digest: string): string {
    const sig = key.sign(responsePayload(key.scheme, binding, key.ss58, digest));
    return signatureHex(sig);
}

/** The twresp/1 headers for an answer with `body`. */
export function signResponse(
    key: Keypair,
    binding: ResponseBinding,
    body: Uint8Array,
): Record<string, string> {
    return {
        ...identityHeaders(key),
        [RESP_HEADER.signature]: signDigest(key, binding, bodySha256(body)),
    };
}

/** What a validator expects of an answer. */
export interface ResponseExpectation extends ResponseBinding {
    /** The miner hotkey this validator queried. */
    expectedResponder: string;
}

function bad(detail: string): TWError {
    return new TWError("tw.bad_response_signature", detail);
}

/**
 * Check an answer's twresp/1 signature against what this validator sent:
 * the miner queried, the request's nonce and sender, the status. Any
 * mismatch, missing or repeated `X-TW-Resp-*` header, unknown scheme or bad
 * signature throws `tw.bad_response_signature`. Returns the scheme.
 */
export function verifyResponse(
    headers: HeaderInput,
    expected: ResponseExpectation,
    body: Uint8Array,
): Scheme {
    return verifyResponseDigest(headers, expected, bodySha256(body));
}

/** {@link verifyResponse} with the body digest given directly (the `tw-end` of 9.2). */
export function verifyResponseDigest(
    headers: HeaderInput,
    expected: ResponseExpectation,
    digest: string,
): Scheme {
    const map = headerMap(headers);
    const dup = duplicateWithPrefix(map, "x-tw-resp-");
    if (dup !== null) {
        throw bad(`duplicate ${dup} header`);
    }
    const version = single(map, RESP_HEADER.version);
    if (version === undefined) {
        throw bad("response is not signed");
    }
    if (version !== "1") {
        throw bad("unsupported response signature version");
    }
    if (single(map, RESP_HEADER.hotkey) !== expected.expectedResponder) {
        throw bad("response signed by another hotkey");
    }
    let scheme: Scheme = "sr25519";
    const declared = single(map, RESP_HEADER.crypto);
    if (declared !== undefined) {
        if (declared !== "sr25519" && declared !== "ed25519") {
            throw bad("unsupported response signature scheme");
        }
        scheme = declared;
    }
    const sigText = single(map, RESP_HEADER.signature) ?? "";
    if (!SIGNATURE_RE.test(sigText)) {
        throw bad("malformed response signature");
    }
    let key: Uint8Array;
    try {
        key = decodeSS58(expected.expectedResponder);
    } catch {
        throw bad("malformed response signature");
    }
    const payload = responsePayload(scheme, expected, expected.expectedResponder, digest);
    if (!verifySignature(scheme, key, payload, Buffer.from(sigText.slice(2), "hex"))) {
        throw bad("invalid response signature");
    }
    return scheme;
}
