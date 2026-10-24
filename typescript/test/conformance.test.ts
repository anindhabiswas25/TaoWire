// Every shared vector (spec 11.7, 11.2 rule 12). legacy_v10.json is Python only (as in
// Go and Rust); python_reference notes are ignored: expected is the normative answer.
import { beforeAll, describe, expect, it } from "vitest";
import {
    StreamDigest,
    TWError,
    bodySha256,
    buildPayload,
    decodeChunk,
    decodeSS58,
    encodeTrailer,
    initCrypto,
    parseTrailer,
    responsePayload,
    signatureHex,
    signResponse,
    verifyResponse,
    verifyResponseDigest,
    verifySignature,
} from "@taowire/btauth";
import {
    type VerifyVector,
    b64,
    devKeys,
    keyBySS58,
    loadVectors,
    request,
    vectorFiles,
    vectorVerifier,
} from "./helpers.js";

beforeAll(initCrypto);

const KNOWN_FILES = [
    "ed25519.json",
    "legacy_v10.json",
    "negative.json",
    "payload.json",
    "sr25519_verify.json",
    "twresp.json",
];

it("knows every vector file", () => {
    // A new file must get a runner here before it can pass.
    expect(vectorFiles()).toEqual(KNOWN_FILES);
});

describe("payload.json", () => {
    const f = loadVectors("payload.json");
    for (const raw of f.vectors) {
        const v = raw as {
            id: string;
            kind: string;
            inputs: Record<string, string | null>;
            expected: { body_sha256: string; payload_base64: string };
        };
        it(v.id, () => {
            expect(v.kind).toBe("build_payload");
            const i = v.inputs;
            const body = b64(i.body_base64 ?? "");
            expect(bodySha256(body)).toBe(v.expected.body_sha256);
            const payload = buildPayload({
                scheme: i.scheme as "sr25519" | "ed25519",
                method: i.method ?? "",
                target: i.target ?? "",
                body,
                nonceNs: BigInt(i.nonce ?? ""),
                sender: i.sender_ss58 ?? "",
                receiver: i.receiver_ss58 ?? null,
            });
            expect(Buffer.from(payload).toString("base64")).toBe(v.expected.payload_base64);
        });
    }
});

describe("dev keys", () => {
    for (const [name, k] of Object.entries(devKeys())) {
        it(name, () => {
            const kp = keyBySS58(k.ss58);
            expect(Buffer.from(kp.publicKey).toString("hex")).toBe(k.public_key_hex);
            expect(kp.ss58).toBe(k.ss58);
            expect(Buffer.from(decodeSS58(k.ss58)).toString("hex")).toBe(k.public_key_hex);
        });
    }
});

async function checkVerify(v: VerifyVector): Promise<void> {
    const verifier = vectorVerifier(v);
    if (v.inputs.prior !== null) {
        await verifier.verify(request(v.inputs.prior));
    }
    const result = verifier.verify(request(v.inputs));
    if (v.expected.valid) {
        const caller = await result;
        expect(caller.hotkey).toBe(v.expected.caller_ss58);
        return;
    }
    const err: unknown = await result.then(
        () => null,
        (e: unknown) => e,
    );
    expect(err, "accepted").toBeInstanceOf(TWError);
    const tw = err as TWError;
    expect({ code: tw.code, status: tw.status }, tw.detail).toEqual({
        code: v.expected.code,
        status: v.expected.status,
    });
}

for (const [name, kind] of [
    ["negative.json", "verify_request"],
    ["sr25519_verify.json", "verify_sr25519"],
    ["ed25519.json", "sign_ed25519"],
] as const) {
    describe(name, () => {
        for (const raw of loadVectors(name).vectors) {
            const v = raw as unknown as VerifyVector;
            it(v.id, async () => {
                expect(v.kind).toBe(kind);
                await checkVerify(v);
                const payload = new TextEncoder().encode(v.inputs.signed_payload_utf8);
                if (kind === "sign_ed25519") {
                    const key = keyBySS58(v.expected.caller_ss58!);
                    expect(signatureHex(key.sign(payload))).toBe(v.expected.signature);
                }
                if (kind === "verify_sr25519") {
                    // Own signatures verify (the Python side is the live interop check).
                    const key = keyBySS58(v.expected.caller_ss58!);
                    expect(verifySignature("sr25519", key.publicKey, payload, key.sign(payload))).toBe(true);
                }
            });
        }
    });
}

interface TwrespVector {
    id: string;
    kind: string;
    inputs: {
        scheme: "sr25519" | "ed25519";
        request_nonce: string;
        sender_ss58: string;
        responder_ss58: string;
        expected_responder: string;
        status: number;
        body_base64: string;
        chunks_base64: string[];
        headers: Record<string, string> | [string, string][];
    };
    expected: {
        valid: boolean;
        error_code: string | null;
        body_sha256: string;
        digest: string;
        count: number;
        payload_utf8: string;
        headers: Record<string, string>;
        signature: string;
    };
}

describe("twresp.json", () => {
    for (const raw of loadVectors("twresp.json").vectors) {
        const v = raw as unknown as TwrespVector;
        it(v.id, () => {
            const { inputs: i, expected: e } = v;
            const binding = {
                requestNonce: BigInt(i.request_nonce),
                sender: i.sender_ss58,
                status: i.status,
            };
            switch (v.kind) {
                case "verify": {
                    const expectation = { ...binding, expectedResponder: i.expected_responder };
                    const run = () => verifyResponse(i.headers, expectation, b64(i.body_base64));
                    if (e.valid) {
                        expect(run).not.toThrow();
                    } else {
                        expect(run).toThrow(expect.objectContaining({ code: e.error_code }) as Error);
                    }
                    break;
                }
                case "stream_ed25519": {
                    const d = new StreamDigest();
                    for (const c of i.chunks_base64) {
                        expect(() => decodeChunk(b64(c))).not.toThrow();
                        d.update(b64(c));
                    }
                    const digest = d.hexdigest();
                    expect(digest).toBe(bodySha256(Buffer.concat(i.chunks_base64.map(b64))));
                    expect(digest).toBe(e.digest);
                    expect(d.count).toBe(e.count);
                    const trailer = { digest, count: BigInt(d.count), signature: e.signature };
                    expect(parseTrailer(encodeTrailer(trailer))).toEqual(trailer);
                    const sb = { ...binding, status: 200 };
                    const payload = responsePayload("ed25519", sb, i.responder_ss58, digest);
                    expect(new TextDecoder().decode(payload)).toBe(e.payload_utf8);
                    const headers = {
                        "X-TW-Resp-Version": "1",
                        "X-TW-Resp-Hotkey": i.responder_ss58,
                        "X-TW-Resp-Crypto": "ed25519",
                        "X-TW-Resp-Signature": e.signature,
                    };
                    expect(
                        verifyResponseDigest(headers, { ...sb, expectedResponder: i.responder_ss58 }, digest),
                    ).toBe("ed25519");
                    const key = keyBySS58(i.responder_ss58);
                    expect(signatureHex(key.sign(payload))).toBe(e.signature);
                    break;
                }
                case "build_sr25519":
                case "sign_ed25519": {
                    const body = b64(i.body_base64);
                    expect(bodySha256(body)).toBe(e.body_sha256);
                    const payload = responsePayload(i.scheme, binding, i.responder_ss58, bodySha256(body));
                    expect(new TextDecoder().decode(payload)).toBe(e.payload_utf8);
                    const expectation = { ...binding, expectedResponder: i.responder_ss58 };
                    expect(verifyResponse(e.headers, expectation, body)).toBe(i.scheme);
                    const own = signResponse(keyBySS58(i.responder_ss58), binding, body);
                    expect(verifyResponse(own, expectation, body)).toBe(i.scheme);
                    if (v.kind === "sign_ed25519") {
                        expect(own["X-TW-Resp-Signature"]).toBe(e.headers["X-TW-Resp-Signature"]);
                    }
                    break;
                }
                default:
                    throw new Error(`unknown twresp vector kind ${v.kind}`);
            }
        });
    }
});
