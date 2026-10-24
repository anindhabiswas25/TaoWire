// Properties of the untrusted-input parsers (definition of done item 5), shared by
// property.test.ts (fixed run count) and fuzz.test.ts (time-boxed, TW_FUZZ_SECONDS).
import fc from "fast-check";
import {
    ChunkError,
    MemoryStore,
    SSEParser,
    TrailerError,
    decodeChunk,
    encodeTrailer,
    parseTrailer,
    SS58Error,
    Signer,
    TWError,
    Verifier,
    decodeSS58,
    verifyResponse,
} from "@tensorwire/btauth";
import { keypair } from "./helpers.js";

const AUTH_CODES = new Set([
    "tw.auth_malformed",
    "tw.auth_wrong_receiver",
    "tw.auth_stale",
    "tw.auth_bad_signature",
    "tw.auth_replayed",
]);

const NAMES = [
    "X-Bittensor-Version",
    "X-Bittensor-Hotkey",
    "X-Bittensor-Receiver",
    "X-Bittensor-Nonce",
    "X-Bittensor-Crypto",
    "X-Bittensor-Signature",
    "x-bittensor-signature",
    "X-BITTENSOR-NONCE",
    "Content-Type",
];

const T0 = 1_752_076_800_000_000_000n;

let cached: { bob: ReturnType<typeof keypair>; headers: [string, string][]; body: Uint8Array } | null = null;

function golden() {
    cached ??= signGolden();
    return {
        bob: cached.bob,
        headers: cached.headers.map(([n, v]) => [n, v] as [string, string]),
        body: cached.body,
    };
}

function signGolden() {
    const bob = keypair("bob_sr25519");
    const signer = new Signer(keypair("alice_sr25519"), { next: () => T0 } as never);
    const body = new TextEncoder().encode('{"prompt": "hello"}');
    const { headers } = signer.sign("POST", "/generate?stream=false", body, bob.ss58);
    return { bob, headers: Object.entries(headers), body };
}

function verifier(self: string): Verifier {
    return new Verifier({ selfHotkey: self, store: new MemoryStore(60), nowNs: () => T0 });
}

async function refusedWithAuthCode(p: Promise<unknown>): Promise<boolean> {
    try {
        await p;
        return false;
    } catch (err) {
        return err instanceof TWError && AUTH_CODES.has(err.code) && err.status === 401;
    }
}

const value = fc.oneof(
    fc.string({ maxLength: 200 }),
    fc.string({ unit: "binary", maxLength: 200 }),
    fc.constantFrom("1", "", "0x", "ed25519", "sr25519", "1752076800000000000", "99999999999999999999"),
);

/** Arbitrary header lists never get in, and every refusal is a 401 auth code. */
export const arbitraryHeaders = fc.asyncProperty(
    fc.array(fc.tuple(fc.oneof(fc.constantFrom(...NAMES), fc.string({ maxLength: 30 })), value), {
        maxLength: 12,
    }),
    fc.uint8Array({ maxLength: 256 }),
    fc.string({ maxLength: 64 }),
    async (headers, body, target) => {
        const { bob } = golden();
        return refusedWithAuthCode(verifier(bob.ss58).verify({ headers, body, method: "POST", target }));
    },
);

/** Changing any one header value, the body, the method or the target of a valid request refuses it. */
export const mutatedGolden = fc.asyncProperty(
    fc.nat(),
    value,
    fc.uint8Array({ minLength: 1, maxLength: 16 }),
    fc.constantFrom("header", "body", "method", "target", "drop", "duplicate"),
    async (which, newValue, extra, part) => {
        const { bob, headers, body } = golden();
        const i = which % headers.length;
        let h = headers.map(([n, v]) => [n, v] as [string, string]);
        let b = body;
        let method = "POST";
        let target = "/generate?stream=false";
        const original = h[i]![1];
        switch (part) {
            case "header":
                if (
                    newValue === original ||
                    (h[i]![0] === "X-Bittensor-Signature" && newValue.toLowerCase() === original.slice(2))
                ) {
                    return true;
                }
                h[i] = [h[i]![0], newValue];
                break;
            case "body":
                b = new Uint8Array([...body, ...extra]);
                break;
            case "method":
                method = "PUT";
                break;
            case "target":
                target = `${target}&${extra[0] ?? 0}`;
                break;
            case "drop":
                h = h.filter((_, j) => j !== i);
                break;
            case "duplicate":
                h.push([h[i]![0].toUpperCase(), h[i]![1]]);
                break;
        }
        // nonce rewrites with a leading zero keep the same number and stay valid (A8)
        if (
            part === "header" &&
            h[i]![0] === "X-Bittensor-Nonce" &&
            /^0+1752076800000000000$/.test(newValue)
        ) {
            return true;
        }
        return refusedWithAuthCode(verifier(bob.ss58).verify({ headers: h, body: b, method, target }));
    },
);

/** SS58 decoding of arbitrary strings throws SS58Error or returns 32 bytes. */
export const ss58Decode = fc.property(
    fc.oneof(
        fc.string({ maxLength: 60 }),
        fc.string({ minLength: 48, maxLength: 48 }),
        fc.base64String({ maxLength: 60 }),
    ),
    (s) => {
        try {
            return decodeSS58(s).length === 32;
        } catch (err) {
            return err instanceof SS58Error;
        }
    },
);

/** twresp/1 verification of arbitrary headers fails closed with tw.bad_response_signature. */
export const twrespHeaders = fc.property(
    fc.array(
        fc.tuple(
            fc.constantFrom(
                "X-TW-Resp-Version",
                "X-TW-Resp-Hotkey",
                "X-TW-Resp-Crypto",
                "X-TW-Resp-Signature",
                "x-tw-resp-signature",
            ),
            value,
        ),
        { maxLength: 8 },
    ),
    fc.uint8Array({ maxLength: 64 }),
    (headers, body) => {
        const { bob } = golden();
        try {
            verifyResponse(
                headers,
                { expectedResponder: bob.ss58, requestNonce: T0, sender: bob.ss58, status: 200 },
                body,
            );
            return false;
        } catch (err) {
            return err instanceof TWError && err.code === "tw.bad_response_signature";
        }
    },
);

const sseToken = fc.oneof(
    fc.constantFrom(
        "event: chunk",
        "event: tw-end",
        "data: ",
        "data:",
        ":",
        " ",
        "\n",
        "\r",
        "\r\n",
        "\ufeff",
        "id: 1",
        '{"a":1}',
    ),
    fc.string(),
);
const sseInput = fc
    .array(sseToken, { maxLength: 40 })
    .map((parts) => new TextEncoder().encode(parts.join("")));
const sseBytes = fc.oneof(sseInput, fc.uint8Array({ maxLength: 512 }));

function eventsOf(p: SSEParser, pieces: Uint8Array[]): string {
    const out = pieces.flatMap((piece) => p.feed(piece));
    out.push(...p.finish());
    return JSON.stringify(out.map((e) => [e.event, Buffer.from(e.data).toString("hex")]));
}

/** SSE parser (spec 9.2): never throws, and any split gives the same events. */
export const sseSplits = fc.property(sseBytes, fc.nat(), (input, cut) => {
    const at = cut % (input.length + 1);
    const whole = eventsOf(new SSEParser(), [input]);
    const split = eventsOf(new SSEParser(), [input.subarray(0, at), input.subarray(at)]);
    const bytewise = eventsOf(
        new SSEParser(),
        Array.from(input, (b) => Uint8Array.of(b)),
    );
    return whole === split && whole === bytewise;
});

const jsonish = fc.oneof(
    fc.json().map((t) => new TextEncoder().encode(t)),
    fc.uint8Array({ maxLength: 256 }),
    fc
        .record(
            {
                digest: fc.oneof(fc.stringMatching(/^[0-9a-f]{64}$/), fc.string()),
                count: fc.oneof(fc.bigInt(), fc.double(), fc.boolean()),
                signature: fc.string(),
            },
            { requiredKeys: [] },
        )
        .map((o) =>
            new TextEncoder().encode(
                JSON.stringify(o, (_k, v: unknown) => (typeof v === "bigint" ? Number(v) : v)),
            ),
        ),
);

/** tw-end parser: arbitrary data is a well-formed trailer that re-encodes to itself, or a TrailerError. */
export const trailerParse = fc.property(jsonish, (data) => {
    let t;
    try {
        t = parseTrailer(data);
    } catch (err) {
        return err instanceof TrailerError;
    }
    const again = parseTrailer(encodeTrailer(t));
    return (
        /^[0-9a-f]{64}$/.test(t.digest) &&
        again.digest === t.digest &&
        again.count === t.count &&
        again.signature === t.signature
    );
});

/** Chunk decoder (D35): arbitrary data is an object / array or a ChunkError, never anything else. */
export const chunkDecode = fc.property(jsonish, (data) => {
    try {
        const v = decodeChunk(data);
        return typeof v === "object" && v !== null;
    } catch (err) {
        return err instanceof ChunkError;
    }
});
