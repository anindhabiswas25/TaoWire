// The weak-key table of src/keys.ts against the field arithmetic of Python's
// crypto.is_weak_public_key (ADR-0010), ported here as the reference.
import fc from "fast-check";
import { describe, expect, it } from "vitest";
import { isWeakPublicKey } from "@tensorwire/btauth";

const P = 2n ** 255n - 19n;
const mod = (a: bigint): bigint => ((a % P) + P) % P;
function pow(base: bigint, exponent: bigint): bigint {
    let result = 1n;
    let b = mod(base);
    for (let e = exponent; e > 0n; e >>= 1n) {
        if (e & 1n) result = (result * b) % P;
        b = (b * b) % P;
    }
    return result;
}
const inv = (a: bigint): bigint => pow(a, P - 2n);
const D = mod(-121665n * inv(121666n));
const SQRT_M1 = pow(2n, (P - 1n) / 4n);

function add([x1, y1]: [bigint, bigint], [x2, y2]: [bigint, bigint]): [bigint, bigint] {
    const t = mod(D * x1 * x2 * y1 * y2);
    return [mod((x1 * y2 + y1 * x2) * inv(1n + t)), mod((y1 * y2 + x1 * x2) * inv(1n - t))];
}

/** crypto.is_weak_public_key, line by line. */
function reference(key: Uint8Array): boolean {
    let n = 0n;
    for (let i = 31; i >= 0; i--) n = (n << 8n) | BigInt(key[i]!);
    const y = n & ((1n << 255n) - 1n);
    const u = mod((y * y - 1n) * inv(D * y * y + 1n));
    let x = pow(u, (P + 3n) / 8n);
    if (mod(x * x) !== u) {
        x = mod(x * SQRT_M1);
        if (mod(x * x) !== u) return false;
    }
    let point: [bigint, bigint] = [x, mod(y)];
    for (let i = 0; i < 3; i++) point = add(point, point);
    return point[0] === 0n && point[1] === 1n;
}

const bytesOf = (y: bigint, sign: boolean): Uint8Array => {
    const out = new Uint8Array(32);
    let v = y | (sign ? 1n << 255n : 0n);
    for (let i = 0; i < 32; i++) {
        out[i] = Number(v & 0xffn);
        v >>= 8n;
    }
    return out;
};

describe("weak ed25519 keys", () => {
    it("the table is exactly the reference's weak set over every candidate encoding", () => {
        // y in 0..18 (and their non-canonical y + p), y = p - 1, and the order-8 y values
        const order8 = [
            "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
            "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
        ].map((h) => {
            let n = 0n;
            const b = Buffer.from(h, "hex");
            for (let i = 31; i >= 0; i--) n = (n << 8n) | BigInt(b[i]!);
            return n & ((1n << 255n) - 1n);
        });
        const ys = [
            ...Array.from({ length: 19 }, (_, i) => BigInt(i)),
            ...Array.from({ length: 19 }, (_, i) => P + BigInt(i)),
            P - 1n,
            ...order8,
        ];
        let weak = 0;
        for (const y of ys) {
            for (const sign of [false, true]) {
                const key = bytesOf(y, sign);
                expect(isWeakPublicKey("ed25519", key), Buffer.from(key).toString("hex")).toBe(
                    reference(key),
                );
                weak += reference(key) ? 1 : 0;
            }
        }
        expect(weak).toBe(14);
    });

    it("random keys agree with the reference", () => {
        fc.assert(
            fc.property(
                fc.uint8Array({ minLength: 32, maxLength: 32 }),
                (key) => isWeakPublicKey("ed25519", key) === reference(key),
            ),
            { numRuns: 300 },
        );
    });
});
