// Shared test helpers: the conformance vectors (spec 11.7) and the pinned dev keys.
import { readFileSync, readdirSync } from "node:fs";
import { Keypair, MemoryStore, type Scheme, Verifier } from "@tensorwire/btauth";

export const VECTORS_DIR = new URL("../../conformance/vectors/", import.meta.url);

export interface VectorFile {
    schema_version: number;
    keys: Record<string, unknown>;
    vectors: Record<string, unknown>[];
}

export function loadVectors(name: string): VectorFile {
    const file = JSON.parse(readFileSync(new URL(name, VECTORS_DIR), "utf8")) as VectorFile;
    if (file.schema_version !== 1 || file.vectors.length === 0) {
        throw new Error(`${name}: schema ${file.schema_version}, ${file.vectors.length} vectors`);
    }
    return file;
}

export function vectorFiles(): string[] {
    return readdirSync(VECTORS_DIR)
        .filter((f) => f.endsWith(".json"))
        .sort();
}

export interface DevKey {
    uri: string;
    scheme: Scheme;
    secret_seed_hex: string;
    public_key_hex: string;
    ss58: string;
}

export function devKeys(): Record<string, DevKey> {
    return loadVectors("payload.json").keys as unknown as Record<string, DevKey>;
}

export function keypair(name: "alice_sr25519" | "bob_sr25519" | "alice_ed25519" | "bob_ed25519"): Keypair {
    const k = devKeys()[name]!;
    return Keypair.fromSeed(k.scheme, Buffer.from(k.secret_seed_hex, "hex"));
}

export function keyBySS58(ss58: string): Keypair {
    const k = Object.values(devKeys()).find((d) => d.ss58 === ss58);
    if (k === undefined) {
        throw new Error(`no dev key ${ss58}`);
    }
    return Keypair.fromSeed(k.scheme, Buffer.from(k.secret_seed_hex, "hex"));
}

export const b64 = (s: string): Uint8Array => Buffer.from(s, "base64");

export interface WireRequest {
    method: string;
    target: string;
    body_base64: string;
    headers: [string, string][];
}

export interface VerifyVector {
    id: string;
    kind: string;
    description: string;
    inputs: WireRequest & {
        self_hotkey: string;
        now_ns: string;
        max_age_s: number;
        allowed_skew_s: number;
        prior: WireRequest | null;
        key?: string;
        signed_payload_utf8: string;
    };
    expected: {
        valid: boolean;
        code: string | null;
        status: number | null;
        caller_ss58: string | null;
        signature?: string;
    };
}

/** A verifier for one vector: its clock, window and a fresh memory store. */
export function vectorVerifier(v: VerifyVector): Verifier {
    const now = BigInt(v.inputs.now_ns);
    return new Verifier({
        selfHotkey: v.inputs.self_hotkey,
        store: new MemoryStore(60),
        maxAgeS: v.inputs.max_age_s,
        allowedSkewS: v.inputs.allowed_skew_s,
        nowNs: () => now,
    });
}

export function request(w: WireRequest) {
    return { headers: w.headers, body: b64(w.body_base64), method: w.method, target: w.target };
}
