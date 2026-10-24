// verifyRequest benchmark (spec 11.3 note): `npm run bench` (builds first).
// Pre-signs N requests per scheme with fresh nonces, then times Verifier.verify on
// each (shape → receiver → freshness → signature → replay store), single thread.
import { readFileSync } from "node:fs";
import { cpus } from "node:os";
import { Keypair, MemoryStore, Signer, Verifier, initCrypto } from "@taowire/btauth";

const N = Number(process.env.TW_BENCH_N ?? "5000");
const keys = JSON.parse(
    readFileSync(new URL("../../conformance/vectors/payload.json", import.meta.url), "utf8"),
).keys;
await initCrypto();
const seed = (name) => Buffer.from(keys[name].secret_seed_hex, "hex");
const bob = Keypair.sr25519FromSeed(seed("bob_sr25519"));
const body = Buffer.from('{"prompt": "hello"}');
const target = "/generate?stream=false";

console.log(`node ${process.version}, ${cpus()[0].model}, N=${N} per scheme`);
for (const scheme of ["sr25519", "ed25519"]) {
    const alice = Keypair.fromSeed(scheme, seed(`alice_${scheme}`));
    const signer = new Signer(alice);
    const requests = Array.from({ length: N }, () => ({
        headers: Object.entries(signer.sign("POST", target, body, bob.ss58).headers),
        body,
        method: "POST",
        target,
    }));
    const verifier = new Verifier({ selfHotkey: bob.ss58, store: new MemoryStore(150), maxAgeS: 60 });
    for (const r of requests.slice(0, 200)) await verifier.verify(r); // warm-up (these nonces are then replays)
    const times = [];
    const start = process.hrtime.bigint();
    for (const r of requests.slice(200)) {
        const t = process.hrtime.bigint();
        await verifier.verify(r);
        times.push(Number(process.hrtime.bigint() - t) / 1e3);
    }
    const totalS = Number(process.hrtime.bigint() - start) / 1e9;
    times.sort((a, b) => a - b);
    const q = (p) => times[Math.min(times.length - 1, Math.floor(p * times.length))].toFixed(1);
    console.log(
        `${scheme}: ${(times.length / totalS).toFixed(0)} verifications/s, p50 ${q(0.5)} µs, p99 ${q(0.99)} µs, max ${times.at(-1).toFixed(1)} µs (${times.length} timed)`,
    );
}
