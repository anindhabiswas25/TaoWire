// Smoke test of an INSTALLED @taowire/btauth (spec 18.4 item 6; release dry run
// R4). Copy it into a project that installed the packed tarball and run it from
// there, so the imports resolve to the installed package. Every entry point
// loads through import (ESM build) and require (CommonJS build); Appendix C's
// ed25519 signature is reproduced exactly; in both builds an sr25519 request
// signed by //Alice verifies for //Bob and its replay is refused.
// Public dev keys only.
import assert from "node:assert/strict";
import { createRequire } from "node:module";

const require = createRequire(import.meta.url);
const esm = await import("@taowire/btauth");
const cjs = require("@taowire/btauth");
for (const sub of ["fastify", "redis", "sidecar"]) {
    await import(`@taowire/btauth/${sub}`);
    require(`@taowire/btauth/${sub}`);
}

const hex = (s) => Uint8Array.from(Buffer.from(s, "hex"));
const body = Buffer.from('{"prompt": "hello"}');
const ALICE_SR = "e5be9a5092b81bca64be81d212e7f2f9eba183bb7a90954f7b76361f6edb5c0a";
const ALICE_ED = "abf8e5bdbe30c65656c0a3cbd181ff8a56294a69dfedd27982aace4a76909115";
const BOB_SR = "398f0c28f98885e046333d4a41c19cee4c37368a9832c6502f6cfd182e2aef89";

for (const [build, api] of [
    ["esm", esm],
    ["cjs", cjs],
]) {
    await api.initCrypto();
    const bob = api.Keypair.fromSeed("sr25519", hex(BOB_SR));

    // Appendix C, ed25519 //Alice -> //Bob: the signature is deterministic.
    const aliceEd = api.Keypair.fromSeed("ed25519", hex(ALICE_ED));
    const payload = api.buildPayload({
        scheme: "ed25519",
        method: "POST",
        target: "/generate?stream=false",
        body,
        nonceNs: 1752076800000000000n,
        sender: aliceEd.ss58,
        receiver: bob.ss58,
    });
    assert.equal(
        api.signatureHex(aliceEd.sign(payload)),
        "0x1a6b631988bf1f7ea093ab9d5acf61f05c316d0b0e428b24b487b75a5f6ee0e1a56a26918fdf871b6cf09437e6588023a4ce423cf622621b2a7feee17612f704",
        build,
    );

    // sr25519 round trip through the public Signer and Verifier, then a replay.
    const alice = api.Keypair.fromSeed("sr25519", hex(ALICE_SR));
    const signed = new api.Signer(alice).sign("POST", "/v1/echo", body, bob.ss58);
    const verifier = new api.Verifier({ selfHotkey: bob.ss58, store: new api.MemoryStore(60) });
    const request = { headers: signed.headers, body, method: "POST", target: "/v1/echo" };
    assert.equal((await verifier.verify(request)).hotkey, alice.ss58, build);
    await assert.rejects(verifier.verify(request), (err) => err.code === "tw.auth_replayed", build);
}
console.log(
    "ok: installed @taowire/btauth (ESM + CJS, 4 entry points, Appendix C, sr25519 round trip, replay)",
);
