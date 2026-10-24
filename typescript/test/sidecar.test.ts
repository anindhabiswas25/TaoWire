// Sidecar client (spec 11.6, 8.5, 8.5.1) against a fake sidecar: token file,
// loopback URL, wire shapes, caller policy, staleness stages, hostile JSON.
import { chmodSync, mkdirSync, mkdtempSync, writeFileSync } from "node:fs";
import { type IncomingMessage, type ServerResponse, createServer } from "node:http";
import type { AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import fc from "fast-check";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { TWError, initCrypto } from "@tensorwire/btauth";
import {
    CallerPolicy,
    SidecarChainError,
    SidecarClient,
    type SidecarClientOptions,
    type Snapshot,
    hasDuplicateKeys,
    isLoopbackUrl,
    parseCallerDecision,
    parseHealth,
    parseSnapshot,
    readTokenFile,
} from "@tensorwire/btauth/sidecar";
import { devKeys } from "./helpers.js";

beforeAll(initCrypto);

const ALICE = devKeys().alice_sr25519!.ss58;
const BOB = devKeys().bob_sr25519!.ss58;
const CHARLIE = devKeys().alice_ed25519!.ss58;
const TOKEN = "t".repeat(32);
const enc = (o: unknown) => new TextEncoder().encode(typeof o === "string" ? o : JSON.stringify(o));
const dir = mkdtempSync(join(tmpdir(), "tw-sidecar-"));

function neuron(uid: number, hotkey: string, permit: boolean, stake: number) {
    return {
        uid,
        hotkey,
        validator_permit: permit,
        total_stake_tao: stake,
        axon: uid === 0 ? null : "203.0.113.7:8091",
    };
}

function snapshotBody(ageS = 1, tempo = 360, extra: Record<string, unknown> = {}) {
    return {
        netuid: 2,
        block: 100,
        tempo,
        age_s: ageS,
        neurons: [neuron(0, ALICE, true, 1000), neuron(1, BOB, false, 5), neuron(2, CHARLIE, true, 10)],
        ...extra,
    };
}

type Handler = (req: IncomingMessage, body: string) => [number, unknown];
interface Fake {
    url: string;
    handler: Handler;
    seen: { auth: string | undefined; url: string; body: string }[];
}

const servers: ReturnType<typeof createServer>[] = [];
afterAll(async () => {
    for (const s of servers) s.closeAllConnections();
    await Promise.all(servers.map((s) => new Promise((r) => s.close(r))));
});

async function fakeSidecar(handler?: Handler): Promise<Fake> {
    const fake: Fake = {
        url: "",
        seen: [],
        handler:
            handler ??
            ((req) => {
                if (req.url?.startsWith("/v1/health") === true) {
                    return [
                        200,
                        { ok: true, hotkey: BOB, netuid: 2, block: 100, metagraph_age_s: 1, stage: "fresh" },
                    ];
                }
                if (req.url?.startsWith("/v1/metagraph") === true) return [200, snapshotBody()];
                return [404, "nope"];
            }),
    };
    const server = createServer((req: IncomingMessage, res: ServerResponse) => {
        const parts: Buffer[] = [];
        req.on("data", (p: Buffer) => parts.push(p));
        req.on("end", () => {
            const body = Buffer.concat(parts).toString();
            fake.seen.push({ auth: req.headers.authorization, url: req.url ?? "", body });
            if (req.headers.authorization !== `Bearer ${TOKEN}`) {
                res.writeHead(401, { "content-type": "application/json" });
                res.end(enc({ error: { code: "tw.sidecar_unauthorized", message: "x", request_id: null } }));
                return;
            }
            const [status, answer] = fake.handler(req, body);
            res.writeHead(status, { "content-type": "application/json" });
            res.end(answer instanceof Uint8Array ? answer : enc(answer));
        });
    });
    servers.push(server);
    await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
    fake.url = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
    return fake;
}

function client(fake: Fake, extra: Partial<SidecarClientOptions> = {}): SidecarClient {
    return new SidecarClient({ netuid: 2, url: fake.url, token: TOKEN, ...extra });
}

async function code(f: () => unknown): Promise<string> {
    try {
        await f();
        return "ok";
    } catch (err) {
        return err instanceof TWError || err instanceof SidecarChainError ? err.code : String(err);
    }
}

describe("token file and URL", () => {
    it("reads an owner-only token file and refuses anything else", () => {
        const good = join(dir, "good.token");
        writeFileSync(good, `${TOKEN}\n`, { mode: 0o600 });
        expect(readTokenFile(good)).toBe(TOKEN);
        const open = join(dir, "open.token");
        writeFileSync(open, TOKEN, { mode: 0o644 });
        chmodSync(open, 0o644);
        const cases: [string, RegExp][] = [
            [open, /group or others/],
            [join(dir, "missing.token"), /cannot open/],
            [dir, /not a regular file/],
        ];
        for (const [content, name] of [
            ["", "empty"],
            ["short", "short"],
            ["x".repeat(1025), "long"],
            [`${"x".repeat(20)} y`, "space"],
            [`${"x".repeat(20)}é`, "latin1"],
        ] as const) {
            const p = join(dir, `${name}.token`);
            writeFileSync(p, content, { mode: 0o600 });
            cases.push([p, /printable ASCII|too large/]);
        }
        for (const [path, err] of cases) {
            expect(() => readTokenFile(path)).toThrow(err);
            try {
                readTokenFile(path);
            } catch (e) {
                expect(String(e)).not.toContain(TOKEN);
            }
        }
        const sub = join(dir, "sub");
        mkdirSync(sub, { recursive: true });
        const c = new SidecarClient({ netuid: 2, tokenFile: good });
        expect(String(c)).not.toContain(TOKEN);
        expect(JSON.stringify({ c })).not.toContain(TOKEN);
    });

    it("accepts loopback URLs only, unless told otherwise", () => {
        for (const u of [
            "http://127.0.0.1:9910",
            "http://127.0.0.2:1",
            "http://[::1]:9910",
            "http://localhost:9910",
        ]) {
            expect(isLoopbackUrl(new URL(u))).toBe(true);
        }
        for (const u of [
            "http://10.0.0.1:9910",
            "http://example.com",
            "http://127.0.0.1.example.com",
            "http://[::2]",
        ]) {
            expect(isLoopbackUrl(new URL(u))).toBe(false);
            expect(() => new SidecarClient({ netuid: 2, url: u, token: TOKEN })).toThrow(/loopback/);
        }
        expect(
            () =>
                new SidecarClient({
                    netuid: 2,
                    url: "http://10.0.0.1",
                    token: TOKEN,
                    unsafeAllowRemote: true,
                }),
        ).not.toThrow();
        expect(() => new SidecarClient({ netuid: 2, url: "ftp://127.0.0.1", token: TOKEN })).toThrow(/http/);
        expect(() => new SidecarClient({ netuid: -1, token: TOKEN })).toThrow(RangeError);
        expect(() => new SidecarClient({ netuid: 2, token: "short" })).toThrow(/printable/);
        expect(() => new SidecarClient({ netuid: 2, token: TOKEN, softAgeS: 10, maxAgeS: 5 })).toThrow(
            RangeError,
        );
        expect(() => new SidecarClient({ netuid: 2, token: TOKEN, refreshS: 0 })).toThrow(RangeError);
        const saved = process.env.TW_SIDECAR_TOKEN_FILE;
        delete process.env.TW_SIDECAR_TOKEN_FILE;
        expect(() => new SidecarClient({ netuid: 2 })).toThrow(/tokenFile/);
        if (saved !== undefined) process.env.TW_SIDECAR_TOKEN_FILE = saved;
    });
});

describe("caller policy", () => {
    const snap = parseSnapshot(enc(snapshotBody()), 2);
    it("follows the Python order", () => {
        const strict = new CallerPolicy();
        expect(strict.check(ALICE, snap)?.uid).toBe(0);
        expect(() => strict.check(BOB, snap)).toThrow(
            expect.objectContaining({ code: "tw.forbidden_not_validator" }) as Error,
        );
        const unknown = "5DAAnrj7VHTznn2AWBemMuyBwZWs6FNFjdyVXUeYum3PTXFy";
        expect(() => strict.check(unknown, snap)).toThrow(
            expect.objectContaining({ code: "tw.forbidden_not_registered" }) as Error,
        );
        expect(new CallerPolicy({ requirePermit: false }).check(BOB, snap)?.uid).toBe(1);
        const staked = new CallerPolicy({ minStakeTao: 100 });
        expect(() => staked.check(CHARLIE, snap)).toThrow(
            expect.objectContaining({ code: "tw.forbidden_low_stake" }) as Error,
        );
        expect(staked.check(ALICE, snap)?.uid).toBe(0);
        const lists = new CallerPolicy({ allowHotkeys: [unknown], denyHotkeys: [ALICE] });
        expect(lists.check(unknown, snap)).toBeNull();
        expect(() => lists.check(ALICE, snap)).toThrow(
            expect.objectContaining({ code: "tw.forbidden_denied", status: 403 }) as Error,
        );
        expect(() => new CallerPolicy({ minStakeTao: -1 })).toThrow(RangeError);
        expect(() => new CallerPolicy({ minStakeTao: Number.NaN })).toThrow(RangeError);
        expect(() => new CallerPolicy({ allowHotkeys: [ALICE], denyHotkeys: [ALICE] })).toThrow(RangeError);
    });
});

describe("sidecar calls", () => {
    it("sends the bearer token and maps a 401", async () => {
        const fake = await fakeSidecar();
        const c = client(fake);
        await c.start();
        c.stop();
        expect(fake.seen.every((s) => s.auth === `Bearer ${TOKEN}`)).toBe(true);
        expect(fake.seen.map((s) => s.url)).toEqual(["/v1/health", "/v1/metagraph?netuid=2"]);
        const wrong = new SidecarClient({ netuid: 2, url: fake.url, token: "w".repeat(32) });
        expect(await code(() => wrong.health())).toBe("tw.sidecar_unauthorized");
    });

    it("checks the sidecar's netuid and hotkey at start", async () => {
        const fake = await fakeSidecar();
        expect(await code(() => client(fake, { expectedHotkey: ALICE }).start())).toMatch(/hotkey/);
        expect(await code(() => client(fake, { expectedHotkey: BOB }).start())).toBe("ok");
        expect(
            await code(() => new SidecarClient({ netuid: 3, url: fake.url, token: TOKEN }).start()),
        ).toMatch(/netuid/);
    });

    it("asks the sidecar's own decision", async () => {
        const answers: unknown[] = [{ allowed: true }, { allowed: false, code: "tw.forbidden_low_stake" }];
        const fake = await fakeSidecar(() => [200, answers.shift()]);
        const c = client(fake);
        expect(await c.caller(ALICE)).toEqual({ allowed: true });
        expect(await c.caller("a/b")).toEqual({ allowed: false, code: "tw.forbidden_low_stake" });
        expect(fake.seen[1]?.url).toBe("/v1/caller/a%2Fb?netuid=2");
    });

    it("publishes the axon once and maps chain refusals", async () => {
        const hash = `0x${"ab".repeat(32)}`;
        const answers: [number, unknown][] = [
            [200, { ok: true, block_hash: hash }],
            [409, { ok: false, code: "rate_limited", error_name: null, remediation: "wait 50 blocks" }],
            [503, { ok: false, code: "chain_unavailable" }],
            [422, { error: { code: "tw.invalid_request", message: "x", request_id: null } }],
            [200, { ok: true, block_hash: "0x12" }],
            [409, "garbage"],
        ];
        const fake = await fakeSidecar(() => answers.shift() ?? [500, ""]);
        const c = client(fake);
        expect(await c.serveAxon({ ip: "203.0.113.7", port: 8091 })).toBe(hash);
        expect(JSON.parse(fake.seen[0]?.body ?? "")).toEqual({
            netuid: 2,
            ip: "203.0.113.7",
            port: 8091,
            tls_cert_hex: null,
        });
        try {
            await c.serveAxon({ ip: "203.0.113.7", port: 8091, tlsCertHex: "0x01ab" });
        } catch (err) {
            expect(err).toBeInstanceOf(SidecarChainError);
            expect((err as SidecarChainError).remediation).toBe("wait 50 blocks");
        }
        expect(await code(() => c.serveAxon({ ip: "x", port: 1 }))).toBe("chain_unavailable");
        expect(await code(() => c.serveAxon({ ip: "x", port: 1 }))).toBe("tw.invalid_request");
        expect(await code(() => c.serveAxon({ ip: "x", port: 1 }))).toBe("tw.invalid_response");
        expect(await code(() => c.serveAxon({ ip: "x", port: 1 }))).toBe("tw.invalid_response");
        expect(fake.seen).toHaveLength(6); // never resent
    });

    it("maps transport failures", async () => {
        const dead = new SidecarClient({ netuid: 2, url: "http://127.0.0.1:1", token: TOKEN });
        expect(await code(() => dead.health())).toBe("tw.connect_error");
        const slowServer = createServer(() => {
            // never answers
        });
        servers.push(slowServer);
        await new Promise<void>((r) => slowServer.listen(0, "127.0.0.1", r));
        const url = `http://127.0.0.1:${(slowServer.address() as AddressInfo).port}`;
        expect(
            await code(() => new SidecarClient({ netuid: 2, url, token: TOKEN, timeoutMs: 200 }).health()),
        ).toBe("tw.timeout");
        const big = await fakeSidecar(() => [200, enc(`{"x":"${"a".repeat(33 * 1024 * 1024)}"}`)]);
        expect(await code(() => client(big).health())).toBe("tw.response_too_large");
        const stale = await fakeSidecar(() => [
            503,
            { error: { code: "tw.metagraph_stale", message: "x", request_id: null } },
        ]);
        expect(await code(() => client(stale).metagraph())).toBe("tw.metagraph_stale");
        const liar = await fakeSidecar(() => [
            503,
            { error: { code: "tw.forbidden_denied", message: "x", request_id: null } },
        ]);
        expect(await code(() => client(liar).metagraph())).toBe("tw.invalid_response");
    });
});

describe("staleness stages (8.5.1) and known callers", () => {
    function clocked(ageS: number, extra: Partial<SidecarClientOptions> = {}) {
        let now = 1_000_000;
        let age = ageS;
        let fail = false;
        const holder = {
            advance: (s: number) => {
                now += s * 1000;
            },
            setAge: (s: number) => {
                age = s;
            },
            setFail: (f: boolean) => {
                fail = f;
            },
        };
        return fakeSidecar((req) => {
            if (fail) return [500, "down"];
            if (req.url?.startsWith("/v1/health") === true) {
                return [
                    200,
                    { ok: true, hotkey: BOB, netuid: 2, block: 1, metagraph_age_s: age, stage: "fresh" },
                ];
            }
            return [200, snapshotBody(age, 10)];
        }).then((fake) => ({ c: client(fake, { monotonicMs: () => now, ...extra }), ...holder }));
    }

    it("judges the reported age against the tempo", async () => {
        // tempo 10: max age 240 s, soft age 120 s
        const t = await clocked(5);
        expect(t.c.stage()).toBe("known_callers_only"); // no snapshot: fail closed
        expect(await code(() => t.c.check(ALICE))).toBe("tw.metagraph_stale");
        await t.c.metagraph();
        expect(t.c.thresholds()).toEqual([120, 240]);
        expect(t.c.stage()).toBe("fresh");
        expect(t.c.check(ALICE, "/r")?.uid).toBe(0);
        t.advance(115);
        expect(t.c.stage()).toBe("degraded");
        t.advance(120);
        expect(t.c.stage()).toBe("degraded"); // exactly the max age is degraded
        t.advance(1);
        expect(t.c.stage()).toBe("known_callers_only");
        expect(t.c.check(ALICE, "/r")?.uid).toBe(0); // known on this route
        expect(await code(() => t.c.check(ALICE, "/other"))).toBe("tw.metagraph_stale");
        expect(await code(() => t.c.check(CHARLIE, "/r"))).toBe("tw.metagraph_stale");
        // The sidecar repeats its own stale snapshot: nothing is cleared.
        t.setAge(241);
        await t.c.metagraph();
        expect(t.c.check(ALICE, "/r")?.uid).toBe(0);
        // The same snapshot answered 3 s late (a slow sidecar) is not newer.
        t.setAge(238);
        await t.c.metagraph();
        expect(t.c.check(ALICE, "/r")?.uid).toBe(0);
        // A failed refresh keeps the snapshot (and its age).
        t.setFail(true);
        expect(await code(() => t.c.metagraph())).toBe("tw.invalid_response");
        expect(t.c.snapshot()).not.toBeNull();
        // A newer snapshot clears the known callers and decides again.
        t.setFail(false);
        t.setAge(0);
        await t.c.metagraph();
        expect(t.c.stage()).toBe("fresh");
        expect(t.c.ageS()).toBe(0);
        expect(await code(() => t.c.check(BOB, "/r"))).toBe("tw.forbidden_not_validator");
    });

    it("strict refuses everyone past the max age; deny always wins", async () => {
        const t = await clocked(0, { strict: true, maxAgeS: 50, softAgeS: 10 });
        await t.c.metagraph();
        expect(t.c.check(ALICE)?.uid).toBe(0);
        t.advance(60);
        expect(await code(() => t.c.check(ALICE))).toBe("tw.metagraph_stale");
        const denied = await clocked(0, { policy: new CallerPolicy({ denyHotkeys: [ALICE] }) });
        expect(await code(() => denied.c.check(ALICE))).toBe("tw.forbidden_denied");
    });

    it("refreshes in the background and stops", async () => {
        const fake = await fakeSidecar();
        const c = client(fake, { refreshS: 0.05 });
        await c.start();
        await c.start(); // replaces, never adds a refresh loop
        await new Promise((r) => setTimeout(r, 300));
        c.stop();
        const n = fake.seen.length;
        expect(n).toBeGreaterThan(3);
        await new Promise((r) => setTimeout(r, 150));
        expect(fake.seen.length).toBe(n);
        const hook = c.policyHook();
        expect(() => {
            hook({ hotkey: ALICE }, { routeOptions: { url: "/v1/x" } });
        }).not.toThrow();
        expect(() => {
            hook({ hotkey: BOB }, { routeOptions: {} });
        }).toThrow(TWError);
    });
});

describe("hostile answers fail closed", () => {
    const valid = snapshotBody();
    const mutations: [string, unknown][] = [
        ["netuid", { ...valid, netuid: 3 }],
        ["netuid string", { ...valid, netuid: "2" }],
        ["block", { ...valid, block: -1 }],
        ["block float", { ...valid, block: 1.5 }],
        ["tempo", { ...valid, tempo: 0 }],
        ["age", { ...valid, age_s: -1 }],
        ["age string", { ...valid, age_s: "1" }],
        ["neurons", { ...valid, neurons: {} }],
        ["neuron null", { ...valid, neurons: [null] }],
        ["uid dup", { ...valid, neurons: [neuron(0, ALICE, true, 1), neuron(0, BOB, true, 1)] }],
        ["hotkey dup", { ...valid, neurons: [neuron(0, ALICE, true, 1), neuron(1, ALICE, true, 1)] }],
        ["hotkey bad", { ...valid, neurons: [neuron(0, "5Grw", true, 1)] }],
        ["permit", { ...valid, neurons: [{ ...neuron(0, ALICE, true, 1), validator_permit: 1 }] }],
        ["stake", { ...valid, neurons: [{ ...neuron(0, ALICE, true, 1), total_stake_tao: -5 }] }],
        ["stake string", { ...valid, neurons: [{ ...neuron(0, ALICE, true, 1), total_stake_tao: "1e9" }] }],
        ["axon", { ...valid, neurons: [{ ...neuron(0, ALICE, true, 1), axon: 5 }] }],
        ["array", [valid]],
    ];

    it("rejects every malformed snapshot whole", () => {
        for (const [name, body] of mutations) {
            expect(() => parseSnapshot(enc(body), 2), name).toThrow(
                expect.objectContaining({ code: "tw.invalid_response" }) as Error,
            );
        }
        expect(() =>
            parseSnapshot(enc(JSON.stringify(valid).replace('"block":100', '"block":100,"block":101')), 2),
        ).toThrow();
        expect(() => parseSnapshot(Uint8Array.of(0xff), 2)).toThrow();
        expect(parseSnapshot(enc(valid), 2).neurons).toHaveLength(3);
    });

    it("allows only exactly {allowed: true}", () => {
        expect(parseCallerDecision(enc({ allowed: true }))).toEqual({ allowed: true });
        for (const body of [
            { allowed: "true" },
            { allowed: 1 },
            { allowed: true, code: "tw.forbidden_denied" },
            { allowed: false },
            { allowed: false, code: "tw.ok" },
            '{"allowed":false,"allowed":true}',
            "[true]",
        ]) {
            expect(() => parseCallerDecision(enc(body)), JSON.stringify(body)).toThrow();
        }
    });

    it("parses health strictly", () => {
        const h = {
            ok: true,
            hotkey: BOB,
            netuid: 2,
            block: null,
            metagraph_age_s: null,
            stage: "known_callers_only",
        };
        expect(parseHealth(enc(h)).block).toBeNull();
        for (const body of [
            { ...h, ok: "yes" },
            { ...h, hotkey: "x" },
            { ...h, stage: "stale" },
            { ...h, block: -1 },
            { ...h, metagraph_age_s: -1 },
        ]) {
            expect(() => parseHealth(enc(body))).toThrow();
        }
    });

    it("finds duplicate keys at any depth", () => {
        expect(hasDuplicateKeys('{"a":1,"b":{"c":[{"d":1,"e":"\\"d\\""}]}}')).toBe(false);
        expect(hasDuplicateKeys('{"a":{"x":1,"x":2}}')).toBe(true);
        expect(hasDuplicateKeys('[{"a":1},{"a":1}]')).toBe(false);
        expect(hasDuplicateKeys('{"a":1,"\\u0061":2}')).toBe(true);
    });

    it("arbitrary JSON never admits a caller (property)", () => {
        const answer = fc.oneof(
            fc.json().map((t) => enc(t)),
            fc.uint8Array({ maxLength: 200 }),
            fc
                .record({
                    netuid: fc.oneof(fc.constant(2), fc.anything()),
                    block: fc.oneof(fc.nat(), fc.anything()),
                    tempo: fc.oneof(fc.integer({ min: 1, max: 100 }), fc.anything()),
                    age_s: fc.oneof(fc.double(), fc.anything()),
                    neurons: fc.array(
                        fc.record({
                            uid: fc.oneof(fc.nat(10), fc.anything()),
                            hotkey: fc.oneof(fc.constant(ALICE), fc.string()),
                            validator_permit: fc.oneof(fc.boolean(), fc.anything()),
                            total_stake_tao: fc.oneof(fc.double(), fc.anything()),
                            axon: fc.oneof(fc.constant(null), fc.anything()),
                        }),
                    ),
                })
                .map((o) => enc(o)),
        );
        fc.assert(
            fc.property(answer, (body) => {
                let snap: Snapshot;
                try {
                    snap = parseSnapshot(body, 2);
                } catch (err) {
                    return err instanceof TWError && err.code === "tw.invalid_response";
                }
                // Accepted: it must really be well formed, and admit only a real permit holder.
                const n = snap.byHotkey.get(ALICE);
                let admitted = true;
                try {
                    new CallerPolicy().check(ALICE, snap);
                } catch {
                    admitted = false;
                }
                return admitted === (n !== undefined && n.validatorPermit);
            }),
            { numRuns: 2000 },
        );
        fc.assert(
            fc.property(
                fc.oneof(
                    fc.json().map((t) => enc(t)),
                    fc.uint8Array({ maxLength: 64 }),
                ),
                (body) => {
                    try {
                        return parseCallerDecision(body).allowed
                            ? Buffer.from(body).toString().replace(/\s/g, "") === '{"allowed":true}'
                            : true;
                    } catch {
                        return true;
                    }
                },
            ),
            { numRuns: 2000 },
        );
    });
});
