// All landing-page copy lives here. Every number and claim comes from the
// repository (README.md, docs/, the CLI source): update it there first.

export const VERSION = "0.1.0a2";
export const REPO = "https://github.com/anindhabiswas25/TaoWire";
export const doc = (path: string) => `${REPO}/blob/main/${path}`;

export const nav = [
  { id: "pipeline", label: "Pipeline" },
  { id: "modules", label: "Modules" },
  { id: "commands", label: "Commands" },
  { id: "install", label: "Install" },
  { id: "tested", label: "Tested" },
];

export const hero = {
  eyebrow: "Secure wire for Bittensor v11 subnets",
  lead:
    "Bittensor v11 removed Axon, Dendrite and Synapse. TaoWire is the networking layer every subnet now needs: built once, tested hard and secure by default. You write your subnet's task; TaoWire carries it.",
  featured: {
    title: "TaoWire",
    tags: ["New", `Alpha ${VERSION}`],
    body:
      "Signed HTTP miner server, validator client and scoring loop, and a migration path from v10. Python reference, with TypeScript, Go and Rust btauth libraries.",
    stats: [
      { value: 2163, format: "int", label: "Verified req/s" },
      { value: 0.46, format: "ms", label: "Auth p50" },
      { value: 0.45, format: "s", label: "256-miner fan-out" },
      { value: 4, format: "int", label: "Languages" },
    ],
  },
  installCmd: `pip install "taowire[all]==${VERSION}"`,
  alpha:
    "Alpha: not security-reviewed yet and APIs may change. Use it on localnet and testnet, not to protect mainnet value.",
};

export const ticker = [
  "btauth/1 signed requests",
  "twresp/1 signed answers",
  "Redis replay store",
  "caller policy: registered / permit / stake",
  "per-hotkey rate limits",
  "SSE streaming with a signed trailer",
  "fail-closed metagraph cache",
  "commit-reveal weights via drand",
  "v10 compat layer and two-way bridge",
  "Python · TypeScript · Go · Rust",
];

export const why = {
  title: "v11 kept the primitives. Not the networking.",
  body: [
    "What v11 kept is btauth/1 (hotkey-signed HTTP requests), ServeAxon and the metagraph. Every subnet now has to build its own validator-to-miner networking.",
    "And every team makes its own security mistakes: no replay store, unsigned answers, no caller checks, no rate limits.",
  ],
  rows: [
    ["Miner HTTP server", "write your own", "ready, you write only the handler"],
    ["Validator client and scoring loop", "write your own", "fan-out, retries, SQLite scores, weights with commit-reveal"],
    ["Request signatures (btauth/1)", "sign / verify primitives", "verified for you, stricter checks"],
    ["Replay protection across workers", "—", "Redis nonce store (required with more than 1 worker)"],
    ["Who may call", "—", "caller policy: registered, permit, stake"],
    ["Signed answers", "—", "twresp/1: bound to the request's nonce and sender"],
    ["Streaming", "—", "SSE with a signed tw-end trailer"],
    ["Chain outages", "—", "staged metagraph staleness that fails closed"],
    ["v10 → v11 migration", "—", "compat layer, taowire migrate, two-way bridge"],
    ["Other languages", "Python only", "TypeScript, Go and Rust, shared conformance vectors"],
  ] as const,
};

export type Stage = { name: string; detail: string; fail: string };

export const pipeline = {
  title: "Every request walks the same pipeline",
  body:
    "You write the route. TaoWire runs everything around it, in this order, and refuses at the first stage that fails, with a fixed public error code.",
  stages: [
    { name: "Body cap", detail: "Oversized bodies are cut off before anything else runs.", fail: "413 tw.payload_too_large" },
    { name: "IP rate limit", detail: "Pre-auth limit per address, so floods never reach crypto.", fail: "429 tw.rate_limited" },
    { name: "btauth/1 verify", detail: "Hotkey signature, receiver and freshness, checked in a worker thread.", fail: "401 tw.auth_bad_signature" },
    { name: "Replay store", detail: "Each nonce is accepted once, in memory or in Redis across workers.", fail: "401 tw.auth_replayed" },
    { name: "Caller policy", detail: "Registered, validator permit, minimum stake: from the metagraph.", fail: "403 tw.forbidden_not_validator" },
    { name: "Hotkey limit", detail: "A per-caller budget once the caller is known.", fail: "429 tw.rate_limited" },
    { name: "Your handler", detail: "Typed request in, typed response out, with a timeout.", fail: "504 tw.handler_timeout" },
    { name: "twresp/1 sign", detail: "The answer is signed and bound to the request's nonce and sender.", fail: "" },
  ] as Stage[],
};

export type Module = {
  name: string;
  cat: "Runtime" | "Security" | "Migration";
  mark: "miner" | "validator" | "signed" | "compat" | "conformance" | "migrate";
  stats: [string, string][];
  href: string;
  keywords: string;
};

export const modules: Module[] = [
  {
    name: "Miner server", cat: "Runtime", mark: "miner", href: doc("docs/miner-guide.md"),
    stats: [["8", "Pipeline stages"], ["1", "Handler to write"], ["Redis", "Nonce store"], ["SSE", "Streaming"]],
    keywords: "miner server route handler tls redis streaming",
  },
  {
    name: "Validator", cat: "Runtime", mark: "validator", href: doc("docs/validator-guide.md"),
    stats: [["256", "Miners in 0.45 s"], ["EMA", "SQLite scores"], ["drand", "Timelocked reveal"], ["auto", "Protocol choice"]],
    keywords: "validator client loop fan-out scores weights commit reveal",
  },
  {
    name: "Signed answers", cat: "Security", mark: "signed", href: doc("docs/protocol/twresp-1.md"),
    stats: [["0.87 ms", "Auth p99"], ["btauth/1", "Requests"], ["twresp/1", "Answers"], ["97%", "Coverage"]],
    keywords: "twresp response signature btauth replay security",
  },
  {
    name: "Compat layer", cat: "Migration", mark: "compat", href: doc("docs/migration-from-v10.md"),
    stats: [["10.5.0", "Live interop"], ["2-way", "Wire bridge"], ["v10", "API shape kept"], ["340", "Tests passed"]],
    keywords: "compat v10 synapse axon dendrite metagraph bridge legacy",
  },
  {
    name: "Conformance", cat: "Security", mark: "conformance", href: doc("docs/multi-language.md"),
    stats: [["143/143", "Vectors"], ["4", "Languages"], ["8/8", "Interop cells"], ["1", "Shared spec"]],
    keywords: "conformance vectors typescript go rust languages interop",
  },
  {
    name: "Migrate CLI", cat: "Migration", mark: "migrate", href: doc("docs/migration-rollout.md"),
    stats: [["scan", "Finds v10 APIs"], ["apply", "Safe rewrites"], ["status", "Rollout numbers"], ["libcst", "Codemods"]],
    keywords: "taowire migrate scan apply status codemods libcst",
  },
];

export const code = {
  title: "What a subnet looks like",
  tabs: [
    {
      id: "miner",
      label: "miner.py",
      caption: "You write the route. TaoWire runs the pipeline around it and signs your answer.",
      src: `from taowire import Miner, RouteContext

miner = Miner.from_env()          # TW_* settings: network, netuid, wallet, ...

@miner.route("/v1/transform", request=TransformRequest,
             response=TransformResponse, timeout_s=5.0)
async def transform(req: TransformRequest, ctx: RouteContext) -> TransformResponse:
    return TransformResponse(result=req.text.upper())

miner.run()                       # publishes the axon on chain, then serves`,
    },
    {
      id: "validator",
      label: "validator.py",
      caption: "You write the task and the score. TaoWire queries the miners, verifies every answer, keeps scores and sets weights.",
      src: `from taowire import SubnetValidator, Task, ValidatorRunner, ValidatorSettings

class MyValidator(SubnetValidator):
    async def make_task(self, round_id: int) -> Task:
        req = TransformRequest(text="hello", op="upper")
        return Task(route="/v1/transform", body=req.model_dump_json().encode(),
                    response_model=TransformResponse, expected=req)

    async def score(self, task, results):
        want = task.expected.text.upper()
        return {uid: 1.0 if r.ok and isinstance(r.data, TransformResponse)
                     and r.data.result == want else 0.0
                for uid, r in results.items()}

ValidatorRunner(MyValidator(), ValidatorSettings.from_env()).run()`,
    },
  ],
};

export type Command = { cmd: string; title: string; lines: string[]; out?: string[] };

export const commands: { title: string; body: string; list: Command[] } = {
  title: "One CLI for the whole lifecycle",
  body: "Scaffold, check, benchmark, migrate, bridge other languages and hand the kit to your AI agent.",
  list: [
    {
      cmd: "taowire init ~/my-subnet", title: "init",
      lines: ["Scaffold a working subnet: protocol, miner, validator,", "tests on TaoWire's FakeChain, .env.example and a compose file."],
      out: ["$ cd ~/my-subnet && pytest -q", "9 passed"],
    },
    {
      cmd: "taowire doctor --role miner", title: "doctor",
      lines: ["Check versions, settings, TLS, hotkey file, coldkey absence,", "chain, registration, axon, port, clock offset, Redis and workers.", "Each check is ok, warn, fail or skip; exit 1 on any fail."],
    },
    {
      cmd: "taowire migrate scan path/to/v10-subnet", title: "migrate",
      lines: ["List every v10 symbol and pattern with its replacement.", "Then `taowire migrate apply` makes the safe rewrites and marks", "the rest with # TW-MIGRATE: comments. `status` reads rollout numbers."],
    },
    {
      cmd: "taowire bench --duration 60", title: "bench",
      lines: ["Real HTTP, signatures, replay store and rate limiters:", "throughput, auth + policy overhead p50/p99, and fan-out."],
      out: ["2,163.5 req/s · p50 0.46 ms · p99 0.865 ms · 256 miners 0.446 s", "(docs/benchmarks.md, one machine)"],
    },
    {
      cmd: "taowire sidecar", title: "sidecar",
      lines: ["Loopback-only, token-protected service for non-Python miners:", "metagraph, caller policy and ServeAxon for TS, Go and Rust."],
    },
    {
      cmd: "taowire sign-request", title: "sign-request",
      lines: ["Debug helper: sign one btauth/1 request with a hotkey and print", "a curl command (or --send it). Fresh for TW_AUTH_MAX_AGE_S, 10 s."],
    },
    {
      cmd: "taowire conformance --vectors ../conformance/vectors", title: "conformance",
      lines: ["Run the Python implementation against the shared vectors.", "A vector file without a checker is a failure, never a skip."],
      out: ["143/143 in Python, TypeScript, Go and Rust"],
    },
    {
      cmd: "taowire mcp", title: "mcp",
      lines: ["MCP server for AI coding agents over stdio.", "Keeps agents on v11 and TaoWire instead of v10 Axon/Dendrite code."],
    },
  ],
};

export const install = {
  title: "Install in your language",
  note: "The alpha is a pre-release: a plain `pip install taowire` skips it, so name the version (or use --pre).",
  langs: [
    { id: "python", label: "Python", cmd: `pip install "taowire[all]==${VERSION}"`, pkg: "taowire", what: "Reference implementation: miner, validator, migration, sidecar", href: `https://pypi.org/project/taowire/${VERSION}/` },
    { id: "ts", label: "TypeScript", cmd: "npm install @taowire/btauth@alpha", pkg: "@taowire/btauth", what: "btauth/1, twresp/1, SSE, sidecar client", href: "https://www.npmjs.com/package/@taowire/btauth" },
    { id: "go", label: "Go", cmd: "go get github.com/anindhabiswas25/TaoWire/go@v0.1.0-alpha.1", pkg: "github.com/anindhabiswas25/TaoWire/go", what: "btauth/1, twresp/1, SSE, sidecar client", href: "https://pkg.go.dev/github.com/anindhabiswas25/TaoWire/go" },
    { id: "rust", label: "Rust", cmd: "cargo add taowire-btauth@0.1.0-alpha.1", pkg: "taowire-btauth", what: "btauth/1, twresp/1, SSE, sidecar client", href: "https://crates.io/crates/taowire-btauth" },
  ],
  extras: "Python extras: [redis], [migrate], [ntp] ([all] = all three), [mcp]. TypeScript peers: fastify, ioredis. Rust features: axum, client, redis, sidecar.",
};

export const quickstart = {
  title: "From zero to weights on chain in under an hour",
  body: "Everything runs on your machine. Nothing touches testnet or mainnet, and only public development keys are used.",
  steps: [
    { n: "01", title: "Get TaoWire", time: "22 s", cmd: `uv venv ~/taowire-env && . ~/taowire-env/bin/activate\nuv pip install "taowire[all]==${VERSION}"` },
    { n: "02", title: "Start a local chain", time: "~3 min", cmd: `git clone --depth 1 ${REPO}.git ~/taowire-repo\nLOCALNET_PYTHON="$(command -v python)" ~/taowire-repo/scripts/localnet_up.sh` },
    { n: "03", title: "Create your subnet", time: "6 s", cmd: "taowire init ~/my-subnet\ncd ~/my-subnet && uv pip install -e '.[dev]' && pytest -q" },
    { n: "04", title: "Check the setup", time: "2 s", cmd: "taowire doctor --role miner" },
    { n: "05", title: "Run miner and validator", time: "5 s to first weights", cmd: "# follow docs/quickstart.md steps 4–7" },
    { n: "06", title: "See weights on chain", time: "1 s", cmd: "# committed, then revealed via drand timelock" },
  ],
};

export const mcp = {
  title: "Your AI agent, on v11 from the first line",
  body:
    "Most agents learned Bittensor from v10 and write Axon / Dendrite / Synapse code that no longer exists. TaoWire ships an MCP server that keeps them on v11 and TaoWire.",
  cmd: `claude mcp add taowire -- uvx --from "taowire[mcp]==${VERSION}" taowire mcp`,
  prompts: ["Use TaoWire to build a subnet where miners caption images", "Port the v10 subnet in this repo to v11 with TaoWire"],
  tools: [
    ["read_doc · search_docs · list_settings · explain_error", "Read the right docs and settings, explain any tw.* error, offline"],
    ["inspect_request · inspect_response", "Debug a 401: the exact signed lines and which check failed"],
    ["scaffold_project · migrate_scan · migrate_apply", "Create a subnet; port a v10 subnet, diff first"],
    ["doctor · read_metagraph", "Check a miner or validator setup; read a subnet, read-only"],
  ] as const,
  safe: "Safe by design: no tool reads private keys or writes to a chain, and file-writing tools only write into an empty directory or a clean git tree.",
};

export const migration = {
  title: "The way across from v10",
  body:
    "taowire.compat keeps a v10-shaped API on top of the kit, and a time-boxed two-way bridge lets v10 and v11 nodes talk while a subnet rolls over. Tested live against bittensor 10.5.0.",
  points: [
    ["scan", "What uses Axon, Dendrite and Synapse, and what can be ported."],
    ["apply", "Codemods to the v11 kit. Review the diff."],
    ["compat", "Synapse, Axon, Dendrite, Metagraph: same shape, new wire."],
    ["bridge", "Mixed v10 / v11 fleets during rollover, with no downgrade."],
  ] as const,
};

export const tested = {
  title: "How it was tested",
  body: `Every release candidate runs the full local gate plus end-to-end checks on a fresh local chain. Latest full run: ${VERSION}, 2026-10-28.`,
  stats: [
    { value: 2467, suffix: "", label: "Python tests passed", note: "unit, property, integration, real Redis" },
    { value: 340, suffix: "", label: "v10 migration tests", note: "live interop with bittensor 10.5.0" },
    { value: 277, suffix: "", label: "TypeScript tests", note: "incl. real Redis" },
    { value: 143, suffix: "/143", label: "Conformance vectors", note: "in all four languages" },
    { value: 97, suffix: "%", label: "Python coverage", note: "≥ 90% on security-critical modules" },
    { value: 7, suffix: "/7", label: "Abuse tests", note: "sig floods, slowloris, 100 MB body, replay storm" },
    { value: 18, suffix: "/18", label: "Localnet end-to-end", note: "weights reveal, TLS, streaming, MCP" },
    { value: 8, suffix: "/8", label: "Interop matrix cells", note: "each language 200/200 both ways" },
  ],
  fuzz: "Every parser of untrusted input is fuzzed: Hypothesis, Go native fuzzing, cargo fuzz. Dependency audits (pip-audit, npm audit, govulncheck, cargo audit): no reachable vulnerabilities.",
  notYet: "Not done yet: an end-to-end run on the public testnet and an external security review. Both come before 1.0.",
};

export const compat = {
  head: ["TaoWire", "bittensor", "Python", "Node", "Go", "Rust"],
  row: [`${VERSION} (alpha)`, ">=11.3.0,<12", "3.10–3.14", "20, 22", "1.22+", "1.80+"],
};

export const cta = {
  line1: "READY TO BUILD",
  line2: "YOUR SUBNET?",
  primary: { label: "READ THE QUICKSTART", href: doc("docs/quickstart.md") },
  secondary: { label: "VIEW ON GITHUB", href: REPO },
};

export const footer = {
  cols: [
    { title: "Build", links: [["Quickstart", "docs/quickstart.md"], ["Miner guide", "docs/miner-guide.md"], ["Validator guide", "docs/validator-guide.md"], ["Streaming", "docs/streaming.md"], ["AI agents (MCP)", "docs/mcp.md"]] },
    { title: "Security", links: [["Threat model", "docs/security.md"], ["Security policy", "SECURITY.md"], ["twresp/1", "docs/protocol/twresp-1.md"], ["Benchmarks", "docs/benchmarks.md"]] },
    { title: "Migrate", links: [["From v10", "docs/migration-from-v10.md"], ["Rollout runbook", "docs/migration-rollout.md"], ["Other languages", "docs/multi-language.md"], ["Sidecar", "docs/sidecar.md"]] },
  ],
  feedback: "This alpha exists to get feedback from subnet builders. Report security problems privately, never in a public issue.",
};
