# Benchmarks

Spec 13.7 targets, measured with `tensorwire bench` (`just bench`), and the
13.6 abuse tests (`just abuse`). Numbers are from one machine on one day;
re-run them on your own hardware before you rely on them.

## Machine and versions (2026-10-23, commits `7187f43` and the Phase 3 head)

| | |
|---|---|
| CPU | 12th Gen Intel Core i5-12500H (4 performance cores with HT + 8 efficiency cores, 16 logical CPUs) |
| Memory | 15.3 GiB |
| OS | Linux 7.0.0-38-generic |
| Python | 3.12.3 |
| Packages | tensorwire 0.1.0.dev0, bittensor 11.3.0, uvicorn 0.54.0, httptools 0.9.0, fastapi 0.159.1, starlette 1.9.0, redis-py 5.3.1 |
| Redis | 7.4.11 in Docker (`redis:7`), published on `127.0.0.1:6379` |

The spec's reference is 4 vCPU / 8 GB. `tensorwire bench` pins the miner
(4 uvicorn workers) to logical CPUs 0-3, which are two performance cores
with their hyper-threads, and the load generators to CPUs 4-15, so the
miner has 4 logical CPUs. Memory is not limited; the miner used about
300 MiB RSS under the heaviest load.

## Results against spec 13.7

| Metric | Target | Result | |
|---|---|---|---|
| Verified requests/s (trivial handler, 1 KB body, 4 workers + Redis) | ≥ 500 | **1,339-1,825 req/s** in two `just bench` runs (60 s, 96 in flight, 0 failed; end-to-end p99 105.7 ms in the first) | met |
| Added latency of auth + policy, p50 | ≤ 2 ms | **0.75-1.69 ms** (`just bench` and repeats); 0.77-0.92 ms with Redis reached directly | met |
| Added latency of auth + policy, p99 | ≤ 5 ms | As configured (Redis through Docker's port mapping): **7.99, 5.63, 5.93 and 4.06 ms** in four runs, so three misses and one pass. With Redis reached directly: **4.24-4.34 ms** in three runs | **not reliably met** as configured; met with direct Redis (see below) |
| Validator fan-out to 256 local miners, 1 KB | all done in ≤ 2 s | **0.715-0.765 s** (slowest of 5 rounds; 256 verified answers per round) | met |

Raw output: `reports/phase-3/a/bench/` and, for the final run at the end of
Phase 3 (all four targets passed that time), `reports/phase-3/a/final/just-bench.txt`.

### Why auth + policy p99 misses as configured

The timed path does three Redis round trips per request: the per-IP
bucket, the replay store, and the per-hotkey bucket. It also hands the
sr25519 verification to a worker thread. Timing each step on its own
(5,000 sequential requests, miner pinned like the bench):

| | p50 | p99 |
|---|---|---|
| whole path, Redis at `127.0.0.1:6379` (Docker port mapping) | 1.01 ms | 7.58 ms |
| of which the per-IP bucket (one Redis call) | 0.38 ms | 3.10 ms |
| of which verification (thread + replay store) | 0.60 ms | 4.97 ms |
| whole path, memory stores (one worker, no Redis) | 0.22 ms | 0.91 ms |

The tail comes from Redis access, not from the kit's own work. On this
machine Redis is reached through Docker's userland proxy (`docker-proxy`):
a plain `PING` has p99 **1.24 ms** through `127.0.0.1:6379` and **0.30 ms**
to the container's own address (`172.17.0.3`). With the same container
reached directly, auth + policy p99 is 4.24-4.34 ms in three runs, under
the target. The target has not been loosened, and the bench has not been
changed to hide the proxy. `just bench` still uses
`TENSORWIRE_BENCH_REDIS_URL` (default `redis://127.0.0.1:6379/14`).

What this means for operators:

- Run Redis where the miner can reach it without a userland proxy: on the
  host itself, in the same network namespace, or over a Unix socket. A
  Redis that is slower again (another host, a managed service) adds its
  round-trip time three times to every request's tail.
- With one worker and no Redis (one host, one process), the kit adds
  0.22 ms p50 and 0.91 ms p99.

To reproduce the direct-Redis numbers:
`tensorwire bench --redis-url redis://<container-ip>:6379/14 --skip throughput --skip fanout`.

## Abuse tests (spec 13.6)

`just abuse`: a real miner process (2 workers on Redis) under attack on
loopback, while a permitted validator queries it at 10 req/s from another
source address. Every test asserts that the validator gets 200 on every
request, with p99 < 200 ms. Evidence: `reports/phase-3/a/abuse/`.

| Attack | Result (two runs) |
|---|---|
| 10,000 req/s with invalid signatures from one IP | 9,555-9,648 req/s answered (≥ 99% 429 from the IP limiter), miner **1.13-1.50 cores** (three runs), ~260-300 MiB RSS; validator p99 20.9-70.4 ms |
| Slowloris: 120 slow-header, 60 slow-body, 60 silent connections | all closed within 3.1 s (deadline `TW_AUTH_MAX_AGE_S + TW_AUTH_ALLOWED_SKEW_S` = 2.5 s in the test); validator p99 21.2-28.5 ms |
| 100 MB body (declared, and chunked) | 413 after 1.9 / 3.0-3.2 MiB were sent; RSS growth ≤ 2.2 MiB |
| Header flood: one 64 KiB header, 2,000 headers, and 2,000 req/s of near-limit (15 KB) headers | 400 for both oversized requests; the flood was rate limited; RSS growth ≤ 19 MiB; validator p99 58.6-112.9 ms |
| Replay storm: one captured valid request replayed 11,000+ times across both workers | never served a second time (0 × 200); the validator who signed it is still served |

One worker without Redis cannot absorb the 10,000 req/s flood on this
CPU. It refuses about 6,900 req/s on one core, the rest queue, and the
validator's p99 rises to 384 ms. The flood test therefore runs only on the
2-worker fleet. A miner that must absorb floods of that size needs more
than one worker (and so Redis).

Changes made during Phase 3 to reach these numbers, without changing any
test: the miner's HTTP protocol moved from h11 to httptools, keeping the
request-read deadline and adding real header limits (h11's limit missed
heads that arrive complete). The per-IP limiter became the outermost layer
with a lean refusal path. It counts refusals with pre-bound metrics and
logs one `ip_rate_limited` line per client per 10 s instead of one access
line per refused request. Before these changes the flood used 2.02 cores
(saturated), oversized headers got 401, and the replay-storm validator p99
was 208.7 ms.
