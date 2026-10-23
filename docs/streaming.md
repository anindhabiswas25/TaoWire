# Streaming responses

A streaming route answers token by token over Server-Sent Events, and the
whole stream is still signed: the last event, `tw-end`, carries a digest of
every chunk and a `twresp/1` signature over it (spec 9.2). TensorWire miners
and validators enforce the same limits on both ends.

## Miner: a streaming route

```python
from collections.abc import AsyncIterator
from pydantic import BaseModel
from tensorwire import Miner, RouteContext

class Prompt(BaseModel):
    text: str

class Token(BaseModel):
    token: str

miner = Miner.from_env()

@miner.route("/v1/generate", request=Prompt, response=Token, stream=True,
             timeout_s=5.0, stream_max_s=30, stream_idle_s=5)
async def generate(req: Prompt, ctx: RouteContext) -> AsyncIterator[Token]:
    async for piece in my_model.generate(req.text):
        yield Token(token=piece)
```

- `stream=True` makes the route a stream. The handler is an async generator,
  or any handler (sync or async) that returns an async iterable or
  `StreamingReply(chunks)`. `response=` is the **chunk** model: each item
  must be an instance of it.
- **Every chunk is a JSON object or array**: a model, a `dict`, a `list`, or
  `bytes` holding JSON object/array text with no line breaks. Scalars (`1`,
  `"text"`, `null`) are refused. Why: the digest is computed over the chunks'
  bytes joined end to end, and with scalars the chunks `1`,`23` and `12`,`3`
  would have the same digest and count, so a relay on plain HTTP could move
  chunk boundaries under a valid signature. Objects and arrays are
  self-delimiting, so only one split is possible.
- The full request path runs before the first byte: body cap, IP and hotkey
  limits, btauth/1 verification, replay store, caller policy, request
  parsing. Failures there are the usual JSON errors (signed when they come
  after authentication).
- The first chunk is fetched **before** anything is sent, within the route's
  `timeout_s`: a handler that raises or stalls there gets the ordinary
  signed `500 tw.handler_error` / `504 tw.handler_timeout`.
- After that the stream is `200 text/event-stream`:

  ```text
  event: chunk
  data: {"token":"Hel"}

  event: chunk
  data: {"token":"lo"}

  event: tw-end
  data: {"digest":"<sha256 hex>","count":2,"signature":"0x..."}
  ```

  `X-TW-Resp-Version`, `X-TW-Resp-Hotkey` (and `X-TW-Resp-Crypto` for
  ed25519) are sent at stream start; the signature is in `tw-end`. It is the
  `twresp/1` payload with status `200` and the body-hash line set to the
  digest, so it binds the stream to the request's nonce and sender like any
  signed response. With `TW_SIGN_RESPONSES=0` the trailer has no signature.
- **Limits on the miner** (`TW_STREAM_MAX_S`, `TW_STREAM_MAX_BYTES`,
  `TW_STREAM_IDLE_S`, or per route `stream_max_s`, `stream_max_bytes`,
  `stream_idle_s`, same ranges): the whole stream within `max_s` (sending to
  a validator that stopped reading included), at most `idle_s` between two
  chunks from your handler, at most `max_bytes` on the wire (256 bytes are
  kept for the trailer).
- **A stream that cannot finish ends without `tw-end`**: a handler
  exception, a limit hit, a chunk that is not a JSON object or array, a
  validator that disconnects, or the miner draining. The validator then
  rejects the whole stream. The miner never signs a trailer over partial
  data. Each abort is logged (`stream_aborted` with route and reason) and
  counted in `tw_stream_aborted_total{side="miner",reason}` with reasons
  `handler_error`, `idle_timeout`, `max_duration`, `max_bytes`, `bad_chunk`,
  `cancelled`.
- **At most 16 open streams per caller hotkey per miner process**
  (`MAX_STREAMS_PER_CALLER`); more get the signed `429 tw.rate_limited`
  (`Retry-After: 1`). A stream can live for `max_s`, much longer than a plain
  request, so without this cap one permitted validator could fill the
  server's connection limit and lock the others out. The per-hotkey rate
  limit (`TW_RATE_HOTKEY_*`) applies to opening streams as to any request.
- v10 Dendrites cannot stream to a TensorWire miner (D33): a v10 request to
  a streaming route gets the v10-shaped `tw.invalid_request` answer.

## Validator: reading a stream

```python
from tensorwire import ValidatorClient

async with ValidatorClient(signer) as client:
    # Everything at once: a MinerResult, data = the tuple of chunks.
    result = await client.query_stream(neuron, "/v1/generate", body,
                                       chunk_model=Token)

    # Or chunk by chunk, as they arrive:
    async with client.stream(neuron, "/v1/generate", body, chunk_model=Token) as stream:
        async for chunk in stream:          # UnverifiedChunk(index, data, raw)
            show_progress(chunk.data)       # display only: NOT verified yet
    result = stream.result                  # the MinerResult
```

**Chunks are unverified until the stream ends.** `UnverifiedChunk.verified`
is always `False`; only the final result can say `response_verified=True`,
once `tw-end` matched every chunk and its signature verified. A miner (or a
relay) can send any chunks it likes before a trailer that fails. Score from
`result` only, never from chunks you saw on the way.

What the client checks (rejections are for the whole stream):

| Problem | `error_code` |
|---|---|
| `tw-end` missing, malformed, repeated, or followed by another event | `tw.bad_response_signature` |
| `count` or `digest` do not match the chunks received | `tw.bad_response_signature` |
| `X-TW-Resp-*` headers missing at stream start, or the trailer signature does not verify for this request | `tw.bad_response_signature` |
| the connection breaks before `tw-end` | `tw.bad_response_signature` |
| the stream runs past `max_s` or the query's time budget, or no complete event for `idle_s` (a one-byte-at-a-time drip is cut too), or the body does not end after `tw-end` | `tw.timeout` |
| more than `max_bytes` on the wire | `tw.response_too_large` |
| a chunk that is not a JSON object or array, or does not fit `chunk_model`; a `200` that is not `text/event-stream`; a compressed stream | `tw.invalid_response` |

Unknown event names and SSE comments are ignored; they are not part of the
digest. With `TW_VERIFY_RESPONSES=0` digest and count are still checked, the
signature is not. Each rejection is counted in
`tw_stream_aborted_total{side="validator",reason}` (`timeout`, `too_large`,
`bad_trailer`, `bad_chunk`, `transport`) and in
`tw_validator_miner_results_total` like any result.

The rules of the client apply until the stream starts: a fresh signature per
attempt, retries on connect errors, timeouts (idempotent requests) and
502/503/504. Once a `200` stream has started there is no retry. **One time
budget** covers the whole query: the stream ends by `max_attempts ×
timeout_s` from the first attempt or by `max_s`, whichever comes first.
Limits come from `TW_STREAM_*` (`ValidatorClient(stream_limits=...)`), and
`stream()` / `query_stream()` take `max_s`, `max_bytes` and `idle_s` per
call. Streams use btauth/1 only: the v10 fallback is not used for them.

`query_stream_many(neurons, route, body, ...)` streams from many miners at
once (bounded by `max_concurrency`) and returns one result per UID. A
`MinerStream` holds a concurrency slot until it ends or is closed: use it as
an async context manager (or call `aclose()`) when you stop early.

## Settings

| Variable | Default | Range | Meaning |
|---|---|---|---|
| `TW_STREAM_MAX_S` | `60` | 1–600 | whole stream |
| `TW_STREAM_MAX_BYTES` | `4194304` | 1024–67108864 | bytes on the wire |
| `TW_STREAM_IDLE_S` | `10` | 1–120 | longest gap between two events |

Both miners and validators read them; a route or a call may override them
within the same ranges.
