# Streaming contract (openapi edge)

## Byte passthrough (Unicode-safe)

The edge is a **byte proxy**. For `stream: true`:

1. Auth + rate limit run at the edge.
2. Upstream SSE bytes are copied incrementally to the client (`forward_v1_stream`) while the edge accumulates any `usage` objects in SSE `data:` events (**METER-001**).
3. After the upstream stream ends, the edge signs a usage report with the accumulated token counts and appends a `teechat_usage` SSE trailer. Streaming responses do **not** set `X-TeeChat-Usage-Report` on the initial headers (counts are unknown until the stream finishes); non-stream JSON responses still include that header.

HTTP `Transfer-Encoding: chunked` may split UTF-8 **bytes** mid code point. That is correct: clients reassemble bytes, then decode (e.g. TeaChat `StreamingUtf8Decoder` with `{ stream: true }`).

### Anti-pattern (InferenceEngine history)

Do **not** decode stream text to JavaScript strings, slice at UTF-16 code unit boundaries, and `Buffer.from(piece, "utf8")` again. Splitting surrogate pairs causes permanent `U+FFFD` in stored history. See `vendor/inference-engine/src/server/ope-chunk-text.ts` (`takeUtf16SafePrefix`).

The openapi edge never decodes model output text.

## Gateway-aligned response headers

Streaming responses set:

- `Cache-Control: no-cache, no-transform`
- `X-Accel-Buffering: no` (disable nginx buffering)
- `Transfer-Encoding: chunked`

Matches gateway `pipeInferenceResultToClient` intent for OPE streams.

## Out of scope on the edge

| Concern | Owner |
|---------|--------|
| Gemma repetition collapse / stop-on-repeat | TeaChat client (`chat-stop-on-repeat.ts`) |
| Thread `frequency_penalty` / `presence_penalty` ladder | Client + engine (JSON fields forwarded as-is) |
| Tool calling / model quality | vLLM upstream |
| OPE encrypt chunk sizing | InferenceEngine (not openapi) |

## Agent tool smoke

Run `scripts/smoke-openapi-agent.sh` against a running edge + upstream (vLLM or mock).
