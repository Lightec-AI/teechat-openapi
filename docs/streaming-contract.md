# Streaming contract (openapi edge)

## Byte passthrough (Unicode-safe)

The edge is a **byte proxy**. For `stream: true`:

1. Auth + rate limit run at the edge.
2. Upstream SSE bytes are copied incrementally to the client (`forward_v1_stream`) unchanged.
3. On the OPE path, the edge decrypts engine OPE NDJSON and re-emits **OpenAI-shaped** SSE deltas, ending with `data: [DONE]\n\n`. Engine `usage_report` trailer frames are **consumed on the gateway hop** (METER-002) and are **not** forwarded to third-party clients.

**Client-visible metering is intentionally omitted.** Billing is engine-signed on the gateway privileged plane (`x-ope-usage-report` / OPE stream trailer → `openapi_usage_events`). Do not append `teechat_usage` SSE events or `X-TeeChat-Usage-Report` headers — strict OpenAI clients (e.g. Cline) Zod-validate every SSE `data:` line and fail on non-`choices` payloads.

HTTP `Transfer-Encoding: chunked` may split UTF-8 **bytes** mid code point. That is correct: clients reassemble bytes, then decode (e.g. TeeChat `StreamingUtf8Decoder` with `{ stream: true }`).

### Anti-pattern (InferenceEngine history)

Do **not** decode stream text to JavaScript strings, slice at UTF-16 code unit boundaries, and `Buffer.from(piece, "utf8")` again. Splitting surrogate pairs causes permanent `U+FFFD` in stored history. See `vendor/inference-engine/src/server/ope-chunk-text.ts` (`takeUtf16SafePrefix`).

The openapi edge never decodes model output text on the passthrough path.

## Gateway-aligned response headers

Streaming responses set:

- `Cache-Control: no-cache, no-transform`
- `X-Accel-Buffering: no` (disable nginx buffering)
- `Transfer-Encoding: chunked`

Matches gateway `pipeInferenceResultToClient` intent for OPE streams.

## Out of scope on the edge

| Concern | Owner |
|---------|--------|
| Gemma repetition collapse / stop-on-repeat | TeeChat client (`chat-stop-on-repeat.ts`) |
| Thread `frequency_penalty` / `presence_penalty` ladder | Client + engine (JSON fields forwarded as-is) |
| Tool calling / model quality | vLLM upstream |
| OPE encrypt chunk sizing | InferenceEngine (not openapi) |
| API token ledger / debit | Gateway ope-api plane (METER-002) |

## Agent tool smoke

Run `scripts/smoke-openapi-agent.sh` against a running edge + upstream (vLLM or mock).

The smoke script asserts **absence** of `teechat_usage` / `X-TeeChat-Usage-Report` on client responses,
and that both `stream:true` SSE and `stream:false` JSON expose structured `tool_calls` when the
engine emits `openai_delta` frames (v0.13.1+ non-stream aggregate).

## Non-stream `openai_delta` aggregate (v0.13.1)

For `stream: false`, OPE plaintext chunks may be neutral `{"type":"openai_delta",…}` frames (same
as the SSE path). The edge merges split `delta.tool_calls` by index into a single
`chat.completion` message — it must **not** flatten frames to `content` only (that drops tools and
yields empty assistant messages with `finish_reason: stop`).
