#!/usr/bin/env bash
# Smoke openapi edge for agent-tool compatibility (Cline, Aider, Goose, etc.).
#
# Requires a running openapi binary and reachable upstream (vLLM OpenAI server).
#
# Usage:
#   bash scripts/dev-run.sh          # terminal 1 — edge on 127.0.0.1:18443
#   bash scripts/smoke-openapi-agent.sh
#
#   OPENAPI_BASE_URL=https://127.0.0.1:8443 \
#   OPENAPI_API_KEY=sk-... \
#   OPENAPI_MODEL=google/gemma-4-31B-it \
#   bash scripts/smoke-openapi-agent.sh
#
# Env:
#   OPENAPI_BASE_URL   Edge root without /v1 suffix (default http://127.0.0.1:18443)
#   OPENAPI_API_KEY    Bearer key in signed catalog (default sk-teechat-dev-local)
#   OPENAPI_MODEL      Model id (default: first id from GET /v1/models)
#   OPENAPI_SMOKE_SKIP_STREAM=1  Skip streaming test (e.g. upstream lacks GPU)
#
# Notes:
#   - Stop-on-repeat and Gemma penalty escalation are client/engine concerns; openapi
#     forwards JSON bodies unchanged (see docs/streaming-contract.md).
#   - Unicode: edge passthrough is byte-safe; clients must decode reassembled bytes.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BASE="${OPENAPI_BASE_URL:-http://127.0.0.1:18443}"
BASE="${BASE%/}"
API_KEY="${OPENAPI_API_KEY:-sk-teechat-dev-local}"
AUTH=(-H "Authorization: Bearer ${API_KEY}" -H "Content-Type: application/json")
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

log() { printf '[smoke-openapi] %s\n' "$*"; }
fail() { log "FAIL: $*"; exit 1; }

log "base=$BASE"

# 0) TLS 1.3 only when hitting HTTPS edge
if [[ "$BASE" == https://* ]]; then
  host_port="${BASE#https://}"
  host="${host_port%%/*}"
  port="${host##*:}"
  host="${host%%:*}"
  [[ "$port" == "$host" ]] && port=443
  OPENAPI_TLS_VERIFY_HOST="$host" OPENAPI_TLS_VERIFY_PORT="$port" \
    bash "$ROOT/scripts/verify-tls13-only.sh"
  log "OK TLS 1.3 only"
fi

# 1) Health
curl -fsS "${BASE}/healthz" | grep -q '"status":"ok"' || fail "healthz"
log "OK healthz"

# 2) Models (must proxy upstream — no static teechat-default-only list)
MODELS_JSON="$(curl -fsS "${AUTH[@]}" "${BASE}/v1/models")"
MODEL="${OPENAPI_MODEL:-$(python3 -c "import json,sys; d=json.load(sys.stdin); print(d['data'][0]['id'])" <<<"$MODELS_JSON")")}"
[[ -n "$MODEL" ]] || fail "no model id in /v1/models"
log "OK models (using model=$MODEL)"

# 3) Non-stream completion + usage header
HDR="$TMP/nostream.hdr"
BODY="$TMP/nostream.body"
curl -fsS -D "$HDR" -o "$BODY" "${AUTH[@]}" \
  -d "{\"model\":\"${MODEL}\",\"messages\":[{\"role\":\"user\",\"content\":\"Reply with exactly: pong\"}],\"stream\":false,\"max_tokens\":16}" \
  "${BASE}/v1/chat/completions"
grep -qi 'X-TeeChat-Usage-Report:' "$HDR" || fail "missing X-TeeChat-Usage-Report on non-stream"
python3 -c "import json; json.load(open('$BODY'))" || fail "non-stream body not json"
log "OK chat/completions (non-stream)"

if [[ "${OPENAPI_SMOKE_SKIP_STREAM:-}" == "1" ]]; then
  log "SKIP stream (-- OPENAPI_SMOKE_SKIP_STREAM=1)"
  log "complete"
  exit 0
fi

# 4) Stream — chunked SSE, usage trailer, UTF-8 safe reassembly (emoji prompt)
STREAM_RAW="$TMP/stream.raw"
curl -fsS -N "${AUTH[@]}" \
  -d "{\"model\":\"${MODEL}\",\"messages\":[{\"role\":\"user\",\"content\":\"Say hi then 💡\"}],\"stream\":true,\"max_tokens\":32}" \
  "${BASE}/v1/chat/completions" >"$STREAM_RAW" || fail "stream request"

grep -q 'Transfer-Encoding: chunked' "$STREAM_RAW" || fail "stream response not chunked"
grep -q 'data:' "$STREAM_RAW" || fail "stream missing SSE data lines"
grep -q 'teechat_usage' "$STREAM_RAW" || fail "stream missing teechat_usage trailer"

python3 - "$STREAM_RAW" <<'PY' || fail "stream UTF-8 / SSE validation"
import sys
from pathlib import Path

raw = Path(sys.argv[1]).read_bytes()
# Split HTTP headers from body (first blank line).
sep = raw.find(b"\r\n\r\n")
if sep < 0:
    raise SystemExit("no HTTP header/body separator")
body = raw[sep + 4 :]
# Must decode as UTF-8 without surrogate errors (edge byte passthrough).
text = body.decode("utf-8")
if "\ufffd" in text:
    raise SystemExit("U+FFFD in stream body — possible text re-encode bug upstream of client")
if "data:" not in text:
    raise SystemExit("missing SSE data in body")
print("stream bytes:", len(body), "valid utf-8, no replacement chars")
PY

log "OK chat/completions (stream + UTF-8)"

log "complete — ready for agent tools (baseURL=${BASE}/v1)"
