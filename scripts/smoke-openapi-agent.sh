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
if [[ -n "${OPENAPI_MODEL:-}" ]]; then
  MODEL="$OPENAPI_MODEL"
else
  MODEL="$(printf '%s' "$MODELS_JSON" | python3 -c "import json,sys; d=json.load(sys.stdin); print(d['data'][0]['id'])")"
fi
[[ -n "$MODEL" ]] || fail "no model id in /v1/models"
log "OK models (using model=$MODEL)"

# 3) Non-stream completion — no TeeChat metering headers on client responses
HDR="$TMP/nostream.hdr"
BODY="$TMP/nostream.body"
curl -fsS -D "$HDR" -o "$BODY" "${AUTH[@]}" \
  -d "{\"model\":\"${MODEL}\",\"messages\":[{\"role\":\"user\",\"content\":\"Reply with exactly: pong\"}],\"stream\":false,\"max_tokens\":16}" \
  "${BASE}/v1/chat/completions"
grep -qi 'X-TeeChat-Usage-Report:' "$HDR" && fail "non-stream must not expose X-TeeChat-Usage-Report (METER-002 gateway billing)"
python3 -c "import json; json.load(open('$BODY'))" || fail "non-stream body not json"
log "OK chat/completions (non-stream, no client metering)"

if [[ "${OPENAPI_SMOKE_SKIP_STREAM:-}" == "1" ]]; then
  log "SKIP stream (-- OPENAPI_SMOKE_SKIP_STREAM=1)"
  log "complete"
  exit 0
fi

# 4) Stream — chunked SSE, no teechat_usage trailer (Cline-safe)
STREAM_HDR="$TMP/stream.hdr"
STREAM_BODY="$TMP/stream.body"
curl -fsS -N -D "$STREAM_HDR" -o "$STREAM_BODY" "${AUTH[@]}" \
  -d "{\"model\":\"${MODEL}\",\"messages\":[{\"role\":\"user\",\"content\":\"Say hi then 💡\"}],\"stream\":true,\"max_tokens\":32}" \
  "${BASE}/v1/chat/completions" || fail "stream request"

grep -qi 'Transfer-Encoding: chunked' "$STREAM_HDR" || fail "stream response not chunked"
grep -q 'data:' "$STREAM_BODY" || fail "stream missing SSE data lines"
grep -q 'teechat_usage' "$STREAM_BODY" && fail "stream must not include teechat_usage trailer"
grep -qi 'X-TeeChat-Usage-Report:' "$STREAM_HDR" && fail "stream must not expose X-TeeChat-Usage-Report"

python3 - "$STREAM_BODY" <<'PY' || fail "stream UTF-8 / SSE validation"
import sys
from pathlib import Path

body = Path(sys.argv[1]).read_bytes()
# Must decode as UTF-8 without surrogate errors (edge byte passthrough).
text = body.decode("utf-8")
if "\ufffd" in text:
    raise SystemExit("U+FFFD in stream body — possible text re-encode bug upstream of client")
if "data:" not in text:
    raise SystemExit("missing SSE data in body")
print("stream bytes:", len(body), "valid utf-8, no replacement chars")
PY

log "OK chat/completions (stream + UTF-8)"

# 5) Structured tool_calls (Cline / WorkBuddy agent loop) — non-stream + stream
TOOLS_BODY="$TMP/tools.json"
python3 - "$MODEL" "$TOOLS_BODY" <<'PY'
import json, sys
model, out = sys.argv[1], sys.argv[2]
payload = {
    "model": model,
    "messages": [{"role": "user", "content": "Call the get_time tool now. Do not answer yourself."}],
    "tools": [{
        "type": "function",
        "function": {
            "name": "get_time",
            "description": "Return current UTC time",
            "parameters": {"type": "object", "properties": {}},
        },
    }],
    "tool_choice": "auto",
    "max_tokens": 128,
    "temperature": 0,
    "stream": False,
}
open(out, "w", encoding="utf-8").write(json.dumps(payload))
PY
curl -fsS -o "$TMP/tools.out" "${AUTH[@]}" -d @"$TOOLS_BODY" \
  "${BASE}/v1/chat/completions" || fail "tools non-stream request"
python3 - "$TMP/tools.out" <<'PY' || fail "tools non-stream missing structured tool_calls"
import json, sys
r = json.load(open(sys.argv[1]))
if "error" in r:
    raise SystemExit(r["error"])
msg = r["choices"][0]["message"]
tc = msg.get("tool_calls") or []
if not tc:
    raise SystemExit(f"no tool_calls in message keys={sorted(msg.keys())} content={msg.get('content')!r}")
name = (tc[0].get("function") or {}).get("name")
if name != "get_time":
    raise SystemExit(f"unexpected tool name {name!r}")
print("non-stream tool_calls ok:", name)
PY
log "OK chat/completions (non-stream tool_calls)"

python3 - "$MODEL" "$TMP/tools-stream.json" <<'PY'
import json, sys
model, out = sys.argv[1], sys.argv[2]
payload = {
    "model": model,
    "messages": [{"role": "user", "content": "Call the get_time tool now. Do not answer yourself."}],
    "tools": [{
        "type": "function",
        "function": {
            "name": "get_time",
            "description": "Return current UTC time",
            "parameters": {"type": "object", "properties": {}},
        },
    }],
    "tool_choice": "auto",
    "max_tokens": 128,
    "temperature": 0,
    "stream": True,
}
open(out, "w", encoding="utf-8").write(json.dumps(payload))
PY
curl -fsS -N -o "$TMP/tools-stream.out" "${AUTH[@]}" -d @"$TMP/tools-stream.json" \
  "${BASE}/v1/chat/completions" || fail "tools stream request"
python3 - "$TMP/tools-stream.out" <<'PY' || fail "tools stream missing structured tool_calls"
from pathlib import Path
import json, sys
body = Path(sys.argv[1]).read_text(encoding="utf-8")
if "\ufffd" in body:
    raise SystemExit("U+FFFD in tools stream")
saw = False
for line in body.splitlines():
    if not line.startswith("data: "):
        continue
    p = line[6:].strip()
    if p == "[DONE]":
        break
    o = json.loads(p)
    d = (o.get("choices") or [{}])[0].get("delta") or {}
    if d.get("tool_calls"):
        saw = True
        break
if not saw:
    raise SystemExit("no delta.tool_calls in SSE (model may have answered in content — agent stall)")
print("stream tool_calls ok")
PY
log "OK chat/completions (stream tool_calls)"

log "complete — ready for agent tools (baseURL=${BASE}/v1)"
