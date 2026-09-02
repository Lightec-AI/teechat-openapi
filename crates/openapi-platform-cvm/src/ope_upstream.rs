//! Hard-cutover upstream: inventory → P1 preassign → Rust OPE → F′ dispatch → OpenAI shape.

use std::collections::HashSet;
use std::io::{BufRead, BufReader, Read, Write};
use std::sync::Mutex;

use openapi_core::authz::OpenApiKeyPolicy;
use openapi_core::error::ApiError;
use openapi_core::handler::{
    HttpMethod, StreamForwardResult, UpstreamForwarder, UpstreamRequestContext, UpstreamResponse,
};
use openapi_core::models::{ModelObject, ModelsListResponse};
use openapi_core::upstream::{body_wants_stream, model_from_body};
use openapi_platform::{
    accept_engine_recipient, encode_nonce_b64_url, independent_token_bound,
    observe_host_time_from_env, request_body_hash_hex, require_engine_challenge_from_env,
    require_signed_usage_from_env, resolve_usage_tokens, verify_engine_challenge_response,
    EngineRecipientPolicy, EphemeralEngineTrust, RecipientTrustVia, UsageVerifyContext,
};
use rand::RngCore;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use tracing::warn;

use crate::gateway_ope_api::{
    DispatchRequest, GatewayOpeApiClient, GatewayOpeApiConfig, GatewayOpeApiError, InventoryEngine,
    InventoryResponse, PreassignRequest, PreassignResponse,
};
use crate::ope_wrap::{
    decrypt_chunk, encrypt_openai_body_with_path, envelope_to_bytes, EncryptedOpeRequest,
};

type BufferedDispatchResponse = (u16, Vec<(String, String)>, Vec<u8>);

/// Clear-HTTP break-glass (forbidden in prod).
pub fn clear_http_break_glass_enabled() -> bool {
    match std::env::var("OPENAPI_UPSTREAM_CLEAR_HTTP") {
        Ok(v) => {
            let v = v.trim().to_ascii_lowercase();
            v == "1" || v == "true" || v == "yes"
        }
        Err(_) => false,
    }
}

pub struct OpeDispatchUpstream {
    client: GatewayOpeApiClient,
    recipient_policy: EngineRecipientPolicy,
    verify_engine_snp_chain: bool,
    /// Reports whose AMD chain already verified, keyed by report hash. Epochs
    /// live for weeks, so this keeps the KDS fetch off the request path without
    /// ever reusing a verdict for a different report.
    verified_reports: Mutex<HashSet<String>>,
    /// Serializes inventory+preassign+dispatch per process (v1 pool size often 1).
    lock: Mutex<()>,
}

impl OpeDispatchUpstream {
    pub fn try_new(config: GatewayOpeApiConfig) -> Result<Self, GatewayOpeApiError> {
        let recipient_policy = config.recipient_policy.clone();
        let verify_engine_snp_chain = config.verify_engine_snp_chain;
        Ok(Self {
            client: GatewayOpeApiClient::try_new(config)?,
            recipient_policy,
            verify_engine_snp_chain,
            verified_reports: Mutex::new(HashSet::new()),
            lock: Mutex::new(()),
        })
    }

    pub fn from_env() -> Result<Option<Self>, GatewayOpeApiError> {
        let Some(cfg) = GatewayOpeApiConfig::from_env()? else {
            return Ok(None);
        };
        Ok(Some(Self::try_new(cfg)?))
    }

    fn map_gw(err: GatewayOpeApiError) -> ApiError {
        match err {
            GatewayOpeApiError::Http { status, body } => {
                if status == 403 {
                    ApiError::Forbidden(format!("ope matrix denied: {body}"))
                } else if status == 409 {
                    ApiError::Upstream(format!("ope assign stale: {body}"))
                } else if status == 503 {
                    ApiError::Upstream(format!("ope unavailable: {body}"))
                } else if (400..500).contains(&status) {
                    // Surface vLLM context-length / bad-request instead of opaque 502.
                    ApiError::BadRequest(format!("ope dispatch {status}: {body}"))
                } else {
                    ApiError::Upstream(format!("ope http {status}: {body}"))
                }
            }
            other => ApiError::Upstream(other.to_string()),
        }
    }

    fn dispatch_status_error(status: u16, msg: &str) -> ApiError {
        if (400..500).contains(&status) {
            ApiError::BadRequest(format!("ope dispatch {status}: {msg}"))
        } else {
            ApiError::Upstream(format!("ope dispatch {status}: {msg}"))
        }
    }

    fn pick_engine<'a>(
        inv: &'a InventoryResponse,
        model: &str,
    ) -> Result<&'a InventoryEngine, ApiError> {
        let m = strip_model_provider_suffix(model.trim());
        if m.is_empty() {
            return Err(ApiError::BadRequest("model required".into()));
        }
        if let Some(e) = inv.engines.iter().find(|e| {
            e.healthy
                && e.ready_sessions > 0
                && e.models.iter().any(|x| strip_model_provider_suffix(x) == m)
        }) {
            return Ok(e);
        }
        if let Some(e) = inv
            .engines
            .iter()
            .find(|e| e.healthy && e.models.iter().any(|x| strip_model_provider_suffix(x) == m))
        {
            return Ok(e);
        }
        Err(ApiError::Upstream(format!(
            "no engine available for model `{m}`"
        )))
    }

    fn verify_preassign(
        &self,
        pre: &PreassignResponse,
        engine: &InventoryEngine,
        ctx: &UpstreamRequestContext,
    ) -> Result<(), ApiError> {
        if pre.assign_id.trim().is_empty()
            || pre.engine_id != engine.engine_id
            || pre.trust.engine_id != engine.engine_id
            || pre.engine_set != engine.engine_set
            || pre.key_set != ctx.key_set
            || pre.openapi_key_id != ctx.key_id
        {
            return Err(ApiError::Forbidden(
                "OPE preassignment binding mismatch".into(),
            ));
        }
        let now_ms = current_unix_ms()?;
        if pre.ttl_ms == 0 || pre.expires_at_ms <= now_ms {
            return Err(ApiError::Forbidden("OPE preassignment expired".into()));
        }
        let trust = EphemeralEngineTrust {
            engine_id: &pre.trust.engine_id,
            epoch_id: &pre.trust.epoch_id,
            not_before: &pre.trust.not_before,
            not_after: &pre.trust.not_after,
            mlkem_encapsulation_key: &pre.trust.hybrid.mlkem_encapsulation_key,
            x25519_public: &pre.trust.hybrid.x25519_public,
            ed25519_public: &pre.trust.identity.ed25519_public,
            identity_signature: &pre.trust.identity.identity_signature,
        };
        // The gateway chose this engine; the edge decides whether its keys may
        // receive customer plaintext (RB-46). ARCH-CHAL: mint nonce → F′ challenge
        // → verify challenge REPORT_DATA (fail-closed). Recipient bind-v2 still
        // uses the relayed *connect* quote, which was minted with nonce=None —
        // passing the challenge nonce here recomputes a different preimage and
        // rejects every live epoch (REPORT_DATA mismatch / client timeouts).
        let mut challenge_vcek_der = None;
        if require_engine_challenge_from_env() {
            let mut nonce = [0u8; 32];
            rand::thread_rng().fill_bytes(&mut nonce);
            let nonce_b64 = encode_nonce_b64_url(&nonce);
            let chal = self
                .client
                .challenge_engine(
                    &pre.trust.engine_id,
                    &nonce_b64,
                    Some(pre.trust.epoch_id.as_str()),
                )
                .map_err(Self::map_gw)?;
            verify_engine_challenge_response(&nonce, &chal)
                .map_err(|e| ApiError::Forbidden(format!("engine challenge failed: {e}")))?;
            challenge_vcek_der = chal.cpu.vcek_der().map_err(|e| {
                ApiError::Forbidden(format!("engine challenge VCEK decode failed: {e}"))
            })?;
        }
        let accepted = accept_engine_recipient(
            &self.recipient_policy,
            &trust,
            pre.trust.cpu_quote(),
            None,
            now_ms,
        )
        .map_err(|e| ApiError::Forbidden(format!("untrusted OPE engine recipient: {e}")))?;
        if let Some(report_b64) = accepted.report_b64.as_deref() {
            self.verify_report_chain(report_b64, challenge_vcek_der.as_deref())?;
        }
        if accepted.via == RecipientTrustVia::IdentitySignature {
            warn!(
                engine_id = %pre.trust.engine_id,
                epoch_id = %pre.trust.epoch_id,
                "OPE recipient accepted on the legacy identity pin; engine predates per-epoch evidence (RB-45)"
            );
        }
        Ok(())
    }

    /// AMD chain verification over the report the epoch keys were found in.
    ///
    /// Prefer the VCEK carried by the nonce-bound engine challenge. It is
    /// untrusted until the built-in AMD chain verifies this exact report.
    /// KDS remains a compatibility fallback for older challenge responses.
    fn verify_report_chain(
        &self,
        report_b64: &str,
        challenge_vcek_der: Option<&[u8]>,
    ) -> Result<(), ApiError> {
        if !self.verify_engine_snp_chain {
            return Ok(());
        }
        let key = hex::encode(Sha256::digest(report_b64.as_bytes()));
        if self
            .verified_reports
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .contains(&key)
        {
            return Ok(());
        }
        let verified = match challenge_vcek_der {
            Some(vcek_der) => {
                openapi_attest::snp::verify_snp_report_with_collateral(report_b64, vcek_der, true)
            }
            None => openapi_attest::snp::verify_snp_report(report_b64, true),
        };
        verified.map_err(|e| {
            ApiError::Forbidden(format!("engine SNP report failed chain verification: {e}"))
        })?;
        self.verified_reports
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .insert(key);
        Ok(())
    }

    fn prepare(
        &self,
        body: &[u8],
        ctx: &UpstreamRequestContext,
        openai_path: &str,
    ) -> Result<(PreassignResponse, EncryptedOpeRequest, String), ApiError> {
        // Clients sometimes send `model@teechat`; inventory/preassign use bare ids.
        let model = strip_model_provider_suffix(&model_from_body(body));
        let mut payload: Value = serde_json::from_slice(body)
            .map_err(|e| ApiError::BadRequest(format!("invalid json: {e}")))?;
        if let Some(obj) = payload.as_object_mut() {
            obj.insert("model".into(), Value::String(model.clone()));
        }
        let _guard = self.lock.lock().unwrap_or_else(|p| p.into_inner());
        let inv = self.client.inventory(&ctx.key_set).map_err(Self::map_gw)?;
        let engine = Self::pick_engine(&inv, &model)?;
        let pre = self
            .client
            .preassign(&PreassignRequest {
                engine_id: engine.engine_id.clone(),
                key_set: Some(ctx.key_set.clone()),
                model: Some(model.clone()),
                openapi_key_id: Some(ctx.key_id.clone()),
            })
            .map_err(Self::map_gw)?;
        self.verify_preassign(&pre, engine, ctx)?;
        let enc = encrypt_openai_body_with_path(&pre.trust, &ctx.key_id, &payload, openai_path)
            .map_err(|e| ApiError::Internal(e.to_string()))?;
        Ok((pre, enc, model))
    }

    fn dispatch_encrypted(
        &self,
        pre: &PreassignResponse,
        enc: &EncryptedOpeRequest,
        ctx: &UpstreamRequestContext,
    ) -> Result<BufferedDispatchResponse, ApiError> {
        let body =
            envelope_to_bytes(&enc.envelope).map_err(|e| ApiError::Internal(e.to_string()))?;
        let resp = self
            .client
            .dispatch(&DispatchRequest {
                engine_id: pre.engine_id.clone(),
                conversation_id: None,
                ephemeral_epoch: Some(enc.ephemeral_epoch.clone()),
                openapi_key_id: Some(ctx.key_id.clone()),
                assign_id: Some(pre.assign_id.clone()),
                body,
            })
            .map_err(Self::map_gw)?;
        Ok((resp.status, resp.headers, resp.body))
    }
}

fn current_unix_ms() -> Result<u64, ApiError> {
    use std::time::{SystemTime, UNIX_EPOCH};
    let host = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
        .unwrap_or(0);
    // RB-49: when OPENAPI_SEALED_TIME=1, refuse host rewind below sealed floor.
    observe_host_time_from_env(host).map_err(|e| ApiError::Forbidden(e.to_string()))
}

impl UpstreamForwarder for OpeDispatchUpstream {
    fn forward_v1(
        &self,
        method: HttpMethod,
        path: &str,
        body: Option<&[u8]>,
    ) -> Result<UpstreamResponse, ApiError> {
        self.forward_v1_ctx(method, path, body, &UpstreamRequestContext::default())
    }

    fn forward_v1_ctx(
        &self,
        method: HttpMethod,
        path: &str,
        body: Option<&[u8]>,
        ctx: &UpstreamRequestContext,
    ) -> Result<UpstreamResponse, ApiError> {
        if method != HttpMethod::Post {
            return Err(ApiError::MethodNotAllowed);
        }
        if !path.starts_with("/v1/") {
            return Err(ApiError::NotFound);
        }
        let body = body.unwrap_or(&[]);
        if body_wants_stream(body) {
            // Caller should use stream path; buffer as fallback.
            let mut buf = Vec::new();
            self.forward_v1_stream_ctx(method, path, Some(body), ctx, &mut buf)?;
            return Ok(UpstreamResponse::Raw {
                bytes: buf,
                content_type: "text/event-stream".into(),
            });
        }
        let (pre, enc, model) = self.prepare(body, ctx, path)?;
        let (status, headers, raw) = self.dispatch_encrypted(&pre, &enc, ctx)?;
        if !(200..300).contains(&status) {
            let msg = String::from_utf8_lossy(&raw);
            return Err(Self::dispatch_status_error(status, &msg));
        }
        let ct = headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("content-type"))
            .map(|(_, v)| v.as_str())
            .unwrap_or("");
        let usage_hdr = headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("x-ope-usage-report"))
            .map(|(_, v)| v.as_str());

        let text = decrypt_ope_body_to_text(&enc, &raw, ct)?;
        if path.contains("embeddings") {
            let embeddings: Value = serde_json::from_str(&text)
                .map_err(|e| ApiError::Upstream(format!("embeddings response is not JSON: {e}")))?;
            if embeddings.get("object").and_then(|v| v.as_str()) == Some("chat.completion") {
                return Err(ApiError::Upstream(
                    "embeddings path returned chat.completion".into(),
                ));
            }
            return Ok(UpstreamResponse::Json(embeddings));
        }
        let (prompt_tokens, completion_tokens) = resolve_usage_or_estimate(
            usage_hdr,
            body,
            &text,
            Some(UsageMeterCtx {
                engine_id: &pre.engine_id,
                epoch_id: &pre.trust.epoch_id,
                verify_key: &pre.trust.identity.ed25519_public,
            }),
        )?;
        let completion =
            openai_chat_completion_json(&model, &text, prompt_tokens, completion_tokens);
        Ok(UpstreamResponse::Json(completion))
    }

    fn forward_v1_stream(
        &self,
        method: HttpMethod,
        path: &str,
        body: Option<&[u8]>,
        out: &mut dyn Write,
    ) -> Result<StreamForwardResult, ApiError> {
        self.forward_v1_stream_ctx(method, path, body, &UpstreamRequestContext::default(), out)
    }

    fn forward_v1_stream_ctx(
        &self,
        method: HttpMethod,
        path: &str,
        body: Option<&[u8]>,
        ctx: &UpstreamRequestContext,
        out: &mut dyn Write,
    ) -> Result<StreamForwardResult, ApiError> {
        if method != HttpMethod::Post {
            return Err(ApiError::MethodNotAllowed);
        }
        if path.contains("embeddings") {
            return Err(ApiError::BadRequest(
                "streaming is not supported for /v1/embeddings".into(),
            ));
        }
        let body = body.unwrap_or(&[]);
        let (pre, enc, model) = self.prepare(body, ctx, path)?;
        let env_bytes =
            envelope_to_bytes(&enc.envelope).map_err(|e| ApiError::Internal(e.to_string()))?;
        let (status, headers, mut reader) = self
            .client
            .dispatch_reader(&DispatchRequest {
                engine_id: pre.engine_id.clone(),
                conversation_id: None,
                ephemeral_epoch: Some(enc.ephemeral_epoch.clone()),
                openapi_key_id: Some(ctx.key_id.clone()),
                assign_id: Some(pre.assign_id.clone()),
                body: env_bytes,
            })
            .map_err(Self::map_gw)?;
        if !(200..300).contains(&status) {
            let mut err_body = Vec::new();
            let _ = reader.read_to_end(&mut err_body);
            let msg = String::from_utf8_lossy(&err_body);
            return Err(Self::dispatch_status_error(status, &msg));
        }
        let ct = headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("content-type"))
            .map(|(_, v)| v.clone())
            .unwrap_or_default();

        let written = bridge_ope_to_openai_sse(
            &enc,
            &mut reader,
            &ct,
            &model,
            out,
        )?;
        Ok(StreamForwardResult {
            status: 200,
            content_type: "text/event-stream".into(),
            bytes_written: written,
        })
    }

    fn list_models(&self) -> Result<ModelsListResponse, ApiError> {
        self.list_models_for_key(
            &UpstreamRequestContext::default(),
            &OpenApiKeyPolicy::unrestricted(),
        )
    }

    fn list_models_for_key(
        &self,
        ctx: &UpstreamRequestContext,
        policy: &OpenApiKeyPolicy,
    ) -> Result<ModelsListResponse, ApiError> {
        let inv = self.client.inventory(&ctx.key_set).map_err(Self::map_gw)?;
        let mut ids: Vec<String> = Vec::new();
        for e in &inv.engines {
            if !e.healthy {
                continue;
            }
            for m in &e.models {
                if policy.allows_model(m) && !ids.iter().any(|x| x == m) {
                    ids.push(m.clone());
                }
            }
        }
        ids.sort();
        Ok(ModelsListResponse {
            object: "list".into(),
            data: ids
                .into_iter()
                .map(|id| ModelObject {
                    id,
                    object: "model".into(),
                    created: 1_700_000_000,
                    owned_by: "teechat".into(),
                })
                .collect(),
        })
    }
}

/// Reassemble UTF-8 safely across OPE decrypt chunks (mirror Tauri `valid_up_to`).
struct Utf8PlainAccumulator {
    pending: Vec<u8>,
}

impl Utf8PlainAccumulator {
    fn new() -> Self {
        Self { pending: Vec::new() }
    }

    fn push(&mut self, bytes: &[u8]) -> Result<Vec<String>, ApiError> {
        self.pending.extend_from_slice(bytes);
        let mut out = Vec::new();
        loop {
            match std::str::from_utf8(&self.pending) {
                Ok(text) => {
                    if !text.is_empty() {
                        out.push(text.to_string());
                    }
                    self.pending.clear();
                    break;
                }
                Err(err) => {
                    let valid = err.valid_up_to();
                    if valid > 0 {
                        let text = std::str::from_utf8(&self.pending[..valid])
                            .map_err(|e| ApiError::Upstream(e.to_string()))?;
                        out.push(text.to_string());
                        self.pending.drain(..valid);
                    }
                    if err.error_len().is_some() {
                        return Err(ApiError::Upstream("ope plaintext invalid utf8".into()));
                    }
                    break;
                }
            }
        }
        Ok(out)
    }

    fn finish(self) -> Result<Option<String>, ApiError> {
        if self.pending.is_empty() {
            return Ok(None);
        }
        String::from_utf8(self.pending)
            .map(Some)
            .map_err(|_| ApiError::Upstream("ope plaintext invalid utf8 tail".into()))
    }
}

fn completion_text_from_openai_delta_frame(frame: &Value) -> String {
    let mut out = String::new();
    let Some(choice) = frame
        .get("choices")
        .and_then(|c| c.as_array())
        .and_then(|a| a.first())
    else {
        return out;
    };
    let delta = choice.get("delta").cloned().unwrap_or(json!({}));
    for key in ["content", "reasoning", "reasoning_content"] {
        if let Some(text) = delta.get(key).and_then(|v| v.as_str()) {
            out.push_str(text);
        }
    }
    out
}

fn append_plain_completion_text(text: &mut String, plain: &[u8]) -> Result<(), ApiError> {
    if let Ok(piece) = std::str::from_utf8(plain) {
        if let Ok(v) = serde_json::from_str::<Value>(piece) {
            if v.get("type").and_then(|t| t.as_str()) == Some("openai_delta") {
                text.push_str(&completion_text_from_openai_delta_frame(&v));
                return Ok(());
            }
        }
        text.push_str(piece);
        return Ok(());
    }
    let valid = std::str::from_utf8(plain)
        .err()
        .map(|e| e.valid_up_to())
        .unwrap_or(0);
    if valid > 0 {
        text.push_str(std::str::from_utf8(&plain[..valid]).map_err(|e| {
            ApiError::Upstream(format!("ope plaintext invalid utf8: {e}"))
        })?);
    }
    if valid < plain.len() {
        return Err(ApiError::Upstream("ope plaintext invalid utf8".into()));
    }
    Ok(())
}

fn openai_sse_from_structured_delta(
    id: &str,
    model: &str,
    delta: &Value,
    finish: Option<&str>,
) -> Option<String> {
    let delta_empty = delta.as_object().is_none_or(|o| o.is_empty());
    if delta_empty && finish.is_none() {
        return None;
    }
    let mut out_delta = json!({});
    if let Some(content) = delta.get("content").and_then(|v| v.as_str()) {
        if !content.is_empty() {
            out_delta["content"] = json!(content);
        }
    }
    for key in ["reasoning_content", "reasoning"] {
        if let Some(reasoning) = delta.get(key).and_then(|v| v.as_str()) {
            if !reasoning.is_empty() {
                out_delta["reasoning_content"] = json!(reasoning);
                break;
            }
        }
    }
    if let Some(tool_calls) = delta.get("tool_calls") {
        out_delta["tool_calls"] = tool_calls.clone();
    }
    Some(
        json!({
            "id": id,
            "object": "chat.completion.chunk",
            "created": 1_700_000_000,
            "model": model,
            "choices": [{
                "index": 0,
                "delta": out_delta,
                "finish_reason": finish
            }]
        })
        .to_string(),
    )
}

fn emit_openai_delta_frame(
    frame: &Value,
    id: &str,
    model: &str,
    out: &mut dyn Write,
    written: &mut u64,
    saw_finish: &mut bool,
) -> Result<(), ApiError> {
    let Some(choice) = frame
        .get("choices")
        .and_then(|c| c.as_array())
        .and_then(|a| a.first())
    else {
        return Ok(());
    };
    let delta = choice.get("delta").cloned().unwrap_or(json!({}));
    let finish = choice
        .get("finish_reason")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty() && !s.eq_ignore_ascii_case("null"));
    if finish.is_some() {
        *saw_finish = true;
    }
    if let Some(chunk) = openai_sse_from_structured_delta(id, model, &delta, finish) {
        *written += write_sse(out, &chunk)?;
    }
    Ok(())
}

fn process_decrypted_plaintext(
    plain: &[u8],
    acc: &mut Utf8PlainAccumulator,
    id: &str,
    model: &str,
    out: &mut dyn Write,
    written: &mut u64,
    saw_finish: &mut bool,
) -> Result<(), ApiError> {
    if let Ok(text) = std::str::from_utf8(plain) {
        if let Ok(v) = serde_json::from_str::<Value>(text) {
            if v.get("type").and_then(|t| t.as_str()) == Some("openai_delta") {
                return emit_openai_delta_frame(&v, id, model, out, written, saw_finish);
            }
        }
    }
    for piece in acc.push(plain)? {
        if piece.is_empty() {
            continue;
        }
        if let Ok(v) = serde_json::from_str::<Value>(&piece) {
            if v.get("type").and_then(|t| t.as_str()) == Some("openai_delta") {
                emit_openai_delta_frame(&v, id, model, out, written, saw_finish)?;
                continue;
            }
        }
        *written += write_sse(out, &openai_sse_delta(&id, model, &piece, None))?;
    }
    Ok(())
}

fn decrypt_ope_body_to_text(
    enc: &EncryptedOpeRequest,
    raw: &[u8],
    content_type: &str,
) -> Result<String, ApiError> {
    if content_type.contains("ope+json-stream") || looks_like_ope_ndjson(raw) {
        return decrypt_ndjson_to_text(enc, raw);
    }
    // Buffered OPE JSON: { server_share, chunks: [] }
    let v: Value = serde_json::from_slice(raw)
        .map_err(|e| ApiError::Upstream(format!("ope body json: {e}")))?;
    if let Some(share) = v.get("server_share").and_then(|x| x.as_str()) {
        let chunks = v
            .get("chunks")
            .and_then(|x| x.as_array())
            .cloned()
            .unwrap_or_default();
        let mut text = String::new();
        for (i, c) in chunks.iter().enumerate() {
            let ct = c
                .as_str()
                .ok_or_else(|| ApiError::Upstream("ope chunk not string".into()))?;
            let plain = decrypt_chunk(&enc.envelope, &enc.client_session, share, i as u32, ct)
                .map_err(|e| ApiError::Upstream(e.to_string()))?;
            append_plain_completion_text(&mut text, &plain)?;
        }
        return Ok(text);
    }
    Err(ApiError::Upstream(
        "unexpected ope response shape (expected stream or server_share/chunks)".into(),
    ))
}

fn looks_like_ope_ndjson(raw: &[u8]) -> bool {
    let s = String::from_utf8_lossy(raw);
    s.lines().any(|l| l.contains("\"ope_stream\""))
}

fn decrypt_ndjson_to_text(enc: &EncryptedOpeRequest, raw: &[u8]) -> Result<String, ApiError> {
    let mut server_share = String::new();
    let mut text = String::new();
    for line in String::from_utf8_lossy(raw).lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let Ok(v) = serde_json::from_str::<Value>(trimmed) else {
            continue;
        };
        if v.get("ope_stream").and_then(|x| x.as_str()) != Some("1.0") {
            continue;
        }
        if let Some(share) = v.get("server_share").and_then(|x| x.as_str()) {
            server_share = share.to_string();
            continue;
        }
        if let (Some(seq), Some(ct)) = (
            v.get("seq").and_then(|x| x.as_u64()),
            v.get("ciphertext").and_then(|x| x.as_str()),
        ) {
            if server_share.is_empty() {
                return Err(ApiError::Upstream(
                    "ope ciphertext before server_share".into(),
                ));
            }
            let plain = decrypt_chunk(
                &enc.envelope,
                &enc.client_session,
                &server_share,
                seq as u32,
                ct,
            )
            .map_err(|e| ApiError::Upstream(e.to_string()))?;
            append_plain_completion_text(&mut text, &plain)?;
        }
    }
    Ok(text)
}

fn bridge_ope_to_openai_sse(
    enc: &EncryptedOpeRequest,
    reader: &mut dyn Read,
    content_type: &str,
    model: &str,
    out: &mut dyn Write,
) -> Result<u64, ApiError> {
    let id = format!("chatcmpl-{}", uuid_like());
    let mut written = 0u64;
    let mut server_share = String::new();
    let mut legacy_acc = Utf8PlainAccumulator::new();
    let mut saw_finish = false;

    if content_type.contains("ope+json-stream") || content_type.is_empty() {
        let mut buf_reader = BufReader::new(reader);
        let mut line = String::new();
        loop {
            line.clear();
            let n = buf_reader
                .read_line(&mut line)
                .map_err(|e| ApiError::Upstream(e.to_string()))?;
            if n == 0 {
                break;
            }
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }
            let Ok(v) = serde_json::from_str::<Value>(trimmed) else {
                continue;
            };
            if v.get("ope_stream").and_then(|x| x.as_str()) != Some("1.0") {
                continue;
            }
            if v.get("type").and_then(|x| x.as_str()) == Some("trailer") {
                continue;
            }
            if let Some(share) = v.get("server_share").and_then(|x| x.as_str()) {
                server_share = share.to_string();
                continue;
            }
            if let (Some(seq), Some(ct)) = (
                v.get("seq").and_then(|x| x.as_u64()),
                v.get("ciphertext").and_then(|x| x.as_str()),
            ) {
                if server_share.is_empty() {
                    return Err(ApiError::Upstream(
                        "ope ciphertext before server_share".into(),
                    ));
                }
                let plain = decrypt_chunk(
                    &enc.envelope,
                    &enc.client_session,
                    &server_share,
                    seq as u32,
                    ct,
                )
                .map_err(|e| ApiError::Upstream(e.to_string()))?;
                if plain.is_empty() {
                    continue;
                }
                process_decrypted_plaintext(
                    &plain,
                    &mut legacy_acc,
                    &id,
                    model,
                    out,
                    &mut written,
                    &mut saw_finish,
                )?;
            }
        }
        if let Some(tail) = legacy_acc.finish()? {
            if !tail.is_empty() {
                if let Ok(v) = serde_json::from_str::<Value>(&tail) {
                    if v.get("type").and_then(|t| t.as_str()) == Some("openai_delta") {
                        emit_openai_delta_frame(&v, &id, model, out, &mut written, &mut saw_finish)?;
                    } else {
                        written += write_sse(out, &openai_sse_delta(&id, model, &tail, None))?;
                    }
                } else {
                    written += write_sse(out, &openai_sse_delta(&id, model, &tail, None))?;
                }
            }
        }
    } else {
        let mut raw = Vec::new();
        reader
            .read_to_end(&mut raw)
            .map_err(|e| ApiError::Upstream(e.to_string()))?;
        let text = decrypt_ope_body_to_text(enc, &raw, content_type)?;
        if !text.is_empty() {
            written += write_sse(out, &openai_sse_delta(&id, model, &text, None))?;
        }
    }

    if !saw_finish {
        written += write_sse(out, &openai_sse_delta(&id, model, "", Some("stop")))?;
    }
    written += write_all_count(out, b"data: [DONE]\n\n")?;
    Ok(written)
}

fn write_sse(out: &mut dyn Write, data: &str) -> Result<u64, ApiError> {
    let line = format!("data: {data}\n\n");
    write_all_count(out, line.as_bytes())
}

fn write_all_count(out: &mut dyn Write, bytes: &[u8]) -> Result<u64, ApiError> {
    out.write_all(bytes)
        .map_err(|e| ApiError::Upstream(e.to_string()))?;
    Ok(bytes.len() as u64)
}

fn openai_sse_delta(id: &str, model: &str, content: &str, finish: Option<&str>) -> String {
    let mut delta = json!({});
    if !content.is_empty() {
        delta["content"] = json!(content);
    }
    json!({
        "id": id,
        "object": "chat.completion.chunk",
        "created": 1_700_000_000,
        "model": model,
        "choices": [{
            "index": 0,
            "delta": delta,
            "finish_reason": finish
        }]
    })
    .to_string()
}

fn openai_chat_completion_json(
    model: &str,
    text: &str,
    prompt_tokens: u64,
    completion_tokens: u64,
) -> Value {
    json!({
        "id": format!("chatcmpl-{}", uuid_like()),
        "object": "chat.completion",
        "created": 1_700_000_000,
        "model": model,
        "choices": [{
            "index": 0,
            "message": { "role": "assistant", "content": text },
            "finish_reason": "stop"
        }],
        "usage": {
            "prompt_tokens": prompt_tokens,
            "completion_tokens": completion_tokens,
            "total_tokens": prompt_tokens + completion_tokens
        }
    })
}

/// `google/gemma-4-31B-it@teechat` → `google/gemma-4-31B-it` (inventory / vLLM ids).
fn strip_model_provider_suffix(model: &str) -> String {
    match model.rfind('@') {
        Some(at) => model[..at].to_string(),
        None => model.to_string(),
    }
}

struct UsageMeterCtx<'a> {
    engine_id: &'a str,
    epoch_id: &'a str,
    verify_key: &'a str,
}

fn resolve_usage_or_estimate(
    usage_hdr: Option<&str>,
    request_body: &[u8],
    completion_text: &str,
    meter: Option<UsageMeterCtx<'_>>,
) -> Result<(u64, u64), ApiError> {
    let require = require_signed_usage_from_env();
    if !require {
        return resolve_usage_tokens(usage_hdr, request_body, completion_text, false, None)
            .map_err(|e| ApiError::BadRequest(e.to_string()));
    }
    let meter = meter.ok_or_else(|| {
        ApiError::BadRequest("engine usage verify context missing (RB-37)".into())
    })?;
    let hash = request_body_hash_hex(request_body);
    let bound = independent_token_bound(request_body, completion_text);
    let ctx = UsageVerifyContext {
        expected_engine_id: meter.engine_id,
        expected_epoch_id: meter.epoch_id,
        verify_key_b64url: meter.verify_key,
        expected_request_hash_hex: &hash,
        max_total_tokens: bound,
    };
    resolve_usage_tokens(usage_hdr, request_body, completion_text, true, Some(&ctx))
        .map_err(|e| ApiError::BadRequest(e.to_string()))
}

fn uuid_like() -> String {
    use rand::RngCore;
    let mut b = [0u8; 8];
    rand::thread_rng().fill_bytes(&mut b);
    hex::encode(b)
}

#[cfg(test)]
mod trust_tests {
    use super::*;
    use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
    use base64::Engine;
    use ed25519_dalek::{Signer, SigningKey};
    use openapi_platform::{
        bind_epoch_report_data_64, compose_launch_digest, ephemeral_signing_bytes,
        EngineIdentityPins, EphemeralEngineTrust, QuoteEpochClaims,
    };

    const MLKEM: &str = "bWxrZW0";
    const X25519: &str = "eDI1NTE5";
    const NOT_BEFORE: &str = "2020-01-01T00:00:00.000Z";
    const NOT_AFTER: &str = "2099-01-01T00:00:00.000Z";
    const ISSUED_AT: &str = "2026-07-31T00:00:00.000Z";
    const TLS_HASH: &str = "cc";
    const REPORT_DATA_OFFSET: usize = 0x50;
    const MEASUREMENT_OFFSET: usize = 0x90;

    fn epoch_claims() -> QuoteEpochClaims {
        QuoteEpochClaims {
            engine_id: "engine-1".into(),
            epoch_id: "epoch-1".into(),
            not_before: NOT_BEFORE.into(),
            not_after: NOT_AFTER.into(),
            mlkem_encapsulation_key: MLKEM.into(),
            x25519_public: X25519.into(),
            usage_signing_public: "dXNhZ2U".into(),
        }
    }

    fn golden_launch_digest() -> String {
        compose_launch_digest(&"ab".repeat(48))
    }

    /// A wrapper shaped like the one the engine emits, minus the AMD signature.
    fn epoch_quote(claims: &QuoteEpochClaims) -> String {
        let mut report = vec![0u8; 1184];
        report[MEASUREMENT_OFFSET..MEASUREMENT_OFFSET + 48].copy_from_slice(&[0xab; 48]);
        let report_data =
            bind_epoch_report_data_64(claims, TLS_HASH, "", "", ISSUED_AT, None).to_vec();
        report[REPORT_DATA_OFFSET..REPORT_DATA_OFFSET + 64].copy_from_slice(&report_data);
        URL_SAFE_NO_PAD.encode(
            serde_json::to_vec(&json!({
                "v": 2,
                "kind": "sev-snp",
                "report_b64": STANDARD.encode(&report),
                "report_data_b64": STANDARD.encode(&report_data),
                "claims": {
                    "v": 1,
                    "kind": "sev-snp",
                    "ed25519_public": "aWQ",
                    "tls_client_cert_sha256": TLS_HASH,
                    "engine": { "version": "0.12.1", "binary_sha256": "" },
                    "vllm": { "version": "v1", "binary_sha256": "" },
                    "issued_at": ISSUED_AT,
                    "epoch": claims,
                },
            }))
            .unwrap(),
        )
    }

    fn preassign(quote: Option<String>, signing_key: &SigningKey) -> PreassignResponse {
        let public = URL_SAFE_NO_PAD.encode(signing_key.verifying_key().to_bytes());
        let unsigned = EphemeralEngineTrust {
            engine_id: "engine-1",
            epoch_id: "epoch-1",
            not_before: NOT_BEFORE,
            not_after: NOT_AFTER,
            mlkem_encapsulation_key: MLKEM,
            x25519_public: X25519,
            ed25519_public: &public,
            identity_signature: "",
        };
        let signature = URL_SAFE_NO_PAD.encode(
            signing_key
                .sign(&ephemeral_signing_bytes(&unsigned))
                .to_bytes(),
        );
        PreassignResponse {
            assign_id: "assign-1".into(),
            engine_id: "engine-1".into(),
            engine_set: "shared".into(),
            key_set: "api".into(),
            openapi_key_id: "key-1".into(),
            expires_at_ms: u64::MAX,
            ttl_ms: 15_000,
            trust: crate::gateway_ope_api::PreassignTrust {
                engine_id: "engine-1".into(),
                epoch_id: "epoch-1".into(),
                not_before: NOT_BEFORE.into(),
                not_after: NOT_AFTER.into(),
                hybrid: crate::gateway_ope_api::PreassignTrustHybrid {
                    kex: "X25519MLKEM768".into(),
                    mlkem_encapsulation_key: MLKEM.into(),
                    x25519_public: X25519.into(),
                },
                identity: crate::gateway_ope_api::PreassignTrustIdentity {
                    ed25519_public: public,
                    identity_signature: signature,
                },
                attestation: quote.map(|q| crate::gateway_ope_api::PreassignTrustAttestation {
                    cpu_tee: Some(crate::gateway_ope_api::PreassignTrustCpuTee {
                        kind: "sev-snp".into(),
                        quote: q,
                    }),
                }),
            },
        }
    }

    fn upstream_with(policy: EngineRecipientPolicy) -> OpeDispatchUpstream {
        let _g = crate::TEST_ENV_LOCK
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        // openapi-platform is linked without cfg(test), so challenge defaults on;
        // unit fixtures have no F′ challenge server.
        std::env::set_var("OPENAPI_OPE_REQUIRE_ENGINE_CHALLENGE", "0");
        std::env::remove_var("OPENAPI_SEALED_TIME");
        std::env::remove_var("OPENAPI_REQUIRE_SIGNED_USAGE");
        let mut config =
            GatewayOpeApiConfig::from_parts("http://127.0.0.1:1", None, None, None, None, false)
                .unwrap();
        config.engine_identity_pins = policy.identity_pins.clone();
        config.recipient_policy = policy;
        OpeDispatchUpstream::try_new(config).unwrap()
    }

    fn inventory_engine() -> InventoryEngine {
        InventoryEngine {
            engine_id: "engine-1".into(),
            engine_set: "shared".into(),
            models: vec!["m1".into()],
            healthy: true,
            ready_sessions: 1,
        }
    }

    fn ctx() -> UpstreamRequestContext {
        UpstreamRequestContext {
            key_id: "key-1".into(),
            key_set: "api".into(),
        }
    }

    fn legacy_policy(key: &SigningKey) -> EngineRecipientPolicy {
        let public = URL_SAFE_NO_PAD.encode(key.verifying_key().to_bytes());
        EngineRecipientPolicy {
            identity_pins: EngineIdentityPins::parse_json(&format!(r#"{{"engine-1":"{public}"}}"#))
                .unwrap(),
            epoch_clock_skew_ms: 300_000,
            ..Default::default()
        }
    }

    fn strict_policy() -> EngineRecipientPolicy {
        EngineRecipientPolicy {
            require_epoch_evidence: true,
            require_launch_digest: true,
            launch_digest_allowlist: [golden_launch_digest()].into_iter().collect(),
            epoch_clock_skew_ms: 300_000,
            ..Default::default()
        }
    }

    /// Legacy fixture: pinned identity, no epoch evidence. Kept until the fleet
    /// is cut over so a regression in the compatibility path is visible.
    fn fixture() -> (
        OpeDispatchUpstream,
        PreassignResponse,
        InventoryEngine,
        UpstreamRequestContext,
    ) {
        let key = SigningKey::from_bytes(&[9u8; 32]);
        (
            upstream_with(legacy_policy(&key)),
            preassign(None, &key),
            inventory_engine(),
            ctx(),
        )
    }

    #[test]
    fn preassign_verification_binds_assignment_inventory_and_signature() {
        let (upstream, pre, engine, ctx) = fixture();
        upstream.verify_preassign(&pre, &engine, &ctx).unwrap();
    }

    #[test]
    fn preassign_verification_rejects_stale_substitution_and_mismatch() {
        let (upstream, mut pre, engine, ctx) = fixture();
        pre.expires_at_ms = 0;
        assert!(matches!(
            upstream.verify_preassign(&pre, &engine, &ctx),
            Err(ApiError::Forbidden(_))
        ));

        let (upstream, mut pre, engine, ctx) = fixture();
        pre.trust.hybrid.x25519_public = "substituted".into();
        assert!(matches!(
            upstream.verify_preassign(&pre, &engine, &ctx),
            Err(ApiError::Forbidden(_))
        ));

        let (upstream, mut pre, engine, ctx) = fixture();
        pre.key_set = "wrong".into();
        assert!(matches!(
            upstream.verify_preassign(&pre, &engine, &ctx),
            Err(ApiError::Forbidden(_))
        ));
    }

    #[test]
    fn accepts_a_preassignment_backed_by_per_epoch_evidence() {
        let key = SigningKey::from_bytes(&[9u8; 32]);
        let claims = epoch_claims();
        let upstream = upstream_with(strict_policy());
        upstream
            .verify_preassign(
                &preassign(Some(epoch_quote(&claims)), &key),
                &inventory_engine(),
                &ctx(),
            )
            .expect("accepted");
    }

    #[test]
    fn refuses_recipient_keys_the_report_does_not_name() {
        // A relay that keeps the engine's real report but swaps the keys the
        // edge would encrypt to is the whole reason the edge re-derives this.
        let key = SigningKey::from_bytes(&[9u8; 32]);
        let claims = epoch_claims();
        let mut pre = preassign(Some(epoch_quote(&claims)), &key);
        pre.trust.hybrid.x25519_public = "relay-key".into();
        let err = upstream_with(strict_policy())
            .verify_preassign(&pre, &inventory_engine(), &ctx())
            .unwrap_err();
        assert!(
            matches!(&err, ApiError::Forbidden(m) if m.contains("X25519")),
            "unexpected error: {err:?}"
        );
    }

    #[test]
    fn refuses_an_engine_image_outside_the_allowlist() {
        let key = SigningKey::from_bytes(&[9u8; 32]);
        let claims = epoch_claims();
        let mut policy = strict_policy();
        policy.launch_digest_allowlist = [compose_launch_digest(&"00".repeat(48))]
            .into_iter()
            .collect();
        let err = upstream_with(policy)
            .verify_preassign(
                &preassign(Some(epoch_quote(&claims)), &key),
                &inventory_engine(),
                &ctx(),
            )
            .unwrap_err();
        assert!(
            matches!(&err, ApiError::Forbidden(m) if m.contains("not allowlisted")),
            "unexpected error: {err:?}"
        );
    }

    #[test]
    fn refuses_a_pin_only_preassignment_once_epoch_evidence_is_required() {
        let key = SigningKey::from_bytes(&[9u8; 32]);
        let mut policy = strict_policy();
        policy.identity_pins = legacy_policy(&key).identity_pins;
        let err = upstream_with(policy)
            .verify_preassign(&preassign(None, &key), &inventory_engine(), &ctx())
            .unwrap_err();
        assert!(
            matches!(&err, ApiError::Forbidden(m) if m.contains("launch measurement")),
            "unexpected error: {err:?}"
        );
    }

    #[test]
    fn chain_verification_is_skipped_when_disabled_and_cached_once_verified() {
        let upstream = upstream_with(strict_policy());
        assert!(upstream
            .verify_report_chain("not-a-real-report", Some(b"untrusted-vcek"))
            .is_ok());
    }

    #[test]
    fn chain_verification_refuses_an_unverifiable_report_when_enabled() {
        let mut config =
            GatewayOpeApiConfig::from_parts("http://127.0.0.1:1", None, None, None, None, false)
                .unwrap();
        config.recipient_policy = strict_policy();
        config.verify_engine_snp_chain = true;
        let upstream = OpeDispatchUpstream::try_new(config).unwrap();
        assert!(matches!(
            upstream.verify_report_chain(&STANDARD.encode([0u8; 1184]), Some(b"invalid-vcek")),
            Err(ApiError::Forbidden(_))
        ));
    }

    #[test]
    fn openai_delta_sse_maps_tool_calls_and_reasoning() {
        let frame = json!({
            "type": "openai_delta",
            "choices": [{
                "index": 0,
                "delta": {
                    "reasoning": "plan",
                    "tool_calls": [{
                        "index": 0,
                        "id": "call_1",
                        "type": "function",
                        "function": { "name": "get_weather", "arguments": "{}" }
                    }]
                },
                "finish_reason": null
            }]
        });
        let sse = openai_sse_from_structured_delta(
            "chatcmpl-test",
            "Qwen/Qwen3.6-35B-A3B",
            &frame["choices"][0]["delta"],
            None,
        )
        .unwrap();
        assert!(sse.contains("\"reasoning_content\":\"plan\""));
        assert!(sse.contains("\"tool_calls\""));
        assert!(sse.contains("get_weather"));
    }

    #[test]
    fn utf8_accumulator_splits_emoji_without_replacement() {
        let mut acc = Utf8PlainAccumulator::new();
        let bytes = "💡综合".as_bytes();
        let (head, tail) = bytes.split_at(2);
        let parts = acc.push(head).unwrap();
        assert!(parts.is_empty());
        let parts = acc.push(tail).unwrap();
        assert_eq!(parts.join(""), "💡综合");
    }

    #[test]
    fn ope_bridge_openai_sse_has_no_client_metering() {
        let finish = openai_sse_delta("chatcmpl-test", "Qwen/Qwen3.6-35B-A3B", "", Some("stop"));
        assert!(!finish.contains("teechat_usage"));
        assert!(!finish.contains("\"usage\""));
        let mut out = Vec::new();
        write_sse(&mut out, &finish).unwrap();
        write_all_count(&mut out, b"data: [DONE]\n\n").unwrap();
        let text = String::from_utf8(out).unwrap();
        assert!(text.contains("[DONE]"));
        assert!(!text.contains("teechat_usage"));
        assert!(!text.contains("X-TeeChat-Usage-Report"));
    }
}
