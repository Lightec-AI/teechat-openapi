//! Edge upstream selection — hard OPE cutover (clear HTTP only as break-glass).

use openapi_core::authz::OpenApiKeyPolicy;
use openapi_core::error::ApiError;
use openapi_core::handler::{
    HttpMethod, StreamForwardResult, UpstreamForwarder, UpstreamRequestContext, UpstreamResponse,
};
use openapi_core::models::ModelsListResponse;
use openapi_platform::EdgeProfile;
use tracing::{info, warn};

use crate::{
    clear_http_break_glass_enabled, require_gateway_ope_api_healthy, OpeDispatchUpstream,
    UreqUpstream,
};

pub enum EdgeUpstream {
    Ope(OpeDispatchUpstream),
    Clear(UreqUpstream),
}

impl EdgeUpstream {
    /// Prod: require F′ OPE. Clear HTTP only when `OPENAPI_UPSTREAM_CLEAR_HTTP=1` and not prod.
    pub fn from_env(profile: EdgeProfile, clear_base_url: &str) -> anyhow::Result<Self> {
        let break_glass = clear_http_break_glass_enabled();
        if break_glass && profile.is_prod() {
            anyhow::bail!("OPENAPI_UPSTREAM_CLEAR_HTTP forbidden when OPENAPI_PROFILE=prod");
        }
        if break_glass {
            warn!("OPENAPI_UPSTREAM_CLEAR_HTTP=1 — using clear HTTP upstream (break-glass)");
            return Ok(Self::Clear(UreqUpstream::new(clear_base_url)));
        }

        match OpeDispatchUpstream::from_env() {
            Ok(Some(ope)) => match require_gateway_ope_api_healthy(profile) {
                Ok(()) => {
                    info!("using F′ OPE dispatch upstream (hard cutover)");
                    Ok(Self::Ope(ope))
                }
                Err(e) if profile.is_prod() => Err(e.into()),
                Err(e) => {
                    warn!(error = %e, "F′ health failed — clear HTTP fallback (dev)");
                    Ok(Self::Clear(UreqUpstream::new(clear_base_url)))
                }
            },
            Ok(None) if profile.is_prod() => {
                anyhow::bail!(
                    "OPENAPI_GATEWAY_OPE_API_URL required in prod (hard OPE cutover); \
                     set URL or OPENAPI_UPSTREAM_CLEAR_HTTP=1 only in non-prod"
                );
            }
            Ok(None) => {
                warn!(
                    "OPENAPI_GATEWAY_OPE_API_URL unset — falling back to clear HTTP upstream (dev)"
                );
                Ok(Self::Clear(UreqUpstream::new(clear_base_url)))
            }
            Err(e) if profile.is_prod() => Err(e.into()),
            Err(e) => {
                warn!(error = %e, "OPE upstream config failed — clear HTTP fallback (dev)");
                Ok(Self::Clear(UreqUpstream::new(clear_base_url)))
            }
        }
    }
}

impl UpstreamForwarder for EdgeUpstream {
    fn forward_v1(
        &self,
        method: HttpMethod,
        path: &str,
        body: Option<&[u8]>,
    ) -> Result<UpstreamResponse, ApiError> {
        match self {
            Self::Ope(u) => u.forward_v1(method, path, body),
            Self::Clear(u) => u.forward_v1(method, path, body),
        }
    }

    fn forward_v1_ctx(
        &self,
        method: HttpMethod,
        path: &str,
        body: Option<&[u8]>,
        ctx: &UpstreamRequestContext,
    ) -> Result<UpstreamResponse, ApiError> {
        match self {
            Self::Ope(u) => u.forward_v1_ctx(method, path, body, ctx),
            Self::Clear(u) => u.forward_v1_ctx(method, path, body, ctx),
        }
    }

    fn forward_v1_stream(
        &self,
        method: HttpMethod,
        path: &str,
        body: Option<&[u8]>,
        out: &mut dyn std::io::Write,
    ) -> Result<StreamForwardResult, ApiError> {
        match self {
            Self::Ope(u) => u.forward_v1_stream(method, path, body, out),
            Self::Clear(u) => u.forward_v1_stream(method, path, body, out),
        }
    }

    fn forward_v1_stream_ctx(
        &self,
        method: HttpMethod,
        path: &str,
        body: Option<&[u8]>,
        ctx: &UpstreamRequestContext,
        out: &mut dyn std::io::Write,
    ) -> Result<StreamForwardResult, ApiError> {
        match self {
            Self::Ope(u) => u.forward_v1_stream_ctx(method, path, body, ctx, out),
            Self::Clear(u) => u.forward_v1_stream_ctx(method, path, body, ctx, out),
        }
    }

    fn list_models(&self) -> Result<ModelsListResponse, ApiError> {
        match self {
            Self::Ope(u) => u.list_models(),
            Self::Clear(u) => u.list_models(),
        }
    }

    fn list_models_for_key(
        &self,
        ctx: &UpstreamRequestContext,
        policy: &OpenApiKeyPolicy,
    ) -> Result<ModelsListResponse, ApiError> {
        match self {
            Self::Ope(u) => u.list_models_for_key(ctx, policy),
            Self::Clear(u) => u.list_models_for_key(ctx, policy),
        }
    }
}
