use crate::handler::HttpMethod;

/// How unknown `/v1/*` paths are treated after the explicit allowlist / denylist.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ProxyMode {
    /// Only explicitly classified OpenAI-compatible routes (default; prod-required).
    #[default]
    Allowlist,
    /// Dev/lab: authenticate then forward unknown `/v1/*` (except denylist).
    Transparent,
}

impl ProxyMode {
    /// Parse `OPENAPI_PROXY_MODE` (`allowlist` default; empty → allowlist).
    pub fn parse(raw: Option<&str>) -> Result<Self, String> {
        match raw.map(str::trim).filter(|s| !s.is_empty()) {
            None => Ok(Self::Allowlist),
            Some(s) if s.eq_ignore_ascii_case("allowlist") || s.eq_ignore_ascii_case("deny") => {
                Ok(Self::Allowlist)
            }
            Some(s) if s.eq_ignore_ascii_case("transparent") || s.eq_ignore_ascii_case("proxy") => {
                Ok(Self::Transparent)
            }
            Some(other) => Err(format!(
                "unknown OPENAPI_PROXY_MODE={other:?}; use allowlist|transparent"
            )),
        }
    }
}

/// How the edge handles an HTTP route.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RouteAction {
    Health,
    Attestation,
    ModelsList,
    /// OpenAI inference POST with usage metering (chat, completions, embeddings, …).
    InferencePost,
    /// Authenticated transparent GET proxy under `/v1/` (transparent mode only).
    ProxyGet,
    /// Authenticated transparent POST proxy under `/v1/` (transparent mode only).
    ProxyPost,
    /// Durable OpenAI control-plane APIs we do not implement (501).
    NotImplemented(&'static str),
    MethodNotAllowed,
    NotFound,
}

/// Strip query/fragment, trim a trailing slash (except `/`), reject `..` traversal.
///
/// ROUTE-001: classify must not treat `?…` / trailing `/` as a distinct route that falls
/// through to transparent proxy.
pub fn normalize_path(raw: &str) -> Result<String, RouteAction> {
    let without_qf = raw.split(['?', '#']).next().unwrap_or(raw);
    if without_qf.is_empty() || !without_qf.starts_with('/') {
        return Err(RouteAction::NotFound);
    }
    // Reject path traversal before collapsing dots would matter.
    if without_qf.split('/').any(|seg| seg == "..") {
        return Err(RouteAction::NotFound);
    }
    let mut path = without_qf.to_string();
    while path.len() > 1 && path.ends_with('/') {
        path.pop();
    }
    Ok(path)
}

/// Classify a normalized path. Default mode is [`ProxyMode::Allowlist`] (PROXY-001).
pub fn classify(method: HttpMethod, path: &str, mode: ProxyMode) -> RouteAction {
    let path = match normalize_path(path) {
        Ok(p) => p,
        Err(action) => return action,
    };

    match path.as_str() {
        "/healthz" if method == HttpMethod::Get => RouteAction::Health,
        "/v1/attestation/challenge" => match method {
            HttpMethod::Post => RouteAction::Attestation,
            _ => RouteAction::MethodNotAllowed,
        },
        "/v1/models" if method == HttpMethod::Get => RouteAction::ModelsList,
        "/v1/chat/completions" => match method {
            HttpMethod::Post => RouteAction::InferencePost,
            _ => RouteAction::MethodNotAllowed,
        },
        "/v1/completions" | "/v1/embeddings" | "/v1/responses" | "/v1/moderations"
            if method == HttpMethod::Post =>
        {
            RouteAction::InferencePost
        }
        p if p.starts_with("/v1/") => {
            if let Some(reason) = not_implemented_reason(p) {
                return RouteAction::NotImplemented(reason);
            }
            match mode {
                ProxyMode::Allowlist => RouteAction::NotFound,
                ProxyMode::Transparent => match method {
                    HttpMethod::Get => RouteAction::ProxyGet,
                    HttpMethod::Post => RouteAction::ProxyPost,
                    HttpMethod::Other => RouteAction::MethodNotAllowed,
                },
            }
        }
        _ => RouteAction::NotFound,
    }
}

fn not_implemented_reason(path: &str) -> Option<&'static str> {
    const BLOCKED: &[(&str, &str)] = &[
        (
            "/v1/fine_tuning",
            "fine-tuning jobs require durable storage; not supported on the edge",
        ),
        (
            "/v1/fine-tuning",
            "fine-tuning jobs require durable storage; not supported on the edge",
        ),
        (
            "/v1/assistants",
            "Assistants API requires durable thread storage; not supported on the edge",
        ),
        (
            "/v1/threads",
            "Assistants API requires durable thread storage; not supported on the edge",
        ),
        (
            "/v1/files",
            "file uploads require durable storage; not supported on the edge",
        ),
        (
            "/v1/batches",
            "batch jobs require durable storage; not supported on the edge",
        ),
        (
            "/v1/vector_stores",
            "vector stores require durable storage; not supported on the edge",
        ),
        (
            "/v1/uploads",
            "upload sessions require durable storage; not supported on the edge",
        ),
        ("/v1/audio", "audio APIs are not yet supported on the edge"),
        (
            "/v1/images",
            "image generation APIs are not yet supported on the edge",
        ),
        (
            "/v1/videos",
            "video generation APIs are not yet supported on the edge",
        ),
        (
            "/v1/realtime",
            "realtime sessions require durable WebSocket state; not supported on the edge",
        ),
        (
            "/v1/containers",
            "container APIs are not supported on the edge",
        ),
    ];
    BLOCKED
        .iter()
        .find(|(prefix, _)| path.starts_with(prefix))
        .map(|(_, reason)| *reason)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inference_routes_classified() {
        for path in [
            "/v1/chat/completions",
            "/v1/completions",
            "/v1/embeddings",
            "/v1/responses",
            "/v1/moderations",
        ] {
            assert_eq!(
                classify(HttpMethod::Post, path, ProxyMode::Allowlist),
                RouteAction::InferencePost,
                "{path}"
            );
        }
    }

    #[test]
    fn durable_apis_return_not_implemented() {
        assert!(matches!(
            classify(HttpMethod::Post, "/v1/files", ProxyMode::Allowlist),
            RouteAction::NotImplemented(_)
        ));
        assert!(matches!(
            classify(HttpMethod::Post, "/v1/batches", ProxyMode::Allowlist),
            RouteAction::NotImplemented(_)
        ));
    }

    #[test]
    fn allowlist_rejects_unknown_v1() {
        assert_eq!(
            classify(HttpMethod::Get, "/v1/models/gpt-4", ProxyMode::Allowlist),
            RouteAction::NotFound
        );
        assert_eq!(
            classify(
                HttpMethod::Post,
                "/v1/some/future/route",
                ProxyMode::Allowlist
            ),
            RouteAction::NotFound
        );
    }

    #[test]
    fn transparent_still_proxies_unknown_v1() {
        assert_eq!(
            classify(HttpMethod::Get, "/v1/models/gpt-4", ProxyMode::Transparent),
            RouteAction::ProxyGet
        );
        assert_eq!(
            classify(
                HttpMethod::Post,
                "/v1/some/future/route",
                ProxyMode::Transparent
            ),
            RouteAction::ProxyPost
        );
    }

    #[test]
    fn normalize_strips_query_and_trailing_slash() {
        assert_eq!(
            classify(
                HttpMethod::Post,
                "/v1/chat/completions?stream=true",
                ProxyMode::Allowlist
            ),
            RouteAction::InferencePost
        );
        assert_eq!(
            classify(
                HttpMethod::Post,
                "/v1/chat/completions/",
                ProxyMode::Allowlist
            ),
            RouteAction::InferencePost
        );
        assert_eq!(
            classify(HttpMethod::Get, "/v1/models/", ProxyMode::Allowlist),
            RouteAction::ModelsList
        );
    }

    #[test]
    fn path_traversal_is_not_found() {
        assert_eq!(
            classify(HttpMethod::Get, "/v1/../etc/passwd", ProxyMode::Transparent),
            RouteAction::NotFound
        );
    }

    #[test]
    fn proxy_mode_parse() {
        assert_eq!(ProxyMode::parse(None).unwrap(), ProxyMode::Allowlist);
        assert_eq!(
            ProxyMode::parse(Some("transparent")).unwrap(),
            ProxyMode::Transparent
        );
        assert!(ProxyMode::parse(Some("weird")).is_err());
    }
}
