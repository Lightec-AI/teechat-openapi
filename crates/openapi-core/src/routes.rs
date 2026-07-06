use crate::handler::HttpMethod;

/// How the edge handles an HTTP route.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RouteAction {
    Health,
    Attestation,
    ModelsList,
    /// OpenAI inference POST with usage metering (chat, completions, embeddings, …).
    InferencePost,
    /// Authenticated transparent GET proxy under `/v1/`.
    ProxyGet,
    /// Authenticated transparent POST proxy under `/v1/`.
    ProxyPost,
    /// Durable OpenAI control-plane APIs we do not implement (501).
    NotImplemented(&'static str),
    MethodNotAllowed,
    NotFound,
}

/// Classify a request path. User demand: proxy unknown `/v1/*` unless explicitly blocked.
pub fn classify(method: HttpMethod, path: &str) -> RouteAction {
    match path {
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
        "/v1/completions"
        | "/v1/embeddings"
        | "/v1/responses"
        | "/v1/moderations" if method == HttpMethod::Post => RouteAction::InferencePost,
        p if p.starts_with("/v1/") => {
            if let Some(reason) = not_implemented_reason(p) {
                return RouteAction::NotImplemented(reason);
            }
            match method {
                HttpMethod::Get => RouteAction::ProxyGet,
                HttpMethod::Post => RouteAction::ProxyPost,
                HttpMethod::Other => RouteAction::MethodNotAllowed,
            }
        }
        _ => RouteAction::NotFound,
    }
}

fn not_implemented_reason(path: &str) -> Option<&'static str> {
    const BLOCKED: &[(&str, &str)] = &[
        ("/v1/fine_tuning", "fine-tuning jobs require durable storage; not supported on the edge"),
        ("/v1/fine-tuning", "fine-tuning jobs require durable storage; not supported on the edge"),
        ("/v1/assistants", "Assistants API requires durable thread storage; not supported on the edge"),
        ("/v1/threads", "Assistants API requires durable thread storage; not supported on the edge"),
        ("/v1/files", "file uploads require durable storage; not supported on the edge"),
        ("/v1/batches", "batch jobs require durable storage; not supported on the edge"),
        ("/v1/vector_stores", "vector stores require durable storage; not supported on the edge"),
        ("/v1/uploads", "upload sessions require durable storage; not supported on the edge"),
        ("/v1/audio", "audio APIs are not yet supported on the edge"),
        ("/v1/images", "image generation APIs are not yet supported on the edge"),
        ("/v1/videos", "video generation APIs are not yet supported on the edge"),
        ("/v1/realtime", "realtime sessions require durable WebSocket state; not supported on the edge"),
        ("/v1/containers", "container APIs are not supported on the edge"),
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
                classify(HttpMethod::Post, path),
                RouteAction::InferencePost,
                "{path}"
            );
        }
    }

    #[test]
    fn durable_apis_return_not_implemented() {
        assert!(matches!(
            classify(HttpMethod::Post, "/v1/files"),
            RouteAction::NotImplemented(_)
        ));
        assert!(matches!(
            classify(HttpMethod::Post, "/v1/batches"),
            RouteAction::NotImplemented(_)
        ));
    }

    #[test]
    fn unknown_v1_proxies() {
        assert_eq!(
            classify(HttpMethod::Get, "/v1/models/gpt-4"),
            RouteAction::ProxyGet
        );
        assert_eq!(
            classify(HttpMethod::Post, "/v1/some/future/route"),
            RouteAction::ProxyPost
        );
    }
}
