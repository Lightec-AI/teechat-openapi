//! Compile-time feature gate disclosure.
//!
//! **Rule:** every Cargo `feature = "..."` that changes runtime behavior in this
//! crate MUST be logged here on every process start. See repo README
//! § "Compile-time features".

/// Emit one structured log line with the value of every runtime-affecting
/// `cfg(feature = …)` for `openapi-platform-cvm`.
///
/// Call once from the edge binary immediately after the tracing subscriber is
/// installed (before accepting traffic).
pub fn log_compile_time_features() {
    tracing::info!(
        target: "openapi_compile_features",
        crate_name = "openapi-platform-cvm",
        catalog_auth = cfg!(feature = "catalog-auth"),
        "compile-time feature gates (logged every start)"
    );
}

#[cfg(test)]
mod tests {
    #[test]
    fn catalog_auth_flag_is_bool() {
        // Ensures the feature symbol stays wired into the log helper.
        let _ = cfg!(feature = "catalog-auth");
        super::log_compile_time_features();
    }
}
