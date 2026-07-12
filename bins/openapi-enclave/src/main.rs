fn main() -> anyhow::Result<()> {
    // Fortanix EDP starts with an empty process environment (no host env injection).
    // Hydrate config from enclave CLI args: `KEY=VALUE` (OPENAPI_* / RUST_LOG only).
    // Example: ftxsgx-runner enclave.sgxs OPENAPI_LISTEN_ADDR=127.0.0.1:18443 ...
    for arg in std::env::args().skip(1) {
        let Some((key, value)) = arg.split_once('=') else {
            continue;
        };
        if key.starts_with("OPENAPI_") || key == "RUST_LOG" {
            // SAFETY: single-threaded startup before any other threads.
            unsafe { std::env::set_var(key, value) };
        }
    }

    openapi_platform_sgx::run()
}
