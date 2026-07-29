fn main() -> anyhow::Result<()> {
    // Fortanix EDP starts with an empty process environment (no host env injection).
    // Hydrate config from enclave CLI args: `KEY=VALUE` (OPENAPI_* / RUST_LOG only).
    // Example: ftxsgx-runner enclave.sgxs OPENAPI_LISTEN_ADDR=127.0.0.1:18443 ...
    //
    // ACME Option A: pass `OPENAPI_MODE=acme-issue` / `acme-renew`, or a positional
    // `acme-issue` / `acme-renew` argument, to run the in-enclave ceremony instead of
    // the edge server.
    let mut acme_mode: Option<openapi_platform_sgx::AcmeMode> = None;
    for arg in std::env::args().skip(1) {
        if arg == "acme-issue" {
            acme_mode = Some(openapi_platform_sgx::AcmeMode::Issue);
            continue;
        }
        if arg == "acme-renew" {
            acme_mode = Some(openapi_platform_sgx::AcmeMode::Renew);
            continue;
        }
        let Some((key, value)) = arg.split_once('=') else {
            continue;
        };
        if key.starts_with("OPENAPI_") || key == "RUST_LOG" {
            // SAFETY: single-threaded startup before any other threads.
            unsafe { std::env::set_var(key, value) };
        }
        if key == "OPENAPI_MODE" {
            match value {
                "acme-issue" => acme_mode = Some(openapi_platform_sgx::AcmeMode::Issue),
                "acme-renew" => acme_mode = Some(openapi_platform_sgx::AcmeMode::Renew),
                _ => {}
            }
        }
    }

    match acme_mode {
        Some(mode) => {
            // Prefer explicit exit over returning Err from main: ftxsgx-runner
            // reports some Result failures as "Enclave panicked" even when the
            // ceremony only failed closed on an ACME policy / LE error.
            if let Err(err) = openapi_platform_sgx::run_acme_ceremony(mode) {
                eprintln!("openapi ACME ceremony failed: {err:#}");
                std::process::exit(1);
            }
            Ok(())
        }
        None => openapi_platform_sgx::run(),
    }
}
