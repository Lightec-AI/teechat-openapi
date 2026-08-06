//! Browser / Capacitor WebView bindings for RB-02 SNP collateral verify.
//!
//! Mirrors the Tauri command `desktop_verify_snp_with_collateral` result shape
//! (camelCase JSON) so `tryVerifyLocalSnpQuote` can soft-wire the same mapping.

use openapi_attest::verify_snp_quote_with_collateral as verify_snp_quote_native;
use serde::Serialize;
use wasm_bindgen::prelude::*;

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SnpCollateralResult {
    ok: bool,
    product_name: String,
    launch_measurement_hex: String,
    report_data_hex: String,
    chip_id_hex: String,
    policy_debug: bool,
    guest_svn: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

fn decode_vcek_der(vcek_der_b64: &str) -> Result<Vec<u8>, String> {
    base64::Engine::decode(
        &base64::engine::general_purpose::STANDARD,
        vcek_der_b64.trim(),
    )
    .or_else(|_| {
        base64::Engine::decode(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD,
            vcek_der_b64.trim().trim_end_matches('='),
        )
    })
    .map_err(|e| format!("vcek_der_b64: {e}"))
}

fn fail(error: impl Into<String>) -> SnpCollateralResult {
    SnpCollateralResult {
        ok: false,
        product_name: String::new(),
        launch_measurement_hex: String::new(),
        report_data_hex: String::new(),
        chip_id_hex: String::new(),
        policy_debug: false,
        guest_svn: 0,
        error: Some(error.into()),
    }
}

fn to_json(result: SnpCollateralResult) -> String {
    serde_json::to_string(&result).unwrap_or_else(|e| {
        serde_json::to_string(&fail(format!("serialize: {e}"))).unwrap_or_else(|_| {
            r#"{"ok":false,"productName":"","launchMeasurementHex":"","reportDataHex":"","chipIdHex":"","policyDebug":false,"guestSvn":0,"error":"serialize"}"#.into()
        })
    })
}

#[wasm_bindgen]
pub fn openapi_attest_wasm_version() -> String {
    env!("CARGO_PKG_VERSION").into()
}

/// I/O-free SNP verify. Returns JSON matching Tauri `DesktopSnpCollateralResult`
/// (camelCase keys).
#[wasm_bindgen]
pub fn verify_snp_quote_with_collateral_json(
    quote_b64: &str,
    vcek_der_b64: &str,
    reject_debug: bool,
) -> String {
    let vcek = match decode_vcek_der(vcek_der_b64) {
        Ok(b) => b,
        Err(e) => return to_json(fail(e)),
    };

    let result = match verify_snp_quote_native(quote_b64, &vcek, reject_debug) {
        Ok(r) => SnpCollateralResult {
            ok: true,
            product_name: r.product_name,
            launch_measurement_hex: r.launch_measurement_hex,
            report_data_hex: r.report_data_hex,
            chip_id_hex: r.chip_id_hex,
            policy_debug: r.policy_debug,
            guest_svn: r.guest_svn,
            error: None,
        },
        Err(e) => fail(e.to_string()),
    };

    to_json(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_garbage_without_panic() {
        let json = verify_snp_quote_with_collateral_json("not-base64!!!", "AAAA", true);
        let v: serde_json::Value = serde_json::from_str(&json).expect("json");
        assert_eq!(v["ok"], false);
        assert!(v.get("error").and_then(|e| e.as_str()).is_some());
    }
}
