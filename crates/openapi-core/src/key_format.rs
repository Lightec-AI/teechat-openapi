use sha2::{Digest, Sha256};

pub const OPENAPI_KEY_PREFIX: &str = "sk-teechat-";
pub const OPENAPI_KEY_ID_PREFIX: &str = "tcak_";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedApiKey {
    pub key_id: String,
    pub secret: String,
    pub full_key: String,
}

pub fn hash_api_key(api_key: &str) -> String {
    let digest = Sha256::digest(api_key.as_bytes());
    hex::encode(digest)
}

fn is_valid_key_id(key_id: &str) -> bool {
    if !key_id.starts_with(OPENAPI_KEY_ID_PREFIX) {
        return false;
    }
    let suffix = &key_id[OPENAPI_KEY_ID_PREFIX.len()..];
    suffix.len() == 8 && suffix.chars().all(|c| c.is_ascii_alphanumeric())
}

pub fn parse_api_key(raw: &str) -> Option<ParsedApiKey> {
    let token = raw.trim();
    if !token.starts_with(OPENAPI_KEY_PREFIX) {
        return None;
    }
    let rest = &token[OPENAPI_KEY_PREFIX.len()..];
    let dot = rest.rfind('.')?;
    if dot == 0 {
        return None;
    }
    let key_id = &rest[..dot];
    let secret = &rest[dot + 1..];
    if !is_valid_key_id(key_id) || secret.len() < 32 {
        return None;
    }
    if !secret
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
    {
        return None;
    }
    Some(ParsedApiKey {
        key_id: key_id.to_string(),
        secret: secret.to_string(),
        full_key: token.to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_structured_key() {
        let secret = "A".repeat(32);
        let key = format!("sk-teechat-tcak_ab12CD34.{secret}");
        let parsed = parse_api_key(&key).unwrap();
        assert_eq!(parsed.key_id, "tcak_ab12CD34");
        assert_eq!(hash_api_key(&key), hash_api_key(&parsed.full_key));
    }

    #[test]
    fn reject_bad_prefix() {
        assert!(parse_api_key("sk-other-tcak_ab12CD34.x").is_none());
    }
}
