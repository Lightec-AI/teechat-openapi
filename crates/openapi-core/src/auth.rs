use crate::authz::OpenApiKeyPolicy;
use crate::catalog::{KeyCatalog, KeyRecord};
use crate::error::ApiError;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthContext {
    pub key_id: String,
    /// L0-signed policy (remote auth) or [`OpenApiKeyPolicy::unrestricted`] (catalog).
    pub policy: OpenApiKeyPolicy,
}

#[derive(Debug)]
pub struct Authenticator {
    catalog: KeyCatalog,
}

impl Authenticator {
    pub fn new(catalog: KeyCatalog) -> Self {
        Self { catalog }
    }

    pub fn catalog(&self) -> &KeyCatalog {
        &self.catalog
    }

    pub fn authenticate_bearer(&self, authorization: Option<&str>) -> Result<AuthContext, ApiError> {
        let header = authorization.ok_or(ApiError::Unauthorized)?;
        let token = header
            .strip_prefix("Bearer ")
            .ok_or(ApiError::Unauthorized)?;
        if token.is_empty() {
            return Err(ApiError::Unauthorized);
        }
        let record = self.catalog.lookup_by_api_key(token)?;
        Ok(AuthContext {
            key_id: record.key_id.clone(),
            policy: OpenApiKeyPolicy::unrestricted(),
        })
    }
}

impl From<&KeyRecord> for AuthContext {
    fn from(record: &KeyRecord) -> Self {
        Self {
            key_id: record.key_id.clone(),
            policy: OpenApiKeyPolicy::unrestricted(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::Authenticator;
    use crate::catalog::{hash_api_key, sign_test_catalog, KeyCatalog, KeyRecord};
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;

    fn test_authenticator(api_key: &str) -> Authenticator {
        let mut csprng = OsRng;
        let signing_key = SigningKey::generate(&mut csprng);
        let verify_key = signing_key.verifying_key();
        let record = KeyRecord {
            key_id: "test".into(),
            key_hash_hex: hash_api_key(api_key),
            revoked: false,
        };
        let signed = sign_test_catalog(vec![record], &signing_key);
        let catalog = KeyCatalog::from_signed(signed, verify_key).unwrap();
        Authenticator::new(catalog)
    }

    #[test]
    fn bearer_auth_ok() {
        let key = "sk-teechat-abc";
        let auth = test_authenticator(key);
        let ctx = auth
            .authenticate_bearer(Some(&format!("Bearer {key}")))
            .unwrap();
        assert_eq!(ctx.key_id, "test");
        assert!(ctx.policy.allows_model("any-model"));
        assert_eq!(ctx.policy.rpm, 0);
    }

    #[test]
    fn missing_bearer_rejected() {
        let auth = test_authenticator("sk-teechat-abc");
        assert!(auth.authenticate_bearer(None).is_err());
    }

    #[test]
    fn wrong_scheme_rejected() {
        let auth = test_authenticator("sk-teechat-abc");
        assert!(auth
            .authenticate_bearer(Some("Token sk-teechat-abc"))
            .is_err());
    }
}
