use std::{collections::HashMap, ops::Add};

use serde::{Deserialize, Serialize};
use validator::Validate;

const JWT_ISSUER: &str = "auth.rust.tobiasbrandy.com"; // TODO: change to app service URL once we have a URL
pub const JWT_TTL: std::time::Duration = std::time::Duration::from_secs(15 * 60); // 15 minutes
const JWT_LEEWAY_SECONDS: u64 = 60;
const JWT_ALGORITHM: jsonwebtoken::Algorithm = jsonwebtoken::Algorithm::HS256;

#[derive(Clone, Deserialize, Validate)]
#[serde(from = "AuthConfigRepr")]
pub struct AuthConfig {
    #[validate(length(min = 1))]
    jwt_secrets: HashMap<u64, String>,
    decoding_keys: HashMap<u64, jsonwebtoken::DecodingKey>,
    encoding_key: jsonwebtoken::EncodingKey,
    header: jsonwebtoken::Header,
}
impl AuthConfig {
    pub fn new(jwt_secrets: HashMap<u64, String>) -> Self {
        if jwt_secrets.is_empty() {
            // Invalid state -> Invalid config
            return Self {
                jwt_secrets,
                decoding_keys: HashMap::new(),
                encoding_key: jsonwebtoken::EncodingKey::from_secret(b""),
                header: jsonwebtoken::Header::new(JWT_ALGORITHM),
            };
        }

        let kid = jwt_secrets.keys().max().unwrap();

        let decoding_keys = jwt_secrets
            .iter()
            .map(|(kid, secret)| {
                (
                    *kid,
                    jsonwebtoken::DecodingKey::from_secret(secret.as_bytes()),
                )
            })
            .collect();

        let encoding_key =
            jsonwebtoken::EncodingKey::from_secret(jwt_secrets.get(kid).unwrap().as_bytes());

        let mut header = jsonwebtoken::Header::new(JWT_ALGORITHM);
        header.kid = Some(kid.to_string());

        Self {
            jwt_secrets,
            decoding_keys,
            encoding_key,
            header,
        }
    }
}
impl std::fmt::Debug for AuthConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuthConfig")
            .field("jwt_secrets", &self.jwt_secrets)
            .finish()
    }
}
#[derive(Debug, Clone, Serialize, Deserialize)]
struct AuthConfigRepr {
    #[serde(deserialize_with = "de_jwt_secrets")]
    jwt_secrets: HashMap<u64, String>,
}
fn de_jwt_secrets<'de, D>(deserializer: D) -> Result<HashMap<u64, String>, D::Error>
where
    D: serde::de::Deserializer<'de>,
{
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum MapEither {
        Map(HashMap<String, String>),
        Str(String),
    }

    match MapEither::deserialize(deserializer)? {
        MapEither::Map(m) => Ok(m
            .into_iter()
            .map(|(k, v)| Ok((k.parse().map_err(serde::de::Error::custom)?, v)))
            .collect::<Result<_, _>>()?),
        MapEither::Str(s) => {
            serde_json::from_str::<HashMap<u64, String>>(&s).map_err(serde::de::Error::custom)
        }
    }
}
impl From<AuthConfigRepr> for AuthConfig {
    fn from(AuthConfigRepr { jwt_secrets }: AuthConfigRepr) -> Self {
        AuthConfig::new(jwt_secrets)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Claims {
    iss: String,
    sub: String,
    aud: String,
    iat: u64,
    nbf: u64,
    exp: u64,
    jti: String,
}

pub fn generate_auth_token(
    config: &AuthConfig,
    email: &str,
    app: &str,
) -> Result<String, jsonwebtoken::errors::Error> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap();

    let claims = Claims {
        iss: JWT_ISSUER.to_owned(),
        sub: email.to_owned(), // TODO: change to DB id once we have a DB
        aud: format!("{JWT_ISSUER}/{app}"),
        iat: now.as_secs(),
        nbf: now.as_secs(),
        exp: now.add(JWT_TTL).as_secs(),
        jti: uuid::Uuid::new_v4().to_string(),
    };

    jsonwebtoken::encode(&config.header, &claims, &config.encoding_key)
}

pub fn validate_auth_token(
    config: &AuthConfig,
    token: &str,
    app: &str,
) -> Result<Claims, jsonwebtoken::errors::Error> {
    let validation = {
        let mut v = jsonwebtoken::Validation::new(JWT_ALGORITHM);
        v.set_required_spec_claims(&["exp", "nbf", "aud", "iss", "sub"]);
        v.set_issuer(&[JWT_ISSUER]);
        v.set_audience(&[format!("{JWT_ISSUER}/{app}")]);
        v.leeway = JWT_LEEWAY_SECONDS;
        v.reject_tokens_expiring_in_less_than = 0;
        v.validate_exp = true;
        v.validate_nbf = true;
        v.validate_aud = true;
        v
    };

    let kid = jsonwebtoken::decode_header(token)?
        .kid
        .and_then(|k| k.parse().ok())
        .unwrap_or(config.header.kid.as_ref().unwrap().parse().unwrap());

    let decoding_key = config.decoding_keys.get(&kid).unwrap();

    jsonwebtoken::decode::<Claims>(token, decoding_key, &validation).map(|data| data.claims)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn create_test_auth_config() -> AuthConfig {
        AuthConfig::new(HashMap::from([
            (1_u64, "test_secret_key_1".to_string()),
            (2_u64, "test_secret_key_2".to_string()),
        ]))
    }

    #[tokio::test]
    async fn test_generate_auth_token_success() {
        let config = create_test_auth_config();
        let email = "test@example.com";
        let app = "test-app";

        let result = generate_auth_token(&config, email, app);
        assert!(result.is_ok());

        let token = result.unwrap();
        // JWT tokens should have 3 parts separated by dots
        assert_eq!(token.split('.').count(), 3);
        assert!(!token.is_empty());
    }

    #[tokio::test]
    async fn test_validate_auth_token_success() {
        let config = create_test_auth_config();
        let email = "test@example.com";
        let app = "test-app";

        let token = generate_auth_token(&config, email, app).unwrap();
        let result = validate_auth_token(&config, &token, app);

        assert!(result.is_ok());
        let claims = result.unwrap();

        assert_eq!(claims.sub, email);
        assert_eq!(claims.iss, JWT_ISSUER);
        assert_eq!(claims.aud, format!("{JWT_ISSUER}/{app}"));

        // Check that timestamps are reasonable
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        assert!(claims.iat <= now);
        assert!(claims.nbf <= now);
        assert!(claims.exp > now);
        assert!(claims.exp <= now + JWT_TTL.as_secs());

        // JTI should be a valid UUID
        assert!(uuid::Uuid::parse_str(&claims.jti).is_ok());
    }

    #[tokio::test]
    async fn test_validate_auth_token_wrong_app() {
        let config = create_test_auth_config();
        let email = "test@example.com";
        let app = "test-app";
        let wrong_app = "wrong-app";

        let token = generate_auth_token(&config, email, app).unwrap();
        let result = validate_auth_token(&config, &token, wrong_app);

        assert!(result.is_err());

        // Should fail due to audience mismatch
        match result.unwrap_err().kind() {
            jsonwebtoken::errors::ErrorKind::InvalidAudience => {}
            _ => panic!("Expected InvalidAudience error"),
        }
    }

    #[tokio::test]
    async fn test_validate_auth_token_invalid_token() {
        let config = create_test_auth_config();
        let invalid_token = "invalid.token.here";
        let app = "test-app";

        let result = validate_auth_token(&config, invalid_token, app);
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_validate_auth_token_tampered_signature() {
        let config = create_test_auth_config();
        let email = "test@example.com";
        let app = "test-app";

        let mut token = generate_auth_token(&config, email, app).unwrap();

        // Tamper with the signature (last part)
        let parts: Vec<&str> = token.split('.').collect();
        let tampered_signature = format!("{}{}x", parts[2], "tampered");
        token = format!("{}.{}.{}", parts[0], parts[1], tampered_signature);

        let result = validate_auth_token(&config, &token, app);
        assert!(result.is_err());

        match result.unwrap_err().kind() {
            jsonwebtoken::errors::ErrorKind::InvalidSignature => {}
            _ => panic!("Expected InvalidSignature error"),
        }
    }

    #[tokio::test]
    async fn test_token_roundtrip_different_apps() {
        let config = create_test_auth_config();
        let email = "test@example.com";
        let app1 = "app1";
        let app2 = "app2";

        let token1 = generate_auth_token(&config, email, app1).unwrap();
        let token2 = generate_auth_token(&config, email, app2).unwrap();

        // Tokens should be different for different apps
        assert_ne!(token1, token2);

        // Each token should validate only for its respective app
        assert!(validate_auth_token(&config, &token1, app1).is_ok());
        assert!(validate_auth_token(&config, &token2, app2).is_ok());
        assert!(validate_auth_token(&config, &token1, app2).is_err());
        assert!(validate_auth_token(&config, &token2, app1).is_err());
    }

    #[tokio::test]
    async fn test_token_uniqueness() {
        let config = create_test_auth_config();
        let email = "test@example.com";
        let app = "test-app";

        // Generate multiple tokens and ensure they're all unique
        let mut tokens = Vec::new();
        for _ in 0..5 {
            tokens.push(generate_auth_token(&config, email, app).unwrap());
            // Small delay to ensure different timestamps
            tokio::time::sleep(tokio::time::Duration::from_millis(1)).await;
        }

        // Check that all tokens are unique
        for i in 0..tokens.len() {
            for j in (i + 1)..tokens.len() {
                assert_ne!(tokens[i], tokens[j], "Tokens should be unique");
            }
        }

        // Verify that all tokens are still valid
        for token in &tokens {
            assert!(validate_auth_token(&config, token, app).is_ok());
        }
    }

    #[test]
    fn test_auth_config_deserialize_from_json_string() {
        // Test that AuthConfigRepr can deserialize jwt_secrets from a JSON string
        let json_data = r#"{"jwt_secrets": "{\"1757003125\": \"4lW+Nwi3kGzsQ1mxJ69ExjOkacYb+HQozdtWRxGBO9g=\"}"}"#;

        let config_repr: AuthConfigRepr = serde_json::from_str(json_data).unwrap();
        let auth_config = AuthConfig::from(config_repr);

        // Verify the deserialized data
        assert_eq!(auth_config.jwt_secrets.len(), 1);
        assert_eq!(
            auth_config.jwt_secrets.get(&1757003125),
            Some(&"4lW+Nwi3kGzsQ1mxJ69ExjOkacYb+HQozdtWRxGBO9g=".to_string())
        );
    }

    #[test]
    fn test_auth_config_deserialize_from_direct_map() {
        // Test that AuthConfigRepr can still deserialize from direct HashMap
        let json_data =
            r#"{"jwt_secrets": {"1757003125": "4lW+Nwi3kGzsQ1mxJ69ExjOkacYb+HQozdtWRxGBO9g="}}"#;

        let config_repr: AuthConfigRepr = serde_json::from_str(json_data).unwrap();
        let auth_config = AuthConfig::from(config_repr);

        // Verify the deserialized data
        assert_eq!(auth_config.jwt_secrets.len(), 1);
        assert_eq!(
            auth_config.jwt_secrets.get(&1757003125),
            Some(&"4lW+Nwi3kGzsQ1mxJ69ExjOkacYb+HQozdtWRxGBO9g=".to_string())
        );
    }
}
