//! Cloudflare Access authentication for machine-to-machine callers.
//!
//! The existing endpoints authenticate a human through a `tower-sessions`
//! cookie. That model does not fit a service calling this API on a schedule:
//! it would need a password-equivalent credential, and it breaks the moment
//! someone sensibly enables 2FA on the account.
//!
//! Instead, this module trusts Cloudflare Access. When a service token calls
//! through an Access-protected hostname, Access validates the token and injects
//! a signed JWT in `Cf-Access-Jwt-Assertion`. Verifying that JWT — signature,
//! audience and expiry — is what proves the request came through Access rather
//! than straight at the origin.
//!
//! Verifying the signature matters. The `Cf-Access-Client-Id` header alone is
//! attacker-supplied: anything that can reach the origin directly can set it.
//! The JWT is signed by the team's Access instance and cannot be forged.

use crate::error::AppError;
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode, decode_header};
use serde::{Deserialize, Serialize};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

/// Cached key set: when it was fetched, and what was fetched.
type CachedKeys = Arc<RwLock<Option<(Instant, Vec<Jwk>)>>>;

/// How long a fetched key set is reused before being refetched. Access rotates
/// its signing keys periodically; an hour keeps us current without fetching on
/// every request.
const JWKS_TTL: Duration = Duration::from_secs(3600);

/// Claims we care about from an Access JWT.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AccessClaims {
    /// Access application audience tag.
    pub aud: Vec<String>,
    /// Issuer — the team domain.
    pub iss: String,
    pub exp: usize,
    /// Set for a *user* login; absent for a service token.
    #[serde(default)]
    pub email: Option<String>,
    /// Set for a *service token*; carries the token's name.
    #[serde(default)]
    pub common_name: Option<String>,
}

impl AccessClaims {
    /// A label for logs: the service token name, or the user's email.
    pub fn subject(&self) -> String {
        self.common_name
            .clone()
            .or_else(|| self.email.clone())
            .unwrap_or_else(|| "unknown".to_string())
    }
}

#[derive(Debug, Clone, Deserialize)]
struct Jwk {
    kid: String,
    n: String,
    e: String,
}

#[derive(Debug, Clone, Deserialize)]
struct Jwks {
    keys: Vec<Jwk>,
}

#[derive(Clone)]
pub struct AccessConfig {
    /// e.g. `https://northsky.cloudflareaccess.com`
    pub team_domain: String,
    /// The Access application's AUD tag.
    pub aud: String,
    /// Optional allowlist of service token names. Empty means any principal
    /// Access lets through is accepted, which is usually what the Access policy
    /// is already for.
    pub allowed_service_tokens: Vec<String>,
    cache: CachedKeys,
}

impl std::fmt::Debug for AccessConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AccessConfig")
            .field("team_domain", &self.team_domain)
            .field("aud", &self.aud)
            .field("allowed_service_tokens", &self.allowed_service_tokens)
            .finish()
    }
}

impl AccessConfig {
    pub fn new(team_domain: String, aud: String, allowed_service_tokens: Vec<String>) -> Self {
        Self {
            team_domain: team_domain.trim_end_matches('/').to_string(),
            aud,
            allowed_service_tokens,
            cache: Arc::new(RwLock::new(None)),
        }
    }

    fn certs_url(&self) -> String {
        format!("{}/cdn-cgi/access/certs", self.team_domain)
    }

    /// The team's signing keys, refetched when the cached copy has aged out.
    async fn keys(&self) -> Result<Vec<Jwk>, AppError> {
        if let Ok(guard) = self.cache.read()
            && let Some((fetched_at, keys)) = guard.as_ref()
            && fetched_at.elapsed() < JWKS_TTL
        {
            return Ok(keys.clone());
        }

        let res = reqwest::Client::new()
            .get(self.certs_url())
            .send()
            .await
            .map_err(|e| AppError::InternalError(format!("Could not fetch Access keys: {e}")))?;

        if !res.status().is_success() {
            return Err(AppError::InternalError(format!(
                "Access key endpoint returned {}",
                res.status()
            )));
        }

        let jwks: Jwks = res
            .json()
            .await
            .map_err(|e| AppError::InternalError(format!("Malformed Access key set: {e}")))?;

        if let Ok(mut guard) = self.cache.write() {
            *guard = Some((Instant::now(), jwks.keys.clone()));
        }

        Ok(jwks.keys)
    }

    /// Verify an Access JWT and return its claims.
    pub async fn verify(&self, token: &str) -> Result<AccessClaims, AppError> {
        let header = decode_header(token)
            .map_err(|e| AppError::AuthError(format!("Malformed Access token: {e}")))?;

        let kid = header
            .kid
            .ok_or_else(|| AppError::AuthError("Access token has no key id".to_string()))?;

        let keys = self.keys().await?;
        let jwk = keys.iter().find(|k| k.kid == kid).ok_or_else(|| {
            AppError::AuthError("Access token signed by an unknown key".to_string())
        })?;

        let key = DecodingKey::from_rsa_components(&jwk.n, &jwk.e)
            .map_err(|e| AppError::InternalError(format!("Unusable Access key: {e}")))?;

        // Pinning the audience is what stops a token minted for a *different*
        // Access application in the same team from being replayed here.
        let mut validation = Validation::new(Algorithm::RS256);
        validation.set_audience(std::slice::from_ref(&self.aud));
        validation.set_issuer(std::slice::from_ref(&self.team_domain));

        let data = decode::<AccessClaims>(token, &key, &validation)
            .map_err(|e| AppError::AuthError(format!("Invalid Access token: {e}")))?;

        if !self.allowed_service_tokens.is_empty() {
            let name = data.claims.common_name.clone().unwrap_or_default();
            if !self.allowed_service_tokens.iter().any(|t| t == &name) {
                return Err(AppError::AuthError(format!(
                    "Service token \"{name}\" is not permitted to issue invite codes"
                )));
            }
        }

        Ok(data.claims)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config() -> AccessConfig {
        AccessConfig::new(
            "https://team.cloudflareaccess.com/".to_string(),
            "aud-tag".to_string(),
            vec![],
        )
    }

    #[test]
    fn trims_a_trailing_slash_from_the_team_domain() {
        assert_eq!(config().team_domain, "https://team.cloudflareaccess.com");
    }

    #[test]
    fn builds_the_documented_certs_url() {
        assert_eq!(
            config().certs_url(),
            "https://team.cloudflareaccess.com/cdn-cgi/access/certs"
        );
    }

    #[tokio::test]
    async fn rejects_a_token_that_is_not_a_jwt() {
        let err = config().verify("not-a-jwt").await.unwrap_err();
        assert!(matches!(err, AppError::AuthError(_)));
    }

    #[tokio::test]
    async fn rejects_a_jwt_with_no_key_id() {
        // Signed with a symmetric key and no `kid`; must not reach the network.
        let token = jsonwebtoken::encode(
            &jsonwebtoken::Header::default(),
            &serde_json::json!({ "aud": ["aud-tag"], "iss": "x", "exp": 9_999_999_999u64 }),
            &jsonwebtoken::EncodingKey::from_secret(b"secret"),
        )
        .expect("failed to build test token");

        let err = config().verify(&token).await.unwrap_err();
        match err {
            AppError::AuthError(msg) => assert!(msg.contains("key id")),
            other => panic!("expected an auth error, got {other:?}"),
        }
    }

    #[test]
    fn subject_prefers_the_service_token_name() {
        let claims = AccessClaims {
            aud: vec!["a".into()],
            iss: "i".into(),
            exp: 0,
            email: Some("someone@example.com".into()),
            common_name: Some("vetting-tool".into()),
        };
        assert_eq!(claims.subject(), "vetting-tool");
    }

    #[test]
    fn subject_falls_back_to_the_user_email() {
        let claims = AccessClaims {
            aud: vec!["a".into()],
            iss: "i".into(),
            exp: 0,
            email: Some("someone@example.com".into()),
            common_name: None,
        };
        assert_eq!(claims.subject(), "someone@example.com");
    }
}
