use std::collections::BTreeMap;

use openidconnect::{
    AccessTokenHash, AdditionalClaims, AuthorizationCode, ClientId, ClientSecret, CsrfToken,
    IssuerUrl, Nonce, OAuth2TokenResponse, PkceCodeChallenge, PkceCodeVerifier, RedirectUrl, Scope,
    TokenResponse, UserInfoClaims,
    core::{CoreAuthenticationFlow, CoreClient, CoreGenderClaim, CoreProviderMetadata},
};
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use url::{Host, Url};

#[derive(Clone)]
pub struct OidcProviderConfig {
    pub issuer_url: Url,
    pub client_id: String,
    pub client_secret: SecretString,
    pub scopes: Vec<String>,
    pub group_claim: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PendingOidcAuthorization {
    pub state: String,
    pub nonce: String,
    pub pkce_verifier: String,
    pub return_to: String,
}

#[derive(Clone, Debug)]
pub struct OidcAuthorization {
    pub url: Url,
    pub pending: PendingOidcAuthorization,
}

#[derive(Clone, Debug)]
pub struct VerifiedOidcIdentity {
    pub issuer: String,
    pub subject: String,
    pub email: String,
    pub email_verified: bool,
    pub display_name: String,
    pub groups: Vec<String>,
    pub acr: Option<String>,
    pub amr: Vec<String>,
    pub stored_claims: Value,
}

#[derive(Debug, thiserror::Error)]
pub enum OidcError {
    #[error("OIDC issuer URL is not allowed")]
    IssuerNotAllowed,
    #[error("OIDC provider discovery failed")]
    Discovery,
    #[error("OIDC client configuration is invalid")]
    ClientConfiguration,
    #[error("OIDC authorization code exchange failed")]
    Exchange,
    #[error("OIDC provider did not return a valid ID token")]
    InvalidIdToken,
    #[error("OIDC provider did not return an email address")]
    MissingEmail,
    #[error("OIDC user-info response could not be verified")]
    UserInfo,
    #[error("OIDC group claim has an unsupported shape")]
    InvalidGroupClaim,
}

#[derive(Debug, Default, Deserialize, Serialize)]
struct DynamicAdditionalClaims {
    #[serde(flatten)]
    values: BTreeMap<String, Value>,
}

impl AdditionalClaims for DynamicAdditionalClaims {}

pub struct OidcFlow<'a> {
    http_client: &'a reqwest::Client,
    allow_private_issuers: bool,
}

impl<'a> OidcFlow<'a> {
    #[must_use]
    pub const fn new(http_client: &'a reqwest::Client, allow_private_issuers: bool) -> Self {
        Self {
            http_client,
            allow_private_issuers,
        }
    }

    /// Discovers an OIDC provider and creates an Authorization Code + PKCE request.
    ///
    /// # Errors
    ///
    /// Returns a stable error when the issuer is unsafe, discovery fails, or the client is invalid.
    pub async fn authorize(
        &self,
        provider: &OidcProviderConfig,
        redirect_url: Url,
        return_to: String,
    ) -> Result<OidcAuthorization, OidcError> {
        validate_remote_url(&provider.issuer_url, self.allow_private_issuers)?;
        let issuer = IssuerUrl::new(provider.issuer_url.to_string())
            .map_err(|_| OidcError::ClientConfiguration)?;
        let metadata = CoreProviderMetadata::discover_async(issuer, self.http_client)
            .await
            .map_err(|_| OidcError::Discovery)?;
        let client = CoreClient::from_provider_metadata(
            metadata,
            ClientId::new(provider.client_id.clone()),
            Some(ClientSecret::new(
                provider.client_secret.expose_secret().to_owned(),
            )),
        )
        .set_redirect_uri(
            RedirectUrl::new(redirect_url.to_string())
                .map_err(|_| OidcError::ClientConfiguration)?,
        );

        let (challenge, verifier) = PkceCodeChallenge::new_random_sha256();
        let mut request = client
            .authorize_url(
                CoreAuthenticationFlow::AuthorizationCode,
                CsrfToken::new_random,
                Nonce::new_random,
            )
            .set_pkce_challenge(challenge);
        for scope in normalized_scopes(&provider.scopes) {
            request = request.add_scope(Scope::new(scope));
        }
        let (url, state, nonce) = request.url();

        Ok(OidcAuthorization {
            url,
            pending: PendingOidcAuthorization {
                state: state.secret().to_owned(),
                nonce: nonce.secret().to_owned(),
                pkce_verifier: verifier.secret().to_owned(),
                return_to: sanitize_return_to(&return_to),
            },
        })
    }

    /// Exchanges and verifies an OIDC Authorization Code response.
    ///
    /// # Errors
    ///
    /// Returns a stable error when discovery, exchange, token verification, or user-info fails.
    #[allow(clippy::too_many_lines)] // Provider verification follows the OIDC exchange order.
    pub async fn complete(
        &self,
        provider: &OidcProviderConfig,
        redirect_url: Url,
        code: String,
        pending: &PendingOidcAuthorization,
    ) -> Result<VerifiedOidcIdentity, OidcError> {
        validate_remote_url(&provider.issuer_url, self.allow_private_issuers)?;
        let issuer = IssuerUrl::new(provider.issuer_url.to_string())
            .map_err(|_| OidcError::ClientConfiguration)?;
        let metadata = CoreProviderMetadata::discover_async(issuer, self.http_client)
            .await
            .map_err(|_| OidcError::Discovery)?;
        let client = CoreClient::from_provider_metadata(
            metadata,
            ClientId::new(provider.client_id.clone()),
            Some(ClientSecret::new(
                provider.client_secret.expose_secret().to_owned(),
            )),
        )
        .set_redirect_uri(
            RedirectUrl::new(redirect_url.to_string())
                .map_err(|_| OidcError::ClientConfiguration)?,
        );

        let token_response = client
            .exchange_code(AuthorizationCode::new(code))
            .map_err(|_| OidcError::ClientConfiguration)?
            .set_pkce_verifier(PkceCodeVerifier::new(pending.pkce_verifier.clone()))
            .request_async(self.http_client)
            .await
            .map_err(|_| OidcError::Exchange)?;
        let id_token = token_response.id_token().ok_or(OidcError::InvalidIdToken)?;
        let verifier = client.id_token_verifier();
        let nonce = Nonce::new(pending.nonce.clone());
        let claims = id_token
            .claims(&verifier, &nonce)
            .map_err(|_| OidcError::InvalidIdToken)?;

        if let Some(expected_hash) = claims.access_token_hash() {
            let actual_hash = AccessTokenHash::from_token(
                token_response.access_token(),
                id_token
                    .signing_alg()
                    .map_err(|_| OidcError::InvalidIdToken)?,
                id_token
                    .signing_key(&verifier)
                    .map_err(|_| OidcError::InvalidIdToken)?,
            )
            .map_err(|_| OidcError::InvalidIdToken)?;
            if actual_hash != *expected_hash {
                return Err(OidcError::InvalidIdToken);
            }
        }

        let email = claims
            .email()
            .map(|value| value.as_str().to_owned())
            .ok_or(OidcError::MissingEmail)?;
        let email_verified = claims.email_verified().unwrap_or(false);
        let display_name = claims
            .name()
            .and_then(|localized| localized.get(None))
            .map(|value| value.as_str().to_owned())
            .or_else(|| {
                claims
                    .preferred_username()
                    .map(|value| value.as_str().to_owned())
            })
            .unwrap_or_else(|| email.clone());

        let groups = if let Some(group_claim) = provider.group_claim.as_deref() {
            let request = client
                .user_info(
                    token_response.access_token().to_owned(),
                    Some(claims.subject().clone()),
                )
                .map_err(|_| OidcError::UserInfo)?;
            let user_info: UserInfoClaims<DynamicAdditionalClaims, CoreGenderClaim> = request
                .request_async(self.http_client)
                .await
                .map_err(|_| OidcError::UserInfo)?;
            extract_groups(user_info.additional_claims().values.get(group_claim))?
        } else {
            Vec::new()
        };

        let issuer = provider
            .issuer_url
            .as_str()
            .trim_end_matches('/')
            .to_owned();
        let subject = claims.subject().as_str().to_owned();
        let acr = claims
            .auth_context_ref()
            .map(|value| value.as_ref().to_owned());
        let amr = claims
            .auth_method_refs()
            .map(|values| {
                values
                    .iter()
                    .map(|value| {
                        let method: &str = value.as_ref();
                        method.to_owned()
                    })
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        let stored_claims = json!({
            "issuer": issuer,
            "subject": subject,
            "email": email,
            "email_verified": email_verified,
            "display_name": display_name,
            "groups": groups,
            "acr": acr,
            "amr": amr,
        });

        Ok(VerifiedOidcIdentity {
            issuer,
            subject,
            email,
            email_verified,
            display_name,
            groups,
            acr,
            amr,
            stored_claims,
        })
    }
}

/// Validates a remote identity-provider URL against the deployment network policy.
///
/// # Errors
///
/// Returns an error when credentials, fragments, insecure schemes, or private
/// network targets are not allowed.
pub fn validate_remote_url(url: &Url, allow_private: bool) -> Result<(), OidcError> {
    if url.username() != "" || url.password().is_some() || url.fragment().is_some() {
        return Err(OidcError::IssuerNotAllowed);
    }
    if !allow_private && url.scheme() != "https" {
        return Err(OidcError::IssuerNotAllowed);
    }
    match url.host() {
        Some(Host::Domain(domain)) if allow_private || is_public_domain(domain) => Ok(()),
        Some(Host::Ipv4(address)) if allow_private || is_global_ipv4(address) => Ok(()),
        Some(Host::Ipv6(address)) if allow_private || is_global_ipv6(address) => Ok(()),
        _ => Err(OidcError::IssuerNotAllowed),
    }
}

#[must_use]
pub fn sanitize_return_to(value: &str) -> String {
    if value.starts_with('/') && !value.starts_with("//") && !value.contains(['\r', '\n']) {
        value.to_owned()
    } else {
        "/".to_owned()
    }
}

fn normalized_scopes(scopes: &[String]) -> Vec<String> {
    let mut normalized = Vec::with_capacity(scopes.len() + 1);
    normalized.push("openid".to_owned());
    for scope in scopes {
        if !normalized.contains(scope) {
            normalized.push(scope.clone());
        }
    }
    normalized
}

fn extract_groups(value: Option<&Value>) -> Result<Vec<String>, OidcError> {
    match value {
        None => Ok(Vec::new()),
        Some(Value::Array(values)) => values
            .iter()
            .map(|value| {
                value
                    .as_str()
                    .map(ToOwned::to_owned)
                    .ok_or(OidcError::InvalidGroupClaim)
            })
            .collect(),
        Some(Value::String(value)) => Ok(value
            .split_whitespace()
            .filter(|group| !group.is_empty())
            .map(ToOwned::to_owned)
            .collect()),
        Some(_) => Err(OidcError::InvalidGroupClaim),
    }
}

#[allow(clippy::case_sensitive_file_extension_comparisons)] // Lowercased DNS suffix, not a file extension.
fn is_public_domain(domain: &str) -> bool {
    let domain = domain.trim_end_matches('.').to_ascii_lowercase();
    domain != "localhost" && !domain.ends_with(".localhost") && !domain.ends_with(".local")
}

fn is_global_ipv6(address: std::net::Ipv6Addr) -> bool {
    !(address.is_loopback()
        || address.is_unspecified()
        || address.is_unique_local()
        || address.is_unicast_link_local())
}

fn is_global_ipv4(address: std::net::Ipv4Addr) -> bool {
    let [a, b, c, _] = address.octets();
    !(a == 0
        || a == 10
        || a == 127
        || (a == 100 && (64..=127).contains(&b))
        || (a == 169 && b == 254)
        || (a == 172 && (16..=31).contains(&b))
        || (a == 192 && b == 0)
        || (a == 192 && b == 168)
        || (a == 198 && (b == 18 || b == 19))
        || (a == 198 && b == 51 && c == 100)
        || (a == 203 && b == 0 && c == 113)
        || a >= 224)
}

#[cfg(test)]
mod tests {
    use serde_json::json;
    use url::Url;

    use super::{extract_groups, sanitize_return_to, validate_remote_url};

    #[test]
    fn redirects_stay_on_the_same_origin() {
        assert_eq!(sanitize_return_to("/work-items/1"), "/work-items/1");
        assert_eq!(sanitize_return_to("https://evil.example"), "/");
        assert_eq!(sanitize_return_to("//evil.example"), "/");
    }

    #[test]
    fn public_issuer_validation_rejects_local_targets() {
        assert!(validate_remote_url(&Url::parse("https://id.example.com").unwrap(), false).is_ok());
        assert!(validate_remote_url(&Url::parse("http://127.0.0.1:9000").unwrap(), false).is_err());
        assert!(validate_remote_url(&Url::parse("http://127.0.0.1:9000").unwrap(), true).is_ok());
    }

    #[test]
    fn group_claim_accepts_arrays_and_space_delimited_strings() {
        assert_eq!(
            extract_groups(Some(&json!(["engineering", "operators"]))).unwrap(),
            ["engineering", "operators"]
        );
        assert_eq!(
            extract_groups(Some(&json!("engineering operators"))).unwrap(),
            ["engineering", "operators"]
        );
    }
}
