use axum::{Json, Router, extract::State, routing::get};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use jsonwebtoken::{DecodingKey, EncodingKey};
use rand::rngs::OsRng;
use rsa::{
    RsaPrivateKey, RsaPublicKey,
    pkcs8::{EncodePrivateKey, LineEnding},
    traits::PublicKeyParts,
};
use secrecy::ExposeSecret;
use serde::Serialize;
use sqlx::FromRow;

use crate::{
    AppState,
    crypto::{SealedSecret, random_token},
    error::ApiError,
};

#[derive(Debug, Serialize)]
struct ProviderMetadata {
    issuer: String,
    authorization_endpoint: String,
    token_endpoint: String,
    userinfo_endpoint: String,
    revocation_endpoint: String,
    end_session_endpoint: String,
    jwks_uri: String,
    response_types_supported: Vec<&'static str>,
    grant_types_supported: Vec<&'static str>,
    subject_types_supported: Vec<&'static str>,
    id_token_signing_alg_values_supported: Vec<&'static str>,
    token_endpoint_auth_methods_supported: Vec<&'static str>,
    code_challenge_methods_supported: Vec<&'static str>,
    scopes_supported: Vec<&'static str>,
    claims_supported: Vec<&'static str>,
}

#[derive(Debug, Serialize)]
struct JwksResponse {
    keys: Vec<PublicJwk>,
}

#[derive(Debug, Serialize)]
struct PublicJwk {
    kty: &'static str,
    #[serde(rename = "use")]
    key_use: String,
    alg: String,
    kid: String,
    n: String,
    e: String,
}

#[derive(Debug, FromRow)]
struct PublicKeyRow {
    key_id: String,
    algorithm: String,
    key_use: String,
    public_modulus: String,
    public_exponent: String,
}

#[derive(Debug, FromRow)]
struct SigningKeyRow {
    key_id: String,
    encrypted_private_key: Vec<u8>,
    private_key_nonce: Vec<u8>,
    envelope_key_id: String,
}

pub(crate) struct SigningKey {
    pub key_id: String,
    pub encoding_key: EncodingKey,
}

pub async fn discovery(State(state): State<AppState>) -> Json<impl Serialize> {
    Json(metadata(&state))
}

pub async fn authorization_server_metadata(State(state): State<AppState>) -> Json<impl Serialize> {
    Json(metadata(&state))
}

pub async fn jwks(State(state): State<AppState>) -> Result<Json<impl Serialize>, ApiError> {
    let rows = public_keys(&state).await?;
    Ok(Json(JwksResponse {
        keys: rows
            .into_iter()
            .map(|row| PublicJwk {
                kty: "RSA",
                key_use: row.key_use,
                alg: row.algorithm,
                kid: row.key_id,
                n: row.public_modulus,
                e: row.public_exponent,
            })
            .collect(),
    }))
}

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/.well-known/openid-configuration", get(discovery))
        .route(
            "/.well-known/oauth-authorization-server",
            get(authorization_server_metadata),
        )
        .route("/oauth2/jwks.json", get(jwks))
}

pub(crate) async fn ensure_signing_key(state: &AppState) -> Result<SigningKey, ApiError> {
    ensure_signing_key_material(&state.database, state.envelope.as_ref()).await
}

pub(crate) async fn maintain_signing_key(
    database: &sqlx::PgPool,
    envelope: &dyn crate::crypto::EnvelopeCipher,
) -> Result<(), ApiError> {
    ensure_signing_key_material(database, envelope)
        .await
        .map(|_| ())
}

async fn ensure_signing_key_material(
    database: &sqlx::PgPool,
    envelope: &dyn crate::crypto::EnvelopeCipher,
) -> Result<SigningKey, ApiError> {
    if let Some(row) = sqlx::query_as::<_, SigningKeyRow>(
        "select * from zeus_private.load_current_oidc_signing_key()",
    )
    .fetch_optional(database)
    .await?
    {
        return open_signing_key(envelope, row);
    }

    let generated = tokio::task::spawn_blocking(generate_rsa_key)
        .await
        .map_err(|_| ApiError::Internal)??;
    let sealed = envelope
        .seal(
            generated.private_pem.as_bytes(),
            signing_key_aad(&generated.key_id).as_bytes(),
        )
        .map_err(|_| ApiError::Internal)?;
    let row = sqlx::query_as::<_, SigningKeyRow>(
        "select * from zeus_private.install_oidc_signing_key($1, $2, $3, $4, $5, $6)",
    )
    .bind(generated.key_id)
    .bind(sealed.ciphertext)
    .bind(sealed.nonce)
    .bind(sealed.key_id)
    .bind(generated.public_modulus)
    .bind(generated.public_exponent)
    .fetch_one(database)
    .await?;
    open_signing_key(envelope, row)
}

pub(crate) async fn decoding_key(state: &AppState, key_id: &str) -> Result<DecodingKey, ApiError> {
    let row = public_keys(state)
        .await?
        .into_iter()
        .find(|row| row.key_id == key_id && row.algorithm == "RS256" && row.key_use == "sig")
        .ok_or(ApiError::Unauthorized)?;
    DecodingKey::from_rsa_components(&row.public_modulus, &row.public_exponent)
        .map_err(|_| ApiError::Unauthorized)
}

fn metadata(state: &AppState) -> ProviderMetadata {
    ProviderMetadata {
        issuer: issuer(state),
        authorization_endpoint: endpoint(state, "/oauth2/authorize"),
        token_endpoint: endpoint(state, "/oauth2/token"),
        userinfo_endpoint: endpoint(state, "/oauth2/userinfo"),
        revocation_endpoint: endpoint(state, "/oauth2/revoke"),
        end_session_endpoint: endpoint(state, "/oauth2/logout"),
        jwks_uri: endpoint(state, "/oauth2/jwks.json"),
        response_types_supported: vec!["code"],
        grant_types_supported: vec!["authorization_code", "refresh_token"],
        subject_types_supported: vec!["pairwise"],
        id_token_signing_alg_values_supported: vec!["RS256"],
        token_endpoint_auth_methods_supported: vec!["client_secret_basic", "none"],
        code_challenge_methods_supported: vec!["S256"],
        scopes_supported: vec![
            "openid",
            "profile",
            "email",
            "zeus.organization",
            "zeus.workspace",
        ],
        claims_supported: vec![
            "iss",
            "sub",
            "aud",
            "exp",
            "iat",
            "auth_time",
            "nonce",
            "name",
            "email",
            "email_verified",
        ],
    }
}

pub(crate) fn issuer(state: &AppState) -> String {
    state.public_url.as_str().trim_end_matches('/').to_owned()
}

fn endpoint(state: &AppState, path: &str) -> String {
    format!("{}{}", issuer(state), path)
}

async fn public_keys(state: &AppState) -> Result<Vec<PublicKeyRow>, ApiError> {
    sqlx::query_as::<_, PublicKeyRow>("select * from zeus_private.list_oidc_public_keys()")
        .fetch_all(&state.database)
        .await
        .map_err(Into::into)
}

fn open_signing_key(
    envelope: &dyn crate::crypto::EnvelopeCipher,
    row: SigningKeyRow,
) -> Result<SigningKey, ApiError> {
    let plaintext = envelope
        .open(
            &SealedSecret {
                ciphertext: row.encrypted_private_key,
                nonce: row.private_key_nonce,
                key_id: row.envelope_key_id,
            },
            signing_key_aad(&row.key_id).as_bytes(),
        )
        .map_err(|_| ApiError::Internal)?;
    let encoding_key = EncodingKey::from_rsa_pem(&plaintext).map_err(|_| ApiError::Internal)?;
    Ok(SigningKey {
        key_id: row.key_id,
        encoding_key,
    })
}

struct GeneratedKey {
    key_id: String,
    private_pem: String,
    public_modulus: String,
    public_exponent: String,
}

fn generate_rsa_key() -> Result<GeneratedKey, ApiError> {
    let private = RsaPrivateKey::new(&mut OsRng, 3072).map_err(|_| ApiError::Internal)?;
    let public = RsaPublicKey::from(&private);
    let private_pem = private
        .to_pkcs8_pem(LineEnding::LF)
        .map_err(|_| ApiError::Internal)?
        .to_string();
    let key_id = random_token(24).map_err(|_| ApiError::Internal)?;
    Ok(GeneratedKey {
        key_id: key_id.expose_secret().to_owned(),
        private_pem,
        public_modulus: URL_SAFE_NO_PAD.encode(public.n().to_bytes_be()),
        public_exponent: URL_SAFE_NO_PAD.encode(public.e().to_bytes_be()),
    })
}

fn signing_key_aad(key_id: &str) -> String {
    format!("oidc-signing-key/{key_id}")
}

#[cfg(test)]
mod tests {
    use super::generate_rsa_key;

    #[test]
    fn generated_key_is_rs256_compatible_and_has_a_public_jwk() {
        let key = generate_rsa_key().expect("RSA key generation succeeds");
        assert!(key.private_pem.starts_with("-----BEGIN PRIVATE KEY-----"));
        assert!(!key.public_modulus.is_empty());
        assert_eq!(key.public_exponent, "AQAB");
        assert!(key.key_id.len() >= 20);
    }
}
