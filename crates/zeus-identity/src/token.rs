//! Opaque-token issuance, digest comparison, and PKCE S256 checks.

use std::fmt;

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use secrecy::{ExposeSecret, SecretString};
use sha2::{Digest, Sha256};
use thiserror::Error;

/// Entropy size in bytes for an opaque token.
pub const OPAQUE_TOKEN_BYTES: usize = 32;
/// Minimum RFC 7636 code-verifier length in ASCII characters.
pub const PKCE_VERIFIER_MIN_LENGTH: usize = 43;
/// Maximum RFC 7636 code-verifier length in ASCII characters.
pub const PKCE_VERIFIER_MAX_LENGTH: usize = 128;

/// Stable failures returned by token and PKCE operations.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum TokenError {
    /// The operating system did not provide token randomness.
    #[error("secure random generation failed")]
    Randomness,
    /// The PKCE verifier is malformed.
    #[error("PKCE verifier is invalid")]
    InvalidPkceVerifier,
    /// The PKCE challenge is malformed.
    #[error("PKCE challenge is invalid")]
    InvalidPkceChallenge,
    /// The verifier does not produce the supplied S256 challenge.
    #[error("PKCE challenge does not match")]
    PkceMismatch,
}

impl TokenError {
    /// Returns the stable, transport-independent error code.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::Randomness => "randomness_failed",
            Self::InvalidPkceVerifier => "invalid_pkce_verifier",
            Self::InvalidPkceChallenge => "invalid_pkce_challenge",
            Self::PkceMismatch => "pkce_mismatch",
        }
    }
}

/// A newly issued opaque token.
///
/// The plaintext is retained only for the caller that must present it once;
/// the digest is the value intended for persistence. Its debug output redacts
/// both values so logging the container cannot disclose the token.
#[derive(Clone)]
pub struct IssuedToken {
    plaintext: SecretString,
    digest: [u8; 32],
}

impl IssuedToken {
    /// Exposes the plaintext token for transport to its intended recipient.
    #[must_use]
    pub fn plaintext(&self) -> &str {
        self.plaintext.expose_secret()
    }

    /// Exposes the plaintext token under an explicitly secret-named method.
    #[must_use]
    pub fn expose_secret(&self) -> &str {
        self.plaintext.expose_secret()
    }

    /// Returns the SHA-256 digest intended for persistence.
    #[must_use]
    pub const fn digest(&self) -> [u8; 32] {
        self.digest
    }

    /// Consumes the value and returns the one-time plaintext plus its digest.
    #[must_use]
    pub fn into_parts(self) -> (SecretString, [u8; 32]) {
        (self.plaintext, self.digest)
    }
}

impl fmt::Debug for IssuedToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("IssuedToken")
            .field("plaintext", &"[REDACTED]")
            .field("digest", &"[REDACTED]")
            .finish()
    }
}

/// Generates a 256-bit random URL-safe opaque token and its SHA-256 digest.
///
/// The encoded plaintext uses unpadded base64url and is suitable for a cookie
/// or authorization header. No prefix or metadata is added.
///
/// # Errors
///
/// Returns [`TokenError::Randomness`] when the operating system RNG fails.
pub fn generate_opaque_token() -> Result<IssuedToken, TokenError> {
    let mut random = [0_u8; OPAQUE_TOKEN_BYTES];
    getrandom::fill(&mut random).map_err(|_| TokenError::Randomness)?;
    let encoded = URL_SAFE_NO_PAD.encode(random);
    let digest = sha256_digest(&encoded);
    Ok(IssuedToken {
        plaintext: SecretString::from(encoded),
        digest,
    })
}

/// Computes a SHA-256 digest for a token or other opaque value.
#[must_use]
pub fn sha256_digest(value: &str) -> [u8; 32] {
    let computed = Sha256::digest(value.as_bytes());
    let mut digest = [0_u8; 32];
    digest.copy_from_slice(&computed);
    digest
}

/// Compares a presented token with a stored digest in constant time.
#[must_use]
pub fn verify_digest(presented: &str, expected: &[u8; 32]) -> bool {
    constant_time_eq_32(&sha256_digest(presented), expected)
}

/// Computes the RFC 7636 S256 challenge for a valid code verifier.
///
/// # Errors
///
/// Returns [`TokenError::InvalidPkceVerifier`] when the verifier is outside
/// the RFC 7636 length or character rules.
pub fn pkce_s256_challenge(verifier: &str) -> Result<String, TokenError> {
    validate_pkce_verifier(verifier)?;
    Ok(URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes())))
}

/// Validates a verifier against an RFC 7636 S256 challenge.
///
/// The comparison is constant-time once both inputs have passed structural
/// validation.
///
/// # Errors
///
/// Returns a stable verifier, challenge, or mismatch error.
pub fn verify_pkce_s256(verifier: &str, expected_challenge: &str) -> Result<(), TokenError> {
    validate_pkce_verifier(verifier)?;
    if !is_valid_pkce_challenge(expected_challenge) {
        return Err(TokenError::InvalidPkceChallenge);
    }
    let actual = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));
    if constant_time_eq_bytes(actual.as_bytes(), expected_challenge.as_bytes()) {
        Ok(())
    } else {
        Err(TokenError::PkceMismatch)
    }
}

/// Returns `true` when the verifier and challenge form a valid S256 pair.
#[must_use]
pub fn is_pkce_s256_match(verifier: &str, expected_challenge: &str) -> bool {
    verify_pkce_s256(verifier, expected_challenge).is_ok()
}

pub(crate) fn constant_time_eq_32(left: &[u8; 32], right: &[u8; 32]) -> bool {
    let mut difference = 0_u8;
    for (&left, &right) in left.iter().zip(right.iter()) {
        difference |= left ^ right;
    }
    difference == 0
}

fn constant_time_eq_bytes(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    let mut difference = 0_u8;
    for (&left, &right) in left.iter().zip(right.iter()) {
        difference |= left ^ right;
    }
    difference == 0
}

fn validate_pkce_verifier(verifier: &str) -> Result<(), TokenError> {
    if !(PKCE_VERIFIER_MIN_LENGTH..=PKCE_VERIFIER_MAX_LENGTH).contains(&verifier.len())
        || !verifier.bytes().all(is_pkce_verifier_byte)
    {
        return Err(TokenError::InvalidPkceVerifier);
    }
    Ok(())
}

fn is_valid_pkce_challenge(challenge: &str) -> bool {
    challenge.len() == 43 && challenge.bytes().all(is_base64url_byte)
}

const fn is_pkce_verifier_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~')
}

const fn is_base64url_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_')
}

#[cfg(test)]
mod tests {
    use super::{
        OPAQUE_TOKEN_BYTES, TokenError, generate_opaque_token, is_pkce_s256_match,
        pkce_s256_challenge, sha256_digest, verify_digest, verify_pkce_s256,
    };

    #[test]
    fn opaque_token_is_random_and_debug_redacted() {
        let issued = generate_opaque_token().expect("random token");
        assert_eq!(issued.plaintext().len(), 43);
        assert_eq!(OPAQUE_TOKEN_BYTES, 32);
        assert_eq!(issued.digest(), sha256_digest(issued.plaintext()));
        assert!(verify_digest(issued.plaintext(), &issued.digest()));
        assert!(!format!("{issued:?}").contains(issued.plaintext()));
    }

    #[test]
    fn digest_comparison_rejects_modified_tokens() {
        let digest = sha256_digest("opaque-value");
        assert!(verify_digest("opaque-value", &digest));
        assert!(!verify_digest("opaque-valuE", &digest));
    }

    #[test]
    fn pkce_s256_matches_rfc7636_example() {
        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        let challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
        assert_eq!(pkce_s256_challenge(verifier).expect("challenge"), challenge);
        assert_eq!(verify_pkce_s256(verifier, challenge), Ok(()));
        assert!(is_pkce_s256_match(verifier, challenge));
        assert_eq!(
            verify_pkce_s256("short", challenge),
            Err(TokenError::InvalidPkceVerifier)
        );
        assert_eq!(
            verify_pkce_s256(verifier, "not-a-challenge"),
            Err(TokenError::InvalidPkceChallenge)
        );
        assert!(!is_pkce_s256_match(verifier, &"A".repeat(43)));
    }
}
