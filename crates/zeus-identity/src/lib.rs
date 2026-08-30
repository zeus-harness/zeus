//! Pure identity primitives for Zeus.
//!
//! This crate deliberately stops at normalization, cryptography, bounded
//! execution, and validation. HTTP, database, mail, and token transport
//! concerns belong to the application layer.

#![forbid(unsafe_code)]

pub mod claims;
pub mod password;
pub mod password_executor;
pub mod policy;
pub mod token;
pub mod totp;

pub use claims::{ClaimsError, JwtClaims, OidcClaims};
pub use password::{
    NormalizedPassword, PasswordError, PasswordHashVerification, PasswordPolicy,
    PasswordVerification, WeakPasswordSet, hash_password, normalize_email, normalize_password,
    validate_password, verify_password,
};
pub use password_executor::{MAX_CONCURRENT_HASHES, PasswordExecutorError, PasswordHashExecutor};
/// API-integration name for [`PasswordHashExecutor`].
pub type PasswordExecutor = PasswordHashExecutor;
pub use policy::{
    AuthMethod, AuthMethods, AuthenticationMethod, IdentityPolicy, OidcScopeSet, OidcScopes,
    PolicyError, RegistrationMode, SessionDuration,
};
pub use token::{
    IssuedToken, TokenError, generate_opaque_token, is_pkce_s256_match, pkce_s256_challenge,
    sha256_digest, verify_digest, verify_pkce_s256,
};
pub use totp::{
    DEFAULT_RECOVERY_CODE_COUNT, RecoveryCode, RecoveryCodeDigest, RecoveryCodeDigests, Totp,
    TotpError, generate_recovery_codes, generate_recovery_codes_with_count, is_replay,
    normalize_recovery_code, recovery_code_digest,
};
