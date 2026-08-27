//! Local-first identity and authentication domain primitives.
//!
//! This crate deliberately contains no database, HTTP, cookie, or authorization
//! policy code. Secret-bearing values have explicit exposure methods and
//! redacted `Debug` implementations; persistence receives only password PHC
//! records or domain-separated token digests.

use std::{fmt, str::FromStr};

use argon2::{
    Algorithm, Argon2, Params, Version,
    password_hash::{
        Error as PasswordHashError, PasswordHash, PasswordHasher, PasswordVerifier, SaltString,
    },
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use rand_core::{OsRng, RngCore};
use serde::Serialize;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use thiserror::Error;
use zeroize::{Zeroize, Zeroizing};

pub const USERNAME_MIN_BYTES: usize = 3;
pub const USERNAME_MAX_BYTES: usize = 32;
pub const PASSWORD_MIN_CHARS: usize = 12;
pub const PASSWORD_MAX_BYTES: usize = 1024;

const USER_ID_RANDOM_BYTES: usize = 16;
const AUTH_SESSION_ID_RANDOM_BYTES: usize = 16;
const TOKEN_RANDOM_BYTES: usize = 32;
const ARGON2_MEMORY_KIB: u32 = 19 * 1024;
const ARGON2_ITERATIONS: u32 = 2;
const ARGON2_LANES: u32 = 1;
const ARGON2_OUTPUT_BYTES: usize = 32;
const ARGON2_MAX_MEMORY_KIB: u32 = 256 * 1024;
const ARGON2_MAX_ITERATIONS: u32 = 10;
const ARGON2_MAX_LANES: u32 = 4;
const INVALID_PASSWORD_SENTINEL: &str = "invalid-candidate-for-uniform-verification";
const SESSION_TOKEN_DOMAIN: &[u8] = b"zeus.session-token.v1\0";
const CSRF_TOKEN_DOMAIN: &[u8] = b"zeus.csrf-token.v1\0";
const BOOTSTRAP_TOKEN_DOMAIN: &[u8] = b"zeus.bootstrap-token.v1\0";
const MEMBER_SETUP_TOKEN_DOMAIN: &[u8] = b"zeus.member-setup-token.v1\0";

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct UserId(String);

impl UserId {
    /// Generates a server-owned, 128-bit random user identifier.
    pub fn generate() -> Result<Self, RandomnessError> {
        let mut bytes = [0_u8; USER_ID_RANDOM_BYTES];
        OsRng
            .try_fill_bytes(&mut bytes)
            .map_err(|_| RandomnessError::Unavailable)?;
        Ok(Self(format!("usr_{}", URL_SAFE_NO_PAD.encode(bytes))))
    }

    /// Parses only the canonical representation produced by [`Self::generate`].
    pub fn parse(value: impl Into<String>) -> Result<Self, UserIdError> {
        let value = value.into();
        let encoded = value
            .strip_prefix("usr_")
            .ok_or(UserIdError::InvalidFormat)?;
        let decoded = URL_SAFE_NO_PAD
            .decode(encoded)
            .map_err(|_| UserIdError::InvalidFormat)?;
        if decoded.len() != USER_ID_RANDOM_BYTES || URL_SAFE_NO_PAD.encode(decoded) != encoded {
            return Err(UserIdError::InvalidFormat);
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for UserId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl FromStr for UserId {
    type Err = UserIdError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::parse(value)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Error)]
pub enum UserIdError {
    #[error("user ID must use the canonical server-generated representation")]
    InvalidFormat,
}

/// Durable account identifier carried by every authorized operation.
///
/// Persistence accepts bounded legacy-compatible values because existing Zeus
/// databases predate the canonical local account. New local deployments use
/// the deterministic `acc_local` identifier.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize)]
pub struct AccountId(String);

impl AccountId {
    pub fn local() -> Self {
        Self("acc_local".into())
    }

    pub fn from_persistence(value: impl Into<String>) -> Result<Self, AuthorityIdError> {
        Ok(Self(validate_authority_id(value.into(), "account ID")?))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for AccountId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

/// Stable, non-secret identity for one login session.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize)]
pub struct AuthSessionId(String);

impl AuthSessionId {
    pub fn generate() -> Result<Self, RandomnessError> {
        let mut bytes = [0_u8; AUTH_SESSION_ID_RANDOM_BYTES];
        OsRng
            .try_fill_bytes(&mut bytes)
            .map_err(|_| RandomnessError::Unavailable)?;
        Ok(Self(format!("asi_{}", URL_SAFE_NO_PAD.encode(bytes))))
    }

    pub fn from_persistence(value: impl Into<String>) -> Result<Self, AuthorityIdError> {
        Ok(Self(validate_authority_id(
            value.into(),
            "authentication session ID",
        )?))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for AuthSessionId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

fn validate_authority_id(value: String, field: &'static str) -> Result<String, AuthorityIdError> {
    if value.is_empty()
        || value.len() > 128
        || value.trim() != value
        || value.bytes().any(|byte| byte.is_ascii_control())
    {
        return Err(AuthorityIdError::Invalid { field });
    }
    Ok(value)
}

#[derive(Clone, Debug, PartialEq, Eq, Error)]
pub enum AuthorityIdError {
    #[error("{field} must be non-empty, trimmed, bounded, and contain no control characters")]
    Invalid { field: &'static str },
}

/// Case-insensitive ASCII username stored in lowercase canonical form.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Username(String);

impl Username {
    pub fn parse(value: impl AsRef<str>) -> Result<Self, UsernameError> {
        let value = value.as_ref();
        if value.len() < USERNAME_MIN_BYTES {
            return Err(UsernameError::TooShort);
        }
        if value.len() > USERNAME_MAX_BYTES {
            return Err(UsernameError::TooLong);
        }
        if !value.is_ascii() {
            return Err(UsernameError::NonAscii);
        }
        let bytes = value.as_bytes();
        if !bytes[0].is_ascii_alphanumeric() || !bytes[bytes.len() - 1].is_ascii_alphanumeric() {
            return Err(UsernameError::InvalidBoundary);
        }
        if let Some((index, byte)) =
            bytes.iter().copied().enumerate().find(|(_, byte)| {
                !byte.is_ascii_alphanumeric() && !matches!(byte, b'.' | b'_' | b'-')
            })
        {
            return Err(UsernameError::InvalidCharacter {
                index,
                character: char::from(byte),
            });
        }
        Ok(Self(value.to_ascii_lowercase()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for Username {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl FromStr for Username {
    type Err = UsernameError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::parse(value)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Error)]
pub enum UsernameError {
    #[error("username must contain at least {USERNAME_MIN_BYTES} ASCII bytes")]
    TooShort,
    #[error("username cannot exceed {USERNAME_MAX_BYTES} ASCII bytes")]
    TooLong,
    #[error("username must contain ASCII characters only")]
    NonAscii,
    #[error("username must start and end with an ASCII letter or digit")]
    InvalidBoundary,
    #[error("username contains unsupported character `{character}` at byte {index}")]
    InvalidCharacter { index: usize, character: char },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MembershipRole {
    Owner,
    Member,
}

impl MembershipRole {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Owner => "owner",
            Self::Member => "member",
        }
    }
}

impl fmt::Display for MembershipRole {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl FromStr for MembershipRole {
    type Err = MembershipRoleError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "owner" => Ok(Self::Owner),
            "member" => Ok(Self::Member),
            _ => Err(MembershipRoleError::Unsupported(value.to_owned())),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Error)]
pub enum MembershipRoleError {
    #[error("unsupported account membership role `{0}`")]
    Unsupported(String),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize)]
pub struct MembershipRevision(u64);

impl MembershipRevision {
    pub fn new(value: u64) -> Result<Self, MembershipRevisionError> {
        if value == 0 {
            return Err(MembershipRevisionError::Zero);
        }
        Ok(Self(value))
    }

    pub const fn get(self) -> u64 {
        self.0
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Error)]
pub enum MembershipRevisionError {
    #[error("membership revision must be positive")]
    Zero,
}

/// Authenticated account authority. Callers carry this value, while storage
/// re-reads the durable membership at every mutation linearization point.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct AuthzContext {
    pub account_id: AccountId,
    pub user_id: String,
    pub membership_role: MembershipRole,
    pub membership_revision: MembershipRevision,
    pub auth_session_id: AuthSessionId,
}

/// A policy-validated password whose allocation is zeroized on drop.
pub struct Password(Zeroizing<String>);

impl Password {
    pub fn new(value: impl Into<String>) -> Result<Self, PasswordPolicyError> {
        let mut value = value.into();
        if let Err(error) = validate_password_policy(&value) {
            value.zeroize();
            return Err(error);
        }
        Ok(Self(Zeroizing::new(value)))
    }

    fn expose_secret(&self) -> &str {
        self.0.as_str()
    }
}

impl fmt::Debug for Password {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("Password([REDACTED])")
    }
}

fn validate_password_policy(value: &str) -> Result<(), PasswordPolicyError> {
    if value.len() > PASSWORD_MAX_BYTES {
        return Err(PasswordPolicyError::TooLong);
    }
    if value.chars().count() < PASSWORD_MIN_CHARS {
        return Err(PasswordPolicyError::TooShort);
    }
    if value.chars().any(char::is_control) {
        return Err(PasswordPolicyError::ControlCharacter);
    }
    if value.chars().all(char::is_whitespace) {
        return Err(PasswordPolicyError::AllWhitespace);
    }
    Ok(())
}

#[derive(Clone, Debug, PartialEq, Eq, Error)]
pub enum PasswordPolicyError {
    #[error("password must contain at least {PASSWORD_MIN_CHARS} characters")]
    TooShort,
    #[error("password cannot exceed {PASSWORD_MAX_BYTES} UTF-8 bytes")]
    TooLong,
    #[error("password cannot contain control characters")]
    ControlCharacter,
    #[error("password cannot consist only of whitespace")]
    AllWhitespace,
}

/// Argon2id PHC text suitable for persistence.
///
/// Debug output is redacted because offline password hashes are still
/// credential material. Use [`Self::as_phc`] only at the persistence boundary.
#[derive(Clone, PartialEq, Eq)]
pub struct PasswordHashRecord(String);

impl PasswordHashRecord {
    pub fn parse(phc: impl Into<String>) -> Result<Self, CredentialError> {
        let phc = phc.into();
        validate_password_hash(&phc)?;
        Ok(Self(phc))
    }

    pub fn as_phc(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for PasswordHashRecord {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PasswordHashRecord([REDACTED])")
    }
}

/// Hashes new credentials using an explicit Argon2id v1.3 policy.
pub fn hash_password(password: &Password) -> Result<PasswordHashRecord, CredentialError> {
    let mut salt_bytes = [0_u8; 16];
    OsRng
        .try_fill_bytes(&mut salt_bytes)
        .map_err(|_| RandomnessError::Unavailable)?;
    let salt = SaltString::encode_b64(&salt_bytes).map_err(|_| CredentialError::HashingFailed)?;
    let encoded = password_hasher()?
        .hash_password(password.expose_secret().as_bytes(), &salt)
        .map_err(|_| CredentialError::HashingFailed)?
        .to_string();
    PasswordHashRecord::parse(encoded)
}

/// Unified credential verification, including an Argon2 dummy-record path for
/// unknown usernames.
///
/// Callers pass `None` when no account exists. Exactly one Argon2 verification
/// is still performed and the result is always `false`, avoiding a cheap
/// unknown-user branch. Invalid password candidates also take the same Argon2
/// path using a fixed valid sentinel.
pub struct PasswordAuthenticator {
    dummy_hash: PasswordHashRecord,
}

impl PasswordAuthenticator {
    pub fn new() -> Result<Self, CredentialError> {
        let dummy_password =
            Password::new(INVALID_PASSWORD_SENTINEL).map_err(|_| CredentialError::HashingFailed)?;
        Ok(Self {
            dummy_hash: hash_password(&dummy_password)?,
        })
    }

    pub fn verify(
        &self,
        stored: Option<&PasswordHashRecord>,
        candidate: &str,
    ) -> Result<bool, CredentialError> {
        let candidate_is_valid = validate_password_policy(candidate).is_ok();
        let candidate = if candidate_is_valid {
            candidate
        } else {
            INVALID_PASSWORD_SENTINEL
        };
        let target = stored.unwrap_or(&self.dummy_hash);
        let parsed =
            PasswordHash::new(target.as_phc()).map_err(|_| CredentialError::InvalidPasswordHash)?;
        let verified = match Argon2::default().verify_password(candidate.as_bytes(), &parsed) {
            Ok(()) => true,
            Err(PasswordHashError::Password) => false,
            Err(_) => return Err(CredentialError::VerificationFailed),
        };
        Ok(stored.is_some() && candidate_is_valid && verified)
    }
}

impl fmt::Debug for PasswordAuthenticator {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PasswordAuthenticator { dummy_hash: [REDACTED] }")
    }
}

fn password_hasher() -> Result<Argon2<'static>, CredentialError> {
    let params = Params::new(
        ARGON2_MEMORY_KIB,
        ARGON2_ITERATIONS,
        ARGON2_LANES,
        Some(ARGON2_OUTPUT_BYTES),
    )
    .map_err(|_| CredentialError::HashingFailed)?;
    Ok(Argon2::new(Algorithm::Argon2id, Version::V0x13, params))
}

fn validate_password_hash(phc: &str) -> Result<(), CredentialError> {
    let parsed = PasswordHash::new(phc).map_err(|_| CredentialError::InvalidPasswordHash)?;
    if parsed.algorithm.as_str() != "argon2id" || parsed.version != Some(0x13) {
        return Err(CredentialError::UnsupportedPasswordHash);
    }
    let memory = parsed
        .params
        .get_decimal("m")
        .ok_or(CredentialError::InvalidPasswordHash)?;
    let iterations = parsed
        .params
        .get_decimal("t")
        .ok_or(CredentialError::InvalidPasswordHash)?;
    let lanes = parsed
        .params
        .get_decimal("p")
        .ok_or(CredentialError::InvalidPasswordHash)?;
    let output_bytes = parsed
        .hash
        .as_ref()
        .map(|output| output.len())
        .ok_or(CredentialError::InvalidPasswordHash)?;
    if !(ARGON2_MEMORY_KIB..=ARGON2_MAX_MEMORY_KIB).contains(&memory)
        || !(ARGON2_ITERATIONS..=ARGON2_MAX_ITERATIONS).contains(&iterations)
        || !(ARGON2_LANES..=ARGON2_MAX_LANES).contains(&lanes)
        || output_bytes != ARGON2_OUTPUT_BYTES
    {
        return Err(CredentialError::UnsupportedPasswordHash);
    }
    Ok(())
}

#[derive(Clone, Debug, PartialEq, Eq, Error)]
pub enum CredentialError {
    #[error(transparent)]
    Randomness(#[from] RandomnessError),
    #[error("password hashing failed")]
    HashingFailed,
    #[error("persisted password hash is malformed")]
    InvalidPasswordHash,
    #[error("persisted password hash uses an unsupported or unsafe policy")]
    UnsupportedPasswordHash,
    #[error("password verification failed unexpectedly")]
    VerificationFailed,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
pub enum RandomnessError {
    #[error("operating-system cryptographic randomness is unavailable")]
    Unavailable,
}

struct OpaqueToken(Zeroizing<String>);

impl OpaqueToken {
    fn generate() -> Result<Self, RandomnessError> {
        let mut bytes = [0_u8; TOKEN_RANDOM_BYTES];
        OsRng
            .try_fill_bytes(&mut bytes)
            .map_err(|_| RandomnessError::Unavailable)?;
        Ok(Self(Zeroizing::new(URL_SAFE_NO_PAD.encode(bytes))))
    }

    fn expose_secret(&self) -> &str {
        self.0.as_str()
    }

    fn from_presented(value: impl Into<String>) -> Result<Self, PresentedTokenError> {
        let mut value = value.into();
        if let Err(error) = validate_presented_token(&value) {
            value.zeroize();
            return Err(error);
        }
        Ok(Self(Zeroizing::new(value)))
    }
}

impl fmt::Debug for OpaqueToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("OpaqueToken([REDACTED])")
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct TokenDigest([u8; 32]);

impl TokenDigest {
    fn new(domain: &[u8], token: &str) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(domain);
        hasher.update(token.as_bytes());
        Self(hasher.finalize().into())
    }

    fn from_persistence(value: &str) -> Result<Self, TokenDigestError> {
        if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(TokenDigestError::InvalidFormat);
        }
        let mut bytes = [0_u8; 32];
        for (index, output) in bytes.iter_mut().enumerate() {
            let offset = index * 2;
            *output = u8::from_str_radix(&value[offset..offset + 2], 16)
                .map_err(|_| TokenDigestError::InvalidFormat)?;
        }
        Ok(Self(bytes))
    }

    fn to_persistence(self) -> String {
        let mut encoded = String::with_capacity(64);
        for byte in self.0 {
            use fmt::Write as _;
            write!(&mut encoded, "{byte:02x}").expect("writing to a String cannot fail");
        }
        encoded
    }

    fn verify(self, domain: &[u8], candidate: &str) -> bool {
        let candidate = Self::new(domain, candidate);
        bool::from(self.0.ct_eq(&candidate.0))
    }
}

impl fmt::Debug for TokenDigest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("TokenDigest([REDACTED])")
    }
}

fn validate_presented_token(value: &str) -> Result<(), PresentedTokenError> {
    // A 32-byte value has exactly 43 URL-safe base64 characters without
    // padding. Re-encoding also rejects non-canonical trailing bits.
    if value.len() != 43 {
        return Err(PresentedTokenError::InvalidFormat);
    }
    let decoded = Zeroizing::new(
        URL_SAFE_NO_PAD
            .decode(value)
            .map_err(|_| PresentedTokenError::InvalidFormat)?,
    );
    if decoded.len() != TOKEN_RANDOM_BYTES {
        return Err(PresentedTokenError::InvalidFormat);
    }
    let canonical = Zeroizing::new(URL_SAFE_NO_PAD.encode(decoded.as_slice()));
    if canonical.as_str() != value {
        return Err(PresentedTokenError::InvalidFormat);
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
pub enum PresentedTokenError {
    #[error("presented token must be a canonical URL-safe no-pad encoding of 32 bytes")]
    InvalidFormat,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
pub enum TokenDigestError {
    #[error("token digest must be exactly 64 hexadecimal characters")]
    InvalidFormat,
}

macro_rules! define_token_types {
    ($token:ident, $digest:ident, $domain:ident) => {
        pub struct $token(OpaqueToken);

        impl $token {
            pub fn generate() -> Result<Self, RandomnessError> {
                Ok(Self(OpaqueToken::generate()?))
            }

            /// Explicitly exposes the bearer value for one transport boundary.
            /// It must never be logged or persisted.
            pub fn expose_secret(&self) -> &str {
                self.0.expose_secret()
            }

            pub fn digest(&self) -> $digest {
                $digest(TokenDigest::new($domain, self.expose_secret()))
            }
        }

        impl fmt::Debug for $token {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(concat!(stringify!($token), "([REDACTED])"))
            }
        }

        #[derive(Clone, Copy, PartialEq, Eq)]
        pub struct $digest(TokenDigest);

        impl $digest {
            /// Validates an incoming bearer and computes its domain-separated
            /// lookup digest without constructing a secret-bearing token type.
            pub fn from_presented(value: &str) -> Result<Self, PresentedTokenError> {
                validate_presented_token(value)?;
                Ok(Self(TokenDigest::new($domain, value)))
            }

            pub fn from_persistence(value: &str) -> Result<Self, TokenDigestError> {
                Ok(Self(TokenDigest::from_persistence(value)?))
            }

            pub fn to_persistence(self) -> String {
                self.0.to_persistence()
            }

            /// Hashes the presented bearer value and compares fixed-size
            /// digests with `subtle`'s constant-time equality primitive.
            pub fn verify(self, presented: &str) -> bool {
                self.0.verify($domain, presented)
            }
        }

        impl fmt::Debug for $digest {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(concat!(stringify!($digest), "([REDACTED])"))
            }
        }
    };
}

define_token_types!(SessionToken, SessionTokenDigest, SESSION_TOKEN_DOMAIN);
define_token_types!(CsrfToken, CsrfTokenDigest, CSRF_TOKEN_DOMAIN);
define_token_types!(BootstrapToken, BootstrapTokenDigest, BOOTSTRAP_TOKEN_DOMAIN);
define_token_types!(
    MemberSetupToken,
    MemberSetupTokenDigest,
    MEMBER_SETUP_TOKEN_DOMAIN
);

impl MemberSetupToken {
    /// Parses the one public setup bearer boundary into a zeroizing value.
    /// Unlike session/CSRF lookup, setup consumption passes the secret-bearing
    /// type to storage so persistence can derive its purpose-specific digest.
    pub fn from_presented(value: impl Into<String>) -> Result<Self, PresentedTokenError> {
        Ok(Self(OpaqueToken::from_presented(value)?))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_user_ids_round_trip_and_reject_noncanonical_values() {
        let id = UserId::generate().unwrap();
        assert_eq!(UserId::parse(id.as_str()).unwrap(), id);
        assert_eq!(UserId::parse("user-1"), Err(UserIdError::InvalidFormat));
        assert_eq!(
            UserId::parse(format!("{}=", id.as_str())),
            Err(UserIdError::InvalidFormat)
        );
    }

    #[test]
    fn usernames_are_ascii_bounded_and_case_canonical() {
        assert_eq!(Username::parse("Alice_01").unwrap().as_str(), "alice_01");
        assert!(Username::parse("abc").is_ok());
        assert!(Username::parse("a".repeat(USERNAME_MAX_BYTES)).is_ok());
        assert_eq!(Username::parse("ab"), Err(UsernameError::TooShort));
        assert_eq!(
            Username::parse("a".repeat(USERNAME_MAX_BYTES + 1)),
            Err(UsernameError::TooLong)
        );
        assert_eq!(
            Username::parse("_alice"),
            Err(UsernameError::InvalidBoundary)
        );
        assert_eq!(
            Username::parse("alice-"),
            Err(UsernameError::InvalidBoundary)
        );
        assert_eq!(Username::parse("张三user"), Err(UsernameError::NonAscii));
        assert!(matches!(
            Username::parse("ali ce"),
            Err(UsernameError::InvalidCharacter { .. })
        ));
    }

    #[test]
    fn authority_context_primitives_are_strict_and_legacy_compatible() {
        assert_eq!(MembershipRole::Owner.to_string(), "owner");
        assert_eq!(
            MembershipRole::from_str("member").unwrap(),
            MembershipRole::Member
        );
        assert!(MembershipRole::from_str("admin").is_err());
        assert_eq!(
            serde_json::to_string(&MembershipRole::Owner).unwrap(),
            "\"owner\""
        );
        assert_eq!(AccountId::local().as_str(), "acc_local");
        assert!(AccountId::from_persistence(" legacy").is_err());
        assert_eq!(MembershipRevision::new(1).unwrap().get(), 1);
        assert!(MembershipRevision::new(0).is_err());

        let auth_session_id = AuthSessionId::generate().unwrap();
        assert!(auth_session_id.as_str().starts_with("asi_"));
        assert_eq!(
            AuthSessionId::from_persistence("legacy-auth-session")
                .unwrap()
                .as_str(),
            "legacy-auth-session"
        );
    }

    #[test]
    fn password_policy_checks_character_and_byte_boundaries() {
        assert!(Password::new("a".repeat(PASSWORD_MIN_CHARS)).is_ok());
        assert!(Password::new("a".repeat(PASSWORD_MAX_BYTES)).is_ok());
        assert!(matches!(
            Password::new("short"),
            Err(PasswordPolicyError::TooShort)
        ));
        assert!(Password::new("valid phrase 123").is_ok());
        assert!(matches!(
            Password::new("valid-password\n"),
            Err(PasswordPolicyError::ControlCharacter)
        ));
        assert!(matches!(
            Password::new(" ".repeat(PASSWORD_MIN_CHARS)),
            Err(PasswordPolicyError::AllWhitespace)
        ));
        assert!(matches!(
            Password::new("a".repeat(PASSWORD_MAX_BYTES + 1)),
            Err(PasswordPolicyError::TooLong)
        ));
        assert!(Password::new("界".repeat(PASSWORD_MIN_CHARS)).is_ok());
    }

    #[test]
    fn argon2id_hashes_verify_and_wrong_passwords_fail() {
        let password = Password::new("correct horse battery staple").unwrap();
        let record = hash_password(&password).unwrap();
        assert!(
            record
                .as_phc()
                .starts_with("$argon2id$v=19$m=19456,t=2,p=1$")
        );

        let authenticator = PasswordAuthenticator::new().unwrap();
        assert!(
            authenticator
                .verify(Some(&record), "correct horse battery staple")
                .unwrap()
        );
        assert!(
            !authenticator
                .verify(Some(&record), "wrong password value")
                .unwrap()
        );
        assert!(!authenticator.verify(None, "wrong password value").unwrap());
        assert!(!authenticator.verify(None, "short").unwrap());
    }

    #[test]
    fn password_and_hash_debug_output_are_redacted() {
        let secret = "a password that must not appear";
        let password = Password::new(secret).unwrap();
        let record = hash_password(&password).unwrap();
        assert!(!format!("{password:?}").contains(secret));
        assert!(!format!("{record:?}").contains(record.as_phc()));
    }

    #[test]
    fn session_tokens_are_32_bytes_and_only_digest_is_persisted() {
        let token = SessionToken::generate().unwrap();
        let decoded = URL_SAFE_NO_PAD.decode(token.expose_secret()).unwrap();
        assert_eq!(decoded.len(), TOKEN_RANDOM_BYTES);

        let digest = token.digest();
        let persisted = digest.to_persistence();
        assert_eq!(persisted.len(), 64);
        assert!(!persisted.contains(token.expose_secret()));
        assert!(digest.verify(token.expose_secret()));
        assert!(!digest.verify("a-different-session-token"));
        assert!(!format!("{token:?}").contains(token.expose_secret()));
        assert!(!format!("{digest:?}").contains(&persisted));

        let restored = SessionTokenDigest::from_persistence(&persisted).unwrap();
        assert_eq!(restored.to_persistence(), persisted);
        assert!(restored.verify(token.expose_secret()));
    }

    #[test]
    fn csrf_tokens_are_32_bytes_stable_and_domain_separated() {
        let token = CsrfToken::generate().unwrap();
        let digest = token.digest();
        let persisted = digest.to_persistence();
        assert_eq!(
            URL_SAFE_NO_PAD.decode(token.expose_secret()).unwrap().len(),
            32
        );
        assert!(digest.verify(token.expose_secret()));
        assert_eq!(
            CsrfTokenDigest::from_persistence(&persisted)
                .unwrap()
                .to_persistence(),
            persisted
        );
        assert_ne!(
            TokenDigest::new(SESSION_TOKEN_DOMAIN, token.expose_secret()),
            TokenDigest::new(CSRF_TOKEN_DOMAIN, token.expose_secret())
        );
    }

    #[test]
    fn bootstrap_tokens_round_trip_without_exposing_the_bearer() {
        let token = BootstrapToken::generate().unwrap();
        assert_eq!(
            URL_SAFE_NO_PAD.decode(token.expose_secret()).unwrap().len(),
            TOKEN_RANDOM_BYTES
        );

        let digest = token.digest();
        let persisted = digest.to_persistence();
        assert_eq!(persisted.len(), 64);
        assert!(!persisted.contains(token.expose_secret()));
        assert!(digest.verify(token.expose_secret()));
        assert!(!digest.verify("a-different-bootstrap-token"));
        assert!(!format!("{token:?}").contains(token.expose_secret()));
        assert!(!format!("{digest:?}").contains(&persisted));

        let restored = BootstrapTokenDigest::from_persistence(&persisted).unwrap();
        assert_eq!(restored.to_persistence(), persisted);
        assert!(restored.verify(token.expose_secret()));
    }

    #[test]
    fn member_setup_tokens_are_one_transport_bearers_with_a_distinct_digest_domain() {
        let token = MemberSetupToken::generate().unwrap();
        assert_eq!(
            URL_SAFE_NO_PAD.decode(token.expose_secret()).unwrap().len(),
            TOKEN_RANDOM_BYTES
        );

        let digest = token.digest();
        let persisted = digest.to_persistence();
        assert_eq!(persisted.len(), 64);
        assert!(digest.verify(token.expose_secret()));
        assert!(!persisted.contains(token.expose_secret()));
        assert!(!format!("{token:?}").contains(token.expose_secret()));
        assert!(!format!("{digest:?}").contains(&persisted));

        let restored = MemberSetupTokenDigest::from_persistence(&persisted).unwrap();
        assert_eq!(restored.to_persistence(), persisted);
        assert!(restored.verify(token.expose_secret()));
        assert_ne!(
            persisted,
            SessionTokenDigest::from_presented(token.expose_secret())
                .unwrap()
                .to_persistence()
        );
        assert_ne!(
            persisted,
            BootstrapTokenDigest::from_presented(token.expose_secret())
                .unwrap()
                .to_persistence()
        );

        let presented = MemberSetupToken::from_presented(token.expose_secret()).unwrap();
        assert_eq!(presented.expose_secret(), token.expose_secret());
        assert_eq!(presented.digest(), token.digest());
        assert!(MemberSetupToken::from_presented("not-a-canonical-token").is_err());
    }

    #[test]
    fn all_token_purposes_are_domain_separated_for_the_same_bearer() {
        let bearer = "same-opaque-bearer-value";
        let session = TokenDigest::new(SESSION_TOKEN_DOMAIN, bearer);
        let csrf = TokenDigest::new(CSRF_TOKEN_DOMAIN, bearer);
        let bootstrap = TokenDigest::new(BOOTSTRAP_TOKEN_DOMAIN, bearer);
        let member_setup = TokenDigest::new(MEMBER_SETUP_TOKEN_DOMAIN, bearer);

        assert_ne!(session, csrf);
        assert_ne!(session, bootstrap);
        assert_ne!(session, member_setup);
        assert_ne!(csrf, bootstrap);
        assert_ne!(csrf, member_setup);
        assert_ne!(bootstrap, member_setup);
    }

    #[test]
    fn presented_tokens_produce_lookup_digests_without_exposing_the_bearer() {
        let token = SessionToken::generate().unwrap();
        let value = token.expose_secret();

        let session = SessionTokenDigest::from_presented(value).unwrap();
        let csrf = CsrfTokenDigest::from_presented(value).unwrap();
        let bootstrap = BootstrapTokenDigest::from_presented(value).unwrap();
        let member_setup = MemberSetupTokenDigest::from_presented(value).unwrap();
        assert_eq!(session, token.digest());
        assert!(session.verify(value));
        assert!(csrf.verify(value));
        assert!(bootstrap.verify(value));
        assert!(member_setup.verify(value));
        assert_ne!(session.to_persistence(), csrf.to_persistence());
        assert_ne!(session.to_persistence(), bootstrap.to_persistence());
        assert_ne!(session.to_persistence(), member_setup.to_persistence());
        assert!(!format!("{session:?}").contains(value));
    }

    #[test]
    fn presented_token_parsing_rejects_malformed_or_wrong_length_values() {
        let valid = SessionToken::generate().unwrap();
        let padded = format!("{}=", valid.expose_secret());
        let invalid_character = format!("!{}", &valid.expose_secret()[1..]);
        let too_short = URL_SAFE_NO_PAD.encode([7_u8; TOKEN_RANDOM_BYTES - 1]);
        let too_long = URL_SAFE_NO_PAD.encode([7_u8; TOKEN_RANDOM_BYTES + 1]);

        for malformed in [
            "",
            padded.as_str(),
            invalid_character.as_str(),
            &too_short,
            &too_long,
        ] {
            assert_eq!(
                SessionTokenDigest::from_presented(malformed),
                Err(PresentedTokenError::InvalidFormat)
            );
            assert_eq!(
                CsrfTokenDigest::from_presented(malformed),
                Err(PresentedTokenError::InvalidFormat)
            );
            assert_eq!(
                BootstrapTokenDigest::from_presented(malformed),
                Err(PresentedTokenError::InvalidFormat)
            );
            assert_eq!(
                MemberSetupTokenDigest::from_presented(malformed),
                Err(PresentedTokenError::InvalidFormat)
            );
        }
    }

    #[test]
    fn token_digest_parser_rejects_noncanonical_values() {
        assert!(SessionTokenDigest::from_persistence("abc").is_err());
        assert!(SessionTokenDigest::from_persistence(&"z".repeat(64)).is_err());
    }
}
