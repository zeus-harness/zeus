//! Password and email normalization plus Argon2id password hashing.

use std::{collections::HashSet, fmt};

use argon2::{
    Algorithm, Argon2, Params, PasswordHasher as _, PasswordVerifier as _, Version,
    password_hash::phc::PasswordHash,
};
use secrecy::{ExposeSecret, SecretString};
use thiserror::Error;
use unicode_normalization::UnicodeNormalization;

/// Argon2id memory cost in KiB for newly created password hashes.
pub const ARGON2_MEMORY_KIB: u32 = 65_536;
/// Argon2id time cost for newly created password hashes.
pub const ARGON2_TIME_COST: u32 = 3;
/// Argon2id parallelism for newly created password hashes.
pub const ARGON2_PARALLELISM: u32 = 4;
/// Salt size in bytes for newly created password hashes.
pub const ARGON2_SALT_BYTES: usize = 16;
/// Derived password hash size in bytes for newly created password hashes.
pub const ARGON2_OUTPUT_BYTES: usize = 32;
/// Minimum password length measured in Unicode scalar values after NFC.
pub const MIN_PASSWORD_CODE_POINTS: usize = 15;
/// Maximum password length measured in Unicode scalar values after NFC.
pub const MAX_PASSWORD_CODE_POINTS: usize = 128;

/// Stable failures returned by password and email operations.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum PasswordError {
    /// The email is not ASCII or does not have the accepted mailbox shape.
    #[error("email is invalid")]
    InvalidEmail,
    /// The password has fewer than [`MIN_PASSWORD_CODE_POINTS`] code points.
    #[error("password is too short")]
    PasswordTooShort,
    /// The password has more than [`MAX_PASSWORD_CODE_POINTS`] code points.
    #[error("password is too long")]
    PasswordTooLong,
    /// The password is present in the configured weak-password set.
    #[error("password is too weak")]
    WeakPassword,
    /// The operating system did not provide a salt.
    #[error("secure random generation failed")]
    Randomness,
    /// Argon2 could not produce a hash.
    #[error("password hashing failed")]
    HashingFailed,
    /// The stored PHC string is malformed or unsupported.
    #[error("password hash is invalid")]
    InvalidHash,
}

impl PasswordError {
    /// Returns the stable, transport-independent error code.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::InvalidEmail => "invalid_email",
            Self::PasswordTooShort => "password_too_short",
            Self::PasswordTooLong => "password_too_long",
            Self::WeakPassword => "weak_password",
            Self::Randomness => "randomness_failed",
            Self::HashingFailed => "hashing_failed",
            Self::InvalidHash => "invalid_hash",
        }
    }
}

/// A normalized password whose debug representation is redacted.
#[derive(Clone)]
pub struct NormalizedPassword(SecretString);

impl NormalizedPassword {
    /// Exposes the normalized password for the short duration of a hash call.
    #[must_use]
    pub fn as_str(&self) -> &str {
        self.0.expose_secret()
    }

    /// Returns the normalized password's Unicode scalar-value length.
    #[must_use]
    pub fn code_point_len(&self) -> usize {
        self.as_str().chars().count()
    }
}

impl PartialEq for NormalizedPassword {
    fn eq(&self, other: &Self) -> bool {
        self.as_str() == other.as_str()
    }
}

impl Eq for NormalizedPassword {}

impl fmt::Debug for NormalizedPassword {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("NormalizedPassword")
            .field("value", &"[REDACTED]")
            .finish()
    }
}

/// A normalized weak-password lookup set.
///
/// Values are NFC-normalized when the set is built. The set's debug output
/// includes only its size, never any password material.
#[derive(Clone, Default)]
pub struct WeakPasswordSet {
    values: HashSet<String>,
}

impl WeakPasswordSet {
    /// Builds a set from values that will be compared after NFC normalization.
    pub fn new<I, S>(values: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        Self {
            values: values
                .into_iter()
                .map(|value| normalize_nfc(value.as_ref()))
                .collect(),
        }
    }

    /// Returns the number of entries in the set.
    #[must_use]
    pub fn len(&self) -> usize {
        self.values.len()
    }

    /// Returns whether the set has no entries.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.values.is_empty()
    }

    fn contains(&self, password: &NormalizedPassword) -> bool {
        self.values.contains(password.as_str())
    }
}

impl fmt::Debug for WeakPasswordSet {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WeakPasswordSet")
            .field("entries", &self.values.len())
            .finish()
    }
}

/// Password validation settings.
#[derive(Clone, Debug, Default)]
pub struct PasswordPolicy {
    weak_passwords: Option<WeakPasswordSet>,
}

impl PasswordPolicy {
    /// Creates a policy without a weak-password list.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            weak_passwords: None,
        }
    }

    /// Creates a policy that rejects passwords in `weak_passwords`.
    #[must_use]
    pub const fn with_weak_passwords(weak_passwords: WeakPasswordSet) -> Self {
        Self {
            weak_passwords: Some(weak_passwords),
        }
    }

    /// Validates and NFC-normalizes a password under this policy.
    ///
    /// # Errors
    ///
    /// Returns a stable error for a length or weak-password violation.
    pub fn validate(&self, password: &str) -> Result<NormalizedPassword, PasswordError> {
        validate_password(password, self.weak_passwords.as_ref())
    }
}

/// Normalizes an email address by trimming and ASCII lowercasing it.
///
/// The accepted shape is an ASCII local part, one `@`, and one or more
/// dot-separated ASCII domain labels. Quoted local parts and domain literals
/// are intentionally outside this application policy.
///
/// # Errors
///
/// Returns [`PasswordError::InvalidEmail`] for non-ASCII input or an invalid
/// mailbox shape.
pub fn normalize_email(email: &str) -> Result<String, PasswordError> {
    let email = email.trim();
    if email.is_empty() || !email.is_ascii() || email.len() > 254 {
        return Err(PasswordError::InvalidEmail);
    }

    let Some((local, domain)) = email.split_once('@') else {
        return Err(PasswordError::InvalidEmail);
    };
    if local.is_empty()
        || domain.is_empty()
        || domain.contains('@')
        || local.len() > 64
        || domain.len() > 253
        || local.starts_with('.')
        || local.ends_with('.')
        || local.contains("..")
        || !local.bytes().all(is_valid_local_byte)
    {
        return Err(PasswordError::InvalidEmail);
    }

    let labels = domain.split('.').collect::<Vec<_>>();
    if labels.is_empty()
        || labels.iter().any(|label| {
            label.is_empty()
                || label.len() > 63
                || label.starts_with('-')
                || label.ends_with('-')
                || !label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        })
    {
        return Err(PasswordError::InvalidEmail);
    }

    Ok(email.to_ascii_lowercase())
}

/// NFC-normalizes and validates a password by Unicode scalar-value count.
///
/// # Errors
///
/// Returns a stable length error when the normalized password is outside the
/// inclusive 15--128 code-point range.
pub fn normalize_password(password: &str) -> Result<NormalizedPassword, PasswordError> {
    let normalized = normalize_nfc(password);
    let code_points = normalized.chars().count();
    if code_points < MIN_PASSWORD_CODE_POINTS {
        return Err(PasswordError::PasswordTooShort);
    }
    if code_points > MAX_PASSWORD_CODE_POINTS {
        return Err(PasswordError::PasswordTooLong);
    }
    Ok(NormalizedPassword(SecretString::from(normalized)))
}

/// Validates a password and optionally rejects it against a weak-password set.
///
/// # Errors
///
/// Returns a stable validation error without including password material.
pub fn validate_password(
    password: &str,
    weak_passwords: Option<&WeakPasswordSet>,
) -> Result<NormalizedPassword, PasswordError> {
    let normalized = normalize_password(password)?;
    if weak_passwords.is_some_and(|set| set.contains(&normalized)) {
        return Err(PasswordError::WeakPassword);
    }
    Ok(normalized)
}

/// Hashes a validated password with the fixed Argon2id PHC profile.
///
/// Newly generated hashes use Argon2id v=19, `m=65536,t=3,p=4`, a random
/// 16-byte salt, and a 32-byte output. The returned string contains only the
/// PHC representation, never the input password.
///
/// # Errors
///
/// Returns a stable validation, randomness, or hashing error.
pub fn hash_password(
    password: &str,
    weak_passwords: Option<&WeakPasswordSet>,
) -> Result<String, PasswordError> {
    let normalized = validate_password(password, weak_passwords)?;
    hash_normalized_password(&normalized)
}

pub(crate) fn hash_normalized_password(
    password: &NormalizedPassword,
) -> Result<String, PasswordError> {
    let mut salt = [0_u8; ARGON2_SALT_BYTES];
    getrandom::fill(&mut salt).map_err(|_| PasswordError::Randomness)?;
    let params = Params::new(
        ARGON2_MEMORY_KIB,
        ARGON2_TIME_COST,
        ARGON2_PARALLELISM,
        Some(ARGON2_OUTPUT_BYTES),
    )
    .map_err(|_| PasswordError::HashingFailed)?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    argon2
        .hash_password_with_salt(password.as_str().as_bytes(), &salt)
        .map(|hash| hash.to_string())
        .map_err(|_| PasswordError::HashingFailed)
}

/// The result of checking a password against a stored PHC string.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PasswordVerification {
    /// Whether the supplied password matched the stored hash.
    pub valid: bool,
    /// Whether a successful login should replace the hash with the current profile.
    pub needs_rehash: bool,
}

impl PasswordVerification {
    /// Returns a successful verification result.
    #[must_use]
    pub const fn valid(needs_rehash: bool) -> Self {
        Self {
            valid: true,
            needs_rehash,
        }
    }

    /// Returns an unsuccessful verification result.
    #[must_use]
    pub const fn invalid() -> Self {
        Self {
            valid: false,
            needs_rehash: false,
        }
    }
}

/// Backwards-compatible name for [`PasswordVerification`].
pub type PasswordHashVerification = PasswordVerification;

/// Verifies a password against a PHC string and reports whether it needs rehashing.
///
/// Valid Argon2id hashes using older parameters are still verified, but a
/// successful check reports `needs_rehash = true`. Other Argon2 algorithms or
/// malformed hashes are rejected as invalid stored hashes.
///
/// # Errors
///
/// Returns a stable validation error for the candidate or stored PHC string.
pub fn verify_password(
    password: &str,
    encoded_hash: &str,
) -> Result<PasswordVerification, PasswordError> {
    let normalized = normalize_password(password)?;
    verify_normalized_password(&normalized, encoded_hash)
}

pub(crate) fn verify_normalized_password(
    normalized: &NormalizedPassword,
    encoded_hash: &str,
) -> Result<PasswordVerification, PasswordError> {
    let parsed = PasswordHash::new(encoded_hash).map_err(|_| PasswordError::InvalidHash)?;
    if parsed.algorithm.as_str() != Algorithm::Argon2id.as_str()
        || parsed.salt.is_none()
        || parsed.hash.is_none()
    {
        return Err(PasswordError::InvalidHash);
    }
    Params::try_from(&parsed).map_err(|_| PasswordError::InvalidHash)?;

    match Argon2::default().verify_password(normalized.as_str().as_bytes(), &parsed) {
        Ok(()) => Ok(PasswordVerification::valid(!is_current_hash(&parsed))),
        Err(argon2::password_hash::Error::PasswordInvalid) => Ok(PasswordVerification::invalid()),
        Err(_) => Err(PasswordError::InvalidHash),
    }
}

fn normalize_nfc(value: &str) -> String {
    value.nfc().collect()
}

fn is_valid_local_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric()
        || matches!(
            byte,
            b'!' | b'#'
                | b'$'
                | b'%'
                | b'&'
                | b'\''
                | b'*'
                | b'+'
                | b'-'
                | b'/'
                | b'='
                | b'?'
                | b'^'
                | b'_'
                | b'`'
                | b'{'
                | b'|'
                | b'}'
                | b'~'
                | b'.'
        )
}

fn is_current_hash(hash: &PasswordHash) -> bool {
    hash.algorithm.as_str() == Algorithm::Argon2id.as_str()
        && hash.version == Some(u32::from(Version::V0x13))
        && hash.params.get_decimal("m") == Some(ARGON2_MEMORY_KIB)
        && hash.params.get_decimal("t") == Some(ARGON2_TIME_COST)
        && hash.params.get_decimal("p") == Some(ARGON2_PARALLELISM)
        && hash.params.get("keyid").is_none()
        && hash.params.get("data").is_none()
        && hash
            .salt
            .as_ref()
            .is_some_and(|salt| salt.len() == ARGON2_SALT_BYTES)
        && hash
            .hash
            .as_ref()
            .is_some_and(|output| output.len() == ARGON2_OUTPUT_BYTES)
}

#[cfg(test)]
mod tests {
    use argon2::{Algorithm, Argon2, Params, PasswordHasher as _, Version};

    use super::{
        ARGON2_MEMORY_KIB, ARGON2_OUTPUT_BYTES, ARGON2_PARALLELISM, ARGON2_SALT_BYTES,
        ARGON2_TIME_COST, MAX_PASSWORD_CODE_POINTS, MIN_PASSWORD_CODE_POINTS, PasswordError,
        PasswordHashVerification, WeakPasswordSet, hash_password, normalize_email,
        normalize_password, validate_password, verify_password,
    };

    #[test]
    fn email_is_trimmed_lowercased_and_shape_checked() {
        assert_eq!(
            normalize_email("  Alice@Example.COM ").expect("valid email"),
            "alice@example.com"
        );
        for invalid in [
            "alice",
            "alice@@example.com",
            "@example.com",
            "a..b@example.com",
        ] {
            assert_eq!(normalize_email(invalid), Err(PasswordError::InvalidEmail));
        }
        assert_eq!(
            normalize_email("用户@example.com"),
            Err(PasswordError::InvalidEmail)
        );
    }

    #[test]
    fn password_boundaries_are_nfc_normalized_and_counted_by_code_point() {
        let minimum = "a".repeat(MIN_PASSWORD_CODE_POINTS);
        let maximum = "🦀".repeat(MAX_PASSWORD_CODE_POINTS);
        assert_eq!(
            normalize_password(&minimum)
                .expect("minimum")
                .code_point_len(),
            15
        );
        assert_eq!(
            normalize_password(&maximum)
                .expect("maximum")
                .code_point_len(),
            128
        );
        assert_eq!(
            normalize_password(&"a".repeat(MIN_PASSWORD_CODE_POINTS - 1)),
            Err(PasswordError::PasswordTooShort)
        );
        assert_eq!(
            normalize_password(&"a".repeat(MAX_PASSWORD_CODE_POINTS + 1)),
            Err(PasswordError::PasswordTooLong)
        );

        let composed = format!("{}{}", "e\u{301}".repeat(14), "x");
        assert_eq!(
            normalize_password(&composed).expect("nfc").code_point_len(),
            15
        );
    }

    #[test]
    fn optional_weak_password_set_is_checked_after_normalization() {
        let weak = WeakPasswordSet::new(["a".repeat(MIN_PASSWORD_CODE_POINTS)]);
        assert_eq!(
            validate_password(&"a".repeat(MIN_PASSWORD_CODE_POINTS), Some(&weak)),
            Err(PasswordError::WeakPassword)
        );
        assert!(validate_password(&"b".repeat(MIN_PASSWORD_CODE_POINTS), Some(&weak)).is_ok());
    }

    #[test]
    fn new_hashes_use_the_fixed_argon2id_profile() {
        let password = "correct horse battery staple";
        let encoded = hash_password(password, None).expect("hash");
        assert!(encoded.starts_with("$argon2id$v=19$m=65536,t=3,p=4$"));
        let parsed = argon2::password_hash::phc::PasswordHash::new(&encoded).expect("phc");
        assert_eq!(parsed.salt.as_ref().expect("salt").len(), ARGON2_SALT_BYTES);
        assert_eq!(
            parsed.hash.as_ref().expect("output").len(),
            ARGON2_OUTPUT_BYTES
        );
        assert_eq!(parsed.params.get_decimal("m"), Some(ARGON2_MEMORY_KIB));
        assert_eq!(parsed.params.get_decimal("t"), Some(ARGON2_TIME_COST));
        assert_eq!(parsed.params.get_decimal("p"), Some(ARGON2_PARALLELISM));
    }

    #[test]
    fn verification_reports_match_and_rehash_need() {
        let password = "correct horse battery staple";
        let current = hash_password(password, None).expect("current hash");
        assert_eq!(
            verify_password(password, &current).expect("verify"),
            PasswordHashVerification::valid(false)
        );
        assert_eq!(
            verify_password("wrong horse battery staple", &current).expect("verify"),
            PasswordHashVerification::invalid()
        );

        let old_params = Params::new(8 * 1024, 1, 1, Some(ARGON2_OUTPUT_BYTES)).expect("params");
        let old_hash = Argon2::new(Algorithm::Argon2id, Version::V0x13, old_params)
            .hash_password_with_salt(password.as_bytes(), &[7_u8; ARGON2_SALT_BYTES])
            .expect("old hash")
            .to_string();
        assert_eq!(
            verify_password(password, &old_hash).expect("old verify"),
            PasswordHashVerification::valid(true)
        );
    }
}
