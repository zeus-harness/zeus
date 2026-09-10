//! RFC 6238 TOTP and one-time recovery-code primitives.

use std::fmt;

use hmac::{Hmac, Mac};
use secrecy::{ExposeSecret, SecretSlice, SecretString};
use sha1::Sha1;
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::token::constant_time_eq_32;

type HmacSha1 = Hmac<Sha1>;

/// TOTP output width.
pub const TOTP_DIGITS: u32 = 6;
/// TOTP time step in seconds.
pub const TOTP_PERIOD_SECONDS: u64 = 30;
/// Number of adjacent time steps accepted on either side of the current step.
pub const TOTP_WINDOW: u64 = 1;
/// Number of recovery codes produced by [`generate_recovery_codes`].
pub const DEFAULT_RECOVERY_CODE_COUNT: usize = 10;
/// Number of decimal digits in each generated recovery code.
pub const RECOVERY_CODE_LENGTH: usize = 10;
/// Maximum batch size accepted by recovery-code generation.
pub const MAX_RECOVERY_CODE_COUNT: usize = 100;

/// Stable failures returned by TOTP and recovery-code operations.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum TotpError {
    /// The TOTP secret is empty or otherwise unusable.
    #[error("TOTP secret is invalid")]
    InvalidSecret,
    /// The supplied TOTP value is not six ASCII digits.
    #[error("TOTP code format is invalid")]
    InvalidCodeFormat,
    /// No counter in the configured window produced the supplied code.
    #[error("TOTP code is invalid")]
    InvalidCode,
    /// The matching counter is not newer than the persisted counter.
    #[error("TOTP code has already been used")]
    Replay,
    /// The operating system did not provide randomness.
    #[error("secure random generation failed")]
    Randomness,
    /// A recovery code is malformed.
    #[error("recovery code is invalid")]
    InvalidRecoveryCode,
    /// The requested recovery-code batch size is outside the supported range.
    #[error("recovery-code count is invalid")]
    InvalidRecoveryCodeCount,
}

impl TotpError {
    /// Returns the stable, transport-independent error code.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::InvalidSecret => "invalid_totp_secret",
            Self::InvalidCodeFormat => "invalid_totp_code_format",
            Self::InvalidCode => "invalid_totp_code",
            Self::Replay => "totp_replay",
            Self::Randomness => "randomness_failed",
            Self::InvalidRecoveryCode => "invalid_recovery_code",
            Self::InvalidRecoveryCodeCount => "invalid_recovery_code_count",
        }
    }
}

/// An RFC 6238 TOTP authenticator holding its secret in a redacted container.
#[derive(Clone)]
pub struct Totp {
    secret: SecretSlice<u8>,
}

impl Totp {
    /// Creates an authenticator from a non-empty binary TOTP secret.
    ///
    /// Base32 transport decoding is intentionally left to the application
    /// boundary; RFC 6238 operates on the decoded secret bytes.
    ///
    /// # Errors
    ///
    /// Returns [`TotpError::InvalidSecret`] for an empty secret.
    pub fn new<S>(secret: S) -> Result<Self, TotpError>
    where
        S: AsRef<[u8]>,
    {
        let secret = secret.as_ref();
        if secret.is_empty() {
            return Err(TotpError::InvalidSecret);
        }
        Ok(Self {
            secret: SecretSlice::from(secret.to_vec()),
        })
    }

    /// Returns the current TOTP counter for a Unix timestamp.
    #[must_use]
    pub const fn counter_at(timestamp_seconds: u64) -> u64 {
        timestamp_seconds / TOTP_PERIOD_SECONDS
    }

    /// Generates a six-digit code for a Unix timestamp.
    ///
    /// # Errors
    ///
    /// Returns [`TotpError::InvalidSecret`] if the authenticator was built
    /// with an unusable secret.
    pub fn code_at(&self, timestamp_seconds: u64) -> Result<String, TotpError> {
        let counter = Self::counter_at(timestamp_seconds);
        self.code_at_counter(counter)
    }

    /// Generates a six-digit code for an explicit counter.
    ///
    /// # Errors
    ///
    /// Returns [`TotpError::InvalidSecret`] if HMAC cannot use the secret.
    pub fn code_at_counter(&self, counter: u64) -> Result<String, TotpError> {
        let value = self.code_value_at_counter(counter)?;
        Ok(format!("{value:06}"))
    }

    /// Verifies a code in the current, previous, and next time steps.
    ///
    /// The returned value is the exact matching counter, which callers can
    /// persist and pass to [`Self::verify_once`] for replay protection.
    ///
    /// # Errors
    ///
    /// Returns a stable format, invalid-code, or secret error.
    pub fn verify_at(&self, code: &str, timestamp_seconds: u64) -> Result<u64, TotpError> {
        let supplied = parse_totp_code(code)?;
        let current = Self::counter_at(timestamp_seconds);
        for counter in [
            current.checked_sub(TOTP_WINDOW),
            Some(current),
            current.checked_add(TOTP_WINDOW),
        ]
        .into_iter()
        .flatten()
        {
            if self.code_value_at_counter(counter)? == supplied {
                return Ok(counter);
            }
        }
        Err(TotpError::InvalidCode)
    }

    /// Verifies a code and rejects a matching counter that was already used.
    ///
    /// A `None` value means that no prior counter has been recorded. The
    /// caller remains responsible for atomically persisting the returned
    /// counter with its account state.
    ///
    /// # Errors
    ///
    /// Returns [`TotpError::Replay`] when `counter <= last_used_counter`.
    pub fn verify_once(
        &self,
        code: &str,
        timestamp_seconds: u64,
        last_used_counter: Option<u64>,
    ) -> Result<u64, TotpError> {
        let counter = self.verify_at(code, timestamp_seconds)?;
        if is_replay(counter, last_used_counter) {
            return Err(TotpError::Replay);
        }
        Ok(counter)
    }

    fn code_value_at_counter(&self, counter: u64) -> Result<u32, TotpError> {
        let mut mac = HmacSha1::new_from_slice(self.secret.expose_secret())
            .map_err(|_| TotpError::InvalidSecret)?;
        mac.update(&counter.to_be_bytes());
        let digest = mac.finalize().into_bytes();
        let offset = usize::from(digest[19] & 0x0f);
        let binary = (u32::from(digest[offset] & 0x7f) << 24)
            | (u32::from(digest[offset + 1]) << 16)
            | (u32::from(digest[offset + 2]) << 8)
            | u32::from(digest[offset + 3]);
        Ok(binary % 10_u32.pow(TOTP_DIGITS))
    }
}

impl fmt::Debug for Totp {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Totp")
            .field("secret", &"[REDACTED]")
            .finish()
    }
}

/// Returns whether a matching TOTP counter must be rejected as a replay.
#[must_use]
pub const fn is_replay(counter: u64, last_used_counter: Option<u64>) -> bool {
    match last_used_counter {
        Some(last_used_counter) => counter <= last_used_counter,
        None => false,
    }
}

/// A generated recovery code with a redacted debug representation.
#[derive(Clone)]
pub struct RecoveryCode(SecretString);

impl RecoveryCode {
    /// Exposes the code for one-time presentation to the account owner.
    #[must_use]
    pub fn as_str(&self) -> &str {
        self.0.expose_secret()
    }

    /// Computes the digest that should be persisted instead of this code.
    #[must_use]
    pub fn digest(&self) -> RecoveryCodeDigest {
        RecoveryCodeDigest::from_normalized(self.as_str())
    }
}

impl fmt::Debug for RecoveryCode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RecoveryCode")
            .field("value", &"[REDACTED]")
            .finish()
    }
}

/// A SHA-256 recovery-code digest suitable for persistence.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct RecoveryCodeDigest([u8; 32]);

impl RecoveryCodeDigest {
    /// Returns the raw digest bytes.
    #[must_use]
    pub const fn as_bytes(self) -> [u8; 32] {
        self.0
    }

    fn from_normalized(code: &str) -> Self {
        let computed = Sha256::digest(code.as_bytes());
        let mut digest = [0_u8; 32];
        digest.copy_from_slice(&computed);
        Self(digest)
    }
}

impl AsRef<[u8]> for RecoveryCodeDigest {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for RecoveryCodeDigest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RecoveryCodeDigest([REDACTED])")
    }
}

/// A digest-only recovery-code collection with consume-once semantics.
#[derive(Clone, Default, Eq, PartialEq)]
pub struct RecoveryCodeDigests {
    digests: Vec<RecoveryCodeDigest>,
}

impl RecoveryCodeDigests {
    /// Builds a digest-only collection, removing duplicate digests.
    #[must_use]
    pub fn from_digests<I>(digests: I) -> Self
    where
        I: IntoIterator<Item = RecoveryCodeDigest>,
    {
        let mut stored = Self::default();
        for digest in digests {
            if !stored.contains_digest(&digest) {
                stored.digests.push(digest);
            }
        }
        stored
    }

    /// Computes and retains only digests from a one-time generated code batch.
    #[must_use]
    pub fn from_codes(codes: &[RecoveryCode]) -> Self {
        Self::from_digests(codes.iter().map(RecoveryCode::digest))
    }

    /// Returns the number of unconsumed codes.
    #[must_use]
    pub fn len(&self) -> usize {
        self.digests.len()
    }

    /// Returns whether no unconsumed digests remain.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.digests.is_empty()
    }

    /// Returns the stored digest values without exposing any recovery code.
    #[must_use]
    pub fn as_slice(&self) -> &[RecoveryCodeDigest] {
        &self.digests
    }

    /// Checks and consumes a matching recovery code exactly once.
    ///
    /// The digest comparison scans every stored digest before deciding, so a
    /// match position is not used as an early-exit signal.
    ///
    /// # Errors
    ///
    /// Returns [`TotpError::InvalidRecoveryCode`] for malformed input.
    pub fn consume(&mut self, code: &str) -> Result<bool, TotpError> {
        let digest = recovery_code_digest(code)?;
        let mut matched_index = None;
        for (index, stored) in self.digests.iter().enumerate() {
            if constant_time_eq_32(&digest.0, &stored.0) && matched_index.is_none() {
                matched_index = Some(index);
            }
        }
        if let Some(index) = matched_index {
            self.digests.swap_remove(index);
            return Ok(true);
        }
        Ok(false)
    }

    /// Checks a recovery code without consuming it.
    ///
    /// # Errors
    ///
    /// Returns [`TotpError::InvalidRecoveryCode`] for malformed input.
    pub fn contains(&self, code: &str) -> Result<bool, TotpError> {
        let digest = recovery_code_digest(code)?;
        Ok(self.contains_digest(&digest))
    }

    fn contains_digest(&self, expected: &RecoveryCodeDigest) -> bool {
        let mut found = false;
        for stored in &self.digests {
            found |= constant_time_eq_32(&expected.0, &stored.0);
        }
        found
    }
}

impl fmt::Debug for RecoveryCodeDigests {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RecoveryCodeDigests")
            .field("count", &self.digests.len())
            .finish()
    }
}

/// Generates the default ten decimal recovery codes.
///
/// The returned plaintext values are intended for one-time display. Callers
/// should immediately turn them into [`RecoveryCodeDigests`] and persist only
/// that digest collection.
///
/// # Errors
///
/// Returns [`TotpError::Randomness`] when the operating system RNG fails.
pub fn generate_recovery_codes() -> Result<Vec<RecoveryCode>, TotpError> {
    generate_recovery_codes_with_count(DEFAULT_RECOVERY_CODE_COUNT)
}

/// Generates a bounded batch of decimal recovery codes.
///
/// # Errors
///
/// Returns a stable count or randomness error.
pub fn generate_recovery_codes_with_count(count: usize) -> Result<Vec<RecoveryCode>, TotpError> {
    if !(1..=MAX_RECOVERY_CODE_COUNT).contains(&count) {
        return Err(TotpError::InvalidRecoveryCodeCount);
    }
    (0..count).map(|_| generate_recovery_code()).collect()
}

/// Normalizes a recovery code by removing ASCII whitespace and hyphens.
///
/// The normalized value must contain exactly ten ASCII decimal digits.
///
/// # Errors
///
/// Returns [`TotpError::InvalidRecoveryCode`] for any other shape.
pub fn normalize_recovery_code(code: &str) -> Result<String, TotpError> {
    let mut normalized = String::with_capacity(code.len());
    for byte in code.bytes() {
        match byte {
            b'0'..=b'9' => normalized.push(char::from(byte)),
            b'-' if !normalized.is_empty() => {}
            byte if byte.is_ascii_whitespace() => {}
            _ => return Err(TotpError::InvalidRecoveryCode),
        }
    }
    if normalized.len() == RECOVERY_CODE_LENGTH {
        Ok(normalized)
    } else {
        Err(TotpError::InvalidRecoveryCode)
    }
}

/// Normalizes a recovery code and returns its SHA-256 digest.
///
/// # Errors
///
/// Returns [`TotpError::InvalidRecoveryCode`] for malformed input.
pub fn recovery_code_digest(code: &str) -> Result<RecoveryCodeDigest, TotpError> {
    Ok(RecoveryCodeDigest::from_normalized(
        &normalize_recovery_code(code)?,
    ))
}

fn generate_recovery_code() -> Result<RecoveryCode, TotpError> {
    let mut code = String::with_capacity(RECOVERY_CODE_LENGTH);
    for _ in 0..RECOVERY_CODE_LENGTH {
        let digit = loop {
            let mut sample = [0_u8; 1];
            getrandom::fill(&mut sample).map_err(|_| TotpError::Randomness)?;
            if sample[0] < 250 {
                break sample[0] % 10;
            }
        };
        code.push(char::from(b'0' + digit));
    }
    Ok(RecoveryCode(SecretString::from(code)))
}

fn parse_totp_code(code: &str) -> Result<u32, TotpError> {
    if code.len() != 6 || !code.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(TotpError::InvalidCodeFormat);
    }
    code.parse().map_err(|_| TotpError::InvalidCodeFormat)
}

#[cfg(test)]
mod tests {
    use super::{
        DEFAULT_RECOVERY_CODE_COUNT, RECOVERY_CODE_LENGTH, TOTP_PERIOD_SECONDS, Totp, TotpError,
        generate_recovery_codes, is_replay, normalize_recovery_code, recovery_code_digest,
    };

    #[test]
    fn rfc6238_sha1_six_digit_vectors_match() {
        let totp = Totp::new(b"12345678901234567890").expect("secret");
        for (timestamp, expected) in [
            (59, "287082"),
            (1_111_111_109, "081804"),
            (1_111_111_111, "050471"),
            (1_234_567_890, "005924"),
            (2_000_000_000, "279037"),
            (20_000_000_000, "353130"),
        ] {
            assert_eq!(totp.code_at(timestamp).expect("code"), expected);
        }
    }

    #[test]
    fn verification_accepts_one_step_each_side_and_returns_counter() {
        let totp = Totp::new(b"12345678901234567890").expect("secret");
        let timestamp = 2 * TOTP_PERIOD_SECONDS;
        let previous = totp.code_at_counter(1).expect("previous");
        let current = totp.code_at_counter(2).expect("current");
        let next = totp.code_at_counter(3).expect("next");
        assert_eq!(totp.verify_at(&previous, timestamp), Ok(1));
        assert_eq!(totp.verify_at(&current, timestamp), Ok(2));
        assert_eq!(totp.verify_at(&next, timestamp), Ok(3));
        assert_eq!(
            totp.verify_at("12", timestamp),
            Err(TotpError::InvalidCodeFormat)
        );
        assert_eq!(
            totp.verify_at("999999", timestamp),
            Err(TotpError::InvalidCode)
        );
    }

    #[test]
    fn replay_check_rejects_equal_and_older_counters() {
        let totp = Totp::new(b"12345678901234567890").expect("secret");
        let code = totp.code_at_counter(2).expect("code");
        assert_eq!(totp.verify_once(&code, 60, None), Ok(2));
        assert_eq!(totp.verify_once(&code, 60, Some(2)), Err(TotpError::Replay));
        assert_eq!(totp.verify_once(&code, 60, Some(3)), Err(TotpError::Replay));
        assert!(!is_replay(3, Some(2)));
    }

    #[test]
    fn recovery_codes_are_digest_only_and_consumed_once() {
        let codes = generate_recovery_codes().expect("codes");
        assert_eq!(codes.len(), DEFAULT_RECOVERY_CODE_COUNT);
        assert!(
            codes
                .iter()
                .all(|code| code.as_str().len() == RECOVERY_CODE_LENGTH)
        );

        let first = codes[0].as_str().to_owned();
        let mut stored = super::RecoveryCodeDigests::from_codes(&codes);
        assert_eq!(stored.len(), DEFAULT_RECOVERY_CODE_COUNT);
        assert!(stored.consume(&first).expect("consume"));
        assert!(!stored.consume(&first).expect("second consume"));
        assert_eq!(stored.len(), DEFAULT_RECOVERY_CODE_COUNT - 1);
        assert!(
            stored
                .as_slice()
                .iter()
                .all(|digest| { !format!("{digest:?}").contains(&first) })
        );
    }

    #[test]
    fn recovery_normalization_is_shared_by_digest() {
        assert_eq!(
            normalize_recovery_code(" 1234-5678-90\n").expect("normalize"),
            "1234567890"
        );
        assert_eq!(
            recovery_code_digest("1234-5678-90").expect("digest"),
            recovery_code_digest("1234567890").expect("digest")
        );
        assert_eq!(
            normalize_recovery_code("not-a-code"),
            Err(TotpError::InvalidRecoveryCode)
        );
    }
}
