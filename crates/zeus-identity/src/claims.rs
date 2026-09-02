//! Pure OIDC and JWT claim types with structural and time validation.

use serde::{Deserialize, Deserializer, Serialize};
use thiserror::Error;

use crate::{normalize_email, policy::OidcScopes};

/// Stable failures returned by claim validation.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum ClaimsError {
    /// The issuer is empty or contains whitespace/control characters.
    #[error("issuer claim is invalid")]
    InvalidIssuer,
    /// The subject or JWT ID is empty or malformed.
    #[error("subject claim is invalid")]
    InvalidSubject,
    /// The audience list is empty or contains a malformed value.
    #[error("audience claim is invalid")]
    InvalidAudience,
    /// Numeric date claims are inconsistent or outside the requested time.
    #[error("JWT time claims are invalid")]
    InvalidTime,
    /// A scope claim is malformed.
    #[error("scope claim is invalid")]
    InvalidScope,
    /// An OIDC email claim is malformed.
    #[error("email claim is invalid")]
    InvalidEmail,
}

impl ClaimsError {
    /// Returns the stable, transport-independent error code.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::InvalidIssuer => "invalid_issuer_claim",
            Self::InvalidSubject => "invalid_subject_claim",
            Self::InvalidAudience => "invalid_audience_claim",
            Self::InvalidTime => "invalid_time_claim",
            Self::InvalidScope => "invalid_scope_claim",
            Self::InvalidEmail => "invalid_email_claim",
        }
    }
}

/// A validated set of common JWT claims.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct JwtClaims {
    /// Issuer (`iss`).
    #[serde(rename = "iss")]
    pub issuer: String,
    /// Subject (`sub`).
    #[serde(rename = "sub")]
    pub subject: String,
    /// Audience (`aud`), represented canonically as a list.
    #[serde(rename = "aud", deserialize_with = "deserialize_audience")]
    pub audience: Vec<String>,
    /// Expiration `NumericDate` (`exp`).
    #[serde(rename = "exp")]
    pub expires_at: u64,
    /// Issued-at `NumericDate` (`iat`).
    #[serde(rename = "iat")]
    pub issued_at: u64,
    /// Optional not-before `NumericDate` (`nbf`).
    #[serde(rename = "nbf", default, skip_serializing_if = "Option::is_none")]
    pub not_before: Option<u64>,
    /// Optional JWT ID (`jti`).
    #[serde(rename = "jti", default, skip_serializing_if = "Option::is_none")]
    pub jwt_id: Option<String>,
    /// Optional space-delimited scope claim (`scope`).
    #[serde(rename = "scope", default, skip_serializing_if = "String::is_empty")]
    pub scope: String,
}

impl JwtClaims {
    /// Validates structural claim invariants without consulting a clock.
    ///
    /// # Errors
    ///
    /// Returns a stable claim error when an identifier, audience, time, or
    /// scope invariant is violated.
    pub fn validate(&self) -> Result<(), ClaimsError> {
        self.validate_common()?;
        if self.expires_at <= self.issued_at
            || self
                .not_before
                .is_some_and(|not_before| not_before >= self.expires_at)
        {
            return Err(ClaimsError::InvalidTime);
        }
        Ok(())
    }

    /// Validates the claims for `now` expressed as a Unix timestamp.
    ///
    /// # Errors
    ///
    /// Returns [`ClaimsError::InvalidTime`] when the claims are not active at
    /// `now`, or a structural claim error.
    pub fn validate_at(&self, now: u64) -> Result<(), ClaimsError> {
        self.validate()?;
        if self.issued_at > now
            || self.expires_at <= now
            || self.not_before.is_some_and(|not_before| not_before > now)
        {
            return Err(ClaimsError::InvalidTime);
        }
        Ok(())
    }

    fn validate_common(&self) -> Result<(), ClaimsError> {
        validate_issuer(&self.issuer)?;
        validate_identifier(&self.subject).map_err(|()| ClaimsError::InvalidSubject)?;
        if self.audience.is_empty()
            || self
                .audience
                .iter()
                .any(|audience| validate_identifier(audience).is_err())
        {
            return Err(ClaimsError::InvalidAudience);
        }
        if self
            .jwt_id
            .as_deref()
            .is_some_and(|jwt_id| validate_identifier(jwt_id).is_err())
        {
            return Err(ClaimsError::InvalidSubject);
        }
        OidcScopes::from_space_delimited(&self.scope, false)
            .map_err(|_| ClaimsError::InvalidScope)?;
        Ok(())
    }
}

/// Common identity claims returned by an OIDC provider.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OidcClaims {
    /// Issuer (`iss`).
    #[serde(rename = "iss")]
    pub issuer: String,
    /// Subject (`sub`).
    #[serde(rename = "sub")]
    pub subject: String,
    /// Audience (`aud`), represented canonically as a list.
    #[serde(rename = "aud", deserialize_with = "deserialize_audience")]
    pub audience: Vec<String>,
    /// Optional email claim.
    pub email: Option<String>,
    /// Optional provider assertion for email verification.
    pub email_verified: Option<bool>,
    /// Optional OIDC scope claim.
    #[serde(default)]
    pub scope: String,
}

impl OidcClaims {
    /// Validates issuer, subject, audience, email, and optional OIDC scope.
    ///
    /// # Errors
    ///
    /// Returns a stable error when an OIDC claim is malformed.
    pub fn validate(&self) -> Result<(), ClaimsError> {
        validate_issuer(&self.issuer)?;
        validate_identifier(&self.subject).map_err(|()| ClaimsError::InvalidSubject)?;
        if self.audience.is_empty()
            || self
                .audience
                .iter()
                .any(|audience| validate_identifier(audience).is_err())
        {
            return Err(ClaimsError::InvalidAudience);
        }
        if self
            .email
            .as_deref()
            .is_some_and(|email| normalize_email(email).is_err())
        {
            return Err(ClaimsError::InvalidEmail);
        }
        if !self.scope.is_empty() {
            OidcScopes::from_space_delimited(&self.scope, true)
                .map_err(|_| ClaimsError::InvalidScope)?;
        }
        Ok(())
    }
}

fn validate_issuer(issuer: &str) -> Result<(), ClaimsError> {
    if issuer.is_empty()
        || issuer.trim() != issuer
        || issuer.chars().any(char::is_whitespace)
        || issuer.chars().any(char::is_control)
    {
        Err(ClaimsError::InvalidIssuer)
    } else {
        Ok(())
    }
}

fn validate_identifier(identifier: &str) -> Result<(), ()> {
    if identifier.is_empty()
        || identifier.len() > 255
        || identifier.chars().any(char::is_whitespace)
        || identifier.chars().any(char::is_control)
    {
        Err(())
    } else {
        Ok(())
    }
}

fn deserialize_audience<'de, D>(deserializer: D) -> Result<Vec<String>, D::Error>
where
    D: Deserializer<'de>,
{
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum Audience {
        One(String),
        Many(Vec<String>),
    }

    match Audience::deserialize(deserializer)? {
        Audience::One(audience) => Ok(vec![audience]),
        Audience::Many(audience) => Ok(audience),
    }
}

#[cfg(test)]
mod tests {
    use super::{ClaimsError, JwtClaims, OidcClaims};

    fn jwt() -> JwtClaims {
        JwtClaims {
            issuer: "https://issuer.example".to_owned(),
            subject: "user-1".to_owned(),
            audience: vec!["zeus".to_owned()],
            expires_at: 200,
            issued_at: 100,
            not_before: Some(100),
            jwt_id: Some("jti-1".to_owned()),
            scope: "openid profile".to_owned(),
        }
    }

    #[test]
    fn jwt_claims_validate_time_and_scope() {
        assert!(jwt().validate_at(150).is_ok());
        let mut expired = jwt();
        expired.expires_at = 150;
        assert_eq!(expired.validate_at(150), Err(ClaimsError::InvalidTime));
        let mut invalid_scope = jwt();
        invalid_scope.scope = "bad\\scope".to_owned();
        assert_eq!(invalid_scope.validate(), Err(ClaimsError::InvalidScope));
    }

    #[test]
    fn oidc_claims_validate_email_and_openid_scope() {
        let claims = OidcClaims {
            issuer: "https://issuer.example".to_owned(),
            subject: "subject".to_owned(),
            audience: vec!["client".to_owned()],
            email: Some("Alice@Example.COM".to_owned()),
            email_verified: Some(true),
            scope: "openid email".to_owned(),
        };
        assert!(claims.validate().is_ok());
        let invalid = OidcClaims {
            scope: "email".to_owned(),
            ..claims
        };
        assert_eq!(invalid.validate(), Err(ClaimsError::InvalidScope));
    }
}
