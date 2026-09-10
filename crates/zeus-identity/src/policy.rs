//! Pure identity policy types and validation.

use std::collections::BTreeSet;

use serde::{Deserialize, Deserializer, Serialize};
use thiserror::Error;

/// Stable failures returned by identity-policy validation.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum PolicyError {
    /// No authentication method was configured.
    #[error("at least one authentication method is required")]
    EmptyAuthMethods,
    /// The session duration is below the safe minimum.
    #[error("session duration is invalid")]
    InvalidSessionDuration,
    /// An OIDC scope token contains a forbidden character or is empty.
    #[error("OIDC scope is invalid")]
    InvalidOidcScope,
    /// An OIDC scope was repeated.
    #[error("OIDC scope is duplicated")]
    DuplicateOidcScope,
    /// The OIDC scope set does not include the required `openid` scope.
    #[error("OIDC scope must include openid")]
    MissingOpenidScope,
}

impl PolicyError {
    /// Returns the stable, transport-independent error code.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::EmptyAuthMethods => "empty_auth_methods",
            Self::InvalidSessionDuration => "invalid_session_duration",
            Self::InvalidOidcScope => "invalid_oidc_scope",
            Self::DuplicateOidcScope => "duplicate_oidc_scope",
            Self::MissingOpenidScope => "missing_openid_scope",
        }
    }
}

/// Controls whether and how a user may register.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RegistrationMode {
    /// New users cannot register.
    Disabled,
    /// New users require an invitation or an equivalent server-side grant.
    #[default]
    InviteOnly,
    /// New users may register without an invitation.
    Open,
}

impl RegistrationMode {
    /// Returns whether the mode permits self-service registration.
    #[must_use]
    pub const fn allows_self_service(self) -> bool {
        matches!(self, Self::Open)
    }
}

/// An authentication method supported by the identity policy.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthMethod {
    /// Local password authentication.
    Password,
    /// `OpenID` Connect authentication.
    Oidc,
    /// Time-based one-time-password second-factor authentication.
    Totp,
    /// Non-user service-account authentication.
    ServiceAccount,
}

/// Descriptive alias for [`AuthMethod`].
pub type AuthenticationMethod = AuthMethod;

/// A validated set of authentication methods.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(transparent)]
pub struct AuthMethods(BTreeSet<AuthMethod>);

impl AuthMethods {
    /// Builds a method set and rejects an empty configuration.
    ///
    /// # Errors
    ///
    /// Returns [`PolicyError::EmptyAuthMethods`] for an empty input.
    pub fn new<I>(methods: I) -> Result<Self, PolicyError>
    where
        I: IntoIterator<Item = AuthMethod>,
    {
        let methods = Self(methods.into_iter().collect());
        methods.validate()?;
        Ok(methods)
    }

    /// Validates that at least one method is enabled.
    ///
    /// # Errors
    ///
    /// Returns [`PolicyError::EmptyAuthMethods`] when no method is enabled.
    pub fn validate(&self) -> Result<(), PolicyError> {
        if self.0.is_empty() {
            Err(PolicyError::EmptyAuthMethods)
        } else {
            Ok(())
        }
    }

    /// Returns whether a method is enabled.
    #[must_use]
    pub fn contains(&self, method: AuthMethod) -> bool {
        self.0.contains(&method)
    }

    /// Returns the number of distinct enabled methods.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Returns whether no methods are enabled.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Iterates over methods in stable enum order.
    pub fn iter(&self) -> std::collections::btree_set::Iter<'_, AuthMethod> {
        self.0.iter()
    }
}

impl Default for AuthMethods {
    fn default() -> Self {
        Self(BTreeSet::from([AuthMethod::Password]))
    }
}

impl<'a> IntoIterator for &'a AuthMethods {
    type Item = &'a AuthMethod;
    type IntoIter = std::collections::btree_set::Iter<'a, AuthMethod>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.iter()
    }
}

impl<'de> Deserialize<'de> for AuthMethods {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let methods = Vec::<AuthMethod>::deserialize(deserializer)?;
        Self::new(methods).map_err(serde::de::Error::custom)
    }
}

/// A validated session lifetime in seconds.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct SessionDuration(u64);

impl SessionDuration {
    /// Smallest accepted session lifetime, matching the service boundary.
    pub const MIN_SECONDS: u64 = 300;
    /// Constructs a session duration from seconds.
    ///
    /// # Errors
    ///
    /// Returns [`PolicyError::InvalidSessionDuration`] below five minutes.
    pub const fn new(seconds: u64) -> Result<Self, PolicyError> {
        if seconds < Self::MIN_SECONDS {
            Err(PolicyError::InvalidSessionDuration)
        } else {
            Ok(Self(seconds))
        }
    }

    /// Returns the duration in seconds.
    #[must_use]
    pub const fn as_secs(self) -> u64 {
        self.0
    }

    /// Returns the value as a standard-library duration.
    #[must_use]
    pub const fn as_duration(self) -> std::time::Duration {
        std::time::Duration::from_secs(self.0)
    }

    /// Rechecks the invariant for values received from a generic source.
    ///
    /// # Errors
    ///
    /// Returns [`PolicyError::InvalidSessionDuration`] below five minutes.
    pub const fn validate(self) -> Result<(), PolicyError> {
        if self.0 < Self::MIN_SECONDS {
            Err(PolicyError::InvalidSessionDuration)
        } else {
            Ok(())
        }
    }
}

impl Default for SessionDuration {
    fn default() -> Self {
        Self(43_200)
    }
}

impl<'de> Deserialize<'de> for SessionDuration {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Self::new(u64::deserialize(deserializer)?).map_err(serde::de::Error::custom)
    }
}

/// A validated OIDC scope list. The list always contains `openid`.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(transparent)]
pub struct OidcScopes(Vec<String>);

/// Descriptive alias for [`OidcScopes`].
pub type OidcScopeSet = OidcScopes;

impl OidcScopes {
    /// Builds and validates an OIDC scope list.
    ///
    /// Scope tokens are kept in caller order, while duplicate tokens are
    /// rejected rather than silently changing authorization semantics.
    ///
    /// # Errors
    ///
    /// Returns a stable scope error for invalid, duplicate, or missing
    /// `openid` values.
    pub fn new<I, S>(scopes: I) -> Result<Self, PolicyError>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let mut values = Vec::new();
        let mut seen = BTreeSet::new();
        for scope in scopes {
            let scope = scope.as_ref();
            if !is_valid_scope_token(scope) {
                return Err(PolicyError::InvalidOidcScope);
            }
            if !seen.insert(scope.to_owned()) {
                return Err(PolicyError::DuplicateOidcScope);
            }
            values.push(scope.to_owned());
        }
        if !seen.contains("openid") {
            return Err(PolicyError::MissingOpenidScope);
        }
        Ok(Self(values))
    }

    /// Parses a space-delimited scope claim.
    ///
    /// When `require_openid` is false, an empty scope string is valid for a
    /// generic access token. OIDC authorization policies should pass `true`.
    ///
    /// # Errors
    ///
    /// Returns a stable scope error for invalid, duplicate, or missing
    /// `openid` values.
    pub fn from_space_delimited(scopes: &str, require_openid: bool) -> Result<Self, PolicyError> {
        let values = scopes.split_whitespace().collect::<Vec<_>>();
        if values.is_empty() && !require_openid {
            return Ok(Self(Vec::new()));
        }
        let mut seen = BTreeSet::new();
        let mut normalized = Vec::with_capacity(values.len());
        for scope in values {
            if !is_valid_scope_token(scope) {
                return Err(PolicyError::InvalidOidcScope);
            }
            if !seen.insert(scope) {
                return Err(PolicyError::DuplicateOidcScope);
            }
            normalized.push(scope.to_owned());
        }
        if require_openid && !seen.contains("openid") {
            return Err(PolicyError::MissingOpenidScope);
        }
        Ok(Self(normalized))
    }

    /// Returns the scopes in their configured order.
    #[must_use]
    pub fn as_slice(&self) -> &[String] {
        &self.0
    }

    /// Returns whether a scope is present.
    #[must_use]
    pub fn contains(&self, scope: &str) -> bool {
        self.0.iter().any(|value| value == scope)
    }

    /// Returns the number of scopes.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Returns whether no scopes are present.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Returns a space-delimited representation suitable for a JWT scope claim.
    #[must_use]
    pub fn to_space_delimited(&self) -> String {
        self.0.join(" ")
    }
}

impl Default for OidcScopes {
    fn default() -> Self {
        Self(vec![
            "openid".to_owned(),
            "profile".to_owned(),
            "email".to_owned(),
        ])
    }
}

impl<'de> Deserialize<'de> for OidcScopes {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Self::new(Vec::<String>::deserialize(deserializer)?).map_err(serde::de::Error::custom)
    }
}

/// Combined identity policy used by application configuration.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct IdentityPolicy {
    /// Registration behavior.
    pub registration_mode: RegistrationMode,
    /// Enabled authentication methods.
    pub auth_methods: AuthMethods,
    /// Maximum lifetime of an authenticated session.
    pub session_duration: SessionDuration,
    /// OIDC scopes requested by the authorization flow.
    pub oidc_scopes: OidcScopes,
}

impl IdentityPolicy {
    /// Builds and validates an identity policy.
    ///
    /// # Errors
    ///
    /// Returns a stable nested policy error when a method, duration, or scope
    /// invariant is violated.
    pub fn new(
        registration_mode: RegistrationMode,
        auth_methods: AuthMethods,
        session_duration: SessionDuration,
        oidc_scopes: OidcScopes,
    ) -> Result<Self, PolicyError> {
        let policy = Self {
            registration_mode,
            auth_methods,
            session_duration,
            oidc_scopes,
        };
        policy.validate()?;
        Ok(policy)
    }

    /// Validates every nested policy invariant.
    ///
    /// # Errors
    ///
    /// Returns a stable nested policy error when an invariant is violated.
    pub fn validate(&self) -> Result<(), PolicyError> {
        self.auth_methods.validate()?;
        self.session_duration.validate()?;
        OidcScopes::new(self.oidc_scopes.0.iter().map(String::as_str))?;
        Ok(())
    }
}

fn is_valid_scope_token(scope: &str) -> bool {
    !scope.is_empty()
        && scope.is_ascii()
        && scope.bytes().all(|byte| {
            byte == 0x21 || (0x23..=0x5b).contains(&byte) || (0x5d..=0x7e).contains(&byte)
        })
}

#[cfg(test)]
mod tests {
    use super::{
        AuthMethod, AuthMethods, IdentityPolicy, OidcScopes, PolicyError, SessionDuration,
    };

    #[test]
    fn policy_defaults_are_valid_and_session_floor_is_enforced() {
        assert!(IdentityPolicy::default().validate().is_ok());
        assert_eq!(
            SessionDuration::new(299),
            Err(PolicyError::InvalidSessionDuration)
        );
        assert_eq!(SessionDuration::new(300).expect("duration").as_secs(), 300);
        assert_eq!(SessionDuration::default().as_secs(), 43_200);
    }

    #[test]
    fn authentication_methods_and_oidc_scopes_are_validated() {
        assert_eq!(
            AuthMethods::new(Vec::new()),
            Err(PolicyError::EmptyAuthMethods)
        );
        let methods = AuthMethods::new([AuthMethod::Password, AuthMethod::Oidc]).expect("methods");
        assert!(methods.contains(AuthMethod::Oidc));
        assert_eq!(
            OidcScopes::new(["profile", "email"]),
            Err(PolicyError::MissingOpenidScope)
        );
        assert_eq!(
            OidcScopes::new(["openid", "email", "email"]),
            Err(PolicyError::DuplicateOidcScope)
        );
        assert!(OidcScopes::new(["openid", "profile", "email"]).is_ok());
        assert_eq!(
            OidcScopes::from_space_delimited("openid email", true)
                .expect("scopes")
                .to_space_delimited(),
            "openid email"
        );
    }
}
