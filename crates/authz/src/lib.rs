//! Exact-match, default-deny authorization for tool dispatch.
//!
//! Policy construction rejects ambiguous rule sets. Dispatch authorization is
//! intentionally a second evaluation: an approval is narrowly bound to the
//! current rule revision and call contract and can never override a deny.

use protocol::{
    Approval, ApprovalScope, ApprovalStatus, PolicyDecision, SandboxProfile, ToolCall, ToolEffect,
};
use serde::{Deserialize, Serialize};
use tenancy::MembershipRole;
use thiserror::Error;

pub const DEFAULT_DENY_REVISION: &str = "zeus-default-deny-v1";

/// Account-level capabilities are deliberately separate from tool policy.
/// Storage re-reads the durable membership before evaluating this matrix.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum AccountCapability {
    Read,
    SessionWrite,
    Reply,
    ApproveDispatch,
    AccountAdmin,
    AuditRead,
}

pub const fn membership_allows(role: MembershipRole, capability: AccountCapability) -> bool {
    match role {
        MembershipRole::Owner => true,
        MembershipRole::Member => matches!(
            capability,
            AccountCapability::Read | AccountCapability::SessionWrite | AccountCapability::Reply
        ),
    }
}

/// One exact-match policy rule. Wildcards are intentionally unsupported.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyRule {
    pub revision: String,
    pub tool: String,
    pub environment: String,
    pub effect: ToolEffect,
    pub sandbox_profile: SandboxProfile,
    pub decision: PolicyDecision,
}

/// The immutable attributes re-evaluated immediately before dispatch.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PolicyContext {
    pub tool: String,
    pub environment: String,
    pub effect: ToolEffect,
    pub sandbox_profile: SandboxProfile,
}

impl PolicyContext {
    pub fn for_call(environment: impl Into<String>, call: &ToolCall) -> Self {
        Self {
            tool: call.tool.clone(),
            environment: environment.into(),
            effect: call.effect.clone(),
            sandbox_profile: call.sandbox_profile.clone(),
        }
    }
}

/// Auditable result of a policy or dispatch-guard evaluation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PolicyEvaluation {
    pub decision: PolicyDecision,
    pub policy_revision: String,
    pub reason: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Error)]
pub enum PolicyBuildError {
    #[error("invalid rule at index {index}: {reason}")]
    InvalidRule { index: usize, reason: String },
    #[error("duplicate exact-match rules at indices {first} and {second}")]
    DuplicateRule { first: usize, second: usize },
    #[error("conflicting exact-match rules at indices {first} and {second}")]
    ConflictingRule { first: usize, second: usize },
}

/// An immutable policy engine. Empty and unmatched policies deny by default.
#[derive(Clone, Debug)]
pub struct PolicyEngine {
    rules: Vec<PolicyRule>,
}

impl PolicyEngine {
    pub fn new(rules: Vec<PolicyRule>) -> Result<Self, PolicyBuildError> {
        for (index, rule) in rules.iter().enumerate() {
            validate_rule(index, rule)?;
        }
        for first in 0..rules.len() {
            for second in (first + 1)..rules.len() {
                if same_match(&rules[first], &rules[second]) {
                    if rules[first] == rules[second] {
                        return Err(PolicyBuildError::DuplicateRule { first, second });
                    }
                    return Err(PolicyBuildError::ConflictingRule { first, second });
                }
            }
        }
        Ok(Self { rules })
    }

    pub fn rules(&self) -> &[PolicyRule] {
        &self.rules
    }

    /// Evaluates an exact context. Missing rules are an explicit default deny.
    pub fn evaluate(&self, context: &PolicyContext) -> PolicyEvaluation {
        let Some(rule) = self.rules.iter().find(|rule| rule_matches(rule, context)) else {
            return PolicyEvaluation {
                decision: PolicyDecision::Deny,
                policy_revision: DEFAULT_DENY_REVISION.into(),
                reason: "no exact policy rule matched".into(),
            };
        };

        PolicyEvaluation {
            decision: rule.decision.clone(),
            policy_revision: rule.revision.clone(),
            reason: match rule.decision {
                PolicyDecision::Allow => "exact rule allowed the call",
                PolicyDecision::RequireApproval => "exact rule requires a bound approval",
                PolicyDecision::Deny => "exact rule denied the call",
            }
            .into(),
        }
    }

    /// Re-evaluates environment/effect/sandbox and, only for an approval rule,
    /// checks the full one-shot approval binding. Explicit and default denies
    /// return before approval is inspected.
    pub fn guard_dispatch(
        &self,
        environment: &str,
        call: &ToolCall,
        approval: Option<&Approval>,
    ) -> PolicyEvaluation {
        let context = PolicyContext::for_call(environment, call);
        let base = self.evaluate(&context);
        match base.decision {
            PolicyDecision::Deny | PolicyDecision::Allow => base,
            PolicyDecision::RequireApproval => {
                let Some(approval) = approval else {
                    return base;
                };
                if approval.status == ApprovalStatus::Rejected {
                    return PolicyEvaluation {
                        decision: PolicyDecision::Deny,
                        policy_revision: base.policy_revision,
                        reason: "the bound approval was rejected".into(),
                    };
                }
                if approval.status != ApprovalStatus::Approved {
                    return base;
                }
                if approval_matches(approval, call, &base.policy_revision) {
                    PolicyEvaluation {
                        decision: PolicyDecision::Allow,
                        policy_revision: base.policy_revision,
                        reason: "the exact rule and one-shot approval both matched".into(),
                    }
                } else {
                    PolicyEvaluation {
                        decision: PolicyDecision::RequireApproval,
                        policy_revision: base.policy_revision,
                        reason: "the approval binding does not match the current call or policy"
                            .into(),
                    }
                }
            }
        }
    }
}

fn validate_rule(index: usize, rule: &PolicyRule) -> Result<(), PolicyBuildError> {
    validate_ascii_token(&rule.revision, 96, false).map_err(|reason| {
        PolicyBuildError::InvalidRule {
            index,
            reason: format!("invalid revision: {reason}"),
        }
    })?;
    validate_ascii_token(&rule.environment, 64, true).map_err(|reason| {
        PolicyBuildError::InvalidRule {
            index,
            reason: format!("invalid environment: {reason}"),
        }
    })?;
    if rule.tool.is_empty()
        || rule.tool.len() > 96
        || rule.tool.starts_with('.')
        || rule.tool.ends_with('.')
        || rule.tool.contains("..")
        || !rule.tool.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || b"._-".contains(&byte)
        })
    {
        return Err(PolicyBuildError::InvalidRule {
            index,
            reason: "invalid exact tool name".into(),
        });
    }
    Ok(())
}

fn validate_ascii_token(value: &str, max_bytes: usize, lowercase: bool) -> Result<(), String> {
    if value.is_empty() || value.len() > max_bytes || value.contains('*') {
        return Err("must be non-empty, bounded, and contain no wildcard".into());
    }
    let valid = value.bytes().all(|byte| {
        (if lowercase {
            byte.is_ascii_lowercase()
        } else {
            byte.is_ascii_alphanumeric()
        }) || byte.is_ascii_digit()
            || b"._:-/".contains(&byte)
    });
    if !valid {
        return Err("contains unsupported characters".into());
    }
    Ok(())
}

fn same_match(left: &PolicyRule, right: &PolicyRule) -> bool {
    left.tool == right.tool
        && left.environment == right.environment
        && left.effect == right.effect
        && left.sandbox_profile == right.sandbox_profile
}

fn rule_matches(rule: &PolicyRule, context: &PolicyContext) -> bool {
    rule.tool == context.tool
        && rule.environment == context.environment
        && rule.effect == context.effect
        && rule.sandbox_profile == context.sandbox_profile
}

fn approval_matches(approval: &Approval, call: &ToolCall, policy_revision: &str) -> bool {
    approval.requires_approval
        && approval.tool == call.tool
        && approval.call_id.as_deref() == Some(call.call_id.as_str())
        && approval.policy_revision.as_deref() == Some(policy_revision)
        && approval.arguments_digest.as_deref() == Some(call.arguments_digest.as_str())
        && approval.sandbox_profile.as_ref() == Some(&call.sandbox_profile)
        && approval.scope == Some(ApprovalScope::AllowOnce)
}

#[cfg(test)]
mod tests {
    use super::*;
    use protocol::ToolExecutorStatus;
    use serde_json::json;

    fn rule(decision: PolicyDecision) -> PolicyRule {
        PolicyRule {
            revision: "policy-7".into(),
            tool: "dev.marker.write".into(),
            environment: "local-development".into(),
            effect: ToolEffect::LocalWrite,
            sandbox_profile: SandboxProfile::WorkspaceWrite,
            decision,
        }
    }

    fn call() -> ToolCall {
        ToolCall {
            call_id: "ZR-1842.t2.s3.dev.marker.write".into(),
            tool: "dev.marker.write".into(),
            tool_version: "1".into(),
            arguments: json!({"marker": "verified"}),
            arguments_digest: "sha256:bound".into(),
            effect: ToolEffect::LocalWrite,
            sandbox_profile: SandboxProfile::WorkspaceWrite,
            executor_status: ToolExecutorStatus::Available,
        }
    }

    fn approval(status: ApprovalStatus) -> Approval {
        Approval {
            id: "approval-1".into(),
            status,
            action: "write marker".into(),
            tool: "dev.marker.write".into(),
            change: "create a local marker".into(),
            requires_approval: true,
            call_id: Some("ZR-1842.t2.s3.dev.marker.write".into()),
            policy_revision: Some("policy-7".into()),
            arguments_digest: Some("sha256:bound".into()),
            sandbox_profile: Some(SandboxProfile::WorkspaceWrite),
            scope: Some(ApprovalScope::AllowOnce),
        }
    }

    #[test]
    fn empty_and_unmatched_policies_deny_by_default() {
        let engine = PolicyEngine::new(Vec::new()).unwrap();
        let evaluation = engine.evaluate(&PolicyContext::for_call("local-development", &call()));
        assert_eq!(evaluation.decision, PolicyDecision::Deny);
        assert_eq!(evaluation.policy_revision, DEFAULT_DENY_REVISION);
    }

    #[test]
    fn account_capabilities_are_default_deny_for_member_authority() {
        assert!(membership_allows(
            MembershipRole::Member,
            AccountCapability::Read
        ));
        assert!(membership_allows(
            MembershipRole::Member,
            AccountCapability::SessionWrite
        ));
        assert!(membership_allows(
            MembershipRole::Member,
            AccountCapability::Reply
        ));
        assert!(!membership_allows(
            MembershipRole::Member,
            AccountCapability::ApproveDispatch
        ));
        assert!(!membership_allows(
            MembershipRole::Member,
            AccountCapability::AccountAdmin
        ));
        assert!(!membership_allows(
            MembershipRole::Member,
            AccountCapability::AuditRead
        ));
        for capability in [
            AccountCapability::Read,
            AccountCapability::SessionWrite,
            AccountCapability::Reply,
            AccountCapability::ApproveDispatch,
            AccountCapability::AccountAdmin,
            AccountCapability::AuditRead,
        ] {
            assert!(membership_allows(MembershipRole::Owner, capability));
        }
    }

    #[test]
    fn slash_separated_policy_revisions_are_valid() {
        let mut versioned = rule(PolicyDecision::RequireApproval);
        versioned.revision = "local-development/v1".into();

        assert!(PolicyEngine::new(vec![versioned]).is_ok());
    }

    #[test]
    fn duplicate_and_conflicting_rules_fail_at_startup() {
        let duplicate = PolicyEngine::new(vec![
            rule(PolicyDecision::Allow),
            rule(PolicyDecision::Allow),
        ]);
        assert!(matches!(
            duplicate,
            Err(PolicyBuildError::DuplicateRule { .. })
        ));

        let conflict = PolicyEngine::new(vec![
            rule(PolicyDecision::Allow),
            rule(PolicyDecision::Deny),
        ]);
        assert!(matches!(
            conflict,
            Err(PolicyBuildError::ConflictingRule { .. })
        ));
    }

    #[test]
    fn an_approval_never_overrides_an_explicit_deny() {
        let engine = PolicyEngine::new(vec![rule(PolicyDecision::Deny)]).unwrap();
        let evaluation = engine.guard_dispatch(
            "local-development",
            &call(),
            Some(&approval(ApprovalStatus::Approved)),
        );
        assert_eq!(evaluation.decision, PolicyDecision::Deny);
        assert_eq!(evaluation.reason, "exact rule denied the call");
    }

    #[test]
    fn approved_call_must_match_every_binding() {
        let engine = PolicyEngine::new(vec![rule(PolicyDecision::RequireApproval)]).unwrap();
        let evaluation = engine.guard_dispatch(
            "local-development",
            &call(),
            Some(&approval(ApprovalStatus::Approved)),
        );
        assert_eq!(evaluation.decision, PolicyDecision::Allow);

        let mut stale = approval(ApprovalStatus::Approved);
        stale.policy_revision = Some("policy-6".into());
        let evaluation = engine.guard_dispatch("local-development", &call(), Some(&stale));
        assert_eq!(evaluation.decision, PolicyDecision::RequireApproval);
    }

    #[test]
    fn environment_and_effect_are_rechecked_before_dispatch() {
        let engine = PolicyEngine::new(vec![rule(PolicyDecision::RequireApproval)]).unwrap();
        let grant = approval(ApprovalStatus::Approved);

        assert_eq!(
            engine
                .guard_dispatch("production", &call(), Some(&grant))
                .decision,
            PolicyDecision::Deny
        );

        let mut changed_effect = call();
        changed_effect.effect = ToolEffect::ProductionWrite;
        assert_eq!(
            engine
                .guard_dispatch("local-development", &changed_effect, Some(&grant))
                .decision,
            PolicyDecision::Deny
        );
    }
}
