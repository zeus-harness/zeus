use crate::WorkspaceRole;
use uuid::Uuid;

/// Applies only after tenant membership has been authenticated. A title or
/// organization role alone cannot authorize Workspace resources.
#[must_use]
pub fn can_decide_approval(
    kind: &str,
    actor: Option<Uuid>,
    requester: Option<Uuid>,
    role: Option<WorkspaceRole>,
    support_access: bool,
) -> bool {
    let Some(actor) = actor else {
        return false;
    };
    if support_access {
        return false;
    }
    match kind {
        "execution" => {
            requester == Some(actor)
                && matches!(
                    role,
                    Some(WorkspaceRole::Owner | WorkspaceRole::Builder | WorkspaceRole::Operator)
                )
        }
        "resource_access" => matches!(role, Some(WorkspaceRole::Owner)),
        "legacy_tool" => matches!(role, Some(WorkspaceRole::Owner | WorkspaceRole::Operator)),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn decisions_require_the_correct_human_authority() {
        let initiator = Uuid::now_v7();
        let other = Uuid::now_v7();
        assert!(can_decide_approval(
            "execution",
            Some(initiator),
            Some(initiator),
            Some(WorkspaceRole::Builder),
            false
        ));
        assert!(!can_decide_approval(
            "execution",
            Some(other),
            Some(initiator),
            Some(WorkspaceRole::Owner),
            false
        ));
        assert!(!can_decide_approval(
            "resource_access",
            Some(initiator),
            Some(initiator),
            Some(WorkspaceRole::Operator),
            false
        ));
        assert!(can_decide_approval(
            "resource_access",
            Some(other),
            Some(initiator),
            Some(WorkspaceRole::Owner),
            false
        ));
        assert!(!can_decide_approval(
            "resource_access",
            None,
            None,
            Some(WorkspaceRole::Owner),
            false
        ));
        assert!(!can_decide_approval(
            "resource_access",
            Some(other),
            Some(initiator),
            Some(WorkspaceRole::Owner),
            true
        ));
        assert!(!can_decide_approval(
            "execution",
            Some(other),
            None,
            Some(WorkspaceRole::Owner),
            false
        ));
    }
}
