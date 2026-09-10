use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OrganizationRole {
    Owner,
    Member,
    Auditor,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkspaceRole {
    Owner,
    Builder,
    Operator,
    Viewer,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Permission {
    ManageOrganization,
    ManageWorkspace,
    BuildWorkflow,
    OperateRun,
    ApproveTool,
    PublishWorkspaceExperience,
    PublishOrganizationExperience,
    ReadAudit,
    ReadWorkspace,
}

impl OrganizationRole {
    #[must_use]
    pub const fn allows(self, permission: Permission) -> bool {
        match self {
            Self::Owner => true,
            Self::Member => matches!(permission, Permission::ReadWorkspace),
            Self::Auditor => matches!(
                permission,
                Permission::ReadAudit | Permission::ReadWorkspace
            ),
        }
    }
}

impl WorkspaceRole {
    #[must_use]
    pub const fn allows(self, permission: Permission) -> bool {
        match self {
            Self::Owner => matches!(
                permission,
                Permission::ManageWorkspace
                    | Permission::BuildWorkflow
                    | Permission::OperateRun
                    | Permission::ApproveTool
                    | Permission::PublishWorkspaceExperience
                    | Permission::ReadAudit
                    | Permission::ReadWorkspace
            ),
            Self::Builder => matches!(
                permission,
                Permission::BuildWorkflow
                    | Permission::OperateRun
                    | Permission::PublishWorkspaceExperience
                    | Permission::ReadWorkspace
            ),
            Self::Operator => matches!(
                permission,
                Permission::OperateRun | Permission::ApproveTool | Permission::ReadWorkspace
            ),
            Self::Viewer => matches!(permission, Permission::ReadWorkspace),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{OrganizationRole, Permission, WorkspaceRole};

    #[test]
    fn organization_owner_can_manage_identity_and_membership_configuration() {
        assert!(OrganizationRole::Owner.allows(Permission::ManageOrganization));
        assert!(!OrganizationRole::Member.allows(Permission::ManageOrganization));
        assert!(!OrganizationRole::Auditor.allows(Permission::ManageOrganization));
    }

    #[test]
    fn workspace_owner_and_builder_keep_distinct_boundaries() {
        assert!(WorkspaceRole::Owner.allows(Permission::ManageWorkspace));
        assert!(WorkspaceRole::Owner.allows(Permission::ApproveTool));
        assert!(!WorkspaceRole::Builder.allows(Permission::ManageWorkspace));
        assert!(!WorkspaceRole::Builder.allows(Permission::ApproveTool));
        assert!(WorkspaceRole::Builder.allows(Permission::BuildWorkflow));
        assert!(WorkspaceRole::Builder.allows(Permission::OperateRun));
    }
}
