use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OrganizationRole {
    Owner,
    Admin,
    Member,
    Auditor,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkspaceRole {
    Admin,
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
            Self::Owner | Self::Admin => true,
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
            Self::Admin => matches!(
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
    use super::{OrganizationRole, Permission};

    #[test]
    fn organization_admins_can_manage_identity_and_membership_configuration() {
        assert!(OrganizationRole::Admin.allows(Permission::ManageOrganization));
        assert!(!OrganizationRole::Member.allows(Permission::ManageOrganization));
        assert!(!OrganizationRole::Auditor.allows(Permission::ManageOrganization));
    }
}
