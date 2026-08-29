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
            Self::Owner => true,
            Self::Admin => !matches!(permission, Permission::ManageOrganization),
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
