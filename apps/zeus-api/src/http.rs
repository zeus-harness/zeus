use std::sync::Arc;

use axum::{
    Json, Router,
    extract::{DefaultBodyLimit, Request, State},
    middleware::{self, Next},
    response::Response as AxumResponse,
    routing::get,
};
use http::{HeaderMap, HeaderName, HeaderValue};
use serde::Serialize;
use tower_http::{
    catch_panic::CatchPanicLayer,
    compression::CompressionLayer,
    trace::{DefaultOnResponse, TraceLayer},
};
use tracing::Level;
use utoipa::{
    Modify, OpenApi, ToSchema,
    openapi::{
        Array, Components, Content, ObjectBuilder, Ref, RefOr, Required, Response, Responses,
        Schema, SecurityRequirement,
        path::{HttpMethod, Operation, Parameter, ParameterBuilder, ParameterIn, PathItem},
        request_body::RequestBodyBuilder,
        schema::Type,
        security::{ApiKey, ApiKeyValue, HttpAuthScheme, HttpBuilder, SecurityScheme},
    },
};
use uuid::Uuid;

use crate::{
    AppState, agents, auth,
    error::{ApiError, ProblemDetails, REQUEST_ID},
    execution_api, experiences, federated_identity, integrations, native_auth, native_identity,
    organization, organization_identity,
    supervisor::SupervisorMetrics,
    work_items,
};

#[derive(OpenApi)]
#[openapi(
    info(
        title = "Zeus API",
        version = "0.1.0",
        description = "Enterprise Harness Agent control plane and durable execution API."
    ),
    paths(
        live,
        ready,
        meta,
        native_identity::setup_status,
        native_identity::setup,
        native_auth::register,
        native_auth::native_login,
        native_auth::native_logout,
        native_auth::request_email_verification,
        native_auth::confirm_email_verification,
        native_auth::request_password_reset,
        native_auth::confirm_password_reset,
        native_auth::verify_mfa,
        native_auth::select_identity_context,
        native_auth::list_web_sessions,
        native_auth::revoke_web_session,
        native_auth::change_password,
        native_auth::configure_totp,
        native_auth::disable_totp,
        native_auth::list_user_organizations,
        native_auth::accept_invitation,
        native_auth::list_federated_identities,
        native_auth::unlink_federated_identity,
        organization_identity::list_invitations,
        organization_identity::create_invitation,
        organization_identity::resend_invitation,
        organization_identity::revoke_invitation,
        auth::current_user,
        auth::create_federated_link_intent,
        federated_identity::list_domains,
        federated_identity::create_domain,
        federated_identity::verify_domain,
        federated_identity::revoke_domain,
        federated_identity::get_identity_policy,
        federated_identity::update_identity_policy,
        auth::create_service_account,
        auth::list_service_accounts,
        auth::revoke_service_account,
        organization::create_organization,
        organization::get_organization,
        organization::update_organization,
        organization::list_workspaces,
        organization::create_workspace,
        organization::get_workspace,
        organization::update_workspace,
        organization::select_workspace,
        execution_api::create_run
    ),
    modifiers(&OpenApiModifier),
    components(schemas(
        HealthResponse,
        MetaResponse,
        FeatureStatus,
        ProblemDetails,
        native_identity::SetupStatusResponse,
        native_identity::SetupRequest,
        native_identity::SetupResponse,
        native_auth::AcceptedIdentityResponse,
        native_auth::RegisterRequest,
        native_auth::NativeLoginRequest,
        native_auth::NativeLoginResponse,
        native_auth::EmailAddressRequest,
        native_auth::TokenConfirmationRequest,
        native_auth::PasswordResetConfirmationRequest,
        native_auth::MfaVerificationRequest,
        native_auth::MfaVerificationResponse,
        native_auth::WebSessionResponse,
        native_auth::ChangePasswordRequest,
        native_auth::TotpSetupRequest,
        native_auth::TotpSetupResponse,
        native_auth::DisableTotpRequest,
        native_auth::SelectIdentityContextRequest,
        native_auth::UserOrganizationResponse,
        native_auth::FederatedIdentityResponse,
        organization_identity::InvitationWorkspaceRequest,
        organization_identity::CreateInvitationRequest,
        organization_identity::InvitationResponse,
        auth::CurrentUserResponse,
        auth::FederatedLinkIntentResponse,
        auth::CreateServiceAccountRequest,
        auth::CreatedServiceAccountResponse,
        auth::ServiceAccountResponse,
        federated_identity::OrganizationDomainResponse,
        federated_identity::CreateOrganizationDomainRequest,
        federated_identity::CreatedOrganizationDomainResponse,
        federated_identity::OrganizationIdentityPolicyResponse,
        federated_identity::UpdateOrganizationIdentityPolicyRequest,
        organization::OrganizationResponse,
        organization::CreateOrganizationRequest,
        organization::UpdateOrganizationRequest,
        organization::CreatedOrganizationResponse,
        organization::WorkspaceResponse,
        organization::WorkspacePageResponse,
        organization::CreateWorkspaceRequest,
        organization::UpdateWorkspaceRequest,
        organization::OrganizationMemberResponse,
        organization::SetOrganizationMemberRequest,
        organization::WorkspaceMemberResponse,
        organization::SetWorkspaceMemberRequest,
        organization::FederatedIdentityProviderResponse,
        organization::CreateFederatedIdentityProviderRequest,
        organization::UpdateFederatedIdentityProviderRequest,
        organization::FederatedGroupMappingResponse,
        organization::CreateFederatedGroupMappingRequest,
        agents::AgentResponse,
        agents::AgentPageResponse,
        agents::CreateAgentRequest,
        agents::UpdateAgentRequest,
        agents::AgentVersionResponse,
        agents::CreateAgentVersionRequest,
        agents::ActivateVersionRequest,
        agents::WorkflowResponse,
        agents::WorkflowPageResponse,
        agents::CreateWorkflowRequest,
        agents::UpdateWorkflowRequest,
        agents::WorkflowVersionResponse,
        agents::CreateWorkflowVersionRequest,
        integrations::ConnectionResponse,
        integrations::ConnectionPageResponse,
        integrations::CreateConnectionRequest,
        integrations::UpdateConnectionRequest,
        integrations::ConnectionSecretResponse,
        integrations::ConnectionSecretPageResponse,
        integrations::CreateConnectionSecretRequest,
        integrations::ConnectionSecretValueRequest,
        integrations::ModelProfileResponse,
        integrations::ModelProfilePageResponse,
        integrations::CreateModelProfileRequest,
        integrations::UpdateModelProfileRequest,
        integrations::CapabilityDefinitionResponse,
        integrations::CapabilityDefinitionPageResponse,
        integrations::CreateCapabilityDefinitionRequest,
        integrations::UpdateCapabilityDefinitionRequest,
        integrations::WorkspaceCapabilityResponse,
        integrations::WorkspaceCapabilityPageResponse,
        integrations::CreateWorkspaceCapabilityRequest,
        integrations::UpdateWorkspaceCapabilityRequest,
        integrations::ScheduleResponse,
        integrations::SchedulePageResponse,
        integrations::CreateScheduleRequest,
        integrations::UpdateScheduleRequest,
        integrations::WebhookEndpointResponse,
        integrations::WebhookEndpointPageResponse,
        integrations::CreatedWebhookEndpointResponse,
        integrations::CreateWebhookEndpointRequest,
        integrations::UpdateWebhookEndpointRequest,
        execution_api::SessionResponse,
        execution_api::SessionPageResponse,
        execution_api::CreateSessionRequest,
        execution_api::SubmitMessageRequest,
        execution_api::AppendedEventResponse,
        execution_api::SessionEventResponse,
        execution_api::CreateRunRequest,
        execution_api::RunResponse,
        execution_api::RunPageResponse,
        execution_api::CancelRunRequest,
        execution_api::RetryRunRequest,
        execution_api::RunEventResponse,
        execution_api::RunUsageResponse,
        execution_api::RunUsageSummaryResponse,
        execution_api::ApprovalResponse,
        execution_api::DecideApprovalRequest,
        execution_api::TraceToolCallResponse,
        execution_api::TraceRunLinkResponse,
        execution_api::TraceExperienceInjectionResponse,
        execution_api::ChildRunResponse,
        execution_api::RunTraceResponse,
        work_items::WorkItemResponse,
        work_items::WorkItemPageResponse,
        work_items::CreateWorkItemRequest,
        work_items::UpdateWorkItemRequest,
        work_items::ExternalReferenceResponse,
        work_items::CreateExternalReferenceRequest,
        work_items::AttachmentResponse,
        work_items::CreateAttachmentRequest,
        experiences::ExperienceEvidenceRef,
        experiences::ExperienceCandidateResponse,
        experiences::ExperienceCandidatePageResponse,
        experiences::CreateExperienceCandidateRequest,
        experiences::ReviewExperienceCandidateRequest,
        experiences::ExperienceEntryResponse,
        experiences::ExperienceEntryPageResponse,
        experiences::WithdrawExperienceRequest,
        experiences::ExperienceSearchResult
    )),
    tags(
        (name = "operations", description = "Process health and diagnostics"),
        (name = "platform", description = "API capabilities and version"),
        (name = "identity", description = "OIDC identity and service accounts"),
        (name = "organization", description = "Organizations, workspaces, members, and roles"),
        (name = "agents", description = "Agents and immutable agent versions"),
        (name = "workflows", description = "Versioned agent workflows, schedules, and webhooks"),
        (name = "models-and-tools", description = "Model profiles, connections, and capabilities"),
        (name = "collaboration", description = "Work items and sessions"),
        (name = "execution", description = "Runs, events, traces, and usage"),
        (name = "approvals", description = "Pending and resolved approvals"),
        (name = "experience", description = "Reviewed team experience"),
        (name = "audit", description = "Tenant audit events")
    )
)]
pub struct ApiDoc;

#[derive(Debug, Serialize, ToSchema)]
pub struct HealthResponse {
    pub status: &'static str,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct FeatureStatus {
    pub name: &'static str,
    pub status: &'static str,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct MetaResponse {
    pub product: &'static str,
    pub version: &'static str,
    pub api_version: &'static str,
    pub queue_backend: &'static str,
    pub worker_process: bool,
    pub features: Vec<FeatureStatus>,
}

pub const SESSION_COOKIE_SECURITY_SCHEME: &str = "sessionCookie";
pub const SERVICE_ACCOUNT_BEARER_SECURITY_SCHEME: &str = "serviceAccountBearer";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BodySchema {
    None,
    Object(&'static str),
    Array(&'static str),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PublicRoute {
    pub path: &'static str,
    pub method: &'static str,
    pub operation_id: &'static str,
    pub tag: &'static str,
    pub success_status: u16,
    pub request_schema: Option<&'static str>,
    pub response_schema: BodySchema,
    pub requires_auth: bool,
}

#[allow(clippy::too_many_arguments)] // The constructor keeps the static route table compact.
const fn public_route(
    path: &'static str,
    method: &'static str,
    operation_id: &'static str,
    tag: &'static str,
    success_status: u16,
    request_schema: Option<&'static str>,
    response_schema: BodySchema,
    requires_auth: bool,
) -> PublicRoute {
    PublicRoute {
        path,
        method,
        operation_id,
        tag,
        success_status,
        request_schema,
        response_schema,
        requires_auth,
    }
}

pub const PUBLIC_ROUTES: &[PublicRoute] = &[
    public_route(
        "/health/live",
        "GET",
        "live",
        "operations",
        200,
        None,
        BodySchema::Object("HealthResponse"),
        false,
    ),
    public_route(
        "/health/ready",
        "GET",
        "ready",
        "operations",
        200,
        None,
        BodySchema::Object("HealthResponse"),
        false,
    ),
    public_route(
        "/metrics",
        "GET",
        "metrics",
        "operations",
        200,
        None,
        BodySchema::None,
        false,
    ),
    public_route(
        "/api/v1/meta",
        "GET",
        "meta",
        "platform",
        200,
        None,
        BodySchema::Object("MetaResponse"),
        false,
    ),
    public_route(
        "/api/v1/openapi.json",
        "GET",
        "openapi",
        "platform",
        200,
        None,
        BodySchema::None,
        false,
    ),
    public_route(
        "/api/v1/setup/status",
        "GET",
        "setup_status",
        "identity",
        200,
        None,
        BodySchema::Object("SetupStatusResponse"),
        false,
    ),
    public_route(
        "/api/v1/setup",
        "POST",
        "setup",
        "identity",
        201,
        Some("SetupRequest"),
        BodySchema::Object("SetupResponse"),
        false,
    ),
    public_route(
        "/api/v1/auth/register",
        "POST",
        "register",
        "identity",
        202,
        Some("RegisterRequest"),
        BodySchema::Object("AcceptedIdentityResponse"),
        false,
    ),
    public_route(
        "/api/v1/auth/login",
        "POST",
        "native_login",
        "identity",
        200,
        Some("NativeLoginRequest"),
        BodySchema::Object("NativeLoginResponse"),
        false,
    ),
    public_route(
        "/api/v1/auth/logout",
        "POST",
        "native_logout",
        "identity",
        204,
        None,
        BodySchema::None,
        true,
    ),
    public_route(
        "/api/v1/auth/email-verifications",
        "POST",
        "request_email_verification",
        "identity",
        202,
        Some("EmailAddressRequest"),
        BodySchema::Object("AcceptedIdentityResponse"),
        false,
    ),
    public_route(
        "/api/v1/auth/email-verifications/confirm",
        "POST",
        "confirm_email_verification",
        "identity",
        204,
        Some("TokenConfirmationRequest"),
        BodySchema::None,
        false,
    ),
    public_route(
        "/api/v1/auth/password-resets",
        "POST",
        "request_password_reset",
        "identity",
        202,
        Some("EmailAddressRequest"),
        BodySchema::Object("AcceptedIdentityResponse"),
        false,
    ),
    public_route(
        "/api/v1/auth/password-resets/confirm",
        "POST",
        "confirm_password_reset",
        "identity",
        204,
        Some("PasswordResetConfirmationRequest"),
        BodySchema::None,
        false,
    ),
    public_route(
        "/api/v1/auth/mfa/verify",
        "POST",
        "verify_mfa",
        "identity",
        200,
        Some("MfaVerificationRequest"),
        BodySchema::Object("MfaVerificationResponse"),
        true,
    ),
    public_route(
        "/api/v1/auth/context",
        "POST",
        "select_identity_context",
        "identity",
        204,
        Some("SelectIdentityContextRequest"),
        BodySchema::None,
        true,
    ),
    public_route(
        "/api/v1/auth/sessions",
        "GET",
        "list_web_sessions",
        "identity",
        200,
        None,
        BodySchema::Array("WebSessionResponse"),
        true,
    ),
    public_route(
        "/api/v1/auth/sessions/{session_id}",
        "DELETE",
        "revoke_web_session",
        "identity",
        204,
        None,
        BodySchema::None,
        true,
    ),
    public_route(
        "/api/v1/users/me/password",
        "PUT",
        "change_password",
        "identity",
        204,
        Some("ChangePasswordRequest"),
        BodySchema::None,
        true,
    ),
    public_route(
        "/api/v1/users/me/totp",
        "POST",
        "configure_totp",
        "identity",
        200,
        Some("TotpSetupRequest"),
        BodySchema::Object("TotpSetupResponse"),
        true,
    ),
    public_route(
        "/api/v1/organizations/{organization_id}/invitations",
        "GET",
        "list_invitations",
        "identity",
        200,
        None,
        BodySchema::Array("InvitationResponse"),
        true,
    ),
    public_route(
        "/api/v1/organizations/{organization_id}/invitations",
        "POST",
        "create_invitation",
        "identity",
        201,
        Some("CreateInvitationRequest"),
        BodySchema::Object("InvitationResponse"),
        true,
    ),
    public_route(
        "/api/v1/organizations/{organization_id}/invitations/{invitation_id}/resend",
        "POST",
        "resend_invitation",
        "identity",
        202,
        None,
        BodySchema::Object("AcceptedIdentityResponse"),
        true,
    ),
    public_route(
        "/api/v1/organizations/{organization_id}/invitations/{invitation_id}",
        "DELETE",
        "revoke_invitation",
        "identity",
        204,
        None,
        BodySchema::None,
        true,
    ),
    public_route(
        "/api/v1/users/me/totp",
        "DELETE",
        "disable_totp",
        "identity",
        204,
        Some("DisableTotpRequest"),
        BodySchema::None,
        true,
    ),
    public_route(
        "/api/v1/users/me/organizations",
        "GET",
        "list_user_organizations",
        "identity",
        200,
        None,
        BodySchema::Array("UserOrganizationResponse"),
        true,
    ),
    public_route(
        "/api/v1/invitations/{token}/accept",
        "POST",
        "accept_invitation",
        "identity",
        204,
        None,
        BodySchema::None,
        true,
    ),
    public_route(
        "/api/v1/users/me/federated-identities",
        "GET",
        "list_federated_identities",
        "identity",
        200,
        None,
        BodySchema::Array("FederatedIdentityResponse"),
        true,
    ),
    public_route(
        "/api/v1/users/me/federated-identities/{identity_id}",
        "DELETE",
        "unlink_federated_identity",
        "identity",
        204,
        None,
        BodySchema::None,
        true,
    ),
    public_route(
        "/api/v1/users/me/federated-identities/{provider_id}/link-intents",
        "POST",
        "create_federated_link_intent",
        "identity",
        200,
        None,
        BodySchema::Object("FederatedLinkIntentResponse"),
        true,
    ),
    public_route(
        "/auth/federated/{organization_slug}/{provider_slug}",
        "GET",
        "federated_login",
        "identity",
        303,
        None,
        BodySchema::None,
        false,
    ),
    public_route(
        "/auth/federated/{organization_slug}/{provider_slug}/callback",
        "GET",
        "federated_callback",
        "identity",
        303,
        None,
        BodySchema::None,
        false,
    ),
    public_route(
        "/auth/logout",
        "POST",
        "logout",
        "identity",
        303,
        None,
        BodySchema::None,
        false,
    ),
    public_route(
        "/api/v1/auth/me",
        "GET",
        "current_user",
        "identity",
        200,
        None,
        BodySchema::Object("CurrentUserResponse"),
        true,
    ),
    public_route(
        "/api/v1/organizations/{organization_id}/service-accounts",
        "GET",
        "list_service_accounts",
        "identity",
        200,
        None,
        BodySchema::Array("ServiceAccountResponse"),
        true,
    ),
    public_route(
        "/api/v1/organizations/{organization_id}/service-accounts",
        "POST",
        "create_service_account",
        "identity",
        201,
        Some("CreateServiceAccountRequest"),
        BodySchema::Object("CreatedServiceAccountResponse"),
        true,
    ),
    public_route(
        "/api/v1/organizations/{organization_id}/service-accounts/{service_account_id}/revoke",
        "POST",
        "revoke_service_account",
        "identity",
        204,
        None,
        BodySchema::None,
        true,
    ),
    public_route(
        "/api/v1/organizations",
        "POST",
        "create_organization",
        "organization",
        201,
        Some("CreateOrganizationRequest"),
        BodySchema::Object("CreatedOrganizationResponse"),
        true,
    ),
    public_route(
        "/api/v1/organizations/{organization_id}",
        "GET",
        "get_organization",
        "organization",
        200,
        None,
        BodySchema::Object("OrganizationResponse"),
        true,
    ),
    public_route(
        "/api/v1/organizations/{organization_id}",
        "PATCH",
        "update_organization",
        "organization",
        200,
        Some("UpdateOrganizationRequest"),
        BodySchema::Object("OrganizationResponse"),
        true,
    ),
    public_route(
        "/api/v1/organizations/{organization_id}/workspaces",
        "GET",
        "list_workspaces",
        "organization",
        200,
        None,
        BodySchema::Object("WorkspacePageResponse"),
        true,
    ),
    public_route(
        "/api/v1/organizations/{organization_id}/workspaces",
        "POST",
        "create_workspace",
        "organization",
        201,
        Some("CreateWorkspaceRequest"),
        BodySchema::Object("WorkspaceResponse"),
        true,
    ),
    public_route(
        "/api/v1/organizations/{organization_id}/members",
        "GET",
        "list_organization_members",
        "organization",
        200,
        None,
        BodySchema::Array("OrganizationMemberResponse"),
        true,
    ),
    public_route(
        "/api/v1/organizations/{organization_id}/members",
        "PUT",
        "set_organization_member",
        "organization",
        204,
        Some("SetOrganizationMemberRequest"),
        BodySchema::None,
        true,
    ),
    public_route(
        "/api/v1/organizations/{organization_id}/identity-providers",
        "GET",
        "list_federated_identity_providers",
        "organization",
        200,
        None,
        BodySchema::Array("FederatedIdentityProviderResponse"),
        true,
    ),
    public_route(
        "/api/v1/organizations/{organization_id}/identity-providers",
        "POST",
        "create_federated_identity_provider",
        "organization",
        201,
        Some("CreateFederatedIdentityProviderRequest"),
        BodySchema::Object("FederatedIdentityProviderResponse"),
        true,
    ),
    public_route(
        "/api/v1/organizations/{organization_id}/identity-providers/{provider_id}",
        "PATCH",
        "update_federated_identity_provider",
        "organization",
        200,
        Some("UpdateFederatedIdentityProviderRequest"),
        BodySchema::Object("FederatedIdentityProviderResponse"),
        true,
    ),
    public_route(
        "/api/v1/organizations/{organization_id}/identity-providers/{provider_id}/group-mappings",
        "GET",
        "list_federated_group_mappings",
        "organization",
        200,
        None,
        BodySchema::Array("FederatedGroupMappingResponse"),
        true,
    ),
    public_route(
        "/api/v1/organizations/{organization_id}/identity-providers/{provider_id}/group-mappings",
        "POST",
        "create_federated_group_mapping",
        "organization",
        201,
        Some("CreateFederatedGroupMappingRequest"),
        BodySchema::Object("FederatedGroupMappingResponse"),
        true,
    ),
    public_route(
        "/api/v1/organizations/{organization_id}/domains",
        "GET",
        "list_domains",
        "identity",
        200,
        None,
        BodySchema::Array("OrganizationDomainResponse"),
        true,
    ),
    public_route(
        "/api/v1/organizations/{organization_id}/domains",
        "POST",
        "create_domain",
        "identity",
        201,
        Some("CreateOrganizationDomainRequest"),
        BodySchema::Object("CreatedOrganizationDomainResponse"),
        true,
    ),
    public_route(
        "/api/v1/organizations/{organization_id}/domains/{domain_id}/verify",
        "POST",
        "verify_domain",
        "identity",
        200,
        None,
        BodySchema::Object("OrganizationDomainResponse"),
        true,
    ),
    public_route(
        "/api/v1/organizations/{organization_id}/domains/{domain_id}",
        "DELETE",
        "revoke_domain",
        "identity",
        204,
        None,
        BodySchema::None,
        true,
    ),
    public_route(
        "/api/v1/organizations/{organization_id}/identity-policy",
        "GET",
        "get_identity_policy",
        "identity",
        200,
        None,
        BodySchema::Object("OrganizationIdentityPolicyResponse"),
        true,
    ),
    public_route(
        "/api/v1/organizations/{organization_id}/identity-policy",
        "PUT",
        "update_identity_policy",
        "identity",
        200,
        Some("UpdateOrganizationIdentityPolicyRequest"),
        BodySchema::Object("OrganizationIdentityPolicyResponse"),
        true,
    ),
    public_route(
        "/api/v1/workspaces/{workspace_id}",
        "GET",
        "get_workspace",
        "organization",
        200,
        None,
        BodySchema::Object("WorkspaceResponse"),
        true,
    ),
    public_route(
        "/api/v1/workspaces/{workspace_id}",
        "PATCH",
        "update_workspace",
        "organization",
        200,
        Some("UpdateWorkspaceRequest"),
        BodySchema::Object("WorkspaceResponse"),
        true,
    ),
    public_route(
        "/api/v1/workspaces/{workspace_id}/select",
        "POST",
        "select_workspace",
        "organization",
        204,
        None,
        BodySchema::None,
        true,
    ),
    public_route(
        "/api/v1/workspaces/{workspace_id}/members",
        "GET",
        "list_workspace_members",
        "organization",
        200,
        None,
        BodySchema::Array("WorkspaceMemberResponse"),
        true,
    ),
    public_route(
        "/api/v1/workspaces/{workspace_id}/members",
        "PUT",
        "set_workspace_member",
        "organization",
        204,
        Some("SetWorkspaceMemberRequest"),
        BodySchema::None,
        true,
    ),
    public_route(
        "/api/v1/workspaces/{workspace_id}/agents",
        "GET",
        "list_agents",
        "agents",
        200,
        None,
        BodySchema::Object("AgentPageResponse"),
        true,
    ),
    public_route(
        "/api/v1/workspaces/{workspace_id}/agents",
        "POST",
        "create_agent",
        "agents",
        201,
        Some("CreateAgentRequest"),
        BodySchema::Object("AgentResponse"),
        true,
    ),
    public_route(
        "/api/v1/workspaces/{workspace_id}/agents/{agent_id}",
        "GET",
        "get_agent",
        "agents",
        200,
        None,
        BodySchema::Object("AgentResponse"),
        true,
    ),
    public_route(
        "/api/v1/workspaces/{workspace_id}/agents/{agent_id}",
        "PATCH",
        "update_agent",
        "agents",
        200,
        Some("UpdateAgentRequest"),
        BodySchema::Object("AgentResponse"),
        true,
    ),
    public_route(
        "/api/v1/workspaces/{workspace_id}/agents/{agent_id}/versions",
        "GET",
        "list_agent_versions",
        "agents",
        200,
        None,
        BodySchema::Array("AgentVersionResponse"),
        true,
    ),
    public_route(
        "/api/v1/workspaces/{workspace_id}/agents/{agent_id}/versions",
        "POST",
        "create_agent_version",
        "agents",
        201,
        Some("CreateAgentVersionRequest"),
        BodySchema::Object("AgentVersionResponse"),
        true,
    ),
    public_route(
        "/api/v1/workspaces/{workspace_id}/agents/{agent_id}/versions/{version_id}",
        "GET",
        "get_agent_version",
        "agents",
        200,
        None,
        BodySchema::Object("AgentVersionResponse"),
        true,
    ),
    public_route(
        "/api/v1/workspaces/{workspace_id}/agents/{agent_id}/active-version",
        "POST",
        "activate_agent_version",
        "agents",
        200,
        Some("ActivateVersionRequest"),
        BodySchema::Object("AgentResponse"),
        true,
    ),
    public_route(
        "/api/v1/workspaces/{workspace_id}/workflows",
        "GET",
        "list_workflows",
        "workflows",
        200,
        None,
        BodySchema::Object("WorkflowPageResponse"),
        true,
    ),
    public_route(
        "/api/v1/workspaces/{workspace_id}/workflows",
        "POST",
        "create_workflow",
        "workflows",
        201,
        Some("CreateWorkflowRequest"),
        BodySchema::Object("WorkflowResponse"),
        true,
    ),
    public_route(
        "/api/v1/workspaces/{workspace_id}/workflows/{workflow_id}",
        "GET",
        "get_workflow",
        "workflows",
        200,
        None,
        BodySchema::Object("WorkflowResponse"),
        true,
    ),
    public_route(
        "/api/v1/workspaces/{workspace_id}/workflows/{workflow_id}",
        "PATCH",
        "update_workflow",
        "workflows",
        200,
        Some("UpdateWorkflowRequest"),
        BodySchema::Object("WorkflowResponse"),
        true,
    ),
    public_route(
        "/api/v1/workspaces/{workspace_id}/workflows/{workflow_id}/versions",
        "GET",
        "list_workflow_versions",
        "workflows",
        200,
        None,
        BodySchema::Array("WorkflowVersionResponse"),
        true,
    ),
    public_route(
        "/api/v1/workspaces/{workspace_id}/workflows/{workflow_id}/versions",
        "POST",
        "create_workflow_version",
        "workflows",
        201,
        Some("CreateWorkflowVersionRequest"),
        BodySchema::Object("WorkflowVersionResponse"),
        true,
    ),
    public_route(
        "/api/v1/workspaces/{workspace_id}/workflows/{workflow_id}/versions/{version_id}",
        "GET",
        "get_workflow_version",
        "workflows",
        200,
        None,
        BodySchema::Object("WorkflowVersionResponse"),
        true,
    ),
    public_route(
        "/api/v1/workspaces/{workspace_id}/workflows/{workflow_id}/active-version",
        "POST",
        "activate_workflow_version",
        "workflows",
        200,
        Some("ActivateVersionRequest"),
        BodySchema::Object("WorkflowResponse"),
        true,
    ),
    public_route(
        "/api/v1/workspaces/{workspace_id}/connections",
        "GET",
        "list_connections",
        "models-and-tools",
        200,
        None,
        BodySchema::Object("ConnectionPageResponse"),
        true,
    ),
    public_route(
        "/api/v1/workspaces/{workspace_id}/connections",
        "POST",
        "create_connection",
        "models-and-tools",
        201,
        Some("CreateConnectionRequest"),
        BodySchema::Object("ConnectionResponse"),
        true,
    ),
    public_route(
        "/api/v1/workspaces/{workspace_id}/connections/{connection_id}",
        "GET",
        "get_connection",
        "models-and-tools",
        200,
        None,
        BodySchema::Object("ConnectionResponse"),
        true,
    ),
    public_route(
        "/api/v1/workspaces/{workspace_id}/connections/{connection_id}",
        "PATCH",
        "update_connection",
        "models-and-tools",
        200,
        Some("UpdateConnectionRequest"),
        BodySchema::Object("ConnectionResponse"),
        true,
    ),
    public_route(
        "/api/v1/workspaces/{workspace_id}/connections/{connection_id}/archive",
        "POST",
        "archive_connection",
        "models-and-tools",
        200,
        None,
        BodySchema::Object("ConnectionResponse"),
        true,
    ),
    public_route(
        "/api/v1/workspaces/{workspace_id}/connections/{connection_id}/secrets",
        "GET",
        "list_connection_secrets",
        "models-and-tools",
        200,
        None,
        BodySchema::Object("ConnectionSecretPageResponse"),
        true,
    ),
    public_route(
        "/api/v1/workspaces/{workspace_id}/connections/{connection_id}/secrets",
        "POST",
        "create_connection_secret",
        "models-and-tools",
        201,
        Some("CreateConnectionSecretRequest"),
        BodySchema::Object("ConnectionSecretResponse"),
        true,
    ),
    public_route(
        "/api/v1/workspaces/{workspace_id}/connections/{connection_id}/secrets/{secret_name}",
        "POST",
        "create_named_connection_secret",
        "models-and-tools",
        201,
        Some("ConnectionSecretValueRequest"),
        BodySchema::Object("ConnectionSecretResponse"),
        true,
    ),
    public_route(
        "/api/v1/workspaces/{workspace_id}/connections/{connection_id}/secrets/{secret_name}",
        "PUT",
        "rotate_connection_secret",
        "models-and-tools",
        200,
        Some("ConnectionSecretValueRequest"),
        BodySchema::Object("ConnectionSecretResponse"),
        true,
    ),
    public_route(
        "/api/v1/workspaces/{workspace_id}/model-profiles",
        "GET",
        "list_model_profiles",
        "models-and-tools",
        200,
        None,
        BodySchema::Object("ModelProfilePageResponse"),
        true,
    ),
    public_route(
        "/api/v1/workspaces/{workspace_id}/model-profiles",
        "POST",
        "create_model_profile",
        "models-and-tools",
        201,
        Some("CreateModelProfileRequest"),
        BodySchema::Object("ModelProfileResponse"),
        true,
    ),
    public_route(
        "/api/v1/workspaces/{workspace_id}/model-profiles/{model_profile_id}",
        "GET",
        "get_model_profile",
        "models-and-tools",
        200,
        None,
        BodySchema::Object("ModelProfileResponse"),
        true,
    ),
    public_route(
        "/api/v1/workspaces/{workspace_id}/model-profiles/{model_profile_id}",
        "PATCH",
        "update_model_profile",
        "models-and-tools",
        200,
        Some("UpdateModelProfileRequest"),
        BodySchema::Object("ModelProfileResponse"),
        true,
    ),
    public_route(
        "/api/v1/workspaces/{workspace_id}/model-profiles/{model_profile_id}/archive",
        "POST",
        "archive_model_profile",
        "models-and-tools",
        200,
        None,
        BodySchema::Object("ModelProfileResponse"),
        true,
    ),
    public_route(
        "/api/v1/organizations/{organization_id}/capability-definitions",
        "GET",
        "list_capability_definitions",
        "models-and-tools",
        200,
        None,
        BodySchema::Object("CapabilityDefinitionPageResponse"),
        true,
    ),
    public_route(
        "/api/v1/organizations/{organization_id}/capability-definitions",
        "POST",
        "create_capability_definition",
        "models-and-tools",
        201,
        Some("CreateCapabilityDefinitionRequest"),
        BodySchema::Object("CapabilityDefinitionResponse"),
        true,
    ),
    public_route(
        "/api/v1/organizations/{organization_id}/capability-definitions/{capability_id}",
        "GET",
        "get_capability_definition",
        "models-and-tools",
        200,
        None,
        BodySchema::Object("CapabilityDefinitionResponse"),
        true,
    ),
    public_route(
        "/api/v1/organizations/{organization_id}/capability-definitions/{capability_id}",
        "PATCH",
        "update_capability_definition",
        "models-and-tools",
        200,
        Some("UpdateCapabilityDefinitionRequest"),
        BodySchema::Object("CapabilityDefinitionResponse"),
        true,
    ),
    public_route(
        "/api/v1/organizations/{organization_id}/capability-definitions/{capability_id}/archive",
        "POST",
        "archive_capability_definition",
        "models-and-tools",
        200,
        None,
        BodySchema::Object("CapabilityDefinitionResponse"),
        true,
    ),
    public_route(
        "/api/v1/workspaces/{workspace_id}/capabilities",
        "GET",
        "list_workspace_capabilities",
        "models-and-tools",
        200,
        None,
        BodySchema::Object("WorkspaceCapabilityPageResponse"),
        true,
    ),
    public_route(
        "/api/v1/workspaces/{workspace_id}/capabilities",
        "POST",
        "create_workspace_capability",
        "models-and-tools",
        201,
        Some("CreateWorkspaceCapabilityRequest"),
        BodySchema::Object("WorkspaceCapabilityResponse"),
        true,
    ),
    public_route(
        "/api/v1/workspaces/{workspace_id}/capabilities/{capability_id}",
        "GET",
        "get_workspace_capability",
        "models-and-tools",
        200,
        None,
        BodySchema::Object("WorkspaceCapabilityResponse"),
        true,
    ),
    public_route(
        "/api/v1/workspaces/{workspace_id}/capabilities/{capability_id}",
        "PATCH",
        "update_workspace_capability",
        "models-and-tools",
        200,
        Some("UpdateWorkspaceCapabilityRequest"),
        BodySchema::Object("WorkspaceCapabilityResponse"),
        true,
    ),
    public_route(
        "/api/v1/workspaces/{workspace_id}/capabilities/{capability_id}/enable",
        "POST",
        "enable_workspace_capability",
        "models-and-tools",
        200,
        None,
        BodySchema::Object("WorkspaceCapabilityResponse"),
        true,
    ),
    public_route(
        "/api/v1/workspaces/{workspace_id}/capabilities/{capability_id}/disable",
        "POST",
        "disable_workspace_capability",
        "models-and-tools",
        200,
        None,
        BodySchema::Object("WorkspaceCapabilityResponse"),
        true,
    ),
    public_route(
        "/api/v1/workspaces/{workspace_id}/schedules",
        "GET",
        "list_schedules",
        "workflows",
        200,
        None,
        BodySchema::Object("SchedulePageResponse"),
        true,
    ),
    public_route(
        "/api/v1/workspaces/{workspace_id}/schedules",
        "POST",
        "create_schedule",
        "workflows",
        201,
        Some("CreateScheduleRequest"),
        BodySchema::Object("ScheduleResponse"),
        true,
    ),
    public_route(
        "/api/v1/workspaces/{workspace_id}/schedules/{schedule_id}",
        "GET",
        "get_schedule",
        "workflows",
        200,
        None,
        BodySchema::Object("ScheduleResponse"),
        true,
    ),
    public_route(
        "/api/v1/workspaces/{workspace_id}/schedules/{schedule_id}",
        "PATCH",
        "update_schedule",
        "workflows",
        200,
        Some("UpdateScheduleRequest"),
        BodySchema::Object("ScheduleResponse"),
        true,
    ),
    public_route(
        "/api/v1/workspaces/{workspace_id}/schedules/{schedule_id}/enable",
        "POST",
        "enable_schedule",
        "workflows",
        200,
        None,
        BodySchema::Object("ScheduleResponse"),
        true,
    ),
    public_route(
        "/api/v1/workspaces/{workspace_id}/schedules/{schedule_id}/disable",
        "POST",
        "disable_schedule",
        "workflows",
        200,
        None,
        BodySchema::Object("ScheduleResponse"),
        true,
    ),
    public_route(
        "/api/v1/workspaces/{workspace_id}/webhook-endpoints",
        "GET",
        "list_webhook_endpoints",
        "workflows",
        200,
        None,
        BodySchema::Object("WebhookEndpointPageResponse"),
        true,
    ),
    public_route(
        "/api/v1/workspaces/{workspace_id}/webhook-endpoints",
        "POST",
        "create_webhook_endpoint",
        "workflows",
        201,
        Some("CreateWebhookEndpointRequest"),
        BodySchema::Object("CreatedWebhookEndpointResponse"),
        true,
    ),
    public_route(
        "/api/v1/workspaces/{workspace_id}/webhook-endpoints/{endpoint_id}",
        "GET",
        "get_webhook_endpoint",
        "workflows",
        200,
        None,
        BodySchema::Object("WebhookEndpointResponse"),
        true,
    ),
    public_route(
        "/api/v1/workspaces/{workspace_id}/webhook-endpoints/{endpoint_id}",
        "PATCH",
        "update_webhook_endpoint",
        "workflows",
        200,
        Some("UpdateWebhookEndpointRequest"),
        BodySchema::Object("WebhookEndpointResponse"),
        true,
    ),
    public_route(
        "/api/v1/workspaces/{workspace_id}/webhook-endpoints/{endpoint_id}/enable",
        "POST",
        "enable_webhook_endpoint",
        "workflows",
        200,
        None,
        BodySchema::Object("WebhookEndpointResponse"),
        true,
    ),
    public_route(
        "/api/v1/workspaces/{workspace_id}/webhook-endpoints/{endpoint_id}/disable",
        "POST",
        "disable_webhook_endpoint",
        "workflows",
        200,
        None,
        BodySchema::Object("WebhookEndpointResponse"),
        true,
    ),
    public_route(
        "/api/v1/workspaces/{workspace_id}/work-items",
        "GET",
        "list_work_items",
        "collaboration",
        200,
        None,
        BodySchema::Object("WorkItemPageResponse"),
        true,
    ),
    public_route(
        "/api/v1/workspaces/{workspace_id}/work-items",
        "POST",
        "create_work_item",
        "collaboration",
        201,
        Some("CreateWorkItemRequest"),
        BodySchema::Object("WorkItemResponse"),
        true,
    ),
    public_route(
        "/api/v1/workspaces/{workspace_id}/work-items/{work_item_id}",
        "GET",
        "get_work_item",
        "collaboration",
        200,
        None,
        BodySchema::Object("WorkItemResponse"),
        true,
    ),
    public_route(
        "/api/v1/workspaces/{workspace_id}/work-items/{work_item_id}",
        "PATCH",
        "update_work_item",
        "collaboration",
        200,
        Some("UpdateWorkItemRequest"),
        BodySchema::Object("WorkItemResponse"),
        true,
    ),
    public_route(
        "/api/v1/workspaces/{workspace_id}/work-items/{work_item_id}/external-references",
        "GET",
        "list_work_item_external_references",
        "collaboration",
        200,
        None,
        BodySchema::Array("ExternalReferenceResponse"),
        true,
    ),
    public_route(
        "/api/v1/workspaces/{workspace_id}/work-items/{work_item_id}/external-references",
        "POST",
        "create_work_item_external_reference",
        "collaboration",
        201,
        Some("CreateExternalReferenceRequest"),
        BodySchema::Object("ExternalReferenceResponse"),
        true,
    ),
    public_route(
        "/api/v1/workspaces/{workspace_id}/work-items/{work_item_id}/attachments",
        "GET",
        "list_work_item_attachments",
        "collaboration",
        200,
        None,
        BodySchema::Array("AttachmentResponse"),
        true,
    ),
    public_route(
        "/api/v1/workspaces/{workspace_id}/work-items/{work_item_id}/attachments",
        "POST",
        "create_work_item_attachment",
        "collaboration",
        201,
        Some("CreateAttachmentRequest"),
        BodySchema::Object("AttachmentResponse"),
        true,
    ),
    public_route(
        "/api/v1/workspaces/{workspace_id}/work-items/{work_item_id}/attachments/{attachment_id}",
        "GET",
        "download_work_item_attachment",
        "collaboration",
        200,
        None,
        BodySchema::None,
        true,
    ),
    public_route(
        "/api/v1/workspaces/{workspace_id}/sessions",
        "GET",
        "list_sessions",
        "collaboration",
        200,
        None,
        BodySchema::Object("SessionPageResponse"),
        true,
    ),
    public_route(
        "/api/v1/workspaces/{workspace_id}/sessions",
        "POST",
        "create_session",
        "collaboration",
        201,
        Some("CreateSessionRequest"),
        BodySchema::Object("SessionResponse"),
        true,
    ),
    public_route(
        "/api/v1/workspaces/{workspace_id}/sessions/{session_id}",
        "GET",
        "get_session",
        "collaboration",
        200,
        None,
        BodySchema::Object("SessionResponse"),
        true,
    ),
    public_route(
        "/api/v1/workspaces/{workspace_id}/sessions/{session_id}/messages",
        "POST",
        "submit_message",
        "collaboration",
        201,
        Some("SubmitMessageRequest"),
        BodySchema::Object("AppendedEventResponse"),
        true,
    ),
    public_route(
        "/api/v1/workspaces/{workspace_id}/sessions/{session_id}/events",
        "GET",
        "list_session_events",
        "collaboration",
        200,
        None,
        BodySchema::Array("SessionEventResponse"),
        true,
    ),
    public_route(
        "/api/v1/workspaces/{workspace_id}/runs",
        "GET",
        "list_runs",
        "execution",
        200,
        None,
        BodySchema::Object("RunPageResponse"),
        true,
    ),
    public_route(
        "/api/v1/workspaces/{workspace_id}/runs",
        "POST",
        "create_run",
        "execution",
        201,
        Some("CreateRunRequest"),
        BodySchema::Object("RunResponse"),
        true,
    ),
    public_route(
        "/api/v1/workspaces/{workspace_id}/runs/{run_id}",
        "GET",
        "get_run",
        "execution",
        200,
        None,
        BodySchema::Object("RunResponse"),
        true,
    ),
    public_route(
        "/api/v1/workspaces/{workspace_id}/runs/{run_id}/trace",
        "GET",
        "get_run_trace",
        "execution",
        200,
        None,
        BodySchema::Object("RunTraceResponse"),
        true,
    ),
    public_route(
        "/api/v1/workspaces/{workspace_id}/runs/{run_id}/children",
        "GET",
        "list_child_runs",
        "execution",
        200,
        None,
        BodySchema::Array("ChildRunResponse"),
        true,
    ),
    public_route(
        "/api/v1/workspaces/{workspace_id}/runs/{run_id}/cancel",
        "POST",
        "cancel_run",
        "execution",
        202,
        Some("CancelRunRequest"),
        BodySchema::None,
        true,
    ),
    public_route(
        "/api/v1/workspaces/{workspace_id}/runs/{run_id}/retry",
        "POST",
        "retry_run",
        "execution",
        201,
        Some("RetryRunRequest"),
        BodySchema::Object("RunResponse"),
        true,
    ),
    public_route(
        "/api/v1/workspaces/{workspace_id}/runs/{run_id}/events",
        "GET",
        "list_run_events",
        "execution",
        200,
        None,
        BodySchema::Array("RunEventResponse"),
        true,
    ),
    public_route(
        "/api/v1/workspaces/{workspace_id}/runs/{run_id}/events/stream",
        "GET",
        "stream_run_events",
        "execution",
        200,
        None,
        BodySchema::None,
        true,
    ),
    public_route(
        "/api/v1/workspaces/{workspace_id}/runs/{run_id}/usage",
        "GET",
        "get_run_usage",
        "execution",
        200,
        None,
        BodySchema::Object("RunUsageSummaryResponse"),
        true,
    ),
    public_route(
        "/api/v1/workspaces/{workspace_id}/approvals",
        "GET",
        "list_approvals",
        "approvals",
        200,
        None,
        BodySchema::Array("ApprovalResponse"),
        true,
    ),
    public_route(
        "/api/v1/workspaces/{workspace_id}/approvals/{approval_id}/approve",
        "POST",
        "approve",
        "approvals",
        204,
        Some("DecideApprovalRequest"),
        BodySchema::None,
        true,
    ),
    public_route(
        "/api/v1/workspaces/{workspace_id}/approvals/{approval_id}/reject",
        "POST",
        "reject",
        "approvals",
        204,
        Some("DecideApprovalRequest"),
        BodySchema::None,
        true,
    ),
    public_route(
        "/api/v1/workspaces/{workspace_id}/experience-candidates",
        "GET",
        "list_experience_candidates",
        "experience",
        200,
        None,
        BodySchema::Object("ExperienceCandidatePageResponse"),
        true,
    ),
    public_route(
        "/api/v1/workspaces/{workspace_id}/experience-candidates",
        "POST",
        "create_experience_candidate",
        "experience",
        201,
        Some("CreateExperienceCandidateRequest"),
        BodySchema::Object("ExperienceCandidateResponse"),
        true,
    ),
    public_route(
        "/api/v1/workspaces/{workspace_id}/experience-candidates/{candidate_id}",
        "GET",
        "get_experience_candidate",
        "experience",
        200,
        None,
        BodySchema::Object("ExperienceCandidateResponse"),
        true,
    ),
    public_route(
        "/api/v1/workspaces/{workspace_id}/experience-candidates/{candidate_id}/review",
        "POST",
        "review_experience_candidate",
        "experience",
        200,
        Some("ReviewExperienceCandidateRequest"),
        BodySchema::Object("ExperienceCandidateResponse"),
        true,
    ),
    public_route(
        "/api/v1/workspaces/{workspace_id}/experience-candidates/{candidate_id}/publish",
        "POST",
        "publish_experience_candidate",
        "experience",
        201,
        None,
        BodySchema::Object("ExperienceEntryResponse"),
        true,
    ),
    public_route(
        "/api/v1/workspaces/{workspace_id}/experience-entries",
        "GET",
        "list_experience_entries",
        "experience",
        200,
        None,
        BodySchema::Object("ExperienceEntryPageResponse"),
        true,
    ),
    public_route(
        "/api/v1/workspaces/{workspace_id}/experience-entries/search",
        "GET",
        "search_experience_entries",
        "experience",
        200,
        None,
        BodySchema::Array("ExperienceSearchResult"),
        true,
    ),
    public_route(
        "/api/v1/workspaces/{workspace_id}/experience-entries/{entry_id}",
        "GET",
        "get_experience_entry",
        "experience",
        200,
        None,
        BodySchema::Object("ExperienceEntryResponse"),
        true,
    ),
    public_route(
        "/api/v1/workspaces/{workspace_id}/experience-entries/{entry_id}/withdraw",
        "POST",
        "withdraw_experience_entry",
        "experience",
        204,
        Some("WithdrawExperienceRequest"),
        BodySchema::None,
        true,
    ),
];

struct OpenApiModifier;

impl Modify for OpenApiModifier {
    fn modify(&self, openapi: &mut utoipa::openapi::OpenApi) {
        let components = openapi.components.get_or_insert_with(Components::new);
        components.add_security_scheme(
            SESSION_COOKIE_SECURITY_SCHEME,
            SecurityScheme::ApiKey(ApiKey::Cookie(ApiKeyValue::with_description(
                "zeus_session",
                "HttpOnly session cookie",
            ))),
        );
        components.add_security_scheme(
            SERVICE_ACCOUNT_BEARER_SECURITY_SCHEME,
            SecurityScheme::Http(
                HttpBuilder::new()
                    .scheme(HttpAuthScheme::Bearer)
                    .bearer_format("ServiceAccount")
                    .description(Some("Bearer token for a Zeus service account"))
                    .build(),
            ),
        );

        for route in PUBLIC_ROUTES {
            let path_item = openapi
                .paths
                .paths
                .entry(route.path.to_owned())
                .or_default();
            let slot = operation_slot(path_item, &route.http_method());
            if slot.is_none() {
                *slot = Some(operation_for(route));
            }
            let operation = slot.as_mut().expect("route operation was just installed");
            operation.operation_id = Some(route.operation_id.to_owned());
            if operation.tags.as_ref().is_none_or(Vec::is_empty) {
                operation.tags = Some(vec![route.tag.to_owned()]);
            }
            if operation.parameters.is_none() {
                let parameters = path_parameters(route.path);
                if !parameters.is_empty() {
                    operation.parameters = Some(parameters);
                }
            }
            if operation.request_body.is_none() {
                operation.request_body = route.request_schema.map(request_body);
            }
            operation
                .responses
                .responses
                .entry(route.success_status.to_string())
                .or_insert_with(|| RefOr::T(success_response(route.response_schema)));
            if !has_problem_response(&operation.responses) {
                operation
                    .responses
                    .responses
                    .insert("default".to_owned(), RefOr::T(problem_response()));
            }
            if operation.security.is_none() {
                operation.security = Some(security_requirements(route.requires_auth));
            }
        }

        mark_write_only(components, "CreateConnectionRequest", "secrets");
        mark_write_only(components, "CreateConnectionSecretRequest", "secret");
        mark_write_only(components, "ConnectionSecretValueRequest", "secret");
        mark_write_only(
            components,
            "CreateFederatedIdentityProviderRequest",
            "client_secret",
        );
        mark_write_only(
            components,
            "UpdateFederatedIdentityProviderRequest",
            "client_secret",
        );
        mark_write_only(components, "CreatedServiceAccountResponse", "token");
        mark_write_only(components, "CreatedWebhookEndpointResponse", "secret");
    }
}

fn operation_slot<'a>(
    path_item: &'a mut PathItem,
    method: &HttpMethod,
) -> &'a mut Option<Operation> {
    match method {
        HttpMethod::Get => &mut path_item.get,
        HttpMethod::Post => &mut path_item.post,
        HttpMethod::Put => &mut path_item.put,
        HttpMethod::Patch => &mut path_item.patch,
        HttpMethod::Delete => &mut path_item.delete,
        HttpMethod::Options | HttpMethod::Head | HttpMethod::Trace => {
            panic!("unsupported HTTP method in PUBLIC_ROUTES")
        }
    }
}

fn operation_for(route: &PublicRoute) -> Operation {
    let mut operation = Operation::new();
    operation.operation_id = Some(route.operation_id.to_owned());
    operation.tags = Some(vec![route.tag.to_owned()]);
    let parameters = path_parameters(route.path);
    if !parameters.is_empty() {
        operation.parameters = Some(parameters);
    }
    operation.request_body = route.request_schema.map(request_body);
    operation.responses = Responses::new();
    operation.responses.responses.insert(
        route.success_status.to_string(),
        RefOr::T(success_response(route.response_schema)),
    );
    operation
        .responses
        .responses
        .insert("default".to_owned(), RefOr::T(problem_response()));
    operation.security = Some(security_requirements(route.requires_auth));
    operation
}

fn path_parameters(path: &str) -> Vec<Parameter> {
    path.split('{')
        .skip(1)
        .filter_map(|part| part.split('}').next())
        .map(|name| {
            ParameterBuilder::new()
                .name(name)
                .parameter_in(ParameterIn::Path)
                .required(Required::True)
                .description(Some("Path identifier"))
                .schema(Some(ObjectBuilder::new().schema_type(Type::String)))
                .build()
        })
        .collect()
}

fn request_body(schema_name: &'static str) -> utoipa::openapi::request_body::RequestBody {
    RequestBodyBuilder::new()
        .description(Some("JSON request body"))
        .required(Some(Required::True))
        .content(
            "application/json",
            json_content(BodySchema::Object(schema_name)),
        )
        .build()
}

fn json_content(schema: BodySchema) -> Content {
    Content::new(schema_ref(schema))
}

fn schema_ref(schema: BodySchema) -> Option<RefOr<Schema>> {
    match schema {
        BodySchema::None => None,
        BodySchema::Object(name) => Some(Ref::from_schema_name(name).into()),
        BodySchema::Array(name) => {
            Some(Schema::Array(Array::new(Ref::from_schema_name(name))).into())
        }
    }
}

fn success_response(schema: BodySchema) -> Response {
    let mut response = Response::new("Successful response");
    if !matches!(schema, BodySchema::None) {
        response
            .content
            .insert("application/json".to_owned(), json_content(schema));
    }
    response
}

fn problem_response() -> Response {
    let mut response = Response::new("Problem Details error");
    response.content.insert(
        "application/problem+json".to_owned(),
        json_content(BodySchema::Object("ProblemDetails")),
    );
    response
}

fn has_problem_response(responses: &Responses) -> bool {
    responses.responses.values().any(|response| match response {
        RefOr::Ref(_) => false,
        RefOr::T(response) => response.content.contains_key("application/problem+json"),
    })
}

fn security_requirements(requires_auth: bool) -> Vec<SecurityRequirement> {
    if requires_auth {
        vec![
            SecurityRequirement::new(SESSION_COOKIE_SECURITY_SCHEME, std::iter::empty::<&str>()),
            SecurityRequirement::new(
                SERVICE_ACCOUNT_BEARER_SECURITY_SCHEME,
                std::iter::empty::<&str>(),
            ),
        ]
    } else {
        vec![SecurityRequirement::default()]
    }
}

fn mark_write_only(components: &mut Components, schema_name: &str, property_name: &str) {
    let Some(RefOr::T(Schema::Object(schema))) = components.schemas.get_mut(schema_name) else {
        return;
    };
    let Some(RefOr::T(Schema::Object(property))) = schema.properties.get_mut(property_name) else {
        return;
    };
    property.write_only = Some(true);
}

impl PublicRoute {
    fn http_method(self) -> HttpMethod {
        match self.method {
            "GET" => HttpMethod::Get,
            "POST" => HttpMethod::Post,
            "PUT" => HttpMethod::Put,
            "PATCH" => HttpMethod::Patch,
            "DELETE" => HttpMethod::Delete,
            _ => panic!("unsupported HTTP method in PUBLIC_ROUTES: {}", self.method),
        }
    }
}

pub fn router(state: AppState) -> Router {
    let request_metrics = Arc::clone(&state.metrics);
    let browser_security_state = state.clone();
    Router::new()
        .merge(auth::routes())
        .merge(native_auth::routes())
        .merge(native_identity::routes())
        .merge(organization::routes())
        .merge(organization_identity::routes())
        .merge(federated_identity::routes())
        .merge(agents::routes())
        .merge(integrations::routes())
        .merge(work_items::routes())
        .merge(experiences::routes())
        .merge(execution_api::routes())
        .route("/health/live", get(live))
        .route("/health/ready", get(ready))
        .route("/metrics", get(metrics))
        .route("/api/v1/meta", get(meta))
        .route("/api/v1/openapi.json", get(openapi))
        .with_state(state)
        .layer(middleware::from_fn_with_state(
            browser_security_state,
            auth::enforce_browser_write_security,
        ))
        .layer(middleware::from_fn_with_state(
            request_metrics,
            track_http_request,
        ))
        .layer(DefaultBodyLimit::max(8 * 1024 * 1024))
        .layer(CompressionLayer::new())
        .layer(CatchPanicLayer::new())
        .layer(
            TraceLayer::new_for_http()
                .make_span_with(|request: &Request| {
                    let request_id = request
                        .headers()
                        .get("x-request-id")
                        .and_then(|value| value.to_str().ok())
                        .unwrap_or("missing");
                    tracing::span!(
                        Level::INFO,
                        "http.request",
                        method = %request.method(),
                        path = request.uri().path(),
                        request_id = %request_id,
                    )
                })
                .on_response(DefaultOnResponse::new().level(Level::INFO)),
        )
        .layer(middleware::from_fn(request_context))
}

async fn request_context(mut request: Request, next: Next) -> AxumResponse {
    let request_id = request_id_from_headers(request.headers()).unwrap_or_else(Uuid::now_v7);
    let header_value = HeaderValue::from_str(&request_id.to_string())
        .expect("a UUID is always a valid header value");
    request.headers_mut().insert(
        HeaderName::from_static("x-request-id"),
        header_value.clone(),
    );
    let mut response = REQUEST_ID
        .scope(request_id, async move { next.run(request).await })
        .await;
    response
        .headers_mut()
        .insert(HeaderName::from_static("x-request-id"), header_value);
    response
}

fn request_id_from_headers(headers: &HeaderMap) -> Option<Uuid> {
    let request_id = headers
        .get("x-request-id")?
        .to_str()
        .ok()
        .and_then(|value| Uuid::parse_str(value).ok())?;
    (request_id.get_version_num() == 7).then_some(request_id)
}

async fn track_http_request(
    State(metrics): State<Arc<SupervisorMetrics>>,
    request: Request,
    next: Next,
) -> AxumResponse {
    if !should_track_http_path(request.uri().path()) {
        return next.run(request).await;
    }
    let _request = metrics.begin_http_request();
    next.run(request).await
}

fn should_track_http_path(path: &str) -> bool {
    !matches!(path, "/health/live" | "/health/ready" | "/metrics")
}

#[utoipa::path(get, path = "/health/live", tag = "operations", responses(
    (status = 200, description = "Process is alive", body = HealthResponse)
))]
async fn live() -> Json<HealthResponse> {
    Json(HealthResponse { status: "ok" })
}

#[utoipa::path(get, path = "/health/ready", tag = "operations", responses(
    (status = 200, description = "Database is ready", body = HealthResponse),
    (status = 503, description = "Database is unavailable", body = ProblemDetails, content_type = "application/problem+json")
))]
async fn ready(State(state): State<AppState>) -> Result<Json<HealthResponse>, ApiError> {
    sqlx::query_scalar::<_, i32>("select 1")
        .fetch_one(&state.database)
        .await
        .map_err(|_| ApiError::DatabaseUnavailable)?;
    Ok(Json(HealthResponse { status: "ready" }))
}

#[utoipa::path(get, path = "/api/v1/meta", tag = "platform", responses(
    (status = 200, description = "Zeus API metadata", body = MetaResponse)
))]
async fn meta(State(state): State<AppState>) -> Json<MetaResponse> {
    Json(MetaResponse {
        product: "Zeus",
        version: state.version,
        api_version: "v1",
        queue_backend: "postgresql",
        worker_process: false,
        features: vec![
            FeatureStatus {
                name: "schema",
                status: "implemented",
            },
            FeatureStatus {
                name: "execution_supervisor",
                status: "implemented",
            },
            FeatureStatus {
                name: "oidc",
                status: "implemented",
            },
            FeatureStatus {
                name: "control_plane",
                status: "implemented",
            },
        ],
    })
}

async fn openapi() -> Json<utoipa::openapi::OpenApi> {
    Json(ApiDoc::openapi())
}

async fn metrics(State(state): State<AppState>) -> String {
    format!(
        concat!(
            "# HELP zeus_runs_claimed_total Runs claimed by this process.\n",
            "# TYPE zeus_runs_claimed_total counter\n",
            "zeus_runs_claimed_total {}\n",
            "# HELP zeus_runs_finished_total Runs finished by this process.\n",
            "# TYPE zeus_runs_finished_total counter\n",
            "zeus_runs_finished_total {}\n",
            "# HELP zeus_runs_failed_total Runs failed by this process.\n",
            "# TYPE zeus_runs_failed_total counter\n",
            "zeus_runs_failed_total {}\n",
            "# HELP zeus_active_runs Runs currently executing in this process.\n",
            "# TYPE zeus_active_runs gauge\n",
            "zeus_active_runs {}\n",
            "# HELP zeus_queue_depth Runs ready to be claimed.\n",
            "# TYPE zeus_queue_depth gauge\n",
            "zeus_queue_depth {}\n",
            "# HELP zeus_http_requests_total HTTP requests completed by this process.\n",
            "# TYPE zeus_http_requests_total counter\n",
            "zeus_http_requests_total {}\n",
            "# HELP zeus_http_inflight_requests HTTP requests currently handled by this process.\n",
            "# TYPE zeus_http_inflight_requests gauge\n",
            "zeus_http_inflight_requests {}\n"
        ),
        state.metrics.claimed(),
        state.metrics.finished(),
        state.metrics.failed(),
        state.metrics.active(),
        state.metrics.queue_depth(),
        state.metrics.http_requests(),
        state.metrics.http_inflight(),
    )
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::{
        ApiDoc, PUBLIC_ROUTES, has_problem_response, request_id_from_headers,
        should_track_http_path,
    };
    use http::{HeaderMap, HeaderValue};
    use utoipa::OpenApi;

    #[test]
    fn public_routes_are_documented_with_unique_operation_ids() {
        let document = ApiDoc::openapi();
        let mut route_keys = BTreeSet::new();
        let mut registered_operation_ids = BTreeSet::new();

        for route in PUBLIC_ROUTES {
            assert!(
                route_keys.insert((route.path, route.method)),
                "duplicate public route {} {}",
                route.method,
                route.path
            );
            let operation = document
                .paths
                .get_path_operation(route.path, route.http_method())
                .unwrap_or_else(|| {
                    panic!("missing OpenAPI operation {} {}", route.method, route.path)
                });
            assert_eq!(
                operation.operation_id.as_deref(),
                Some(route.operation_id),
                "operationId mismatch for {} {}",
                route.method,
                route.path
            );
            assert!(
                operation
                    .responses
                    .responses
                    .contains_key(&route.success_status.to_string()),
                "missing success response for {} {}",
                route.method,
                route.path
            );
            assert!(
                has_problem_response(&operation.responses),
                "missing problem+json response for {} {}",
                route.method,
                route.path
            );
            assert!(
                registered_operation_ids.insert(route.operation_id),
                "duplicate operationId {}",
                route.operation_id
            );
        }

        let mut document_operation_ids = BTreeSet::new();
        for path_item in document.paths.paths.values() {
            for operation in [
                &path_item.get,
                &path_item.put,
                &path_item.post,
                &path_item.delete,
                &path_item.options,
                &path_item.head,
                &path_item.patch,
                &path_item.trace,
            ]
            .into_iter()
            .flatten()
            {
                let operation_id = operation
                    .operation_id
                    .as_deref()
                    .expect("every OpenAPI operation has an operationId");
                assert!(
                    document_operation_ids.insert(operation_id),
                    "duplicate document operationId {operation_id}"
                );
            }
        }
        assert_eq!(document_operation_ids, registered_operation_ids);
    }

    #[test]
    fn openapi_declares_security_schemes_and_no_reserved_contract() {
        let openapi = ApiDoc::openapi();
        let components = openapi.components.as_ref().expect("OpenAPI components");
        assert!(components.security_schemes.contains_key("sessionCookie"));
        assert!(
            components
                .security_schemes
                .contains_key("serviceAccountBearer")
        );
        let document = openapi.to_json().expect("valid OpenAPI JSON");
        assert!(!document.contains("The contract is reserved"));
        assert!(!document.contains("\"501\""));
    }

    #[test]
    fn operational_probes_do_not_create_http_pressure() {
        assert!(!should_track_http_path("/health/live"));
        assert!(!should_track_http_path("/health/ready"));
        assert!(!should_track_http_path("/metrics"));
        assert!(should_track_http_path("/api/v1/runs"));
        assert!(should_track_http_path("/auth/login"));
    }

    #[test]
    fn request_ids_accept_only_uuid_v7_values() {
        let request_id = uuid::Uuid::now_v7();
        let mut headers = HeaderMap::new();
        headers.insert(
            "x-request-id",
            HeaderValue::from_str(&request_id.to_string()).expect("valid header"),
        );
        assert_eq!(request_id_from_headers(&headers), Some(request_id));

        headers.insert("x-request-id", HeaderValue::from_static("not-a-uuid"));
        assert_eq!(request_id_from_headers(&headers), None);
    }
}
