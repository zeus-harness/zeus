use serde::Serialize;
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

use crate::{
    agents, auth, error::ProblemDetails, execution_api, experiences, federated_identity,
    integrations, native_auth, native_identity, oidc_provider, organization, organization_identity,
    platform_tenants, work_items,
};

use super::operations;

mod routes;

#[derive(OpenApi)]
#[openapi(
    info(
        title = "Zeus API",
        version = "0.1.0",
        description = "Enterprise Harness Agent control plane and durable execution API."
    ),
    paths(
        operations::live,
        operations::ready,
        operations::meta,
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
        native_auth::list_external_identities,
        native_auth::unlink_organization_federated_binding,
        native_auth::revoke_external_identity,
        organization_identity::list_invitations,
        organization_identity::create_invitation,
        organization_identity::resend_invitation,
        organization_identity::revoke_invitation,
        auth::current_user,
        auth::create_external_identity_link_intent,
        federated_identity::list_domains,
        federated_identity::create_domain,
        federated_identity::verify_domain,
        federated_identity::revoke_domain,
        federated_identity::get_identity_policy,
        federated_identity::update_identity_policy,
        auth::create_service_account,
        auth::create_workspace_service_account,
        auth::list_service_accounts,
        auth::list_workspace_service_accounts,
        auth::revoke_service_account,
        auth::revoke_workspace_service_account,
        organization::create_organization,
        organization::get_organization,
        organization::update_organization,
        organization::list_workspaces,
        organization::create_workspace,
        organization::get_workspace,
        organization::update_workspace,
        organization::select_workspace,
        platform_tenants::list_platform_organizations,
        platform_tenants::get_platform_organization,
        platform_tenants::create_platform_organization,
        platform_tenants::update_platform_organization,
        platform_tenants::transition_platform_organization,
        platform_tenants::resend_platform_owner_invitation,
        platform_tenants::replace_platform_owner_invitation,
        platform_tenants::create_platform_tenant_access_grant,
        platform_tenants::revoke_platform_tenant_access_grant,
        execution_api::create_run,
        execution_api::start_work_item_run,
        execution_api::list_runs,
        execution_api::list_approvals
    ),
    modifiers(&OpenApiModifier),
    components(schemas(
        HealthResponse,
        MetaResponse,
        FeatureStatus,
        ProblemDetails,
        OAuthProtocolError,
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
        native_auth::OrganizationFederatedBindingResponse,
        native_auth::ExternalIdentityResponse,
        native_auth::AvailableFederatedProviderResponse,
        native_auth::ExternalIdentityOverviewResponse,
        organization_identity::InvitationWorkspaceRequest,
        organization_identity::CreateInvitationRequest,
        organization_identity::InvitationResponse,
        auth::CurrentUserResponse,
        auth::ExternalIdentityLinkIntentRequest,
        auth::ExternalIdentityLinkIntentResponse,
        auth::CreateServiceAccountRequest,
        auth::CreateWorkspaceServiceAccountRequest,
        auth::CreatedServiceAccountResponse,
        auth::ServiceAccountResponse,
        federated_identity::OrganizationDomainResponse,
        federated_identity::CreateOrganizationDomainRequest,
        federated_identity::CreatedOrganizationDomainResponse,
        federated_identity::OrganizationIdentityPolicyResponse,
        federated_identity::UpdateOrganizationIdentityPolicyRequest,
        oidc_provider::OidcClientResponse,
        oidc_provider::CreateOidcClientRequest,
        oidc_provider::CreatedOidcClientResponse,
        oidc_provider::UpdateOidcClientRequest,
        oidc_provider::OidcGrantResponse,
        oidc_provider::AuthorizationRequestResponse,
        oidc_provider::AuthorizationDecisionRequest,
        oidc_provider::AuthorizationDecisionResponse,
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
        platform_tenants::PlatformOrganizationResponse,
        platform_tenants::CreatePlatformOrganizationRequest,
        platform_tenants::CreatedPlatformOrganizationResponse,
        platform_tenants::UpdatePlatformOrganizationRequest,
        platform_tenants::TransitionPlatformOrganizationRequest,
        platform_tenants::PlatformOrganizationMutationResponse,
        platform_tenants::ReplacePlatformOwnerInvitationRequest,
        platform_tenants::PlatformOwnerInvitationResponse,
        platform_tenants::CreatePlatformTenantAccessGrantRequest,
        platform_tenants::PlatformTenantAccessGrantResponse,
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
        execution_api::StartWorkItemRunRequest,
        execution_api::RunResponse,
        execution_api::RunPageResponse,
        execution_api::WorkItemRunStartResponse,
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
pub struct OAuthProtocolError {
    pub error: String,
    pub error_description: Option<String>,
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

pub(super) const PUBLIC_ROUTES: routes::PublicRoutes = routes::PUBLIC_ROUTES;

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
            if uses_oauth_error_contract(route.path) {
                operation
                    .responses
                    .responses
                    .insert("default".to_owned(), RefOr::T(oauth_error_response()));
            } else if !has_problem_response(&operation.responses) {
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

fn oauth_error_response() -> Response {
    let mut response = Response::new("OAuth 2.0 or OpenID Connect error");
    response.content.insert(
        "application/json".to_owned(),
        json_content(BodySchema::Object("OAuthProtocolError")),
    );
    response
}

pub(super) fn uses_oauth_error_contract(path: &str) -> bool {
    matches!(
        path,
        "/oauth2/authorize" | "/oauth2/token" | "/oauth2/userinfo" | "/oauth2/revoke"
    )
}

pub(super) fn has_problem_response(responses: &Responses) -> bool {
    responses.responses.values().any(|response| match response {
        RefOr::Ref(_) => false,
        RefOr::T(response) => response.content.contains_key("application/problem+json"),
    })
}

#[cfg(test)]
pub(super) fn has_oauth_error_response(responses: &Responses) -> bool {
    matches!(
        responses.responses.get("default"),
        Some(RefOr::T(response)) if response.content.contains_key("application/json")
    )
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
    pub(super) fn http_method(self) -> HttpMethod {
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
