import type { components } from './generated/schema';
import { jsonRequest, requestJson, type ApiFetcher } from './client';
import { serverApiUrl } from './server';

export type PlatformOrganization = components['schemas']['PlatformOrganizationResponse'];
export type CreatedPlatformOrganization = components['schemas']['CreatedPlatformOrganizationResponse'];
export type PlatformOrganizationMutation = components['schemas']['PlatformOrganizationMutationResponse'];
export type PlatformTenantAccessGrant = components['schemas']['PlatformTenantAccessGrantResponse'];
export type CreatePlatformOrganization = components['schemas']['CreatePlatformOrganizationRequest'];
export type CreatePlatformTenantAccessGrant = components['schemas']['CreatePlatformTenantAccessGrantRequest'];

function platformOrganizationPath(organizationId?: string): string {
  return organizationId
    ? `/api/v1/platform/organizations/${encodeURIComponent(organizationId)}`
    : '/api/v1/platform/organizations';
}

export function listPlatformOrganizations(
  fetcher: ApiFetcher,
  apiBaseUrl?: string
): Promise<PlatformOrganization[]> {
  return requestJson<PlatformOrganization[]>(
    fetcher,
    serverApiUrl(apiBaseUrl, platformOrganizationPath())
  );
}

export function getPlatformOrganization(
  fetcher: ApiFetcher,
  organizationId: string,
  apiBaseUrl?: string
): Promise<PlatformOrganization> {
  return requestJson<PlatformOrganization>(
    fetcher,
    serverApiUrl(apiBaseUrl, platformOrganizationPath(organizationId))
  );
}

export function createPlatformOrganization(
  fetcher: ApiFetcher,
  payload: CreatePlatformOrganization,
  idempotencyKey: string,
  apiBaseUrl?: string
): Promise<CreatedPlatformOrganization> {
  return requestJson<CreatedPlatformOrganization>(
    fetcher,
    serverApiUrl(apiBaseUrl, platformOrganizationPath()),
    jsonRequest('POST', payload, { 'idempotency-key': idempotencyKey })
  );
}

export function updatePlatformOrganization(
  fetcher: ApiFetcher,
  organizationId: string,
  revision: number,
  payload: { name?: string; slug?: string; identity_settings_mode?: string },
  apiBaseUrl?: string
): Promise<PlatformOrganizationMutation> {
  return requestJson<PlatformOrganizationMutation>(
    fetcher,
    serverApiUrl(apiBaseUrl, platformOrganizationPath(organizationId)),
    jsonRequest('PATCH', payload, { 'if-match': `"${revision}"` })
  );
}

export function transitionPlatformOrganization(
  fetcher: ApiFetcher,
  organizationId: string,
  revision: number,
  action: 'suspend' | 'resume' | 'archive' | 'restore',
  apiBaseUrl?: string
): Promise<PlatformOrganizationMutation> {
  return requestJson<PlatformOrganizationMutation>(
    fetcher,
    serverApiUrl(apiBaseUrl, `${platformOrganizationPath(organizationId)}/status`),
    jsonRequest('POST', { action }, { 'if-match': `"${revision}"` })
  );
}

export function resendPlatformOwnerInvitation(
  fetcher: ApiFetcher,
  organizationId: string,
  revision: number,
  apiBaseUrl?: string
): Promise<unknown> {
  return requestJson(
    fetcher,
    serverApiUrl(apiBaseUrl, `${platformOrganizationPath(organizationId)}/owner-invitation/resend`),
    jsonRequest('POST', {}, { 'if-match': `"${revision}"` })
  );
}

export function replacePlatformOwnerInvitation(
  fetcher: ApiFetcher,
  organizationId: string,
  revision: number,
  ownerEmail: string,
  apiBaseUrl?: string
): Promise<unknown> {
  return requestJson(
    fetcher,
    serverApiUrl(apiBaseUrl, `${platformOrganizationPath(organizationId)}/owner-invitation/replace`),
    jsonRequest('POST', { owner_email: ownerEmail }, { 'if-match': `"${revision}"` })
  );
}

export function createPlatformTenantAccessGrantResponse(
  fetcher: ApiFetcher,
  payload: CreatePlatformTenantAccessGrant,
  apiBaseUrl?: string
): Promise<Response> {
  return fetcher(serverApiUrl(apiBaseUrl, '/api/v1/platform/tenant-access-grants'),
    jsonRequest('POST', payload)
  );
}

export function revokePlatformTenantAccessGrantResponse(
  fetcher: ApiFetcher,
  grantId: string,
  apiBaseUrl?: string
): Promise<Response> {
  return fetcher(
    serverApiUrl(
      apiBaseUrl,
      `/api/v1/platform/tenant-access-grants/${encodeURIComponent(grantId)}`
    ),
    { method: 'DELETE', headers: { accept: 'application/json' } }
  );
}
