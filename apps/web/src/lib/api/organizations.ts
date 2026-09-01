import type { components } from './generated/schema';
import { jsonRequest, requestJson, type ApiFetcher } from './client';
import { serverApiUrl } from './server';

export type Organization = components['schemas']['OrganizationResponse'];

export function getOrganization(
  fetcher: ApiFetcher,
  organizationId: string,
  apiBaseUrl?: string
): Promise<Organization> {
  return requestJson<Organization>(
    fetcher,
    serverApiUrl(
      apiBaseUrl,
      `/api/v1/organizations/${encodeURIComponent(organizationId)}`
    )
  );
}

export function updateOrganization(
  fetcher: ApiFetcher,
  organizationId: string,
  revision: number,
  payload: { name?: string; slug?: string },
  apiBaseUrl?: string
): Promise<Organization> {
  return requestJson<Organization>(
    fetcher,
    serverApiUrl(
      apiBaseUrl,
      `/api/v1/organizations/${encodeURIComponent(organizationId)}`
    ),
    jsonRequest('PATCH', payload, { 'if-match': `"${revision}"` })
  );
}
