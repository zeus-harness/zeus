import type { components } from './generated/schema';
import { requestJson, requestWorkspaceJson, ZeusApiError, type ApiFetcher, type WorkspaceRequestOptions } from './client';
import { serverApiUrl } from './server';

export type Agent = components['schemas']['AgentResponse'];
export type AgentVersion = components['schemas']['AgentVersionResponse'];
export type Workflow = components['schemas']['WorkflowResponse'];
export type WorkflowVersion = components['schemas']['WorkflowVersionResponse'];
export type ModelProfile = components['schemas']['ModelProfileResponse'];
export type Connection = components['schemas']['ConnectionResponse'];
export type WorkspaceCapability = components['schemas']['WorkspaceCapabilityResponse'];
export type CapabilityDefinition = components['schemas']['CapabilityDefinitionResponse'];

export function loadCapabilityCatalog(fetcher: ApiFetcher, apiBaseUrl: string | undefined, organizationId: string) {
  return requestJson<{ items: CapabilityDefinition[] }>(fetcher,
    serverApiUrl(apiBaseUrl, `/api/v1/organizations/${encodeURIComponent(organizationId)}/capability-definitions?limit=100`));
}

export async function loadAgentStudio(
  fetcher: ApiFetcher,
  options: WorkspaceRequestOptions,
  resource: 'agents' | 'workflows',
  selectedId: string | null,
  organizationId: string
) {
  const page = await requestWorkspaceJson<{ items: (Agent | Workflow)[]; next_cursor?: string | null }>(
    fetcher, options, `/${resource}`, undefined, { limit: 100 }
  );
  const selected = selectedId
    ? await requestWorkspaceJson<Agent | Workflow>(fetcher, options, `/${resource}/${encodeURIComponent(selectedId)}`)
    : null;
  let agentVersions: AgentVersion[] = [];
  let workflowVersions: WorkflowVersion[] = [];
  let agents: Agent[] = [];
  let modelProfiles: ModelProfile[] = [];
  let capabilities: WorkspaceCapability[] = [];
  let catalog: CapabilityDefinition[] = [];
  if (resource === 'agents' && selected) {
    agentVersions = await requestWorkspaceJson(fetcher, options, `/agents/${selected.id}/versions`);
  }
  if (resource === 'workflows') {
    const [agentPage, modelPage, capabilityPage] = await Promise.all([
      requestWorkspaceJson<{ items: Agent[] }>(fetcher, options, '/agents', undefined, { limit: 100 }),
      requestWorkspaceJson<{ items: ModelProfile[] }>(fetcher, options, '/model-profiles', undefined, { limit: 100 }),
      requestWorkspaceJson<{ items: WorkspaceCapability[] }>(fetcher, options, '/capabilities', undefined, { limit: 100 })
    ]);
    agents = agentPage.items.filter((agent) => !agent.archived_at && agent.active_version_id);
    modelProfiles = modelPage.items.filter((profile) => !profile.archived_at);
    capabilities = capabilityPage.items.filter((capability) => capability.enabled);
    try {
      catalog = (await loadCapabilityCatalog(fetcher, options.apiBaseUrl, organizationId)).items;
    } catch (error) {
      // Workspace builders may not have Organization catalog permission. IDs remain usable.
      if (!(error instanceof ZeusApiError) || error.status !== 403) throw error;
    }
    if (selected) workflowVersions = await requestWorkspaceJson(fetcher, options, `/workflows/${selected.id}/versions`);
  }
  return { resources: page.items, selected, agentVersions, workflowVersions, agents, modelProfiles, capabilities, catalog };
}

export type AgentStudioData = Awaited<ReturnType<typeof loadAgentStudio>>;

export async function loadModelConnections(fetcher: ApiFetcher, options: WorkspaceRequestOptions) {
  const [connections, models] = await Promise.all([
    requestWorkspaceJson<{ items: Connection[] }>(fetcher, options, '/connections', undefined, { limit: 100 }),
    requestWorkspaceJson<{ items: ModelProfile[] }>(fetcher, options, '/model-profiles', undefined, { limit: 100 })
  ]);
  return {
    connections: connections.items.filter((connection) => !connection.archived_at && connection.provider_kind === 'openai_compatible'),
    modelProfiles: models.items.filter((profile) => !profile.archived_at)
  };
}

export type ModelConnectionsData = Awaited<ReturnType<typeof loadModelConnections>>;
