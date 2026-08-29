export type CurrentPrincipal = {
  principal_kind: 'user' | 'service_account';
  principal_id: string;
  user_id: string | null;
  organization_id: string;
  workspace_id: string | null;
  organization_role: string | null;
  workspace_role: string | null;
  scopes: string[];
  email: string | null;
  display_name: string;
};

export type PrincipalResult = {
  principal: CurrentPrincipal | null;
  status: 'ready' | 'unauthenticated' | 'unavailable';
};

export function serverApiUrl(apiBaseUrl: string | undefined, path: string): string {
  const base = apiBaseUrl?.trim().replace(/\/+$/, '') ?? '';
  return `${base}${path}`;
}

export function serverApiFetcher(
  fetcher: typeof fetch,
  cookie: string | null
): typeof fetch {
  return (input, init = {}) => {
    const headers = new Headers(init.headers);
    if (cookie) {
      headers.set('cookie', cookie);
    }
    return fetcher(input, { ...init, headers });
  };
}

export async function loadCurrentPrincipal(
  fetcher: typeof fetch,
  apiBaseUrl: string | undefined
): Promise<PrincipalResult> {
  try {
    const response = await fetcher(serverApiUrl(apiBaseUrl, '/api/v1/auth/me'), {
      headers: { accept: 'application/json' }
    });
    if (response.status === 401) {
      return { principal: null, status: 'unauthenticated' };
    }
    if (!response.ok) {
      return { principal: null, status: 'unavailable' };
    }
    return {
      principal: (await response.json()) as CurrentPrincipal,
      status: 'ready'
    };
  } catch {
    return { principal: null, status: 'unavailable' };
  }
}
