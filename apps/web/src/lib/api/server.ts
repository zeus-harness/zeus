import type { Cookies } from '@sveltejs/kit';

export type CurrentPrincipal = {
  principal_kind: 'user' | 'service_account';
  principal_id: string;
  user_id: string | null;
  organization_id: string | null;
  workspace_id: string | null;
  organization_role: string | null;
  workspace_role: string | null;
  scopes: string[];
  email: string | null;
  display_name: string;
  email_verified_at: string | null;
  platform_roles: string[];
  auth_methods: string[];
  has_native_password: boolean;
  authenticated_at: string | null;
  mfa_satisfied_at: string | null;
  idle_expires_at: string | null;
  absolute_expires_at: string | null;
  tenant_access_grant_id: string | null;
  tenant_access_expires_at: string | null;
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
  cookie: string | null,
  browserOrigin?: string
): typeof fetch {
  return (input, init = {}) => {
    const headers = new Headers(input instanceof Request ? input.headers : undefined);
    new Headers(init.headers).forEach((value, name) => headers.set(name, value));
    if (cookie) {
      headers.set('cookie', cookie);
    }
    const method = (init.method ?? (input instanceof Request ? input.method : 'GET')).toUpperCase();
    if (!['GET', 'HEAD', 'OPTIONS', 'TRACE'].includes(method)) {
      const csrfToken = readCookie(cookie, 'zeus_csrf');
      if (csrfToken && !headers.has('x-zeus-csrf')) {
        headers.set('x-zeus-csrf', csrfToken);
      }
      if (browserOrigin && !headers.has('origin')) {
        headers.set('origin', browserOrigin);
      }
    }
    return fetcher(input, { ...init, headers });
  };
}

export function forwardZeusAuthCookies(response: Response, cookies: Cookies): number {
  const forwarded = new Set<string>();

  for (const rawCookie of response.headers.getSetCookie()) {
    const segments = rawCookie.split(';').map((segment) => segment.trim());
    const pair = segments.shift();
    const separator = pair?.indexOf('=') ?? -1;
    if (!pair || separator < 1) continue;

    const name = pair.slice(0, separator);
    if (
      name !== 'zeus_session' &&
      name !== 'zeus_csrf' &&
      name !== 'zeus_tenant_access_grant'
    ) continue;

    const value = pair.slice(separator + 1);
    const attributes = new Map<string, string | true>();
    for (const segment of segments) {
      const [rawName, ...rawValue] = segment.split('=');
      attributes.set(rawName.toLowerCase(), rawValue.length > 0 ? rawValue.join('=') : true);
    }

    const rawMaxAge = attributes.get('max-age');
    const maxAge = typeof rawMaxAge === 'string' ? Number.parseInt(rawMaxAge, 10) : undefined;
    cookies.set(name, value, {
      path: '/',
      httpOnly: name !== 'zeus_csrf',
      secure: attributes.has('secure'),
      sameSite: 'lax',
      ...(Number.isSafeInteger(maxAge) ? { maxAge } : {})
    });
    forwarded.add(name);
  }

  return forwarded.size;
}

function readCookie(header: string | null, name: string): string | null {
  if (!header) return null;
  for (const part of header.split(';')) {
    const separator = part.indexOf('=');
    if (separator < 1) continue;
    if (part.slice(0, separator).trim() === name) {
      return part.slice(separator + 1).trim();
    }
  }
  return null;
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
