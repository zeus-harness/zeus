import { describe, expect, it } from 'vitest';
import type { RequestEvent } from '@sveltejs/kit';
import { manageInvitation } from './organization-invitations';
const org = '019f0000-0000-7000-8000-000000000001';
const invitation = '019f0000-0000-7000-8000-000000000002';
function event(values: Record<string, string>, handler: (request: Request) => Response | Promise<Response>, principal: Record<string, unknown> = {}) {
  const url = new URL(`http://web.test/organizations/${org}/settings/members`);
  return { params: { organizationId: org, resource: 'members' }, url,
    request: new Request(url, { method: 'POST', headers: { cookie: 'zeus_csrf=test-csrf' }, body: new URLSearchParams(values) }),
    fetch: (async (input: RequestInfo | URL, init?: RequestInit) => {
      const request = new Request(input, init);
      if (request.url.endsWith('/auth/me')) return Response.json({ organization_id: org, organization_role: 'owner', ...principal });
      return handler(request);
    }) as typeof fetch } as RequestEvent;
}
describe('organization invitations', () => {
  it('defaults to member without workspace grants and forwards CSRF', async () => {
    const result = await manageInvitation(event({ operation: 'create', email: ' colleague@example.test ' }, async request => {
      expect(request.url).toBe(`http://api.test/api/v1/organizations/${org}/invitations`);
      expect(await request.json()).toEqual({ email: 'colleague@example.test', organization_role: 'member', workspaces: [] });
      expect(request.headers.get('x-zeus-csrf')).toBe('test-csrf');
      expect(request.headers.get('origin')).toBe('http://web.test');
      return Response.json({}, { status: 201 });
    }), 'http://api.test');
    expect(result).toMatchObject({ type: 'success' });
  });
  it.each([{ organization_role: 'member' }, { organization_id: 'another-org' }, { tenant_access_grant_id: 'support' }])('rejects unauthorized actor before writing', async principal => {
    expect(await manageInvitation(event({ operation: 'create', email: 'a@example.test' }, () => { throw new Error('must not write'); }, principal), 'http://api.test')).toMatchObject({ status: 403 });
  });
  it.each([{ email: 'bad', organization_role: 'member' }, { email: 'a@example.test', organization_role: 'platform_owner' }])('rejects invalid input before writing', async fields => {
    expect(await manageInvitation(event({ operation: 'create', ...fields }, () => { throw new Error('must not write'); }), 'http://api.test')).toMatchObject({ status: 400 });
  });
  it.each(['resend', 'revoke'])('uses the scoped endpoint for %s', async operation => {
    const result = await manageInvitation(event({ operation, invitation_id: invitation }, request => {
      expect(request.url).toBe(`http://api.test/api/v1/organizations/${org}/invitations/${invitation}${operation === 'resend' ? '/resend' : ''}`);
      expect(request.method).toBe(operation === 'resend' ? 'POST' : 'DELETE');
      return new Response(null, { status: operation === 'resend' ? 202 : 204 });
    }), 'http://api.test');
    expect(result).toMatchObject({ type: 'success' });
  });
  it('returns a recoverable state-change error without leaking API detail', async () => {
    const result = await manageInvitation(event({ operation: 'revoke', invitation_id: invitation }, () => Response.json({ detail: 'internal-details' }, { status: 404 })), 'http://api.test');
    expect(result).toMatchObject({ status: 404, data: { type: 'error', message: '邀请已处理或不存在，请刷新页面。' } });
  });
});
