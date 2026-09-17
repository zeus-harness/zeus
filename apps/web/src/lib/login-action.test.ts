import { describe, expect, it } from 'vitest';
import { loginAction } from './login-action';

describe('login form return context', () => {
  it.each(['login', 'federated'] as const)('preserves filtered task destinations through the %s named action', (action) => {
    const target = '/019f0000-0000-7000-8000-000000000001/work-items?view=created&q=客户';
    const page = new URL('http://web.test/login');
    page.searchParams.set('return_to', target);
    const submitted = new URL(loginAction(action, page), page);
    expect(submitted.searchParams.has(`/${action}`)).toBe(true);
    expect(submitted.searchParams.get('return_to')).toBe(target);
  });
});
