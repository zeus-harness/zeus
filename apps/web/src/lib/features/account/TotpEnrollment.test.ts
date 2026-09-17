import { describe, expect, it } from 'vitest';
import { render } from 'svelte/server';
import TotpEnrollment from './TotpEnrollment.svelte';

describe('TOTP enrollment presentation', () => {
  it('hides the secret by default and exposes explicit display and copy controls', () => {
    const { body } = render(TotpEnrollment, { props: { secret: 'TEST_TOTP_SECRET', qrDataUrl: 'data:image/png;base64,TEST_ONLY' } });
    expect(body).not.toContain('TEST_TOTP_SECRET');
    expect(body).not.toContain('otpauth:');
    expect(body).toContain('显示密钥');
    expect(body).toContain('复制密钥');
    expect(body).toContain('aria-pressed="false"');
    expect(body).toContain('data:image/png;base64,TEST_ONLY');
  });

  it('keeps manual setup available if QR generation fails without revealing the secret', () => {
    const { body } = render(TotpEnrollment, { props: { secret: 'TEST_TOTP_SECRET', qrDataUrl: null } });
    expect(body).toContain('二维码暂不可用');
    expect(body).not.toContain('TEST_TOTP_SECRET');
  });
});
