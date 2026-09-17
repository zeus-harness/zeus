<script lang="ts">
  import { Button } from '@zeus/ui/components/ui/button';
  let { secret, qrDataUrl }: { secret: string; qrDataUrl: string | null } = $props();
  let visible = $state(false);
  let copyStatus = $state('');

  async function copySecret() {
    try {
      await navigator.clipboard.writeText(secret);
      copyStatus = '密钥已复制';
    } catch {
      copyStatus = '无法访问剪贴板，请显示密钥后手动复制。';
    }
  }
</script>

<div class="space-y-4">
  <p class="text-sm leading-6 text-muted-foreground">使用身份验证器扫描二维码。也可以复制或显示密钥后手动添加。</p>
  {#if qrDataUrl}
    <img src={qrDataUrl} alt="用于绑定 Zeus 身份验证器的二维码" width="256" height="256" class="max-w-full rounded-lg border border-border bg-white" />
  {:else}
    <p class="text-sm text-muted-foreground" role="status">二维码暂不可用，请使用下方密钥手动添加。</p>
  {/if}
  <div class="space-y-3">
    <p class="text-sm font-medium">Secret（手动设置密钥）</p>
    <code id="totp-secret" class="block break-all rounded-lg border border-border bg-muted/40 p-3 font-mono text-sm">{visible ? secret : '••••••••••••••••••••••••••••••••'}</code>
    <div class="flex flex-wrap gap-3">
      <Button type="button" variant="outline" aria-controls="totp-secret" aria-pressed={visible} onclick={() => { visible = !visible; }}>{visible ? '隐藏密钥' : '显示密钥'}</Button>
      <Button type="button" variant="outline" onclick={copySecret}>复制密钥</Button>
    </div>
    <p class="text-xs text-muted-foreground" role="status" aria-live="polite">{copyStatus}</p>
  </div>
</div>
