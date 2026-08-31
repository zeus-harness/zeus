<script lang="ts">
  import type { PageData } from './$types';

  let { data } = $props<{ data: PageData }>();
</script>

<svelte:head>
  <title>Zeus · 控制面资源</title>
</svelte:head>

<div class="page-heading">
  <div>
    <p class="section-label">Workspace administration</p>
    <h1>控制面资源</h1>
    <p class="lede">
      从这里进入 Agent、Workflow 以及运行所依赖的模型、连接、能力和触发配置。
    </p>
  </div>
  <span class={data.workspaceConfigured ? 'context-status is-ready' : 'context-status'}>
    {data.workspaceConfigured ? 'Workspace context ready' : 'Workspace context required'}
  </span>
</div>

{#if !data.workspaceConfigured}
  <section class="configuration-notice" role="status" aria-live="polite">
    <div>
      <h2>需要 Workspace 上下文</h2>
      <p>
        当前会话还没有选择 Workspace。完成登录并选择 Workspace 后，列表页才会请求业务 API。
      </p>
    </div>
    <code class="configuration-key">/api/v1/auth/me</code>
  </section>
{/if}

<section class="resource-section" aria-labelledby="resource-heading">
  <div class="section-heading">
    <div>
      <h2 id="resource-heading">资源目录</h2>
      <p>选择一个资源查看当前 Workspace 的服务端列表结果。</p>
    </div>
    <span class="resource-count">{data.resources.length} resources</span>
  </div>

  <div class="resource-list">
    {#each data.resources as resource (resource.slug)}
      <a class="resource-link" href={`/admin/${resource.slug}`}>
        <span class="resource-copy">
          <span class="resource-label">{resource.label}</span>
          <span class="resource-description">{resource.description}</span>
        </span>
        <span class="resource-api is-ready">List API declared</span>
        <span class="resource-arrow" aria-hidden="true">
          <svg viewBox="0 0 16 16" role="presentation">
            <path d="M3 8h9M8.5 4.5 12 8l-3.5 3.5"></path>
          </svg>
        </span>
      </a>
    {/each}
  </div>
</section>

<style>
  .page-heading {
    display: flex;
    align-items: flex-start;
    justify-content: space-between;
    gap: 2rem;
    padding-bottom: 2rem;
    border-bottom: 1px solid var(--border);
  }

  .section-label {
    margin: 0 0 0.75rem;
    color: var(--muted-foreground);
    font-size: 0.75rem;
    font-weight: 700;
    letter-spacing: 0.08em;
    text-transform: uppercase;
  }

  h1,
  h2,
  p {
    margin-top: 0;
  }

  h1 {
    margin-bottom: 0.75rem;
    font-size: clamp(1.75rem, 3vw, 2.25rem);
    letter-spacing: -0.035em;
    line-height: 1.1;
  }

  .lede {
    max-width: 38rem;
    margin-bottom: 0;
    color: var(--muted-foreground);
    font-size: 0.9375rem;
    line-height: 1.65;
  }

  .context-status,
  .resource-api {
    display: inline-flex;
    align-items: center;
    border: 1px solid var(--border);
    border-radius: 999px;
    padding: 0.35rem 0.65rem;
    color: var(--muted-foreground);
    font-size: 0.6875rem;
    font-weight: 650;
    letter-spacing: 0.02em;
    white-space: nowrap;
  }

  .context-status.is-ready,
  .resource-api.is-ready {
    border-color: color-mix(in oklab, var(--primary) 28%, var(--border));
    color: var(--foreground);
  }

  .configuration-notice {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 1.5rem;
    margin-top: 1.5rem;
    border: 1px solid var(--border);
    border-left: 3px solid var(--primary);
    border-radius: 0.625rem;
    padding: 1rem 1.125rem;
    background: var(--card);
  }

  .configuration-notice h2 {
    margin-bottom: 0.35rem;
    font-size: 0.875rem;
  }

  .configuration-notice p {
    max-width: 42rem;
    margin-bottom: 0;
    color: var(--muted-foreground);
    font-size: 0.8125rem;
    line-height: 1.55;
  }

  code {
    border-radius: 0.35rem;
    background: var(--muted);
    padding: 0.12rem 0.35rem;
    color: var(--foreground);
    font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
    font-size: 0.78em;
  }

  .configuration-key {
    flex: 0 0 auto;
    background: var(--muted);
    padding: 0.45rem 0.6rem;
    font-size: 0.75rem;
  }

  .resource-section {
    margin-top: 2.25rem;
  }

  .section-heading {
    display: flex;
    align-items: baseline;
    justify-content: space-between;
    gap: 1rem;
    margin-bottom: 0.75rem;
  }

  .section-heading h2 {
    margin-bottom: 0.35rem;
    font-size: 1rem;
    letter-spacing: -0.015em;
  }

  .section-heading p {
    margin-bottom: 0;
    color: var(--muted-foreground);
    font-size: 0.8125rem;
  }

  .resource-count {
    color: var(--muted-foreground);
    font-size: 0.6875rem;
    font-weight: 650;
    white-space: nowrap;
  }

  .resource-list {
    border-top: 1px solid var(--border);
  }

  .resource-link {
    display: grid;
    grid-template-columns: minmax(0, 1fr) auto auto;
    align-items: center;
    gap: 1.25rem;
    min-height: 4.75rem;
    border-bottom: 1px solid var(--border);
    color: var(--foreground);
    text-decoration: none;
    transition: padding 120ms ease, background-color 120ms ease;
  }

  .resource-link:hover {
    padding: 0 0.75rem;
    background: var(--accent);
  }

  .resource-copy {
    display: flex;
    min-width: 0;
    flex-direction: column;
    gap: 0.25rem;
  }

  .resource-label {
    font-size: 0.9375rem;
    font-weight: 650;
    letter-spacing: -0.01em;
  }

  .resource-description {
    overflow: hidden;
    color: var(--muted-foreground);
    font-size: 0.8125rem;
    line-height: 1.4;
    text-overflow: ellipsis;
    white-space: nowrap;
  }

  .resource-arrow {
    color: var(--muted-foreground);
    line-height: 1;
  }

  .resource-arrow svg {
    display: block;
    width: 1rem;
    height: 1rem;
    fill: none;
    stroke: currentColor;
    stroke-linecap: round;
    stroke-linejoin: round;
    stroke-width: 1.25;
  }

  @media (max-width: 640px) {
    .page-heading,
    .configuration-notice {
      display: block;
    }

    .context-status {
      margin-top: 1rem;
    }

    .configuration-key {
      display: inline-block;
      margin-top: 0.75rem;
    }

    .section-heading {
      align-items: flex-start;
      flex-direction: column;
      gap: 0.5rem;
    }

    .resource-link {
      grid-template-columns: minmax(0, 1fr) auto;
      gap: 0.75rem;
      padding: 0.85rem 0;
    }

    .resource-api {
      grid-column: 1;
      grid-row: 2;
      justify-self: start;
    }

    .resource-arrow {
      grid-column: 2;
      grid-row: 1 / span 2;
    }

    .resource-link:hover {
      padding: 0.85rem 0.5rem;
    }
  }
</style>
