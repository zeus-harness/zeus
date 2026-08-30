<script lang="ts">
  import { page } from '$app/state';

  import { managementResources } from '$lib/control-plane';

  let { children } = $props();
  let pathname = $derived(page.url.pathname);
  const identityNavigation = [
    { href: '/admin/identity-providers', label: 'Identity Providers', hint: '身份提供商' },
    { href: '/admin/domains', label: 'Domains', hint: '已验证域名' },
    { href: '/admin/security', label: 'Security', hint: '身份策略' },
    { href: '/admin/oidc-clients', label: 'OIDC Clients', hint: '应用接入' }
  ] as const;

  function navigationClass(active: boolean) {
    return active ? 'navigation-link is-active' : 'navigation-link';
  }
</script>

<svelte:head>
  <title>Zeus · Control plane</title>
  <meta name="description" content="Zeus workspace control plane" />
</svelte:head>

<div class="admin-shell">
  <header class="admin-header">
    <div class="header-inner">
      <a class="brand" href="/" aria-label="返回 Zeus 运行概览">
        <span class="brand-mark" aria-hidden="true">Z</span>
        <span>Zeus</span>
      </a>
      <span class="header-divider" aria-hidden="true"></span>
      <span class="header-section">Control plane</span>
      <a class="back-link" href="/">返回运行概览</a>
    </div>
  </header>

  <div class="admin-body">
    <aside class="sidebar">
      <div class="sidebar-heading">Workspace</div>
      <nav class="navigation" aria-label="控制面导航">
        <a
          class={navigationClass(pathname === '/admin')}
          href="/admin"
          aria-current={pathname === '/admin' ? 'page' : undefined}
        >
          <span>Overview</span>
          <span class="navigation-hint">总览</span>
        </a>

        {#each managementResources as resource (resource.slug)}
          <a
            class={navigationClass(pathname === `/admin/${resource.slug}`)}
            href={`/admin/${resource.slug}`}
            aria-current={pathname === `/admin/${resource.slug}` ? 'page' : undefined}
          >
            <span>{resource.label}</span>
          </a>
        {/each}

        <div class="navigation-divider" aria-hidden="true"></div>
        <div class="sidebar-heading nested-heading">Organization</div>
        {#each identityNavigation as item (item.href)}
          <a
            class={navigationClass(pathname === item.href)}
            href={item.href}
            aria-current={pathname === item.href ? 'page' : undefined}
          >
            <span>{item.label}</span>
            <span class="navigation-hint">{item.hint}</span>
          </a>
        {/each}
      </nav>

      <div class="sidebar-note">
        <span class="sidebar-note-label">Data scope</span>
        <p>列表按当前 Workspace 加载，服务端不会填充演示业务数据。</p>
      </div>
    </aside>

    <main class="admin-content">{@render children()}</main>
  </div>
</div>

<style>
  .admin-shell {
    min-height: 100vh;
    background: var(--background);
    color: var(--foreground);
  }

  .admin-header {
    border-bottom: 1px solid var(--border);
    background: color-mix(in oklab, var(--card) 88%, transparent);
  }

  .header-inner {
    display: flex;
    min-height: 4rem;
    align-items: center;
    gap: 1rem;
    max-width: 1480px;
    margin: 0 auto;
    padding: 0 2rem;
  }

  .brand {
    display: inline-flex;
    align-items: center;
    gap: 0.7rem;
    color: var(--foreground);
    font-size: 1rem;
    font-weight: 650;
    letter-spacing: -0.02em;
    text-decoration: none;
  }

  .brand-mark {
    display: grid;
    width: 2.25rem;
    height: 2.25rem;
    place-items: center;
    border-radius: 0.75rem;
    background: var(--primary);
    color: var(--primary-foreground);
    font-size: 1rem;
    font-weight: 700;
  }

  .header-divider {
    width: 1px;
    height: 1.5rem;
    background: var(--border);
  }

  .header-section {
    color: var(--muted-foreground);
    font-size: 0.875rem;
    font-weight: 550;
  }

  .back-link {
    margin-left: auto;
    color: var(--muted-foreground);
    font-size: 0.8125rem;
    text-decoration: none;
  }

  .back-link:hover {
    color: var(--foreground);
  }

  .admin-body {
    display: grid;
    grid-template-columns: 14rem minmax(0, 1fr);
    max-width: 1480px;
    min-height: calc(100vh - 4rem);
    margin: 0 auto;
  }

  .sidebar {
    display: flex;
    flex-direction: column;
    gap: 0.75rem;
    border-right: 1px solid var(--border);
    padding: 1.5rem 1rem;
  }

  .sidebar-heading {
    padding: 0 0.75rem;
    color: var(--muted-foreground);
    font-size: 0.6875rem;
    font-weight: 700;
    letter-spacing: 0.1em;
    text-transform: uppercase;
  }

  .navigation {
    display: flex;
    flex-direction: column;
    gap: 0.25rem;
  }

  .navigation-link {
    display: flex;
    min-height: 2.25rem;
    align-items: center;
    justify-content: space-between;
    gap: 0.75rem;
    border-radius: 0.625rem;
    padding: 0.5rem 0.75rem;
    color: var(--muted-foreground);
    font-size: 0.8125rem;
    font-weight: 550;
    text-decoration: none;
    transition:
      background-color 120ms ease,
      color 120ms ease;
  }

  .navigation-link:hover {
    background: var(--accent);
    color: var(--accent-foreground);
  }

  .navigation-link.is-active {
    background: var(--accent);
    color: var(--accent-foreground);
  }

  .navigation-divider {
    height: 1px;
    margin: 0.65rem 0.75rem 0.35rem;
    background: var(--border);
  }

  .nested-heading {
    padding-top: 0.25rem;
  }

  .navigation-hint {
    color: var(--muted-foreground);
    font-size: 0.6875rem;
    font-weight: 500;
  }

  .sidebar-note {
    margin-top: auto;
    border-top: 1px solid var(--border);
    padding: 1rem 0.75rem 0;
  }

  .sidebar-note-label {
    color: var(--muted-foreground);
    font-size: 0.6875rem;
    font-weight: 700;
    letter-spacing: 0.08em;
    text-transform: uppercase;
  }

  .sidebar-note p {
    margin: 0.5rem 0 0;
    color: var(--muted-foreground);
    font-size: 0.75rem;
    line-height: 1.55;
  }

  .admin-content {
    min-width: 0;
    padding: 2.25rem clamp(1.25rem, 4vw, 4rem);
  }

  @media (max-width: 800px) {
    .header-inner {
      padding: 0 1.25rem;
    }

    .header-divider,
    .header-section {
      display: none;
    }

    .admin-body {
      display: block;
    }

    .sidebar {
      gap: 0.5rem;
      border-right: 0;
      border-bottom: 1px solid var(--border);
      padding: 0.75rem 1.25rem;
    }

    .sidebar-heading,
    .sidebar-note {
      display: none;
    }

    .navigation {
      flex-direction: row;
      gap: 0.25rem;
      overflow-x: auto;
      padding-bottom: 0.125rem;
    }

    .navigation-link {
      flex: 0 0 auto;
      min-height: 2rem;
      white-space: nowrap;
    }

    .navigation-hint {
      display: none;
    }

    .admin-content {
      padding: 1.5rem 1.25rem 2.5rem;
    }
  }
</style>
