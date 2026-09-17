export type ManagementResourceSlug =
  | 'agents'
  | 'workflows'
  | 'members'
  | 'workspaces'
  | 'model-profiles'
  | 'connections'
  | 'capabilities'
  | 'schedules'
  | 'webhooks'
  | 'service-accounts';

export type ManagementColumn = {
  label: string;
  key: string;
};

export type ManagementResource = {
  slug: ManagementResourceSlug;
  label: string;
  description: string;
  endpoint: string;
  columns: readonly ManagementColumn[];
};

export const managementResources: readonly ManagementResource[] = [
  {
    slug: 'agents',
    label: '智能体',
    description: '管理可部署的 Harness Agent。',
    endpoint: 'agents',
    columns: [
      { label: '名称', key: 'name' },
      { label: '活动版本', key: 'active_version_id' },
      { label: '修订版本', key: 'revision' },
      { label: '更新时间', key: 'updated_at' }
    ]
  },
  {
    slug: 'workflows',
    label: '流程',
    description: '查看 Workspace 中的版本化工作流。',
    endpoint: 'workflows',
    columns: [
      { label: '名称', key: 'name' },
      { label: '活动版本', key: 'active_version_id' },
      { label: '修订版本', key: 'revision' },
      { label: '更新时间', key: 'updated_at' }
    ]
  },
  {
    slug: 'model-profiles',
    label: '模型目录',
    description: '查看模型提供方与调用策略。',
    endpoint: 'model-profiles',
    columns: [
      { label: '名称', key: 'name' },
      { label: 'Provider', key: 'provider_kind' },
      { label: '模型', key: 'model' },
      { label: '更新时间', key: 'updated_at' }
    ]
  },
  {
    slug: 'connections',
    label: '连接',
    description: '管理外部服务连接及其生命周期。',
    endpoint: 'connections',
    columns: [
      { label: '名称', key: 'name' },
      { label: 'Provider', key: 'provider_kind' },
      { label: '归档时间', key: 'archived_at' },
      { label: '更新时间', key: 'updated_at' }
    ]
  },
  {
    slug: 'capabilities',
    label: '工具权限',
    description: '查看能力目录与审批边界。',
    endpoint: 'capabilities',
    columns: [
      { label: 'Capability', key: 'capability_id' },
      { label: '启用', key: 'enabled' },
      { label: '需要审批', key: 'approval_required' },
      { label: '更新时间', key: 'updated_at' }
    ]
  },
  {
    slug: 'schedules',
    label: '定时任务',
    description: '安排周期性工作流运行。',
    endpoint: 'schedules',
    columns: [
      { label: '名称', key: 'name' },
      { label: 'Cron', key: 'cron_expression' },
      { label: '启用', key: 'enabled' },
      { label: '下次运行', key: 'next_run_at' }
    ]
  },
  {
    slug: 'webhooks',
    label: 'Webhook 触发器',
    description: '接入外部事件触发器。',
    endpoint: 'webhook-endpoints',
    columns: [
      { label: 'Public Key', key: 'public_key' },
      { label: 'Workflow', key: 'workflow_id' },
      { label: '启用', key: 'enabled' },
      { label: '更新时间', key: 'updated_at' }
    ]
  }
];

export function getManagementResource(slug: string): ManagementResource | undefined {
  return managementResources.find((resource) => resource.slug === slug);
}

export const agentStudioResources = managementResources.filter((resource) =>
  ['agents', 'workflows', 'schedules', 'webhooks'].includes(resource.slug)
);

export const workspaceSettingResources: readonly ManagementResource[] = [
  {
    slug: 'members',
    label: '成员',
    description: '管理 Workspace 成员和角色。',
    endpoint: 'members',
    columns: [
      { label: '成员', key: 'display_name' },
      { label: '邮箱', key: 'email' },
      { label: '角色', key: 'role' },
      { label: '状态', key: 'status' }
    ]
  },
  ...managementResources.filter((resource) =>
    ['capabilities'].includes(resource.slug)
  ),
  {
    slug: 'service-accounts',
    label: '服务账号',
    description: '管理仅属于此 Workspace 的机器身份。',
    endpoint: 'service-accounts',
    columns: [
      { label: '名称', key: 'name' },
      { label: 'Token Prefix', key: 'token_prefix' },
      { label: 'Scopes', key: 'scopes' },
      { label: '最后使用', key: 'last_used_at' }
    ]
  }
];

export function getWorkspaceSettingResource(slug: string): ManagementResource | undefined {
  return workspaceSettingResources.find((resource) => resource.slug === slug);
}

export const organizationSettingResources: readonly ManagementResource[] = [
  { ...managementResources.find((resource) => resource.slug === 'connections')!, label: '模型供应商', endpoint: 'model-providers', description: '组织统一管理供应商及密钥，一个供应商可配置多个模型。' },
  { ...managementResources.find((resource) => resource.slug === 'model-profiles')!, label: '模型目录', description: '组织内所有 Workspace 共用的模型。' },
  {
    slug: 'members',
    label: '成员',
    description: '管理 Organization Owner、成员和 Auditor。',
    endpoint: 'members',
    columns: [
      { label: '成员', key: 'display_name' },
      { label: '邮箱', key: 'email' },
      { label: '角色', key: 'role' },
      { label: '状态', key: 'status' }
    ]
  },
  {
    slug: 'workspaces',
    label: '工作空间',
    description: '查看 Organization 下的 Workspace 生命周期。',
    endpoint: 'workspaces',
    columns: [
      { label: '名称', key: 'name' },
      { label: 'Slug', key: 'slug' },
      { label: '状态', key: 'status' },
      { label: '修订版本', key: 'revision' }
    ]
  },
  {
    slug: 'capabilities',
    label: '能力目录',
    description: '管理 Organization 可分配的企业 Capability 定义。',
    endpoint: 'capability-definitions',
    columns: [
      { label: '名称', key: 'display_name' },
      { label: 'Registry Key', key: 'registry_key' },
      { label: '风险', key: 'risk_level' },
      { label: '幂等模式', key: 'idempotency_mode' }
    ]
  }
];
