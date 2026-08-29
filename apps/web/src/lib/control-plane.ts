export type ManagementResourceSlug =
  | 'agents'
  | 'workflows'
  | 'model-profiles'
  | 'connections'
  | 'capabilities'
  | 'schedules'
  | 'webhooks';

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
    label: 'Agents',
    description: '管理可部署的 Harness Agent。',
    endpoint: 'agents',
    columns: [
      { label: '名称', key: 'name' },
      { label: '活动版本', key: 'active_version_id' },
      { label: 'Revision', key: 'revision' },
      { label: '更新时间', key: 'updated_at' }
    ]
  },
  {
    slug: 'workflows',
    label: 'Workflows',
    description: '查看 Workspace 中的版本化工作流。',
    endpoint: 'workflows',
    columns: [
      { label: '名称', key: 'name' },
      { label: '活动版本', key: 'active_version_id' },
      { label: 'Revision', key: 'revision' },
      { label: '更新时间', key: 'updated_at' }
    ]
  },
  {
    slug: 'model-profiles',
    label: 'Model Profiles',
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
    label: 'Connections',
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
    label: 'Capabilities',
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
    label: 'Schedules',
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
    label: 'Webhooks',
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
