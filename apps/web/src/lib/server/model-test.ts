import { fail, type RequestEvent } from '@sveltejs/kit';
import { requestJson, ZeusApiError } from '$lib/api/client';
import { serverApiUrl } from '$lib/api/server';
import { requireOrganizationAction } from './organization-context';
import { studioId } from './agent-studio';

const messages: Record<string, string> = {
  ok: '已使用保存的密钥访问供应商目录，且模型可见；尚未验证生成能力。',
  authentication_failed: '供应商拒绝认证，请检查或轮换 API Key，并确认调用权限。',
  endpoint_or_model_not_found: '供应商不支持模型目录查询或地址不存在。请检查地址，必要时通过工作项验证生成能力。',
  model_not_listed: '已连接供应商，但目录中没有该模型 ID。请检查模型名称与权限。',
  timeout: '20 秒内未完成响应，请检查网络或供应商状态。',
  rate_limited: '供应商限流，请稍后重试或检查额度。',
  connection_failed: '无法连接供应商，请检查地址、网络和 TLS 配置。',
  invalid_configuration: '模型参数无效，请检查配置。',
  credential_missing: '没有可用供应商密钥，请保存密钥后重试。',
  invalid_response: '供应商目录响应不符合兼容协议；可通过工作项验证生成能力。',
  provider_rejected: '供应商拒绝测试请求，请检查模型权限和参数兼容性。'
};
export async function testModel(event: Pick<RequestEvent, 'fetch' | 'request' | 'url'> & { params: { organizationId?: string; resource?: string } }, apiBaseUrl?: string) {
  const context = await requireOrganizationAction(event, apiBaseUrl, event.params.organizationId);
  if (context.error) return context.error;
  if (event.params.resource !== 'model-profiles') return fail(400, { type: 'error' as const, message: '请从模型目录发起测试。' });
  const form = await event.request.formData();
  try {
    const id = studioId(String(form.get('resource_id') ?? ''));
    const revision = Number(form.get('revision'));
    if (!Number.isSafeInteger(revision) || revision < 1) return fail(400, { type: 'error' as const, message: '请刷新模型配置后重试。' });
    const result = await requestJson<{ success: boolean; code: string; checked_at: string }>(context.apiFetch,
      serverApiUrl(apiBaseUrl, `/api/v1/organizations/${context.organizationId}/model-profiles/${id}/test`),
      { method: 'POST', headers: { 'if-match': `"revision-${revision}"` } });
    return { type: result.success ? 'success' as const : 'error' as const, message: `${messages[result.code] ?? '测试未通过，请检查模型配置。'} 测试时间：${result.checked_at}。结果仅代表本次测试。` };
  } catch (cause) {
    const status = cause instanceof ZeusApiError ? cause.status : 502;
    return fail(status, { type: 'error' as const, message: status === 412 ? '模型配置已更新，请刷新后重新测试。' : status === 403 ? '当前会话无权测试此模型。' : '测试未完成，请检查配置或稍后重试。' });
  }
}
