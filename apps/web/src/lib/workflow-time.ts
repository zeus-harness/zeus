export function workflowTimeSummary(policy: unknown, runtimeSeconds: number): string {
  if (!policy || typeof policy !== 'object' || !('runtime_clock' in policy) || policy.runtime_clock !== 'active') {
    return `总运行时限 ${runtimeSeconds} 秒（旧版，包含等待）`;
  }
  const wait = 'wait_timeout_seconds' in policy ? policy.wait_timeout_seconds : undefined;
  const total = 'business_timeout_seconds' in policy ? policy.business_timeout_seconds : undefined;
  return `执行预算 ${runtimeSeconds} 秒 · 单次等待 ${duration(wait)} · 总期限 ${duration(total)}`;
}

function duration(seconds: unknown): string {
  if (typeof seconds !== 'number' || !Number.isSafeInteger(seconds) || seconds <= 0) return '未配置';
  return seconds % 86400 === 0 ? `${seconds / 86400} 天` : `${seconds} 秒`;
}
