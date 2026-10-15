/** Accept legacy time-crate tuples while old API deployments are still running. */
export function displayTimestamp(value: unknown): string {
  let date: Date;
  if (Array.isArray(value) && value.length === 9 && value.every(Number.isFinite)) {
    const [year, ordinal, hour, minute, second, nanos, oh, om, os] = value as number[];
    date = new Date(Date.UTC(year, 0, ordinal, hour - oh, minute - om, second - os, Math.floor(nanos / 1e6)));
  } else if (typeof value === 'string') date = new Date(value);
  else return '—';
  return Number.isNaN(date.getTime()) ? '—' : new Intl.DateTimeFormat('zh-CN', {
    timeZone: 'Asia/Shanghai', year: 'numeric', month: '2-digit', day: '2-digit',
    hour: '2-digit', minute: '2-digit', hour12: false
  }).format(date) + ' UTC+8';
}
