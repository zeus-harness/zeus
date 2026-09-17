// Named actions replace the query string unless the return target is carried explicitly.
export function loginAction(action: 'login' | 'federated', url: URL): string {
  return `?/${action}&return_to=${encodeURIComponent(url.searchParams.get('return_to') ?? '/')}`;
}
