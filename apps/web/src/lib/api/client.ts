import type { paths } from './schema';

export type ApiMeta =
  paths['/api/v1/meta']['get']['responses'][200]['content']['application/json'];

export class ZeusApiClient {
  constructor(
    private readonly baseUrl = '',
    private readonly fetcher: typeof fetch = fetch
  ) {}

  async meta(signal?: AbortSignal): Promise<ApiMeta> {
    const response = await this.fetcher(`${this.baseUrl}/api/v1/meta`, {
      headers: { accept: 'application/json' },
      signal
    });
    if (!response.ok) {
      throw new Error(`Zeus API returned ${response.status}`);
    }
    return response.json() as Promise<ApiMeta>;
  }
}
