import { describe, it, expect, vi, afterEach } from 'vitest';
import { MetabaseApiClient } from '../src/api.js';

describe('MetabaseApiClient with an existing Metabase session', () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it('sends the session token and never logs in', async () => {
    const fetchMock = vi.fn(async () => ({ ok: true, json: async () => ({ id: 1 }) }));
    vi.stubGlobal('fetch', fetchMock);
    const client = new MetabaseApiClient(undefined, { sessionToken: 'abc', onExpired: vi.fn() });
    expect(await client.getSessionToken()).toBe('abc');
    await client.request('/api/user/current');
    const [url, init] = fetchMock.mock.calls[0] as unknown as [
      string,
      { headers: Record<string, string> },
    ];
    expect(String(url)).toContain('/api/user/current');
    expect(init.headers['X-Metabase-Session']).toBe('abc');
    expect(init.headers['X-API-KEY']).toBeUndefined();
  });

  it('calls onExpired and fails without retrying when Metabase returns 401', async () => {
    const fetchMock = vi.fn(async () => ({ ok: false, status: 401, json: async () => ({}) }));
    vi.stubGlobal('fetch', fetchMock);
    const onExpired = vi.fn();
    const client = new MetabaseApiClient(undefined, { sessionToken: 'abc', onExpired });
    await expect(client.request('/api/user/current')).rejects.toThrow('Metabase session expired');
    expect(onExpired).toHaveBeenCalledOnce();
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });
});
