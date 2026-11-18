import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { MetabaseSessionOAuthProvider, readCookie } from '../src/oauth.js';

const publicUrl = new URL('https://metabase.example.com/mcp');
const client: Record<string, unknown> = {
  client_id: 'client-1',
  client_name: 'Test Client',
  redirect_uris: ['http://localhost:9999/callback'],
};

function fakeResponse(cookie?: string, originalUrl = '/mcp/authorize?client_id=client-1') {
  const response: Record<string, unknown> = {
    req: { headers: { cookie }, originalUrl },
    statusCode: 0,
    headers: {} as Record<string, string>,
    body: '',
    redirectedTo: '',
  };
  response.status = (code: number) => {
    response.statusCode = code;
    return response;
  };
  response.type = () => response;
  response.setHeader = (name: string, value: string) => {
    (response.headers as Record<string, string>)[name] = value;
    return response;
  };
  response.send = (body: string) => {
    response.body = body;
    return response;
  };
  response.redirect = (location: string) => {
    response.redirectedTo = location;
    return response;
  };
  return response as {
    req: unknown;
    statusCode: number;
    body: string;
    redirectedTo: string;
    headers: Record<string, string>;
  };
}

describe('readCookie', () => {
  it('returns the named cookie', () => {
    expect(readCookie('a=1; metabase.SESSION=abc%2D1; b=2', 'metabase.SESSION')).toBe('abc-1');
  });

  it('returns undefined when the cookie is missing', () => {
    expect(readCookie(undefined, 'metabase.SESSION')).toBeUndefined();
    expect(readCookie('a=1', 'metabase.SESSION')).toBeUndefined();
  });
});

describe('MetabaseSessionOAuthProvider', () => {
  let provider: MetabaseSessionOAuthProvider;
  let validSessions: Set<string>;

  beforeEach(() => {
    validSessions = new Set(['good-session']);
    vi.stubGlobal(
      'fetch',
      vi.fn(async (_url: URL, init: { headers: Record<string, string> }) => {
        const session = init.headers['X-Metabase-Session'];
        return validSessions.has(session)
          ? { ok: true, json: async () => ({ email: 'user@example.com' }) }
          : { ok: false, json: async () => ({}) };
      })
    );
    provider = new MetabaseSessionOAuthProvider('http://metabase.internal', publicUrl);
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  const params = {
    codeChallenge: 'challenge',
    redirectUri: 'http://localhost:9999/callback',
    state: 'state-1',
  };

  async function confirmedCode(session = 'good-session'): Promise<string> {
    const page = fakeResponse(`metabase.SESSION=${session}`);
    await provider.authorize(client as never, params, page as never);
    const confirmToken = /name="confirm_token" value="([^"]+)"/.exec(page.body)![1];
    const result = fakeResponse(`metabase.SESSION=${session}`);
    await provider.confirm(
      {
        headers: { cookie: `metabase.SESSION=${session}`, origin: publicUrl.origin },
        body: { confirm_token: confirmToken, decision: 'allow' },
      } as never,
      result as never
    );
    return new URL(result.redirectedTo).searchParams.get('code')!;
  }

  it('shows a login page that polls Metabase when there is no session', async () => {
    const response = fakeResponse(undefined);
    await provider.authorize(client as never, params, response as never);
    expect(response.statusCode).toBe(200);
    expect(response.body).toContain('href="/auth/login"');
    expect(response.body).toContain("fetch('/api/user/current'");
    expect(response.redirectedTo).toBe('');
  });

  it('shows the login page for an expired Metabase session', async () => {
    const response = fakeResponse('metabase.SESSION=expired');
    await provider.authorize(client as never, params, response as never);
    expect(response.body).toContain('Log in to Metabase');
    expect(response.body).not.toContain('confirm_token');
  });

  it('shows a confirmation page for a valid session and escapes client input', async () => {
    const evilClient = { ...client, client_name: '<script>x</script>' } as never;
    const response = fakeResponse('metabase.SESSION=good-session');
    await provider.authorize(evilClient, params, response as never);
    expect(response.statusCode).toBe(200);
    expect(response.body).toContain('user@example.com');
    expect(response.body).toContain('&lt;script&gt;');
    expect(response.body).not.toContain('<script>');
    expect(response.body).toContain('action="/mcp/authorize/confirm"');
  });

  it('issues tokens that map to the Metabase session after the user allows', async () => {
    const code = await confirmedCode();
    expect(await provider.challengeForAuthorizationCode(client as never, code)).toBe('challenge');
    const tokens = await provider.exchangeAuthorizationCode(client as never, code);
    const info = await provider.verifyAccessToken(tokens.access_token);
    expect(info.extra).toEqual({ metabaseSession: 'good-session' });
    expect(tokens.token_type).toBe('Bearer');
  });

  it('accepts an authorization code only once', async () => {
    const code = await confirmedCode();
    await provider.exchangeAuthorizationCode(client as never, code);
    await expect(provider.exchangeAuthorizationCode(client as never, code)).rejects.toThrow();
  });

  it('rejects a code redeemed by another client', async () => {
    const code = await confirmedCode();
    const other = { ...client, client_id: 'client-2' } as never;
    await expect(provider.exchangeAuthorizationCode(other, code)).rejects.toThrow();
  });

  it('returns access_denied when the user denies', async () => {
    const page = fakeResponse('metabase.SESSION=good-session');
    await provider.authorize(client as never, params, page as never);
    const confirmToken = /name="confirm_token" value="([^"]+)"/.exec(page.body)![1];
    const result = fakeResponse();
    await provider.confirm(
      {
        headers: { cookie: 'metabase.SESSION=good-session', origin: publicUrl.origin },
        body: { confirm_token: confirmToken, decision: 'deny' },
      } as never,
      result as never
    );
    const target = new URL(result.redirectedTo);
    expect(target.searchParams.get('error')).toBe('access_denied');
    expect(target.searchParams.get('code')).toBeNull();
  });

  it('rejects a forged confirmation token', async () => {
    const result = fakeResponse();
    await provider.confirm(
      {
        headers: { cookie: 'metabase.SESSION=good-session', origin: publicUrl.origin },
        body: { confirm_token: 'e30.forged', decision: 'allow' },
      } as never,
      result as never
    );
    expect(result.statusCode).toBe(400);
    expect(result.redirectedTo).toBe('');
  });

  it('rejects a confirmation from another origin', async () => {
    const result = fakeResponse();
    await provider.confirm(
      {
        headers: { cookie: 'metabase.SESSION=good-session', origin: 'https://evil.example' },
        body: { confirm_token: 'x', decision: 'allow' },
      } as never,
      result as never
    );
    expect(result.statusCode).toBe(403);
  });

  it('refreshes tokens while the Metabase session is valid and rotates the refresh token', async () => {
    const tokens = await provider.exchangeAuthorizationCode(client as never, await confirmedCode());
    const refreshed = await provider.exchangeRefreshToken(client as never, tokens.refresh_token!);
    expect(refreshed.access_token).not.toBe(tokens.access_token);
    await expect(
      provider.exchangeRefreshToken(client as never, tokens.refresh_token!)
    ).rejects.toThrow();
  });

  it('refuses to refresh once the Metabase session expired and revokes its tokens', async () => {
    const tokens = await provider.exchangeAuthorizationCode(client as never, await confirmedCode());
    validSessions.delete('good-session');
    await expect(
      provider.exchangeRefreshToken(client as never, tokens.refresh_token!)
    ).rejects.toThrow('Metabase session expired');
    await expect(provider.verifyAccessToken(tokens.access_token)).rejects.toThrow();
  });

  it('rejects an access token once its Metabase session is gone and frees session state', async () => {
    const revoked = vi.fn();
    provider.onSessionRevoked = revoked;
    const tokens = await provider.exchangeAuthorizationCode(client as never, await confirmedCode());
    vi.useFakeTimers();
    vi.setSystemTime(Date.now() + 2 * 60 * 1000);
    validSessions.delete('good-session');
    await expect(provider.verifyAccessToken(tokens.access_token)).rejects.toThrow(
      'Metabase session expired'
    );
    vi.useRealTimers();
    expect(revoked).toHaveBeenCalledWith('good-session');
  });

  it('revokes every token of a Metabase session', async () => {
    const tokens = await provider.exchangeAuthorizationCode(client as never, await confirmedCode());
    provider.revokeMetabaseSession('good-session');
    await expect(provider.verifyAccessToken(tokens.access_token)).rejects.toThrow();
  });

  it('registers clients with generated ids', () => {
    const registered = provider.clientsStore.registerClient!({
      redirect_uris: ['http://localhost:1/cb'],
    } as never) as { client_id: string };
    expect(provider.clientsStore.getClient(registered.client_id)).toBeTruthy();
  });
});
