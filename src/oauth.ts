/**
 * OAuth 2.1 authorization server that logs users in through Metabase itself.
 *
 * The MCP is served on the same origin as Metabase (for example https://metabase.example.com/mcp),
 * so the browser sends the user's `metabase.SESSION` cookie to /mcp/authorize. The server checks
 * the cookie against Metabase, asks the user to confirm, and issues its own short-lived MCP
 * tokens that map to that Metabase session. No password ever reaches the MCP.
 *
 * All state is in memory: run one replica, and users log in again after a restart.
 */

import { createHmac, randomBytes, randomUUID, timingSafeEqual } from 'node:crypto';
import type { Request, Response } from 'express';
import type {
  OAuthServerProvider,
  AuthorizationParams,
} from '@modelcontextprotocol/sdk/server/auth/provider.js';
import type { OAuthRegisteredClientsStore } from '@modelcontextprotocol/sdk/server/auth/clients.js';
import type { AuthInfo } from '@modelcontextprotocol/sdk/server/auth/types.js';
import {
  InvalidGrantError,
  InvalidTokenError,
} from '@modelcontextprotocol/sdk/server/auth/errors.js';
import type {
  OAuthClientInformationFull,
  OAuthTokens,
} from '@modelcontextprotocol/sdk/shared/auth.js';

export const METABASE_SESSION_COOKIE = 'metabase.SESSION';

const AUTH_CODE_TTL_MS = 5 * 60 * 1000;
const CONFIRM_TTL_MS = 10 * 60 * 1000;
const ACCESS_TOKEN_TTL_MS = 15 * 60 * 1000;
// How long a verified Metabase session is trusted before the next request asks Metabase again.
const SESSION_RECHECK_MS = 60 * 1000;
const REFRESH_TOKEN_TTL_MS = 14 * 24 * 60 * 60 * 1000;

interface AuthorizationCodeRecord {
  clientId: string;
  codeChallenge: string;
  redirectUri: string;
  metabaseSession: string;
  resource?: URL;
  expiresAt: number;
}

interface TokenRecord {
  clientId: string;
  metabaseSession: string;
  resource?: URL;
  expiresAt: number;
}

interface ConfirmPayload {
  clientId: string;
  redirectUri: string;
  codeChallenge: string;
  state?: string;
  resource?: string;
  scopes?: string[];
  expiresAt: number;
}

/** Returns one cookie value from a Cookie header, or undefined. */
export function readCookie(cookieHeader: string | undefined, name: string): string | undefined {
  if (!cookieHeader) {
    return undefined;
  }
  for (const part of cookieHeader.split(';')) {
    const separator = part.indexOf('=');
    if (separator > 0 && part.slice(0, separator).trim() === name) {
      return decodeURIComponent(part.slice(separator + 1).trim());
    }
  }
  return undefined;
}

function escapeHtml(text: string): string {
  return text
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

class InMemoryClientsStore implements OAuthRegisteredClientsStore {
  private clients = new Map<string, OAuthClientInformationFull>();

  getClient(clientId: string): OAuthClientInformationFull | undefined {
    return this.clients.get(clientId);
  }

  registerClient(
    client: Omit<OAuthClientInformationFull, 'client_id' | 'client_id_issued_at'>
  ): OAuthClientInformationFull {
    const registered: OAuthClientInformationFull = {
      ...client,
      client_id: randomUUID(),
      client_id_issued_at: Math.floor(Date.now() / 1000),
    };
    this.clients.set(registered.client_id, registered);
    return registered;
  }
}

export class MetabaseSessionOAuthProvider implements OAuthServerProvider {
  private readonly clients = new InMemoryClientsStore();
  private readonly authorizationCodes = new Map<string, AuthorizationCodeRecord>();
  private readonly accessTokens = new Map<string, TokenRecord>();
  private readonly refreshTokens = new Map<string, TokenRecord>();
  private readonly signingKey = randomBytes(32);
  private readonly sessionCheckedAt = new Map<string, number>();

  /** Called after a Metabase session's tokens are dropped, so callers can free per-session state. */
  onSessionRevoked: ((metabaseSession: string) => void) | null = null;

  /**
   * @param metabaseUrl internal Metabase URL used to validate sessions
   * @param publicUrl public URL of the MCP, for example https://metabase.example.com/mcp
   */
  constructor(
    private readonly metabaseUrl: string,
    private readonly publicUrl: URL
  ) {}

  get clientsStore(): OAuthRegisteredClientsStore {
    return this.clients;
  }

  /** Returns the Metabase user's email when the session is valid, otherwise undefined. */
  async getSessionUser(metabaseSession: string): Promise<string | undefined> {
    try {
      const response = await fetch(new URL('/api/user/current', this.metabaseUrl), {
        headers: { 'X-Metabase-Session': metabaseSession },
      });
      if (!response.ok) {
        return undefined;
      }
      const user = (await response.json()) as { email?: string };
      return user.email ?? 'unknown user';
    } catch {
      return undefined;
    }
  }

  /** Drops every token tied to a Metabase session, so the next MCP request gets 401. */
  revokeMetabaseSession(metabaseSession: string): void {
    this.sessionCheckedAt.delete(metabaseSession);
    this.onSessionRevoked?.(metabaseSession);
    for (const store of [this.accessTokens, this.refreshTokens]) {
      for (const [token, record] of store) {
        if (record.metabaseSession === metabaseSession) {
          store.delete(token);
        }
      }
    }
  }

  private sign(encodedPayload: string): string {
    return createHmac('sha256', this.signingKey).update(encodedPayload).digest('base64url');
  }

  private verifyConfirmToken(confirmToken: string): ConfirmPayload | undefined {
    const [encodedPayload, signature] = confirmToken.split('.');
    if (!encodedPayload || !signature) {
      return undefined;
    }
    const expected = Buffer.from(this.sign(encodedPayload));
    const actual = Buffer.from(signature);
    if (expected.length !== actual.length || !timingSafeEqual(expected, actual)) {
      return undefined;
    }
    const payload = JSON.parse(
      Buffer.from(encodedPayload, 'base64url').toString()
    ) as ConfirmPayload;
    return payload.expiresAt > Date.now() ? payload : undefined;
  }

  /**
   * Metabase's login page cannot send the browser back to a non-Metabase path: its single-page app
   * treats `?redirect=` as an in-app route and never requests it from the server. So this page opens
   * the login in a new tab and polls Metabase from the same origin until the cookie is valid.
   */
  private sendLoginPage(res: Response): void {
    res
      .status(200)
      .type('html')
      .setHeader('Cache-Control', 'no-store')
      .send(
        `<!doctype html><html><head><meta charset="utf-8"><title>Log in to Metabase</title></head>` +
          `<body style="font-family:sans-serif;max-width:32rem;margin:4rem auto">` +
          `<h1>Log in to Metabase</h1>` +
          `<p>Log in in the new tab. This page continues on its own once you are logged in.</p>` +
          `<p><a href="/auth/login" target="_blank" rel="noopener">Open the Metabase login</a></p>` +
          `<script>setInterval(async()=>{try{const r=await fetch('/api/user/current',` +
          `{credentials:'same-origin'});if(r.ok)location.reload()}catch(e){}},2000)</script>` +
          `</body></html>`
      );
  }

  /**
   * Step 1. No valid Metabase cookie: show the login page above.
   * Valid cookie: show who is asking and wait for the user to confirm. Without this page any
   * registered client could take over a logged-in user's session with a link.
   */
  async authorize(
    client: OAuthClientInformationFull,
    params: AuthorizationParams,
    res: Response
  ): Promise<void> {
    const request = res.req as Request;
    const metabaseSession = readCookie(request.headers.cookie, METABASE_SESSION_COOKIE);
    const email = metabaseSession ? await this.getSessionUser(metabaseSession) : undefined;
    if (!email) {
      this.sendLoginPage(res);
      return;
    }

    const payload: ConfirmPayload = {
      clientId: client.client_id,
      redirectUri: params.redirectUri,
      codeChallenge: params.codeChallenge,
      state: params.state,
      resource: params.resource?.href,
      scopes: params.scopes,
      expiresAt: Date.now() + CONFIRM_TTL_MS,
    };
    const encodedPayload = Buffer.from(JSON.stringify(payload)).toString('base64url');
    const confirmToken = `${encodedPayload}.${this.sign(encodedPayload)}`;
    const confirmAction = `${this.publicUrl.pathname.replace(/\/$/, '')}/authorize/confirm`;
    const redirectHost = new URL(params.redirectUri).host;

    res
      .status(200)
      .type('html')
      .setHeader('Cache-Control', 'no-store')
      .send(
        `<!doctype html><html><head><meta charset="utf-8"><title>Allow access to Metabase</title></head>` +
          `<body style="font-family:sans-serif;max-width:32rem;margin:4rem auto">` +
          `<h1>Allow access to Metabase?</h1>` +
          `<p><b>${escapeHtml(client.client_name ?? 'An MCP client')}</b> (redirects to ` +
          `<code>${escapeHtml(redirectHost)}</code>) wants to use Metabase as ` +
          `<b>${escapeHtml(email)}</b>, with your permissions.</p>` +
          `<form method="post" action="${escapeHtml(confirmAction)}">` +
          `<input type="hidden" name="confirm_token" value="${escapeHtml(confirmToken)}">` +
          `<button name="decision" value="allow">Allow</button> ` +
          `<button name="decision" value="deny">Deny</button></form></body></html>`
      );
  }

  /** Step 2. The user pressed Allow or Deny. Issues the authorization code. */
  async confirm(request: Request, res: Response): Promise<void> {
    const origin = request.headers.origin;
    if (origin && origin !== this.publicUrl.origin) {
      res.status(403).send('Cross-origin request rejected');
      return;
    }
    const payload = this.verifyConfirmToken(String(request.body?.confirm_token ?? ''));
    const metabaseSession = readCookie(request.headers.cookie, METABASE_SESSION_COOKIE);
    if (!payload || !metabaseSession || !(await this.getSessionUser(metabaseSession))) {
      res.status(400).send('This login request expired. Start the connection again.');
      return;
    }

    const target = new URL(payload.redirectUri);
    if (request.body?.decision !== 'allow') {
      target.searchParams.set('error', 'access_denied');
    } else {
      const code = randomBytes(32).toString('base64url');
      this.authorizationCodes.set(code, {
        clientId: payload.clientId,
        codeChallenge: payload.codeChallenge,
        redirectUri: payload.redirectUri,
        metabaseSession,
        resource: payload.resource ? new URL(payload.resource) : undefined,
        expiresAt: Date.now() + AUTH_CODE_TTL_MS,
      });
      target.searchParams.set('code', code);
    }
    if (payload.state) {
      target.searchParams.set('state', payload.state);
    }
    res.setHeader('Cache-Control', 'no-store');
    res.redirect(target.href);
  }

  async challengeForAuthorizationCode(
    _client: OAuthClientInformationFull,
    authorizationCode: string
  ): Promise<string> {
    const record = this.authorizationCodes.get(authorizationCode);
    if (!record || record.expiresAt < Date.now()) {
      throw new InvalidGrantError('Invalid or expired authorization code');
    }
    return record.codeChallenge;
  }

  private issueTokens(record: Omit<TokenRecord, 'expiresAt'>): OAuthTokens {
    const accessToken = randomBytes(32).toString('base64url');
    const refreshToken = randomBytes(32).toString('base64url');
    this.accessTokens.set(accessToken, { ...record, expiresAt: Date.now() + ACCESS_TOKEN_TTL_MS });
    this.refreshTokens.set(refreshToken, {
      ...record,
      expiresAt: Date.now() + REFRESH_TOKEN_TTL_MS,
    });
    return {
      access_token: accessToken,
      token_type: 'Bearer',
      expires_in: ACCESS_TOKEN_TTL_MS / 1000,
      refresh_token: refreshToken,
    };
  }

  async exchangeAuthorizationCode(
    client: OAuthClientInformationFull,
    authorizationCode: string,
    _codeVerifier?: string,
    redirectUri?: string
  ): Promise<OAuthTokens> {
    const record = this.authorizationCodes.get(authorizationCode);
    this.authorizationCodes.delete(authorizationCode); // one use only
    if (!record || record.expiresAt < Date.now() || record.clientId !== client.client_id) {
      throw new InvalidGrantError('Invalid or expired authorization code');
    }
    if (redirectUri && redirectUri !== record.redirectUri) {
      throw new InvalidGrantError('redirect_uri does not match the authorization request');
    }
    return this.issueTokens({
      clientId: record.clientId,
      metabaseSession: record.metabaseSession,
      resource: record.resource,
    });
  }

  async exchangeRefreshToken(
    client: OAuthClientInformationFull,
    refreshToken: string
  ): Promise<OAuthTokens> {
    const record = this.refreshTokens.get(refreshToken);
    this.refreshTokens.delete(refreshToken); // rotate on every use
    if (!record || record.expiresAt < Date.now() || record.clientId !== client.client_id) {
      throw new InvalidGrantError('Invalid or expired refresh token');
    }
    // Refreshing must fail once the user's Metabase session is gone, so the client logs in again.
    if (!(await this.getSessionUser(record.metabaseSession))) {
      this.revokeMetabaseSession(record.metabaseSession);
      throw new InvalidGrantError('Metabase session expired');
    }
    return this.issueTokens(record);
  }

  async verifyAccessToken(token: string): Promise<AuthInfo> {
    const record = this.accessTokens.get(token);
    if (!record || record.expiresAt < Date.now()) {
      this.accessTokens.delete(token);
      throw new InvalidTokenError('Invalid or expired access token');
    }
    // A Metabase logout or permission change must take effect within a minute, not at token expiry.
    const checkedAt = this.sessionCheckedAt.get(record.metabaseSession) ?? 0;
    if (Date.now() - checkedAt > SESSION_RECHECK_MS) {
      if (!(await this.getSessionUser(record.metabaseSession))) {
        this.revokeMetabaseSession(record.metabaseSession);
        throw new InvalidTokenError('Metabase session expired');
      }
      this.sessionCheckedAt.set(record.metabaseSession, Date.now());
    }
    return {
      token,
      clientId: record.clientId,
      scopes: [],
      expiresAt: Math.floor(record.expiresAt / 1000),
      resource: record.resource,
      extra: { metabaseSession: record.metabaseSession },
    };
  }
}
