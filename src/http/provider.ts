/**
 * iFoodOAuthProvider — implements OAuthServerProvider for @modelcontextprotocol/sdk.
 *
 * Issues audience-bound (RFC 8707) JWT access tokens signed with HS256.
 * Downstream iFood API tokens are established via the /login flow
 * (token paste from browser).
 */

import type { Response } from "express";
import { SignJWT, jwtVerify } from "jose";

import type { OAuthServerProvider, AuthorizationParams } from "@modelcontextprotocol/sdk/server/auth/provider.js";
import type { AuthInfo } from "@modelcontextprotocol/sdk/server/auth/types.js";
import type {
  OAuthClientInformationFull,
  OAuthTokens,
  OAuthTokenRevocationRequest,
} from "@modelcontextprotocol/sdk/shared/auth.js";
import { InvalidGrantError, InvalidTokenError } from "@modelcontextprotocol/sdk/server/auth/errors.js";

import {
  AuthCodeStore,
  InMemoryClientsStore,
  PendingAuthStore,
  RefreshTokenStore,
  UserTokenStore,
} from "./store.js";

export type ProviderConfig = {
  issuerUrl: URL;
  resourceUrl: URL;
  loginPath: string;
  jwtSecret: Uint8Array;
  accessTokenTtlSec?: number;
  refreshTokenTtlSec?: number;
};

export class iFoodOAuthProvider implements OAuthServerProvider {
  readonly clientsStore = new InMemoryClientsStore();
  readonly pending = new PendingAuthStore();
  readonly codes = new AuthCodeStore();
  readonly refreshTokens = new RefreshTokenStore();
  readonly userTokens = new UserTokenStore();

  constructor(private readonly cfg: ProviderConfig) {}

  /* --------------------------- authorize() --------------------------- */

  async authorize(
    client: OAuthClientInformationFull,
    params: AuthorizationParams,
    res: Response
  ): Promise<void> {
    const flow = this.pending.create({
      clientId: client.client_id,
      redirectUri: params.redirectUri,
      state: params.state,
      scopes: params.scopes ?? [],
      codeChallenge: params.codeChallenge,
      resource: params.resource?.href,
    });

    const loginUrl = new URL(this.cfg.loginPath, this.cfg.issuerUrl);
    loginUrl.searchParams.set("authFlow", flow.flowId);
    res.redirect(302, loginUrl.toString());
  }

  /* ----------------- PKCE challenge lookup for /token --------------- */

  async challengeForAuthorizationCode(
    client: OAuthClientInformationFull,
    authorizationCode: string
  ): Promise<string> {
    const ac = this.codes.peek(authorizationCode);
    if (!ac) throw new InvalidGrantError("authorization code is invalid or expired");
    if (ac.clientId !== client.client_id) throw new InvalidGrantError("client_id mismatch");
    return ac.codeChallenge;
  }

  /* --------------------- exchange code → tokens --------------------- */

  async exchangeAuthorizationCode(
    client: OAuthClientInformationFull,
    authorizationCode: string,
    _codeVerifier?: string,
    redirectUri?: string,
    resource?: URL
  ): Promise<OAuthTokens> {
    const ac = this.codes.take(authorizationCode);
    if (!ac) throw new InvalidGrantError("authorization code is invalid or expired");
    if (ac.clientId !== client.client_id) throw new InvalidGrantError("client_id mismatch");
    if (redirectUri && ac.redirectUri !== redirectUri) throw new InvalidGrantError("redirect_uri mismatch");
    if (resource && ac.resource && ac.resource !== resource.href) {
      throw new InvalidGrantError("resource mismatch");
    }

    return this.issueTokens({
      clientId: client.client_id,
      userSub: ac.userSub,
      resource: ac.resource,
      scopes: ac.scopes,
    });
  }

  /* ------------------- exchange refresh → tokens ------------------- */

  async exchangeRefreshToken(
    client: OAuthClientInformationFull,
    refreshToken: string,
    scopes?: string[],
    resource?: URL
  ): Promise<OAuthTokens> {
    const rec = this.refreshTokens.take(refreshToken);
    if (!rec) throw new InvalidGrantError("refresh token is invalid or expired");
    if (rec.clientId !== client.client_id) throw new InvalidGrantError("client_id mismatch");
    if (resource && rec.resource && rec.resource !== resource.href) {
      throw new InvalidGrantError("resource mismatch");
    }
    if (!this.userTokens.has(rec.userSub)) {
      throw new InvalidGrantError("downstream session expired; re-authenticate via the login page");
    }

    return this.issueTokens({
      clientId: client.client_id,
      userSub: rec.userSub,
      resource: rec.resource,
      scopes: scopes && scopes.length ? scopes : rec.scopes,
    });
  }

  /* ----------------------- token verification ----------------------- */

  async verifyAccessToken(token: string): Promise<AuthInfo> {
    try {
      const { payload } = await jwtVerify(token, this.cfg.jwtSecret, {
        issuer: this.cfg.issuerUrl.href,
        audience: this.cfg.resourceUrl.href,
      });
      const scopes =
        typeof payload.scope === "string" ? payload.scope.split(" ").filter(Boolean) : [];
      return {
        token,
        clientId: String(payload.client_id ?? ""),
        scopes,
        expiresAt: typeof payload.exp === "number" ? payload.exp : undefined,
        resource: new URL(this.cfg.resourceUrl.href),
        extra: { userSub: String(payload.sub ?? "") },
      };
    } catch {
      throw new InvalidTokenError("access token is invalid or expired");
    }
  }

  /* ------------------------------ revoke ---------------------------- */

  async revokeToken(
    _client: OAuthClientInformationFull,
    request: OAuthTokenRevocationRequest
  ): Promise<void> {
    if (request.token_type_hint === "refresh_token" || !request.token_type_hint) {
      this.refreshTokens.take(request.token);
    }
  }

  /* ---------------------------- internals --------------------------- */

  private async issueTokens(opts: {
    clientId: string;
    userSub: string;
    resource?: string;
    scopes: string[];
  }): Promise<OAuthTokens> {
    const accessTtl = this.cfg.accessTokenTtlSec ?? 60 * 60; // 1h
    const refreshTtl = this.cfg.refreshTokenTtlSec ?? 60 * 60 * 24 * 30; // 30d

    const now = Math.floor(Date.now() / 1000);
    const audience = opts.resource ?? this.cfg.resourceUrl.href;

    const accessToken = await new SignJWT({
      client_id: opts.clientId,
      scope: opts.scopes.join(" "),
    })
      .setProtectedHeader({ alg: "HS256", typ: "at+jwt" })
      .setIssuer(this.cfg.issuerUrl.href)
      .setAudience(audience)
      .setSubject(opts.userSub)
      .setIssuedAt(now)
      .setExpirationTime(now + accessTtl)
      .sign(this.cfg.jwtSecret);

    const refresh = this.refreshTokens.create(
      { clientId: opts.clientId, userSub: opts.userSub, resource: opts.resource, scopes: opts.scopes },
      refreshTtl
    );

    return {
      access_token: accessToken,
      token_type: "Bearer",
      expires_in: accessTtl,
      refresh_token: refresh.refreshToken,
      scope: opts.scopes.join(" ") || undefined,
    };
  }
}
