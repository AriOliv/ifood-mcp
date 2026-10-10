/**
 * In-memory stores for the OAuth 2.1 authorization server and downstream
 * iFood API session tokens. Single-process only.
 */

import { randomBytes, randomUUID } from "crypto";
import { InvalidClientMetadataError } from "@modelcontextprotocol/sdk/server/auth/errors.js";
import type { OAuthClientInformationFull } from "@modelcontextprotocol/sdk/shared/auth.js";
import type { OAuthRegisteredClientsStore } from "@modelcontextprotocol/sdk/server/auth/clients.js";

function randomId(bytes = 16): string {
  return randomBytes(bytes).toString("hex");
}

const nowSec = () => Math.floor(Date.now() / 1000);

/** Drop expired entries and enforce a hard cap (oldest first) so memory cannot grow unbounded. */
function prune<T extends { expiresAt: number }>(map: Map<string, T>, max: number): void {
  const now = nowSec();
  for (const [k, v] of map) if (v.expiresAt < now) map.delete(k);
  while (map.size >= max) {
    const oldest = map.keys().next().value;
    if (oldest === undefined) break;
    map.delete(oldest);
  }
}

const MAX_CLIENTS = 1000;
const MAX_PENDING = 5000;
const MAX_CODES = 5000;
const MAX_REFRESH = 10000;

/** Only https, loopback http, or reverse-DNS custom schemes (native apps) are acceptable redirect targets. */
export function isAcceptableRedirectUri(raw: string): boolean {
  let u: URL;
  try {
    u = new URL(raw);
  } catch {
    return false;
  }
  if (u.username || u.password || u.hash) return false;
  if (u.protocol === "https:") return true;
  if (u.protocol === "http:") return ["localhost", "127.0.0.1", "[::1]"].includes(u.hostname);
  if (["javascript:", "data:", "vbscript:", "file:", "blob:", "about:", "ftp:", "ws:", "wss:"].includes(u.protocol)) {
    return false;
  }
  return true; // custom app scheme, e.g. cursor:// or vscode://
}

/* ----------------------------- DCR clients -------------------------------- */

export class InMemoryClientsStore implements OAuthRegisteredClientsStore {
  private clients = new Map<string, OAuthClientInformationFull>();

  getClient(clientId: string): OAuthClientInformationFull | undefined {
    return this.clients.get(clientId);
  }

  async registerClient(
    client: Omit<OAuthClientInformationFull, "client_id" | "client_id_issued_at">
  ): Promise<OAuthClientInformationFull> {
    if (!client.redirect_uris?.length || client.redirect_uris.length > 10) {
      throw new InvalidClientMetadataError("between 1 and 10 redirect_uris are required");
    }
    for (const uri of client.redirect_uris) {
      if (!isAcceptableRedirectUri(String(uri))) {
        throw new InvalidClientMetadataError("redirect_uri must be https, loopback http, or a custom app scheme");
      }
    }
    if (this.clients.size >= MAX_CLIENTS) {
      const oldest = this.clients.keys().next().value;
      if (oldest !== undefined) this.clients.delete(oldest);
    }
    const full: OAuthClientInformationFull = {
      ...client,
      client_id: `ifood_${randomId(12)}`,
      client_id_issued_at: Math.floor(Date.now() / 1000),
    };
    this.clients.set(full.client_id, full);
    return full;
  }
}

/* ----------------------- Pending authorization flows ---------------------- */

export type PendingAuthFlow = {
  flowId: string;
  clientId: string;
  redirectUri: string;
  state?: string;
  scopes: string[];
  codeChallenge: string;
  resource?: string;
  createdAt: number;
  expiresAt: number;
  /** Per-flow device + session UUIDs. Generated at flow creation; bound to the eventual iFood tokens. */
  deviceId: string;
  sessionId: string;
  /** Step 2 → 3 link: opaque key returned by /authorization-codes. */
  otpKey?: string;
  /** Identifier the user submitted (email or "+55..."). For UX echo-back. */
  identifier?: string;
  /** "EMAIL" | "SMS" | "WHATSAPP" — channel chosen for OTP delivery. */
  otpChannel?: string;
  /** Resolved email — as typed (email login) or supplied via the email-challenge page (phone login). */
  resolvedEmail?: string;
  /** Opaque token from step 3, reused in steps 4 and 5. */
  otpToken?: string;
  /** Masked email returned by step 4 — shown as a hint when prompting for the real email. */
  maskedEmail?: string;
  /** One-shot error message shown on the next page render (kept server-side, never in the URL). */
  flashError?: string;
  /** Abuse counters: OTP sends and verification attempts for this flow. */
  sends?: number;
  attempts?: number;
};

export class PendingAuthStore {
  private flows = new Map<string, PendingAuthFlow>();

  create(
    partial: Omit<PendingAuthFlow, "flowId" | "createdAt" | "expiresAt" | "deviceId" | "sessionId"> &
      Partial<Pick<PendingAuthFlow, "deviceId" | "sessionId">>,
    ttlSec = 600
  ): PendingAuthFlow {
    prune(this.flows, MAX_PENDING);
    const now = nowSec();
    const flow: PendingAuthFlow = {
      ...partial,
      flowId: randomId(16),
      createdAt: now,
      expiresAt: now + ttlSec,
      deviceId: partial.deviceId ?? randomUUID(),
      sessionId: partial.sessionId ?? randomUUID(),
    };
    this.flows.set(flow.flowId, flow);
    return flow;
  }

  get(flowId: string): PendingAuthFlow | undefined {
    const f = this.flows.get(flowId);
    if (!f) return undefined;
    if (f.expiresAt < Math.floor(Date.now() / 1000)) {
      this.flows.delete(flowId);
      return undefined;
    }
    return f;
  }

  update(flowId: string, patch: Partial<PendingAuthFlow>): void {
    const f = this.flows.get(flowId);
    if (!f) return;
    this.flows.set(flowId, { ...f, ...patch });
  }

  delete(flowId: string): void {
    this.flows.delete(flowId);
  }
}

/* ---------------------- Authorization codes (short-lived) ----------------- */

export type AuthCode = {
  code: string;
  clientId: string;
  redirectUri: string;
  codeChallenge: string;
  scopes: string[];
  resource?: string;
  userSub: string;
  expiresAt: number;
};

export class AuthCodeStore {
  private codes = new Map<string, AuthCode>();

  create(partial: Omit<AuthCode, "code" | "expiresAt">, ttlSec = 60): AuthCode {
    prune(this.codes, MAX_CODES);
    const ac: AuthCode = {
      ...partial,
      code: randomId(24),
      expiresAt: Math.floor(Date.now() / 1000) + ttlSec,
    };
    this.codes.set(ac.code, ac);
    return ac;
  }

  peek(code: string): AuthCode | undefined {
    const ac = this.codes.get(code);
    if (!ac) return undefined;
    if (ac.expiresAt < Math.floor(Date.now() / 1000)) {
      this.codes.delete(code);
      return undefined;
    }
    return ac;
  }

  take(code: string): AuthCode | undefined {
    const ac = this.peek(code);
    if (!ac) return undefined;
    this.codes.delete(code);
    return ac;
  }
}

/* ------------------------- MCP refresh tokens ----------------------------- */

export type RefreshRecord = {
  refreshToken: string;
  clientId: string;
  userSub: string;
  resource?: string;
  scopes: string[];
  expiresAt: number;
};

export class RefreshTokenStore {
  private tokens = new Map<string, RefreshRecord>();

  create(
    partial: Omit<RefreshRecord, "refreshToken" | "expiresAt">,
    ttlSec = 60 * 60 * 24 * 30
  ): RefreshRecord {
    prune(this.tokens, MAX_REFRESH);
    const r: RefreshRecord = {
      ...partial,
      refreshToken: randomId(32),
      expiresAt: Math.floor(Date.now() / 1000) + ttlSec,
    };
    this.tokens.set(r.refreshToken, r);
    return r;
  }

  /** Peek without consuming (used to authorise revocation). */
  peek(token: string): RefreshRecord | undefined {
    return this.tokens.get(token);
  }

  hasForUser(userSub: string): boolean {
    const now = nowSec();
    for (const r of this.tokens.values()) if (r.userSub === userSub && r.expiresAt >= now) return true;
    return false;
  }

  take(token: string): RefreshRecord | undefined {
    const r = this.tokens.get(token);
    if (!r) return undefined;
    this.tokens.delete(token); // single-use rotation
    if (r.expiresAt < Math.floor(Date.now() / 1000)) return undefined;
    return r;
  }
}

/* ------------------- Per-user iFood API tokens (downstream) --------------- */


export type iFoodTokenPair = {
  accessToken: string;
  refreshToken: string;
  accountId: string;
  deviceId: string;
  sessionId: string;
};

export class UserTokenStore {
  private byId = new Map<string, iFoodTokenPair>();

  set(userSub: string, pair: iFoodTokenPair): void {
    this.byId.set(userSub, pair);
  }

  get(userSub: string): iFoodTokenPair | undefined {
    return this.byId.get(userSub);
  }

  has(userSub: string): boolean {
    return this.byId.has(userSub);
  }

  delete(userSub: string): void {
    this.byId.delete(userSub);
  }

  allIds(): string[] {
    return Array.from(this.byId.keys());
  }
}
