/**
 * SessionTokenProvider — a TokenProvider backed by the per-user UserTokenStore.
 * When a tool calls the iFood API and the access token is stale, we
 * transparently refresh using the stored refresh token and write the new pair
 * back to the store.
 */

import axios from "axios";

import type { TokenProvider } from "../index.js";
import { MAIN_URL } from "../index.js";
import type { UserTokenStore } from "./store.js";

function jwtExp(token: string): number {
  try {
    const p = token.split(".")[1];
    const decoded = JSON.parse(Buffer.from(p, "base64url").toString());
    return decoded.exp ?? 0;
  } catch {
    return 0;
  }
}

function expired(token: string, marginSec = 30): boolean {
  if (!token) return true;
  return Date.now() / 1000 >= jwtExp(token) - marginSec;
}

const REFRESH_URL =
  process.env.IFOOD_REFRESH_URL || `${MAIN_URL}/v1/auth/token`;

export class SessionTokenProvider implements TokenProvider {
  constructor(
    private readonly userSub: string,
    private readonly store: UserTokenStore
  ) {}

  async refreshAccessToken(): Promise<string | null> {
    const pair = this.store.get(this.userSub);
    if (!pair?.refreshToken || expired(pair.refreshToken)) return null;

    try {
      const res = await axios.post(
        REFRESH_URL,
        { refreshToken: pair.refreshToken, grantType: "refresh_token" },
        { headers: { "content-type": "application/json" } }
      );
      const newAccess = res.data?.accessToken || res.data?.access_token;
      const newRefresh = res.data?.refreshToken || res.data?.refresh_token;
      if (newAccess) {
        this.store.set(this.userSub, {
          ...pair,
          accessToken: newAccess,
          refreshToken: newRefresh || pair.refreshToken,
        });
        return newAccess;
      }
    } catch {
      // refresh failed — user must re-authenticate
    }
    return null;
  }

  async getValidToken(): Promise<{
    token: string | null;
    accountId: string;
    deviceId?: string;
    sessionId?: string;
    error?: string;
  }> {
    const pair = this.store.get(this.userSub);
    if (!pair) {
      return {
        token: null,
        accountId: "",
        error: "No iFood session found. Re-authenticate via the OAuth login page.",
      };
    }

    const ids = { deviceId: pair.deviceId, sessionId: pair.sessionId };

    if (!expired(pair.accessToken)) {
      return { token: pair.accessToken, accountId: pair.accountId, ...ids };
    }

    if (pair.refreshToken && !expired(pair.refreshToken)) {
      const newToken = await this.refreshAccessToken();
      if (newToken) {
        return { token: newToken, accountId: pair.accountId, ...ids };
      }
    }

    return {
      token: null,
      accountId: pair.accountId,
      ...ids,
      error: "iFood token expired and refresh failed. Re-authenticate via the OAuth login page.",
    };
  }
}

/**
 * Background loop that proactively refreshes tokens before they expire.
 */
export function startTokenRefreshLoop(store: UserTokenStore, intervalMs = 60_000): () => void {
  const timer = setInterval(async () => {
    for (const userSub of store.allIds()) {
      const pair = store.get(userSub);
      if (!pair) continue;
      // Refresh if the access token expires within 120s
      if (!expired(pair.accessToken, 120)) continue;
      new SessionTokenProvider(userSub, store).refreshAccessToken().catch(() => {});
    }
  }, intervalMs);
  timer.unref?.();
  return () => clearInterval(timer);
}
