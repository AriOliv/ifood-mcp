/**
 * iFood OTP authentication client.
 *
 * Drives the 5-step OTP flow used by the iFood website:
 *   1. POST /v4/identity-providers           — list providers (informational)
 *   2. POST /v2/identity-providers/OTP/authorization-codes  — send 6-digit OTP
 *   3. POST /v2/identity-providers/OTP/access-tokens        — exchange OTP → opaque token
 *   4. POST /v1/identity-providers/OTP/challenges           — opaque token → masked email
 *   5. POST /v3/identity-providers/OTP/authentications      — opaque token + email → JWT pair
 *
 * Step 4 is required to discover the email when the user identified by phone.
 * The `device_id` sent in step 5 must match the `x-ifood-device-id` header
 * later used on API calls.
 */

import axios from "axios";
import { MAIN_URL } from "../index.js";

const TENANT_ID = "IFO";

export type OtpChannel = "EMAIL" | "SMS" | "WHATSAPP";

export type Phone = {
  country_code: number;
  area_code: number;
  number: string;
};

const SHARED_HEADERS = (deviceId: string, sessionId: string): Record<string, string> => ({
  "content-type": "application/json",
  accept: "application/json, text/plain, */*",
  "accept-language": "pt-BR,pt;q=1",
  app_version: "9.141.4",
  browser: "Mac OS",
  platform: "Desktop",
  "user-agent":
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/147.0.0.0 Safari/537.36",
  "x-client-application-key":
    process.env.IFOOD_CLIENT_KEY || "41a266ee-51b7-4c37-9e9d-5cd331f280d5",
  "x-device-model": "Macintosh Brave",
  "x-ifood-device-id": deviceId,
  "x-ifood-session-id": sessionId,
});

/** Step 2 — request OTP code via the chosen channel. Returns an opaque key + timeout. */
export async function requestOtpCode(opts: {
  channel: OtpChannel;
  email?: string;
  phone?: Phone;
  deviceId: string;
  sessionId: string;
}): Promise<{ key: string; timeoutSec: number }> {
  if (!opts.email && !opts.phone) {
    throw new Error("either email or phone is required");
  }
  const body: Record<string, unknown> = {
    tenant_id: TENANT_ID,
    type: opts.channel,
  };
  if (opts.email) body.email = opts.email;
  if (opts.phone) body.phone = opts.phone;

  const res = await axios.post(
    `${MAIN_URL}/v2/identity-providers/OTP/authorization-codes`,
    body,
    { headers: SHARED_HEADERS(opts.deviceId, opts.sessionId) }
  );
  return {
    key: String(res.data.key),
    timeoutSec: Number(res.data.timeout_in_seconds ?? 60),
  };
}

/** Step 3 — exchange (key + 6-digit code) for an opaque OTP token. */
export async function exchangeOtpCode(opts: {
  key: string;
  authCode: string;
  deviceId: string;
  sessionId: string;
}): Promise<{ otpToken: string }> {
  const res = await axios.post(
    `${MAIN_URL}/v2/identity-providers/OTP/access-tokens`,
    { key: opts.key, auth_code: opts.authCode },
    { headers: SHARED_HEADERS(opts.deviceId, opts.sessionId) }
  );
  return { otpToken: String(res.data.access_token) };
}

/** Step 4 — resolve opaque OTP token to the masked email. Used when user identified by phone. */
export async function lookupChallengeEmail(opts: {
  otpToken: string;
  deviceId: string;
  sessionId: string;
}): Promise<{ email: string }> {
  const res = await axios.post(
    `${MAIN_URL}/v1/identity-providers/OTP/challenges`,
    { token: opts.otpToken, tenant: TENANT_ID },
    { headers: SHARED_HEADERS(opts.deviceId, opts.sessionId) }
  );
  return { email: String(res.data.email) };
}

/** Step 5 — mint the JWT pair. Email is required (masked is fine for phone-flow lookups, but real email works). */
export async function authenticateOtp(opts: {
  otpToken: string;
  email: string;
  deviceId: string;
  sessionId: string;
}): Promise<{
  accessToken: string;
  refreshToken: string;
  accountId: string;
}> {
  const res = await axios.post(
    `${MAIN_URL}/v3/identity-providers/OTP/authentications`,
    {
      tenant_id: TENANT_ID,
      token: opts.otpToken,
      device_id: opts.deviceId,
      email: opts.email,
    },
    { headers: SHARED_HEADERS(opts.deviceId, opts.sessionId) }
  );
  if (!res.data.authenticated) {
    throw new Error(res.data.error_message || "authentication rejected by iFood");
  }
  return {
    accessToken: String(res.data.access_token),
    refreshToken: String(res.data.refresh_token),
    accountId: String(res.data.account_id),
  };
}

/**
 * Parse a Brazilian phone string (with or without country code) into the
 * { country_code, area_code, number } shape iFood expects.
 *
 *   "21 96758-2535"     → { country_code: 55, area_code: 21, number: "967582535" }
 *   "+55 11 99999-0000" → { country_code: 55, area_code: 11, number: "999990000" }
 *   "11999990000"       → { country_code: 55, area_code: 11, number: "999990000" }
 */
export function parsePhoneBR(input: string): Phone | null {
  const digits = input.replace(/\D/g, "");
  if (!digits) return null;
  let rest = digits;
  let countryCode = 55;
  if (rest.length > 11 && rest.startsWith("55")) {
    countryCode = 55;
    rest = rest.slice(2);
  }
  if (rest.length < 10 || rest.length > 11) return null;
  const areaCode = Number(rest.slice(0, 2));
  const number = rest.slice(2);
  if (!Number.isFinite(areaCode)) return null;
  return { country_code: countryCode, area_code: areaCode, number };
}
