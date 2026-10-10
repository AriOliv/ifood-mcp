/**
 * Security helpers shared by the stdio and HTTP entrypoints: hardened HTTP
 * client, upstream URL allowlist, tool-argument validation, secret redaction
 * and PII minimisation of data returned to the LLM.
 */

import axios from "axios";

/* ------------------------------ upstream URLs ----------------------------- */

const ALLOWED_HOST_SUFFIXES = [".ifood.com.br"];

/**
 * Validate an operator-supplied upstream URL. Tokens are sent to these hosts,
 * so they must be https and belong to iFood unless explicitly overridden with
 * IFOOD_ALLOW_CUSTOM_HOSTS=1 (e.g. local mock server in tests).
 */
export function assertIfoodUrl(name: string, value: string): string {
  let u: URL;
  try {
    u = new URL(value);
  } catch {
    throw new Error(`${name} is not a valid URL`);
  }
  if (process.env.IFOOD_ALLOW_CUSTOM_HOSTS === "1") return value.replace(/\/$/, "");
  const hostOk = ALLOWED_HOST_SUFFIXES.some((s) => u.hostname.endsWith(s));
  if (u.protocol !== "https:" || !hostOk) {
    throw new Error(
      `${name} must be an https URL on ifood.com.br (set IFOOD_ALLOW_CUSTOM_HOSTS=1 to override)`
    );
  }
  return value.replace(/\/$/, "");
}

/* ------------------------------- HTTP client ------------------------------ */

/** No redirects (Authorization must never follow a 3xx to another host), bounded time and size. */
export const ifoodHttp = axios.create({
  timeout: 20_000,
  maxRedirects: 0,
  maxContentLength: 5 * 1024 * 1024,
  maxBodyLength: 1024 * 1024,
});

/* -------------------------------- redaction ------------------------------- */

const JWT_RE = /eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]*/g;
const BEARER_RE = /Bearer\s+[A-Za-z0-9._~+/=-]+/gi;
const KV_SECRET_RE =
  /("?(?:access_?token|refresh_?token|token|secret_?key|access_?key|password|authorization|cvv|otp)"?\s*[:=]\s*)("[^"]*"|[^\s,;&}]+)/gi;

/** Strip anything that looks like a credential from a string and cap its length. */
export function redactSecrets(input: unknown, max = 300): string {
  let s = typeof input === "string" ? input : String(input ?? "");
  s = s.replace(BEARER_RE, "Bearer [REDACTED]").replace(JWT_RE, "[REDACTED_JWT]");
  s = s.replace(KV_SECRET_RE, (_m, k) => `${k}"[REDACTED]"`);
  s = s.replace(/[\r\n\t]+/g, " ");
  return s.length > max ? `${s.slice(0, max)}…` : s;
}

/* ---------------------------- PII minimisation ---------------------------- */

export type PiiMode = "standard" | "off";

export function piiMode(): PiiMode {
  return process.env.IFOOD_MCP_PII_MODE === "off" ? "off" : "standard";
}

const SECRET_KEYS =
  /^(access_?token|refresh_?token|id_?token|token|secret|secret_?key|access_?key|password|cvv|cvc|securityCode|pin|signature_?key|devicePaymentSecret)$/i;
const DOCUMENT_KEYS =
  /^(cpf|documentNumber|nationalIdentificationNumber|nationalId|taxId|taxpayerId|rg)$/i;
const CARD_KEYS = /^(cardNumber|pan|fullNumber|card_?number|bin|expirationDate|expiry|expirationMonth|expirationYear|holderName|cardHolder)$/i;
const CONTACT_KEYS = /^(email|emailAddress)$/i;
const PHONE_KEYS = /^(phone|phoneNumber|cellphone|mobile)$/i;

function maskEmail(v: string): string {
  const [u, d] = v.split("@");
  if (!d) return "[REDACTED]";
  return `${u.slice(0, 1)}***@${d}`;
}

function maskTail(v: string, keep = 2): string {
  const digits = v.replace(/\D/g, "");
  if (digits.length <= keep) return "***";
  return `***${digits.slice(-keep)}`;
}

/**
 * Recursively minimise personal/sensitive data before it reaches the LLM
 * context (LGPD art. 6, III — necessity). Credentials are always removed;
 * national IDs, card identifiers and contact details are masked. Address data
 * is kept because it is needed to build carts. Disable with IFOOD_MCP_PII_MODE=off
 * (credentials are still removed).
 */
export function minimizePii(value: unknown, mode: PiiMode = piiMode(), depth = 0): unknown {
  if (depth > 20) return "[TRUNCATED]";
  if (Array.isArray(value)) return value.map((v) => minimizePii(v, mode, depth + 1));
  if (value && typeof value === "object") {
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
      if (SECRET_KEYS.test(k)) {
        out[k] = "[REDACTED]";
      } else if (mode === "standard" && (DOCUMENT_KEYS.test(k) || CARD_KEYS.test(k))) {
        out[k] = "[REDACTED]";
      } else if (mode === "standard" && CONTACT_KEYS.test(k) && typeof v === "string") {
        out[k] = maskEmail(v);
      } else if (mode === "standard" && PHONE_KEYS.test(k) && (typeof v === "string" || typeof v === "number")) {
        out[k] = maskTail(String(v));
      } else {
        out[k] = minimizePii(v, mode, depth + 1);
      }
    }
    return out;
  }
  return value;
}

/* ---------------------------- argument validation ------------------------- */

type Schema = {
  type?: string;
  properties?: Record<string, Schema>;
  required?: string[];
  enum?: unknown[];
  items?: Schema;
  [k: string]: unknown;
};

/** Properties that are identifiers interpolated into URL paths / queries. */
const ID_PROP = /(^id$|Id$|^alias$|^tags$)/;
const ID_RE = /^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$/;
const MAX_STRING = 2000;
const MAX_ARRAY = 100;
const MAX_DEPTH = 8;

function isPlainObject(v: unknown): v is Record<string, unknown> {
  return !!v && typeof v === "object" && !Array.isArray(v);
}

function validate(value: unknown, schema: Schema, path: string, depth: number, errors: string[]): void {
  if (depth > MAX_DEPTH) {
    errors.push(`${path}: nesting too deep`);
    return;
  }
  const t = schema.type;
  if (t === "string") {
    if (typeof value !== "string") return void errors.push(`${path}: expected string`);
    if (value.length > MAX_STRING) errors.push(`${path}: too long`);
    // eslint-disable-next-line no-control-regex
    if (/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/.test(value)) errors.push(`${path}: control characters not allowed`);
    if (schema.enum && !schema.enum.includes(value)) errors.push(`${path}: not an allowed value`);
    const leaf = path.split(".").pop() ?? "";
    if (ID_PROP.test(leaf.replace(/\[\d*\]$/, "")) && !ID_RE.test(value)) {
      errors.push(`${path}: invalid identifier`);
    }
  } else if (t === "number") {
    if (typeof value !== "number" || !Number.isFinite(value)) errors.push(`${path}: expected finite number`);
    else {
      const leaf = path.split(".").pop() ?? "";
      if (/^(latitude|lat)$/.test(leaf) && Math.abs(value) > 90) errors.push(`${path}: out of range`);
      if (/^(longitude|lon)$/.test(leaf) && Math.abs(value) > 180) errors.push(`${path}: out of range`);
      if (/^(size|pageSize)$/.test(leaf) && (value < 1 || value > 50)) errors.push(`${path}: must be 1..50`);
      if (/^(page)$/.test(leaf) && (value < 0 || value > 10_000)) errors.push(`${path}: out of range`);
      if (leaf === "distanceInKm" && (value <= 0 || value > 100)) errors.push(`${path}: out of range`);
      if (leaf === "quantity" && (!Number.isInteger(value) || value < 1 || value > 99)) {
        errors.push(`${path}: must be an integer 1..99`);
      }
    }
  } else if (t === "boolean") {
    if (typeof value !== "boolean") errors.push(`${path}: expected boolean`);
  } else if (t === "array") {
    if (!Array.isArray(value)) return void errors.push(`${path}: expected array`);
    if (value.length > MAX_ARRAY) return void errors.push(`${path}: too many items`);
    if (schema.items) value.forEach((v, i) => validate(v, schema.items!, `${path}[${i}]`, depth + 1, errors));
  } else if (t === "object") {
    if (!isPlainObject(value)) return void errors.push(`${path}: expected object`);
    const props = schema.properties;
    if (props) {
      for (const r of schema.required ?? []) {
        if (value[r] === undefined) errors.push(`${path}.${r}: required`);
      }
      for (const [k, v] of Object.entries(value)) {
        if (k === "__proto__" || k === "constructor" || k === "prototype") {
          errors.push(`${path}.${k}: forbidden key`);
          continue;
        }
        const sub = props[k];
        if (!sub) {
          // strict at the top level; nested payloads may carry extra upstream fields
          if (depth === 0) errors.push(`${path}.${k}: unknown property`);
          continue;
        }
        if (v !== undefined) validate(v, sub, `${path}.${k}`, depth + 1, errors);
      }
    } else {
      // free-form object (e.g. subItems, checkoutPayload): bound size only
      if (JSON.stringify(value).length > 64 * 1024) errors.push(`${path}: too large`);
    }
  }
}

/** Validate tool arguments against the tool's declared JSON schema. Returns a list of errors. */
export function validateToolArgs(inputSchema: Record<string, unknown>, args: unknown): string[] {
  const errors: string[] = [];
  validate(args, { type: "object", ...(inputSchema as Schema) }, "args", 0, errors);
  return errors;
}

/** Percent-encode a value for safe use as a single URL path segment. */
export function encodePathSegment(v: unknown): string {
  const s = String(v);
  if (s === "." || s === ".." || /[/\\]/.test(s)) throw new Error("invalid path parameter");
  return encodeURIComponent(s);
}

/* ------------------------------ rate limiting ----------------------------- */

/** Tiny fixed-window in-memory limiter keyed by an arbitrary string. */
export class RateLimiter {
  private hits = new Map<string, { n: number; reset: number }>();
  constructor(private readonly max: number, private readonly windowMs: number) {
    const t = setInterval(() => this.sweep(), windowMs);
    t.unref?.();
  }
  /** Returns true when the call is allowed. */
  take(key: string): boolean {
    const now = Date.now();
    const e = this.hits.get(key);
    if (!e || e.reset <= now) {
      this.hits.set(key, { n: 1, reset: now + this.windowMs });
      return true;
    }
    e.n += 1;
    return e.n <= this.max;
  }
  private sweep(): void {
    const now = Date.now();
    for (const [k, e] of this.hits) if (e.reset <= now) this.hits.delete(k);
  }
}
