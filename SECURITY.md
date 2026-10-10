# Security

## Reporting a vulnerability

Please open a private security advisory on GitHub (Security → Report a vulnerability) instead of a public issue. Never include real bearer tokens, cookies or HAR captures in reports.

## Security audit (2026-10-10)

Scope: `src/index.ts` (stdio + tool executor), `src/http-server.ts`, `src/http/*` (OAuth 2.1 AS, login/OTP, token stores), dependencies, CI and configuration.

| # | Finding | Severity | Status |
|---|---------|----------|--------|
| 1 | **Path/parameter injection in tool calls.** Tool arguments were interpolated unencoded into upstream URL paths and never validated against the declared schema (`orderId: "../../x"`, `?`, `#`). Allowed hitting arbitrary authenticated iFood endpoints with the user's token. | Alta | Fixed: all args validated against the tool schema (types, ranges, identifier charset, unknown top-level keys rejected, size/depth bounds); path segments percent-encoded and `.`/`..`/`/` refused. |
| 2 | **`/login/paste` accepted unverified JWTs.** The `sub` came from an unsigned decode, so an attacker could overwrite another user's stored iFood session and obtain an MCP grant bound to their `sub`. Enabled by default. | Alta | Fixed: disabled unless `ENABLE_TOKEN_PASTE=1`; when enabled the token must be accepted by iFood (`/v1/customers/me`) first; attempt-limited. |
| 3 | **Token persisted to a world-readable file, also in HTTP mode.** Any API response containing `accessToken` was written to `~/.ifood-tokens.json` (default umask) — in multi-user HTTP mode this wrote one user's credential to a host-wide file, contradicting the README. | Alta | Fixed: persisted only for the single-user stdio provider, file mode `0600`. |
| 4 | **No abuse controls on login.** Unlimited OTP sends (SMS/WhatsApp/e-mail bombing of arbitrary victims) and unlimited OTP guesses; unbounded dynamic client registration and in-memory stores (memory DoS, never swept). | Alta | Fixed: per-IP limiter on `POST /login/*`, ≤3 OTP sends and ≤5 verify attempts per flow, global per-IP throttle, hard caps + expiry pruning on clients/flows/codes/refresh tokens. |
| 5 | **Dangerous redirect URIs in DCR** (`http://` remote hosts, etc.) allowing authorization-code delivery to attacker origins. | Média | Fixed: only https, loopback http, or custom app schemes; userinfo/fragment rejected; ≤10 per client. Login page now shows the redirect host to the user. |
| 6 | **OAuth hardening gaps.** `redirect_uri` optional at token exchange; refresh could widen scope; revoke ignored client binding and left iFood credentials in memory; JWT verify did not pin `alg`/`typ`; arbitrary scopes accepted. | Média | Fixed: strict `redirect_uri` match, scope narrowing only, revocation bound to the client and drops stored iFood session with the last grant, `alg=HS256`/`typ=at+jwt`/`sub`+`exp` required, scopes filtered to `mcp:tools`. |
| 7 | **Reflected content injection on login pages** (`?error=` rendered from the URL) and error messages echoing upstream text (account enumeration hints). | Média | Fixed: errors held server-side and shown once; generic user-facing messages; details only redacted in server logs. |
| 8 | **Missing HTTP security headers / CSP.** Login pages framable (clickjacking), cacheable, no CSP. | Média | Fixed: CSP (`default-src 'none'`, script pinned by hash, `frame-ancestors 'none'`), `X-Frame-Options`, `nosniff`, `Referrer-Policy`, HSTS (https), `Cache-Control: no-store`, `x-powered-by` removed. |
| 9 | **PII / LGPD exposure to the LLM.** Profile, contact, document and payment data were forwarded verbatim into model context. | Média | Mitigated: responses are minimised (credentials always redacted; CPF/document, card identifiers masked; e-mail/phone partially masked). Addresses are kept because carts need them. `IFOOD_MCP_PII_MODE=off` relaxes masking (credentials still redacted). |
| 10 | **Unconfirmed destructive action.** `ifood_checkout` could be triggered by prompt injection from merchant-controlled text (reviews, item descriptions). | Média | Mitigated: requires `confirmedByUser: true`; MCP tool annotations (`readOnlyHint`, `destructiveHint`) added so clients can prompt. |
| 11 | **Upstream request hardening / SSRF surface.** Operator-set URLs (`IFOOD_MAIN_URL`, `IFOOD_REFRESH_URL`) could send tokens anywhere; axios followed redirects (Authorization could be forwarded) and had no timeout. | Média | Fixed: URLs must be https on `*.ifood.com.br` (override `IFOOD_ALLOW_CUSTOM_HOSTS=1` for mocks), shared client with no redirects, 20 s timeout, size limits. Tool args cannot influence host or scheme. |
| 12 | **Vulnerable dependencies** (`npm audit`: 1 critical `proxy-addr`, 6 high incl. `ip-address`, express/qs chain). | Alta | Fixed via `npm audit fix`. Recommended: the maintainer should add `npm audit --audit-level=high` to CI (see "CI recommendation"). One moderate `qs` advisory remains upstream (re-check periodically). |
| 13 | **Information disclosure.** `/healthz` exposed public URL and tool count; no final error handler; 4 MB JSON limit; secrets could reach logs via upstream error text. | Baixa | Fixed: minimal health response, JSON-only error handler without stacks, 1 MB / 64 KB body limits, all logged/returned upstream errors pass through `redactSecrets`. |
| 14 | **Dev `/login/preview` route enabled by default** (unless `NODE_ENV=production`). | Baixa | Fixed: requires `ENABLE_LOGIN_PREVIEW=1` and non-production. |
| 15 | **`/mcp` Origin not validated.** | Baixa | Added opt-in `ALLOWED_ORIGINS` allowlist (Bearer auth already prevents CSRF; opt-in so browser clients such as claude.ai keep working). |

### Accepted / residual risks

- **Unofficial API.** The server impersonates the iFood web client (client key, device headers). iFood may change or block it; this is outside our control.
- **In-memory stores.** iFood tokens, MCP refresh tokens and OAuth state live in process memory (never on disk in HTTP mode). They are plaintext in memory; a memory dump exposes them. Restart = re-login. Single process only.
- **Dynamic client registration is open** (required by MCP clients). Mitigated by redirect-URI policy, caps and rate limits; the user still must complete an iFood OTP login to approve any client.
- **Access tokens are stateless JWTs (1 h)** and cannot be revoked individually; revocation removes the refresh token and the stored iFood session, so tool calls fail immediately.
- **Prompt injection.** Tool results contain third-party text (menus, reviews). The checkout confirmation flag reduces, but cannot eliminate, the risk; keep client-side tool approval enabled for `ifood_checkout`.
- **PII masking is key-based** (best effort) and does not scan free text.

## Operator checklist

1. Run HTTP mode only behind TLS (`PUBLIC_URL` must be `https://`, enforced except for localhost) and set `TRUST_PROXY` correctly so rate limits see real client IPs.
2. Generate `MCP_JWT_SECRET` with `openssl rand -hex 32`; rotate it to invalidate all sessions. Never reuse it.
3. Keep `ENABLE_TOKEN_PASTE` and `ENABLE_LOGIN_PREVIEW` unset in production. Set `NODE_ENV=production`.
4. Set `ALLOWED_ORIGINS` if you only serve known browser-based clients.
5. Do not set `IFOOD_MCP_PII_MODE=off` unless users have consented under LGPD for that processing.
6. In stdio mode, treat `.env` and `~/.ifood-tokens.json` as secrets (`chmod 600`); never commit them or HAR captures. Prefer short-lived tokens.
7. Require human approval for `ifood_checkout` in your MCP client.
8. Do not log request bodies at the reverse proxy for `/login/*` and `/token` (they carry OTP codes and credentials).
9. Run `npm audit` / `npm test` in CI (see "CI recommendation") and update dependencies regularly.
10. Run one instance per trust domain; for multi-instance deployments move stores to an encrypted external store (e.g. Redis with TLS + encryption at rest).

## CI recommendation (maintainer action)

The automation token used for this audit lacks the `workflow` scope, so `.github/workflows/ci.yml` was **not** modified. Please add these steps manually after `npm run typecheck`:

```yaml
      - run: npm test
      - run: npm audit --audit-level=high
```

The scripts `npm test` (node:test via tsx) and `npm run audit` already exist in `package.json`.
