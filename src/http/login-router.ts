/**
 * /login — two-step OTP flow that drives iFood's OTP authentication endpoints
 * and mints an OAuth 2.1 authorization code for the waiting MCP client.
 *
 *   1. GET  /login                — identifier (email or phone) + channel
 *   2. POST /login/start          — calls iFood /authorization-codes (sends OTP)
 *   3. GET  /login/verify         — 6-digit OTP entry form
 *   4. POST /login/verify         — exchanges OTP → JWT pair, mints auth code, redirects
 *
 * A "paste tokens" fallback is also exposed at /login/paste for advanced users
 * who already have JWTs extracted from browser DevTools.
 */

import { Router } from "express";
import type { iFoodOAuthProvider } from "./provider.js";
import {
  authenticateOtp,
  exchangeOtpCode,
  lookupChallengeEmail,
  parsePhoneBR,
  requestOtpCode,
  type OtpChannel,
  type Phone,
} from "./ifood-auth.js";

const STYLE = `
  :root {
    --bg: #f4f4f4;
    --card: #ffffff;
    --ink: #1a1a1a;
    --ink-soft: #555;
    --ink-muted: #888;
    --line: #e0e0e0;
    --field-bg: #fafafa;
    --primary: #EA1D2C;
    --primary-hover: #c41825;
    --primary-ink: #fff;
    --primary-ring: rgba(234,29,44,0.18);
    --error: #dc2626;
    --error-bg: rgba(220,38,38,0.06);
    --success: #16a34a;
    --success-bg: rgba(22,163,74,0.06);
    --shadow: 0 2px 8px rgba(0,0,0,0.08), 0 16px 48px rgba(0,0,0,0.06);
    --radius: 14px;
    --radius-sm: 8px;
  }
  @media (prefers-color-scheme: dark) {
    :root {
      --bg: #111;
      --card: #1c1c1c;
      --ink: #f0f0f0;
      --ink-soft: #bbb;
      --ink-muted: #777;
      --line: #2e2e2e;
      --field-bg: #141414;
      --primary: #ff3344;
      --primary-hover: #e02030;
      --shadow: 0 2px 8px rgba(0,0,0,0.5), 0 16px 48px rgba(0,0,0,0.4);
    }
  }
  * { box-sizing: border-box; }
  html, body { height: 100%; margin: 0; }
  body {
    background: var(--bg);
    color: var(--ink);
    font-family: ui-sans-serif, -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
    -webkit-font-smoothing: antialiased;
    display: grid; place-items: center; padding: 32px 20px;
  }
  .shell { width: 100%; max-width: 440px; display: flex; flex-direction: column; gap: 16px; }
  .card {
    background: var(--card);
    border: 1px solid var(--line);
    border-radius: var(--radius);
    padding: 36px 36px 30px;
    box-shadow: var(--shadow);
  }
  .brand { display: flex; align-items: center; gap: 12px; margin-bottom: 28px; }
  .brand-icon {
    width: 40px; height: 40px; border-radius: 10px;
    background: var(--primary); display: grid; place-items: center;
    flex: 0 0 auto;
  }
  .brand-icon svg { width: 22px; height: 22px; fill: #fff; }
  .brand-text { display: flex; flex-direction: column; gap: 2px; }
  .brand-name { font-weight: 700; font-size: 16px; color: var(--ink); }
  .brand-scope { font-size: 11px; color: var(--ink-muted); font-weight: 500; letter-spacing: 0.02em; }
  h1 { margin: 0 0 8px; font-size: 22px; font-weight: 700; letter-spacing: -0.02em; }
  .sub { margin: 0 0 24px; color: var(--ink-soft); font-size: 14px; line-height: 1.55; }
  .sub strong { color: var(--ink); }
  .sub code, .echo {
    font-family: ui-monospace, "SF Mono", Menlo, monospace;
    font-size: 12px; background: var(--field-bg);
    border: 1px solid var(--line); border-radius: 4px; padding: 1px 5px;
    color: var(--ink-soft);
  }
  .alert {
    display: flex; gap: 10px; align-items: flex-start;
    padding: 10px 13px; font-size: 13px; line-height: 1.45; margin-bottom: 18px;
    border: 1px solid transparent; border-radius: var(--radius-sm);
  }
  .alert.error { color: var(--error); background: var(--error-bg); border-color: color-mix(in srgb, var(--error) 20%, transparent); }
  .alert.success { color: var(--success); background: var(--success-bg); border-color: color-mix(in srgb, var(--success) 20%, transparent); }
  .field { margin-bottom: 16px; }
  .field-label { display: block; font-size: 12px; font-weight: 600; color: var(--ink-soft); margin-bottom: 6px; }
  .field-hint { font-size: 11px; color: var(--ink-muted); margin-top: 5px; }
  .field-input {
    width: 100%; padding: 12px 14px; font-size: 14px; color: var(--ink);
    background: var(--field-bg); border: 1px solid var(--line);
    border-radius: var(--radius-sm);
    font-family: inherit;
    transition: border-color .15s, box-shadow .15s;
  }
  .field-input.code {
    font-family: ui-monospace, "SF Mono", Menlo, monospace;
    font-size: 22px; letter-spacing: 8px; text-align: center;
  }
  .field-input.token {
    font-family: ui-monospace, "SF Mono", Menlo, monospace;
    font-size: 13px; resize: vertical; min-height: 72px; word-break: break-all;
  }
  .field-input:focus {
    outline: none; border-color: var(--primary);
    box-shadow: 0 0 0 3px var(--primary-ring);
  }
  .channels { display: grid; grid-template-columns: 1fr 1fr 1fr; gap: 8px; margin-bottom: 16px; }
  .channel-opt input[type=radio] { display: none; }
  .channel-opt label {
    display: flex; align-items: center; justify-content: center; gap: 6px;
    padding: 10px 8px; border: 1px solid var(--line); border-radius: var(--radius-sm);
    background: var(--field-bg); cursor: pointer; font-size: 13px; font-weight: 600;
    color: var(--ink-soft);
    transition: all .12s;
  }
  .channel-opt input[type=radio]:checked + label {
    border-color: var(--primary); color: var(--primary); background: rgba(234,29,44,0.04);
  }
  .btn {
    width: 100%; padding: 13px 16px; margin-top: 4px;
    font-size: 14px; font-weight: 700; color: var(--primary-ink);
    background: var(--primary); border: 1px solid var(--primary);
    border-radius: var(--radius-sm); cursor: pointer;
    transition: background .12s, transform .06s;
    font-family: inherit; letter-spacing: -0.01em;
    display: inline-flex; align-items: center; justify-content: center; gap: 10px;
  }
  .btn:hover { background: var(--primary-hover); border-color: var(--primary-hover); }
  .btn:active { transform: translateY(1px); }
  .btn[disabled] { opacity: 0.7; cursor: progress; }
  .btn .spinner {
    width: 14px; height: 14px; border: 2px solid rgba(255,255,255,0.3); border-top-color: #fff;
    border-radius: 50%; animation: spin .7s linear infinite; display: none;
  }
  .btn[disabled] .spinner { display: inline-block; }
  @keyframes spin { to { transform: rotate(360deg); } }
  .footer-link {
    display: block; text-align: center; font-size: 12px; color: var(--ink-muted);
    margin-top: 18px; text-decoration: none;
  }
  .footer-link:hover { color: var(--primary); }
  .footer-note { font-size: 11px; color: var(--ink-muted); text-align: center; }
  @media (max-width: 520px) { .card { padding: 26px 22px 22px; } }
`;

const SCRIPT = `
  (function(){
    document.querySelectorAll('form').forEach(function(f){
      f.addEventListener('submit', function(){
        var b = f.querySelector('button[type=submit]');
        if (b) { b.disabled = true; }
      });
    });
    var code = document.getElementById('authCode');
    if (code) { code.focus(); code.addEventListener('input', function(){
      this.value = this.value.replace(/\\D/g, '').slice(0, 6);
    }); }
  })();
`;

const IFOOD_ICON = `<svg viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg"><path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm-1 14H9V8h2v8zm4 0h-2V8h2v8z"/></svg>`;

function escapeHtml(s: string): string {
  return s.replace(/[&<>"']/g, (c) =>
    ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]!)
  );
}

function page(body: string, title = "iFood MCP · Autenticação"): string {
  return `<!doctype html><html lang="pt-BR"><head>
  <meta charset="utf-8"/>
  <meta name="viewport" content="width=device-width,initial-scale=1"/>
  <meta name="color-scheme" content="light dark"/>
  <title>${escapeHtml(title)}</title>
  <style>${STYLE}</style>
  </head><body><main class="shell"><div class="card">
    <div class="brand">
      <div class="brand-icon">${IFOOD_ICON}</div>
      <div class="brand-text">
        <span class="brand-name">iFood MCP</span>
        <span class="brand-scope">MCP · Autenticação</span>
      </div>
    </div>
    ${body}
  </div>
  <p class="footer-note">OAuth 2.1 · PKCE S256 · tokens não são armazenados em disco</p>
  </main><script>${SCRIPT}</script></body></html>`;
}

function alertBox(kind: "error" | "success", msg: string): string {
  const icon =
    kind === "error"
      ? `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>`
      : `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M20 6 9 17l-5-5"/></svg>`;
  return `<div class="alert ${kind}" role="${kind === "error" ? "alert" : "status"}">${icon}<span>${escapeHtml(msg)}</span></div>`;
}

function decodeJwtPayload(token: string): { sub?: string; exp?: number } {
  try {
    const [, payloadB64] = token.split(".");
    return JSON.parse(Buffer.from(payloadB64, "base64url").toString());
  } catch {
    return {};
  }
}

function isPhoneInput(s: string): boolean {
  return /\d/.test(s) && !s.includes("@");
}

function redirectWithError(
  flowId: string,
  message: string,
  step: "start" | "verify" | "email" = "start"
): string {
  const path = step === "start" ? "/login" : `/login/${step}`;
  return `${path}?authFlow=${encodeURIComponent(flowId)}&error=${encodeURIComponent(message)}`;
}

export function createLoginRouter(provider: iFoodOAuthProvider): Router {
  const router = Router();

  // Dev-only preview route
  if (process.env.NODE_ENV !== "production") {
    router.get("/login/preview", (_req, res) => {
      const flow = provider.pending.create({
        clientId: "preview-client",
        redirectUri: "http://localhost:3000/preview-callback",
        scopes: ["mcp:tools"],
        codeChallenge: "preview",
        state: "preview",
      });
      res.redirect(`/login?authFlow=${flow.flowId}`);
    });
  }

  /* ---------------- step 1: identifier + channel form ---------------- */

  router.get("/login", (req, res) => {
    const flowId = typeof req.query.authFlow === "string" ? req.query.authFlow : "";
    const flow = flowId ? provider.pending.get(flowId) : undefined;
    if (!flow) {
      res.status(400).send(
        page(`<h1>Link expirado</h1>
          <p class="sub">O fluxo de autorização expirou ou não foi encontrado. Reconecte seu cliente MCP e tente novamente.</p>`)
      );
      return;
    }

    const err = typeof req.query.error === "string" ? req.query.error : "";

    res.send(
      page(`
        <h1>Conectar ao iFood</h1>
        <p class="sub">Autorize <strong>${escapeHtml(flow.clientId)}</strong> a acessar sua conta iFood.</p>

        ${err ? alertBox("error", err) : ""}

        <form method="post" action="login/start" novalidate>
          <input type="hidden" name="authFlow" value="${escapeHtml(flow.flowId)}"/>

          <div class="field">
            <label class="field-label" for="identifier">E-mail ou telefone</label>
            <input class="field-input" id="identifier" name="identifier" required autofocus
              placeholder="ex: voce@gmail.com ou (11) 99999-0000"
              autocomplete="username"
              value="${escapeHtml(flow.identifier ?? "")}"/>
            <p class="field-hint">Mesmo e-mail/telefone usado no app do iFood.</p>
          </div>

          <div class="field-label">Receber código por</div>
          <div class="channels">
            <div class="channel-opt"><input type="radio" id="ch-w" name="channel" value="WHATSAPP" checked/><label for="ch-w">WhatsApp</label></div>
            <div class="channel-opt"><input type="radio" id="ch-s" name="channel" value="SMS"/><label for="ch-s">SMS</label></div>
            <div class="channel-opt"><input type="radio" id="ch-e" name="channel" value="EMAIL"/><label for="ch-e">E-mail</label></div>
          </div>

          <button class="btn" type="submit">
            <span class="spinner"></span>
            <span>Enviar código</span>
          </button>
        </form>

        <a class="footer-link" href="/login/paste?authFlow=${escapeHtml(flow.flowId)}">já tenho os tokens (avançado)</a>`)
    );
  });

  /* ---------------- step 2: send OTP ---------------- */

  router.post("/login/start", async (req, res) => {
    const { authFlow, identifier, channel } = req.body ?? {};
    if (typeof authFlow !== "string" || typeof identifier !== "string" || typeof channel !== "string") {
      res.status(400).send("missing fields");
      return;
    }
    const flow = provider.pending.get(authFlow);
    if (!flow) {
      res.status(400).send("flow expired");
      return;
    }

    const trimmed = identifier.trim();
    if (!trimmed) {
      res.redirect(302, redirectWithError(authFlow, "Informe seu e-mail ou telefone."));
      return;
    }
    if (!["EMAIL", "SMS", "WHATSAPP"].includes(channel)) {
      res.redirect(302, redirectWithError(authFlow, "Canal de OTP inválido."));
      return;
    }

    let phone: Phone | undefined;
    let email: string | undefined;
    if (isPhoneInput(trimmed)) {
      const parsed = parsePhoneBR(trimmed);
      if (!parsed) {
        res.redirect(302, redirectWithError(authFlow, "Telefone inválido. Use formato BR, ex: (11) 99999-0000."));
        return;
      }
      phone = parsed;
    } else {
      if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(trimmed)) {
        res.redirect(302, redirectWithError(authFlow, "E-mail inválido."));
        return;
      }
      email = trimmed.toLowerCase();
    }

    if (channel === "EMAIL" && !email) {
      res.redirect(302, redirectWithError(authFlow, "Para canal E-mail, informe um e-mail."));
      return;
    }
    if (channel !== "EMAIL" && !phone) {
      res.redirect(302, redirectWithError(authFlow, "Para canal SMS/WhatsApp, informe um telefone."));
      return;
    }

    try {
      const { key } = await requestOtpCode({
        channel: channel as OtpChannel,
        email,
        phone,
        deviceId: flow.deviceId,
        sessionId: flow.sessionId,
      });
      provider.pending.update(authFlow, {
        otpKey: key,
        identifier: trimmed,
        otpChannel: channel,
        resolvedEmail: email,
      });
      res.redirect(302, `/login/verify?authFlow=${encodeURIComponent(authFlow)}`);
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : "falha ao enviar código";
      res.redirect(302, redirectWithError(authFlow, `iFood: ${msg}`));
    }
  });

  /* ---------------- step 3: OTP entry form ---------------- */

  router.get("/login/verify", (req, res) => {
    const flowId = typeof req.query.authFlow === "string" ? req.query.authFlow : "";
    const flow = flowId ? provider.pending.get(flowId) : undefined;
    if (!flow || !flow.otpKey) {
      res.redirect(302, `/login?authFlow=${encodeURIComponent(flowId)}`);
      return;
    }
    const err = typeof req.query.error === "string" ? req.query.error : "";

    res.send(
      page(`
        <h1>Digite o código</h1>
        <p class="sub">Enviamos um código de 6 dígitos por <strong>${escapeHtml(
          flow.otpChannel ?? "OTP"
        )}</strong> para <span class="echo">${escapeHtml(flow.identifier ?? "")}</span>.</p>

        ${err ? alertBox("error", err) : ""}

        <form method="post" action="/login/verify" novalidate>
          <input type="hidden" name="authFlow" value="${escapeHtml(flow.flowId)}"/>
          <div class="field">
            <label class="field-label" for="authCode">Código</label>
            <input class="field-input code" id="authCode" name="authCode" required
              inputmode="numeric" pattern="[0-9]{6}" maxlength="6" autocomplete="one-time-code"
              placeholder="••••••"/>
          </div>
          <button class="btn" type="submit">
            <span class="spinner"></span>
            <span>Verificar e conectar</span>
          </button>
        </form>

        <a class="footer-link" href="/login?authFlow=${escapeHtml(flow.flowId)}">voltar</a>`)
    );
  });

  /* ---------------- step 4: exchange OTP → JWT, mint auth code ---------------- */

  router.post("/login/verify", async (req, res) => {
    const { authFlow, authCode } = req.body ?? {};
    if (typeof authFlow !== "string" || typeof authCode !== "string") {
      res.status(400).send("missing fields");
      return;
    }
    const flow = provider.pending.get(authFlow);
    if (!flow || !flow.otpKey) {
      res.status(400).send("flow expired");
      return;
    }

    const code = authCode.replace(/\D/g, "");
    if (code.length !== 6) {
      res.redirect(302, redirectWithError(authFlow, "Código deve ter 6 dígitos.", "verify"));
      return;
    }

    try {
      const { otpToken } = await exchangeOtpCode({
        key: flow.otpKey,
        authCode: code,
        deviceId: flow.deviceId,
        sessionId: flow.sessionId,
      });

      // If the user identified by phone, ask iFood for the masked email and
      // redirect to a "type your full email" page. iFood requires the real
      // email in step 5 — the masked form does NOT work.
      let email = flow.resolvedEmail;
      if (!email) {
        const r = await lookupChallengeEmail({
          otpToken,
          deviceId: flow.deviceId,
          sessionId: flow.sessionId,
        });
        if (r.email.includes("*")) {
          provider.pending.update(authFlow, {
            otpToken,
            maskedEmail: r.email,
          });
          res.redirect(302, `/login/email?authFlow=${encodeURIComponent(authFlow)}`);
          return;
        }
        email = r.email;
      }

      await completeAuthentication(res, authFlow, flow, otpToken, email);
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : "falha na verificação";
      res.redirect(302, redirectWithError(authFlow, `iFood: ${msg}`, "verify"));
    }
  });

  /* ---------------- step 4b: email challenge (phone-identified users) ---------------- */

  router.get("/login/email", (req, res) => {
    const flowId = typeof req.query.authFlow === "string" ? req.query.authFlow : "";
    const flow = flowId ? provider.pending.get(flowId) : undefined;
    if (!flow || !flow.otpToken) {
      res.redirect(302, `/login?authFlow=${encodeURIComponent(flowId)}`);
      return;
    }
    const err = typeof req.query.error === "string" ? req.query.error : "";
    const masked = flow.maskedEmail ?? "";

    res.send(
      page(`
        <h1>Confirme seu e-mail</h1>
        <p class="sub">O iFood pediu o e-mail completo da conta. A dica é <span class="echo">${escapeHtml(
          masked
        )}</span>.</p>

        ${err ? alertBox("error", err) : ""}

        <form method="post" action="/login/email" novalidate>
          <input type="hidden" name="authFlow" value="${escapeHtml(flow.flowId)}"/>
          <div class="field">
            <label class="field-label" for="email">E-mail completo</label>
            <input class="field-input" id="email" name="email" type="email" required autofocus
              placeholder="voce@gmail.com" autocomplete="email"/>
            <p class="field-hint">Digite o e-mail exatamente como cadastrado no iFood.</p>
          </div>
          <button class="btn" type="submit">
            <span class="spinner"></span>
            <span>Conectar</span>
          </button>
        </form>

        <a class="footer-link" href="/login?authFlow=${escapeHtml(flow.flowId)}">recomeçar</a>`)
    );
  });

  router.post("/login/email", async (req, res) => {
    const { authFlow, email } = req.body ?? {};
    if (typeof authFlow !== "string" || typeof email !== "string") {
      res.status(400).send("missing fields");
      return;
    }
    const flow = provider.pending.get(authFlow);
    if (!flow || !flow.otpToken) {
      res.redirect(302, `/login?authFlow=${encodeURIComponent(authFlow)}`);
      return;
    }
    const trimmed = email.trim().toLowerCase();
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(trimmed)) {
      res.redirect(302, redirectWithError(authFlow, "E-mail inválido.", "email"));
      return;
    }

    try {
      await completeAuthentication(res, authFlow, flow, flow.otpToken, trimmed);
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : "falha na verificação";
      res.redirect(302, redirectWithError(authFlow, `iFood: ${msg}`, "email"));
    }
  });

  /* ---------------- helper: step 5 + mint auth code + redirect ---------------- */

  async function completeAuthentication(
    res: Parameters<Parameters<typeof router.get>[1]>[1],
    authFlow: string,
    flow: NonNullable<ReturnType<typeof provider.pending.get>>,
    otpToken: string,
    email: string
  ): Promise<void> {
    const { accessToken, refreshToken, accountId } = await authenticateOtp({
      otpToken,
      email,
      deviceId: flow.deviceId,
      sessionId: flow.sessionId,
    });

    const sub = decodeJwtPayload(accessToken).sub || accountId;

    provider.userTokens.set(sub, {
      accessToken,
      refreshToken,
      accountId,
      deviceId: flow.deviceId,
      sessionId: flow.sessionId,
    });

    const ac = provider.codes.create({
      clientId: flow.clientId,
      redirectUri: flow.redirectUri,
      codeChallenge: flow.codeChallenge,
      scopes: flow.scopes,
      resource: flow.resource,
      userSub: sub,
    });
    provider.pending.delete(authFlow);

    const redirect = new URL(flow.redirectUri);
    redirect.searchParams.set("code", ac.code);
    if (flow.state) redirect.searchParams.set("state", flow.state);
    res.redirect(302, redirect.toString());
  }

  /* ---------------- fallback: paste tokens (advanced) ---------------- */

  router.get("/login/paste", (req, res) => {
    const flowId = typeof req.query.authFlow === "string" ? req.query.authFlow : "";
    const flow = flowId ? provider.pending.get(flowId) : undefined;
    if (!flow) {
      res.status(400).send(page(`<h1>Link expirado</h1><p class="sub">Reconecte e tente novamente.</p>`));
      return;
    }
    const err = typeof req.query.error === "string" ? req.query.error : "";

    res.send(
      page(`
        <h1>Colar tokens</h1>
        <p class="sub">Modo avançado: cole os JWTs extraídos do DevTools (header <code>authorization</code> + cookie <code>aRefreshToken</code>).</p>

        ${err ? alertBox("error", err) : ""}

        <form method="post" action="/login/paste" novalidate>
          <input type="hidden" name="authFlow" value="${escapeHtml(flow.flowId)}"/>
          <div class="field">
            <label class="field-label" for="accessToken">Access Token <span style="color:var(--primary)">*</span></label>
            <textarea class="field-input token" id="accessToken" name="accessToken" required autofocus rows="3" placeholder="eyJraWQi..."></textarea>
          </div>
          <div class="field">
            <label class="field-label" for="refreshToken">Refresh Token <span style="color:var(--ink-muted)">(opcional)</span></label>
            <textarea class="field-input token" id="refreshToken" name="refreshToken" rows="3" placeholder="eyJraWQi..."></textarea>
          </div>
          <button class="btn" type="submit">
            <span class="spinner"></span>
            <span>Conectar</span>
          </button>
        </form>

        <a class="footer-link" href="/login?authFlow=${escapeHtml(flow.flowId)}">voltar ao login normal</a>`)
    );
  });

  router.post("/login/paste", (req, res) => {
    const { authFlow, accessToken, refreshToken } = req.body ?? {};
    if (typeof authFlow !== "string" || typeof accessToken !== "string") {
      res.status(400).send("missing fields");
      return;
    }
    const flow = provider.pending.get(authFlow);
    if (!flow) {
      res.status(400).send("flow expired");
      return;
    }

    const token = accessToken.trim().replace(/^Bearer\s+/i, "");
    if (!token) {
      res.redirect(
        302,
        `/login/paste?authFlow=${encodeURIComponent(authFlow)}&error=${encodeURIComponent("Access token vazio.")}`
      );
      return;
    }

    const { sub, exp } = decodeJwtPayload(token);
    if (!sub) {
      res.redirect(
        302,
        `/login/paste?authFlow=${encodeURIComponent(authFlow)}&error=${encodeURIComponent("Token inválido — campo 'sub' ausente.")}`
      );
      return;
    }
    const nowSec = Math.floor(Date.now() / 1000);
    if (exp && exp < nowSec) {
      res.redirect(
        302,
        `/login/paste?authFlow=${encodeURIComponent(authFlow)}&error=${encodeURIComponent("Access token expirado.")}`
      );
      return;
    }

    provider.userTokens.set(sub, {
      accessToken: token,
      refreshToken: typeof refreshToken === "string" ? refreshToken.trim() : "",
      accountId: sub,
      deviceId: flow.deviceId,
      sessionId: flow.sessionId,
    });

    const ac = provider.codes.create({
      clientId: flow.clientId,
      redirectUri: flow.redirectUri,
      codeChallenge: flow.codeChallenge,
      scopes: flow.scopes,
      resource: flow.resource,
      userSub: sub,
    });
    provider.pending.delete(authFlow);

    const redirect = new URL(flow.redirectUri);
    redirect.searchParams.set("code", ac.code);
    if (flow.state) redirect.searchParams.set("state", flow.state);
    res.redirect(302, redirect.toString());
  });

  return router;
}
