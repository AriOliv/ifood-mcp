#!/usr/bin/env node
/**
 * Remote MCP server for iFood.
 *
 * Exposes the iFood tools over the Streamable HTTP transport with
 * OAuth 2.1 authorization as specified by the MCP Authorization spec.
 *
 * Endpoints:
 *   GET  /.well-known/oauth-authorization-server
 *   GET  /.well-known/oauth-protected-resource
 *   POST /register   (RFC 7591 DCR)
 *   GET  /authorize
 *   POST /token
 *   POST /revoke
 *   GET  /login      (HTML — paste iFood tokens from browser DevTools)
 *   POST /login/token
 *   ALL  /mcp        (MCP Streamable HTTP, Bearer-protected)
 *   GET  /healthz
 *
 * Environment:
 *   PORT             default 3000
 *   PUBLIC_URL       https URL the client sees (e.g. https://mcp.myhost.com)
 *   MCP_JWT_SECRET   HS256 signing key (≥32 chars)
 *   IFOOD_REFRESH_URL  override refresh endpoint (default: MAIN_URL/v1/auth/token)
 */

import dotenv from "dotenv";
dotenv.config();

import express from "express";

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
  type CallToolRequest,
  type CallToolResult,
  type Tool,
} from "@modelcontextprotocol/sdk/types.js";
import { mcpAuthRouter } from "@modelcontextprotocol/sdk/server/auth/router.js";
import { requireBearerAuth } from "@modelcontextprotocol/sdk/server/auth/middleware/bearerAuth.js";

import { toolDefinitions, executeTool, toolAnnotations } from "./index.js";
import { redactSecrets, RateLimiter } from "./security.js";
import { iFoodOAuthProvider } from "./http/provider.js";
import { createLoginRouter } from "./http/login-router.js";
import { SessionTokenProvider, startTokenRefreshLoop } from "./http/session-provider.js";

const PORT = Number(process.env.PORT ?? 3000);
const PUBLIC_URL = (process.env.PUBLIC_URL ?? `http://localhost:${PORT}`).replace(/\/$/, "");
const JWT_SECRET_STR = process.env.MCP_JWT_SECRET;

if (!JWT_SECRET_STR || JWT_SECRET_STR.length < 32) {
  console.error("MCP_JWT_SECRET is required and must be at least 32 characters. Aborting.");
  process.exit(1);
}
const JWT_SECRET = new TextEncoder().encode(JWT_SECRET_STR);

const issuerUrl = new URL(PUBLIC_URL);
const isLoopback = ["localhost", "127.0.0.1", "[::1]"].includes(issuerUrl.hostname);
if (issuerUrl.protocol !== "https:" && !isLoopback) {
  console.error("PUBLIC_URL must be https (plain http is only allowed for localhost). Aborting.");
  process.exit(1);
}
// Optional comma-separated Origin allowlist for /mcp (DNS-rebinding / browser-origin protection).
const ALLOWED_ORIGINS = (process.env.ALLOWED_ORIGINS ?? "")
  .split(",")
  .map((o) => o.trim())
  .filter(Boolean);
const resourceUrl = new URL("/mcp", PUBLIC_URL);

const provider = new iFoodOAuthProvider({
  issuerUrl,
  resourceUrl,
  loginPath: "/login",
  jwtSecret: JWT_SECRET,
});

const toolMap = new Map(toolDefinitions.map((t) => [t.name, t]));

const app = express();

app.disable("x-powered-by");
// Set TRUST_PROXY=1 when behind a reverse proxy so rate limits see the real client IP.
if (process.env.TRUST_PROXY) {
  const v = process.env.TRUST_PROXY;
  app.set("trust proxy", /^\d+$/.test(v) ? Number(v) : v === "true" ? 1 : v);
}

// Baseline security headers on every response.
app.use((req, res, next) => {
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("X-Frame-Options", "DENY");
  res.setHeader("Referrer-Policy", "no-referrer");
  res.setHeader("Cross-Origin-Resource-Policy", "same-origin");
  if (issuerUrl.protocol === "https:") {
    res.setHeader("Strict-Transport-Security", "max-age=31536000; includeSubDomains");
  }
  // OAuth/login/MCP responses carry credentials or per-user data: never cache.
  if (!req.path.startsWith("/.well-known/")) {
    res.setHeader("Cache-Control", "no-store");
    res.setHeader("Pragma", "no-cache");
  }
  next();
});

// Global per-IP throttle (in addition to the SDK's limits on /authorize, /token, /register).
const globalLimiter = new RateLimiter(300, 60_000);
app.use((req, res, next) => {
  if (!globalLimiter.take(req.ip ?? "unknown")) {
    res.status(429).json({ error: "rate_limited" });
    return;
  }
  next();
});

app.use(express.json({ limit: "1mb" }));
app.use(express.urlencoded({ extended: false, limit: "64kb" }));

app.use((req, _res, next) => {
  const sessionId = req.header("mcp-session-id");
  const hasAuth = !!req.header("authorization");
  const bodyMethod = (req.body as { method?: string } | undefined)?.method;
  console.log(
    `[http] ${req.method} ${req.path}${bodyMethod ? ` rpc=${bodyMethod}` : ""}${
      sessionId ? ` session=${sessionId.slice(0, 8)}` : ""
    }${hasAuth ? " auth=yes" : " auth=no"}`
  );
  next();
});

app.use(
  mcpAuthRouter({
    provider,
    issuerUrl,
    baseUrl: new URL(PUBLIC_URL),
    resourceServerUrl: resourceUrl,
    scopesSupported: ["mcp:tools"],
    resourceName: "iFood MCP",
  })
);

app.use(createLoginRouter(provider));

app.get("/healthz", (_req, res) => {
  res.json({ ok: true });
});

/* ----------------------------- MCP endpoint -------------------------- */

const resourceMetadataUrl = `${PUBLIC_URL}/.well-known/oauth-protected-resource${resourceUrl.pathname}`;
const bearerGuard = requireBearerAuth({
  verifier: provider,
  requiredScopes: [],
  resourceMetadataUrl,
});

function makeMcpServer(userSub: string): McpServer {
  const sessionProvider = new SessionTokenProvider(userSub, provider.userTokens);

  const mcp = new McpServer(
    { name: "@aol/ifood-mcp", version: "1.0.0" },
    { capabilities: { tools: {} } }
  );

  const low = mcp.server;

  low.setRequestHandler(ListToolsRequestSchema, async () => {
    const tools: Tool[] = toolDefinitions.map((def) => ({
      name: def.name,
      description: def.description,
      inputSchema: { type: "object" as const, ...def.inputSchema },
      annotations: toolAnnotations(def),
    }));
    return { tools };
  });

  low.setRequestHandler(CallToolRequestSchema, async (req: CallToolRequest) => {
    const def = toolMap.get(req.params.name);
    if (!def) {
      const r: CallToolResult = {
        content: [{ type: "text", text: `Unknown tool: ${redactSecrets(req.params.name, 80)}` }],
        isError: true,
      };
      return r;
    }
    const args = (req.params.arguments as Record<string, unknown>) ?? {};
    console.log(`[mcp] tools/call name=${redactSecrets(req.params.name, 64)}`);
    return executeTool(def, args, sessionProvider);
  });

  return mcp;
}

function originGuard(req: express.Request, res: express.Response, next: express.NextFunction): void {
  const origin = req.header("origin");
  if (origin && ALLOWED_ORIGINS.length > 0 && !ALLOWED_ORIGINS.includes(origin)) {
    res.status(403).json({ error: "forbidden_origin" });
    return;
  }
  next();
}

app.all("/mcp", originGuard, bearerGuard, async (req, res) => {
  const auth = req.auth;
  const userSub = auth?.extra?.userSub as string | undefined;
  if (!userSub) {
    res.status(401).json({ error: "invalid_token", error_description: "missing sub" });
    return;
  }

  const transport = new StreamableHTTPServerTransport({ sessionIdGenerator: undefined });
  res.on("close", () => {
    transport.close().catch(() => {});
  });
  try {
    const server = makeMcpServer(userSub);
    await server.connect(transport);
    await transport.handleRequest(req, res, req.body);
  } catch (err) {
    console.error(`[mcp] request failed: ${redactSecrets(err instanceof Error ? err.message : err)}`);
    if (!res.headersSent) res.status(500).json({ error: "server_error" });
  }
});

// Final error handler: never leak stack traces or internals to clients.
app.use((err: unknown, _req: express.Request, res: express.Response, _next: express.NextFunction) => {
  const status = typeof (err as { status?: unknown })?.status === "number" ? (err as { status: number }).status : 500;
  if (status >= 500) console.error(`[http] error: ${redactSecrets(err instanceof Error ? err.message : err)}`);
  if (!res.headersSent) res.status(status >= 400 && status < 600 ? status : 500).json({ error: status >= 500 ? "server_error" : "invalid_request" });
});

/* ----------------------- Background refresh loop --------------------- */

startTokenRefreshLoop(provider.userTokens, 60_000);

/* -------------------------------- Listen ----------------------------- */

app.listen(PORT, () => {
  console.log(`iFood MCP remote listening on :${PORT}`);
  console.log(`  Public URL:     ${PUBLIC_URL}`);
  console.log(`  Resource (MCP): ${resourceUrl.href}`);
  console.log(`  Authorization:  ${issuerUrl.href}`);
  console.log(`  Tools:          ${toolDefinitions.length}`);
});

process.on("SIGTERM", () => process.exit(0));
process.on("SIGINT", () => process.exit(0));
