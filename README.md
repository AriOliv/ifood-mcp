# iFood MCP Server <img src="assets/logo.png" align="right" width="102"/>

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Node.js](https://img.shields.io/badge/node-%E2%89%A520-brightgreen.svg)](https://nodejs.org/)
[![TypeScript](https://img.shields.io/badge/TypeScript-5-blue.svg)](https://www.typescriptlang.org/)
[![MCP](https://img.shields.io/badge/MCP-stdio%20%7C%20HTTP%2BOAuth-purple.svg)](https://modelcontextprotocol.io/)

Unofficial [Model Context Protocol](https://modelcontextprotocol.io/) server for [iFood](https://www.ifood.com.br) — Brazil's largest food delivery platform. Browse restaurants, search food, manage your cart and place orders through any AI assistant that speaks MCP.

> Not affiliated with iFood. Wraps the public consumer web API for personal use.

## What This MCP Server Does

This MCP server gives AI assistants (Claude Code, Claude Desktop, Cursor, Codex, etc.) access to your iFood account. It exposes 25 tools that let an AI:

- 🔍 Search restaurants and food items near you
- 🍔 Browse merchants, full catalogs, item details and customer reviews
- 🛒 Build a cart with items, delivery method and payment
- 💳 List your saved payment methods and addresses
- 📦 List past orders, get order details, and reorder
- 🎁 Check loyalty cards, wallet benefits and coupons
- 📍 Explore the home feed, categories and curated browse pages

## Two Authentication Modes

| Mode | Transport | Login | Best for |
| --- | --- | --- | --- |
| **HTTP + OAuth 2.1** | Streamable HTTP | Real iFood OTP (e‑mail / SMS / WhatsApp) on a hosted login page | Multi‑user deploys, remote MCP, sharing with friends |
| **stdio** | Standard input / output | Tokens pasted from browser DevTools into a `.env` file | Local single‑user setup, fastest to wire up |

You can run either mode independently; the same tool definitions back both.

## Prerequisites

- [Node.js](https://nodejs.org/en/download) **≥ 20**
- An active iFood account (any region in Brazil)
- For HTTP+OAuth mode: nothing else — the login UI handles everything
- For stdio mode: a recent JWT extracted from browser DevTools (see below)

Check your install with `node -v` and `npm -v`.

## Installation

### 1. Clone and build

```bash
git clone https://github.com/AriOliv/ifood-mcp.git
cd ifood-mcp
npm install
npm run build
```

### 2. Pick a mode

#### Option A — HTTP + OAuth 2.1 (recommended)

```bash
# Generate a JWT signing secret (≥32 chars)
echo "MCP_JWT_SECRET=$(openssl rand -hex 32)" >> .env
echo "PORT=3001" >> .env

# Run with auto-reload
npm run dev
```

Then register the server with your client.

##### Claude Code

```bash
claude mcp add --transport http ifood http://localhost:3001/mcp
```

Run `/mcp` inside Claude Code → click `ifood` → it'll open the browser at the OTP login page. Authenticate with your iFood e‑mail and the 6‑digit code that arrives via WhatsApp/SMS/Email.

##### Cursor

Add to `~/.cursor/mcp.json`:

```json
{
  "mcpServers": {
    "ifood": {
      "type": "http",
      "url": "http://localhost:3001/mcp"
    }
  }
}
```

Cursor will trigger the OAuth flow on first use.

##### Codex

```bash
codex mcp add --transport http ifood http://localhost:3001/mcp
```

#### Option B — stdio (single user)

Extract your iFood credentials from browser DevTools:

1. Open [iFood](https://www.ifood.com.br) and sign in
2. DevTools → Network tab → reload, do any action (e.g. open a restaurant)
3. Click any `site-api` request
4. Copy the `authorization` header value (drop the `Bearer ` prefix)
5. From the cookies tab, copy `aRefreshToken`, `aDeviceId`, `aSessionId` and `aAccountId`
6. Drop them into a `.env`:

```bash
cp .env.example .env
# fill in IFOOD_ACCESS_TOKEN, IFOOD_ACCOUNT_ID, IFOOD_DEVICE_ID, IFOOD_SESSION_ID
```

##### Claude Desktop

Edit `~/Library/Application Support/Claude/claude_desktop_config.json` (macOS) or `%APPDATA%\Claude\claude_desktop_config.json` (Windows):

```json
{
  "mcpServers": {
    "ifood": {
      "command": "node",
      "args": ["/absolute/path/to/ifood-mcp/build/index.js"],
      "env": {
        "IFOOD_ACCESS_TOKEN": "eyJraWQi...",
        "IFOOD_ACCOUNT_ID": "fa0ac7f3-...",
        "IFOOD_DEVICE_ID": "1141f82b-...",
        "IFOOD_SESSION_ID": "97fe984b-..."
      }
    }
  }
}
```

##### Claude Code (stdio)

```bash
claude mcp add --transport stdio ifood \
  --env IFOOD_ACCESS_TOKEN=eyJraWQi... \
  --env IFOOD_ACCOUNT_ID=fa0ac7f3-... \
  --env IFOOD_DEVICE_ID=1141f82b-... \
  --env IFOOD_SESSION_ID=97fe984b-... \
  -- node /absolute/path/to/ifood-mcp/build/index.js
```

## Available Tools

### 👤 Customer
| Tool | Description |
| --- | --- |
| `ifood_customer_me` | Authenticated customer profile |
| `ifood_addresses` | Saved delivery addresses |
| `ifood_contact_methods` | Verified e‑mails and phones |
| `ifood_external_identities` | Linked identity providers (Google, Apple, OTP) |

### 📦 Orders
| Tool | Description |
| --- | --- |
| `ifood_orders_list` | Past orders, paginated |
| `ifood_order_detail` | Full details of a single order |
| `ifood_reorder` | Pre-fill cart with items from a previous order |

### 🔍 Discovery
| Tool | Description |
| --- | --- |
| `ifood_search` | Search restaurants and items by term + location |
| `ifood_filter_options` | Available search filters (categories, dietary, price) |
| `ifood_home` | Localized home feed |
| `ifood_browse_page` | Curated browse pages linked from the home feed |
| `ifood_categories` | Top-level categories (restaurants, groceries, drugstore, …) |

### 🍔 Merchants
| Tool | Description |
| --- | --- |
| `ifood_merchant_info` | Delivery fees, methods, hours, rating, address |
| `ifood_merchant_catalog` | Full menu with items, prices, add-ons |
| `ifood_item_detail` | Single item details (price, description, options) |
| `ifood_customer_merchant_items` | Customer's previously‑ordered items at a merchant |
| `ifood_reviews` | Customer reviews/ratings, paginated |
| `ifood_merchant_payment_methods` | Payment methods accepted by a specific merchant |

### 🎁 Loyalty & Wallet
| Tool | Description |
| --- | --- |
| `ifood_loyalty_cards` | iFood Club, stamps, etc. |
| `ifood_benefits` | Wallet benefits, coupons and promotions near a location |
| `ifood_payment_methods` | Customer's saved payment methods |

### 🛒 Cart & Checkout
| Tool | Description |
| --- | --- |
| `ifood_cart_create` | Create a new cart with items for a merchant |
| `ifood_cart_set_delivery_method` | DEFAULT / PRIORITY / TAKEOUT |
| `ifood_cart_set_payment_method` | Apply payment method UUIDs to the cart |
| `ifood_checkout` | Place the order (final step) |

## Example Prompts

Once connected, ask your AI assistant:

```
"encontre opções de açaí perto de -23.59182, -46.648688"

"qual é o cardápio da hamburgueria mais bem avaliada na minha região?"

"liste meus 5 últimos pedidos e me mostre o status de cada um"

"crie um carrinho no Burger King com 2 Whoppers e finalize com Pix"

"me mostre as avaliações do restaurante <id> nas últimas 30 reviews"

"existe algum cupom ativo na minha carteira pra delivery agora?"
```

> [!TIP]
> If a tool needs `latitude`/`longitude` and you don't know yours, ask the AI to call `ifood_addresses` first — your saved addresses include coordinates.

## Architecture

```
┌──────────────────┐    OAuth 2.1     ┌─────────────────────┐    Bearer JWT     ┌─────────────────┐
│  AI assistant    │◄────────────────►│   ifood-mcp server  │◄─────────────────►│  iFood API      │
│  (Claude/Cursor) │   /mcp endpoint  │   (Express + MCP)   │   site-api / wsl. │  (consumer web) │
└──────────────────┘                  └─────────────────────┘                   └─────────────────┘
                                              │
                                              ▼
                                      ┌──────────────┐
                                      │  /login      │  HTML — iFood OTP
                                      │  (browser)   │  e‑mail / SMS / WhatsApp
                                      └──────────────┘
```

- **Stateless transport**: each `/mcp` call creates a fresh `StreamableHTTPServerTransport` + `McpServer` bound to the authenticated user's session — handles concurrent users without sticky sessions.
- **In‑memory token stores**: per‑user iFood JWT pairs auto‑refreshed every 60s. Single‑process; for horizontal scaling move to Redis.
- **OAuth 2.1 + PKCE S256**, audience‑bound HS256 JWTs, opaque rotating refresh tokens.
- **5‑step iFood OTP flow** wrapped in `src/http/ifood-auth.ts`: `/authorization-codes` → `/access-tokens` → `/challenges` → `/authentications`.

## Development

```bash
npm run dev          # http-server with auto-reload (tsx watch)
npm run dev:stdio    # stdio with auto-reload
npm run build        # tsc → build/
npm run typecheck    # tsc --noEmit
```

Project layout:

```
src/
  index.ts              tool definitions + executeTool dispatcher + stdio entry
  http-server.ts        Express + OAuth + Streamable HTTP transport
  http/
    store.ts            in-memory OAuth + iFood token stores
    provider.ts         OAuthServerProvider implementation
    session-provider.ts SessionTokenProvider + background refresh loop
    login-router.ts     OTP login HTML pages
    ifood-auth.ts       chained iFood OTP HTTP client
```

## Security & Disclaimer

- 🔒 In HTTP mode, iFood tokens live only in memory — never written to disk. Process restart = re‑login.
- 🚫 Don't commit `.env`, HAR files or any DevTools captures — they contain bearer tokens. The `.gitignore` blocks all common spots.
- ⚠️ **Unofficial**. iFood does not publish a public API. This wraps the consumer website's endpoints, which can change without notice. Use at your own discretion and respect [iFood's Terms of Service](https://www.ifood.com.br/termos-e-politicas).
- 🛡️ The login flow may eventually trip iFood's bot‑detection. If you see opaque errors during login, try the `/login/paste` fallback to provide tokens manually.

## Contributing

Issues and PRs welcome. When opening an issue please include:

- Output of `npm run typecheck`
- Whether you're using stdio or HTTP+OAuth mode
- Redacted request/response (no tokens) when reporting an API failure

## License

Released under the [MIT License](LICENSE).

---

Made by Ari and Claude a.k.a Claudão.
