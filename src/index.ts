#!/usr/bin/env node

import dotenv from "dotenv";
dotenv.config();

import { readFileSync, writeFileSync } from "fs";
import { homedir } from "os";
import { join } from "path";
import { pathToFileURL } from "url";

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
  ListToolsRequestSchema,
  CallToolRequestSchema,
  type Tool,
  type CallToolResult,
  type CallToolRequest,
} from "@modelcontextprotocol/sdk/types.js";

import axios, { type AxiosError } from "axios";

export interface McpToolDefinition {
  name: string;
  description: string;
  inputSchema: Record<string, unknown>;
  method: string;
  pathTemplate: string;
  /** "main" = www.ifood.com.br/site-api, "wsloja" = wsloja.ifood.com.br/ifood-ws-v3 */
  baseUrl: "main" | "wsloja";
  pathParams?: string[];
  queryParams?: string[];
  bodyParams?: string[];
  /** Send args[bodyUnwrap] as the raw request body (unwrapped). Overrides bodyParams. */
  bodyUnwrap?: string;
  requiresAuth: boolean;
  /** Adds access_key / secret_key headers (required for cart & checkout operations). */
  requiresAccessKey?: boolean;
  /** Adds x-ifood-device-payment-secret header (required for checkout). */
  requiresDevicePaymentSecret?: boolean;
}

export const MAIN_URL =
  process.env.IFOOD_MAIN_URL || "https://www.ifood.com.br/site-api";
const WSLOJA_URL =
  process.env.IFOOD_WSLOJA_URL || "https://wsloja.ifood.com.br/ifood-ws-v3";

export interface TokenProvider {
  getValidToken(): Promise<{
    token: string | null;
    accountId: string;
    deviceId?: string;
    sessionId?: string;
    error?: string;
  }>;
}

const TOKEN_FILE = join(homedir(), ".ifood-tokens.json");

function loadPersistedTokens(): { accessToken: string } {
  try {
    const raw = readFileSync(TOKEN_FILE, "utf-8");
    return JSON.parse(raw);
  } catch {
    return { accessToken: "" };
  }
}

function persistTokens(tokens: { accessToken: string }) {
  try {
    writeFileSync(TOKEN_FILE, JSON.stringify(tokens, null, 2), "utf-8");
  } catch {
    // best-effort
  }
}

function jwtExp(token: string): number {
  try {
    const payload = token.split(".")[1];
    const decoded = JSON.parse(Buffer.from(payload, "base64url").toString());
    return decoded.exp ?? 0;
  } catch {
    return 0;
  }
}

function isTokenExpired(token: string, marginSec = 30): boolean {
  if (!token) return true;
  const exp = jwtExp(token);
  return Date.now() / 1000 >= exp - marginSec;
}

function getAccessToken(): string {
  const persisted = loadPersistedTokens();
  if (persisted.accessToken && !isTokenExpired(persisted.accessToken)) {
    return persisted.accessToken;
  }
  const envToken = process.env.IFOOD_ACCESS_TOKEN || "";
  if (envToken && !isTokenExpired(envToken)) {
    return envToken;
  }
  return envToken; // return even if expired so we get a proper 401
}

function getDefaultHeaders(opts: {
  accountId: string;
  deviceId?: string;
  sessionId?: string;
}): Record<string, string> {
  const deviceId = opts.deviceId || process.env.IFOOD_DEVICE_ID || "";
  const sessionId = opts.sessionId || process.env.IFOOD_SESSION_ID || "";
  const accountId = opts.accountId;
  const clientKey =
    process.env.IFOOD_CLIENT_KEY || "41a266ee-51b7-4c37-9e9d-5cd331f280d5";

  return {
    accept: "application/json, text/plain, */*",
    "accept-language": "pt-BR,pt;q=1",
    account_id: accountId,
    app_version: "9.141.4",
    browser: "Mac OS",
    "cache-control": "no-cache, no-store",
    platform: "Desktop",
    "user-agent":
      "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/147.0.0.0 Safari/537.36",
    "x-client-application-key": clientKey,
    "x-device-model": "Macintosh Brave",
    "x-ifood-device-id": deviceId,
    "x-ifood-session-id": sessionId,
    "x-ifood-user-id": accountId,
  };
}

export class EnvTokenProvider implements TokenProvider {
  async getValidToken(): Promise<{ token: string | null; accountId: string; error?: string }> {
    const token = getAccessToken();
    const accountId = process.env.IFOOD_ACCOUNT_ID || "";
    if (!token) {
      return {
        token: null,
        accountId,
        error: "Not authenticated. Set IFOOD_ACCESS_TOKEN in the .env file.",
      };
    }
    return { token, accountId };
  }
}

const defaultProvider = new EnvTokenProvider();

// Body sent on POST /v2/cardstack/search/results — declares which card types the
// client can render. iFood returns empty results if this is missing.
const SEARCH_BODY = {
  "supported-headers": ["OPERATION_HEADER"],
  "supported-cards": [
    "MERCHANT_LIST",
    "CATALOG_ITEM_LIST",
    "CATALOG_ITEM_LIST_V2",
    "CATALOG_ITEM_LIST_V3",
    "FEATURED_MERCHANT_LIST",
    "CATALOG_ITEM_CAROUSEL",
    "CATALOG_ITEM_CAROUSEL_V2",
    "CATALOG_ITEM_CAROUSEL_V3",
    "BIG_BANNER_CAROUSEL",
    "IMAGE_BANNER",
    "MERCHANT_LIST_WITH_ITEMS_CAROUSEL",
    "SMALL_BANNER_CAROUSEL",
    "NEXT_CONTENT",
    "MERCHANT_CAROUSEL",
    "MERCHANT_TILE_CAROUSEL",
    "SIMPLE_MERCHANT_CAROUSEL",
    "INFO_CARD",
    "MERCHANT_LIST_V2",
    "ROUND_IMAGE_CAROUSEL",
    "BANNER_GRID",
    "MEDIUM_IMAGE_BANNER",
    "MEDIUM_BANNER_CAROUSEL",
    "RELATED_SEARCH_CAROUSEL",
    "ADS_BANNER",
  ],
  "supported-actions": [
    "catalog-item",
    "item-details",
    "merchant",
    "page",
    "card-content",
    "last-restaurants",
    "webmiddleware",
    "reorder",
    "search",
    "groceries",
    "groceries-details",
    "home-tab",
  ],
  "feed-feature-name": "",
  "faster-overrides": "",
};

// GraphQL query used by ifood_merchant_info — returns full merchant + merchantExtra data
const MERCHANT_INFO_QUERY = `query ($merchantId: String!) { merchant (merchantId: $merchantId, required: true) { available availableForScheduling contextSetup { catalogGroup context regionGroup } currency deliveryFee { originalValue type value } deliveryMethods { catalogGroup deliveredBy id maxTime minTime mode originalValue priority schedule { now shifts { dayOfWeek endTime interval startTime } timeSlots { availableLoad date endDateTime endTime id isAvailable originalPrice price startDateTime startTime } } subtitle title type value state } deliveryTime distance features id mainCategory { code name } minimumOrderValue name paymentCodes preparationTime priceRange resources { fileName type } slug tags takeoutTime userRating } merchantExtra (merchantId: $merchantId, required: false) { address { city country district latitude longitude state streetName streetNumber timezone zipCode } categories { code description friendlyName } companyCode configs { bagItemNoteLength chargeDifferentToppingsMode nationalIdentificationNumberRequired orderNoteLength } deliveryTime description documents { CNPJ { type value } MCC { type value } } enabled features groups { externalId id name type } id locale mainCategory { code description friendlyName } merchantChain { externalId id name } minimumOrderValue minimumOrderValueV2 name phoneIf priceRange resources { fileName type } shifts { dayOfWeek duration start } shortId tags takeoutTime test type userRatingCount } }`;

export const toolDefinitions: McpToolDefinition[] = [
  // ─── Customer ────────────────────────────────────────────────────────────────
  {
    name: "ifood_customer_me",
    description: "Get the authenticated customer's profile (name, email, phone, addresses).",
    inputSchema: { type: "object", properties: {} },
    method: "get",
    pathTemplate: "/v1/customers/me",
    baseUrl: "main",
    requiresAuth: true,
  },

  {
    name: "ifood_addresses",
    description: "List the customer's saved delivery addresses.",
    inputSchema: { type: "object", properties: {} },
    method: "get",
    pathTemplate: "/v1/customers/me/addresses",
    baseUrl: "main",
    requiresAuth: true,
  },
  {
    name: "ifood_contact_methods",
    description: "List the customer's verified contact methods (emails and phone numbers).",
    inputSchema: { type: "object", properties: {} },
    method: "get",
    pathTemplate: "/v1/customers/me/contact-methods",
    baseUrl: "main",
    requiresAuth: true,
  },
  {
    name: "ifood_external_identities",
    description: "List the customer's external identity providers (OTP_EMAIL, OTP_PHONE, GOOGLE, etc.).",
    inputSchema: { type: "object", properties: {} },
    method: "get",
    pathTemplate: "/v1/customers/me/external-identities",
    baseUrl: "main",
    requiresAuth: true,
  },

  // ─── Orders ──────────────────────────────────────────────────────────────────
  {
    name: "ifood_orders_list",
    description: "List the customer's past orders with optional pagination.",
    inputSchema: {
      type: "object",
      properties: {
        page: { type: "number", description: "Page number (default 0)" },
        size: { type: "number", description: "Results per page (default 10, max 50)" },
      },
    },
    method: "get",
    pathTemplate: "/v4/customers/me/orders",
    baseUrl: "main",
    queryParams: ["page", "size"],
    requiresAuth: true,
  },
  {
    name: "ifood_order_detail",
    description: "Get full details of a single order (items, totals, payment, delivery, status history).",
    inputSchema: {
      type: "object",
      properties: {
        orderId: { type: "string", description: "Order UUID" },
      },
      required: ["orderId"],
    },
    method: "get",
    pathTemplate: "/v3/customers/me/orders/{orderId}",
    baseUrl: "main",
    pathParams: ["orderId"],
    requiresAuth: true,
  },
  {
    name: "ifood_reorder",
    description: "Get items from a previous order ready for reorder. Returns pre-filled cart data.",
    inputSchema: {
      type: "object",
      properties: {
        orderId: { type: "string", description: "Previous order UUID" },
        lat: { type: "number", description: "Delivery latitude" },
        lon: { type: "number", description: "Delivery longitude" },
      },
      required: ["orderId"],
    },
    method: "get",
    pathTemplate: "/v1/customers/me/orders/{orderId}/reorder",
    baseUrl: "main",
    pathParams: ["orderId"],
    queryParams: ["lat", "lon"],
    requiresAuth: true,
  },

  // ─── Loyalty ─────────────────────────────────────────────────────────────────
  {
    name: "ifood_loyalty_cards",
    description: "List the customer's loyalty cards (iFood Club, stamps, etc.).",
    inputSchema: { type: "object", properties: {} },
    method: "get",
    pathTemplate: "/v1/customers/me/loyalty-cards",
    baseUrl: "main",
    requiresAuth: true,
  },

  // ─── Benefits & Coupons ──────────────────────────────────────────────────────
  {
    name: "ifood_benefits",
    description: "List wallet benefits, coupons and promotions near a location. Optionally filter by merchant.",
    inputSchema: {
      type: "object",
      properties: {
        lat: { type: "number", description: "Delivery latitude" },
        lon: { type: "number", description: "Delivery longitude" },
        distanceInKm: { type: "number", description: "Search radius in km (default 10)" },
        merchantId: { type: "string", description: "Optional: filter coupons for a specific merchant UUID" },
      },
    },
    method: "get",
    pathTemplate: "/v3/customers/me/wallet/benefits",
    baseUrl: "main",
    queryParams: ["lat", "lon", "distanceInKm", "merchantId"],
    requiresAuth: true,
  },

  // ─── Search ──────────────────────────────────────────────────────────────────
  {
    name: "ifood_search",
    description: "Search for restaurants or food items near a delivery location.",
    inputSchema: {
      type: "object",
      properties: {
        term: { type: "string", description: "Search query, e.g. 'pizza', 'açaí', 'sushi'" },
        latitude: { type: "number", description: "Delivery latitude" },
        longitude: { type: "number", description: "Delivery longitude" },
        size: { type: "number", description: "Number of results to return (default 20)" },
      },
      required: ["term", "latitude", "longitude"],
    },
    method: "post",
    pathTemplate: "/v2/cardstack/search/results",
    baseUrl: "main",
    queryParams: ["term", "latitude", "longitude", "size"],
    bodyUnwrap: "_searchBody",
    requiresAuth: true,
  },
  {
    name: "ifood_filter_options",
    description: "Get available search filter options (categories, dietary restrictions, price range, etc.).",
    inputSchema: { type: "object", properties: {} },
    method: "get",
    pathTemplate: "/v6/filter-options/IFOOD/BR",
    baseUrl: "main",
    requiresAuth: true,
  },

  // ─── Merchant ────────────────────────────────────────────────────────────────
  {
    name: "ifood_merchant_info",
    description: "Get detailed merchant info: delivery fees, methods, hours, rating, address, menu categories.",
    inputSchema: {
      type: "object",
      properties: {
        merchantId: { type: "string", description: "Merchant UUID" },
        latitude: { type: "number", description: "Delivery latitude (improves fee accuracy)" },
        longitude: { type: "number", description: "Delivery longitude (improves fee accuracy)" },
      },
      required: ["merchantId"],
    },
    method: "post",
    pathTemplate: "/v1/merchant-info/graphql",
    baseUrl: "main",
    queryParams: ["latitude", "longitude"],
    bodyUnwrap: "_graphql",
    requiresAuth: true,
  },
  {
    name: "ifood_item_detail",
    description: "Get a single catalog item's full details (price, description, options, sub-items).",
    inputSchema: {
      type: "object",
      properties: {
        merchantId: { type: "string", description: "Merchant UUID" },
        itemId: { type: "string", description: "Item UUID from the catalog" },
      },
      required: ["merchantId", "itemId"],
    },
    method: "get",
    pathTemplate: "/v1/merchants/restaurant/{merchantId}/items/{itemId}",
    baseUrl: "main",
    pathParams: ["merchantId", "itemId"],
    requiresAuth: true,
  },
  {
    name: "ifood_customer_merchant_items",
    description: "List items the customer has previously ordered at a specific merchant (favorites/history).",
    inputSchema: {
      type: "object",
      properties: {
        merchantId: { type: "string", description: "Merchant UUID" },
      },
      required: ["merchantId"],
    },
    method: "get",
    pathTemplate: "/v1/customers/me/merchants/{merchantId}/items",
    baseUrl: "main",
    pathParams: ["merchantId"],
    requiresAuth: true,
  },
  {
    name: "ifood_reviews",
    description: "List a merchant's customer reviews/ratings, paginated.",
    inputSchema: {
      type: "object",
      properties: {
        merchantId: { type: "string", description: "Merchant UUID (restaurantUuid)" },
        page: { type: "number", description: "Page number (default 1)" },
        pageSize: { type: "number", description: "Page size (default 30)" },
      },
      required: ["merchantId"],
    },
    method: "get",
    pathTemplate: "/v1/review/evaluations",
    baseUrl: "main",
    queryParams: ["filterJson"],
    requiresAuth: true,
  },
  {
    name: "ifood_home",
    description: "Get the localized home feed (carousels, banners, restaurants near you).",
    inputSchema: {
      type: "object",
      properties: {
        latitude: { type: "number", description: "Delivery latitude" },
        longitude: { type: "number", description: "Delivery longitude" },
        alias: {
          type: "string",
          description: "Home variant alias (e.g. HOME_MULTICATEGORY, HOME_FOOD_DELIVERY_V3, HOME_GROCERIES_V3). Default: HOME_MULTICATEGORY",
        },
        size: { type: "number", description: "Number of cards (default 20)" },
      },
      required: ["latitude", "longitude"],
    },
    method: "get",
    pathTemplate: "/v2/bm/home",
    baseUrl: "main",
    queryParams: ["latitude", "longitude", "alias", "size"],
    requiresAuth: true,
  },
  {
    name: "ifood_browse_page",
    description: "Fetch a specific browse page (linked from home feed cards). Returns the page's content layout.",
    inputSchema: {
      type: "object",
      properties: {
        pageId: { type: "string", description: "Page UUID (from home feed card)" },
        latitude: { type: "number", description: "Delivery latitude" },
        longitude: { type: "number", description: "Delivery longitude" },
      },
      required: ["pageId", "latitude", "longitude"],
    },
    method: "get",
    pathTemplate: "/v1/bm/page/{pageId}",
    baseUrl: "main",
    pathParams: ["pageId"],
    queryParams: ["latitude", "longitude"],
    requiresAuth: true,
  },
  {
    name: "ifood_categories",
    description: "List top-level categories available in the location (restaurants, groceries, drugstore, etc.).",
    inputSchema: {
      type: "object",
      properties: {
        latitude: { type: "number", description: "Delivery latitude" },
        longitude: { type: "number", description: "Delivery longitude" },
      },
      required: ["latitude", "longitude"],
    },
    method: "get",
    pathTemplate: "/v2/categories",
    baseUrl: "main",
    queryParams: ["latitude", "longitude"],
    requiresAuth: true,
  },
  {
    name: "ifood_merchant_catalog",
    description: "Get a merchant's full food catalog with items, prices, add-ons and categories.",
    inputSchema: {
      type: "object",
      properties: {
        merchantId: { type: "string", description: "Merchant UUID" },
        latitude: { type: "number", description: "Delivery latitude" },
        longitude: { type: "number", description: "Delivery longitude" },
      },
      required: ["merchantId"],
    },
    method: "get",
    pathTemplate: "/v1/merchants/restaurant/{merchantId}/catalog",
    baseUrl: "main",
    pathParams: ["merchantId"],
    queryParams: ["latitude", "longitude"],
    requiresAuth: true,
  },

  // ─── Payment Methods ─────────────────────────────────────────────────────────
  {
    name: "ifood_payment_methods",
    description: "List the customer's available wallet payment methods (credit card, PIX, etc.).",
    inputSchema: { type: "object", properties: {} },
    method: "get",
    pathTemplate: "/v1/payments/br/wallet/payment-methods",
    baseUrl: "main",
    requiresAuth: true,
  },
  {
    name: "ifood_merchant_payment_methods",
    description: "List payment methods accepted by a specific merchant.",
    inputSchema: {
      type: "object",
      properties: {
        merchantId: { type: "string", description: "Merchant UUID" },
        tags: {
          type: "string",
          description: "Filter tag, e.g. 'delivered_by_ifood' (default)",
        },
      },
      required: ["merchantId"],
    },
    method: "get",
    pathTemplate: "/v1/merchants/{merchantId}/payment-methods",
    baseUrl: "main",
    pathParams: ["merchantId"],
    queryParams: ["tags"],
    requiresAuth: true,
  },

  // ─── Cart ────────────────────────────────────────────────────────────────────
  {
    name: "ifood_cart_create",
    description:
      "Create a new cart with items for a merchant. Returns the cartId and full cart response used in subsequent cart operations.",
    inputSchema: {
      type: "object",
      properties: {
        merchant: {
          type: "object",
          description: "Merchant info",
          properties: {
            id: { type: "string", description: "Merchant UUID" },
            name: { type: "string" },
          },
          required: ["id"],
        },
        address: {
          type: "object",
          description: "Delivery address",
          properties: {
            id: { type: "string", description: "Address UUID from customer profile" },
            coordinates: {
              type: "object",
              properties: {
                latitude: { type: "number" },
                longitude: { type: "number" },
              },
            },
            streetName: { type: "string" },
            streetNumber: { type: "string" },
            neighborhood: { type: "string" },
            complement: { type: "string" },
            state: { type: "string" },
            city: { type: "string" },
            zipCode: { type: "string" },
          },
        },
        items: {
          type: "array",
          description: "Items to add to the cart",
          items: {
            type: "object",
            properties: {
              id: { type: "string", description: "Item UUID from catalog" },
              quantity: { type: "number" },
              observation: { type: "string", description: "Special instructions" },
              subItems: {
                type: "array",
                description: "Add-ons or options",
                items: { type: "object" },
              },
            },
            required: ["id", "quantity"],
          },
        },
        delivery: {
          type: "object",
          description: "Delivery method",
          properties: {
            id: {
              type: "string",
              enum: ["DEFAULT", "PRIORITY", "TAKEOUT"],
              description: "Delivery method ID",
            },
            now: { type: "boolean", description: "Deliver ASAP (default true)" },
            deliveryBy: { type: "string", description: "Provider, e.g. IFOOD" },
          },
        },
        account: {
          type: "object",
          description: "Customer account info",
          properties: {
            id: { type: "string", description: "Account UUID" },
            name: { type: "string" },
            email: { type: "string" },
            phone: {
              type: "object",
              properties: {
                countryCode: { type: "number" },
                areaCode: { type: "number" },
                number: { type: "string" },
              },
            },
          },
        },
      },
      required: ["merchant", "items"],
    },
    method: "post",
    pathTemplate: "/v1/carts",
    baseUrl: "main",
    bodyUnwrap: "_cartBody",
    requiresAuth: true,
    requiresAccessKey: true,
  },
  {
    name: "ifood_cart_set_delivery_method",
    description: "Set the delivery method on an existing cart (DEFAULT = standard, PRIORITY = express, TAKEOUT = pickup).",
    inputSchema: {
      type: "object",
      properties: {
        cartId: { type: "string", description: "Cart UUID returned by ifood_cart_create" },
        id: {
          type: "string",
          enum: ["DEFAULT", "PRIORITY", "TAKEOUT"],
          description: "Delivery method ID",
        },
        now: { type: "boolean", description: "Deliver now (default true)" },
        deliveryBy: { type: "string", description: "Provider (default IFOOD)" },
      },
      required: ["cartId", "id"],
    },
    method: "put",
    pathTemplate: "/v1/carts/{cartId}/deliveryMethod",
    baseUrl: "main",
    pathParams: ["cartId"],
    bodyParams: ["id", "now", "deliveryBy"],
    requiresAuth: true,
    requiresAccessKey: true,
  },
  {
    name: "ifood_cart_set_payment_method",
    description: "Set the payment method on an existing cart using payment method IDs from ifood_payment_methods.",
    inputSchema: {
      type: "object",
      properties: {
        cartId: { type: "string", description: "Cart UUID" },
        paymentMethods: {
          type: "array",
          description: "Array of payment method UUIDs",
          items: { type: "string" },
        },
      },
      required: ["cartId", "paymentMethods"],
    },
    method: "put",
    pathTemplate: "/v1/carts/{cartId}/paymentMethod",
    baseUrl: "main",
    pathParams: ["cartId"],
    bodyUnwrap: "paymentMethods",
    requiresAuth: true,
    requiresAccessKey: true,
  },

  // ─── Checkout ────────────────────────────────────────────────────────────────
  {
    name: "ifood_checkout",
    description:
      "Place the order (checkout). Provide the full checkout payload including paymentSources, signature and cartRequest (the stringified cart response from ifood_cart_create).",
    inputSchema: {
      type: "object",
      properties: {
        cartId: { type: "string", description: "Cart UUID" },
        checkoutPayload: {
          type: "object",
          description:
            "Full checkout payload: { paymentSources: { sources, contextInfo }, signature, cartRequest }",
        },
      },
      required: ["cartId", "checkoutPayload"],
    },
    method: "post",
    pathTemplate: "/v1/carts/{cartId}/checkout",
    baseUrl: "wsloja",
    pathParams: ["cartId"],
    bodyUnwrap: "checkoutPayload",
    requiresAuth: true,
    requiresAccessKey: true,
    requiresDevicePaymentSecret: true,
  },
];

const toolMap = new Map(toolDefinitions.map((t) => [t.name, t]));

function buildPath(template: string, args: Record<string, unknown>): string {
  let path = template;
  const matches = template.match(/\{([^}]+)\}/g);
  if (matches) {
    for (const m of matches) {
      const key = m.slice(1, -1);
      const val = args[key];
      if (val !== undefined && val !== null) {
        path = path.replace(m, String(val));
      }
    }
  }
  return path;
}

function buildQuery(
  def: McpToolDefinition,
  args: Record<string, unknown>
): Record<string, string> {
  const params: Record<string, string> = {};
  for (const key of def.queryParams || []) {
    const val = args[key];
    if (val !== undefined && val !== null && val !== "") {
      params[key] = String(val);
    }
  }
  // Inject static query params per tool
  if (def.name === "ifood_search") {
    params.alias = "SEARCH_RESULTS_MERCHANT_TAB_GLOBAL";
    params.channel = "IFOOD";
    if (!params.size) params.size = "20";
  }
  if (def.name === "ifood_merchant_info") {
    params.channel = "IFOOD";
  }
  if (def.name === "ifood_home") {
    params.channel = "IFOOD";
    if (!params.alias) params.alias = "HOME_MULTICATEGORY";
    if (!params.size) params.size = "20";
  }
  if (def.name === "ifood_browse_page" || def.name === "ifood_categories") {
    params.channel = "IFOOD";
  }
  if (def.name === "ifood_reviews") {
    const filter = {
      restaurantUuid: String(args.merchantId ?? ""),
      page: Number(args.page ?? 1),
      pageSize: Number(args.pageSize ?? 30),
      visible: true,
    };
    params.filterJson = JSON.stringify(filter);
  }
  return params;
}

function buildBody(
  def: McpToolDefinition,
  args: Record<string, unknown>
): Record<string, unknown> | undefined {
  if (!def.bodyParams || def.bodyParams.length === 0) return undefined;
  const body: Record<string, unknown> = {};
  for (const key of def.bodyParams) {
    const val = args[key];
    if (val !== undefined) {
      body[key] = val;
    }
  }
  return Object.keys(body).length > 0 ? body : undefined;
}

export async function executeTool(
  def: McpToolDefinition,
  args: Record<string, unknown>,
  tokenProvider: TokenProvider = defaultProvider
): Promise<CallToolResult> {
  const baseUrl = def.baseUrl === "wsloja" ? WSLOJA_URL : MAIN_URL;
  const url = `${baseUrl}${buildPath(def.pathTemplate, args)}`;
  const query = buildQuery(def, args);
  const body = buildBody(def, args);

  const { token, accountId, deviceId, sessionId, error } = await tokenProvider.getValidToken();
  if (def.requiresAuth && !token) {
    return {
      content: [
        {
          type: "text",
          text: error ?? "Not authenticated.",
        },
      ],
      isError: true,
    };
  }

  const headers: Record<string, string> = {
    ...getDefaultHeaders({ accountId, deviceId, sessionId }),
    "content-type": "application/json",
  };

  if (def.requiresAuth && token) {
    headers["authorization"] = `Bearer ${token}`;
  }

  if (def.requiresAccessKey) {
    const accessKey = process.env.IFOOD_ACCESS_KEY || "";
    const secretKey = process.env.IFOOD_SECRET_KEY || "";
    if (accessKey) headers["access_key"] = accessKey;
    if (secretKey) headers["secret_key"] = secretKey;
  }

  if (def.requiresDevicePaymentSecret) {
    const secret = process.env.IFOOD_DEVICE_PAYMENT_SECRET || "";
    if (secret) headers["x-ifood-device-payment-secret"] = secret;
    headers["x-ifood-customer-id"] = accountId;
  }

  // Per-tool extra headers
  if (def.name === "ifood_search") {
    headers["country"] = "BR";
    headers["origin"] = "https://www.ifood.com.br";
    headers["referer"] = `https://www.ifood.com.br/busca?q=${encodeURIComponent(String(args.term ?? ""))}`;
  }

  const config: {
    method: string;
    url: string;
    params?: Record<string, string>;
    data?: unknown;
    headers: Record<string, string>;
  } = { method: def.method, url, headers };

  if (Object.keys(query).length > 0) config.params = query;

  if (["post", "put", "patch"].includes(def.method.toLowerCase())) {
    if (def.bodyUnwrap === "_graphql") {
      // Build GraphQL payload for ifood_merchant_info
      config.data = {
        query: MERCHANT_INFO_QUERY,
        variables: { merchantId: args.merchantId },
      };
    } else if (def.bodyUnwrap === "_searchBody") {
      config.data = SEARCH_BODY;
    } else if (def.bodyUnwrap === "_cartBody") {
      // Assemble cart body from individual top-level args
      const cartBody: Record<string, unknown> = {};
      if (args.merchant) cartBody.merchant = args.merchant;
      if (args.address) cartBody.address = args.address;
      if (args.items) cartBody.items = args.items;
      if (args.delivery) cartBody.delivery = args.delivery;
      if (args.account) cartBody.account = args.account;
      config.data = cartBody;
    } else if (def.bodyUnwrap) {
      const raw = args[def.bodyUnwrap];
      if (raw !== undefined) config.data = raw;
    } else if (body) {
      config.data = body;
    }
  }

  try {
    const res = await axios(config);

    // Persist fresh token if provided in response (future-proof)
    const newToken =
      res.data?.accessToken || res.data?.access_token;
    if (newToken) {
      persistTokens({ accessToken: newToken });
    }

    return {
      content: [{ type: "text", text: JSON.stringify(res.data, null, 2) }],
    };
  } catch (err) {
    const axErr = err as AxiosError<{
      message?: string;
      error?: string;
      description?: string;
    }>;
    const status = axErr.response?.status;
    const data = axErr.response?.data;
    const msg =
      data?.message ||
      data?.error ||
      data?.description ||
      axErr.message ||
      "Unknown error";

    if (status === 401) {
      return {
        content: [
          {
            type: "text",
            text: "Authentication failed (401). The iFood token has expired — re-authenticate via the login page or update IFOOD_ACCESS_TOKEN in .env.",
          },
        ],
        isError: true,
      };
    }

    console.error(
      `[ifood-mcp] FAIL tool=${def.name} ${def.method.toUpperCase()} ${url} status=${status ?? "network"} msg="${msg}"`
    );
    return {
      content: [
        {
          type: "text",
          text: `API Error (${status ?? "unknown"}): ${msg}`,
        },
      ],
      isError: true,
    };
  }
}

const mcpServer = new McpServer(
  { name: "@aol/ifood-mcp", version: "1.0.0" },
  { capabilities: { tools: {} } }
);

const server = mcpServer.server;

server.setRequestHandler(ListToolsRequestSchema, async () => {
  const tools: Tool[] = toolDefinitions.map((def) => ({
    name: def.name,
    description: def.description,
    inputSchema: { type: "object" as const, ...def.inputSchema },
  }));
  return { tools };
});

server.setRequestHandler(
  CallToolRequestSchema,
  async (request: CallToolRequest) => {
    const { name, arguments: args } = request.params;
    const def = toolMap.get(name);
    if (!def) {
      return {
        content: [{ type: "text", text: `Unknown tool: ${name}` }],
        isError: true,
      };
    }
    const safeArgs = (args as Record<string, unknown>) || {};
    console.error(`[ifood-mcp] tools/call name=${name}`);
    return executeTool(def, safeArgs);
  }
);

export async function main() {
  const transport = new StdioServerTransport();
  await mcpServer.connect(transport);
}

const isEntrypoint = (() => {
  try {
    const entry = process.argv[1];
    if (!entry) return false;
    return import.meta.url === pathToFileURL(entry).href;
  } catch {
    return false;
  }
})();

if (isEntrypoint) {
  main().catch((err) => {
    console.error(err);
    process.exit(1);
  });
}
