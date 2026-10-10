import { test } from "node:test";
import assert from "node:assert/strict";

import {
  assertIfoodUrl,
  encodePathSegment,
  minimizePii,
  redactSecrets,
  validateToolArgs,
  RateLimiter,
} from "../src/security.js";
import { toolDefinitions, executeTool, toolAnnotations } from "../src/index.js";
import { isAcceptableRedirectUri } from "../src/http/store.js";

const def = (name: string) => toolDefinitions.find((t) => t.name === name)!;

test("assertIfoodUrl only allows https ifood.com.br", () => {
  assert.equal(assertIfoodUrl("x", "https://www.ifood.com.br/site-api/"), "https://www.ifood.com.br/site-api");
  assert.throws(() => assertIfoodUrl("x", "http://www.ifood.com.br"));
  assert.throws(() => assertIfoodUrl("x", "https://ifood.com.br.evil.com"));
  assert.throws(() => assertIfoodUrl("x", "https://evilifood.com.br"));
  assert.throws(() => assertIfoodUrl("x", "not a url"));
});

test("redactSecrets strips JWTs, bearer tokens and key/value secrets", () => {
  const jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abcdefghijk";
  assert.ok(!redactSecrets(`oops ${jwt}`).includes(jwt));
  assert.ok(!redactSecrets("Authorization: Bearer abc.def.ghi").includes("abc.def.ghi"));
  assert.ok(!redactSecrets('{"refresh_token":"s3cr3t"}').includes("s3cr3t"));
  assert.ok(redactSecrets("x".repeat(1000)).length <= 301);
});

test("minimizePii masks documents, cards, contacts and removes credentials", () => {
  const out = minimizePii(
    {
      cpf: "123.456.789-00",
      email: "maria@example.com",
      phone: "11999990000",
      accessToken: "abc",
      card: { cardNumber: "4111111111111111", brand: "VISA", lastDigits: "1111" },
      address: { streetName: "Rua A" },
    },
    "standard"
  ) as any;
  assert.equal(out.cpf, "[REDACTED]");
  assert.equal(out.email, "m***@example.com");
  assert.equal(out.phone, "***00");
  assert.equal(out.accessToken, "[REDACTED]");
  assert.equal(out.card.cardNumber, "[REDACTED]");
  assert.equal(out.card.brand, "VISA");
  assert.equal(out.address.streetName, "Rua A");
  const off = minimizePii({ cpf: "1", accessToken: "t" }, "off") as any;
  assert.equal(off.cpf, "1");
  assert.equal(off.accessToken, "[REDACTED]");
});

test("validateToolArgs rejects traversal ids, unknown props, bad ranges", () => {
  const s = def("ifood_order_detail").inputSchema;
  assert.deepEqual(validateToolArgs(s, { orderId: "3f2b9c1e-1111-2222-3333-444455556666" }), []);
  assert.ok(validateToolArgs(s, { orderId: "../../v1/customers/me" }).length > 0);
  assert.ok(validateToolArgs(s, { orderId: "a?b=c" }).length > 0);
  assert.ok(validateToolArgs(s, {}).length > 0);
  assert.ok(validateToolArgs(s, { orderId: "abc", extra: 1 }).length > 0);
  const search = def("ifood_search").inputSchema;
  assert.ok(validateToolArgs(search, { term: "pizza", latitude: 200, longitude: 0 }).length > 0);
  assert.ok(validateToolArgs(search, { term: "pizza", latitude: 1, longitude: 1, size: 9999 }).length > 0);
  assert.deepEqual(validateToolArgs(search, { term: "pizza", latitude: -23.5, longitude: -46.6 }), []);
});

test("encodePathSegment blocks traversal", () => {
  assert.throws(() => encodePathSegment(".."));
  assert.throws(() => encodePathSegment("a/b"));
  assert.equal(encodePathSegment("a b"), "a%20b");
});

test("executeTool rejects invalid args before any network/token use", async () => {
  let called = false;
  const provider = {
    async getValidToken() {
      called = true;
      return { token: "t", accountId: "a" };
    },
  };
  const r = await executeTool(def("ifood_order_detail"), { orderId: "../x" }, provider);
  assert.equal(r.isError, true);
  assert.equal(called, false);
});

test("checkout requires explicit confirmation", async () => {
  const provider = { async getValidToken() { return { token: "t", accountId: "a" }; } };
  const r = await executeTool(
    def("ifood_checkout"),
    { cartId: "abc", checkoutPayload: {}, confirmedByUser: false },
    provider
  );
  assert.equal(r.isError, true);
  assert.match((r.content[0] as { text: string }).text, /approval/i);
  assert.equal(toolAnnotations(def("ifood_checkout")).destructiveHint, true);
  assert.equal(toolAnnotations(def("ifood_customer_me")).readOnlyHint, true);
});

test("redirect URI policy", () => {
  assert.ok(isAcceptableRedirectUri("https://claude.ai/api/mcp/auth_callback"));
  assert.ok(isAcceptableRedirectUri("http://localhost:6274/cb"));
  assert.ok(isAcceptableRedirectUri("cursor://anysphere.cursor-retrieval/oauth/callback"));
  assert.ok(!isAcceptableRedirectUri("http://evil.com/cb"));
  assert.ok(!isAcceptableRedirectUri("javascript:alert(1)"));
  assert.ok(!isAcceptableRedirectUri("https://user:pw@example.com/cb"));
  assert.ok(!isAcceptableRedirectUri("https://example.com/cb#frag"));
});

test("RateLimiter enforces window", () => {
  const rl = new RateLimiter(2, 60_000);
  assert.ok(rl.take("a") && rl.take("a"));
  assert.ok(!rl.take("a"));
  assert.ok(rl.take("b"));
});
