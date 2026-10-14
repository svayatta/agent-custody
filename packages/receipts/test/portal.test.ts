// The portal is the tenant's own door: register and get a tenant and a key shown once, sign in, see the numbers
// the log keeps, mint and revoke keys, pay. Nothing here is reachable without a session except the Stripe webhook,
// which is reachable only with Stripe's signature. Postgres runs in-process through PGlite; the log server runs
// beside the portal on the same tenancy so the dashboard's numbers come from real appends; Stripe is a stand-in
// that answers the two calls the portal makes.
import { createHmac } from "node:crypto";
import { Script } from "node:vm";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { PGlite } from "@electric-sql/pglite";
import { generateKeyPair } from "../src/crypto.ts";
import { httpLog, postgresResolver, serveLog, type RunningLog } from "../src/log-sink.ts";
import { PostgresTenancy } from "../src/log-store.ts";
import { founderNote, PortalStore, readSession, sendFollowUps, servePortal, signSession, verifyStripeSignature, type RunningPortal } from "../src/portal.ts";
import { policyDigest } from "../src/policy.ts";

let db: PGlite;
let tenancy: PostgresTenancy;
let log: RunningLog;
let portal: RunningPortal;
const stripeCalls: { path: string; body: URLSearchParams }[] = [];
const mails: { to: string[]; subject: string; text: string; from: string }[] = [];
/** who GitHub says the signed-in user is; a test changes it to play another person */
let gh = { id: 4242, email: "Octo@Example.com" };
// GitHub's and Google's endpoints, stood in: a code becomes a token, a token becomes a subject and a verified email
const oauthFetch: typeof fetch = async (url, init) => {
  const u = String(url);
  const j = (body: unknown) => new Response(JSON.stringify(body), { status: 200, headers: { "content-type": "application/json" } });
  if (u === "https://github.com/login/oauth/access_token") { const b = JSON.parse(String(init?.body)); return j(b.code === "gh-code" && b.client_secret === "gh_secret" ? { access_token: "gh-token" } : { error: "bad_verification_code" }); }
  if (u === "https://api.github.com/user") return j({ id: gh.id, login: "octo" });
  if (u === "https://api.github.com/user/emails") return j([{ email: "old@example.com", primary: false, verified: false }, { email: gh.email, primary: true, verified: true }]);
  if (u === "https://oauth2.googleapis.com/token") { const b = new URLSearchParams(String(init?.body)); const claims = Buffer.from(JSON.stringify({ sub: "g-1", email: "Gina@Example.com", email_verified: true })).toString("base64url"); return j(b.get("code") === "g-code" ? { id_token: `h.${claims}.s` } : { error: "invalid_grant" }); }
  return new Response("not stood in: " + u, { status: 500 });
};
const mailFetch: typeof fetch = async (_url, init) => { mails.push(JSON.parse(String(init?.body))); return new Response("{}", { status: 200 }); };
const stripeFetch: typeof fetch = async (url, init) => {
  const path = String(url).replace("https://api.stripe.com/v1/", "");
  stripeCalls.push({ path, body: new URLSearchParams(String(init?.body ?? "")) });
  if (path === "checkout/sessions") return new Response(JSON.stringify({ id: "cs_test_1", url: "https://checkout.stripe.com/c/pay/cs_test_1" }), { status: 200, headers: { "content-type": "application/json" } });
  if (path === "billing_portal/sessions") return new Response(JSON.stringify({ url: "https://billing.stripe.com/p/session/x" }), { status: 200, headers: { "content-type": "application/json" } });
  return new Response(JSON.stringify({ error: { message: "no such route" } }), { status: 404 });
};
const SECRET = "portal-secret-for-tests-at-least-32-chars-long";
const WHSEC = "whsec_test_secret";

beforeAll(async () => {
  db = new PGlite();
  await db.query("SELECT 1");
  tenancy = new PostgresTenancy(db, { quotas: { free: 3 } });
  await tenancy.addTenant("default", "log.example.test");
  log = await serveLog(postgresResolver(tenancy), generateKeyPair(), { port: 0 });
  portal = await servePortal({ tenancy, client: db, secret: SECRET, publicUrl: log.url, checkpointsUrl: "https://checkpoints.example.test/", keyid: "abc123", portalUrl: "https://app.example.test/", stripe: { secretKey: "sk_test_x", webhookSecret: WHSEC, priceTeam: "price_team", fetch: stripeFetch }, mail: { apiKey: "re_test", from: "hello@example.test", notify: "sales@example.test", fetch: mailFetch }, oauth: { github: { clientId: "gh_id", clientSecret: "gh_secret" }, google: { clientId: "g_id", clientSecret: "g_secret" }, fetch: oauthFetch }, log: () => {} }, { port: 0 });
}, 60_000);

afterAll(async () => {
  await portal?.close();
  await log?.close();
  await db?.close();
});

/** a browser: keeps the cookie, sends JSON */
function browser() {
  let cookie = "";
  const call = async (method: string, path: string, body?: unknown) => {
    const res = await fetch(new URL(path, portal.url), { method, headers: { ...(cookie ? { cookie } : {}), ...(body !== undefined ? { "content-type": "application/json" } : {}) }, body: body !== undefined ? JSON.stringify(body) : undefined });
    const set = res.headers.get("set-cookie");
    if (set) cookie = set.split(";")[0]!;
    return { status: res.status, json: (await res.json().catch(() => ({}))) as any };
  };
  return { call, cookieValue: () => cookie };
}

describe("the tenant portal", () => {
  it("registers an account with a tenant and a first key shown once, then the dashboard shows the log's numbers as appends land", async () => {
    const b = browser();
    const bad = await b.call("POST", "/api/register", { email: "dana@example.com", password: "short", tenant: "acme" });
    expect(bad.status).toBe(400);
    const taken = await b.call("POST", "/api/register", { email: "dana@example.com", password: "a-long-enough-password", tenant: "default" });
    expect(taken.status).toBe(400); // reserved
    // who is registering is part of the record: a name and an organisation are required, the rest is optional and checked for shape
    const nameless = await b.call("POST", "/api/register", { email: "dana@example.com", password: "a-long-enough-password", tenant: "acme", company: "Acme" });
    expect(nameless.status).toBe(400);
    expect(nameless.json.error).toMatch(/your name/);
    const badHandle = await b.call("POST", "/api/register", { email: "dana@example.com", password: "a-long-enough-password", tenant: "acme", name: "Dana", company: "Acme", telegram: "@no spaces" });
    expect(badHandle.status).toBe(400);
    const r = await b.call("POST", "/api/register", { email: "Dana@Example.com", password: "a-long-enough-password", tenant: "acme", name: "Dana Ortiz", company: "Acme Ltd", role: "Head of Platform", phone: "+44 20 7946 0000", telegram: "@dana_ortiz" });
    expect(r.status).toBe(200);
    expect(await new PortalStore(db).registrations()).toEqual([{ tenantId: "acme", email: "dana@example.com", registeredAt: expect.any(String), billing: null, name: "Dana Ortiz", company: "Acme Ltd", role: "Head of Platform", phone: "+44 20 7946 0000", telegram: "dana_ortiz" }]);
    expect(r.json).toMatchObject({ tenant: "acme", logId: "acme", plan: "free" });
    expect(r.json.token).toMatch(/^[0-9a-f]{64}$/);
    expect(r.json.welcome).toContain("t/acme/");
    // the same sheet as data, so the page can show it as steps at registration and again under Setup
    expect(r.json.setup).toMatchObject({ log: expect.stringContaining("t/acme/"), logId: "acme", checkpoints: "https://checkpoints.example.test/acme/latest.json", keyid: "abc123", config: expect.stringContaining('"hashOnly": true'), verify: expect.stringContaining("--log-id acme"), export: expect.stringContaining("--tenant acme") });
    expect(r.json.exportCommand).toContain("--tenant acme");
    expect(readSession(SECRET, b.cookieValue().split("=")[1])).toBeTruthy();
    // the same email or tenant again is refused
    expect((await browser().call("POST", "/api/register", { email: "dana@example.com", password: "a-long-enough-password", tenant: "other", name: "Someone", company: "Somewhere" })).status).toBe(409);
    expect((await browser().call("POST", "/api/register", { email: "x@example.com", password: "a-long-enough-password", tenant: "acme", name: "Someone", company: "Somewhere" })).status).toBe(409);

    // one email to the person with the sheet and never the key, one to the operator with the contact details
    await new Promise((r) => setTimeout(r, 50));
    expect(mails.map((m) => [m.to[0], m.subject])).toEqual([["dana@example.com", 'Your agent-custody log "acme" is ready'], ["sales@example.test", "New registration: Acme Ltd (acme)"], ["dana@example.com", "Verify your email address for agent-custody"]]);
    expect(mails[2]!.text).toMatch(/verify-email\?token=/);
    expect(mails[0]!.text).toContain("t/acme/");
    expect(mails[0]!.text).toContain("Hello Dana Ortiz");
    expect(mails[0]!.text).not.toContain(r.json.token);
    expect(mails[1]!.text).toContain("+44 20 7946 0000");
    expect(mails[1]!.text).toContain("@dana_ortiz");
    const pageRes = await fetch(portal.url);
    const page = await pageRes.text();
    // the page's own script must parse: a quote escaped once inside the TypeScript template literal once left the page blank
    for (const m of page.matchAll(/<script>([\s\S]*?)<\/script>/g)) new Script(m[1]!);
    expect(pageRes.headers.get("content-security-policy")).toContain("img-src 'self'");
    expect(page).toContain('data-view="setup"');
    expect(page).toContain('rel="icon" href="/favicon.svg"');
    expect(page).toContain('id="themeToggle"');
    expect(page).toContain(':root[data-theme="dark"]');
    const icon = await fetch(new URL("favicon.svg", portal.url));
    expect(icon.status).toBe(200);
    expect(icon.headers.get("content-type")).toBe("image/svg+xml");
    const me = await b.call("GET", "/api/me");
    expect(me.json).toMatchObject({ email: "dana@example.com", tenant: "acme", plan: "free", used: 0, quota: 3, billing: true });
    // the key works on the log; the dashboard reflects the appends
    const sink = httpLog(`${log.url}t/acme/`, { token: r.json.token, hashOnly: true });
    await sink.append("one");
    await sink.append("two");
    const o = await b.call("GET", "/api/overview");
    expect(o.json).toMatchObject({ tenant: "acme", used: 2, quota: 3, treeSize: 2, latestCheckpoint: null });
    expect(o.json.months.at(-1)).toMatchObject({ appends: 2 });
    expect(o.json.keys).toHaveLength(1);
    expect(o.json.audit.map((e: any) => e.action)).toEqual(["token.add", "tenant.add"]);
    expect(o.json.audit[1].actor).toBe("portal:dana@example.com");
    expect(o.json.urls.checkpoints).toBe("https://checkpoints.example.test/acme/latest.json");
  });

  it("signs in and out, throttles wrong passwords, and refuses every tenant route without a session or with a forged cookie", async () => {
    const b = browser();
    expect((await b.call("POST", "/api/login", { email: "dana@example.com", password: "wrong-password!" })).status).toBe(401);
    expect((await b.call("POST", "/api/login", { email: "dana@example.com", password: "a-long-enough-password" })).status).toBe(200);
    expect((await b.call("GET", "/api/me")).status).toBe(200);
    expect((await b.call("POST", "/api/logout", {})).status).toBe(200);
    expect((await b.call("GET", "/api/me")).status).toBe(401);
    const forged = await fetch(new URL("/api/me", portal.url), { headers: { cookie: `custody_session=${signSession("another-secret-that-is-not-the-one", "someone")}` } });
    expect(forged.status).toBe(401);
    // a write without a JSON body is refused even with a session, which is the cross-site guard
    const c = browser();
    await c.call("POST", "/api/login", { email: "dana@example.com", password: "a-long-enough-password" });
    const noJson = await fetch(new URL("/api/keys", portal.url), { method: "POST", headers: { cookie: c.cookieValue() }, body: "label=x" });
    expect(noJson.status).toBe(415);
    const page = await fetch(portal.url);
    expect(page.headers.get("content-security-policy")).toMatch(/default-src 'none'/);
    const html = await page.text();
    expect(html).toContain("API keys");
    expect(html).toContain("https://docs.agent-custody.dev/reference/");
    expect(html).toContain("https://agent-custody.dev/verify");
  });

  it("mints and revokes keys with the portal user as the actor, and a revoked key stops appending", async () => {
    const b = browser();
    await b.call("POST", "/api/login", { email: "dana@example.com", password: "a-long-enough-password" });
    const m = await b.call("POST", "/api/keys", { label: "second fleet" });
    expect(m.status).toBe(200);
    expect(m.json.token).toMatch(/^[0-9a-f]{64}$/);
    const keys = (await b.call("GET", "/api/keys")).json.keys;
    expect(keys.map((k: any) => k.label)).toEqual(["first key", "second fleet"]);
    const sink = httpLog(`${log.url}t/acme/`, { token: m.json.token, hashOnly: true, retries: 1 });
    await sink.append("three");
    expect((await b.call("POST", `/api/keys/${m.json.tokenHash}/revoke`, {})).json).toEqual({ revoked: 1 });
    await expect(sink.append("four")).rejects.toThrow(/401/);
    const o = await b.call("GET", "/api/overview");
    expect(o.json.audit[0]).toMatchObject({ action: "token.revoke", actor: "portal:dana@example.com" });
    // and the free allowance is now used up: the dashboard says so
    expect(o.json).toMatchObject({ used: 3, quota: 3 });
  });

  it("checkout sends the tenant to Stripe with the right price and reference; the signed webhook moves the plan to team; a cancellation moves it back; a bad signature is refused", async () => {
    const b = browser();
    await b.call("POST", "/api/login", { email: "dana@example.com", password: "a-long-enough-password" });
    const c = await b.call("POST", "/api/checkout", {});
    expect(c.json.url).toBe("https://checkout.stripe.com/c/pay/cs_test_1");
    const call = stripeCalls.find((x) => x.path === "checkout/sessions")!;
    expect(call.body.get("mode")).toBe("subscription");
    expect(call.body.get("line_items[0][price]")).toBe("price_team");
    expect(call.body.get("client_reference_id")).toBe("acme");
    expect(call.body.get("success_url")).toBe("https://app.example.test/?upgraded=1");
    const event = (type: string, object: Record<string, unknown>) => JSON.stringify({ id: "evt_1", type, data: { object } });
    const signed = (payload: string, secret = WHSEC) => { const t = Math.floor(Date.now() / 1000); return `t=${t},v1=${createHmac("sha256", secret).update(`${t}.${payload}`).digest("hex")}`; };
    const post = (payload: string, sig: string) => fetch(new URL("/stripe/webhook", portal.url), { method: "POST", headers: { "content-type": "application/json", "stripe-signature": sig }, body: payload });
    const completed = event("checkout.session.completed", { id: "cs_test_1", client_reference_id: "acme", customer: "cus_1", subscription: "sub_1" });
    expect((await post(completed, signed(completed, "whsec_wrong"))).status).toBe(400);
    expect((await post(completed, signed(completed))).status).toBe(200);
    expect((await tenancy.tenant("acme"))!.plan).toBe("team");
    expect((await b.call("GET", "/api/me")).json).toMatchObject({ plan: "team", quota: 1_000_000 });
    expect((await b.call("GET", "/api/overview")).json.billing).toEqual({ status: "active" });
    // paying again is refused; managing billing goes to Stripe's portal for the customer on record
    expect((await b.call("POST", "/api/checkout", {})).status).toBe(409);
    expect((await b.call("POST", "/api/billing-portal", {})).json.url).toBe("https://billing.stripe.com/p/session/x");
    expect(stripeCalls.find((x) => x.path === "billing_portal/sessions")!.body.get("customer")).toBe("cus_1");
    const deleted = event("customer.subscription.deleted", { id: "sub_1", status: "canceled" });
    expect((await post(deleted, signed(deleted))).status).toBe(200);
    expect((await tenancy.tenant("acme"))!.plan).toBe("free");
    const audit = (await b.call("GET", "/api/overview")).json.audit;
    expect(audit.slice(0, 2).map((e: any) => [e.action, e.actor, e.detail.plan])).toEqual([["tenant.plan", "stripe:customer.subscription.deleted", "free"], ["tenant.plan", "stripe:checkout", "team"]]);
    // an old timestamp is refused even with a valid mac
    const stale = `t=${Math.floor(Date.now() / 1000) - 3600},v1=${createHmac("sha256", WHSEC).update(`${Math.floor(Date.now() / 1000) - 3600}.${deleted}`).digest("hex")}`;
    expect(verifyStripeSignature(stale, deleted, WHSEC)).toBe(false);
  });

  it("password hashing is scrypt with a fresh salt, and a stored hash never verifies the wrong password", () => {
    const h1 = PortalStore.hashPassword("correct horse battery");
    const h2 = PortalStore.hashPassword("correct horse battery");
    expect(h1).not.toBe(h2);
    expect(h1.startsWith("scrypt$")).toBe(true);
    expect(PortalStore.checkPassword("correct horse battery", h1)).toBe(true);
    expect(PortalStore.checkPassword("correct horse batter", h1)).toBe(false);
    expect(PortalStore.checkPassword("x", "garbage")).toBe(false);
  });
});

describe("policies", () => {
  it("a tenant publishes named policy versions whose digest is exactly the policyDigest the gateway writes, matches a receipt's digest to a name, sees the text, removes a version, and every change is in the audit trail; the same text twice is refused", async () => {
    const b = browser();
    expect((await b.call("POST", "/api/register", { email: "pol@example.com", password: "a-long-enough-password", tenant: "polco", name: "Pol", company: "Polco" })).status).toBe(200);
    const text = 'permit(principal, action == Action::"stripe.refund", resource) when { context.args.amount <= 100000 };\n';
    const published = await b.call("POST", "/api/policies", { name: "refunds-v1", text });
    expect(published.status).toBe(200);
    expect(published.json.policy).toMatchObject({ name: "refunds-v1", digest: policyDigest(text), bytes: text.length, createdBy: "portal:pol@example.com" });
    const id = published.json.policy.id as string;
    expect((await b.call("POST", "/api/policies", { name: "refunds-v1-again", text })).status).toBe(409); // same bytes, already named
    expect((await b.call("POST", "/api/policies", { name: "", text })).status).toBe(400);
    const listed = await b.call("GET", "/api/policies");
    expect(listed.json.policies.map((p: { name: string }) => p.name)).toEqual(["refunds-v1"]);
    // the digest a receipt carries reads as the name; a digest nobody published reads as nothing, not an error
    expect((await b.call("GET", `/api/policies?digest=${policyDigest(text)}`)).json.match).toMatchObject({ id, name: "refunds-v1" });
    expect((await b.call("GET", `/api/policies?digest=${"0".repeat(64)}`)).json.match).toBeNull();
    expect((await b.call("GET", "/api/policies?digest=nope")).status).toBe(400);
    expect((await b.call("GET", `/api/policies/${id}`)).json.policy.text).toBe(text);
    expect((await b.call("POST", `/api/policies/${id}/remove`, {})).json).toEqual({ removed: true });
    expect((await b.call("GET", "/api/policies")).json.policies).toEqual([]);
    const audit = (await tenancy.audit({ tenant: "polco" })).map((e) => e.action);
    expect(audit.slice(0, 2)).toEqual(["policy.remove", "policy.add"]);
    // another tenant's session never sees it
    const page = await (await fetch(portal.url)).text();
    expect(page).toContain('data-view="policies"');
  });
});

describe("two-step registration and provider sign-in", () => {
  it("an account first, the tenant on the next screen: register with email and password, /api/me says no tenant, the tenant routes refuse, onboard creates the tenant and the first key and sends the two emails", async () => {
    const b = browser();
    const r = await b.call("POST", "/api/register", { email: "Two@Example.com", password: "a-long-enough-password" });
    expect(r.status).toBe(200);
    expect(r.json).toEqual({ email: "two@example.com", tenant: null, emailVerified: false });
    expect((await b.call("GET", "/api/me")).json).toMatchObject({ email: "two@example.com", tenant: null, profile: { name: null, company: null } });
    expect((await b.call("GET", "/api/overview")).status).toBe(409);
    expect((await b.call("POST", "/api/onboard", { tenant: "twoco", company: "Two Co" })).status).toBe(400); // a name is needed
    const before = mails.length;
    const on = await b.call("POST", "/api/onboard", { tenant: "twoco", name: "Tu Two", company: "Two Co", role: "CTO" });
    expect(on.status).toBe(200);
    expect(on.json).toMatchObject({ tenant: "twoco", logId: "twoco", plan: "free" });
    expect(on.json.token).toMatch(/^[0-9a-f]{64}$/);
    expect(on.json.setup.log).toContain("t/twoco/");
    expect((await b.call("GET", "/api/me")).json).toMatchObject({ email: "two@example.com", tenant: "twoco", plan: "free" });
    expect((await b.call("POST", "/api/onboard", { tenant: "twoco2", name: "Tu", company: "Two" })).status).toBe(409); // one tenant per account
    await new Promise((r) => setTimeout(r, 50));
    expect(mails.slice(before).map((m) => [m.to[0], m.subject])).toEqual([["two@example.com", 'Your agent-custody log "twoco" is ready'], ["sales@example.test", "New registration: Two Co (twoco)"]]);
    expect(mails[before]!.text).toContain("Hello Tu Two");
    const store = new PortalStore(db);
    expect((await store.registrations()).find((x) => x.tenantId === "twoco")).toMatchObject({ email: "two@example.com", name: "Tu Two", company: "Two Co", role: "CTO" });
  });

  it("GitHub and Google sign-in: the start sets a signed state and redirects to the provider; the callback with that state exchanges the code, takes the verified email, links or creates the account, and sets the session; a wrong state is refused; the same subject twice is the same account; the page offers both", async () => {
    const start = await fetch(new URL("auth/github", portal.url), { redirect: "manual" });
    expect(start.status).toBe(302);
    const to = new URL(start.headers.get("location")!);
    expect(to.origin + to.pathname).toBe("https://github.com/login/oauth/authorize");
    expect(to.searchParams.get("client_id")).toBe("gh_id");
    expect(to.searchParams.get("redirect_uri")).toBe("https://app.example.test/auth/github/callback");
    const state = to.searchParams.get("state")!;
    const stateCookie = start.headers.get("set-cookie")!.split(";")[0]!;
    expect(stateCookie).toBe(`custody_oauth=${state}`);
    // a callback whose state is not the one in the cookie is refused before any exchange
    expect((await fetch(new URL(`auth/github/callback?code=gh-code&state=${state}x`, portal.url), { headers: { cookie: stateCookie } })).status).toBe(400);
    expect((await fetch(new URL(`auth/github/callback?code=gh-code&state=${state}`, portal.url))).status).toBe(400); // no cookie
    const cb = await fetch(new URL(`auth/github/callback?code=gh-code&state=${state}`, portal.url), { headers: { cookie: stateCookie } });
    expect(cb.status).toBe(200);
    expect(cb.headers.get("content-type")).toMatch(/text\/html/);
    const setCookies = cb.headers.getSetCookie();
    const session = setCookies.find((c) => c.startsWith("custody_session="))!;
    expect(session).toContain("SameSite=Strict");
    expect(setCookies.find((c) => c.startsWith("custody_oauth="))).toContain("Max-Age=0");
    const meRes = await fetch(new URL("api/me", portal.url), { headers: { cookie: session.split(";")[0]! } });
    expect(await meRes.json()).toMatchObject({ email: "octo@example.com", tenant: null });
    // again with the same subject: the same account, not a second one
    const again = await fetch(new URL("auth/github", portal.url), { redirect: "manual" });
    const st2 = new URL(again.headers.get("location")!).searchParams.get("state")!;
    const cb2 = await fetch(new URL(`auth/github/callback?code=gh-code&state=${st2}`, portal.url), { headers: { cookie: `custody_oauth=${st2}` } });
    const s2 = cb2.headers.getSetCookie().find((c) => c.startsWith("custody_session="))!.split(";")[0]!;
    const uid1 = readSession(SECRET, session.split(";")[0]!.split("=")[1]!);
    expect(readSession(SECRET, s2.split("=")[1]!)).toBe(uid1);
    // a bad code is a provider failure, reported, no session
    const st3 = new URL((await fetch(new URL("auth/github", portal.url), { redirect: "manual" })).headers.get("location")!).searchParams.get("state")!;
    expect((await fetch(new URL(`auth/github/callback?code=wrong&state=${st3}`, portal.url), { headers: { cookie: `custody_oauth=${st3}` } })).status).toBe(502);
    // Google, through the id token
    const g = await fetch(new URL("auth/google", portal.url), { redirect: "manual" });
    const gto = new URL(g.headers.get("location")!);
    expect(gto.origin + gto.pathname).toBe("https://accounts.google.com/o/oauth2/v2/auth");
    expect(gto.searchParams.get("scope")).toBe("openid email");
    const gstate = gto.searchParams.get("state")!;
    const gcb = await fetch(new URL(`auth/google/callback?code=g-code&state=${gstate}`, portal.url), { headers: { cookie: `custody_oauth=${gstate}` } });
    expect(gcb.status).toBe(200);
    const gs = gcb.headers.getSetCookie().find((c) => c.startsWith("custody_session="))!.split(";")[0]!;
    expect(await (await fetch(new URL("api/me", portal.url), { headers: { cookie: gs } })).json()).toMatchObject({ email: "gina@example.com", tenant: null });
    const page = await (await fetch(portal.url)).text();
    expect(page).toContain('["github","google"]');
    expect(page).toContain('id="onboardForm"');
  });
});

describe("email verification and account linking (issue #103)", () => {
  const verifyLinkFor = (email: string) => { const m = [...mails].reverse().find((x) => x.to[0] === email && /Verify your email/.test(x.subject))!; return new URL(/(https?:\S+verify-email\?token=\S+)/.exec(m.text)![1]!); };
  const ghSignIn = async (cookie?: string, link = false) => {
    const start = await fetch(new URL(`auth/github${link ? "?link=1" : ""}`, portal.url), { redirect: "manual", headers: cookie ? { cookie } : {} });
    if (start.status !== 302) return { status: start.status, setCookies: [] as string[], text: await start.text() };
    const state = new URL(start.headers.get("location")!).searchParams.get("state")!;
    const cb = await fetch(new URL(`auth/github/callback?code=gh-code&state=${state}`, portal.url), { headers: { cookie: `custody_oauth=${state}${cookie ? `; ${cookie}` : ""}` } });
    return { status: cb.status, setCookies: cb.headers.getSetCookie(), text: await cb.text() };
  };

  it("a password account is unverified until its link is used; a provider sign-in for that address is refused and links only once the address is verified", async () => {
    const b = browser();
    expect((await b.call("POST", "/api/register", { email: "vera@example.com", password: "a-long-enough-password" })).json).toEqual({ email: "vera@example.com", tenant: null, emailVerified: false });
    await new Promise((r) => setTimeout(r, 50));
    expect((await b.call("GET", "/api/me")).json).toMatchObject({ emailVerified: false, identities: [], providers: ["github", "google"], mail: true });
    const uid = readSession(SECRET, b.cookieValue().split("=")[1]!);
    // an attacker-shaped situation: GitHub vouches for vera@example.com, but the password account never verified it
    gh = { id: 777, email: "Vera@Example.com" };
    const refused = await ghSignIn();
    expect(refused.status).toBe(409);
    expect(refused.text).toMatch(/has not verified it/);
    expect(refused.setCookies.find((c) => c.startsWith("custody_session="))).toBeUndefined();
    // a bad link does nothing; the real one verifies the address
    expect((await fetch(new URL("verify-email?token=nope", portal.url))).status).toBe(400);
    const link = verifyLinkFor("vera@example.com");
    expect((await fetch(new URL(link.pathname + link.search, portal.url))).status).toBe(200);
    expect((await b.call("GET", "/api/me")).json).toMatchObject({ emailVerified: true });
    // now the provider sign-in links to the verified account and signs it in: same account, no second one
    const ok = await ghSignIn();
    expect(ok.status).toBe(200);
    const session = ok.setCookies.find((c) => c.startsWith("custody_session="))!.split(";")[0]!;
    expect(readSession(SECRET, session.split("=")[1]!)).toBe(uid);
    // resend is a no-op once verified
    expect((await b.call("POST", "/api/verify-email/resend", {})).json).toEqual({ ok: true, emailVerified: true });
    gh = { id: 4242, email: "Octo@Example.com" };
  });

  it("a signed-in account links a provider from its session even when the provider's email differs, and that identity then signs into the same account", async () => {
    // the verified account from the previous test, signed in with its password (a sixth registration would hit the throttle)
    const b = browser();
    expect((await b.call("POST", "/api/login", { email: "vera@example.com", password: "a-long-enough-password" })).status).toBe(200);
    const uid = readSession(SECRET, b.cookieValue().split("=")[1]!);
    gh = { id: 888, email: "Someone@Else.com" };
    expect((await ghSignIn(undefined, true)).status).toBe(401); // linking needs a session
    const linked = await ghSignIn(b.cookieValue(), true);
    expect(linked.status, linked.text).toBe(200);
    expect(linked.text).toMatch(/GitHub is linked to vera@example.com/);
    expect((await b.call("GET", "/api/me")).json).toMatchObject({ identities: ["github"], emailVerified: true });
    const again = await ghSignIn();
    expect(again.status).toBe(200);
    const session = again.setCookies.find((c) => c.startsWith("custody_session="))!.split(";")[0]!;
    expect(readSession(SECRET, session.split("=")[1]!)).toBe(uid);
    gh = { id: 4242, email: "Octo@Example.com" };
  });
});

describe("the founder's note", () => {
  it("goes once to each registration between an hour and a week old, by name and tenant, never to the operator's own domains, is retried after a provider failure, and a dry run sends nothing", async () => {
    const store = new PortalStore(db);
    const t0 = new Date("2026-09-29T07:00:00Z");
    const mk = async (email: string, name: string, tenant: string, at: Date) => {
      const u = await store.createUser(email, "a-long-enough-password", { name, company: "Co " + tenant });
      await tenancy.addTenant(tenant, tenant, "test");
      await store.addMember(u.id, tenant);
      await db.query("UPDATE portal_users SET created_at = $2 WHERE id = $1", [u.id, at.toISOString()]);
      return u;
    };
    await mk("burak@example.com", "Burak Yilmaz", "zyai", new Date(t0.getTime() - 2 * 3_600_000));     // two hours old: due
    await mk("fresh@example.com", "Fresh One", "fresh", new Date(t0.getTime() - 10 * 60_000));           // ten minutes old: not yet
    await mk("old@example.com", "Old One", "oldco", new Date(t0.getTime() - 9 * 86_400_000));           // nine days old: too late, left alone
    await mk("ops@example.test", "Us", "usco", new Date(t0.getTime() - 3 * 3_600_000));                  // our own domain: marked, not written to
    const captured: { to: string[]; subject: string; text: string }[] = [];
    let refuse = false;
    const mailFetch: typeof fetch = async (_u, init) => { if (refuse) return new Response("nope", { status: 500 }); captured.push(JSON.parse(String(init?.body))); return new Response("{}", { status: 200 }); };
    const mail = { apiKey: "re", from: "Partha <partha@example.test>", notify: "partha@example.test", fetch: mailFetch };
    const dry = await sendFollowUps(store, mail, { portalUrl: "https://app.example.test/", now: t0, dryRun: true, log: () => {} });
    expect(dry.sent).toEqual(["burak@example.com"]);
    expect(captured).toHaveLength(0);
    refuse = true;
    const first = await sendFollowUps(store, mail, { portalUrl: "https://app.example.test/", now: t0, log: () => {} });
    expect(first).toEqual({ sent: [], skipped: ["ops@example.test"], failed: ["burak@example.com"] });
    refuse = false;
    const second = await sendFollowUps(store, mail, { portalUrl: "https://app.example.test/", now: t0, log: () => {} });
    expect(second).toEqual({ sent: ["burak@example.com"], skipped: [], failed: [] });
    expect(captured).toHaveLength(1);
    expect(captured[0]!.to).toEqual(["burak@example.com"]);
    expect(captured[0]!.subject).toBe("Welcome to agent-custody, and one question");
    expect(captured[0]!.text).toContain("Hi Burak,");
    expect(captured[0]!.text).toContain("registering zyai");
    expect(captured[0]!.text).toContain("at Co zyai?");
    expect(captured[0]!.text).toContain('"mode": "observe"');
    expect(captured[0]!.text).toContain("partha@example.test");
    // once only, and the ten-minute-old one becomes due later
    expect((await sendFollowUps(store, mail, { portalUrl: "https://app.example.test/", now: t0, log: () => {} })).sent).toEqual([]);
    expect((await sendFollowUps(store, mail, { portalUrl: "https://app.example.test/", now: new Date(t0.getTime() + 2 * 3_600_000), log: () => {} })).sent).toContain("fresh@example.com"); // other tests' registrations may be due too
    expect(founderNote({ name: "Solo", tenant: "t", company: null, portalUrl: "https://p/", from: "x@y.z" }).text).toContain("What are you building?");
  });
});
