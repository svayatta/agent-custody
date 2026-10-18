// Aspect: an enterprise tenant signs in through its own identity provider, and roles limit each member. Source: src/portal.ts, src/sso.ts
// Run:    node examples/29-enterprise-sign-in.ts
//
// The operator sets single sign-on for tenant acme: the identity provider, and the one email domain that it may sign
// in. A person at that domain signs in through the provider and joins as readonly, so a policy write is refused. An
// owner promotes them to reviewer, and the write works. Then the operator enforces single sign-on, and the owner's
// password stops working. The provider here is a stand-in in memory behind an injected fetch: no network, no browser.
import { PGlite } from "@electric-sql/pglite";
import { PostgresTenancy } from "../src/log-store.ts";
import { PortalStore, servePortal, type SsoSetting } from "../src/portal.ts";
import { standInIdp } from "../scripts/idp-standin.ts";
import { step } from "./_out.ts";

const db = new PGlite();
const tenancy = new PostgresTenancy(db);
const store = new PortalStore(db);
const idp = standInIdp("https://login.acme.example", "portal-client", "client-secret");
const portal = await servePortal({ tenancy, client: db, secret: "example-secret-of-at-least-32-characters", publicUrl: "http://log.example/", portalUrl: "http://portal.example/", ssoFetch: idp.fetch, log: () => {} }, { port: 0 });
const call = (path: string, init: { method?: string; body?: unknown; cookie?: string } = {}) =>
  fetch(new URL(path, portal.url), { method: init.method ?? "GET", redirect: "manual", headers: { ...(init.cookie ? { cookie: init.cookie } : {}), ...(init.body ? { "content-type": "application/json" } : {}) }, ...(init.body ? { body: JSON.stringify(init.body) } : {}) });
const must = (ok: boolean, what: string) => { if (!ok) throw new Error(what); };

step(1, "olga registers the tenant acme with a password; the operator then sets single sign-on for it");
const registered = await call("api/register", { method: "POST", body: { email: "olga@acme.example", password: "olga-long-password", tenant: "acme", name: "Olga", company: "Acme" } });
const olga = registered.headers.get("set-cookie")!.split(";")[0]!;
const sso: SsoSetting = { tenant: "acme", protocol: "oidc", config: { issuer: "https://login.acme.example", clientId: "portal-client", clientSecret: "client-secret" }, domains: ["acme.example"], defaultRole: "readonly", enforced: false };
await store.setSso(sso);
console.log("   agent-custody log-admin sso set acme --oidc-issuer https://login.acme.example --oidc-client-id portal-client --oidc-secret-env ACME_OIDC_SECRET --domains acme.example");
console.log("   the operator sets it, never the tenant: an issuer URL from a tenant would make the portal fetch any URL");

step(2, "ann signs in with single sign-on: her address names the tenant, the provider vouches for her, and she joins as readonly");
const lookup = await call("auth/sso?email=ann@acme.example");
const start = await call(lookup.headers.get("location")!);
const back = new URL(idp.signIn(start.headers.get("location")!, { sub: "ann-1", email: "ann@acme.example" }));
const done = await call(back.pathname + back.search, { cookie: start.headers.get("set-cookie")!.split(";")[0]! });
const ann = done.headers.getSetCookie().find((c) => c.startsWith("custody_session="))!.split(";")[0]!;
const me = (await (await call("api/me", { cookie: ann })).json()) as { email: string; role: string };
console.log(`   ${me.email} is ${me.role} in acme (the provider ran PKCE and a nonce; no password, no MFA step)`);
must(me.role === "readonly", "ann should be readonly");

step(3, "a readonly member publishes a policy: refused");
const policy = { name: "refunds-v1", text: 'permit(principal, action == Action::"stripe.refund", resource) when { context.args.amount <= 100000 };' };
const refused = await call("api/policies", { method: "POST", body: policy, cookie: ann });
console.log(`   HTTP ${refused.status}: ${((await refused.json()) as { error: string }).error}`);
must(refused.status === 403, "a readonly write should be refused");

step(4, "olga, the owner, promotes ann to reviewer; ann publishes the policy");
const members = ((await (await call("api/members", { cookie: olga })).json()) as { members: { id: string; email: string }[] }).members;
const promoted = await call(`api/members/${members.find((m) => m.email === "ann@acme.example")!.id}/role`, { method: "POST", body: { role: "reviewer" }, cookie: olga });
must(promoted.status === 200, "the promotion should work");
const published = await call("api/policies", { method: "POST", body: policy, cookie: ann });
const digest = ((await published.json()) as { policy: { digest: string } }).policy.digest;
console.log(`   HTTP ${published.status}: ${policy.name} published as ${digest.slice(0, 16)}...`);
must(published.status === 200, "a reviewer should publish");

step(5, "the operator enforces single sign-on: olga's password and her old session stop working, ann's session does not");
await store.setSso({ ...sso, enforced: true });
console.log("   agent-custody log-admin sso set acme ... --enforce");
const password = await call("api/login", { method: "POST", body: { email: "olga@acme.example", password: "olga-long-password" } });
console.log(`   password sign-in: HTTP ${password.status}: ${((await password.json()) as { error: string }).error}`);
const old = await call("api/me", { cookie: olga });
console.log(`   olga's password session: HTTP ${old.status}`);
const still = await call("api/me", { cookie: ann });
console.log(`   ann's single sign-on session: HTTP ${still.status}`);
must(password.status === 403 && old.status === 401 && still.status === 200, "enforcement should turn password access off");

await portal.close();
await db.close();
console.log("\nOK");
