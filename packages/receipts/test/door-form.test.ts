// The form protector: the door serves one script for a plain HTML form, built from its challenge config and never
// carrying the secret. In a browser the script renders the provider's widget in each same-origin POST form, sends the
// form with the token in the door's challenge header, and follows the answer. Here the script runs in a small DOM
// stand-in against a real door, a stand-in provider, and a site that records what reached it: a passed check reaches
// the site with a receipt id and no token in the body, a missing token sends nothing, a failed one never reaches the
// site, and the widget is reset after every send because a token serves one request.
import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Script, runInNewContext } from "node:vm";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { loadDoorConfig } from "../src/config.ts";
import { loadPublicKey } from "../src/crypto.ts";
import { door } from "../src/door-app.ts";
import { FORM_SCRIPT_PATH, formScript } from "../src/door-form.ts";
import { ARRIVAL_FACT, RECEIPT_HEADER, createDoorHost, serveDoor, type Arrival, type DoorHost, type RunningDoor } from "../src/door.ts";
import type { ReceiptBundle, ReceiptStatement } from "../src/receipt.ts";
import { verifyBundle } from "../src/verify.ts";
import { buildDoorFixture, type DoorFixture } from "../scripts/door-fixture.ts";

const SECRET_ENV = "DOOR_FORM_TEST_TURNSTILE";
const SECRET = "form-secret-never-in-the-script";
const challenge = { provider: "turnstile", siteKey: "site-form-1", secretEnv: SECRET_ENV, hostnames: ["shop.example"], action: "contact" };

/** The site behind the door: records each request and answers a page. */
const site = async () => {
  const seen: { method: string; path: string; headers: Record<string, unknown>; body: string }[] = [];
  const server: Server = createServer((req, res) => {
    const chunks: Buffer[] = [];
    req.on("data", (c: Buffer) => chunks.push(c));
    req.on("end", () => {
      seen.push({ method: req.method ?? "", path: req.url ?? "", headers: req.headers, body: Buffer.concat(chunks).toString("utf8") });
      res.writeHead(200, { "content-type": "text/html; charset=utf-8" });
      res.end("<p>Thank you</p>");
    });
  });
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  return { url: `http://127.0.0.1:${(server.address() as AddressInfo).port}`, seen, close: () => new Promise<void>((r) => { server.closeAllConnections(); server.close(() => r()); }) };
};

interface FakeForm {
  attrs: Record<string, string>;
  noButton?: boolean;
  /** the widget's hidden fields, as elements the script may disable */
  hidden?: { name: string; disabled: boolean }[];
  fields: [string, string][];
  handlers: ((e: unknown) => Promise<void>)[];
  inserted: { className: string; textContent: string }[];
}
const formOf = (attrs: Record<string, string>, fields: [string, string][] = []): FakeForm => ({ attrs, fields, handlers: [], inserted: [] });

/**
 * Runs the script in a DOM stand-in: forms that report their attributes and fields, a provider whose token is
 * `token()`, and `fetch` passed through. Returns what the script did to the page.
 */
function runScript(script: string, o: { origin: string; forms: FakeForm[]; token: () => string; fetch: typeof fetch; dataForms?: string; provider?: "turnstile" | "hcaptcha" }) {
  const widget = { rendered: [] as Record<string, unknown>[], reset: 0 };
  const page = { assigned: [] as string[], written: [] as string[], selector: "" };
  let loader: { src?: string; onload?: () => void } = {};
  const element = (tag: string) => ({ tag, className: "", textContent: "", setAttribute() {} });
  const document = {
    currentScript: { dataset: o.dataForms ? { forms: o.dataForms } : {} },
    readyState: "complete",
    head: { append: (el: typeof loader) => { loader = el; } },
    createElement: element,
    querySelectorAll: (selector: string) => {
      page.selector = selector;
      return o.forms.map((f) => ({
        getAttribute: (n: string) => f.attrs[n] ?? null,
        querySelector: () => (f.noButton ? null : { before: (...els: FakeForm["inserted"]) => f.inserted.push(...els) }),
        querySelectorAll: (sel: string) => (f.hidden ?? []).filter((el) => sel === `[name="${el.name}"]`),
        append: (...els: FakeForm["inserted"]) => f.inserted.push(...els),
        addEventListener: (type: string, fn: FakeForm["handlers"][number]) => { if (type === "submit") f.handlers.push(fn); },
        fields: f.fields,
      }));
    },
    addEventListener() {},
    open() {},
    write: (html: string) => page.written.push(html),
    close() {},
  };
  class FormDataStandIn {
    entries: [string, string][];
    constructor(form: { fields: [string, string][] }) { this.entries = [...form.fields]; }
    delete(name: string) { this.entries = this.entries.filter(([k]) => k !== name); }
    [Symbol.iterator]() { return this.entries[Symbol.iterator](); }
  }
  const widgetApi = {
    render: (_box: unknown, options: Record<string, unknown>) => { widget.rendered.push(options); return `w${widget.rendered.length}`; },
    getResponse: () => o.token(),
    reset: () => { widget.reset += 1; },
  };
  const location = { href: `${o.origin}/contact`, origin: o.origin, assign: (u: string) => page.assigned.push(u) };
  runInNewContext(script, { document, location, window: { [o.provider ?? "turnstile"]: widgetApi }, fetch: o.fetch, URL, URLSearchParams, FormData: FormDataStandIn, AbortSignal, console });
  return { widget, page, loader: () => loader };
}
/** Fires the form's submit handlers, from a button with these attributes when given; reports whether the native post was stopped. */
const submit = async (f: FakeForm, button?: Record<string, string>) => {
  let stopped = false;
  const submitter = button ? { hasAttribute: (n: string) => Object.hasOwn(button, n), getAttribute: (n: string) => button[n] ?? null } : null;
  await Promise.all(f.handlers.map((h) => h({ preventDefault: () => { stopped = true; }, submitter })));
  return stopped;
};
const noteOf = (f: FakeForm) => f.inserted.find((e) => e.className === "agent-custody-challenge-note")?.textContent;

describe("the form protector", () => {
  let fx: DoorFixture;
  let shop: Awaited<ReturnType<typeof site>>;
  let host: DoorHost;
  let running: RunningDoor;
  const asked: Record<string, string>[] = [];
  const decode = (b: ReceiptBundle) => JSON.parse(Buffer.from(b.envelope.payload, "base64").toString()) as ReceiptStatement;

  beforeAll(async () => {
    process.env[SECRET_ENV] = SECRET;
    shop = await site();
    fx = buildDoorFixture(mkdtempSync(join(tmpdir(), "agent-custody-door-form-")), shop.url, { challenge, routes: [{ name: "contact", methods: ["POST"], path: "/contact" }] });
    writeFileSync(join(fx.dir, "policy.cedar"), 'permit(principal, action == Action::"contact", resource) when { context.facts.arrival.challenge.outcome == "passed" };\n');
    // the provider: "good" passes for the site's hostname and action, anything else fails; nothing leaves the machine
    const provider: typeof fetch = async (input, init) => {
      const u = String(input instanceof Request ? input.url : input);
      if (!u.startsWith("https://challenges.cloudflare.com/")) return fetch(input, init);
      const form = Object.fromEntries(new URLSearchParams(String(init?.body)));
      asked.push(form);
      return new Response(JSON.stringify(form.response === "good" ? { success: true, hostname: "shop.example", action: "contact" } : { success: false, "error-codes": ["invalid-input-response"] }), { headers: { "content-type": "application/json" } });
    };
    host = await createDoorHost(loadDoorConfig(fx.configFile), { fetch: provider });
    running = await serveDoor(host, { port: 0, log: () => {} });
  }, 60_000);
  afterAll(async () => {
    await running?.close();
    await host?.close();
    await shop?.close();
    delete process.env[SECRET_ENV];
  });

  const served = async () => {
    const res = await fetch(`${running.url}${FORM_SCRIPT_PATH}`);
    return { res, script: await res.text() };
  };

  it("the door serves the script for its challenge: JavaScript, public, the site key and the header, never the secret", async () => {
    const { res, script } = await served();
    expect(res.status).toBe(200);
    expect(res.headers.get("content-type")).toBe("text/javascript; charset=utf-8");
    expect(res.headers.get("x-content-type-options")).toBe("nosniff");
    expect(res.headers.get(RECEIPT_HEADER)).toBeNull();
    expect(script).toContain('"siteKey":"site-form-1"');
    expect(script).toContain('"header":"x-agent-custody-challenge"');
    expect(script).toContain('"action":"contact"');
    expect(script).toContain("https://challenges.cloudflare.com/turnstile/v0/api.js?render=explicit");
    expect(script).not.toContain(SECRET);
    expect(script).not.toContain(SECRET_ENV);
    expect(() => new Script(script)).not.toThrow();
    expect(script).toBe(formScript(loadDoorConfig(fx.configFile).challenge!));
    // a cache-busting query string still gets the script, not a decision
    const busted = await fetch(`${running.url}${FORM_SCRIPT_PATH}?v=2`);
    expect(busted.status).toBe(200);
    expect(await busted.text()).toBe(script);
  });

  it("a passed check reaches the site once, form-encoded, with the receipt id and without the token; the page shows the site's answer and the widget is reset", async () => {
    const { script } = await served();
    const contact = formOf({ method: "post", action: "/contact" }, [["name", "Ada"], ["message", "Hello"], ["cf-turnstile-response", "good"]]);
    const search = formOf({ method: "get", action: "/search" });
    const elsewhere = formOf({ method: "post", action: "https://forms.example/submit" });
    const run = runScript(script, { origin: running.url, forms: [contact, search, elsewhere], token: () => "good", fetch });
    expect(run.loader().src).toBe("https://challenges.cloudflare.com/turnstile/v0/api.js?render=explicit");
    run.loader().onload!();
    // only the same-origin POST form is protected
    expect(run.widget.rendered).toEqual([{ sitekey: "site-form-1", "response-field": false, action: "contact" }]);
    expect(search.handlers).toHaveLength(0);
    expect(elsewhere.handlers).toHaveLength(0);
    expect(run.page.selector).toBe("form");

    const before = shop.seen.length;
    await submit(contact);
    expect(shop.seen.length).toBe(before + 1);
    const reached = shop.seen.at(-1)!;
    expect(reached).toMatchObject({ method: "POST", path: "/contact", body: "name=Ada&message=Hello" });
    expect(reached.headers["content-type"]).toMatch(/^application\/x-www-form-urlencoded/);
    expect(reached.headers["x-agent-custody-challenge"]).toBeUndefined();
    const receiptId = reached.headers[RECEIPT_HEADER] as string;
    expect(asked.at(-1)).toMatchObject({ response: "good", secret: SECRET });
    expect(run.page.written).toEqual(["<p>Thank you</p>"]);
    expect(run.widget.reset).toBe(1);

    const bundle = JSON.parse(readFileSync(join(fx.receiptsDir, `${receiptId}.json`), "utf8")) as ReceiptBundle;
    expect((decode(bundle).predicate.facts[ARRIVAL_FACT]!.value as Arrival).challenge).toEqual({ provider: "turnstile", outcome: "passed" });
    expect(verifyBundle(bundle, { issuerKeys: [loadPublicKey(fx.doorPub)], principalKeys: [], logFile: fx.logFile }).ok).toBe(true);
  });

  it("without a token nothing is sent and the page says to complete the check; a failed check never reaches the site and the widget is reset", async () => {
    const { script } = await served();
    let calls = 0;
    const counting: typeof fetch = (input, init) => { calls += 1; return fetch(input, init); };
    const contact = formOf({ method: "POST", action: "/contact" }, [["message", "Hi"]]);
    let token = "";
    const run = runScript(script, { origin: running.url, forms: [contact], token: () => token, fetch: counting });
    run.loader().onload!();
    await submit(contact);
    expect(calls).toBe(0);
    expect(noteOf(contact)).toBe("Complete the check above, then send the form again.");
    expect(run.widget.reset).toBe(0);

    token = "bad";
    const before = shop.seen.length;
    await submit(contact);
    expect(calls).toBe(1);
    expect(shop.seen.length).toBe(before);
    expect(noteOf(contact)).toBe("The check did not pass. Complete it again, then send the form.");
    expect(run.widget.reset).toBe(1);
    expect(run.page.written).toEqual([]);
  });

  it("follows a redirect as a form post would, sends multipart when the form says so, and honours data-forms", async () => {
    const { script } = await served();
    const sent: { url: string; init: RequestInit }[] = [];
    const redirecting: typeof fetch = async (input, init) => {
      sent.push({ url: String(input), init: init! });
      return { redirected: true, url: `${running.url}/thanks`, status: 200, ok: true, headers: new Headers() } as unknown as Response;
    };
    const upload = formOf({ method: "post", action: "/contact", enctype: "multipart/form-data" }, [["note", "x"], ["h-captcha-response", "t"]]);
    const run = runScript(script, { origin: running.url, forms: [upload], token: () => "good", fetch: redirecting, dataForms: "#upload" });
    run.loader().onload!();
    expect(run.page.selector).toBe("#upload");
    await submit(upload);
    expect(run.page.assigned).toEqual([`${running.url}/thanks`]);
    expect(sent[0]!.url).toBe(`${running.url}/contact`);
    expect((sent[0]!.init.headers as Record<string, string>)["x-agent-custody-challenge"]).toBe("good");
    // multipart keeps the form data as it is, less the widget's copy of the token
    expect([...(sent[0]!.init.body as unknown as Iterable<[string, string]>)]).toEqual([["note", "x"]]);
    expect(sent[0]!.init.signal).toBeInstanceOf(AbortSignal);
  });

  it("a button's formmethod GET or formaction on another site posts natively; its formaction and formenctype on this site are used", async () => {
    const { script } = await served();
    const sent: { url: string; init: RequestInit }[] = [];
    const recording: typeof fetch = async (input, init) => { sent.push({ url: String(input), init: init! }); return new Response("<p>ok</p>", { headers: { "content-type": "text/html" } }); };
    const contact = formOf({ method: "post", action: "/contact" }, [["message", "Hi"]]);
    const run = runScript(script, { origin: running.url, forms: [contact], token: () => "good", fetch: recording });
    run.loader().onload!();
    expect(await submit(contact, { formmethod: "get" })).toBe(false);
    expect(await submit(contact, { formaction: "https://elsewhere.example/post" })).toBe(false);
    expect(sent).toHaveLength(0);
    expect(await submit(contact, { formaction: "/contact/urgent", formenctype: "multipart/form-data" })).toBe(true);
    expect(sent.map((s) => s.url)).toEqual([`${running.url}/contact/urgent`]);
    expect(sent[0]!.init.body).not.toBeInstanceOf(URLSearchParams);
  });

  it("when the answer does not arrive the page says the form may have been sent, and the widget is reset", async () => {
    const { script } = await served();
    const failing: typeof fetch = async () => { throw new TypeError("Failed to fetch"); };
    const contact = formOf({ method: "post", action: "/contact" }, [["message", "Hi"]]);
    const run = runScript(script, { origin: running.url, forms: [contact], token: () => "good", fetch: failing });
    run.loader().onload!();
    await submit(contact);
    expect(noteOf(contact)).toBe("The answer did not arrive, and the form may have been sent. Check before you send it again.");
    expect(run.widget.reset).toBe(1);
  });

  it("hCaptcha: its script and widget, no Turnstile-only options, its token field removed; a form without a submit button gets the widget at its end", async () => {
    const script = formScript({ provider: "hcaptcha", siteKey: "hc-site", secretEnv: "UNUSED", header: "x-agent-custody-challenge", timeoutMs: 5000, hostnames: ["shop.example"], maxInFlight: 64 } as Parameters<typeof formScript>[0]);
    const sent: { url: string; init: RequestInit }[] = [];
    const recording: typeof fetch = async (input, init) => { sent.push({ url: String(input), init: init! }); return new Response("{}", { headers: { "content-type": "application/json" } }); };
    const bare = { ...formOf({ method: "post", action: "/contact" }, [["message", "Hi"], ["h-captcha-response", "tok"], ["g-recaptcha-response", "tok"]]), noButton: true };
    const run = runScript(script, { origin: running.url, forms: [bare], token: () => "hc-token", fetch: recording, provider: "hcaptcha" });
    expect(run.loader().src).toBe("https://js.hcaptcha.com/1/api.js?render=explicit");
    run.loader().onload!();
    expect(run.widget.rendered).toEqual([{ sitekey: "hc-site" }]);
    expect(bare.inserted.map((e) => e.className)).toEqual(["agent-custody-challenge", "agent-custody-challenge-note"]);
    await submit(bare);
    expect((sent[0]!.init.headers as Record<string, string>)["x-agent-custody-challenge"]).toBe("hc-token");
    expect(String(sent[0]!.init.body)).toBe("message=Hi");
    expect(noteOf(bare)).toBe("Sent.");

    // a button that posts natively (GET here) takes no token with it: the widget's hidden fields are disabled first
    const hidden = [{ name: "h-captcha-response", disabled: false }, { name: "g-recaptcha-response", disabled: false }, { name: "message", disabled: false }];
    const withFields = { ...formOf({ method: "post", action: "/contact" }, [["message", "Hi"]]), hidden };
    const again = runScript(script, { origin: running.url, forms: [withFields], token: () => "hc-token", fetch: recording, provider: "hcaptcha" });
    again.loader().onload!();
    expect(await submit(withFields, { formmethod: "get" })).toBe(false);
    expect(hidden.map((el) => [el.name, el.disabled])).toEqual([["h-captcha-response", true], ["g-recaptcha-response", true], ["message", false]]);
    expect(sent).toHaveLength(1);
  });

  it("a config value cannot close the script element or inject code: '<' is escaped, and the value arrives intact", () => {
    const siteKey = 'k</script><script>alert(1)</script>"';
    const script = formScript({ provider: "turnstile", siteKey, secretEnv: "UNUSED", header: "x-agent-custody-challenge", timeoutMs: 5000, hostnames: ["shop.example"], maxInFlight: 64 } as Parameters<typeof formScript>[0]);
    expect(script).not.toContain("</script>");
    const form = formOf({ method: "post", action: "/contact" });
    const run = runScript(script, { origin: "https://shop.example", forms: [form], token: () => "", fetch });
    run.loader().onload!();
    expect(run.widget.rendered).toEqual([{ sitekey: siteKey, "response-field": false }]);
  });

  it("a door with no challenge has no form protector: 404, and the in-process door has none either", async () => {
    const plain = buildDoorFixture(mkdtempSync(join(tmpdir(), "agent-custody-door-form-plain-")), shop.url);
    const h = await createDoorHost(loadDoorConfig(plain.configFile));
    const d = await serveDoor(h, { port: 0, log: () => {} });
    try {
      const res = await fetch(`${d.url}${FORM_SCRIPT_PATH}`);
      expect(res.status).toBe(404);
      expect(await res.json()).toEqual({ error: "this door has no challenge configured, so it has no form protector" });
    } finally {
      await d.close();
      await h.close();
    }
  });

  it("the in-process door serves the same script from its middleware, without deciding or receipting the request", async () => {
    const app = buildDoorFixture(mkdtempSync(join(tmpdir(), "agent-custody-door-form-app-")), shop.url, { challenge });
    const cfg = JSON.parse(readFileSync(app.configFile, "utf8")) as Record<string, unknown>;
    delete cfg.origin;
    writeFileSync(app.configFile, JSON.stringify(cfg));
    const guard = door(app.configFile, { autoFlush: false });
    let appRan = 0;
    const server = createServer((req, res) => guard(req, res, () => { appRan += 1; res.end("app"); }));
    await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
    try {
      const res = await fetch(`http://127.0.0.1:${(server.address() as AddressInfo).port}${FORM_SCRIPT_PATH}?v=3`);
      expect(res.status).toBe(200);
      expect(res.headers.get(RECEIPT_HEADER)).toBeNull();
      expect(await res.text()).toBe(guard.formScript());
      expect(appRan).toBe(0);
      expect(guard.formScript()).not.toContain(SECRET);
    } finally {
      server.closeAllConnections();
      await new Promise<void>((r) => server.close(() => r()));
      guard.close();
    }
  });
});
