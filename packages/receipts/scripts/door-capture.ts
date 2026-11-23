// Records a small labelled set from real clients on this machine, for `agent-custody door measure`
// (docs/door-error-rates.md). Run it with node from packages/receipts:
//
//   node scripts/door-capture.ts --out labelled/capture.jsonl --meta labelled/capture.meta.json [--hellos <file>] [--skip safari,chrome-headful]
//
// It starts two listeners on localhost. The TLS listener has a throwaway self-signed certificate, reads the ClientHello
// before the handshake, and computes its JA4. The plain listener serves the same site over http. Then it runs each
// client in turn, so every request in that time belongs to the client's session. It adds the certificate to no trust
// store: each tool gets the certificate as its CA for one process, and Chrome gets its key hash for one temporary profile.
// Safari stops at the certificate warning, so its ClientHello is recorded and its headers come from the plain listener.
//
// An observation is what a door behind a TLS proxy records: `secure` is true. For the plain listener this is an
// assumption: a browser treats http://localhost as a secure origin and sends it the headers that it sends to an https
// site. The script prints a comparison of Chrome's header names on the two listeners.
import { execFileSync, spawn, type ChildProcess } from "node:child_process";
import { X509Certificate, createHash } from "node:crypto";
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { createServer as createHttpServer, type IncomingMessage, type ServerResponse } from "node:http";
import { createServer as createHttpsServer } from "node:https";
import { createServer as createTcpServer, type Server, type Socket } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { setTimeout as sleep } from "node:timers/promises";
import { parseArgs } from "node:util";
import { formScript, FORM_SCRIPT_PATH } from "../src/door-form.ts";
import type { LabelledRecord } from "../src/door-measure.ts";
import { FLAG_SIGNALS, observationOf, type FlagSignal } from "../src/door-signals.ts";
import { clientHelloBytes, ja4Of } from "./ja4.ts";

const { values: args } = parseArgs({ options: { out: { type: "string" }, meta: { type: "string" }, hellos: { type: "string" }, skip: { type: "string", default: "" } } });
if (!args.out || !args.meta) throw new Error("door-capture needs --out <capture.jsonl> and --meta <capture.meta.json>");
const skip = new Set(args.skip.split(",").filter(Boolean));

const CHROME = "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome";
// A label is good only for a flag that the capture can show true or false. The known-tool table of door-signals.ts is
// filled from this capture, so no session here is good for that flag: its tools are in the table and its browsers are
// not, by construction. The pace of a session is the pace of this script, so no session is good for the timing flag.
const MISMATCH_FLAGS: FlagSignal[] = ["fingerprint.headers.mismatch", "fingerprint.headers.hintsMismatch", "fingerprint.headers.fetchInvalid", "fingerprint.tls.mismatch"];
const BEHAVIOUR_FLAGS: FlagSignal[] = ["behaviour.navigation.directWrite", "behaviour.form.fast", "behaviour.form.noInput"];

const tmp = mkdtempSync(join(tmpdir(), "door-capture-"));
const started = performance.now();
const now = () => Math.round(performance.now() - started);

// One file, five sets, so that each kind of client has its own rates: a rate over a mix of kinds would say more about
// the mix this script chose than about any client.
const SETS = { browsers: "capture-real-browsers", tools: "capture-tools", copied: "capture-tools-browser-ua", headless: "capture-headless-chrome", headlessCopied: "capture-headless-chrome-browser-ua" };
interface Session { set: string; name: string; label: LabelledRecord["label"]; labelSource: string; validFor: FlagSignal[] }
let current: Session | undefined;
const records: (LabelledRecord & { order: number })[] = [];
const hellos: { session: string; ja4: string; hex: string; at: number }[] = [];
const ja4ByPort = new Map<number, string>();
let order = 0;

const PAGE = `<!doctype html><html lang="en"><head><meta charset="utf-8"><title>Capture</title><link rel="stylesheet" href="/style.css">
<script src="/app.js" defer></script><script src="${FORM_SCRIPT_PATH}" defer></script></head>
<body><h1>Capture</h1><img src="/pixel.png" alt="" width="1" height="1">
<form method="post" action="/submit"><input name="name" autocomplete="off"><input name="message" autocomplete="off"><button type="submit">Send</button></form></body></html>`;
const APP = `fetch("/api/data").then((r) => r.json()).then(() => fetch("/api/echo", { method: "POST", body: "{}", headers: { "content-type": "application/json" } }));`;
const STUB = `window.turnstile = { render: () => "capture", getResponse: () => "capture", reset: () => {} };`;
// the door's own script, with the provider's widget replaced by a local stub: the capture asks no outside service
const FORM_SCRIPT = formScript({ provider: "turnstile", siteKey: "capture", secretEnv: "UNUSED", hostnames: ["localhost"], header: "x-agent-custody-challenge", timeoutMs: 1000, maxInFlight: 1 } as Parameters<typeof formScript>[0], true)
  .replace("https://challenges.cloudflare.com/turnstile/v0/api.js?render=explicit", "/widget-stub.js");
if (!FORM_SCRIPT.includes("/widget-stub.js")) throw new Error("the form script did not take the stub");
const PIXEL = Buffer.from("iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNkYPhfDwAChwGA60e6kgAAAABJRU5ErkJggg==", "base64");

function handle(secureTransport: boolean) {
  return (req: IncomingMessage, res: ServerResponse) => {
    const path = (req.url ?? "/").split("?")[0]!;
    const method = req.method ?? "GET";
    if (current) {
      const ja4 = secureTransport ? ja4ByPort.get(req.socket.remotePort ?? -1) : undefined;
      const observation = observationOf({ headers: req.headers, rawHeaders: req.rawHeaders, transport: { secure: true, ...(ja4 ? { tls: { ja4 } } : {}) } }, now(), method, path);
      records.push({ set: current.set, session: current.name, label: current.label, labelSource: current.labelSource, validFor: current.validFor, observation, order: order++ });
    }
    req.resume();
    const send = (type: string, body: string | Buffer, status = 200) => res.writeHead(status, { "content-type": type, "cache-control": "no-store" }).end(body);
    if (method === "POST") return send(path.startsWith("/api/") ? "application/json" : "text/html; charset=utf-8", path.startsWith("/api/") ? "{}" : "<!doctype html><title>Received</title><p>Received.</p>");
    if (path === "/") return send("text/html; charset=utf-8", PAGE);
    if (path === "/style.css") return send("text/css", "body { font-family: sans-serif }");
    if (path === "/app.js") return send("text/javascript", APP);
    if (path === FORM_SCRIPT_PATH) return send("text/javascript", FORM_SCRIPT);
    if (path === "/widget-stub.js") return send("text/javascript", STUB);
    if (path === "/pixel.png") return send("image/png", PIXEL);
    if (path === "/api/data") return send("application/json", "{}");
    return send("text/plain", "not found", 404);
  };
}

const listen = (server: Server, port: number, host: string) => new Promise<number>((resolve, reject) => server.once("error", reject).listen(port, host, () => resolve((server.address() as { port: number }).port)));
/** One port on 127.0.0.1 and on ::1, since a client resolves localhost to either. */
async function listenBoth(make: () => Server): Promise<{ port: number; servers: Server[] }> {
  const first = make();
  const port = await listen(first, 0, "127.0.0.1");
  const second = make();
  try {
    await listen(second, port, "::1");
    return { port, servers: [first, second] };
  } catch {
    return { port, servers: [first] };
  }
}

execFileSync("openssl", ["req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes", "-days", "2", "-subj", "/CN=localhost", "-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1", "-keyout", join(tmp, "key.pem"), "-out", join(tmp, "cert.pem")], { stdio: "ignore" });
const ca = join(tmp, "cert.pem");
const spki = createHash("sha256").update(new X509Certificate(readFileSync(ca)).publicKey.export({ type: "spki", format: "der" })).digest("base64");
// offers http/1.1 only: the JA4 comes from the ClientHello, which the client sends before it learns this
const https = createHttpsServer({ key: readFileSync(join(tmp, "key.pem")), cert: readFileSync(ca), ALPNProtocols: ["http/1.1"] }, handle(true));
https.on("tlsClientError", () => {});
const tlsFront = () =>
  createTcpServer((socket: Socket) => {
    let seen = Buffer.alloc(0);
    socket.on("error", () => {});
    const onData = (chunk: Buffer) => {
      seen = Buffer.concat([seen, chunk]);
      let hello: Buffer | null = null;
      try {
        hello = clientHelloBytes(seen);
      } catch {
        return socket.destroy();
      }
      if (!hello && seen.length < 32_768) return;
      socket.removeListener("data", onData);
      socket.pause();
      if (hello) {
        const ja4 = ja4Of(hello);
        ja4ByPort.set(socket.remotePort ?? -1, ja4);
        hellos.push({ session: current?.name ?? "none", ja4, hex: hello.toString("hex"), at: now() });
      }
      socket.unshift(seen);
      https.emit("connection", socket);
      process.nextTick(() => socket.resume());
    };
    socket.on("data", onData);
  });
const tls = await listenBoth(tlsFront);
const plain = await listenBoth(() => createHttpServer(handle(false)));
const TLS = `https://localhost:${tls.port}`;
const PLAIN = `http://localhost:${plain.port}`;

async function session(s: Session, run: () => Promise<void> | void): Promise<void> {
  if ([...skip].some((k) => s.name.startsWith(k))) return;
  current = s;
  try {
    await run();
  } catch (e) {
    console.error(`${s.name}: ${e instanceof Error ? e.message.split("\n")[0] : e}`);
  }
  await sleep(300);
  current = undefined;
  console.error(`${s.name}: ${records.filter((r) => r.session === s.name).length} arrival(s)`);
}
// A mismatch flag compares the request with the browser that the User-Agent states. A client with its own User-Agent
// states no browser, so the flag cannot be true for it, and its sessions are not labelled for that flag.
const automated = (set: string, name: string): Session => ({ set, name, label: "automated", labelSource: "scripted-client", validFor: set === SETS.tools || set === SETS.headless ? BEHAVIOUR_FLAGS : [...MISMATCH_FLAGS, ...BEHAVIOUR_FLAGS] });
const browser = (name: string): Session => ({ set: SETS.browsers, name, label: "human", labelSource: "real-browser", validFor: MISMATCH_FLAGS });
// never the sync form: this process is also the server that the client waits for
const run = (cmd: string, argv: string[], env: Record<string, string> = {}) =>
  new Promise<void>((resolve, reject) => {
    const child = spawn(cmd, argv, { stdio: ["ignore", "ignore", "pipe"], timeout: 120_000, env: { ...process.env, ...env } });
    let stderr = "";
    child.stderr!.on("data", (d: Buffer) => (stderr += d));
    child.once("error", reject).once("exit", (code) => (code === 0 ? resolve() : reject(new Error(`${cmd} exited ${code}: ${stderr.trim()}`))));
  });
const version = (cmd: string, argv: string[]) => {
  try {
    return execFileSync(cmd, argv, { encoding: "utf8" }).trim().split("\n")[0]!;
  } catch {
    return "absent";
  }
};

// ---- the tools: each takes the base URL, the CA file, a User-Agent ("" for its own), and a mode
const BODY = "name=a&message=b";
const PYTHON = `
import ssl, sys, urllib.request
base, ca, ua, mode = sys.argv[1:5]
context = ssl.create_default_context(cafile=ca)
def do(path, data=None):
    request = urllib.request.Request(base + path, data=data, headers={"User-Agent": ua} if ua else {})
    urllib.request.urlopen(request, context=context, timeout=10).read()
if mode != "post":
    do("/")
do("/submit", b"${BODY}")
`;
const GO = `package main

import (
	"crypto/tls"
	"crypto/x509"
	"io"
	"net/http"
	"os"
	"strings"
)

func main() {
	base, ca, ua, mode := os.Args[1], os.Args[2], os.Args[3], os.Args[4]
	pem, err := os.ReadFile(ca)
	if err != nil {
		panic(err)
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(pem)
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = &tls.Config{RootCAs: pool}
	client := &http.Client{Transport: transport}
	do := func(method, path, body string) {
		req, _ := http.NewRequest(method, base+path, strings.NewReader(body))
		if ua != "" {
			req.Header.Set("User-Agent", ua)
		}
		if body != "" {
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		}
		res, err := client.Do(req)
		if err != nil {
			panic(err)
		}
		io.Copy(io.Discard, res.Body)
		res.Body.Close()
	}
	if mode != "post" {
		do("GET", "/", "")
	}
	do("POST", "/submit", "${BODY}")
}
`;
const JS = (tlsOption: string) => `
const [base, ca, ua, mode] = process.argv.slice(-4);
const headers = ua ? { "user-agent": ua } : {};
const more = () => ({ signal: AbortSignal.timeout(10_000), ...${tlsOption} });
if (mode !== "post") await (await fetch(base + "/", { headers, ...more() })).text();
await (await fetch(base + "/submit", { method: "POST", body: "${BODY}", headers: { ...headers, "content-type": "application/x-www-form-urlencoded" }, ...more() })).text();
`;
writeFileSync(join(tmp, "client.py"), PYTHON);
writeFileSync(join(tmp, "client.go"), GO);
writeFileSync(join(tmp, "client-node.mjs"), JS("{}"));
writeFileSync(join(tmp, "client-bun.mjs"), JS(`{ tls: { ca: require("node:fs").readFileSync(ca, "utf8") } }`));

const tools: Record<string, (ua: string, mode: string) => Promise<void>> = {
  curl: async (ua, mode) => {
    const base = ["-sS", "--max-time", "10", "--cacert", ca, "-o", "/dev/null", ...(ua ? ["-A", ua] : [])];
    if (mode !== "post") await run("curl", [...base, `${TLS}/`]);
    await run("curl", [...base, "-d", BODY, `${TLS}/submit`]);
  },
  "python-urllib": (ua, mode) => run("python3", ["-I", join(tmp, "client.py"), TLS, ca, ua, mode]),
  go: (ua, mode) => run("go", ["run", join(tmp, "client.go"), TLS, ca, ua, mode], { GO111MODULE: "off", GOFLAGS: "" }),
  node: (ua, mode) => run(process.execPath, [join(tmp, "client-node.mjs"), TLS, ca, ua, mode], { NODE_EXTRA_CA_CERTS: ca }),
  bun: (ua, mode) => run("bun", [join(tmp, "client-bun.mjs"), TLS, ca, ua, mode]),
};

// ---- Chrome
const CHROME_FLAGS = ["--no-first-run", "--no-default-browser-check", "--disable-background-networking", "--disable-component-update", "--disable-sync", "--disable-default-apps", `--ignore-certificate-errors-spki-list=${spki}`];
let profiles = 0;
function chrome(extra: string[]): { child: ChildProcess; dir: string; stop: () => Promise<void> } {
  const dir = join(tmp, `chrome-${profiles++}`);
  const child = spawn(CHROME, [`--user-data-dir=${dir}`, ...CHROME_FLAGS, ...extra], { stdio: "ignore" });
  const stop = async () => {
    child.kill("SIGTERM");
    await Promise.race([new Promise((r) => child.once("exit", r)), sleep(5000)]);
    if (child.exitCode === null && child.signalCode === null) child.kill("SIGKILL");
    await sleep(300);
  };
  return { child, dir, stop };
}

interface Cdp { send(method: string, params?: object, sessionId?: string): Promise<Record<string, unknown>>; close(): void }
/** A DevTools protocol client over the WebSocket that Node has. */
async function cdp(dir: string): Promise<Cdp> {
  const portFile = join(dir, "DevToolsActivePort");
  for (let i = 0; i < 100 && !existsSync(portFile); i++) await sleep(100);
  const [port, path] = readFileSync(portFile, "utf8").trim().split("\n");
  const ws = new WebSocket(`ws://127.0.0.1:${port}${path}`);
  await new Promise((resolve, reject) => {
    ws.onopen = resolve;
    ws.onerror = reject;
  });
  let id = 0;
  const waiting = new Map<number, { resolve: (v: Record<string, unknown>) => void; reject: (e: Error) => void }>();
  ws.onmessage = (event) => {
    const m = JSON.parse(String(event.data)) as { id?: number; result?: Record<string, unknown>; error?: { message: string } };
    const w = m.id === undefined ? undefined : waiting.get(m.id);
    if (!w) return;
    waiting.delete(m.id!);
    if (m.error) w.reject(new Error(m.error.message));
    else w.resolve(m.result ?? {});
  };
  return {
    send: (method, params = {}, sessionId) => new Promise((resolve, reject) => {
      waiting.set(++id, { resolve, reject });
      ws.send(JSON.stringify({ id, method, params, ...(sessionId ? { sessionId } : {}) }));
    }),
    close: () => ws.close(),
  };
}

/** Opens the page in a new tab of a headless Chrome and gives the tab's protocol session, after the page's requests settle. */
async function tab(c: Cdp, url: string): Promise<string> {
  const { targetId } = await c.send("Target.createTarget", { url });
  const { sessionId } = await c.send("Target.attachToTarget", { targetId, flatten: true });
  await sleep(2500);
  return sessionId as string;
}
const evaluate = async (c: Cdp, tabSession: string, expression: string) => ((await c.send("Runtime.evaluate", { expression, returnByValue: true }, tabSession)).result as { value?: unknown } | undefined)?.value;
const TEXT = "a short message";
async function typeKeys(c: Cdp, tabSession: string, text: string, pauseMs: () => number): Promise<void> {
  for (const ch of text) {
    await c.send("Input.dispatchKeyEvent", { type: "keyDown", text: ch, key: ch, unmodifiedText: ch }, tabSession);
    await c.send("Input.dispatchKeyEvent", { type: "keyUp", key: ch }, tabSession);
    const pause = pauseMs();
    if (pause) await sleep(pause);
  }
}
const pressEnter = async (c: Cdp, tabSession: string) => {
  await c.send("Input.dispatchKeyEvent", { type: "keyDown", key: "Enter", code: "Enter", windowsVirtualKeyCode: 13, text: "\r" }, tabSession);
  await c.send("Input.dispatchKeyEvent", { type: "keyUp", key: "Enter", code: "Enter", windowsVirtualKeyCode: 13 }, tabSession);
};
const focus = (c: Cdp, tabSession: string) => evaluate(c, tabSession, `document.querySelector('input[name="message"]').focus()`);

// the four ways a script fills the form, and what each makes the form report say
const fills: Record<string, (c: Cdp, tabSession: string) => Promise<void>> = {
  // sets the values from script and submits from script: no key press, no pointer press
  "set-value": async (c, t) => void (await evaluate(c, t, `document.querySelector('input[name="message"]').value = ${JSON.stringify(TEXT)}; document.querySelector("form").requestSubmit()`)),
  // inserts the text as a paste would, then clicks the button with a synthetic mouse
  "insert-text-click": async (c, t) => {
    await focus(c, t);
    await c.send("Input.insertText", { text: TEXT }, t);
    const box = (await evaluate(c, t, `(() => { const r = document.querySelector("button").getBoundingClientRect(); return { x: r.x + r.width / 2, y: r.y + r.height / 2 }; })()`)) as { x: number; y: number };
    for (const type of ["mousePressed", "mouseReleased"]) await c.send("Input.dispatchMouseEvent", { type, x: box.x, y: box.y, button: "left", clickCount: 1 }, t);
  },
  // sends each key as fast as the protocol takes it
  "keys-no-pause": async (c, t) => {
    await focus(c, t);
    await typeKeys(c, t, TEXT, () => 0);
    await pressEnter(c, t);
  },
  // sends each key with a pause, as a script that imitates a person does
  "keys-paced": async (c, t) => {
    await focus(c, t);
    await typeKeys(c, t, TEXT, () => 80 + Math.floor(Math.random() * 120));
    await pressEnter(c, t);
  },
};

// ---- the run
let chromeUa = "";
if (!skip.has("chrome-headful")) {
  for (const [name, url] of [["chrome-tls", `${TLS}/`], ["chrome-plain", `${PLAIN}/`]] as const) {
    await session(browser(name), async () => {
      const c = chrome([url]);
      await sleep(7000);
      await c.stop();
    });
  }
  chromeUa = records.find((r) => r.session === "chrome-tls")?.observation?.userAgent ?? "";
}
if (!skip.has("safari")) {
  await session(browser("safari-plain"), async () => {
    await run("open", ["-a", "Safari", `${PLAIN}/`]);
    await sleep(8000);
  });
  // Safari stops at the certificate warning: the ClientHello is all that arrives
  current = browser("safari-tls");
  await run("open", ["-a", "Safari", `${TLS}/`]);
  await sleep(6000);
  current = undefined;
  try {
    await run("osascript", ["-e", 'tell application "Safari" to quit']);
  } catch {
    try {
      await run("pkill", ["-x", "Safari"]);
    } catch { /* not running */ }
  }
  const hello = hellos.find((h) => h.session === "safari-tls");
  const userAgent = records.find((r) => r.session === "safari-plain")?.observation?.userAgent;
  // one record from two connections of the same browser: the ClientHello of the https attempt and the User-Agent of the plain page load
  if (hello && userAgent) records.push({ set: SETS.browsers, session: "safari-tls", label: "human", labelSource: "real-browser", validFor: ["fingerprint.tls.mismatch"], observation: { at: hello.at, method: "GET", path: "/", secure: true, userAgent, referer: "absent", secFetch: {}, tls: { ja4: hello.ja4 } }, order: order++ });
  console.error(`safari-tls: ${hello ? `ClientHello ${hello.ja4}` : "no ClientHello"}`);
}
// a program that sends a browser's User-Agent: the one Chrome sent here, or a fixed one when Chrome was skipped
const copiedUa = chromeUa || "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/157.0.0.0 Safari/537.36";
for (const [tool, go] of Object.entries(tools)) {
  if (skip.has(tool)) continue;
  await session(automated(SETS.tools, `${tool}-get-post`), () => go("", "get-post"));
  await session(automated(SETS.tools, `${tool}-post`), () => go("", "post"));
  await session(automated(SETS.copied, `${tool}-browser-ua-get-post`), () => go(copiedUa, "get-post"));
}
if (!skip.has("chrome-headless")) {
  for (const [name, set, extra] of [["chrome-headless", SETS.headless, []], ["chrome-headless-browser-ua", SETS.headlessCopied, [`--user-agent=${copiedUa}`]]] as const) {
    const c = chrome(["--headless=new", "--remote-debugging-port=0", ...extra, "about:blank"]);
    try {
      const protocol = await cdp(c.dir);
      await session(automated(set, `${name}-load`), async () => void (await tab(protocol, `${TLS}/`)));
      for (const [fill, act] of Object.entries(fills)) {
        await session(automated(set, `${name}-form-${fill}`), async () => {
          const t = await tab(protocol, `${TLS}/`);
          await act(protocol, t);
          await sleep(1500);
        });
      }
      protocol.close();
    } finally {
      await c.stop();
    }
  }
}

for (const s of [...tls.servers, ...plain.servers]) s.close();
https.close();

// ---- what was recorded
const names = (sessionName: string, path: string, method = "GET") => records.find((r) => r.session === sessionName && r.observation?.path === path && r.observation.method === method)?.observation?.headers?.names ?? [];
const comparison: Record<string, { tlsOnly: string[]; plainOnly: string[] }> = {};
for (const [path, method] of [["/", "GET"], ["/style.css", "GET"], ["/app.js", "GET"], ["/pixel.png", "GET"], ["/api/data", "GET"], ["/api/echo", "POST"]] as const) {
  const [a, b] = [names("chrome-tls", path, method), names("chrome-plain", path, method)];
  if (a.length && b.length) comparison[`${method} ${path}`] = { tlsOnly: a.filter((n) => !b.includes(n)), plainOnly: b.filter((n) => !a.includes(n)) };
}
const sessionsSeen = [...new Set(records.map((r) => r.session))];
const ja4BySession = Object.fromEntries(sessionsSeen.map((s) => [s, [...new Set(records.filter((r) => r.session === s).map((r) => r.observation?.tls?.ja4).filter(Boolean))]]).filter(([, v]) => (v as string[]).length));
records.sort((a, b) => sessionsSeen.indexOf(a.session) - sessionsSeen.indexOf(b.session) || a.observation!.at - b.observation!.at || a.order - b.order);
writeFileSync(args.out, records.map(({ order: _order, ...r }) => JSON.stringify(r)).join("\n") + "\n");
const meta = {
  sets: Object.values(SETS),
  date: new Date().toISOString().slice(0, 10),
  machine: { os: `macOS ${version("sw_vers", ["-productVersion"])}`, arch: process.arch },
  clients: {
    chrome: version(CHROME, ["--version"]),
    safari: version("defaults", ["read", "/Applications/Safari.app/Contents/Info", "CFBundleShortVersionString"]),
    curl: version("curl", ["--version"]).replace(/\s*\(.*?\)/, ""),
    python: `${version("python3", ["--version"])} with ${version("python3", ["-I", "-c", "import ssl; print(ssl.OPENSSL_VERSION)"])}`,
    go: version("go", ["version"]),
    node: process.version,
    bun: version("bun", ["--version"]),
  },
  skipped: [...skip],
  records: records.length,
  sessions: sessionsSeen.length,
  ja4BySession,
  chromeHeaderNamesTlsAgainstPlain: comparison,
};
writeFileSync(args.meta, JSON.stringify(meta, null, 2) + "\n");
// one ClientHello for each JA4 seen, so that a reader can compute the JA4 again (test/ja4.test.ts does)
if (args.hellos) writeFileSync(args.hellos, JSON.stringify(hellos.filter((h, i) => hellos.findIndex((x) => x.ja4 === h.ja4) === i).map(({ session: name, ja4, hex }) => ({ session: name, ja4, hex })), null, 2) + "\n");
rmSync(tmp, { recursive: true, force: true });
console.error(`wrote ${records.length} record(s) in ${sessionsSeen.length} session(s) to ${args.out}`);
process.exit(0);
