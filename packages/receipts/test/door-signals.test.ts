// The door's behavioural and fingerprint signals, as pure functions of an observation. A policy may act on a flag, so
// what matters is when each flag is true, when it must stay false for a real browser or a real person, and that a
// hostile header can neither throw nor grow what the door keeps. Every time comes from the observation: no test waits.
import { describe, expect, it } from "vitest";
import {
  FLAG_SIGNALS, FORM_FAST_MIN_KEYS, FORM_FAST_MS_PER_KEY, FORM_REPORT_HEADER, HISTORY_MAX_ARRIVALS, HISTORY_WINDOW_MS, KNOWN_TOOL_JA4, MAX_FORM_EVENTS, MAX_FORM_FILL_MS, MAX_HEADER_NAMES,
  MAX_HEADER_NAME_LENGTH, MAX_USER_AGENT, SEC_CH_UA_SINCE, SEC_FETCH_SINCE, TIMING_MIN_GAPS, TLS13_SINCE,
  createHistoryTracker, flagOf, formSignals, headerFingerprint, isPageLoad, navigationSignals, observationOf, parseFormReport, refererRelation, signalsOf, statedClient, timingSignals, tlsFingerprint,
  type Observation,
} from "../src/door-signals.ts";

const CHROME = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36";
const EDGE = `${CHROME} Edg/126.0.0.0`;
const FIREFOX = "Mozilla/5.0 (X11; Linux x86_64; rv:127.0) Gecko/20100101 Firefox/127.0";
const SAFARI = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15";
const CHROME_IOS = "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/126.0.6478.54 Mobile/15E148 Safari/604.1";
const WEBVIEW = "Mozilla/5.0 (Linux; Android 14; Pixel 8 Build/AP1A; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/126.0.0.0 Mobile Safari/537.36";
const CHROME_HEADERS = ["host", "connection", "sec-ch-ua", "sec-ch-ua-mobile", "sec-ch-ua-platform", "upgrade-insecure-requests", "user-agent", "accept", "sec-fetch-site", "sec-fetch-mode", "sec-fetch-user", "sec-fetch-dest", "accept-encoding", "accept-language"];
// shaped as a JA4, with hashes that are plainly not a real client's
const ja4 = (a: string) => `${a}_000000000000_111111111111`;

const seen = (over: Partial<Observation> = {}): Observation => ({ at: 0, method: "GET", path: "/", referer: "absent", secFetch: {}, ...over });
const browser = (over: Partial<Observation> = {}) => seen({ userAgent: CHROME, secure: true, headers: { names: CHROME_HEADERS, ordered: true }, ...over });

describe("the client a User-Agent states", () => {
  it("names the browser family by its engine, a known tool by its name, and nothing it does not know", () => {
    expect(statedClient(CHROME)).toEqual({ kind: "browser", family: "chromium", version: 126 });
    expect(statedClient(EDGE)).toEqual({ kind: "browser", family: "chromium", version: 126 });
    expect(statedClient(FIREFOX)).toEqual({ kind: "browser", family: "firefox", version: 127 });
    expect(statedClient(SAFARI)).toEqual({ kind: "browser", family: "safari", version: 17 });
    // every browser on iOS runs WebKit, and its own version says nothing of the engine's
    expect(statedClient(CHROME_IOS)).toEqual({ kind: "browser", family: "safari" });
    for (const [ua, family] of [["curl/8.7.1", "curl"], ["python-requests/2.32.3", "python-requests"], ["Go-http-client/2.0", "go-http-client"], ["node", "node"], ["undici", "node"], ["okhttp/4.12.0", "okhttp"], ["Python/3.12 aiohttp/3.9.5", "aiohttp"], ["Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)", "crawler"], [CHROME.replace("Chrome/", "HeadlessChrome/"), "headless-chrome"]] as const) {
      expect(statedClient(ua), ua).toEqual({ kind: "tool", family });
    }
    expect(statedClient("Mozilla/5.0 (Linux; Android 10; CUBOT_X30) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Mobile Safari/537.36")).toMatchObject({ kind: "browser", family: "chromium" });
    expect(statedClient("Mozilla/5.0")).toEqual({ kind: "other", family: "other" });
    expect(statedClient("MyApp/1.0")).toEqual({ kind: "other", family: "other" });
    expect(statedClient(undefined)).toEqual({ kind: "unstated", family: "unstated" });
    expect(statedClient("   ")).toEqual({ kind: "unstated", family: "unstated" });
  });

  it("reads a hostile User-Agent only up to its limit", () => {
    expect(statedClient(`${"x".repeat(MAX_USER_AGENT)} curl/8`)).toEqual({ kind: "other", family: "other" });
    expect(() => statedClient(`Mozilla/5.0 ${"Chrome/".repeat(100_000)}`)).not.toThrow();
  });
});

describe("the header fingerprint", () => {
  it("does not flag a real browser's request, and hashes the header order", () => {
    const fp = headerFingerprint(browser());
    expect(fp).toEqual({ client: "browser", family: "chromium", version: 126, order: expect.stringMatching(/^[0-9a-f]{16}$/), count: CHROME_HEADERS.length, mismatch: false });
    expect(headerFingerprint(browser()).order).toBe(fp.order);
    expect(headerFingerprint(browser({ headers: { names: [...CHROME_HEADERS].reverse(), ordered: true } })).order).not.toBe(fp.order);
    for (const userAgent of [FIREFOX, SAFARI]) expect(headerFingerprint(browser({ userAgent, headers: { names: CHROME_HEADERS.filter((n) => !n.startsWith("sec-ch-")), ordered: true } })).mismatch).toBe(false);
  });

  it("flags a User-Agent that states a browser on a request without the headers that browser always sends, and says which", () => {
    const bare = { names: ["host", "user-agent", "accept"], ordered: true };
    expect(headerFingerprint(browser({ headers: bare }))).toMatchObject({ mismatch: true, missing: "accept-language sec-fetch-site sec-fetch-mode sec-fetch-dest sec-ch-ua" });
    expect(headerFingerprint(browser({ userAgent: FIREFOX, headers: bare }))).toMatchObject({ mismatch: true, missing: "accept-language sec-fetch-site sec-fetch-mode sec-fetch-dest" });
    expect(headerFingerprint(browser({ headers: { names: CHROME_HEADERS.filter((n) => n !== "sec-ch-ua"), ordered: true } }))).toMatchObject({ mismatch: true, missing: "sec-ch-ua" });
  });

  it("expects sec-fetch-* and sec-ch-ua only where every such browser sends them: over https, from the version that began, not on OPTIONS or an upgrade, not from an embedded Chromium", () => {
    const withLanguage = { names: ["host", "user-agent", "accept", "accept-language"], ordered: true };
    // a browser sends them only to an https site, and the door does not always know the scheme
    expect(headerFingerprint(browser({ headers: withLanguage, secure: false })).mismatch).toBe(false);
    const unknownScheme = browser({ headers: withLanguage });
    delete unknownScheme.secure;
    expect(headerFingerprint(unknownScheme).mismatch).toBe(false);
    expect(headerFingerprint(browser({ headers: withLanguage, method: "OPTIONS" })).mismatch).toBe(false);
    expect(headerFingerprint(browser({ headers: { names: [...withLanguage.names, "upgrade"], ordered: true } })).mismatch).toBe(false);
    const at = (version: number) => CHROME.replace("Chrome/126", `Chrome/${version}`);
    expect(headerFingerprint(browser({ headers: withLanguage, userAgent: at(SEC_FETCH_SINCE.chromium - 1) })).mismatch).toBe(false);
    const withFetch = { names: [...withLanguage.names, "sec-fetch-site", "sec-fetch-mode", "sec-fetch-dest"], ordered: true };
    expect(headerFingerprint(browser({ headers: withFetch, userAgent: at(SEC_CH_UA_SINCE - 1) })).mismatch).toBe(false);
    expect(headerFingerprint(browser({ headers: withFetch, userAgent: at(SEC_CH_UA_SINCE) })).mismatch).toBe(true);
    expect(headerFingerprint(browser({ headers: withFetch, userAgent: WEBVIEW })).mismatch).toBe(false);
    // an application that names itself before Chrome/ is embedded Chromium too; the same name after it, or a plain Chrome, is not
    const named = (product: string) => CHROME.replace("Chrome/126.0.0.0", product);
    expect(headerFingerprint(browser({ headers: withFetch, userAgent: named("Claude/4.4212.0 Chrome/152.0.7977.167") })).mismatch).toBe(false);
    expect(headerFingerprint(browser({ headers: withFetch, userAgent: named("Chrome/152.0.7977.167 App/1.0") })).mismatch).toBe(true);
    expect(headerFingerprint(browser({ headers: withFetch, userAgent: named("Chrome/152.0.7977.167") })).mismatch).toBe(true);
    // a WebView browser that drops "; wv)", and a browser that says it is like Chrome: not all of them send sec-ch-ua
    expect(headerFingerprint(browser({ headers: withFetch, userAgent: "Mozilla/5.0 (Linux; Android 13) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/110.0.5481.153 Mobile DuckDuckGo/5 Safari/537.36" })).mismatch).toBe(false);
    expect(headerFingerprint(browser({ headers: withFetch, userAgent: "Mozilla/5.0 (Linux; Android 11; KFTRWI) AppleWebKit/537.36 (KHTML, like Gecko) Silk/120.4.1 like Chrome/120.0.6099.230 Safari/537.36" })).mismatch).toBe(false);
    // the exemption is for sec-ch-ua only: the same User-Agents without the header every browser sends are flagged
    expect(headerFingerprint(browser({ headers: { names: ["host", "user-agent"], ordered: true }, userAgent: "Mozilla/5.0 (Linux; Android 13) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/110.0.5481.153 Mobile Safari/537.36" })).mismatch).toBe(true);
    // a browser on iOS states no engine version, so only the header every browser sends is expected
    expect(headerFingerprint(browser({ headers: withLanguage, userAgent: CHROME_IOS })).mismatch).toBe(false);
    expect(headerFingerprint(browser({ headers: { names: ["host", "user-agent"], ordered: true }, userAgent: CHROME_IOS }))).toMatchObject({ mismatch: true, missing: "accept-language" });
  });

  it("never flags a client that does not state a browser", () => {
    for (const userAgent of ["curl/8.7.1", "python-requests/2.32.3", "MyApp/1.0", undefined]) {
      const o = browser({ headers: { names: ["host"], ordered: true } });
      if (userAgent) o.userAgent = userAgent; else delete o.userAgent;
      expect(headerFingerprint(o).mismatch, String(userAgent)).toBe(false);
    }
  });

  it("records no order when the host cannot see it, and neither order nor a flag when the host does not get the full header set", () => {
    const unordered = headerFingerprint(browser({ headers: { names: ["host", "user-agent"], ordered: false } }));
    expect(unordered).toMatchObject({ count: 2, mismatch: true });
    expect(unordered).not.toHaveProperty("order");
    const partial = browser();
    delete partial.headers;
    expect(headerFingerprint(partial)).toEqual({ client: "browser", family: "chromium", version: 126, mismatch: false });
  });

  it("reads at most a fixed number of names of a fixed length", () => {
    const flood = headerFingerprint(browser({ headers: { names: Array.from({ length: 50_000 }, (_, i) => `x-${i}-${"a".repeat(10_000)}`), ordered: true } }));
    expect(flood.count).toBe(MAX_HEADER_NAMES);
    // two names that differ only past the limit are one name to the fingerprint
    const long = (tail: string) => headerFingerprint(seen({ headers: { names: [`${"n".repeat(MAX_HEADER_NAME_LENGTH)}${tail}`], ordered: true } })).order;
    expect(long("a")).toBe(long("b"));
  });
});

describe("the TLS fingerprint", () => {
  it("reads the first section of a JA4: protocol, version, SNI, counts, ALPN", () => {
    expect(tlsFingerprint(seen({ tls: { ja4: ja4("t13d1516h2") } }))).toEqual({ ja4: ja4("t13d1516h2"), malformed: false, protocol: "tcp", version: "13", sni: true, ciphers: 15, extensions: 16, alpn: "h2", mismatch: false, knownTool: false });
    expect(tlsFingerprint(seen({ tls: { ja4: ja4("q13i0310h3") } }))).toMatchObject({ protocol: "quic", sni: false, ciphers: 3, extensions: 10, alpn: "h3" });
  });

  it("flags a stated browser whose ClientHello offers no TLS 1.3 or no ALPN, and no other client", () => {
    const flag = (userAgent: string | undefined, a: string) => tlsFingerprint(seen({ ...(userAgent ? { userAgent } : {}), tls: { ja4: ja4(a) } }))!.mismatch;
    for (const ua of [CHROME, FIREFOX, SAFARI]) {
      expect(flag(ua, "t13d1516h2"), ua).toBe(false);
      expect(flag(ua, "t13d1516h1"), ua).toBe(false);
      expect(flag(ua, "q13d0310h3"), ua).toBe(false);
      expect(flag(ua, "t12d1516h2"), ua).toBe(true);
      expect(flag(ua, "t13d151600"), ua).toBe(true);
    }
    expect(flag("curl/8.7.1", "t12d151600")).toBe(false);
    expect(flag(undefined, "t12d151600")).toBe(false);
    // a browser from before TLS 1.3, and one that states no engine version, are not judged
    expect(flag(CHROME.replace("Chrome/126", `Chrome/${TLS13_SINCE.chromium - 1}`), "t12d1516h2")).toBe(false);
    expect(flag(CHROME_IOS, "t12d1516h2")).toBe(false);
  });

  it("records a value that is not a JA4 as malformed, with nothing read from it", () => {
    // a proxy that appends to the client's header instead of overwriting it gives the first of these
    for (const bad of [`${ja4("t13d1516h2")}, ${ja4("t13d1516h2")}`, "", "t13d1516h2", ja4("x13d1516h2"), ja4("t13d1516h2").toUpperCase(), `${ja4("t13d1516h2")}\n`, "a".repeat(100_000)]) {
      expect(tlsFingerprint(seen({ userAgent: CHROME, tls: { ja4: bad } })), bad.slice(0, 40)).toEqual({ malformed: true, mismatch: false, knownTool: false });
    }
    for (const notText of [null, 7, {}, [ja4("t13d1516h2")]]) expect(tlsFingerprint(seen({ tls: { ja4: notText as unknown as string } }))).toEqual({ malformed: true, mismatch: false, knownTool: false });
  });

  it("takes what Cloudflare gives without a JA4 only in the documented shapes, and is absent when nothing usable arrived", () => {
    const sha1 = "2jmj7l5rSw0yVb/vlWAYkK/YBwk=";
    expect(tlsFingerprint(seen({ tls: { negotiated: "TLSv1.3", cipher: "AEAD-AES128-GCM-SHA256", extensionsSha1: sha1, helloLength: 508 } }))).toEqual({ malformed: false, negotiated: "13", cipher: "AEAD-AES128-GCM-SHA256", extensionsSha1: sha1, helloLength: 508, mismatch: false, knownTool: false });
    expect(tlsFingerprint(seen({ tls: { negotiated: "TLSv9", cipher: "a b", extensionsSha1: "short", helloLength: 1.5 } }))).toBeUndefined();
    expect(tlsFingerprint(seen({ tls: { helloLength: -1 } }))).toBeUndefined();
    expect(tlsFingerprint(seen({ tls: {} }))).toBeUndefined();
    expect(tlsFingerprint(seen())).toBeUndefined();
  });

  it("marks a JA4 of the known-tool table, whatever the User-Agent says, and no other", () => {
    const [known] = [...KNOWN_TOOL_JA4.keys()];
    expect(KNOWN_TOOL_JA4.get(known!)).toBe("curl");
    expect(tlsFingerprint(seen({ userAgent: CHROME, tls: { ja4: known! } }))).toMatchObject({ knownTool: true, mismatch: false });
    expect(tlsFingerprint(seen({ userAgent: "curl/8.7.1", tls: { ja4: ja4("t13d1516h2") } }))!.knownTool).toBe(false);
    // each entry is a well-formed JA4; test/door-measure.test.ts checks each against the committed capture
    for (const key of KNOWN_TOOL_JA4.keys()) expect(tlsFingerprint(seen({ tls: { ja4: key } }))).toMatchObject({ malformed: false, ja4: key });
  });
});

describe("the source history", () => {
  const paced = (gaps: number[]) => {
    const history = createHistoryTracker();
    let at = 1000;
    let last = history.record("remote:a", seen({ at }));
    for (const gap of gaps) last = history.record("remote:a", seen({ at: (at += gap) }));
    return timingSignals(last);
  };

  it("a first arrival has no gap; later ones give the count and the median gap as integers", () => {
    expect(paced([])).toEqual({ gaps: 0, regular: false });
    expect(paced([300])).toEqual({ gaps: 1, medianGapMs: 300, regular: false });
    expect(paced([100, 900, 301])).toEqual({ gaps: 3, medianGapMs: 301, regular: false });
    expect(paced([100, 201, 400, 900])).toEqual({ gaps: 4, medianGapMs: 300, regular: false });
    // a clock that gives fractions of a millisecond still gives integers
    const history = createHistoryTracker();
    history.record("s", seen({ at: 10.7 }));
    expect(timingSignals(history.record("s", seen({ at: 250.2 })))).toEqual({ gaps: 1, medianGapMs: 240, regular: false });
  });

  it("flags a steady pace only with enough gaps, a small spread, and a pace slower than a burst", () => {
    expect(paced(Array(TIMING_MIN_GAPS).fill(1000)).regular).toBe(true);
    expect(paced([1000, 1040, 960, 1010, 990, 1000]).regular).toBe(true);
    expect(paced(Array(TIMING_MIN_GAPS - 1).fill(1000)).regular).toBe(false);
    // a person: gaps that vary
    expect(paced([1000, 4200, 800, 15_000, 2300, 1000]).regular).toBe(false);
    expect(paced([1000, 1000, 1000, 1000, 1000, 1200]).regular).toBe(false);
    // a page that loads its parts at once is a burst, which the rate counts
    expect(paced(Array(10).fill(0)).regular).toBe(false);
    expect(paced(Array(10).fill(20)).regular).toBe(false);
  });

  it("keeps a fixed number of arrivals per source and forgets what is older than the window", () => {
    expect(paced(Array(500).fill(1000)).gaps).toBe(HISTORY_MAX_ARRIVALS - 1);
    const history = createHistoryTracker();
    history.record("s", seen({ at: 0 }));
    history.record("s", seen({ at: 1000 }));
    expect(history.record("s", seen({ at: 1000 + HISTORY_WINDOW_MS })).times).toEqual([1000 + HISTORY_WINDOW_MS]);
  });

  it("holds a clock that goes back, or gives no number, at the last time seen", () => {
    const history = createHistoryTracker();
    history.record("s", seen({ at: 5000 }));
    expect(history.record("s", seen({ at: 100 })).times).toEqual([5000, 5000]);
    expect(history.record("s", seen({ at: Number.NaN })).times).toEqual([5000, 5000, 5000]);
    expect(timingSignals(history.record("s", seen({ at: Number.POSITIVE_INFINITY })))).toEqual({ gaps: 3, medianGapMs: 0, regular: false });
  });

  it("keeps at most maxSources sources, forgets the least recently seen first, and keeps a long key by its hash", () => {
    const history = createHistoryTracker({ maxSources: 3, maxKeyLength: 8 });
    for (const s of ["a", "b", "c"]) history.record(s, seen({ at: 1 }));
    history.record("a", seen({ at: 2 }));
    history.record("d", seen({ at: 3 }));
    expect(history.size()).toBe(3);
    // b was the least recently seen, so it starts again; a was seen since, so it is remembered
    expect(history.record("a", seen({ at: 4 })).times).toEqual([1, 2, 4]);
    expect(history.record("b", seen({ at: 5 })).times).toEqual([5]);
    const flood = createHistoryTracker({ maxSources: 100 });
    for (let i = 0; i < 5000; i++) flood.record(`remote:${i}`, seen({ at: i }));
    expect(flood.size()).toBe(100);
    const long = "x".repeat(100_000);
    history.record(long, seen({ at: 6 }));
    expect(history.record(long, seen({ at: 7 })).times).toEqual([6, 7]);
  });

  it("drops the sources with no arrival inside the window, without a timer", () => {
    const history = createHistoryTracker();
    for (let i = 0; i < 50; i++) history.record(`remote:${i}`, seen({ at: 0 }));
    history.record("late", seen({ at: HISTORY_WINDOW_MS + 60_000 }));
    expect(history.size()).toBe(1);
  });

  it("does not throw on a history it did not make", () => {
    expect(timingSignals({ times: [Number.NaN, 5, 1, Number.POSITIVE_INFINITY] })).toMatchObject({ gaps: 3, regular: false });
    expect(timingSignals({} as never)).toEqual({ gaps: 0, regular: false });
    expect(timingSignals(undefined as never)).toEqual({ gaps: 0, regular: false });
    expect(navigationSignals(seen({ method: "POST" }), undefined as never).directWrite).toBe(true);
  });
});

describe("navigation", () => {
  const page = (at: number) => seen({ at, accept: "text/html,application/xhtml+xml", secFetch: { dest: "document", mode: "navigate", site: "none" } });

  it("a page load is a GET for a document, by sec-fetch-dest when sent and by Accept otherwise", () => {
    expect(isPageLoad(page(0))).toBe(true);
    expect(isPageLoad(seen({ accept: "text/html" }))).toBe(true);
    expect(isPageLoad(seen({ accept: "text/html", secFetch: { dest: "empty" } }))).toBe(false);
    expect(isPageLoad(seen({ accept: "application/json" }))).toBe(false);
    expect(isPageLoad(seen({ method: "POST", accept: "text/html" }))).toBe(false);
    expect(isPageLoad(seen())).toBe(false);
  });

  it("flags a write with no earlier page load from the source and no same-origin referer", () => {
    const history = createHistoryTracker();
    const post = (at: number, over: Partial<Observation> = {}) => seen({ at, method: "POST", ...over });
    const cold = post(0);
    expect(navigationSignals(cold, history.record("remote:bot", cold))).toEqual({ pageLoaded: false, referer: "absent", directWrite: true });
    for (const method of ["PUT", "PATCH", "DELETE"]) expect(navigationSignals(seen({ method }), { times: [0] }).directWrite, method).toBe(true);
    // a read is never a direct write
    expect(navigationSignals(seen(), { times: [0] }).directWrite).toBe(false);
    // a referer on the same origin: a form on a page the door did not see load
    expect(navigationSignals(post(1, { referer: "same-origin" }), { times: [1] })).toMatchObject({ referer: "same-origin", directWrite: false });
    expect(navigationSignals(post(1, { referer: "cross-origin" }), { times: [1] }).directWrite).toBe(true);
    // no referer (Referrer-Policy: no-referrer), and the browser says that the page of the same origin sent the write
    expect(navigationSignals(post(1, { secFetch: { site: "same-origin" } }), { times: [1] }).directWrite).toBe(false);
    expect(navigationSignals(post(1, { secFetch: { site: "Same-Origin" } }), { times: [1] }).directWrite).toBe(false);
    for (const site of ["same-site", "cross-site", "none"]) expect(navigationSignals(post(1, { secFetch: { site } }), { times: [1] }).directWrite, site).toBe(true);
    // a person: the page, then the form
    history.record("remote:person", page(1000));
    const filled = post(31_000);
    expect(navigationSignals(filled, history.record("remote:person", filled))).toMatchObject({ pageLoaded: true, directWrite: false });
    // the page load of one source says nothing for another
    const other = post(31_500);
    expect(navigationSignals(other, history.record("remote:other", other)).directWrite).toBe(true);
    // a page load is not its own earlier page load
    const first = page(0);
    expect(navigationSignals(first, createHistoryTracker().record("s", first)).pageLoaded).toBe(false);
  });

  it("forgets a page load older than the window", () => {
    const history = createHistoryTracker();
    history.record("s", page(0));
    const inside = seen({ at: HISTORY_WINDOW_MS - 1, method: "POST" });
    expect(navigationSignals(inside, history.record("s", inside)).pageLoaded).toBe(true);
    const late = seen({ at: HISTORY_WINDOW_MS + 5, method: "POST" });
    expect(navigationSignals(late, history.record("s", late))).toMatchObject({ pageLoaded: false, directWrite: true });
  });

  it("records sec-fetch-* as sent when each is a token, and as `other` when it is not", () => {
    expect(navigationSignals(seen({ secFetch: { site: "Same-Origin", mode: "cors", dest: "empty" } }), { times: [0] })).toMatchObject({ site: "same-origin", mode: "cors", dest: "empty" });
    expect(navigationSignals(seen({ secFetch: { site: "<script>", mode: "a".repeat(5000), dest: "" } }), { times: [0] })).toMatchObject({ site: "other", mode: "other", dest: "other" });
    expect(navigationSignals(seen({ secFetch: { site: 7 as unknown as string } }), { times: [0] })).not.toHaveProperty("site");
    expect(navigationSignals(seen({ referer: "javascript:" as never, secFetch: undefined as never }), { times: [0] }).referer).toBe("absent");
  });

  it("compares the referer's host with the host the request names", () => {
    expect(refererRelation("https://shop.example/contact?x=1", "shop.example")).toBe("same-origin");
    expect(refererRelation("https://SHOP.example/", "shop.EXAMPLE")).toBe("same-origin");
    expect(refererRelation("https://shop.example:8443/", "shop.example")).toBe("cross-origin");
    // a default port is the same authority with or without it, on each side
    expect(refererRelation("https://shop.example/x", "shop.example:443")).toBe("same-origin");
    expect(refererRelation("http://shop.example/x", "shop.example:80")).toBe("same-origin");
    expect(refererRelation("https://shop.example:443/x", "shop.example")).toBe("same-origin");
    expect(refererRelation("https://shop.example:8443/", "shop.example:8443")).toBe("same-origin");
    expect(refererRelation("https://shop.example:8443/", "shop.example:443")).toBe("cross-origin");
    expect(refererRelation("https://evil.example/shop.example", "shop.example")).toBe("cross-origin");
    expect(refererRelation("not a url", "shop.example")).toBe("cross-origin");
    expect(refererRelation("https://shop.example/", undefined)).toBe("cross-origin");
    expect(refererRelation(undefined, "shop.example")).toBe("absent");
    expect(refererRelation("", "shop.example")).toBe("absent");
  });
});

describe("the form report", () => {
  const report = (ms: number, k: number, p: number, paste = 0, trusted = 1) => `v=1;ms=${ms};k=${k};p=${p};paste=${paste};trusted=${trusted}`;

  it("is labelled a claim, and carries the counts the script sent", () => {
    expect(formSignals(seen({ form: report(41_250, 63, 4, 1, 1) }))).toEqual({ report: "claimed", fillMs: 41_250, keys: 63, pointers: 4, pasted: true, trusted: true, fast: false, noInput: false });
    expect(formSignals(seen({ form: report(900, 2, 1, 0, 0) }))).toMatchObject({ pasted: false, trusted: false });
    expect(formSignals(seen())).toBeUndefined();
  });

  it("flags more key presses than a person makes in the time, and a submit with no input", () => {
    const keys = 40;
    expect(formSignals(seen({ form: report(keys * FORM_FAST_MS_PER_KEY - 1, keys, 1) }))).toMatchObject({ fast: true, noInput: false });
    expect(formSignals(seen({ form: report(keys * FORM_FAST_MS_PER_KEY, keys, 1) }))!.fast).toBe(false);
    // a filled-in form sent with one click, or a few keys and Enter, is not fast
    expect(formSignals(seen({ form: report(0, 0, 1) }))).toMatchObject({ fast: false, noInput: false });
    expect(formSignals(seen({ form: report(5, FORM_FAST_MIN_KEYS - 1, 0) }))).toMatchObject({ fast: false, noInput: false });
    expect(formSignals(seen({ form: report(0, 0, 0) }))).toMatchObject({ fast: false, noInput: true });
  });

  it("accepts only the exact report, and a malformed one sets no flag", () => {
    expect(parseFormReport(report(MAX_FORM_FILL_MS, MAX_FORM_EVENTS, MAX_FORM_EVENTS))).toEqual({ fillMs: MAX_FORM_FILL_MS, keys: MAX_FORM_EVENTS, pointers: MAX_FORM_EVENTS, pasted: false, trusted: true });
    const bad = [
      "", "v=1", report(MAX_FORM_FILL_MS + 1, 1, 1), report(1, MAX_FORM_EVENTS + 1, 1), report(-1, 1, 1), report(1.5, 1, 1), report(1, 1, 1, 2), report(1, 1, 1).replace("v=1", "v=2"),
      ` ${report(1, 1, 1)}`, `${report(1, 1, 1)}\n`, `${report(1, 1, 1)};field=secret`, `${report(1, 1, 1)}, ${report(1, 1, 1)}`, report(1, 1, 1).replace("k=1", "k=0x1"), report(1, 1, 1).replace("ms=1", "ms=1e3"), "v=1;".repeat(100_000),
    ];
    for (const value of bad) {
      expect(parseFormReport(value), value.slice(0, 60)).toBeNull();
      expect(formSignals(seen({ form: value }))).toEqual({ report: "malformed", fast: false, noInput: false });
    }
    for (const notText of [null, undefined, 5, {}, [report(1, 1, 1)]]) expect(parseFormReport(notText)).toBeNull();
  });
});

describe("the observation of a request", () => {
  const request = (headers: Record<string, string | string[]>, extra: object = {}) => ({ headers, rawHeaders: Object.entries(headers).flatMap(([k, v]) => [k, String(v)]), ...extra });

  it("reads a TLS fingerprint header only when the operator named it and the door trusts its proxy", () => {
    const req = request({ host: "shop.example", "x-ja4": ja4("t13d1516h2") });
    expect(observationOf(req, 0, "GET", "/")).not.toHaveProperty("tls");
    expect(observationOf(req, 0, "GET", "/", { trustProxy: true })).not.toHaveProperty("tls");
    expect(observationOf(req, 0, "GET", "/", { tlsHeader: "x-ja4" })).not.toHaveProperty("tls");
    expect(observationOf(req, 0, "GET", "/", { trustProxy: true, tlsHeader: "X-JA4" }).tls).toEqual({ ja4: ja4("t13d1516h2") });
    // the host's own view of the connection is used when no header is named
    expect(observationOf({ ...req, transport: { tls: { negotiated: "TLSv1.3" } } }, 0, "GET", "/").tls).toEqual({ negotiated: "TLSv1.3" });
  });

  it("knows the client used https only from the host or from the trusted proxy", () => {
    const req = request({ host: "shop.example", "x-forwarded-proto": "http, https" });
    expect(observationOf(req, 0, "GET", "/")).not.toHaveProperty("secure");
    expect(observationOf(req, 0, "GET", "/", { trustProxy: true }).secure).toBe(true);
    expect(observationOf(request({ "x-forwarded-proto": "https, http" }), 0, "GET", "/", { trustProxy: true })).not.toHaveProperty("secure");
    expect(observationOf({ ...req, transport: { secure: false } }, 0, "GET", "/", { trustProxy: true }).secure).toBe(false);
  });

  it("lists the header names as received, without the door's own, and not at all when a proxy selected them", () => {
    const req = request({ Host: "shop.example", "User-Agent": "curl/8.7.1", "X-Agent-Custody-Grant": "g", [FORM_REPORT_HEADER]: "v=1", "X-Challenge": "t", "X-JA4": "j", Accept: "*/*" });
    expect(observationOf(req, 0, "GET", "/", { own: ["x-challenge"], tlsHeader: "x-ja4" }).headers).toEqual({ names: ["host", "user-agent", "accept"], ordered: true });
    expect(observationOf({ headers: { accept: "*/*", host: "shop.example", gone: undefined } }, 0, "GET", "/").headers).toEqual({ names: ["accept", "host"], ordered: false });
    expect(observationOf(req, 0, "GET", "/", { partialHeaders: true })).not.toHaveProperty("headers");
  });

  it("takes the referer's relation to the host the client named, which behind a trusted proxy is x-forwarded-host", () => {
    const req = request({ host: "127.0.0.1:8080", "x-forwarded-host": "shop.example", referer: "https://shop.example/contact" });
    expect(observationOf(req, 0, "POST", "/contact").referer).toBe("cross-origin");
    expect(observationOf(req, 0, "POST", "/contact", { trustProxy: true }).referer).toBe("same-origin");
    expect(observationOf(request({ host: "shop.example", referer: "https://shop.example/" }), 0, "post", "/contact")).toMatchObject({ method: "POST", referer: "same-origin" });
  });

  it("cuts every value it keeps, whatever arrives", () => {
    const huge = "a".repeat(1_000_000);
    const o = observationOf(request({ host: huge, "user-agent": huge, accept: huge, referer: `https://${huge}/`, "sec-fetch-site": huge, "sec-fetch-mode": huge, "sec-fetch-dest": huge, "x-ja4": huge, [FORM_REPORT_HEADER]: huge }), 0, huge, `/${huge}`, { trustProxy: true, tlsHeader: "x-ja4" });
    expect(JSON.stringify(o).length).toBeLessThan(8192);
    expect(() => signalsOf(o, createHistoryTracker().record(huge, o))).not.toThrow();
    // a repeated field arrives as a list in some hosts
    expect(observationOf({ headers: { "user-agent": ["curl/8", "x"], [FORM_REPORT_HEADER]: ["v=1", "v=1"] } }, 0, "GET", "/")).toMatchObject({ userAgent: "curl/8, x", form: "v=1, v=1" });
  });
});

describe("every signal of an arrival", () => {
  it("has each flag as a boolean at its path, or the whole group absent; and every number is an integer", () => {
    const history = createHistoryTracker();
    const full = browser({ at: 12.75, method: "POST", tls: { ja4: ja4("t13d1516h2"), helloLength: 508 }, form: "v=1;ms=5000;k=12;p=2;paste=0;trusted=1" });
    history.record("s", seen({ at: 1.5 }));
    const all = signalsOf(full, history.record("s", full));
    for (const name of FLAG_SIGNALS) expect(typeof flagOf(all, name), name).toBe("boolean");
    const numbers: number[] = [];
    JSON.stringify(all, (_, v: unknown) => { if (typeof v === "number") numbers.push(v); return v; });
    expect(numbers.length).toBeGreaterThan(5);
    expect(numbers.every(Number.isSafeInteger)).toBe(true);

    const bare = seen({ at: 20 });
    const least = signalsOf(bare, history.record("t", bare));
    expect(least).toEqual({
      fingerprint: { headers: { client: "unstated", family: "unstated", mismatch: false } },
      behaviour: { timing: { gaps: 0, regular: false }, navigation: { pageLoaded: false, referer: "absent", directWrite: false } },
    });
    expect(FLAG_SIGNALS.filter((name) => flagOf(least, name) === undefined)).toEqual(["fingerprint.tls.mismatch", "fingerprint.tls.knownTool", "behaviour.form.fast", "behaviour.form.noInput"]);
  });

  it("gives the same signals for the same observations, replayed", () => {
    const arrivals = [seen({ at: 0, accept: "text/html" }), browser({ at: 800 }), browser({ at: 30_000, method: "POST", referer: "same-origin", form: "v=1;ms=20000;k=30;p=3;paste=0;trusted=1" })];
    const run = () => {
      const history = createHistoryTracker();
      return arrivals.map((o) => signalsOf(o, history.record("remote:203.0.113.9", o)));
    };
    expect(run()).toEqual(run());
  });
});
