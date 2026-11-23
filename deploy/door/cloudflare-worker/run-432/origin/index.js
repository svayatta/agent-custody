// The test origin. It writes one log line and one R2 object for each request, then answers with a small JSON body.
// GET /__hits?run=<id> lists the requests of one run. The door relays no request to that path.
export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (url.pathname === "/__hits") {
      const listed = await env.HITS.list({ prefix: `hits/${url.searchParams.get("run") ?? ""}/` });
      return Response.json({ truncated: listed.truncated, hits: listed.objects.map((o) => o.key) });
    }
    const hit = {
      time: new Date().toISOString(),
      method: request.method,
      path: url.pathname,
      run: (request.headers.get("x-run") ?? "none").replace(/[^A-Za-z0-9_-]/g, ""),
      forwardedFor: request.headers.get("x-forwarded-for"),
    };
    console.log(JSON.stringify({ origin: "hit", ...hit }));
    await env.HITS.put(`hits/${hit.run}/${hit.time} ${hit.method} ${hit.path}`, JSON.stringify(hit));
    return Response.json({ ok: true, origin: "door-origin-test", method: hit.method, path: hit.path });
  },
};
