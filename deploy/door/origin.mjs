// A stand-in site: answers every request with what reached it, including the receipt id and class the proxy added.
import { createServer } from "node:http";

createServer((req, res) => {
  let bytes = 0;
  req.on("data", (c) => { bytes += c.length; });
  req.on("end", () => {
    console.log(`${req.method} ${req.url} receipt=${req.headers["x-agent-custody-receipt"] ?? "-"}`);
    res.writeHead(200, { "content-type": "application/json" });
    res.end(JSON.stringify({ origin: "reached", method: req.method, path: req.url, bodyBytes: bytes, receipt: req.headers["x-agent-custody-receipt"] ?? null, class: req.headers["x-agent-custody-class"] ?? null, grantHeader: req.headers["x-agent-custody-grant"] ?? null }) + "\n");
  });
}).listen(8081, "0.0.0.0");
