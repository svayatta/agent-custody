// How an agent presents a grant over HTTP, shared by the HTTP gateway and the door. Kept apart from both so that a door
// running outside Node (a Worker) can read a grant without loading the gateway.
import type { IncomingHttpHeaders } from "node:http";
import type { Envelope } from "./crypto.ts";

export const GRANT_HEADER = "x-agent-custody-grant";

/** The header value that presents a grant: the DSSE envelope as base64url JSON. Send it as `Authorization: Bearer <value>` or as `X-Agent-Custody-Grant`. */
export function grantHeader(envelope: Envelope): string {
  return Buffer.from(JSON.stringify(envelope)).toString("base64url");
}

export function parseGrantHeader(req: { headers: IncomingHttpHeaders }): Envelope | null {
  const explicit = req.headers[GRANT_HEADER];
  const auth = req.headers.authorization ?? "";
  const raw = typeof explicit === "string" && explicit ? explicit : auth.startsWith("Bearer ") ? auth.slice(7) : "";
  if (!raw) return null;
  try {
    const parsed = JSON.parse(Buffer.from(raw, "base64url").toString("utf8")) as Envelope;
    return parsed && typeof parsed === "object" && typeof parsed.payload === "string" && Array.isArray(parsed.signatures) ? parsed : null;
  } catch {
    return null;
  }
}
