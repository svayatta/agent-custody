// An OIDC identity provider in memory, behind a fetch: discovery, keys, and a token endpoint that checks the PKCE
// verifier. For the tests and the examples; nothing here touches the network.
import { createHash, generateKeyPairSync, sign } from "node:crypto";

const b64 = (v: unknown) => Buffer.from(JSON.stringify(v)).toString("base64url");

export function standInIdp(issuer: string, clientId: string, clientSecret: string) {
  const { publicKey, privateKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
  const codes = new Map<string, { challenge: string; nonce: string; sub: string; email: string }>();
  const json = (v: unknown, status = 200) => new Response(JSON.stringify(v), { status, headers: { "content-type": "application/json" } });
  const idp = {
    tokenCalls: 0,
    fetch: (async (url: string, init?: RequestInit) => {
      if (!(init?.signal instanceof AbortSignal)) throw new Error("an outbound fetch needs a timeout");
      if (url === `${issuer}/.well-known/openid-configuration`) return json({ issuer, authorization_endpoint: `${issuer}/authorize`, token_endpoint: `${issuer}/token`, jwks_uri: `${issuer}/jwks` });
      if (url === `${issuer}/jwks`) return json({ keys: [{ ...publicKey.export({ format: "jwk" }), kid: "k1", use: "sig" }] });
      if (url === `${issuer}/token`) {
        idp.tokenCalls++;
        const form = new URLSearchParams(String(init?.body));
        const grant = codes.get(form.get("code") ?? "");
        const pkceOk = grant && createHash("sha256").update(form.get("code_verifier") ?? "").digest("base64url") === grant.challenge;
        if (!grant || !pkceOk || form.get("client_id") !== clientId || form.get("client_secret") !== clientSecret) return json({ error: "invalid_grant" }, 400);
        codes.delete(form.get("code")!);
        const now = Math.floor(Date.now() / 1000);
        const input = `${b64({ alg: "RS256", kid: "k1" })}.${b64({ iss: issuer, aud: clientId, sub: grant.sub, email: grant.email, nonce: grant.nonce, iat: now, exp: now + 300 })}`;
        return json({ id_token: `${input}.${sign("sha256", Buffer.from(input), privateKey).toString("base64url")}` });
      }
      return new Response("not stood in: " + url, { status: 404 });
    }) as typeof fetch,
    /** The person signs in at the provider: the address that the provider sends the browser back to. */
    signIn(authorizeUrl: string, who: { sub: string; email: string }): string {
      const q = new URL(authorizeUrl).searchParams;
      const code = `code-${codes.size}-${Math.random().toString(36).slice(2)}`;
      codes.set(code, { challenge: q.get("code_challenge")!, nonce: q.get("nonce")!, ...who });
      return `${q.get("redirect_uri")}?${new URLSearchParams({ code, state: q.get("state")! })}`;
    },
  };
  return idp;
}
