// Enterprise sign-in for the portal: OIDC (code + PKCE) and SAML 2.0. The caller checks the email domain.
import { createHash, createPublicKey, randomBytes, verify as cryptoVerify, type JsonWebKeyInput } from "node:crypto";
import { createRequire } from "node:module";

export interface OidcConfig { issuer: string; clientId: string; clientSecret: string }
export interface SamlConfig { entryPoint: string; idpCert: string; idpIssuer?: string }
export interface SsoIdentity { subject: string; email: string }

const SKEW_SECONDS = 60;
const CACHE_MS = 3_600_000;
const b64url = (b: Buffer) => b.toString("base64url");

export function pkce(): { verifier: string; challenge: string } {
  const verifier = b64url(randomBytes(32));
  return { verifier, challenge: b64url(createHash("sha256").update(verifier).digest()) };
}

interface Discovery { issuer: string; authorization_endpoint: string; token_endpoint: string; jwks_uri: string }
type Jwk = JsonWebKeyInput["key"] & { kid?: string; use?: string };
const discoveries = new Map<string, { at: number; doc: Discovery }>();
const keySets = new Map<string, { at: number; keys: Jwk[] }>();

const getJson = async (f: typeof fetch, url: string, what: string): Promise<unknown> => {
  const r = await f(url, { headers: { accept: "application/json" }, redirect: "error", signal: AbortSignal.timeout(10_000) });
  if (!r.ok) throw new Error(`${what} answered HTTP ${r.status}`);
  return r.json();
};
const httpsUrl = (u: unknown, what: string): string => {
  if (typeof u !== "string" || !URL.canParse(u) || new URL(u).protocol !== "https:") throw new Error(`${what} must be an https URL`);
  return u;
};

async function discover(c: OidcConfig, f: typeof fetch): Promise<Discovery> {
  httpsUrl(c.issuer, "the OIDC issuer");
  const hit = discoveries.get(c.issuer);
  if (hit && Date.now() - hit.at < CACHE_MS) return hit.doc;
  const doc = (await getJson(f, `${c.issuer.replace(/\/$/, "")}/.well-known/openid-configuration`, "OIDC discovery")) as Discovery;
  if (doc.issuer !== c.issuer) throw new Error("the OIDC discovery document names a different issuer");
  for (const k of ["authorization_endpoint", "token_endpoint", "jwks_uri"] as const) httpsUrl(doc[k], `the OIDC ${k}`);
  discoveries.set(c.issuer, { at: Date.now(), doc });
  return doc;
}

async function jwks(c: OidcConfig, d: Discovery, f: typeof fetch, fresh: boolean): Promise<Jwk[]> {
  const hit = keySets.get(c.issuer);
  if (hit && !fresh && Date.now() - hit.at < CACHE_MS) return hit.keys;
  const keys = ((await getJson(f, d.jwks_uri, "OIDC key set")) as { keys?: Jwk[] }).keys;
  if (!Array.isArray(keys)) throw new Error("the OIDC key set has no keys");
  keySets.set(c.issuer, { at: Date.now(), keys });
  return keys;
}

export async function oidcAuthorizeUrl(c: OidcConfig, o: { redirectUri: string; state: string; nonce: string; codeChallenge: string; fetch?: typeof fetch }): Promise<string> {
  const d = await discover(c, o.fetch ?? fetch);
  const u = new URL(d.authorization_endpoint);
  const q = { response_type: "code", client_id: c.clientId, redirect_uri: o.redirectUri, scope: "openid email profile", state: o.state, nonce: o.nonce, code_challenge: o.codeChallenge, code_challenge_method: "S256" };
  for (const [k, v] of Object.entries(q)) u.searchParams.set(k, v);
  return u.toString();
}

async function verifySignature(c: OidcConfig, d: Discovery, f: typeof fetch, token: string): Promise<Record<string, unknown>> {
  const parts = token.split(".");
  const [h, p, s] = parts;
  if (parts.length !== 3 || !h || !p || !s) throw new Error("the id_token is not a JWS");
  const header = JSON.parse(Buffer.from(h, "base64url").toString()) as { alg?: string; kid?: string };
  const kty = { RS256: "RSA", ES256: "EC" }[header.alg as string];
  if (!kty) throw new Error(`the id_token algorithm ${String(header.alg)} is not accepted; use RS256 or ES256`);
  const candidates = (keys: Jwk[]) => keys.filter((k) => k.kty === kty && (!k.use || k.use === "sig") && (!header.kid || k.kid === header.kid));
  let found = candidates(await jwks(c, d, f, false));
  if (!found.length) found = candidates(await jwks(c, d, f, true)); // rotated keys
  if (!found.length) throw new Error("no key in the OIDC key set matches the id_token");
  const ok = found.some((k) => {
    if (header.alg === "ES256" && k.crv !== "P-256") return false;
    const key = createPublicKey({ key: k, format: "jwk" });
    return cryptoVerify("sha256", Buffer.from(`${h}.${p}`), header.alg === "ES256" ? { key, dsaEncoding: "ieee-p1363" } : key, Buffer.from(s, "base64url"));
  });
  if (!ok) throw new Error("the id_token signature is not valid");
  return JSON.parse(Buffer.from(p, "base64url").toString()) as Record<string, unknown>;
}

export async function oidcExchange(c: OidcConfig, o: { code: string; redirectUri: string; codeVerifier: string; nonce: string; fetch?: typeof fetch; now?: number }): Promise<SsoIdentity> {
  const f = o.fetch ?? fetch;
  const d = await discover(c, f);
  const r = await f(d.token_endpoint, {
    method: "POST",
    headers: { accept: "application/json", "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({ grant_type: "authorization_code", code: o.code, redirect_uri: o.redirectUri, client_id: c.clientId, client_secret: c.clientSecret, code_verifier: o.codeVerifier }),
    redirect: "error",
    signal: AbortSignal.timeout(10_000),
  });
  const tok = (await r.json().catch(() => ({}))) as { id_token?: string; error?: string };
  if (!r.ok || !tok.id_token) throw new Error(`the OIDC token endpoint refused the code (HTTP ${r.status}${tok.error ? `, ${tok.error}` : ""})`);

  const claims = await verifySignature(c, d, f, tok.id_token);
  const now = (o.now ?? Date.now()) / 1000;
  const aud = [claims.aud].flat();
  if (claims.iss !== c.issuer) throw new Error("the id_token issuer is not the configured issuer");
  if (!aud.includes(c.clientId)) throw new Error("the id_token audience does not include this client");
  if (aud.length > 1 && claims.azp !== c.clientId) throw new Error("the id_token has several audiences and its azp is not this client");
  if (typeof claims.exp !== "number" || claims.exp + SKEW_SECONDS <= now) throw new Error("the id_token has expired");
  if (typeof claims.iat === "number" && claims.iat - SKEW_SECONDS > now) throw new Error("the id_token is issued in the future");
  if (claims.nonce !== o.nonce) throw new Error("the id_token nonce does not match this sign-in");
  if (typeof claims.sub !== "string" || !claims.sub) throw new Error("the id_token has no sub claim");
  if (typeof claims.email !== "string" || !claims.email.includes("@")) throw new Error("the id_token has no email claim");
  // Many enterprise IdPs omit email_verified.
  if (claims.email_verified === false) throw new Error("the provider says the email address is not verified");
  return { subject: claims.sub, email: claims.email.toLowerCase() };
}

// Never verify XML signatures by hand: node-saml does it.
const EMAIL_CLAIM = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress";
const EMAIL_FORMAT = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress";

function samlClient(c: SamlConfig, sp: { spEntityId: string; acsUrl: string }, requestId: string) {
  let lib: { SAML: new (o: Record<string, unknown>) => any };
  try {
    lib = createRequire(import.meta.url)("@node-saml/node-saml");
  } catch (cause) {
    if ((cause as { code?: string }).code !== "MODULE_NOT_FOUND") throw cause;
    throw new Error("SAML sign-in needs the optional package @node-saml/node-saml; install it beside @agent-custody/receipts", { cause });
  }
  return new lib.SAML({
    entryPoint: c.entryPoint, idpCert: c.idpCert, issuer: sp.spEntityId, callbackUrl: sp.acsUrl, audience: sp.spEntityId,
    wantAssertionsSigned: true, wantAuthnResponseSigned: false,
    acceptedClockSkewMs: SKEW_SECONDS * 1000, signatureAlgorithm: "sha256", generateUniqueId: () => requestId,
  });
}

export async function samlAuthorizeUrl(c: SamlConfig, o: { spEntityId: string; acsUrl: string; relayState?: string }): Promise<{ url: string; requestId: string }> {
  const requestId = `_${randomBytes(20).toString("hex")}`;
  return { url: await samlClient(c, o, requestId).getAuthorizeUrlAsync(o.relayState ?? "", undefined, {}), requestId };
}

type Xml = any;

export async function samlValidate(c: SamlConfig, o: { spEntityId: string; acsUrl: string; samlResponse: string; requestId: string }): Promise<SsoIdentity> {
  const { profile } = await samlClient(c, o, o.requestId).validatePostResponseAsync({ SAMLResponse: o.samlResponse });
  if (!profile?.nameID) throw new Error("the SAML response has no NameID");
  // Only the assertion is signed: the Response's InResponseTo proves nothing.
  const assertion: Xml = profile.getAssertion().Assertion;
  if (c.idpIssuer && profile.issuer !== c.idpIssuer) throw new Error("the SAML assertion issuer is not the configured IdP");
  const bearer = (assertion.Subject?.[0]?.SubjectConfirmation ?? [])
    .filter((s: Xml) => s.$?.Method === "urn:oasis:names:tc:SAML:2.0:cm:bearer")
    .flatMap((s: Xml) => s.SubjectConfirmationData ?? []);
  const bound = bearer.some((d: Xml) => d.$?.InResponseTo === o.requestId && d.$?.Recipient === o.acsUrl && Date.parse(d.$?.NotOnOrAfter) + SKEW_SECONDS * 1000 > Date.now());
  if (!bound) throw new Error("the SAML assertion is not an answer to this sign-in request");
  if (!assertion.Conditions?.[0]?.$?.NotOnOrAfter) throw new Error("the SAML assertion has no validity period");

  const attr = (name: string): string | undefined => [profile.attributes?.[name]].flat()[0] as string | undefined;
  const email = [attr("email"), attr(EMAIL_CLAIM), profile.nameIDFormat === EMAIL_FORMAT ? profile.nameID : undefined].find((e) => typeof e === "string" && e.includes("@"));
  if (!email) throw new Error("the SAML assertion has no email address");
  return { subject: profile.nameID, email: email.toLowerCase() };
}
