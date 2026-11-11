// The tenant portal: where a team registers, gets its tenant on the hosted log and its first API key, watches its
// usage against its plan, mints and revokes keys, and pays. One process beside the log, on the same Postgres, with
// its own tables under `portal_`. Everything a tenant can do here they could also do by asking the operator; the
// portal removes the asking. It holds no receipts and never sees a receipt: the numbers it shows are the log's
// counts, the hashes it lists are the same hashes the export carries.
//
// Sessions are a signed cookie, passwords are scrypt, the page is one inline file with no framework and a strict
// content-security policy, and every API write requires a JSON body, which with a SameSite=Strict cookie is what
// keeps a cross-site page from acting as the user. Billing is Stripe Checkout for the team plan; the webhook moves
// the tenant's plan, and nothing about a card ever passes through here.
import { createHash, createHmac, randomBytes, randomUUID, scryptSync, timingSafeEqual } from "node:crypto";
import { createServer, type IncomingMessage, type Server as HttpServer, type ServerResponse } from "node:http";
import type { AddressInfo } from "node:net";
import { postgresCheckpoints, type CheckpointStore } from "./checkpoints.ts";
import { DESIGN_CSS } from "./design.ts";
import { welcomeSheet } from "./log-admin.ts";
import { clientAddress } from "./log-sink.ts";
import { SITE_NAV, siteUrl } from "./site-links.ts";
import { PLAN_QUOTAS, RateLimiter, type Plan, type PostgresLike, type PostgresTenancy } from "./log-store.ts";
import { oidcAuthorizeUrl, oidcExchange, pkce, samlAuthorizeUrl, samlValidate, type OidcConfig, type SamlConfig, type SsoIdentity } from "./sso.ts";

export interface StripeOptions {
  secretKey: string;
  webhookSecret: string;
  /** the Stripe price id of the team plan's monthly subscription */
  priceTeam: string;
  fetch?: typeof fetch;
}

/** Outbound mail over an HTTP API in Resend's shape (`POST /emails` with a bearer key). One message at registration; never a secret. */
export interface MailOptions {
  apiKey: string;
  /** the sender, an address on a domain the provider has verified */
  from: string;
  /** an operator address that gets a note per registration, with the contact details */
  notify?: string;
  /** the endpoint; Resend's by default */
  url?: string;
  fetch?: typeof fetch;
}

/** Sign in through GitHub or Google: the OAuth web flow over fetch, no library. The callback is `<portalUrl>auth/<provider>/callback`. */
export interface OAuthOptions {
  github?: { clientId: string; clientSecret: string };
  google?: { clientId: string; clientSecret: string };
  fetch?: typeof fetch;
}

export interface PortalOptions {
  tenancy: PostgresTenancy;
  /** the Postgres client the tenancy uses; the portal's own tables live beside the log's */
  client: PostgresLike;
  /** signs session cookies; rotate to sign everyone out */
  secret: string;
  /** the log's public base URL, for the welcome sheet and the export command */
  publicUrl: string;
  checkpointsUrl?: string;
  /** the log's current signing keyid, for the sheet */
  keyid?: string;
  /** the portal's own public URL, for Stripe's return addresses */
  portalUrl?: string;
  stripe?: StripeOptions;
  mail?: MailOptions;
  oauth?: OAuthOptions;
  /** the fetch for OIDC discovery, keys, and tokens; the global one by default */
  ssoFetch?: typeof fetch;
  /** key throttles by X-Forwarded-For; only behind a proxy you run. Also marks cookies Secure. */
  trustProxy?: boolean;
  /** table prefix; default portal_ */
  prefix?: string;
  log?: (message: string) => void;
}

export interface PortalUser {
  id: string;
  email: string;
  createdAt: string;
  /** when the address was confirmed: by a verification link, a password reset, or a provider that vouched for it; null until then */
  emailVerifiedAt?: string | null;
  /** a session or an MFA cookie signed before this time (ms) is not valid: set by a password reset or change */
  sessionsAfter?: number;
}

/** A provider sign-in whose verified email belongs to a password account that never verified its address: refused, never linked (issue #103). */
export class UnverifiedAccountError extends Error {
  email: string;
  constructor(email: string) {
    super(`an account with the address ${email} exists but has not verified it; sign in with its password, then link the provider from the account page`);
    this.email = email;
  }
}

/** A single sign-on identity that the tenant's rules refuse: another domain, or an account in another tenant. */
export class SsoRefusedError extends Error {}

/** A request the client got wrong: answered with its status and message. Any other error is answered with a plain 500. */
class ClientError extends Error {
  status: number;
  constructor(status: number, message: string) {
    super(message);
    this.status = status;
  }
}

/** One tenant's enterprise identity provider. Set by the operator only, because an IdP is trusted for the domains that the operator checked. */
export interface SsoSetting {
  tenant: string;
  protocol: "oidc" | "saml";
  config: OidcConfig | SamlConfig;
  domains: string[];
  defaultRole: Role;
  enforced: boolean;
}

const ident = (s: string) => {
  if (!/^[a-z_][a-z0-9_]*$/.test(s)) throw new Error(`prefix must be a plain identifier; got "${s}"`);
  return s;
};

/** Users, memberships, and billing records, beside the log's tables. */
/** What a registration says about the person and the organisation; every field optional in the store, the route decides what it requires. */
export interface Profile { name?: string | null; company?: string | null; role?: string | null; phone?: string | null; telegram?: string | null }
const PROFILE_COLUMNS = ["name", "company", "role", "phone", "telegram"] as const;

/** Lowest first. */
export const ROLES = ["readonly", "reviewer", "admin", "owner"] as const;
export type Role = (typeof ROLES)[number];

// ---- TOTP (RFC 6238) ----
const B32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
export const base32 = (b: Buffer): string => {
  const bits = [...b].map((x) => x.toString(2).padStart(8, "0")).join("");
  return (bits.match(/.{1,5}/g) ?? []).map((c) => B32[parseInt(c.padEnd(5, "0"), 2)]).join("");
};
export function totp(key: Buffer, step: number): string {
  const counter = Buffer.alloc(8);
  counter.writeBigUInt64BE(BigInt(step));
  const mac = createHmac("sha1", key).update(counter).digest();
  const at = mac[19]! & 15;
  return String((mac.readUInt32BE(at) & 0x7fffffff) % 1_000_000).padStart(6, "0");
}
/** The time step the code matches, one step either side of now allowed; null when none. */
export function totpStep(key: Buffer, code: string, now = Date.now()): number | null {
  const here = Math.floor(now / 30_000);
  for (const step of [here - 1, here, here + 1]) {
    const want = Buffer.from(totp(key, step));
    const got = Buffer.from(code);
    if (got.length === want.length && timingSafeEqual(got, want)) return step;
  }
  return null;
}

// ---- QR code (ISO/IEC 18004): byte mode, error correction level M, versions 1 to 40; for the two-step setup ----
// Level M per version: error correction codewords per block, and the number of blocks.
const QR_ECC = [0, 10, 16, 26, 18, 24, 16, 18, 22, 22, 26, 30, 22, 22, 24, 24, 28, 28, 26, 26, 26, 26, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28];
const QR_BLOCKS = [0, 1, 1, 1, 2, 2, 4, 4, 4, 5, 5, 5, 8, 9, 9, 10, 10, 11, 13, 14, 16, 17, 17, 18, 20, 21, 23, 25, 26, 28, 29, 31, 33, 35, 37, 38, 40, 43, 45, 47, 49];
const gfMul = (x: number, y: number) => {
  let z = 0;
  for (let i = 7; i >= 0; i--) z = ((z << 1) ^ ((z >>> 7) * 0x11d)) ^ (((y >>> i) & 1) * x);
  return z;
};
const qrRawModules = (v: number) => {
  let n = (16 * v + 128) * v + 64;
  if (v >= 2) {
    const a = Math.floor(v / 7) + 2;
    n -= (25 * a - 10) * a - 55;
    if (v >= 7) n -= 36;
  }
  return n;
};
/** The modules of the QR code for `text`, true for dark, without the quiet zone. */
export function qrMatrix(text: string): boolean[][] {
  const data = [...Buffer.from(text, "utf8")];
  let v = 1;
  const capacity = (v: number) => (Math.floor(qrRawModules(v) / 8) - QR_ECC[v]! * QR_BLOCKS[v]!) * 8;
  while (4 + (v < 10 ? 8 : 16) + data.length * 8 > capacity(v)) if (++v > 40) throw new Error("too long for a QR code");
  const bits: number[] = [];
  const put = (val: number, len: number) => { for (let i = len - 1; i >= 0; i--) bits.push((val >>> i) & 1); };
  put(4, 4);
  put(data.length, v < 10 ? 8 : 16);
  for (const b of data) put(b, 8);
  const cap = capacity(v);
  put(0, Math.min(4, cap - bits.length));
  put(0, (8 - (bits.length % 8)) % 8);
  for (let pad = 0xec; bits.length < cap; pad ^= 0xec ^ 0x11) put(pad, 8);
  const words = Array.from({ length: bits.length / 8 }, (_, i) => parseInt(bits.slice(i * 8, i * 8 + 8).join(""), 2));
  // Reed-Solomon over GF(256), and the blocks interleaved
  const eccLen = QR_ECC[v]!;
  const nBlocks = QR_BLOCKS[v]!;
  const div = new Array<number>(eccLen).fill(0);
  div[eccLen - 1] = 1;
  for (let i = 0, root = 1; i < eccLen; i++, root = gfMul(root, 2)) for (let j = 0; j < eccLen; j++) div[j] = gfMul(div[j]!, root) ^ (div[j + 1] ?? 0);
  const raw = Math.floor(qrRawModules(v) / 8);
  const nShort = nBlocks - (raw % nBlocks);
  const shortLen = Math.floor(raw / nBlocks);
  const blocks: number[][] = [];
  for (let i = 0, k = 0; i < nBlocks; i++) {
    const dat = words.slice(k, k + shortLen - eccLen + (i < nShort ? 0 : 1));
    k += dat.length;
    const rem = new Array<number>(eccLen).fill(0);
    for (const b of dat) {
      const f = b ^ rem.shift()!;
      rem.push(0);
      div.forEach((c, j) => { rem[j]! ^= gfMul(c, f); });
    }
    if (i < nShort) dat.push(0);
    blocks.push([...dat, ...rem]);
  }
  const all: number[] = [];
  for (let i = 0; i < blocks[0]!.length; i++) blocks.forEach((b, j) => { if (i !== shortLen - eccLen || j >= nShort) all.push(b[i]!); });
  // function patterns
  const size = v * 4 + 17;
  const m = Array.from({ length: size }, () => new Array<boolean>(size).fill(false));
  const fixed = Array.from({ length: size }, () => new Array<boolean>(size).fill(false));
  const set = (x: number, y: number, dark: boolean) => { m[y]![x] = dark; fixed[y]![x] = true; };
  for (let i = 0; i < size; i++) { set(6, i, i % 2 === 0); set(i, 6, i % 2 === 0); }
  for (const [cx, cy] of [[3, 3], [size - 4, 3], [3, size - 4]] as const) {
    for (let dy = -4; dy <= 4; dy++) for (let dx = -4; dx <= 4; dx++) {
      const d = Math.max(Math.abs(dx), Math.abs(dy));
      if (cx + dx >= 0 && cx + dx < size && cy + dy >= 0 && cy + dy < size) set(cx + dx, cy + dy, d !== 2 && d !== 4);
    }
  }
  const align: number[] = [];
  if (v > 1) {
    const n = Math.floor(v / 7) + 2;
    const step = Math.floor((v * 8 + n * 3 + 5) / (n * 4 - 4)) * 2;
    align.push(6);
    for (let pos = size - 7; align.length < n; pos -= step) align.splice(1, 0, pos);
  }
  for (const [i, ax] of align.entries()) for (const [j, ay] of align.entries()) {
    if ((i === 0 && j === 0) || (i === 0 && j === align.length - 1) || (i === align.length - 1 && j === 0)) continue;
    for (let dy = -2; dy <= 2; dy++) for (let dx = -2; dx <= 2; dx++) set(ax + dx, ay + dy, Math.max(Math.abs(dx), Math.abs(dy)) !== 1);
  }
  const format = (mask: number) => {
    const d = mask; // level M is 00
    let r = d;
    for (let i = 0; i < 10; i++) r = (r << 1) ^ ((r >>> 9) * 0x537);
    const f = ((d << 10) | r) ^ 0x5412;
    const bit = (i: number) => ((f >>> i) & 1) === 1;
    for (let i = 0; i <= 5; i++) set(8, i, bit(i));
    set(8, 7, bit(6)); set(8, 8, bit(7)); set(7, 8, bit(8));
    for (let i = 9; i < 15; i++) set(14 - i, 8, bit(i));
    for (let i = 0; i < 8; i++) set(size - 1 - i, 8, bit(i));
    for (let i = 8; i < 15; i++) set(8, size - 15 + i, bit(i));
    set(8, size - 8, true);
  };
  format(0);
  if (v >= 7) {
    let r = v;
    for (let i = 0; i < 12; i++) r = (r << 1) ^ ((r >>> 11) * 0x1f25);
    const f = (v << 12) | r;
    for (let i = 0; i < 18; i++) {
      const a = size - 11 + (i % 3), b = Math.floor(i / 3), dark = ((f >>> i) & 1) === 1;
      set(a, b, dark); set(b, a, dark);
    }
  }
  // the codewords, in the zigzag from the bottom right
  let i = 0;
  for (let right = size - 1; right >= 1; right -= 2) {
    if (right === 6) right = 5;
    for (let vert = 0; vert < size; vert++) for (let j = 0; j < 2; j++) {
      const x = right - j;
      const y = ((right + 1) & 2) === 0 ? size - 1 - vert : vert;
      if (!fixed[y]![x] && i < all.length * 8) { m[y]![x] = ((all[i >>> 3]! >>> (7 - (i & 7))) & 1) === 1; i++; }
    }
  }
  // the mask with the lowest penalty
  const MASKS = [(x: number, y: number) => (x + y) % 2 === 0, (_x: number, y: number) => y % 2 === 0, (x: number) => x % 3 === 0, (x: number, y: number) => (x + y) % 3 === 0, (x: number, y: number) => (Math.floor(x / 3) + Math.floor(y / 2)) % 2 === 0, (x: number, y: number) => ((x * y) % 2) + ((x * y) % 3) === 0, (x: number, y: number) => (((x * y) % 2) + ((x * y) % 3)) % 2 === 0, (x: number, y: number) => (((x + y) % 2) + ((x * y) % 3)) % 2 === 0];
  const apply = (k: number) => { for (let y = 0; y < size; y++) for (let x = 0; x < size; x++) if (!fixed[y]![x] && MASKS[k]!(x, y)) m[y]![x] = !m[y]![x]; };
  const penalty = () => {
    let p = 0, dark = 0;
    const lines = [...m.map((r) => r.map(Number).join("")), ...m.map((_, x) => m.map((r) => Number(r[x])).join(""))];
    for (const l of lines) {
      for (const run of l.match(/0{5,}|1{5,}/g) ?? []) p += run.length - 2;
      p += 40 * ((l.match(/(?=10111010000|00001011101)/g) ?? []).length);
    }
    for (let y = 0; y < size; y++) for (let x = 0; x < size; x++) {
      if (m[y]![x]) dark++;
      if (x < size - 1 && y < size - 1 && m[y]![x] === m[y]![x + 1] && m[y]![x] === m[y + 1]![x] && m[y]![x] === m[y + 1]![x + 1]) p += 3;
    }
    return p + 10 * (Math.ceil(Math.abs(dark * 20 - size * size * 10) / (size * size)) - 1);
  };
  let best = 0, least = Infinity;
  for (let k = 0; k < 8; k++) {
    apply(k); format(k);
    const p = penalty();
    if (p < least) { least = p; best = k; }
    apply(k);
  }
  apply(best); format(best);
  return m;
}
/** The QR code as an SVG, dark on white with a four-module quiet zone, whatever the page's theme. */
export function qrSvg(text: string): string {
  const m = qrMatrix(text);
  const n = m.length + 8;
  let d = "";
  m.forEach((row, y) => row.forEach((dark, x) => { if (dark) d += `M${x + 4} ${y + 4}h1v1h-1z`; }));
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${n} ${n}" shape-rendering="crispEdges" role="img" aria-label="QR code"><rect width="${n}" height="${n}" fill="#fff"/><path d="${d}" fill="#000"/></svg>`;
}

const sha256 = (s: string) => createHash("sha256").update(s).digest("hex");
const recoveryHash = (code: string) => sha256(code.toLowerCase().replace(/[^a-z0-9]/g, ""));

export class PortalStore {
  private readonly client: PostgresLike;
  private readonly p: string;
  private ready: Promise<void> | null = null;
  // no parameter properties: the CLI runs on plain Node type stripping
  constructor(client: PostgresLike, prefix = "portal_") {
    this.client = client;
    this.p = ident(prefix);
  }
  private init(): Promise<void> {
    if (!this.ready) {
      const p = this.p;
      this.ready = (async () => {
        await this.client.query(`CREATE TABLE IF NOT EXISTS ${p}users (id TEXT PRIMARY KEY, email TEXT NOT NULL UNIQUE, password_hash TEXT NOT NULL, created_at TIMESTAMPTZ NOT NULL DEFAULT now())`);
        await this.client.query(`CREATE TABLE IF NOT EXISTS ${p}members (user_id TEXT NOT NULL REFERENCES ${p}users(id), tenant_id TEXT NOT NULL, role TEXT NOT NULL DEFAULT 'owner', created_at TIMESTAMPTZ NOT NULL DEFAULT now(), PRIMARY KEY (user_id, tenant_id))`);
        await this.client.query(`CREATE TABLE IF NOT EXISTS ${p}billing (tenant_id TEXT PRIMARY KEY, customer_id TEXT, subscription_id TEXT, status TEXT NOT NULL, updated_at TIMESTAMPTZ NOT NULL DEFAULT now())`);
        // the Stripe `created` time (unix seconds) of the event that set the billing state; an older event does not move it back
        await this.client.query(`ALTER TABLE ${p}billing ADD COLUMN IF NOT EXISTS event_created BIGINT`);
        // the Stripe event ids already applied; a redelivery of one is ignored
        await this.client.query(`CREATE TABLE IF NOT EXISTS ${p}stripe_events (id TEXT PRIMARY KEY, received_at TIMESTAMPTZ NOT NULL DEFAULT now())`);
        // who the account belongs to: added after the first tenants registered, so the columns are optional
        for (const c of PROFILE_COLUMNS) await this.client.query(`ALTER TABLE ${p}users ADD COLUMN IF NOT EXISTS ${c} TEXT`);
        // when the founder's note went out, so it goes once
        await this.client.query(`ALTER TABLE ${p}users ADD COLUMN IF NOT EXISTS followed_up_at TIMESTAMPTZ`);
        // when the address was confirmed; a provider sign-in links to a password account only once this is set
        await this.client.query(`ALTER TABLE ${p}users ADD COLUMN IF NOT EXISTS email_verified_at TIMESTAMPTZ`);
        // a provider identity linked to an account: GitHub or Google's stable subject, and the verified email it gave
        await this.client.query(`CREATE TABLE IF NOT EXISTS ${p}identities (provider TEXT NOT NULL, subject TEXT NOT NULL, user_id TEXT NOT NULL REFERENCES ${p}users(id), email TEXT NOT NULL, created_at TIMESTAMPTZ NOT NULL DEFAULT now(), PRIMARY KEY (provider, subject))`);
        await this.client.query(`ALTER TABLE ${p}users ADD COLUMN IF NOT EXISTS mfa_secret TEXT`);
        await this.client.query(`ALTER TABLE ${p}users ADD COLUMN IF NOT EXISTS mfa_enabled_at TIMESTAMPTZ`);
        await this.client.query(`ALTER TABLE ${p}users ADD COLUMN IF NOT EXISTS mfa_last_step BIGINT`);
        await this.client.query(`CREATE TABLE IF NOT EXISTS ${p}invites (tenant_id TEXT NOT NULL, email TEXT NOT NULL, role TEXT NOT NULL, invited_by TEXT NOT NULL, created_at TIMESTAMPTZ NOT NULL DEFAULT now(), PRIMARY KEY (tenant_id, email))`);
        // who an admin removed from a tenant: single sign-on does not let them back in on its own
        await this.client.query(`CREATE TABLE IF NOT EXISTS ${p}removed (tenant_id TEXT NOT NULL, user_id TEXT NOT NULL, PRIMARY KEY (tenant_id, user_id))`);
        // the address too, so the removal holds after the account is made again under a new id
        await this.client.query(`ALTER TABLE ${p}removed ADD COLUMN IF NOT EXISTS email TEXT`);
        await this.client.query(`ALTER TABLE ${p}users ADD COLUMN IF NOT EXISTS mfa_recovery TEXT[]`);
        await this.client.query(`ALTER TABLE ${p}users ADD COLUMN IF NOT EXISTS sessions_after BIGINT`);
        // the SHA-256 of each password reset token; the token itself is only in the mail
        await this.client.query(`CREATE TABLE IF NOT EXISTS ${p}resets (token_hash TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES ${p}users(id), expires_at TIMESTAMPTZ NOT NULL)`);
        await this.client.query(`CREATE TABLE IF NOT EXISTS ${p}sso (tenant_id TEXT PRIMARY KEY, protocol TEXT NOT NULL, config TEXT NOT NULL, domains TEXT[] NOT NULL, default_role TEXT NOT NULL, enforced BOOLEAN NOT NULL DEFAULT false, updated_at TIMESTAMPTZ NOT NULL DEFAULT now())`);
      })();
    }
    return this.ready;
  }
  static hashPassword(password: string): string {
    const salt = randomBytes(16);
    return `scrypt$${salt.toString("hex")}$${scryptSync(password, salt, 64).toString("hex")}`;
  }
  static checkPassword(password: string, stored: string): boolean {
    const [alg, saltHex, hashHex] = stored.split("$");
    if (alg !== "scrypt" || !saltHex || !hashHex) return false;
    const expected = Buffer.from(hashHex, "hex");
    const got = scryptSync(password, Buffer.from(saltHex, "hex"), expected.length);
    return got.length === expected.length && timingSafeEqual(got, expected);
  }
  async createUser(email: string, password: string, profile: Profile = {}): Promise<PortalUser> {
    await this.init();
    const id = randomUUID();
    const rows = (await this.client.query(`INSERT INTO ${this.p}users (id, email, password_hash, name, company, role, phone, telegram) VALUES ($1, $2, $3, $4, $5, $6, $7, $8) ON CONFLICT (email) DO NOTHING RETURNING id, email, created_at`, [id, email, PortalStore.hashPassword(password), profile.name ?? null, profile.company ?? null, profile.role ?? null, profile.phone ?? null, profile.telegram ?? null])).rows as Record<string, unknown>[];
    if (!rows[0]) throw new Error("an account with this email already exists");
    return { id, email, createdAt: new Date(rows[0].created_at as string).toISOString() };
  }
  async userByEmail(email: string): Promise<PortalUser | null> {
    await this.init();
    const rows = (await this.client.query(`SELECT id, email, created_at, email_verified_at FROM ${this.p}users WHERE email = $1`, [email])).rows as Record<string, unknown>[];
    return rows[0] ? PortalStore.asUser(rows[0]) : null;
  }
  private static asUser(r: Record<string, unknown>): PortalUser {
    return { id: String(r.id), email: String(r.email), createdAt: new Date(r.created_at as string).toISOString(), emailVerifiedAt: r.email_verified_at ? new Date(r.email_verified_at as string).toISOString() : null, ...(r.sessions_after != null ? { sessionsAfter: Number(r.sessions_after) } : {}) };
  }
  async markEmailVerified(userId: string, at = new Date()): Promise<void> {
    await this.init();
    await this.client.query(`UPDATE ${this.p}users SET email_verified_at = COALESCE(email_verified_at, $2) WHERE id = $1`, [userId, at.toISOString()]);
  }
  /** Links a provider identity to a signed-in account: the account proved itself with its session, so the provider's email need not match. */
  async linkIdentity(provider: string, subject: string, email: string, userId: string): Promise<void> {
    await this.init();
    await this.client.query(`INSERT INTO ${this.p}identities (provider, subject, user_id, email) VALUES ($1, $2, $3, $4) ON CONFLICT (provider, subject) DO UPDATE SET user_id = EXCLUDED.user_id, email = EXCLUDED.email`, [provider, subject, userId, email]);
  }
  async identities(userId: string): Promise<string[]> {
    await this.init();
    const rows = (await this.client.query(`SELECT DISTINCT provider FROM ${this.p}identities WHERE user_id = $1 ORDER BY provider`, [userId])).rows as { provider: string }[];
    return rows.map((r) => r.provider);
  }
  /** the account's profile, for the onboarding screen and the operator's note */
  async profile(userId: string): Promise<Profile> {
    await this.init();
    const rows = (await this.client.query(`SELECT name, company, role, phone, telegram FROM ${this.p}users WHERE id = $1`, [userId])).rows as Record<string, unknown>[];
    const r = rows[0] ?? {};
    const str = (v: unknown) => (v == null ? null : String(v));
    return { name: str(r.name), company: str(r.company), role: str(r.role), phone: str(r.phone), telegram: str(r.telegram) };
  }
  /** Accounts with a tenant, a name, and no founder's note yet, registered inside the window: the hourly job's work list. */
  async pendingFollowUps(o: { now: Date; minAgeMs: number; maxAgeMs: number }): Promise<{ id: string; email: string; name: string; company: string | null; tenantId: string; createdAt: string }[]> {
    await this.init();
    const rows = (await this.client.query(
      `SELECT u.id, u.email, u.name, u.company, m.tenant_id, u.created_at FROM ${this.p}users u JOIN ${this.p}members m ON m.user_id = u.id
       WHERE u.followed_up_at IS NULL AND u.name IS NOT NULL AND u.created_at <= $1 AND u.created_at >= $2 ORDER BY u.created_at`,
      [new Date(o.now.getTime() - o.minAgeMs).toISOString(), new Date(o.now.getTime() - o.maxAgeMs).toISOString()],
    )).rows as Record<string, unknown>[];
    return rows.map((r) => ({ id: String(r.id), email: String(r.email), name: String(r.name), company: r.company == null ? null : String(r.company), tenantId: String(r.tenant_id), createdAt: new Date(r.created_at as string).toISOString() }));
  }
  async markFollowedUp(userId: string, at = new Date()): Promise<void> {
    await this.init();
    await this.client.query(`UPDATE ${this.p}users SET followed_up_at = $2 WHERE id = $1`, [userId, at.toISOString()]);
  }
  async updateProfile(userId: string, profile: Profile): Promise<void> {
    await this.init();
    await this.client.query(`UPDATE ${this.p}users SET name = $2, company = $3, role = $4, phone = $5, telegram = $6 WHERE id = $1`, [userId, profile.name ?? null, profile.company ?? null, profile.role ?? null, profile.phone ?? null, profile.telegram ?? null]);
  }
  /**
   * The account behind a provider sign-in: the linked one; else the account with that email, linked from now on, but
   * only if that account has verified its address (otherwise anyone could register a victim's address with a
   * password, wait for the victim to sign in with Google, and keep password access to the merged account: issue
   * #103; the refusal is UnverifiedAccountError); else a new account with a random password nobody knows, its address
   * counted as verified because the provider vouched for it. The provider's email must be verified.
   */
  async findOrCreateOAuthUser(provider: string, subject: string, email: string): Promise<PortalUser> {
    await this.init();
    const linked = (await this.client.query(`SELECT user_id FROM ${this.p}identities WHERE provider = $1 AND subject = $2`, [provider, subject])).rows as { user_id: string }[];
    if (linked[0]) {
      const u = await this.user(linked[0].user_id);
      if (u) return u;
    }
    let user = await this.userByEmail(email);
    if (user && !user.emailVerifiedAt) throw new UnverifiedAccountError(email);
    if (!user) {
      user = await this.createUser(email, randomBytes(32).toString("hex"));
      await this.markEmailVerified(user.id);
    }
    await this.linkIdentity(provider, subject, email, user.id);
    return user;
  }
  async authenticate(email: string, password: string): Promise<PortalUser | null> {
    await this.init();
    const rows = (await this.client.query(`SELECT id, email, password_hash, created_at FROM ${this.p}users WHERE email = $1`, [email])).rows as Record<string, unknown>[];
    const r = rows[0];
    if (!r || !PortalStore.checkPassword(password, String(r.password_hash))) return null;
    return { id: String(r.id), email: String(r.email), createdAt: new Date(r.created_at as string).toISOString() };
  }
  /** A reset token for the account, good for `ttlMs` and once. Only its hash is stored. */
  async createPasswordReset(userId: string, ttlMs = 3_600_000): Promise<string> {
    await this.init();
    const token = randomBytes(32).toString("base64url");
    await this.client.query(`INSERT INTO ${this.p}resets (token_hash, user_id, expires_at) VALUES ($1, $2, $3)`, [sha256(token), userId, new Date(Date.now() + ttlMs).toISOString()]);
    return token;
  }
  /** The account of a reset token that has not expired, and the token is gone; null otherwise. */
  async takePasswordReset(token: string): Promise<string | null> {
    await this.init();
    const rows = (await this.client.query(`DELETE FROM ${this.p}resets WHERE token_hash = $1 RETURNING user_id, expires_at`, [sha256(token)])).rows as { user_id: string; expires_at: string }[];
    return rows[0] && new Date(rows[0].expires_at).getTime() > Date.now() ? rows[0].user_id : null;
  }
  /** Sets the password, ends every session and MFA cookie signed before `at`, and drops the account's reset tokens. */
  async setPassword(userId: string, password: string, at = Date.now()): Promise<void> {
    await this.init();
    await this.client.query(`UPDATE ${this.p}users SET password_hash = $2, sessions_after = $3 WHERE id = $1`, [userId, PortalStore.hashPassword(password), at]);
    await this.client.query(`DELETE FROM ${this.p}resets WHERE user_id = $1`, [userId]);
  }
  async unlinkIdentities(userId: string): Promise<void> {
    await this.init();
    await this.client.query(`DELETE FROM ${this.p}identities WHERE user_id = $1`, [userId]);
  }
  async user(id: string): Promise<PortalUser | null> {
    await this.init();
    const rows = (await this.client.query(`SELECT id, email, created_at, email_verified_at, sessions_after FROM ${this.p}users WHERE id = $1`, [id])).rows as Record<string, unknown>[];
    return rows[0] ? PortalStore.asUser(rows[0]) : null;
  }
  async addMember(userId: string, tenantId: string, role: Role = "owner"): Promise<void> {
    await this.init();
    await this.client.query(`INSERT INTO ${this.p}members (user_id, tenant_id, role) VALUES ($1, $2, $3) ON CONFLICT DO NOTHING`, [userId, tenantId, role]);
  }
  async roleOf(userId: string, tenantId: string): Promise<Role | null> {
    await this.init();
    const rows = (await this.client.query(`SELECT role FROM ${this.p}members WHERE user_id = $1 AND tenant_id = $2`, [userId, tenantId])).rows as { role: Role }[];
    return rows[0]?.role ?? null;
  }
  async members(tenantId: string): Promise<{ id: string; email: string; role: Role; joinedAt: string; mfa: boolean }[]> {
    await this.init();
    const rows = (await this.client.query(`SELECT u.id, u.email, m.role, m.created_at, u.mfa_enabled_at FROM ${this.p}members m JOIN ${this.p}users u ON u.id = m.user_id WHERE m.tenant_id = $1 ORDER BY m.created_at, u.email`, [tenantId])).rows as Record<string, unknown>[];
    return rows.map((r) => ({ id: String(r.id), email: String(r.email), role: r.role as Role, joinedAt: new Date(r.created_at as string).toISOString(), mfa: !!r.mfa_enabled_at }));
  }
  // Both statements skip the row of the last owner, and return false then.
  async setRole(tenantId: string, userId: string, role: Role): Promise<boolean> {
    await this.init();
    return (await this.client.query(`UPDATE ${this.p}members SET role = $3 WHERE user_id = $1 AND tenant_id = $2 AND ($3 = 'owner' OR role <> 'owner' OR EXISTS (SELECT 1 FROM ${this.p}members o WHERE o.tenant_id = $2 AND o.role = 'owner' AND o.user_id <> $1)) RETURNING user_id`, [userId, tenantId, role])).rows.length > 0;
  }
  // The removal record stays after a rejoin by invite. It has no effect while the user is a member: only findOrCreateSsoUser reads it, and only when the home tenant differs.
  async removeMember(tenantId: string, userId: string): Promise<boolean> {
    await this.init();
    const gone = (await this.client.query(`DELETE FROM ${this.p}members WHERE user_id = $1 AND tenant_id = $2 AND (role <> 'owner' OR EXISTS (SELECT 1 FROM ${this.p}members o WHERE o.tenant_id = $2 AND o.role = 'owner' AND o.user_id <> $1)) RETURNING user_id`, [userId, tenantId])).rows.length > 0;
    if (gone) await this.client.query(`INSERT INTO ${this.p}removed (tenant_id, user_id, email) SELECT $1, id, email FROM ${this.p}users WHERE id = $2 ON CONFLICT DO NOTHING`, [tenantId, userId]);
    return gone;
  }
  async invite(tenantId: string, email: string, role: Role, by: string): Promise<void> {
    await this.init();
    await this.client.query(`INSERT INTO ${this.p}invites (tenant_id, email, role, invited_by) VALUES ($1, $2, $3, $4) ON CONFLICT (tenant_id, email) DO UPDATE SET role = EXCLUDED.role, invited_by = EXCLUDED.invited_by, created_at = now()`, [tenantId, email, role, by]);
  }
  async invitesOf(tenantId: string): Promise<{ email: string; role: Role; invitedBy: string; createdAt: string }[]> {
    await this.init();
    const rows = (await this.client.query(`SELECT email, role, invited_by, created_at FROM ${this.p}invites WHERE tenant_id = $1 ORDER BY created_at`, [tenantId])).rows as Record<string, unknown>[];
    return rows.map((r) => ({ email: String(r.email), role: r.role as Role, invitedBy: String(r.invited_by), createdAt: new Date(r.created_at as string).toISOString() }));
  }
  async invitesFor(email: string): Promise<{ tenant: string; role: Role }[]> {
    await this.init();
    const rows = (await this.client.query(`SELECT tenant_id, role FROM ${this.p}invites WHERE email = $1 AND created_at > now() - interval '7 days' ORDER BY created_at`, [email])).rows as { tenant_id: string; role: Role }[];
    return rows.map((r) => ({ tenant: r.tenant_id, role: r.role }));
  }
  async removeInvite(tenantId: string, email: string): Promise<boolean> {
    await this.init();
    return (await this.client.query(`DELETE FROM ${this.p}invites WHERE tenant_id = $1 AND email = $2 RETURNING email`, [tenantId, email])).rows.length > 0;
  }
  async takeInvite(tenantId: string, email: string): Promise<Role | null> {
    await this.init();
    const rows = (await this.client.query(`DELETE FROM ${this.p}invites WHERE tenant_id = $1 AND email = $2 AND created_at > now() - interval '7 days' RETURNING role`, [tenantId, email])).rows as { role: Role }[];
    return rows[0]?.role ?? null;
  }
  async mfa(userId: string): Promise<{ secret: string | null; enabled: boolean; recoveryCodes: number }> {
    await this.init();
    const rows = (await this.client.query(`SELECT mfa_secret, mfa_enabled_at, mfa_recovery FROM ${this.p}users WHERE id = $1`, [userId])).rows as Record<string, unknown>[];
    return { secret: rows[0]?.mfa_secret ? String(rows[0].mfa_secret) : null, enabled: !!rows[0]?.mfa_enabled_at, recoveryCodes: ((rows[0]?.mfa_recovery as string[] | null) ?? []).length };
  }
  /** Replaces the account's recovery codes with ten new ones, returned once; only their hashes are stored. */
  async newRecoveryCodes(userId: string): Promise<string[]> {
    await this.init();
    const codes = Array.from({ length: 10 }, () => base32(randomBytes(8)).slice(0, 12).toLowerCase().replace(/(.{4})(?=.)/g, "$1-"));
    await this.client.query(`UPDATE ${this.p}users SET mfa_recovery = $2::text[] WHERE id = $1`, [userId, codes.map(recoveryHash)]);
    return codes;
  }
  /** False when the code is not one of the account's unused recovery codes. */
  async takeRecoveryCode(userId: string, code: string): Promise<boolean> {
    await this.init();
    const h = recoveryHash(code);
    return (await this.client.query(`UPDATE ${this.p}users SET mfa_recovery = array_remove(mfa_recovery, $2) WHERE id = $1 AND $2 = ANY(mfa_recovery) RETURNING id`, [userId, h])).rows.length > 0;
  }
  async setMfaSecret(userId: string, secretHex: string): Promise<boolean> {
    await this.init();
    return (await this.client.query(`UPDATE ${this.p}users SET mfa_secret = $2, mfa_last_step = NULL WHERE id = $1 AND mfa_enabled_at IS NULL RETURNING id`, [userId, secretHex])).rows.length > 0;
  }
  /** False when this step or a later one was used already. */
  async takeMfaStep(userId: string, step: number): Promise<boolean> {
    await this.init();
    return (await this.client.query(`UPDATE ${this.p}users SET mfa_last_step = $2 WHERE id = $1 AND (mfa_last_step IS NULL OR mfa_last_step < $2) RETURNING id`, [userId, step])).rows.length > 0;
  }
  async enableMfa(userId: string): Promise<void> {
    await this.init();
    await this.client.query(`UPDATE ${this.p}users SET mfa_enabled_at = now() WHERE id = $1`, [userId]);
  }
  async resetMfa(email: string): Promise<boolean> {
    await this.init();
    return (await this.client.query(`UPDATE ${this.p}users SET mfa_secret = NULL, mfa_enabled_at = NULL, mfa_last_step = NULL, mfa_recovery = NULL WHERE email = $1 RETURNING id`, [email])).rows.length > 0;
  }
  /** Replaces the tenant's setting. A domain belongs to one tenant, so a domain that another tenant holds is refused. */
  async setSso(s: SsoSetting): Promise<void> {
    await this.init();
    const domains = [...new Set(s.domains.map((d) => d.trim().toLowerCase()))];
    if (!domains.length || domains.some((d) => !/^[a-z0-9]([a-z0-9.-]*[a-z0-9])?\.[a-z]{2,}$/.test(d))) throw new Error("SSO needs one or more email domains, such as acme.example");
    if (!ROLES.includes(s.defaultRole) || s.defaultRole === "owner") throw new Error("the default role of an SSO member is readonly, reviewer, or admin");
    const held = (await this.client.query(`SELECT tenant_id, domains FROM ${this.p}sso WHERE tenant_id <> $1 AND domains && $2::text[]`, [s.tenant, domains])).rows as { tenant_id: string; domains: string[] }[];
    if (held[0]) throw new Error(`the domain ${domains.find((d) => held[0]!.domains.includes(d))} belongs to tenant ${held[0].tenant_id} already`);
    await this.client.query(
      `INSERT INTO ${this.p}sso (tenant_id, protocol, config, domains, default_role, enforced, updated_at) VALUES ($1, $2, $3, $4::text[], $5, $6, now())
       ON CONFLICT (tenant_id) DO UPDATE SET protocol = EXCLUDED.protocol, config = EXCLUDED.config, domains = EXCLUDED.domains, default_role = EXCLUDED.default_role, enforced = EXCLUDED.enforced, updated_at = now()`,
      [s.tenant, s.protocol, JSON.stringify(s.config), domains, s.defaultRole, s.enforced],
    );
  }
  private async ssoWhere(where: string, param: string): Promise<SsoSetting | null> {
    await this.init();
    const r = ((await this.client.query(`SELECT tenant_id, protocol, config, domains, default_role, enforced FROM ${this.p}sso WHERE ${where}`, [param])).rows as Record<string, unknown>[])[0];
    return r ? { tenant: String(r.tenant_id), protocol: r.protocol as "oidc" | "saml", config: JSON.parse(String(r.config)), domains: r.domains as string[], defaultRole: r.default_role as Role, enforced: !!r.enforced } : null;
  }
  ssoOf(tenant: string): Promise<SsoSetting | null> {
    return this.ssoWhere("tenant_id = $1", tenant);
  }
  ssoByDomain(domain: string): Promise<SsoSetting | null> {
    return this.ssoWhere("$1 = ANY(domains)", domain.toLowerCase());
  }
  async removeSso(tenant: string): Promise<boolean> {
    await this.init();
    return (await this.client.query(`DELETE FROM ${this.p}sso WHERE tenant_id = $1 RETURNING tenant_id`, [tenant])).rows.length > 0;
  }
  /**
   * The account behind an identity that the tenant's IdP vouched for: the linked one; else the account with that
   * email, linked from now on, if it verified its address; else a new verified account with a random password.
   * The IdP proves the address, so an account that never verified it loses the address: the account goes, with its
   * password, its sessions, and its links. A tenant that it owned stays for the operator. There are two exceptions: an
   * unverified member of this same tenant, who verifies by password first (UnverifiedAccountError), and an
   * unverified member of another tenant that has other members, who is refused. An account with
   * no tenant joins with the default role. A member that an admin removed joins again only through a new invite,
   * with the invited role.
   */
  async findOrCreateSsoUser(s: SsoSetting, id: SsoIdentity): Promise<PortalUser> {
    await this.init();
    const provider = `sso:${s.tenant}`;
    const parts = id.email.split("@");
    if (parts.length !== 2 || !s.domains.includes(parts[1]!)) throw new SsoRefusedError(`the address ${id.email} is not in a domain that signs in to ${s.tenant} through single sign-on`);
    const linked = (await this.client.query(`SELECT user_id FROM ${this.p}identities WHERE provider = $1 AND subject = $2`, [provider, id.subject])).rows as { user_id: string }[];
    let user = linked[0] ? await this.user(linked[0].user_id) : null;
    const known = !!user;
    user ??= await this.userByEmail(id.email);
    const unverified = !!user && !known && !user.emailVerifiedAt;
    let home = user ? await this.tenantOf(user.id) : null;
    if (unverified && home === s.tenant) throw new UnverifiedAccountError(id.email);
    // deleting an unverified account would strand the other members of the tenant that it belongs to
    if (home && home !== s.tenant && (!unverified || (await this.client.query(`SELECT 1 FROM ${this.p}members WHERE tenant_id = $1 AND user_id <> $2 LIMIT 1`, [home, user!.id])).rows.length)) throw new SsoRefusedError(`the account ${id.email} belongs to another tenant`);
    let role = s.defaultRole;
    // the removal is looked up before an unverified account goes, or the person would rejoin as a new account; an account of another tenant is no way around it
    if (home !== s.tenant && (await this.client.query(`SELECT 1 FROM ${this.p}removed WHERE tenant_id = $1 AND (email = $3 OR user_id = $2)`, [s.tenant, user?.id ?? "", id.email])).rows.length) {
      const invited = await this.takeInvite(s.tenant, id.email);
      if (!invited) throw new SsoRefusedError(`${id.email} was removed from ${s.tenant}; an admin must invite the address again`);
      role = invited;
    }
    if (unverified) {
      for (const t of ["members", "identities", "resets"]) await this.client.query(`DELETE FROM ${this.p}${t} WHERE user_id = $1`, [user!.id]);
      await this.client.query(`DELETE FROM ${this.p}users WHERE id = $1`, [user!.id]);
      user = null;
      home = null;
    }
    if (!user) {
      user = await this.createUser(id.email, randomBytes(32).toString("hex"));
      await this.markEmailVerified(user.id);
    }
    if (!known) await this.linkIdentity(provider, id.subject, id.email, user.id);
    if (!home) await this.addMember(user.id, s.tenant, role);
    return user;
  }
  /** the user's tenant; one per account today */
  async tenantOf(userId: string): Promise<string | null> {
    await this.init();
    const rows = (await this.client.query(`SELECT tenant_id FROM ${this.p}members WHERE user_id = $1 ORDER BY created_at LIMIT 1`, [userId])).rows as { tenant_id: string }[];
    return rows[0]?.tenant_id ?? null;
  }
  async setBilling(tenantId: string, b: { customerId?: string | null; subscriptionId?: string | null; status: string; eventCreated?: number }): Promise<void> {
    await this.init();
    await this.client.query(
      `INSERT INTO ${this.p}billing (tenant_id, customer_id, subscription_id, status, event_created, updated_at) VALUES ($1, $2, $3, $4, $5, now())
       ON CONFLICT (tenant_id) DO UPDATE SET customer_id = COALESCE(EXCLUDED.customer_id, ${this.p}billing.customer_id), subscription_id = COALESCE(EXCLUDED.subscription_id, ${this.p}billing.subscription_id), status = EXCLUDED.status, event_created = COALESCE(EXCLUDED.event_created, ${this.p}billing.event_created), updated_at = now()`,
      [tenantId, b.customerId ?? null, b.subscriptionId ?? null, b.status, b.eventCreated ?? null],
    );
  }
  async billing(tenantId: string): Promise<{ customerId: string | null; subscriptionId: string | null; status: string; eventCreated: number | null } | null> {
    await this.init();
    const rows = (await this.client.query(`SELECT customer_id, subscription_id, status, event_created FROM ${this.p}billing WHERE tenant_id = $1`, [tenantId])).rows as Record<string, unknown>[];
    const r = rows[0];
    return r ? { customerId: r.customer_id ? String(r.customer_id) : null, subscriptionId: r.subscription_id ? String(r.subscription_id) : null, status: String(r.status), eventCreated: r.event_created == null ? null : Number(r.event_created) } : null;
  }
  /** Has this Stripe event id been applied already? */
  async stripeEventSeen(id: string): Promise<boolean> {
    await this.init();
    return (await this.client.query(`SELECT 1 FROM ${this.p}stripe_events WHERE id = $1`, [id])).rows.length > 0;
  }
  /** Records a Stripe event id as applied, after it was applied, so a failure before this point lets Stripe's retry through. */
  async noteStripeEvent(id: string): Promise<void> {
    await this.init();
    await this.client.query(`INSERT INTO ${this.p}stripe_events (id) VALUES ($1) ON CONFLICT (id) DO NOTHING`, [id]);
  }
  /** Every portal registration with its tenant and billing state, oldest first: what the operator's admin page lists. Owners only. */
  async registrations(): Promise<({ tenantId: string; email: string; registeredAt: string; billing: string | null } & Profile)[]> {
    await this.init();
    const rows = (await this.client.query(`SELECT m.tenant_id, u.email, u.created_at, u.name, u.company, u.role, u.phone, u.telegram, b.status FROM ${this.p}members m JOIN ${this.p}users u ON u.id = m.user_id LEFT JOIN ${this.p}billing b ON b.tenant_id = m.tenant_id WHERE m.role = 'owner' ORDER BY u.created_at, m.tenant_id`)).rows as Record<string, unknown>[];
    const str = (v: unknown) => (v == null ? null : String(v));
    return rows.map((r) => ({ tenantId: String(r.tenant_id), email: String(r.email), registeredAt: new Date(r.created_at as string).toISOString(), billing: str(r.status), name: str(r.name), company: str(r.company), role: str(r.role), phone: str(r.phone), telegram: str(r.telegram) }));
  }
  async tenantBySubscription(subscriptionId: string): Promise<string | null> {
    await this.init();
    const rows = (await this.client.query(`SELECT tenant_id FROM ${this.p}billing WHERE subscription_id = $1`, [subscriptionId])).rows as { tenant_id: string }[];
    return rows[0]?.tenant_id ?? null;
  }
}

// ---- sessions ----
const b64u = (b: Buffer) => b.toString("base64url");
/** `via` records how the user signed in, for example `sso:acme`. */
export function signSession(secret: string, userId: string, ttlMs = 14 * 86_400_000, via?: string): string {
  const body = b64u(Buffer.from(JSON.stringify({ u: userId, e: Date.now() + ttlMs, i: Date.now(), ...(via ? { a: via } : {}) })));
  return `${body}.${createHmac("sha256", secret).update(body).digest("base64url")}`;
}
function readClaims(secret: string, cookie: string | undefined): { u: string; a?: string; i: number } | null {
  if (!cookie) return null;
  const [body, mac] = cookie.split(".");
  if (!body || !mac) return null;
  const expected = createHmac("sha256", secret).update(body).digest("base64url");
  if (expected.length !== mac.length || !timingSafeEqual(Buffer.from(expected), Buffer.from(mac))) return null;
  try {
    const { u, e, a, i } = JSON.parse(Buffer.from(body, "base64url").toString()) as { u: string; e: number; a?: string; i?: number };
    // a cookie from before the issue time was added counts as issued at 0, so a reset ends it too
    return typeof u === "string" && typeof e === "number" && e > Date.now() ? { u, i: typeof i === "number" ? i : 0, ...(typeof a === "string" ? { a } : {}) } : null;
  } catch {
    return null;
  }
}
export const readSession = (secret: string, cookie: string | undefined): string | null => readClaims(secret, cookie)?.u ?? null;
/** The `via` of a valid session, or null. */
export const readSessionVia = (secret: string, cookie: string | undefined): string | null => readClaims(secret, cookie)?.a ?? null;

// ---- Stripe, over its REST API; no SDK ----
const form = (o: Record<string, string>) => new URLSearchParams(o).toString();
export async function stripeRequest(s: StripeOptions, path: string, body: Record<string, string>): Promise<Record<string, unknown>> {
  const f = s.fetch ?? fetch;
  const res = await f(`https://api.stripe.com/v1/${path}`, { method: "POST", headers: { authorization: `Bearer ${s.secretKey}`, "content-type": "application/x-www-form-urlencoded" }, body: form(body), signal: AbortSignal.timeout(15_000) });
  const json = (await res.json()) as Record<string, unknown>;
  if (!res.ok) throw new Error(`stripe ${path}: ${(json.error as { message?: string })?.message ?? res.status}`);
  return json;
}
/** Stripe-Signature: t=<unix>,v1=<hmac>; the mac is over `${t}.${rawBody}` with the endpoint secret. */
export function verifyStripeSignature(header: string | undefined, rawBody: string, secret: string, now = Date.now(), toleranceMs = 5 * 60_000): boolean {
  if (!header) return false;
  const parts = Object.fromEntries(header.split(",").map((kv) => kv.split("=") as [string, string]));
  const t = Number(parts.t);
  if (!Number.isFinite(t) || Math.abs(now - t * 1000) > toleranceMs) return false;
  const expected = createHmac("sha256", secret).update(`${parts.t}.${rawBody}`).digest("hex");
  return header
    .split(",")
    .filter((kv) => kv.startsWith("v1="))
    .some((kv) => {
      const sig = kv.slice(3);
      return sig.length === expected.length && timingSafeEqual(Buffer.from(sig), Buffer.from(expected));
    });
}

export interface RunningPortal {
  url: string;
  close(): Promise<void>;
}

const TENANT_ID = /^[a-z0-9][a-z0-9-]{1,38}[a-z0-9]$/;
const EMAIL = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const ENFORCED = "Your organisation signs in through its identity provider. Use Sign in with single sign-on";
const RESERVED = new Set(["default", "admin", "api", "www", "log", "checkpoints", "app", "portal", "stripe", "health", "t"]);

/** One message through the provider. Best effort: a refusal or a failure is reported through `log`, never thrown. Returns whether it was accepted. */
export async function deliverMail(mail: MailOptions, m: { to: string; subject: string; text: string }, log: (message: string) => void = console.error): Promise<boolean> {
  const f = mail.fetch ?? fetch;
  try {
    const r = await f(mail.url ?? "https://api.resend.com/emails", { method: "POST", headers: { authorization: `Bearer ${mail.apiKey}`, "content-type": "application/json" }, body: JSON.stringify({ from: mail.from, to: [m.to], subject: m.subject, text: m.text }), signal: AbortSignal.timeout(10_000) });
    if (r.ok) return true;
    log(`agent-custody portal: mail to ${m.to} refused: ${r.status} ${(await r.text()).slice(0, 200)}`);
  } catch (e) {
    log(`agent-custody portal: mail to ${m.to} failed: ${e instanceof Error ? e.message : String(e)}`);
  }
  return false;
}

/**
 * The founder's note, sent about an hour after a registration by `sendFollowUps`, once. Written to get the first
 * receipt appended: it asks which stack they are on, offers to do the integration, and says to start in observe mode.
 */
export function founderNote(o: { name: string; tenant: string; company: string | null; portalUrl: string; from: string }): { subject: string; text: string } {
  const first = o.name.trim().split(/\s+/)[0] || o.name;
  const signer = o.from.replace(/^.*<|>.*$/g, "");
  return {
    subject: "Welcome to agent-custody, and one question",
    text: [
      `Hi ${first},`, "",
      `Thanks for registering ${o.tenant} on agent-custody. I am Partha, the founder; you will get me, not a queue.`, "",
      "One question so I can help rather than guess: which stack are your agents on, and what do they touch? Claude Code, the OpenAI Agents SDK, LangChain, OpenClaw, DeepSeek Harness, Hermes, plain Python, or an MCP host. If you tell me, I will send the exact config for it, and if it is quicker, I will do the integration with you on a call: twenty minutes gets a first receipt into your log and verified in the browser.", "",
      'Two things worth knowing from the start. Run it in observe mode first, "mode": "observe" in the config: nothing is blocked, and each receipt records what the policy would have denied, so you tune the policy against real traffic before turning it on. And the log only ever receives a hash per receipt; the receipts stay on your machines.', "",
      `You are on the free plan, ten thousand appends a month, no card. If you hit that, tell me and I move you up while we talk. The setup sheet is under Setup in the dashboard whenever you need it: ${o.portalUrl}`, "",
      `What are you building${o.company ? ` at ${o.company}` : ""}? I would like to know what you want the receipts to prove, and to whom.`, "",
      "Partha", `agent-custody.dev · ${signer}`,
    ].join("\n"),
  };
}

/**
 * Sends the founder's note to every account registered between an hour and a week ago that has not had it, and
 * marks each one. Accounts on the operator's own mail domains are marked without a message. Idempotent: run it hourly.
 */
export async function sendFollowUps(store: PortalStore, mail: MailOptions, o: { portalUrl: string; now?: Date; minAgeMs?: number; maxAgeMs?: number; dryRun?: boolean; log?: (message: string) => void } = { portalUrl: "https://app.agent-custody.dev/" }): Promise<{ sent: string[]; skipped: string[]; failed: string[] }> {
  const log = o.log ?? console.error;
  const now = o.now ?? new Date();
  const own = new Set([mail.from, mail.notify ?? ""].map((a) => a.replace(/^.*<|>.*$/g, "").split("@")[1]?.toLowerCase()).filter(Boolean));
  const sent: string[] = [];
  const skipped: string[] = [];
  const failed: string[] = [];
  for (const u of await store.pendingFollowUps({ now, minAgeMs: o.minAgeMs ?? 3_600_000, maxAgeMs: o.maxAgeMs ?? 7 * 86_400_000 })) {
    if (own.has(u.email.split("@")[1]?.toLowerCase() ?? "")) {
      if (!o.dryRun) await store.markFollowedUp(u.id, now);
      skipped.push(u.email);
      continue;
    }
    const note = founderNote({ name: u.name, tenant: u.tenantId, company: u.company, portalUrl: o.portalUrl, from: mail.from });
    if (o.dryRun) { sent.push(u.email); continue; }
    if (await deliverMail(mail, { to: u.email, ...note }, log)) {
      await store.markFollowedUp(u.id, now);
      sent.push(u.email);
      log(`agent-custody portal: founder's note sent to ${u.email} for tenant ${u.tenantId}`);
    } else {
      failed.push(u.email); // left pending; the next run tries again
    }
  }
  return { sent, skipped, failed };
}

export function portalHandler(o: PortalOptions): (req: IncomingMessage, res: ServerResponse) => Promise<void> {
  const store = new PortalStore(o.client, o.prefix);
  const heads: CheckpointStore = postgresCheckpoints(o.client);
  const log = o.log ?? ((m) => console.error(m));
  const loginFailures = new RateLimiter({ perSecond: 1 / 30, burst: 8 });
  const registrations = new RateLimiter({ perSecond: 1 / 600, burst: 5 });
  // per account, whatever the address
  const mfaFailures = new RateLimiter({ perSecond: 1 / 120, burst: 5 });
  const resetsByClient = new RateLimiter({ perSecond: 1 / 600, burst: 5 });
  const resetsByEmail = new RateLimiter({ perSecond: 1 / 900, burst: 3 });
  const base = o.publicUrl.endsWith("/") ? o.publicUrl : `${o.publicUrl}/`;
  const cookieName = "custody_session";

  const sheet = (tenant: string, logId: string) => welcomeSheet({ tenant, logId, publicUrl: base, ...(o.checkpointsUrl ? { checkpointsUrl: o.checkpointsUrl } : {}), ...(o.keyid ? { keyid: o.keyid } : {}) });
  const portalBase = (o.portalUrl ?? "http://localhost/").replace(/\/?$/, "/");
  // Mail is best effort and off the request path: a provider outage is logged, never a failed registration.
  const send = async (m: { to: string; subject: string; text: string }) => { if (o.mail) await deliverMail(o.mail, m, log); };
  /** The verification link: a signed, single-purpose token good for a day. Until it is used, a provider sign-in for this address will not link to the account. */
  const verificationMail = (u: PortalUser) => ({
    to: u.email,
    subject: "Verify your email address for agent-custody",
    text: ["Hello,", "", "Please confirm this address for your agent-custody account by opening the link below. It is good for 24 hours.", "", `${portalBase}verify-email?token=${signSession(o.secret, `verify:${u.id}`, 86_400_000)}`, "", "If you did not create an account, ignore this mail; nothing was created in your name that works without it.", "", "agent-custody"].join("\n"),
  });

  const resetMail = (to: string, token: string) => ({
    to,
    subject: "Reset your agent-custody password",
    text: ["Hello,", "", "Someone asked to reset the password of your agent-custody account. Open the link below to set a new password. The link works one time, for one hour.", "", `${portalBase}reset-password?token=${token}`, "", "If you did not ask for this, ignore this mail. Your password stays the same.", "", "agent-custody"].join("\n"),
  });

  const welcomeMail = (to: string, name: string, tenant: string, logId: string) => send({ to, subject: `Your agent-custody log "${tenant}" is ready`, text: [
    `Hello ${name},`, "",
    `Your tenant "${tenant}" is live on the hosted log. Your API key was shown once when you registered and is not in this email; if it is gone, mint another under API keys at ${portalBase}.`, "",
    "Everything below is under Setup in the dashboard whenever you need it.", "",
    sheet(tenant, logId), "",
    `Dashboard: ${portalBase}`, "Getting started: https://agent-custody.dev/guide/getting-started", "Questions: reply to this email.",
  ].join("\n") });
  const notifyMail = (p: Profile & { email: string; tenant: string }) => o.mail?.notify ? send({ to: o.mail.notify, subject: `New registration: ${p.company} (${p.tenant})`, text: [`${p.name}${p.role ? `, ${p.role}` : ""} at ${p.company} registered tenant "${p.tenant}".`, "", `email     ${p.email}`, `phone     ${p.phone ?? "-"}`, `telegram  ${p.telegram ? `@${p.telegram}` : "-"}`, "", "The Registrations section of the admin page has the same, with their usage."].join("\n") }) : Promise.resolve();
  const exportCommand = (tenant: string) => `npx @agent-custody/receipts log-export --log-url ${base} --tenant ${tenant} --token-env AGENT_CUSTODY_LOG_TOKEN --out custody-export/`;
  // The welcome sheet as data: what the page renders as numbered steps, at registration and again under Setup.
  const setupFor = (tenant: string, logId: string) => {
    const url = `${base}t/${tenant}/`;
    return {
      log: url,
      logId,
      checkpoints: o.checkpointsUrl ? `${o.checkpointsUrl.replace(/\/?$/, "/")}${tenant}/latest.json` : null,
      keys: `${base}.well-known/agent-custody-log.json`,
      keyid: o.keyid ?? null,
      env: "export AGENT_CUSTODY_LOG_TOKEN=<the key shown at registration>",
      config: `"log": { "url": "${url}", "tokenEnv": "AGENT_CUSTODY_LOG_TOKEN", "hashOnly": true }`,
      verify: `npx @agent-custody/receipts verify receipts/<id>.json --issuer-key <your gateway.pub> --principal-key <your principal.pub> --log-url ${url} --log-id ${logId}`,
      audit: `npx @agent-custody/receipts audit --older receipts/<earlier>.json --newer receipts/<later>.json --log-url ${url} --log-id ${logId}`,
      export: exportCommand(tenant),
    };
  };

  return async (req, res) => {
    const url = new URL(req.url ?? "/", "http://localhost");
    const addr = clientAddress(req, o.trustProxy);
    const json = (status: number, body: unknown, headers: Record<string, string | string[]> = {}) => {
      res.writeHead(status, { "content-type": "application/json", "cache-control": "no-store", ...headers });
      res.end(JSON.stringify(body));
    };
    const page = (status: number, title: string, body: string, headers: Record<string, string | string[]> = {}) => {
      res.writeHead(status, { "content-type": "text/html; charset=utf-8", "cache-control": "no-store", "content-security-policy": "default-src 'none'; style-src 'unsafe-inline'", ...headers });
      res.end(resultPage(title, `<p>${body}</p>`));
    };
    const esc = (v: string) => v.replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" })[c]!);
    const setCookie = (value: string | null) => `${cookieName}=${value ?? ""}; Path=/; HttpOnly; SameSite=Strict${o.trustProxy ? "; Secure" : ""}; Max-Age=${value ? 14 * 86_400 : 0}`;
    // the state between the first step and the code; never a session
    const mfaCookie = (id: string | null) => `custody_mfa=${id ? signSession(o.secret, `mfa:${id}`, 300_000) : ""}; Path=/api/login; HttpOnly; SameSite=Strict${o.trustProxy ? "; Secure" : ""}; Max-Age=${id ? 300 : 0}`;
    const cookies = Object.fromEntries((req.headers.cookie ?? "").split(";").map((c) => c.trim().split("=") as [string, string]).filter(([k]) => k));
    const claims = readClaims(o.secret, cookies[cookieName]);
    const userId = claims?.u ?? null;
    const via = claims?.a ?? null;
    // a password reset or change ends every session and MFA cookie signed before it
    const fresh = (u: PortalUser | null, c: { i: number } | null) => (u && c && c.i >= (u.sessionsAfter ?? 0) ? u : null);
    // A page, not a redirect: the session cookie is SameSite=Strict, and a redirect that started at the provider
    // would not carry it. The page's own navigation to / does.
    const signedInPage = (who: string, next: string, setCookies: string[], lead: string) => {
      res.writeHead(200, { "content-type": "text/html; charset=utf-8", "cache-control": "no-store", "set-cookie": setCookies, "content-security-policy": "default-src 'none'; style-src 'unsafe-inline'" });
      res.end(resultPage("Signed in", `<p>${lead} ${esc(who)}. <a href="${next}">Continue</a>.</p>`, `<meta http-equiv="refresh" content="0;url=${next}">`));
    };
    const enforcedFor = async (id: string) => {
      const t = await store.tenantOf(id);
      return t && (await store.ssoOf(t))?.enforced;
    };
    const rawBody = async (): Promise<string> => {
      let text = "";
      for await (const chunk of req) {
        text += chunk;
        if (text.length > 65_536) throw new ClientError(413, "body too large");
      }
      return text;
    };
    const jsonBody = async (): Promise<Record<string, unknown>> => {
      if (!(req.headers["content-type"] ?? "").startsWith("application/json")) throw new ClientError(400, "expected a JSON body");
      const t = await rawBody();
      if (!t) return {};
      try {
        return JSON.parse(t) as Record<string, unknown>;
      } catch {
        throw new ClientError(400, "the body is not valid JSON");
      }
    };

    try {
      if (req.method === "GET" && url.pathname === "/health") return json(200, { ok: true, stripe: !!o.stripe });
      if (req.method === "GET" && url.pathname === "/favicon.svg") { res.writeHead(200, { "content-type": "image/svg+xml", "cache-control": "public, max-age=86400" }); return void res.end(FAVICON); }
      if (req.method === "GET" && url.pathname === "/") {
        res.writeHead(200, { "content-type": "text/html; charset=utf-8", "cache-control": "no-store", "x-frame-options": "DENY", "content-security-policy": "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; img-src 'self'; connect-src 'self'; form-action 'self'; base-uri 'none'" });
        const providers = JSON.stringify((["github", "google"] as const).filter((p) => !!o.oauth?.[p]));
        return void res.end(PORTAL_PAGE.replace("__LOG_BASE__", base.replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" })[c]!)).replace("__PROVIDERS__", providers).replace("__MAIL__", String(!!o.mail)));
      }

      // ---- Stripe's webhook: the only caller that is not a browser with a session ----
      if (req.method === "POST" && url.pathname === "/stripe/webhook") {
        if (!o.stripe) return json(503, { error: "billing is not configured" });
        const raw = await rawBody();
        if (!verifyStripeSignature(req.headers["stripe-signature"] as string | undefined, raw, o.stripe.webhookSecret)) return json(400, { error: "bad signature" });
        const event = JSON.parse(raw) as { id?: unknown; created?: unknown; type: string; data: { object: Record<string, unknown> } };
        if (typeof event.id !== "string" || !event.id || typeof event.created !== "number") return json(400, { error: "an event needs an id and a created time" });
        // Stripe delivers at least once and in no set order: a repeat is ignored by its id, and an event older than the
        // one that set the stored state is ignored by its created time, so neither moves the plan back (issue #105)
        if (await store.stripeEventSeen(event.id)) return json(200, { received: true, duplicate: true });
        const obj = event.data.object;
        const checkout = event.type === "checkout.session.completed";
        const subscription = event.type === "customer.subscription.deleted" || event.type === "customer.subscription.updated";
        const ref = String(obj.client_reference_id ?? "");
        const tenant = checkout ? (ref && (await o.tenancy.tenant(ref)) ? ref : null) : subscription ? await store.tenantBySubscription(String(obj.id ?? "")) : null;
        const stored = tenant ? (await store.billing(tenant))?.eventCreated : null;
        if (tenant && stored != null && event.created < stored) {
          log(`agent-custody portal: ignored ${event.type} ${event.id} for tenant ${tenant}: older than the stored billing state`);
        } else if (tenant && checkout) {
          await store.setBilling(tenant, { customerId: obj.customer ? String(obj.customer) : null, subscriptionId: obj.subscription ? String(obj.subscription) : null, status: "active", eventCreated: event.created });
          await o.tenancy.setPlan(tenant, "team", "stripe:checkout");
          log(`agent-custody portal: tenant ${tenant} moved to team by checkout ${String(obj.id ?? "")}`);
        } else if (tenant) {
          const status = event.type === "customer.subscription.deleted" ? "canceled" : String(obj.status ?? "unknown");
          await store.setBilling(tenant, { status, eventCreated: event.created });
          const plan: Plan = status === "active" || status === "trialing" || status === "past_due" ? "team" : "free";
          const current = (await o.tenancy.tenant(tenant))?.plan;
          if (current !== "enterprise" && current !== plan) await o.tenancy.setPlan(tenant, plan, `stripe:${event.type}`);
        }
        await store.noteStripeEvent(event.id);
        return json(200, { received: true });
      }

      // ---- registration and login ----
      // The tenant and its first key, from the profile and tenant id given: the second step of registration, or the
      // whole of it when a script sends everything at once.
      type Refusal = { status: number; body: Record<string, unknown> };
      // What the tenant setup needs, checked before anything is created: a mistyped form leaves nothing behind.
      const parseOnboarding = async (b: Record<string, unknown>): Promise<Refusal | { tenant: string; profile: Profile }> => {
        const tenant = String(b.tenant ?? "").trim().toLowerCase();
        if (!TENANT_ID.test(tenant) || RESERVED.has(tenant)) return { status: 400, body: { error: "the tenant id is the name in your log's URL: three to forty lowercase letters, digits, or hyphens, and not a reserved word" } };
        const text = (k: string, max: number) => String(b[k] ?? "").trim().slice(0, max);
        const profile: Profile = { name: text("name", 120), company: text("company", 160), role: text("role", 120) || null, phone: text("phone", 40) || null, telegram: text("telegram", 40).replace(/^@/, "") || null };
        if (!profile.name) return { status: 400, body: { error: "your name is needed, so we know who to write to" } };
        if (!profile.company) return { status: 400, body: { error: "the company or organisation the tenant is for is needed" } };
        if (profile.telegram && !/^[A-Za-z0-9_]{5,32}$/.test(profile.telegram)) return { status: 400, body: { error: "a Telegram username is five to thirty-two letters, digits, or underscores, with or without the @" } };
        if (profile.phone && !/^[+0-9 ()./-]{6,40}$/.test(profile.phone)) return { status: 400, body: { error: "a phone number is digits, with an optional + and spaces" } };
        if (await o.tenancy.tenant(tenant)) return { status: 409, body: { error: "that tenant id is taken" } };
        return { tenant, profile };
      };
      const onboard = async (user: PortalUser, parsed: { tenant: string; profile: Profile }): Promise<Refusal> => {
        const { tenant, profile } = parsed;
        if (await store.tenantOf(user.id)) return { status: 409, body: { error: "this account already has a tenant" } };
        await store.updateProfile(user.id, profile);
        const t = await o.tenancy.addTenant(tenant, tenant, `portal:${user.email}`);
        await store.addMember(user.id, tenant);
        const minted = await o.tenancy.addToken(tenant, "first key", `portal:${user.email}`);
        log(`agent-custody portal: ${user.email} registered tenant ${tenant}`);
        void welcomeMail(user.email, profile.name!, t.id, t.logId);
        void notifyMail({ ...profile, email: user.email, tenant: t.id });
        return { status: 200, body: { tenant: t.id, logId: t.logId, plan: t.plan, token: minted.token, tokenHash: minted.tokenHash.slice(0, 12), welcome: sheet(t.id, t.logId), setup: setupFor(t.id, t.logId), exportCommand: exportCommand(t.id) } };
      };
      // `on` is the state the account must be in: true to sign in or turn MFA off, false to turn it on.
      // With MFA on, a recovery code works once in place of a code.
      const checkCode = async (id: string, code: unknown, on: boolean): Promise<Refusal | null> => {
        if (!mfaFailures.take(id)) return { status: 429, body: { error: "too many codes tried for this account; wait a few minutes" } };
        const m = await store.mfa(id);
        if (!m.secret || m.enabled !== on) return { status: 409, body: { error: on ? "MFA is not on for this account" : "start the MFA setup first" } };
        const given = String(code ?? "").trim();
        if (on && !/^[0-9]{6}$/.test(given)) return (await store.takeRecoveryCode(id, given)) ? null : { status: 401, body: { error: "that code is not valid, or was used already" } };
        const step = totpStep(Buffer.from(m.secret, "hex"), given);
        if (step === null || !(await store.takeMfaStep(id, step))) return { status: 401, body: { error: "that code is not valid, or was used already" } };
        if (!on) await store.enableMfa(id);
        return null;
      };
      if (req.method === "POST" && url.pathname === "/api/register") {
        const b = await jsonBody();
        const email = String(b.email ?? "").trim().toLowerCase();
        const password = String(b.password ?? "");
        if (!EMAIL.test(email)) return json(400, { error: "a valid email address is needed" });
        if (password.length < 10) return json(400, { error: "the password needs at least ten characters" });
        const oneStep = "tenant" in b || "company" in b || "name" in b;
        let parsed: { tenant: string; profile: Profile } | null = null;
        if (oneStep) {
          const p = await parseOnboarding(b);
          if ("status" in p) return json(p.status, p.body);
          parsed = p;
        }
        // throttled once the request is well formed: a mistyped form costs nothing, five real registrations from one address, then one every ten minutes
        if (!registrations.take(`reg:${addr}`)) return json(429, { error: "too many registrations from this address; try again later" });
        let user: PortalUser;
        try {
          user = await store.createUser(email, password);
        } catch (e) {
          return json(409, { error: e instanceof Error ? e.message : String(e) });
        }
        const cookie = { "set-cookie": setCookie(signSession(o.secret, user.id)) };
        if (!parsed) { log(`agent-custody portal: ${email} created an account`); void send(verificationMail(user)); return json(200, { email, tenant: null, emailVerified: false }, cookie); }
        const r = await onboard(user, parsed);
        void send(verificationMail(user));
        return json(r.status, r.body, cookie);
      }
      if (req.method === "GET" && url.pathname === "/verify-email") {
        const who = readSession(o.secret, url.searchParams.get("token") ?? undefined);
        if (!who?.startsWith("verify:")) return page(400, "Link not valid", "This verification link is not valid or has expired. Sign in and ask for a new one from the account page.");
        const u = await store.user(who.slice("verify:".length));
        if (!u) return page(400, "Link not valid", "This verification link belongs to no account.");
        // Opening the link proves nothing: an attacker may have registered the address, and its owner may click the link. Only the account's own session confirms it, through POST /api/verify-email.
        const token = url.searchParams.get("token")!;
        res.writeHead(200, { "content-type": "text/html; charset=utf-8", "cache-control": "no-store", "content-security-policy": "default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; connect-src 'self'" });
        return void res.end(`${resultPage("Confirm your address", `<p id="m" aria-live="polite">Confirming ${esc(u.email)}...</p>`)}<script>
fetch("/api/verify-email", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ token: ${JSON.stringify(token).replace(/</g, "\\u003c")} }) }).then(async (r) => {
  const b = await r.json().catch(() => ({}));
  const m = document.getElementById("m");
  if (r.ok) m.innerHTML = "Your address is confirmed. <a href='/'>Continue to your account</a>.";
  else if (r.status === 401) m.innerHTML = "Sign in to this account with its password first, then open the link again. <a href='/'>Sign in</a>.";
  else m.textContent = b.error || "The address was not confirmed.";
});
</script>`);
      }
      // ---- enterprise sign-in through the tenant's own identity provider, which only the operator sets ----
      const sso = /^\/auth\/sso(?:\/([a-z0-9-]+)(\/callback|\/saml|\/saml\/acs)?)?$/.exec(url.pathname);
      if (sso && req.method === (sso[2] === "/saml/acs" ? "POST" : "GET")) {
        const [, t, tail] = sso;
        if (!t) {
          const domain = (url.searchParams.get("email") ?? "").split("@")[1]?.trim().toLowerCase() ?? "";
          const found = domain ? await store.ssoByDomain(domain) : null;
          if (!found) return page(404, "No single sign-on", `No single sign-on is set up for ${esc(domain || "that address")}. <a href="/">Sign in another way</a>.`);
          res.writeHead(302, { location: `/auth/sso/${found.tenant}`, "cache-control": "no-store" });
          return void res.end();
        }
        const conf = await store.ssoOf(t);
        const oidcCookie = (v: string | null) => `custody_sso=${v ?? ""}; Path=/auth; HttpOnly; SameSite=Lax${o.trustProxy ? "; Secure" : ""}; Max-Age=${v ? 600 : 0}`;
        // the IdP posts to the ACS from another site, and only SameSite=None comes back with that post
        const samlCookie = (v: string | null) => `custody_saml=${v ?? ""}; Path=/auth/sso; HttpOnly; SameSite=None; Secure; Max-Age=${v ? 600 : 0}`;
        const flowCookie = conf?.protocol === "saml" ? samlCookie : oidcCookie;
        const refuse = (status: number, text: string) => page(status, "Single sign-on", esc(text), { "set-cookie": flowCookie(null) });
        if (!conf) return refuse(404, "No single sign-on is set up for that organisation.");
        const at = `${portalBase}auth/sso/${t}`;
        const sp = { spEntityId: `${at}/saml`, acsUrl: `${at}/saml/acs` };
        const sayFailed = (what: string, e: unknown) => {
          log(`agent-custody portal: ${what} for ${t} failed: ${e instanceof Error ? e.message : String(e)}`);
          return `${what} failed. Ask your administrator to check the identity provider settings.`;
        };
        if (tail === "/saml") {
          if (conf.protocol !== "saml") return refuse(404, "This organisation does not use SAML.");
          res.writeHead(200, { "content-type": "application/samlmetadata+xml", "cache-control": "no-store" });
          return void res.end(`<?xml version="1.0"?><EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="${esc(sp.spEntityId)}"><SPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol" WantAssertionsSigned="true"><NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress</NameIDFormat><AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="${esc(sp.acsUrl)}" index="0"/></SPSSODescriptor></EntityDescriptor>`);
        }
        const ssoFetch = o.ssoFetch ? { fetch: o.ssoFetch } : {};
        if (!tail) {
          try {
            if (conf.protocol === "oidc") {
              const { verifier, challenge } = pkce();
              const state = randomBytes(16).toString("hex");
              const nonce = randomBytes(16).toString("hex");
              const to = await oidcAuthorizeUrl(conf.config as OidcConfig, { redirectUri: `${at}/callback`, state, nonce, codeChallenge: challenge, ...ssoFetch });
              res.writeHead(302, { location: to, "set-cookie": oidcCookie(signSession(o.secret, `oidc:${t}:${state}:${verifier}:${nonce}`, 600_000)), "cache-control": "no-store" });
            } else {
              const { url: to, requestId } = await samlAuthorizeUrl(conf.config as SamlConfig, sp);
              res.writeHead(302, { location: to, "set-cookie": samlCookie(signSession(o.secret, `saml:${t}:${requestId}`, 600_000)), "cache-control": "no-store" });
            }
            return void res.end();
          } catch (e) {
            return refuse(502, sayFailed("Single sign-on start", e));
          }
        }
        let id: SsoIdentity;
        try {
          if (tail === "/callback" && conf.protocol === "oidc") {
            const [kind, flowTenant, state, verifier, nonce] = (readSession(o.secret, cookies.custody_sso) ?? "").split(":");
            const code = url.searchParams.get("code") ?? "";
            if (kind !== "oidc" || flowTenant !== t || !code || !state || state !== url.searchParams.get("state")) return refuse(400, "The sign-in did not start here, or took too long. Go back and try again.");
            id = await oidcExchange(conf.config as OidcConfig, { code, redirectUri: `${at}/callback`, codeVerifier: verifier!, nonce: nonce!, ...ssoFetch });
          } else if (tail === "/saml/acs" && conf.protocol === "saml") {
            const [kind, flowTenant, requestId] = (readSession(o.secret, cookies.custody_saml) ?? "").split(":");
            const samlResponse = new URLSearchParams(await rawBody()).get("SAMLResponse") ?? "";
            if (kind !== "saml" || flowTenant !== t || !samlResponse) return refuse(400, "The sign-in did not start here, or took too long. Go back and try again.");
            id = await samlValidate(conf.config as SamlConfig, { ...sp, samlResponse, requestId: requestId! });
          } else {
            return refuse(404, "Not found.");
          }
        } catch (e) {
          return refuse(401, sayFailed("Single sign-on", e));
        }
        let user: PortalUser;
        try {
          user = await store.findOrCreateSsoUser(conf, id);
        } catch (e) {
          if (e instanceof UnverifiedAccountError) return refuse(409, e.message);
          if (e instanceof SsoRefusedError) return refuse(403, e.message);
          throw e;
        }
        log(`agent-custody portal: ${id.email} signed in through single sign-on for ${t}`);
        return signedInPage(id.email, "/", [setCookie(signSession(o.secret, user.id, undefined, `sso:${t}`)), flowCookie(null)], "Signed in as");
      }
      // ---- sign in through a provider: the OAuth web flow, state in a short-lived signed cookie ----
      const provider = /^\/auth\/(github|google)(\/callback)?$/.exec(url.pathname);
      if (req.method === "GET" && provider && o.oauth?.[provider[1] as "github" | "google"]) {
        const name = provider[1] as "github" | "google";
        const conf = o.oauth[name]!;
        const redirectUri = `${portalBase}auth/${name}/callback`;
        const stateCookie = (value: string | null) => `custody_oauth=${value ?? ""}; Path=/auth; HttpOnly; SameSite=Lax${o.trustProxy ? "; Secure" : ""}; Max-Age=${value ? 600 : 0}`;
        if (!provider[2]) {
          // ?link=1 from a signed-in session links the provider to that account instead of signing in; the state says so
          const linking = url.searchParams.get("link") === "1";
          if (linking && !fresh(userId ? await store.user(userId) : null, claims)) return json(401, { error: "sign in first, then link a provider from the account page" });
          const state = signSession(o.secret, `oauth:${name}:${linking ? `link:${userId}:` : ""}${randomBytes(16).toString("hex")}`, 600_000);
          const authorize = name === "github"
            ? `https://github.com/login/oauth/authorize?${new URLSearchParams({ client_id: conf.clientId, redirect_uri: redirectUri, scope: "user:email", state })}`
            : `https://accounts.google.com/o/oauth2/v2/auth?${new URLSearchParams({ client_id: conf.clientId, redirect_uri: redirectUri, response_type: "code", scope: "openid email", state, prompt: "select_account" })}`;
          res.writeHead(302, { location: authorize, "set-cookie": stateCookie(state), "cache-control": "no-store" });
          return void res.end();
        }
        const state = url.searchParams.get("state") ?? "";
        const code = url.searchParams.get("code") ?? "";
        const expected = cookies.custody_oauth;
        const stateUser = readSession(o.secret, state);
        if (!code || !state || state !== expected || !stateUser?.startsWith(`oauth:${name}:`)) return json(400, { error: "the sign-in did not start here, or took too long; go back and try again" }, { "set-cookie": stateCookie(null) });
        const f = o.oauth.fetch ?? fetch;
        let subject = "";
        let email = "";
        try {
          if (name === "github") {
            const tok = (await (await f("https://github.com/login/oauth/access_token", { method: "POST", headers: { accept: "application/json", "content-type": "application/json" }, body: JSON.stringify({ client_id: conf.clientId, client_secret: conf.clientSecret, code, redirect_uri: redirectUri }), signal: AbortSignal.timeout(10_000) })).json()) as { access_token?: string; error?: string };
            if (!tok.access_token) throw new Error(tok.error ?? "no access token");
            const gh = { authorization: `Bearer ${tok.access_token}`, accept: "application/vnd.github+json", "user-agent": "agent-custody-portal" };
            const me = (await (await f("https://api.github.com/user", { headers: gh, signal: AbortSignal.timeout(10_000) })).json()) as { id?: number | string };
            const emails = (await (await f("https://api.github.com/user/emails", { headers: gh, signal: AbortSignal.timeout(10_000) })).json()) as { email: string; primary: boolean; verified: boolean }[];
            const primary = emails.find((e) => e.primary && e.verified) ?? emails.find((e) => e.verified);
            if (me.id === undefined || !primary) throw new Error("GitHub gave no verified email; add one to your GitHub account or use email and password");
            subject = String(me.id);
            email = primary.email.toLowerCase();
          } else {
            const tok = (await (await f("https://oauth2.googleapis.com/token", { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" }, body: new URLSearchParams({ client_id: conf.clientId, client_secret: conf.clientSecret, code, redirect_uri: redirectUri, grant_type: "authorization_code" }), signal: AbortSignal.timeout(10_000) })).json()) as { id_token?: string; error?: string };
            if (!tok.id_token) throw new Error(tok.error ?? "no id token");
            // the id token came straight from Google's token endpoint over TLS in this exchange, so its claims are read without a second signature check
            const claims = JSON.parse(Buffer.from(tok.id_token.split(".")[1] ?? "", "base64url").toString()) as { sub?: string; email?: string; email_verified?: boolean };
            if (!claims.sub || !claims.email || claims.email_verified !== true) throw new Error("Google gave no verified email");
            subject = claims.sub;
            email = claims.email.toLowerCase();
          }
        } catch (e) {
          log(`agent-custody portal: ${name} sign-in failed: ${e instanceof Error ? e.message : String(e)}`);
          return json(502, { error: `${name === "github" ? "GitHub" : "Google"} sign-in failed: ${e instanceof Error ? e.message : String(e)}` }, { "set-cookie": stateCookie(null) });
        }
        const linkTo = /^oauth:[a-z]+:link:([^:]+):/.exec(stateUser)?.[1];
        let user: PortalUser;
        if (linkTo) {
          // linking: the signed state records the session that started it (the Strict cookie does not come back from the provider), so the provider's email need not match; when it does, it also confirms the address
          const owner = fresh(await store.user(linkTo), readClaims(o.secret, state));
          if (!owner) return json(401, { error: "the account that started the link no longer exists" }, { "set-cookie": stateCookie(null) });
          await store.linkIdentity(name, subject, email, owner.id);
          if (email === owner.email) await store.markEmailVerified(owner.id);
          log(`agent-custody portal: ${owner.email} linked ${name}`);
          return page(200, "Linked", `${name === "github" ? "GitHub" : "Google"} is linked to ${esc(owner.email)}. <a href="/">Continue</a>.`, { "set-cookie": stateCookie(null) });
        }
        try {
          user = await store.findOrCreateOAuthUser(name, subject, email);
        } catch (e) {
          if (!(e instanceof UnverifiedAccountError)) throw e;
          log(`agent-custody portal: ${name} sign-in for ${email} refused: the password account has not verified its address`);
          return page(409, "Sign in with your password", `An account with the address ${esc(email)} already exists. <a href="/">Sign in with its password</a>, then link ${name === "github" ? "GitHub" : "Google"} from the account page.`, { "set-cookie": stateCookie(null) });
        }
        if (await enforcedFor(user.id)) return page(403, "Single sign-on required", `${esc(ENFORCED)}.`, { "set-cookie": stateCookie(null) });
        const mfa = (await store.mfa(user.id)).enabled;
        log(`agent-custody portal: ${email} signed in with ${name}${mfa ? ", MFA code needed" : ""}`);
        return signedInPage(email, mfa ? "/?mfa=1" : "/", [mfa ? mfaCookie(user.id) : setCookie(signSession(o.secret, user.id)), stateCookie(null)], mfa ? "One more step for" : "Signed in as");
      }
      if (req.method === "POST" && url.pathname === "/api/login") {
        if (!loginFailures.take(`login:${addr}`)) return json(429, { error: "too many attempts; wait a minute" });
        const b = await jsonBody();
        const user = await store.authenticate(String(b.email ?? "").trim().toLowerCase(), String(b.password ?? ""));
        if (!user) return json(401, { error: "email or password not recognised" });
        if (await enforcedFor(user.id)) return json(403, { error: ENFORCED });
        if ((await store.mfa(user.id)).enabled) return json(200, { mfa: true }, { "set-cookie": mfaCookie(user.id) });
        return json(200, { email: user.email }, { "set-cookie": setCookie(signSession(o.secret, user.id)) });
      }
      if (req.method === "POST" && url.pathname === "/api/login/mfa") {
        if (!loginFailures.take(`login:${addr}`)) return json(429, { error: "too many attempts; wait a minute" });
        const b = await jsonBody();
        const half_ = readClaims(o.secret, cookies.custody_mfa);
        const half = half_?.u.startsWith("mfa:") ? fresh(await store.user(half_.u.slice(4)), half_) : null;
        if (!half) return json(401, { error: "the password step expired; sign in again" });
        const refused = await checkCode(half.id, b.code, true);
        if (refused) return json(refused.status, refused.body);
        return json(200, { email: half.email }, { "set-cookie": [setCookie(signSession(o.secret, half.id)), mfaCookie(null)] });
      }
      // ---- password reset by mail: the same answer for every address, and the token proves the mailbox ----
      if (req.method === "POST" && url.pathname === "/api/password/forgot") {
        const email = String((await jsonBody()).email ?? "").trim().toLowerCase();
        if (!o.mail) return json(503, { error: "mail is not configured on this portal" });
        if (!EMAIL.test(email)) return json(400, { error: "a valid email address is needed" });
        if (!resetsByClient.take(`reset:${addr}`)) return json(429, { error: "too many reset requests from this address; try again later" });
        // the lookup runs after the answer, so the time to answer does not tell whether the address has an account
        if (resetsByEmail.take(email)) void (async () => {
          const u = await store.userByEmail(email);
          // a member of a tenant that enforces single sign-on gets no password
          if (!u || (await enforcedFor(u.id))) return;
          await send(resetMail(u.email, await store.createPasswordReset(u.id)));
          log(`agent-custody portal: ${u.email} asked for a password reset`);
        })().catch((e) => log(`agent-custody portal: a password reset failed: ${e instanceof Error ? e.message : String(e)}`));
        return json(200, { ok: true });
      }
      if (req.method === "GET" && url.pathname === "/reset-password") {
        const token = url.searchParams.get("token") ?? "";
        res.writeHead(200, { "content-type": "text/html; charset=utf-8", "cache-control": "no-store", "referrer-policy": "no-referrer", "content-security-policy": "default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; connect-src 'self'; form-action 'none'; base-uri 'none'" });
        return void res.end(`${resultPage("Set a new password", `<style>form { display: grid; gap: .75rem; margin-top: 1rem; } [hidden] { display: none; } label { display: grid; gap: .35rem; font-weight: 600; font-size: .9rem; } label span { font-weight: 400; color: var(--ink2); font-size: .82rem; } input { font: inherit; padding: .6rem .8rem; border: 1px solid var(--line); border-radius: 8px; background: var(--bg); color: var(--ink); } button { font: inherit; font-weight: 600; padding: .6rem .9rem; border-radius: 8px; border: 1px solid var(--accent); background: var(--accent); color: #fff; cursor: pointer; }</style>
<form id="f"><label>New password<input id="pw" type="password" autocomplete="new-password" minlength="10" required><span>At least ten characters.</span></label><button type="submit">Set the password</button></form><p id="m" aria-live="polite"></p>`)}<script>
document.getElementById("f").onsubmit = async (e) => {
  e.preventDefault();
  const m = document.getElementById("m");
  const r = await fetch("/api/password/reset", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ token: ${JSON.stringify(token).replace(/</g, "\\u003c")}, password: document.getElementById("pw").value }) });
  const b = await r.json().catch(() => ({}));
  if (r.ok) { document.getElementById("f").hidden = true; m.innerHTML = "Your password is set. Other sessions of this account are signed out. <a href='/'>Sign in</a>."; }
  else m.textContent = b.error || "The password was not set.";
};
</script>`);
      }
      if (req.method === "POST" && url.pathname === "/api/password/reset") {
        const b = await jsonBody();
        const password = String(b.password ?? "");
        // checked before the token is used, so a short password does not spend the link
        if (password.length < 10) return json(400, { error: "the password needs at least ten characters" });
        const id = await store.takePasswordReset(String(b.token ?? ""));
        const u = id ? await store.user(id) : null;
        if (!u) return json(400, { error: "this reset link is not valid, was used already, or is older than one hour; ask for a new one" });
        if (await enforcedFor(u.id)) return json(403, { error: ENFORCED });
        await store.setPassword(u.id, password);
        // The link proves the mailbox, and the new password replaces any password set before that proof. A provider
        // linked before the address was proved was linked by whoever held that password, so it goes.
        if (!u.emailVerifiedAt) {
          await store.unlinkIdentities(u.id);
          await store.markEmailVerified(u.id);
        }
        log(`agent-custody portal: ${u.email} reset their password`);
        // no session here: the user signs in with the new password, and two-step sign-in still applies
        return json(200, { ok: true });
      }
      if (req.method === "POST" && url.pathname === "/api/logout") return json(200, { ok: true }, { "set-cookie": setCookie(null) });

      // ---- everything below needs a session ----
      if (!url.pathname.startsWith("/api/")) return json(404, { error: "not found" });
      const user = fresh(userId ? await store.user(userId) : null, claims);
      if (!user) return json(401, { error: "sign in first" });
      if (req.method !== "GET" && !(req.headers["content-type"] ?? "").startsWith("application/json")) return json(415, { error: "expected a JSON body" });
      const tenantId = await store.tenantOf(user.id);
      const ssoConf = tenantId ? await store.ssoOf(tenantId) : null;
      if (ssoConf?.enforced && via !== `sso:${tenantId}`) return json(401, { error: ENFORCED });
      const account = async () => { const m = await store.mfa(user.id); return { emailVerified: !!user.emailVerifiedAt, identities: await store.identities(user.id), providers: (["github", "google"] as const).filter((p) => !!o.oauth?.[p]), mail: !!o.mail, mfa: m.enabled, recoveryCodes: m.recoveryCodes }; };
      if (req.method === "POST" && url.pathname === "/api/verify-email") {
        const who = readSession(o.secret, String((await jsonBody()).token ?? ""));
        if (!who?.startsWith("verify:")) return json(400, { error: "this verification link is not valid or has expired" });
        if (who.slice("verify:".length) !== user.id) return json(403, { error: "this link belongs to another account; sign in to the account it was sent for" });
        await store.markEmailVerified(user.id);
        log(`agent-custody portal: ${user.email} verified their address`);
        return json(200, { ok: true, emailVerified: true });
      }
      if (req.method === "POST" && url.pathname === "/api/verify-email/resend") {
        if (user.emailVerifiedAt) return json(200, { ok: true, emailVerified: true });
        if (!o.mail) return json(503, { error: "mail is not configured on this portal" });
        void send(verificationMail(user));
        return json(200, { ok: true, emailVerified: false });
      }
      if (req.method === "GET" && url.pathname === "/api/me" && !tenantId) return json(200, { email: user.email, tenant: null, profile: await store.profile(user.id), invites: await store.invitesFor(user.email), billing: !!o.stripe, ...(await account()) });
      if (req.method === "POST" && url.pathname === "/api/mfa/setup") {
        await jsonBody();
        const secret = randomBytes(20);
        if (!(await store.setMfaSecret(user.id, secret.toString("hex")))) return json(409, { error: "MFA is on already; turn it off first" });
        const b32 = base32(secret);
        const uri = `otpauth://totp/agent-custody:${encodeURIComponent(user.email)}?secret=${b32}&issuer=agent-custody`;
        return json(200, { secret: b32, uri, qr: qrSvg(uri) });
      }
      if (req.method === "POST" && (url.pathname === "/api/mfa/enable" || url.pathname === "/api/mfa/disable")) {
        const on = url.pathname.endsWith("/disable");
        const refused = await checkCode(user.id, (await jsonBody()).code, on);
        if (refused) return json(refused.status, refused.body);
        if (on) await store.resetMfa(user.email);
        log(`agent-custody portal: ${user.email} turned MFA ${on ? "off" : "on"}`);
        return json(200, { mfa: !on, ...(on ? {} : { recoveryCodes: await store.newRecoveryCodes(user.id) }) });
      }
      // a code is needed, so a stolen session cannot take the codes
      if (req.method === "POST" && url.pathname === "/api/mfa/recovery") {
        const refused = await checkCode(user.id, (await jsonBody()).code, true);
        if (refused) return json(refused.status, refused.body);
        log(`agent-custody portal: ${user.email} made new recovery codes`);
        return json(200, { recoveryCodes: await store.newRecoveryCodes(user.id) });
      }
      if (req.method === "POST" && url.pathname === "/api/password/change") {
        const b = await jsonBody();
        const password = String(b.password ?? "");
        if (ssoConf?.enforced) return json(409, { error: "this tenant signs in through its identity provider; its members have no password here" });
        if (password.length < 10) return json(400, { error: "the new password needs at least ten characters" });
        if (!loginFailures.take(`password:${user.id}`)) return json(429, { error: "too many attempts; wait a minute" });
        if (!(await store.authenticate(user.email, String(b.current ?? "")))) return json(401, { error: "the current password is not correct" });
        await store.setPassword(user.id, password);
        log(`agent-custody portal: ${user.email} changed their password`);
        // this browser stays signed in; every other session ends
        return json(200, { ok: true }, { "set-cookie": setCookie(signSession(o.secret, user.id, undefined, via ?? undefined)) });
      }
      // The address must be verified: otherwise anyone who registers the invited address with a password gets in.
      if (req.method === "POST" && url.pathname === "/api/invites/accept") {
        const tenant = String((await jsonBody()).tenant ?? "");
        if (tenantId) return json(409, { error: "this account has a tenant already; one tenant per account" });
        if (!user.emailVerifiedAt) return json(403, { error: "verify your email address first, then accept the invite" });
        if ((await store.ssoOf(tenant))?.enforced) return json(409, { error: "members of this tenant join through its identity provider" });
        const role = await store.takeInvite(tenant, user.email);
        if (!role) return json(404, { error: "no invite to this address for that tenant, or it is older than seven days" });
        await store.addMember(user.id, tenant, role);
        log(`agent-custody portal: ${user.email} joined tenant ${tenant} as ${role}`);
        return json(200, { tenant, role });
      }
      if (req.method === "POST" && url.pathname === "/api/onboard") {
        const p = await parseOnboarding(await jsonBody());
        if ("status" in p) return json(p.status, p.body);
        const r = await onboard(user, p);
        return json(r.status, r.body);
      }
      if (!tenantId) return json(409, { error: "this account has no tenant yet; finish setting it up" });
      const tenant = await o.tenancy.tenant(tenantId);
      if (!tenant) return json(409, { error: "the tenant no longer exists" });

      // The lowest role a route needs; an unlisted write needs admin.
      const myRole = (await store.roleOf(user.id, tenantId))!;
      const needs: [RegExp, Role][] = [[/^\/api\/(checkout|billing-portal)$/, "owner"], [/^\/api\/policies(\/|$)/, "reviewer"]];
      const least: Role = req.method === "GET" ? "readonly" : needs.find(([re]) => re.test(url.pathname))?.[1] ?? "admin";
      if (ROLES.indexOf(myRole) < ROLES.indexOf(least)) return json(403, { error: `this needs the ${least} role or higher; you are ${myRole}` });

      if (req.method === "GET" && url.pathname === "/api/me") {
        const q = await o.tenancy.quota(tenantId);
        return json(200, { email: user.email, tenant: tenantId, role: myRole, logId: tenant.logId, plan: q.plan, used: q.used, quota: q.quota, disabled: !!tenant.disabledAt, billing: !!o.stripe, sso: ssoConf && { protocol: ssoConf.protocol, enforced: ssoConf.enforced }, ...(await account()) });
      }
      if (req.method === "GET" && url.pathname === "/api/overview") {
        const q = await o.tenancy.quota(tenantId);
        const backend = await o.tenancy.log(tenantId);
        const size = await backend.size();
        const latest = await heads.latest(tenantId);
        const months: { month: string; appends: number }[] = [];
        for (let i = 5; i >= 0; i--) {
          const d = new Date();
          const month = new Date(Date.UTC(d.getUTCFullYear(), d.getUTCMonth() - i, 1)).toISOString().slice(0, 7);
          const u = await o.tenancy.usage(month);
          months.push({ month, appends: u.tenants.find((t) => t.id === tenantId)?.appends ?? 0 });
        }
        const keys = (await o.tenancy.listTokens(tenantId)).map((k) => ({ label: k.label, hash: k.tokenHash.slice(0, 12), createdAt: k.createdAt, revokedAt: k.revokedAt }));
        const audit = await o.tenancy.audit({ tenant: tenantId, limit: 50 });
        const billing = await store.billing(tenantId);
        return json(200, { tenant: tenantId, logId: tenant.logId, plan: q.plan, used: q.used, quota: q.quota, treeSize: size, rootHash: size ? await backend.root(size) : null, latestCheckpoint: latest ? { treeSize: latest.treeSize, signedAt: latest.signedAt } : null, months, keys, audit, billing: billing ? { status: billing.status } : null, urls: { log: `${base}t/${tenantId}/`, keys: `${base}.well-known/agent-custody-log.json`, checkpoints: o.checkpointsUrl ? `${o.checkpointsUrl.replace(/\/?$/, "/")}${tenantId}/latest.json` : null }, exportCommand: exportCommand(tenantId), welcome: sheet(tenantId, tenant.logId), setup: setupFor(tenantId, tenant.logId), stripe: !!o.stripe });
      }
      if (req.method === "GET" && url.pathname === "/api/members") return json(200, { members: await store.members(tenantId), invites: await store.invitesOf(tenantId) });
      const ownerOnly = (...roles: string[]) => myRole !== "owner" && roles.includes("owner");
      const OWNER_ONLY = { error: "this needs the owner role: only an owner changes an owner or grants owner" };
      if (req.method === "POST" && url.pathname === "/api/members") {
        if (ssoConf?.enforced) return json(409, { error: "this tenant signs in through its identity provider: members join through it, not by invite" });
        const b = await jsonBody();
        const email = String(b.email ?? "").trim().toLowerCase();
        const role = String(b.role ?? "");
        if (!EMAIL.test(email)) return json(400, { error: "a valid email address is needed" });
        if (!(ROLES as readonly string[]).includes(role)) return json(400, { error: `role must be one of ${ROLES.join(", ")}` });
        if (ownerOnly(role, ...(await store.invitesOf(tenantId)).filter((i) => i.email === email).map((i) => i.role))) return json(403, OWNER_ONLY);
        await store.invite(tenantId, email, role as Role, user.email);
        log(`agent-custody portal: ${user.email} invited ${email} to tenant ${tenantId} as ${role}`);
        void send({ to: email, subject: `You are invited to ${tenantId} on agent-custody`, text: [`${user.email} invited you to the agent-custody tenant "${tenantId}" as ${role}.`, "", `Sign up or sign in with this address at ${portalBase}, verify the address, and accept the invite. The invite is good for seven days.`, "", "agent-custody"].join("\n") });
        return json(200, { invited: email, role });
      }
      if (req.method === "POST" && url.pathname === "/api/invites/remove") {
        const email = String((await jsonBody()).email ?? "").trim().toLowerCase();
        const invited = (await store.invitesOf(tenantId)).find((i) => i.email === email);
        if (invited && ownerOnly(invited.role)) return json(403, OWNER_ONLY);
        log(`agent-custody portal: ${user.email} cancelled the invite of ${email} to tenant ${tenantId}`);
        return json(200, { removed: await store.removeInvite(tenantId, email) });
      }
      const member = /^\/api\/members\/([0-9a-f-]{36})\/(role|remove)$/.exec(url.pathname);
      if (req.method === "POST" && member) {
        const b = await jsonBody();
        const target = await store.roleOf(member[1]!, tenantId);
        if (!target) return json(404, { error: "no such member" });
        if (member[2] === "role") {
          const role = String(b.role ?? "");
          if (!(ROLES as readonly string[]).includes(role)) return json(400, { error: `role must be one of ${ROLES.join(", ")}` });
          if (ownerOnly(target, role)) return json(403, OWNER_ONLY);
          if (!(await store.setRole(tenantId, member[1]!, role as Role))) return json(409, { error: "the last owner cannot be demoted; make another member an owner first" });
          log(`agent-custody portal: ${user.email} made ${member[1]} ${role} in tenant ${tenantId}`);
          return json(200, { role });
        }
        if (ownerOnly(target)) return json(403, OWNER_ONLY);
        if (!(await store.removeMember(tenantId, member[1]!))) return json(409, { error: "the last owner cannot be removed; make another member an owner first" });
        log(`agent-custody portal: ${user.email} removed ${member[1]} from tenant ${tenantId}`);
        return json(200, { removed: true });
      }
      if (req.method === "GET" && url.pathname === "/api/keys") {
        return json(200, { keys: (await o.tenancy.listTokens(tenantId)).map((k) => ({ label: k.label, hash: k.tokenHash.slice(0, 12), createdAt: k.createdAt, revokedAt: k.revokedAt })) });
      }
      if (req.method === "POST" && url.pathname === "/api/keys") {
        const b = await jsonBody();
        const label = String(b.label ?? "").trim().slice(0, 64) || "key";
        const minted = await o.tenancy.addToken(tenantId, label, `portal:${user.email}`);
        return json(200, { token: minted.token, tokenHash: minted.tokenHash.slice(0, 12), label });
      }
      const revoke = /^\/api\/keys\/([0-9a-f]{8,64})\/revoke$/.exec(url.pathname);
      if (req.method === "POST" && revoke) {
        await jsonBody();
        return json(200, { revoked: await o.tenancy.revokeToken(tenantId, revoke[1]!, `portal:${user.email}`) });
      }
      // Policies: named versions the tenant publishes so a receipt's policyDigest reads as a name. The gateway never
      // reads these; enforcement stays on the tenant's machines.
      if (req.method === "GET" && url.pathname === "/api/policies") {
        const digest = url.searchParams.get("digest");
        if (digest !== null) {
          if (!/^[0-9a-f]{64}$/i.test(digest)) return json(400, { error: "a policy digest is 64 hexadecimal characters, the policyDigest a receipt carries" });
          return json(200, { match: await o.tenancy.policyByDigest(tenantId, digest) });
        }
        return json(200, { policies: await o.tenancy.listPolicies(tenantId) });
      }
      if (req.method === "POST" && url.pathname === "/api/policies") {
        const b = await jsonBody();
        const name = String(b.name ?? "").trim().slice(0, 80);
        const text = typeof b.text === "string" ? b.text : "";
        if (!name) return json(400, { error: "a name for this version is needed, for example refunds-v3 or 2026-10-01" });
        if (!text.trim()) return json(400, { error: "the policy text is empty" });
        if (text.length > 256_000) return json(400, { error: "a policy is at most 256 KB" });
        try {
          return json(200, { policy: await o.tenancy.addPolicy(tenantId, name, text, `portal:${user.email}`) });
        } catch (e) {
          return json(409, { error: e instanceof Error ? e.message : String(e) });
        }
      }
      const pol = /^\/api\/policies\/(pol_[0-9a-f]{16})(\/remove)?$/.exec(url.pathname);
      if (req.method === "GET" && pol && !pol[2]) {
        const p = await o.tenancy.policy(tenantId, pol[1]!);
        return p ? json(200, { policy: p }) : json(404, { error: "no such policy version" });
      }
      if (req.method === "POST" && pol && pol[2]) {
        await jsonBody();
        return json(200, { removed: await o.tenancy.removePolicy(tenantId, pol[1]!, `portal:${user.email}`) });
      }
      if (req.method === "POST" && url.pathname === "/api/checkout") {
        if (!o.stripe) return json(503, { error: "billing is not configured on this portal yet; email us and we move the plan by hand" });
        await jsonBody();
        if (tenant.plan !== "free") return json(409, { error: `this tenant is already on the ${tenant.plan} plan` });
        const portalUrl = (o.portalUrl ?? "http://localhost/").replace(/\/?$/, "/");
        const session = await stripeRequest(o.stripe, "checkout/sessions", { mode: "subscription", "line_items[0][price]": o.stripe.priceTeam, "line_items[0][quantity]": "1", client_reference_id: tenantId, customer_email: user.email, success_url: `${portalUrl}?upgraded=1`, cancel_url: `${portalUrl}?cancelled=1`, "metadata[tenant]": tenantId });
        return json(200, { url: String(session.url) });
      }
      if (req.method === "POST" && url.pathname === "/api/billing-portal") {
        if (!o.stripe) return json(503, { error: "billing is not configured" });
        await jsonBody();
        const b = await store.billing(tenantId);
        if (!b?.customerId) return json(409, { error: "no billing record for this tenant" });
        const session = await stripeRequest(o.stripe, "billing_portal/sessions", { customer: b.customerId, return_url: (o.portalUrl ?? "http://localhost/").replace(/\/?$/, "/") });
        return json(200, { url: String(session.url) });
      }
      return json(404, { error: "not found" });
    } catch (e) {
      if (e instanceof ClientError) {
        if (!res.headersSent) json(e.status, { error: e.message });
        return;
      }
      // the detail can name a table, a query, or another service: it goes to the operator, not to the browser
      log(`agent-custody portal: ${req.method} ${url.pathname} failed: ${e instanceof Error ? (e.stack ?? e.message) : String(e)}`);
      if (!res.headersSent) json(500, { error: "internal error" });
      else res.end();
    }
  };
}

export function servePortal(o: PortalOptions, opts: { port: number; host?: string }): Promise<RunningPortal> {
  const host = opts.host ?? "127.0.0.1";
  const handler = portalHandler(o);
  const server: HttpServer = createServer((req, res) => void handler(req, res));
  return new Promise((resolve) => {
    server.listen(opts.port, host, () => {
      const { port } = server.address() as AddressInfo;
      resolve({ url: `http://${host}:${port}/`, close: () => new Promise((r) => { server.closeAllConnections?.(); server.close(() => r()); }) });
    });
  });
}

// ---- the page: one file, no framework, no outside requests ----
const FAVICON = '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64"><rect width="64" height="64" rx="14" fill="#b45309"/><path d="M19 11H45V45L41.75 48 38.5 45 35.25 48 32 45 28.75 48 25.5 45 22.25 48 19 45Z" fill="#fff"/><path d="M25 20h14M25 27h14" stroke="#b45309" stroke-width="2.6" stroke-linecap="round"/><path d="M25 37.5l5 4.5 9.5-10" fill="none" stroke="#b45309" stroke-width="3.4" stroke-linecap="round" stroke-linejoin="round"/></svg>';

const MARK = '<svg class="mark" viewBox="0 0 64 64" aria-hidden="true"><rect class="tile" width="64" height="64" rx="14"/><path d="M19 11H45V45L41.75 48 38.5 45 35.25 48 32 45 28.75 48 25.5 45 22.25 48 19 45Z" fill="#fff"/><path class="ink" d="M25 20h14M25 27h14" stroke-width="2.6" stroke-linecap="round"/><path class="ink" d="M25 37.5l5 4.5 9.5-10" fill="none" stroke-width="3.4" stroke-linecap="round" stroke-linejoin="round"/></svg>';

// The small pages outside the app (errors, results, the address check) share the brand without the app's script.
const RESULT_STYLE = `<style>
${DESIGN_CSS}
  body { min-height: 100vh; display: grid; place-items: center; padding: 1.5rem .75rem; font-size: var(--text-md); line-height: 1.6; background-color: var(--bg); background-image: radial-gradient(56rem 26rem at 50% -8rem, var(--accent-bg), transparent 72%), radial-gradient(circle at 1px 1px, color-mix(in srgb, var(--ink2) 20%, transparent) 1px, transparent 0); background-size: 100% 100%, 22px 22px; background-repeat: no-repeat, repeat; }
  main { position: relative; width: 100%; max-width: 27rem; padding: 2rem 2.25rem; background: var(--panel); border: 1px solid var(--line); border-radius: var(--radius-md); box-shadow: var(--shadow); }
  .brand { display: inline-flex; align-items: center; gap: .55rem; margin: 0 0 1.25rem; color: var(--ink); font-weight: 700; text-decoration: none; }
  .mark { width: 28px; height: 28px; display: block; } .mark .tile { fill: var(--accent); } .mark .ink { stroke: var(--accent); }
  h1 { margin: 0 0 .5rem; }
  p { margin: 0; color: var(--ink2); overflow-wrap: anywhere; }
  a { font-weight: 600; }
  @media (max-width: 30rem) { main { padding: 1.5rem 1.25rem; } }
</style>`;
const resultPage = (title: string, body: string, head = "") =>
  `<!doctype html><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">${head}<title>${title}</title>${RESULT_STYLE}<main><a class="brand" href="/">${MARK}agent-custody</a><h1>${title}</h1>${body}</main>`;

// the website's one nav list, on the dashboard's own host
const DASHBOARD_NAV = SITE_NAV.map((l) => `<a href="${siteUrl(l.link)}" target="_blank" rel="noopener">${l.text}</a>`).join("");

const PORTAL_PAGE = `<!doctype html>
<html lang="en">
<meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>agent-custody</title>
<link rel="icon" href="/favicon.svg" type="image/svg+xml">
<script>(() => { try { const t = localStorage.getItem("agent-custody-theme"); if (t === "dark" || t === "light") document.documentElement.dataset.theme = t; } catch {} })();</script>
<style>
${DESIGN_CSS}
  :root { --field: var(--line-strong); --lift: 0 1px 2px rgb(28 25 23 / .04); }
  .top { display: flex; align-items: center; gap: 1rem; padding: .7rem 1.25rem; border-bottom: 1px solid var(--line); background: var(--panel); }
  .brand { font-weight: 700; display: inline-flex; align-items: center; gap: .5rem; color: var(--ink); text-decoration: none; } .brand svg { width: 20px; height: 20px; display: block; } .brand rect { fill: var(--accent); }
  .top .links { margin-left: auto; display: flex; gap: .9rem; font-size: .9rem; } .top .links a { color: var(--accent); text-decoration: none; }
  #themeToggle[aria-pressed="true"] .moon, #themeToggle[aria-pressed="false"] .sun { display: none; }
  .pill { display: inline-block; padding: .05rem .55rem; border-radius: var(--radius-full); font: 600 var(--text-xs)/1.6 var(--font); background: var(--accent-bg); color: var(--accent); }
  .notice { padding: .6rem 1.25rem; font-size: .9rem; color: var(--ink); background: var(--accent-bg); border-bottom: 1px solid var(--line); } .notice a, .notice button { margin-left: .6rem; } .notice button { font: inherit; background: none; border: 1px solid var(--line); border-radius: var(--radius-sm); min-height: 0; padding: .1rem .5rem; color: var(--ink); font-weight: 600; cursor: pointer; }
  .notice button:hover { background: var(--panel); border-color: var(--line); }
  .layout { display: grid; grid-template-columns: 15rem 1fr; min-height: calc(100vh - 3.3rem); }
  nav { border-right: 1px solid var(--line); background: var(--panel); padding: 1rem 0; }
  nav .group { font: 600 var(--text-xs)/1.4 var(--font); color: var(--ink3); padding: 1rem 1.25rem .35rem; }
  nav a { display: flex; justify-content: space-between; gap: .5rem; padding: .45rem 1.25rem; color: var(--ink); text-decoration: none; border-left: 3px solid transparent; }
  nav a:hover { background: var(--bg); } nav a.on { border-left-color: var(--accent); background: var(--accent-bg); font-weight: 600; }
  nav a span.n { color: var(--ink2); font-size: var(--text-xs); font-variant-numeric: tabular-nums; }
  .navbtn { display: none; } .userbtn { min-height: 2.25rem; }
  #userMenu { position: fixed; inset: auto; margin: 0; min-width: 14rem; max-width: calc(100vw - 1rem); padding: var(--space-2); border: 1px solid var(--line); border-radius: var(--radius-md); background: var(--panel); color: var(--ink); box-shadow: var(--shadow); }
  #userMenu:popover-open { display: grid; gap: var(--space-1); }
  #userMenu .who { padding: var(--space-2) var(--space-3); color: var(--ink2); font-size: var(--text-sm); overflow-wrap: anywhere; }
  #userMenu a { padding: var(--space-2) var(--space-3); border-radius: var(--radius-sm); color: var(--ink); font-size: var(--text-sm); text-decoration: none; } #userMenu a:hover { background: var(--soft); }
  #userMenu button { width: 100%; justify-content: flex-start; gap: var(--space-3); padding: 0 var(--space-3); color: var(--ink); }
  @media (max-width: 48rem) { .navbtn { display: inline-flex; } nav { position: fixed; z-index: 10; inset: 0 auto 0 0; width: min(18rem, 85vw); overflow-y: auto; visibility: hidden; transform: translateX(-100%); } nav.open { visibility: visible; transform: none; box-shadow: 0 0 0 100vmax rgb(12 10 9 / .5); } }
  @media (max-width: 48rem) and (prefers-reduced-motion: no-preference) { nav { transition: transform .2s, visibility 0s .2s; } nav.open { transition: transform .2s, visibility 0s; } }
  main { padding: 2rem 2rem 3rem; max-width: 72rem; min-width: 0; }
  h1 { margin: 0 0 1rem; } h2 { font-size: var(--text-md); margin: 1.5rem 0 .6rem; }
  .cards { display: grid; grid-template-columns: repeat(auto-fit, minmax(13rem, 1fr)); gap: .9rem; }
  .card { box-shadow: var(--lift); padding: 1rem 1.1rem; }
  .card:is(.ok, .warn, .bad) .k::before { content: ""; display: inline-block; width: .5rem; height: .5rem; margin-right: .45rem; border-radius: var(--radius-full); background: var(--ok); vertical-align: .05em; }
  .card.warn .k::before { background: var(--warn); } .card.bad .k::before { background: var(--bad); }
  .card .k { font-weight: 500; color: var(--ink2); }
  .card .v { font-size: var(--text-2xl); font-weight: 700; margin: .2rem 0 0; font-variant-numeric: tabular-nums; }
  .card .s { color: var(--ink2); font-size: .88rem; }
  .panel { padding: 1rem 1.25rem; margin-top: .9rem; box-shadow: var(--lift); overflow-x: auto; } .panel > h2:first-child { margin-top: 0; }
  table { border-collapse: collapse; width: 100%; font-size: .92rem; }
  th, td { text-align: left; padding: .55rem .75rem .55rem 0; border-bottom: 1px solid var(--line); vertical-align: middle; } tbody tr:last-child > * { border-bottom: 0; }
  td button:not(.link) { min-height: 2rem; padding: 0 .7rem; font-size: var(--text-xs); } td select { min-height: 2rem; }
  #audit td:nth-child(-n+3) { white-space: nowrap; } #audit td:last-child { min-width: 16rem; overflow-wrap: anywhere; font-size: .86rem; }
  th { font-size: var(--text-xs); font-weight: 600; color: var(--ink2); } th::first-letter { text-transform: uppercase; }
  code, pre, .mono { font-size: .86em; }
  pre { background: var(--bg); border: 1px solid var(--line); border-radius: var(--radius-sm); padding: .8rem .9rem; overflow-x: auto; white-space: pre-wrap; }
  .bars { display: grid; grid-template-columns: repeat(6, 1fr); gap: .6rem; align-items: end; height: 9rem; }
  .bar { display: flex; flex-direction: column; justify-content: flex-end; align-items: center; height: 100%; font-size: .75rem; color: var(--ink2); }
  .bar i { display: block; width: 70%; max-width: 4rem; background: var(--accent); border-radius: var(--radius-sm) var(--radius-sm) 0 0; min-height: 2px; }
  .bar b { font-weight: 400; font-variant-numeric: tabular-nums; margin-top: .3rem; }
  label { display: grid; gap: .25rem; font-size: .85rem; color: var(--ink2); margin: 0 0 .8rem; }
  label .opt { font-size: var(--text-xs); margin-left: .3rem; } label .hint { font-size: .8rem; line-height: 1.45; } label .hint code { font-family: var(--mono); font-size: .9em; }
  textarea { font: .86rem/1.5 var(--mono); padding: .5rem .6rem; width: 100%; }
  input { font: inherit; padding: .5rem .6rem; }
  input, textarea { border: 1px solid var(--field); border-radius: var(--radius-sm); background: var(--bg); color: var(--ink); transition: border-color .15s, box-shadow .15s; }
  input::placeholder, textarea::placeholder { color: var(--ink2); opacity: .8; }
  input:focus, select:focus, textarea:focus { outline: 2px solid transparent; border-color: var(--accent); box-shadow: 0 0 0 3px color-mix(in srgb, var(--accent) 30%, transparent); }
  button.link { background: none; border: 0; padding: 0; color: var(--accent); font: inherit; text-decoration: underline; text-underline-offset: 3px; cursor: pointer; }
  body:has(> .auth:not([hidden])) { min-height: 100vh; background-color: var(--bg); background-image: radial-gradient(56rem 26rem at 50% -8rem, var(--accent-bg), transparent 72%), radial-gradient(circle at 1px 1px, color-mix(in srgb, var(--ink2) 20%, transparent) 1px, transparent 0); background-size: 100% 100%, 22px 22px; background-repeat: no-repeat, repeat; }
  .auth { --pad: 2.25rem; position: relative; max-width: 27rem; margin: 3.5rem auto 4rem; padding: var(--pad) var(--pad) 1.75rem; background: var(--panel); border: 1px solid var(--line); border-radius: var(--radius-md); box-shadow: var(--shadow); }
  #onboard { max-width: 31rem; } .auth.wide { max-width: 44rem; }
  .auth.split { padding: 0; } .auth.split > .pane { padding: var(--pad) var(--pad) 1.75rem; } .pitch { display: none; }
  .pitch .eyebrow { color: #f59e0b; }
  .pitch h2 { margin: 0 0 1rem; font: 700 var(--text-2xl)/1.15 var(--font); letter-spacing: -.025em; color: #fafaf9; }
  .pitch > p { margin: 0 0 2rem; max-width: 30rem; color: #a8a29e; }
  .flow { list-style: none; counter-reset: flow; display: grid; gap: 1.1rem; margin: 0; padding: 0; }
  .flow li { counter-increment: flow; display: grid; grid-template-columns: 2rem 1fr; gap: .1rem .85rem; }
  .flow li::before { content: counter(flow); grid-row: span 2; display: grid; place-items: center; width: 2rem; height: 2rem; border: 1px solid rgb(255 255 255 / .2); border-radius: var(--radius-full); color: #a8a29e; font: 700 var(--text-xs) var(--font); }
  .flow li.now::before { background: #f59e0b; border-color: #f59e0b; color: #1c1917; }
  .flow b { color: #fafaf9; font-weight: 600; } .flow span { color: #a8a29e; font-size: var(--text-sm); }
  @media (min-width: 60rem) {
    .auth.split { display: grid; grid-template-columns: minmax(0, 1fr) 27rem; max-width: 64rem; overflow: hidden; }
    #onboard.split { grid-template-columns: minmax(0, 1fr) 31rem; max-width: 68rem; }
    .pitch { display: flex; flex-direction: column; justify-content: center; padding: 3rem; background: radial-gradient(circle at 1px 1px, rgb(255 255 255 / .07) 1px, transparent 0) 0 0 / 22px 22px, linear-gradient(160deg, #292524, #0c0a09); }
    #onboard .pitch { justify-content: flex-start; padding-top: 4.5rem; }
    .split .fine { border-radius: 0; }
    .auth.wide { display: grid; grid-template-columns: 21rem minmax(0, 1fr); gap: 0 2.5rem; align-items: start; max-width: 72rem; }
    .wide .side { position: sticky; top: 1.5rem; } .wide #firstSetup > .step:first-child { border-top: 0; padding-top: 0; }
  }
  .auth .mark { display: block; width: 40px; height: 40px; margin: 0 0 1rem; } .mark .tile { fill: var(--accent); } .mark .ink { stroke: var(--accent); }
  .auth .eyebrow { margin: 0 0 .3rem; font: 600 var(--text-sm)/1.4 var(--font); color: var(--accent); }
  .auth h1 { margin: 0 0 1.5rem; }
  .auth h1 + .muted { margin-top: -.75rem; }
  .auth label { color: var(--ink); font-weight: 600; font-size: .85rem; gap: .4rem; margin: 0 0 1rem; }
  .auth label { position: relative; } .auth label .opt { position: absolute; top: .1rem; right: 0; margin: 0; }
  .auth label .opt, .auth label .hint { font-weight: 400; color: var(--ink2); }
  .auth input { width: 100%; min-height: 2.75rem; padding: .6rem .8rem; font-size: 1rem; font-weight: 400; }
  .auth form > button[type="submit"] { display: block; width: 100%; min-height: 2.75rem; margin-top: .25rem; }
    .providers { display: grid; gap: .6rem; margin: 0 0 1.25rem; }
  .providers a { display: flex; align-items: center; justify-content: center; gap: .6rem; min-height: 2.75rem; padding: .55rem .9rem; border: 1px solid var(--field); border-radius: var(--radius-sm); background: var(--panel); color: var(--ink); text-decoration: none; font-weight: 600; transition: border-color .15s, background-color .15s; }
  .providers a:hover { border-color: var(--accent); background: var(--bg); } .providers svg { width: 18px; height: 18px; flex: none; }
  .or { display: flex; align-items: center; gap: .75rem; margin: .4rem 0 0; color: var(--ink2); font-size: var(--text-xs); }
  .or::before, .or::after { content: ""; flex: 1; height: 1px; background: var(--line); }
  #authNote { margin: 1rem 0 0; padding: .65rem .85rem; border-radius: var(--radius-sm); background: var(--accent-bg); color: var(--ink); font-size: .88rem; }
  #ssoForm { margin-top: 1.5rem; padding-top: 1.25rem; border-top: 1px solid var(--line); } #ssoForm button { margin-top: .25rem; }
  .auth .swap { text-align: center; margin: 1.25rem 0 0; }
  .tabs { display: grid; grid-template-columns: 1fr 1fr; gap: .25rem; margin: 0 0 1.5rem; padding: .25rem; border-radius: 10px; background: var(--bg); border: 1px solid var(--line); }
  .tabs button { background: transparent; border: 0; color: var(--ink2); padding: .5rem; border-radius: 7px; } .tabs button[aria-selected="true"] { background: var(--panel); color: var(--ink); box-shadow: 0 1px 2px rgb(0 0 0 / .12); }
  .tabs button:not([aria-selected="true"]):hover { color: var(--ink); background: transparent; }
  .auth .forgot { position: absolute; top: 0; right: 0; font-weight: 400; font-size: .82rem; }
  .qr { width: 12rem; max-width: 100%; margin: .5rem 0; } .qr svg { display: block; width: 100%; height: auto; border-radius: 6px; }
  .codes { columns: 2; font-family: var(--mono); }
  #firstSetup pre { overflow-wrap: anywhere; }
  .auth .fine { margin: 1.5rem calc(-1 * var(--pad)) -1.75rem; padding: 1rem var(--pad); border-top: 1px solid var(--line); border-radius: 0 0 var(--radius-md) var(--radius-md); background: var(--bg); font-size: .82rem; line-height: 1.55; }
  .auth .msg { min-height: 0; margin: .75rem 0 0; font-size: .9rem; } .auth .msg:empty { margin: 0; }
  .auth .msg.err:not(:empty), .auth .msg.ok:not(:empty) { padding: .55rem .8rem; border-radius: var(--radius-sm); border: 1px solid; }
  .auth .msg.err:not(:empty) { border-color: color-mix(in srgb, var(--bad) 40%, var(--panel)); background: color-mix(in srgb, var(--bad) 8%, var(--panel)); }
  .auth .msg.ok:not(:empty) { border-color: color-mix(in srgb, var(--ok) 40%, var(--panel)); background: color-mix(in srgb, var(--ok) 8%, var(--panel)); }
  @media (max-width: 30rem) { .top { flex-wrap: wrap; row-gap: .4rem; } .brand { white-space: nowrap; } .userbtn { margin-left: auto; } .top .links { order: 1; flex-basis: 100%; margin-left: 0; font-size: .85rem; } #planTag, #tenantTag { display: none !important; } .auth { --pad: 1.25rem; margin: 1rem .75rem 2rem; } .auth h1 { font-size: var(--text-xl); } }
  .step { display: grid; grid-template-columns: 2rem 1fr; gap: .2rem .8rem; padding: 1rem 0; border-top: 1px solid var(--line); }
  .step .n { font: 700 var(--text-sm)/1.6 var(--font); color: var(--accent); }
  .step h3 { margin: 0 0 .3rem; font-size: 1rem; } .step p { margin: 0 0 .5rem; color: var(--ink2); font-size: .92rem; }
  .snip { position: relative; margin: .4rem 0 .6rem; } .snip pre { margin: 0; padding-right: 4.5rem; font-family: var(--mono); font-size: .84rem; }
  .snip button { position: absolute; top: .45rem; right: .45rem; min-height: 1.75rem; padding: 0 .6rem; font-size: var(--text-xs); }
  .addr th { text-align: left; font-weight: 600; padding-right: 1rem; white-space: nowrap; } .addr td { word-break: break-all; }
  .once { border: 1px solid var(--warn); background: color-mix(in srgb, var(--warn) 10%, var(--panel)); border-radius: var(--radius-md); padding: 1rem 1.1rem; margin: 1rem 0; }
  .tok { font-family: var(--mono); word-break: break-all; padding: .6rem .75rem; background: var(--bg); border: 1px solid var(--line); border-radius: var(--radius-sm); }
  .msg { min-height: 1.4rem; margin: .6rem 0; color: var(--ink2); } .panel > .msg:empty { display: none; } .msg.err { color: var(--bad); } .msg.ok { color: var(--ok); }
  .muted { color: var(--ink2); }
  [hidden] { display: none !important; }
  @media (max-width: 48rem) { .layout { grid-template-columns: 1fr; } main { padding: 1.25rem 1rem 2rem; }
    .cards { grid-template-columns: 1fr 1fr; gap: .6rem; } .card { padding: .75rem .85rem; } .card .k { font-size: var(--text-xs); } .card .v { font-size: var(--text-xl); } .card .s { font-size: .8rem; line-height: 1.35; }
    table:has(#urls), #urls, table:has(#audit), #audit { display: block; } table:has(#audit) thead { display: none; }
    #urls tr { display: grid; gap: .15rem; padding: .55rem 0; border-bottom: 1px solid var(--line); } #urls tr:last-child { border-bottom: 0; }
    #urls th, #urls td { padding: 0; border: 0; } #urls td { overflow-wrap: anywhere; font-size: .8rem; }
    #audit tr { display: grid; grid-template-columns: minmax(0, 1fr) auto; gap: .15rem .75rem; padding: .65rem 0; border-bottom: 1px solid var(--line); } #audit tr:last-child { border-bottom: 0; }
    #audit td { min-width: 0; padding: 0; border: 0; white-space: normal; }
    #audit td:nth-child(3) { grid-area: 1 / 1; font-weight: 600; } #audit td:nth-child(1) { grid-area: 1 / 2; color: var(--ink2); font-size: .8rem; white-space: nowrap; }
    #audit td:nth-child(2), #audit td:nth-child(4), #audit td[colspan] { grid-column: 1 / -1; font-size: .8rem; } #audit td:nth-child(2) { color: var(--ink2); } }
  abbr[title] { text-decoration: underline dotted; text-underline-offset: 2px; cursor: help; }
</style>
<div class="top"><button class="navbtn icon" id="menuBtn" type="button" aria-expanded="false" aria-controls="nav" aria-label="Navigation" hidden><svg viewBox="0 0 24 24" aria-hidden="true"><path d="M4 6h16M4 12h16M4 18h16"/></svg></button><a class="brand" href="#overview"><svg viewBox="0 0 64 64" aria-hidden="true"><rect width="64" height="64" rx="14"/><path d="M19 11H45V45L41.75 48 38.5 45 35.25 48 32 45 28.75 48 25.5 45 22.25 48 19 45Z" fill="#fff"/><path d="M25 20h14M25 27h14" stroke="var(--accent)" stroke-width="2.6" stroke-linecap="round"/><path d="M25 37.5l5 4.5 9.5-10" fill="none" stroke="var(--accent)" stroke-width="3.4" stroke-linecap="round" stroke-linejoin="round"/></svg>agent-custody</a><span id="tenantTag" class="pill" hidden></span><span id="planTag" class="pill" hidden></span><span class="links">${DASHBOARD_NAV}</span><button class="userbtn quiet" id="userBtn" type="button" popovertarget="userMenu" aria-expanded="false" aria-controls="userMenu">Account</button><div id="userMenu" popover><span class="who" id="who" data-acct></span><a href="#account" data-view="account" data-acct>Security</a><button class="theme icon" id="themeToggle" type="button" aria-label="Dark mode" aria-pressed="false" title="Dark mode"><svg class="moon" viewBox="0 0 24 24" aria-hidden="true"><path d="M21 12.8A9 9 0 1 1 11.2 3a7 7 0 0 0 9.8 9.8z"/></svg><svg class="sun" viewBox="0 0 24 24" aria-hidden="true"><circle cx="12" cy="12" r="4"/><path d="M12 2v2M12 20v2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M2 12h2M20 12h2M4.9 19.1l1.4-1.4M17.7 6.3l1.4-1.4"/></svg>Dark mode</button><button class="quiet" id="signout" type="button" data-acct>Sign out</button></div></div>
<div id="notice" class="notice" hidden></div>
<section id="auth" class="auth split" hidden>
  <aside class="pitch">
    <p class="eyebrow">agent-custody hosted log</p>
    <h2>Proof of what your AI agents did.</h2>
    <p>Your gateway signs a receipt for each tool call that it checks. This log keeps the hash of each receipt in a Merkle tree with signed heads, so a changed or removed receipt shows.</p>
    <ol class="flow">
      <li><b>Your agent calls a tool</b><span>The gateway checks the call against your policy before it runs.</span></li>
      <li><b>The gateway signs a receipt</b><span>The receipt stays on your machines.</span></li>
      <li><b>Its hash comes to this log</b><span>Anyone with the public keys can verify the receipt and its place in the log.</span></li>
    </ol>
  </aside>
  <div class="pane">
  ${MARK}
  <p class="eyebrow">Hosted log</p>
  <h1 id="authTitle">Sign in</h1>
  <div class="tabs" id="authTabs" role="tablist"><button type="button" role="tab" id="tabSignIn" aria-selected="true">Sign in</button><button type="button" role="tab" id="tabSignUp" aria-selected="false">Sign up</button></div>
  <div id="providers" class="providers" hidden></div>
  <form id="authForm">
    <label>Work email<input id="email" type="email" autocomplete="email" required></label>
    <label>Password<button class="link forgot" id="forgotOpen" type="button" hidden>Forgot password?</button><input id="password" type="password" autocomplete="current-password" minlength="10" required><span class="hint" id="pwRule" hidden>At least ten characters.</span></label>
    <button id="authGo" type="submit">Sign in</button>
    <p class="msg" id="authMsg" aria-live="polite"></p>
  </form>
  <form id="forgotForm" hidden>
    <p class="muted">Enter the address of your account. We send a link to set a new password. The link works for one hour.</p>
    <label>Work email<input id="forgotEmail" type="email" autocomplete="email" required></label>
    <button type="submit">Send the link</button>
    <p class="msg" id="forgotMsg" aria-live="polite"></p>
    <p class="muted swap"><button class="link" id="forgotBack" type="button">Back to sign in</button></p>
  </form>
  <form id="mfaForm" hidden>
    <p class="muted">Your account has two-step sign-in. Enter the six-digit code from your authenticator app, or one of your recovery codes.</p>
    <label>Code<input id="mfaCode" autocomplete="one-time-code" maxlength="20" required></label>
    <button type="submit">Verify</button>
    <p class="msg" id="mfaMsg" aria-live="polite"></p>
  </form>
  <p class="muted" id="authNote" hidden>Next you name your organisation and get your tenant and its first key. Two minutes.</p>
  <p class="muted swap" id="ssoSwap"><button class="link" id="ssoOpen" type="button">Sign in with single sign-on</button></p>
  <form id="ssoForm" action="/auth/sso" method="get" hidden>
    <label>Work email for single sign-on<input name="email" type="email" autocomplete="email" required></label>
    <button class="quiet" type="submit">Continue with single sign-on</button>
  </form>
  <p class="muted fine">The free plan is ten thousand <abbr title="An append is one receipt hash your gateway writes to your log.">appends</abbr> a month, no card. Your gateway sends only hashes; nothing you log here can be read by us.</p>
  </div>
</section>
<section id="onboard" class="auth split" hidden>
  <aside class="pitch">
    <p class="eyebrow">Setup, step 1 of 4</p>
    <h2>Your own log, in about two minutes.</h2>
    <ol class="flow">
      <li class="now"><b>Create your tenant</b><span>Name your organisation. The tenant id becomes the path of your log.</span></li>
      <li><b>Copy your first API key</b><span>We show it once and keep only its hash.</span></li>
      <li><b>Point your gateway at the log</b><span>One config entry and one environment variable.</span></li>
      <li><b>Send your first receipt</b><span>The dashboard shows the append within seconds.</span></li>
    </ol>
  </aside>
  <div class="pane">
  ${MARK}
  <h1>Set up your tenant</h1>
  <p class="muted">Signed in as <b id="onboardWho"></b>. A tenant is your own log on this service, with its own keys and its own path.</p>
  <div id="invites" class="panel" hidden><p><b>You are invited to join a tenant.</b> Your email address must be verified first.</p><div id="inviteList"></div></div>
  <form id="onboardForm">
    <label>Your name<input id="name" autocomplete="name" maxlength="120" required></label>
    <label>Company or organisation<input id="company" autocomplete="organization" maxlength="160" required></label>
    <label>Tenant id<input id="tenant" placeholder="acme" pattern="[a-z0-9][a-z0-9\\-]{1,38}[a-z0-9]" required><span class="hint">A short name for your organisation, filled in from the company name; change it if you like. It becomes the path of your log, which your gateway config and your auditors will use: <code id="tenantPreview">__LOG_BASE__t/&lt;tenant&gt;/</code></span></label>
    <label>Your role <span class="opt">optional</span><input id="role" autocomplete="organization-title" maxlength="120" placeholder="Head of Platform"></label>
    <button type="submit">Create tenant</button>
    <p class="msg" id="onboardMsg" aria-live="polite"></p>
  </form>
  <p class="muted"><a href="#" id="signoutOnboard">Sign out</a></p>
  </div>
</section>
<section id="welcome" class="auth wide" hidden>
  <div class="side">
  ${MARK}
  <h1>Your tenant is ready</h1>
  <p class="muted">That was step 1 of 4. Steps 2 to 4 take you to your first receipt in this log. Everything here is under <b>Setup</b> in the dashboard whenever you need it again.</p>
  <div class="once"><p><b>Your first API key, shown once.</b> Put it in the environment your gateway reads as <code>AGENT_CUSTODY_LOG_TOKEN</code>. We keep only its hash.</p><p class="tok" id="firstToken"></p><button class="quiet" id="copyFirst">Copy API key</button></div>
  <p><button id="toDash">Go to the dashboard</button></p>
  </div>
  <div id="firstSetup"></div>
</section>
<div class="layout" id="app" hidden>
  <nav id="nav" aria-label="Main">
    <div class="group">Monitor</div>
    <a href="#overview" data-view="overview">Overview</a>
    <a href="#usage" data-view="usage">Usage</a>
    <a href="#activity" data-view="activity">Activity</a>
    <div class="group">Log</div>
    <a href="#setup" data-view="setup">Setup</a>
    <a href="#keys" data-view="keys">API keys <span class="n" id="nKeys"></span></a>
    <a href="#policies" data-view="policies">Policies <span class="n" id="nPolicies"></span></a>
    <a href="#export" data-view="export">Export</a>
    <div class="group">Organisation</div>
    <a href="#members" data-view="members">Members <span class="n" id="nMembers"></span></a>
    <a href="#billing" data-view="billing">Billing</a>
  </nav>
  <main>
    <div data-pane="overview">
      <h1>Overview</h1>
      <div class="panel" id="firstReceipt" hidden><h2>Send your first receipt</h2><p>Your log is empty. Put your API key where your gateway runs, point the gateway at this log, and run your agent once. The numbers show here after the first append.</p><p><a href="#setup" data-view="setup">Open Setup</a></p></div>
      <div class="cards" id="ovCards">
        <div class="card" id="cUsed"><div class="k">Appends this month</div><div class="v" id="vUsed">–</div><div class="s" id="sUsed"></div></div>
        <div class="card" id="cSize"><div class="k">Receipts in your log</div><div class="v" id="vSize">–</div><div class="s">leaf hashes, all time</div></div>
        <div class="card" id="cKeys"><div class="k">Live keys</div><div class="v" id="vKeys">–</div><div class="s" id="sKeys"></div></div>
        <div class="card" id="cCp"><div class="k"><abbr title="A checkpoint is the log's size and root hash, signed and published apart from the log, so anyone can check later that it was never rewritten.">Latest checkpoint</abbr></div><div class="v" id="vCp">–</div><div class="s" id="sCp"></div></div>
      </div>
      <p class="muted">Tree heads on this log are signed by our key; there is no second, independent witness yet. Every receipt you log here is checkable by anyone with your gateway's public key and ours: <a href="https://agent-custody.dev/receipts/#what-a-receipt-proves-and-what-it-does-not" target="_blank" rel="noopener">what a receipt proves and what it does not</a>.</p>
      <h2>Your log</h2>
      <div class="panel"><table><tbody id="urls"></tbody></table></div>
    </div>
    <div data-pane="activity" hidden>
      <h1>Activity</h1>
      <div class="panel"><table><thead><tr><th>when</th><th>who</th><th>action</th><th>detail</th></tr></thead><tbody id="audit"></tbody></table></div>
    </div>
    <div data-pane="usage" hidden>
      <h1>Usage</h1>
      <div class="panel"><div class="bars" id="bars"></div></div>
      <p class="muted" id="usageNote"></p>
    </div>
    <div data-pane="keys" hidden>
      <h1>API keys</h1>
      <p class="muted">An API key is what your gateway presents on each append. It is shown once when created; we keep only its hash. Create a second API key before revoking the first to rotate without a gap.</p>
      <div class="panel"><form id="mintForm" style="display:flex;gap:.6rem;align-items:end;flex-wrap:wrap"><label style="margin:0">Label<input id="label" placeholder="support fleet"></label><button type="submit">Create API key</button></form>
        <div id="minted" class="once" hidden><p><b>Shown once.</b></p><p class="tok" id="mintedTok"></p><button class="quiet" id="copyMinted">Copy API key</button></div>
        <table style="margin-top:1rem"><thead><tr><th>label</th><th>hash</th><th>created</th><th>state</th><th></th></tr></thead><tbody id="keyRows"></tbody></table></div>
      <p class="msg" id="keysMsg"></p>
    </div>
    <div data-pane="policies" hidden>
      <h1>Policies</h1>
      <p class="muted">Enforcement stays on your machines: the gateway reads its <abbr title="Cedar is the policy language the gateway uses to allow or deny each tool call.">Cedar</abbr> file locally and writes the file's SHA-256 into every receipt as <code>policyDigest</code>. This page gives those digests names. Publish each version you deploy, byte for byte as the gateway loads it, and a receipt's digest reads as "refunds-v3" instead of a hash, here and in your export. We never evaluate a policy and nothing here is read by the gateway.</p>
      <div class="panel"><form id="policyForm"><label>Name for this version<input id="policyName" placeholder="refunds-v3" maxlength="80" required></label><label>Policy text, exactly as the gateway's file<textarea id="policyText" rows="8" spellcheck="false" placeholder="permit(principal, action == Action::&quot;stripe.refund&quot;, resource) when { context.args.amount <= 100000 };" required></textarea></label><button type="submit">Publish version</button> <span class="muted" id="policyDigestPreview"></span></form></div>
      <div class="panel"><h2>Match a receipt</h2><p class="muted">Paste a receipt file, or just its <code>policyDigest</code>, to see which published version decided it.</p><form id="matchForm"><label>Receipt JSON or digest<textarea id="matchIn" rows="3" spellcheck="false"></textarea></label><button type="submit" class="quiet">Match</button></form><p class="msg" id="matchOut"></p></div>
      <div class="panel"><table><thead><tr><th>name</th><th>digest</th><th>bytes</th><th>published</th><th>by</th><th></th></tr></thead><tbody id="policyRows"></tbody></table></div>
      <div class="panel" id="policyView" hidden><h2 id="policyViewName"></h2><pre id="policyViewText"></pre></div>
      <p class="msg" id="policiesMsg"></p>
    </div>
    <div data-pane="members" hidden>
      <h1>Members</h1>
      <p class="muted">An owner manages everything, billing and owners included. An admin manages keys and members below owner. A reviewer publishes policy versions. A read-only member only looks. An invited person creates an account with the invited address, verifies it, and accepts on the first screen. An invite is good for seven days.</p>
      <div class="panel" id="inviteBox" hidden><form id="inviteForm" style="display:flex;gap:.6rem;align-items:end;flex-wrap:wrap"><label style="margin:0">Email<input id="inviteEmail" type="email" required></label><label style="margin:0">Role<select id="inviteRole"></select></label><button type="submit">Invite</button></form></div>
      <div class="panel"><table><thead><tr><th>member</th><th>role</th><th>joined</th><th>two-step</th><th></th></tr></thead><tbody id="memberRows"></tbody></table></div>
      <h2>Pending invites</h2>
      <div class="panel"><table><thead><tr><th>email</th><th>role</th><th>invited by</th><th>sent</th><th></th></tr></thead><tbody id="inviteRows"></tbody></table></div>
      <p class="msg" id="membersMsg"></p>
    </div>
    <div data-pane="account" hidden>
      <h1>Account</h1>
      <h2>Two-step sign-in</h2>
      <p class="muted">Two-step sign-in is <b id="mfaState">off</b>. With it on, a password or a GitHub or Google sign-in is followed by a six-digit code from an authenticator app (TOTP).</p>
      <div class="panel">
        <button id="mfaStart" type="button">Set up</button>
        <div id="mfaSetupBox" hidden>
          <p>Scan this QR code with your authenticator app, then type a code from the app.</p>
          <div class="qr" id="mfaQr"></div>
          <p class="muted">Cannot scan? Type this secret into the app by hand:</p>
          <p class="tok" id="mfaSecret"></p>
          <details><summary class="muted">Show the setup address</summary><p class="tok" id="mfaUri"></p></details>
          <form id="mfaOnForm"><label>Code<input id="mfaOnCode" inputmode="numeric" autocomplete="one-time-code" pattern="[0-9]{6}" maxlength="6" required></label><button type="submit">Turn on</button></form>
        </div>
        <div id="recoveryBox" class="once" hidden><p><b>Your recovery codes, shown once.</b> Keep them in a safe place. Each code works one time in place of a code from the app, if you lose your phone. We keep only their hashes.</p><div class="snip"><pre class="codes" id="recoveryCodes"></pre><button type="button" class="quiet" data-copy>Copy</button></div></div>
        <form id="mfaOffForm" hidden><label>Current code or recovery code<input id="mfaOffCode" autocomplete="one-time-code" maxlength="20" required></label><button type="submit" class="quiet">Turn off</button></form>
        <form id="recoveryForm" hidden><p class="muted"><span id="recoveryLeft"></span> Make new codes to replace all of them.</p><label>Current code<input id="recoveryCode" inputmode="numeric" autocomplete="one-time-code" pattern="[0-9]{6}" maxlength="6" required></label><button type="submit" class="quiet">Make new recovery codes</button></form>
      </div>
      <p class="msg" id="accountMsg"></p>
      <h2>Password</h2>
      <div class="panel">
        <form id="pwForm"><label>Current password<input id="pwCurrent" type="password" autocomplete="current-password" required></label><label>New password<input id="pwNew" type="password" autocomplete="new-password" minlength="10" required><span class="hint">At least ten characters.</span></label><button type="submit">Change password</button></form>
        <p class="muted">A change signs out every other session of this account. An account made through GitHub, Google, or single sign-on has a random password that nobody knows<span id="pwNoMail">.</span><span id="pwMail" hidden>: to set one, sign out and use <b>Forgot password?</b> on the sign-in page.</span></p>
        <p class="msg" id="pwMsg"></p>
      </div>
    </div>
    <div data-pane="billing" hidden>
      <h1>Billing</h1>
      <div class="panel" id="billingPanel"></div>
      <p class="msg" id="billingMsg"></p>
    </div>
    <div data-pane="export" hidden>
      <h1>Export</h1>
      <p class="muted">Everything the log holds about you, any time, with your key: every <abbr title="A leaf is one entry in the log: the hash of one receipt.">leaf</abbr> hash as a log file the verifier reads offline, the signed head, the published keys, the checkpoints, your usage, and the actions taken on your tenant. It checks itself before writing.</p>
      <pre id="exportCmd"></pre>
    </div>
    <div data-pane="setup" hidden>
      <h1>Setup</h1>
      <p class="muted">How to connect a gateway or SDK to your log, what to hand your auditors, and how to take your data. The same sheet you saw at registration.</p>
      <div id="setupPane"></div>
    </div>
  </main>
</div>
<script>
(() => {
  const $ = (id) => document.getElementById(id);
  const esc = (s) => String(s).replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));
  const api = async (method, path, body) => {
    const r = await fetch(path, { method, headers: body !== undefined ? { "content-type": "application/json" } : {}, body: body !== undefined ? JSON.stringify(body) : undefined, credentials: "same-origin" });
    const j = await r.json().catch(() => ({}));
    if (!r.ok) { const e = new Error(j.error || r.statusText); e.status = r.status; throw e; }
    return j;
  };
  const fmt = (n) => Number(n).toLocaleString();
  const ago = (iso) => { const m = Math.round((Date.now() - Date.parse(iso)) / 60000); return m < 60 ? m + " min ago" : m < 1440 ? Math.round(m / 60) + " h ago" : Math.round(m / 1440) + " d ago"; };
  let registering = false;
  let myRole = "readonly";
  const ROLES = ["readonly", "reviewer", "admin", "owner"];
  const can = (least) => ROLES.indexOf(myRole) >= ROLES.indexOf(least);
  const note = (id, text, ok) => { $(id).className = "msg " + (ok ? "ok" : "err"); $(id).textContent = text; };
  const show = (id) => {
    for (const s of ["auth", "onboard", "welcome", "app"]) $(s).hidden = s !== id;
    $("menuBtn").hidden = id !== "app";
    for (const el of document.querySelectorAll("[data-acct]")) el.hidden = id !== "app";
    if (id !== "app") { document.title = "agent-custody"; setDrawer(false); }
  };
  const PROVIDERS = __PROVIDERS__;
  const MAIL = __MAIL__;
  const ICONS = { github: "<svg viewBox='0 0 16 16' aria-hidden='true'><path fill='currentColor' d='M8 0C3.58 0 0 3.58 0 8c0 3.54 2.29 6.53 5.47 7.59.4.07.55-.17.55-.38 0-.19-.01-.82-.01-1.49-2.01.37-2.53-.49-2.69-.94-.09-.23-.48-.94-.82-1.13-.28-.15-.68-.52-.01-.53.63-.01 1.08.58 1.23.82.72 1.21 1.87.87 2.33.66.07-.52.28-.87.51-1.07-1.78-.2-3.64-.89-3.64-3.95 0-.87.31-1.59.82-2.15-.08-.2-.36-1.02.08-2.12 0 0 .67-.21 2.2.82.64-.18 1.32-.27 2-.27.68 0 1.36.09 2 .27 1.53-1.04 2.2-.82 2.2-.82.44 1.1.16 1.92.08 2.12.51.56.82 1.27.82 2.15 0 3.07-1.87 3.75-3.65 3.95.29.25.54.73.54 1.48 0 1.07-.01 1.93-.01 2.2 0 .21.15.46.55.38A8.01 8.01 0 0 0 16 8c0-4.42-3.58-8-8-8z'/></svg>", google: "<svg viewBox='0 0 48 48' aria-hidden='true'><path fill='#EA4335' d='M24 9.5c3.54 0 6.71 1.22 9.21 3.6l6.85-6.85C35.9 2.38 30.47 0 24 0 14.62 0 6.51 5.38 2.56 13.22l7.98 6.19C12.43 13.72 17.74 9.5 24 9.5z'/><path fill='#4285F4' d='M46.98 24.55c0-1.57-.15-3.09-.38-4.55H24v9.02h12.94c-.58 2.96-2.26 5.48-4.78 7.18l7.73 6c4.51-4.18 7.09-10.36 7.09-17.65z'/><path fill='#FBBC05' d='M10.53 28.59c-.48-1.45-.76-2.99-.76-4.59s.27-3.14.76-4.59l-7.98-6.19C.92 16.46 0 20.12 0 24c0 3.88.92 7.54 2.56 10.78l7.97-6.19z'/><path fill='#34A853' d='M24 48c6.48 0 11.93-2.13 15.89-5.81l-7.73-6c-2.15 1.45-4.92 2.3-8.16 2.3-6.26 0-11.57-4.22-13.47-9.91l-7.98 6.19C6.51 42.62 14.62 48 24 48z'/></svg>" };
  if (PROVIDERS.length) { $("providers").innerHTML = PROVIDERS.map((p) => "<a href='/auth/" + p + "'>" + ICONS[p] + "Continue with " + (p === "github" ? "GitHub" : "Google") + "</a>").join("") + "<p class=or>or with email</p>"; $("providers").hidden = false; }
  const TITLES = { overview: "Overview", usage: "Usage", activity: "Activity", setup: "Setup", keys: "API keys", policies: "Policies", export: "Export", members: "Members", billing: "Billing", account: "Security" };
  const route = () => {
    if ($("app").hidden) return;
    const h = location.hash.slice(1), name = Object.hasOwn(TITLES, h) ? h : "overview";
    for (const p of document.querySelectorAll("[data-pane]")) p.hidden = p.dataset.pane !== name;
    for (const a of document.querySelectorAll("nav a[data-view]")) a.classList.toggle("on", a.dataset.view === name);
    document.title = TITLES[name] + " \u00b7 agent-custody";
    if (h !== name) history.replaceState(null, "", "#" + name);
    scrollTo(0, 0);
  };
  addEventListener("hashchange", route);
  const setDrawer = (open, refocus) => {
    $("nav").classList.toggle("open", open); $("menuBtn").setAttribute("aria-expanded", open);
    if (open) $("nav").querySelector("a").focus(); else if (refocus) $("menuBtn").focus();
  };
  const drawerOpen = () => $("nav").classList.contains("open");
  $("menuBtn").onclick = () => setDrawer(!drawerOpen());
  matchMedia("(max-width: 48rem)").onchange = () => setDrawer(false);
  document.addEventListener("keydown", (e) => { if (e.key === "Escape" && drawerOpen()) setDrawer(false, true); });
  $("userMenu").addEventListener("beforetoggle", (e) => { if (e.newState === "open") { const r = $("userBtn").getBoundingClientRect(); $("userMenu").style.top = r.bottom + 6 + "px"; $("userMenu").style.right = document.documentElement.clientWidth - r.right + "px"; } });
  $("userMenu").addEventListener("toggle", (e) => $("userBtn").setAttribute("aria-expanded", e.newState === "open"));
  const LOG_BASE = $("tenantPreview").textContent.replace("t/<tenant>/", "");
  const slug = (s) => s.toLowerCase().normalize("NFKD").replace(/[^a-z0-9]+/g, "-").replace(/^-+|-+$/g, "").slice(0, 40);
  let tenantEdited = false;
  const previewTenant = () => { $("tenantPreview").textContent = LOG_BASE + "t/" + ($("tenant").value || "<tenant>") + "/"; };
  $("company").oninput = () => { if (!tenantEdited) { $("tenant").value = slug($("company").value); previewTenant(); } };
  $("tenant").oninput = () => { tenantEdited = $("tenant").value !== ""; previewTenant(); };
  const authTab = (signUp) => {
    registering = signUp;
    $("tabSignIn").setAttribute("aria-selected", String(!signUp)); $("tabSignUp").setAttribute("aria-selected", String(signUp));
    $("authTitle").textContent = signUp ? "Sign up" : "Sign in"; $("authGo").textContent = signUp ? "Sign up" : "Sign in";
    $("authNote").hidden = !signUp; $("pwRule").hidden = !signUp; $("forgotOpen").hidden = signUp || !MAIL; $("ssoSwap").hidden = signUp; $("ssoForm").hidden = true;
    $("password").autocomplete = signUp ? "new-password" : "current-password";
    $("authForm").hidden = false; $("forgotForm").hidden = true; $("authMsg").textContent = "";
  };
  $("tabSignIn").onclick = () => authTab(false);
  $("tabSignUp").onclick = () => authTab(true);
  authTab(false);
  $("ssoOpen").onclick = () => { $("ssoSwap").hidden = true; $("ssoForm").hidden = false; $("ssoForm").querySelector("input").focus(); };
  $("forgotOpen").onclick = () => { $("authForm").hidden = true; $("ssoSwap").hidden = true; $("authTitle").textContent = "Reset your password"; $("forgotForm").hidden = false; $("forgotEmail").value = $("email").value; $("forgotMsg").textContent = ""; $("forgotEmail").focus(); };
  $("forgotBack").onclick = () => authTab(false);
  $("forgotForm").onsubmit = async (e) => {
    e.preventDefault();
    try { await api("POST", "/api/password/forgot", { email: $("forgotEmail").value }); note("forgotMsg", "If an account has this address, we sent it a link to set a new password. The link works for one hour.", true); }
    catch (err) { note("forgotMsg", err.message, false); }
  };
  $("authForm").onsubmit = async (e) => {
    e.preventDefault(); $("authMsg").className = "msg"; $("authMsg").textContent = "";
    try {
      const r = await api("POST", registering ? "/api/register" : "/api/login", { email: $("email").value, password: $("password").value });
      if (r.mfa) { askCode(); return; }
      await enter();
    } catch (err) { $("authMsg").className = "msg err"; $("authMsg").textContent = err.message; }
  };
  const askCode = () => { $("authForm").hidden = true; $("ssoForm").hidden = true; $("ssoSwap").hidden = true; $("providers").hidden = true; $("authTabs").hidden = true; $("authTitle").textContent = "Enter your code"; $("mfaForm").hidden = false; $("mfaCode").focus(); };
  $("mfaForm").onsubmit = async (e) => {
    e.preventDefault();
    try { await api("POST", "/api/login/mfa", { code: $("mfaCode").value }); location.href = "/"; }
    catch (err) { note("mfaMsg", err.message, false); }
  };
  $("onboardForm").onsubmit = async (e) => {
    e.preventDefault(); $("onboardMsg").className = "msg"; $("onboardMsg").textContent = "";
    try {
      const r = await api("POST", "/api/onboard", { tenant: $("tenant").value, name: $("name").value, company: $("company").value, role: $("role").value });
      $("firstToken").textContent = r.token; renderSetup($("firstSetup"), Object.assign({}, r.setup, { env: "export AGENT_CUSTODY_LOG_TOKEN=" + r.token }), true); show("welcome");
    } catch (err) { $("onboardMsg").className = "msg err"; $("onboardMsg").textContent = err.message; }
  };
  $("signoutOnboard").onclick = async (e) => { e.preventDefault(); await api("POST", "/api/logout", {}); location.hash = ""; show("auth"); };
  $("copyFirst").onclick = () => navigator.clipboard.writeText($("firstToken").textContent);
  // Light or dark by choice, kept in this browser; unset, the page follows the system. The button says where it is going.
  const themeNow = () => document.documentElement.dataset.theme || (matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light");
  const themeLabel = () => { $("themeToggle").setAttribute("aria-pressed", String(themeNow() === "dark")); };
  $("themeToggle").onclick = () => { const next = themeNow() === "dark" ? "light" : "dark"; document.documentElement.dataset.theme = next; try { localStorage.setItem("agent-custody-theme", next); } catch {} themeLabel(); };
  themeLabel();
  const snip = (text) => "<div class=snip><pre>" + esc(text) + "</pre><button type=button class=quiet data-copy>Copy</button></div>";
  const step = (n, title, body) => "<div class=step><span class=n>" + n + "</span><div><h3>" + title + "</h3>" + body + "</div></div>";
  const renderSetup = (el, s, atRegistration) => {
    const n = atRegistration ? 1 : 0;
    el.innerHTML =
      step(n + 1, "Keep the key where your gateway runs", (atRegistration ? "<p>Your first key is shown once; we keep only its hash. Put it in the environment of the machine that runs your gateway or SDK. The command below holds your key:</p>" : "<p>Your key was shown once at registration. If it is gone, mint another under <a href=\\"#keys\\" data-view=\\"keys\\">API keys</a>. It lives in the environment of the machine that runs your gateway or SDK:</p>") + snip(s.env)) +
      step(n + 2, "Point your gateway or SDK at your log", "<p>Add this to <code>gateway.json</code> or <code>sdk.json</code>. <code>hashOnly</code> means this log receives the hash of each receipt and never the receipt.</p>" + snip(s.config)) +
      step(n + 3, "Send the first receipt", "<p>Run your agent through the gateway once. The <a href=\\"#overview\\" data-view=\\"overview\\">Overview</a> shows the append within seconds, and the first signed checkpoint follows within minutes. New to the gateway? <a href=\\"https://agent-custody.dev/guide/getting-started\\" target=\\"_blank\\" rel=\\"noopener\\">Getting started</a> takes ten minutes.</p>") +
      "<h2>After the first receipt</h2>" + step("", "Hand this to whoever verifies your receipts", "<p>Both commands fetch this log's published keys and pin them; <code>--log-id</code> makes sure the tree heads are this log's.</p>" + snip(s.verify) + snip(s.audit)) +
      step("", "Take your data, any time", "<p>Every leaf hash, the signed head, the keys, the checkpoints, your usage, and the actions taken on your tenant, checked against each other and written as a log copy the verifier reads offline.</p>" + snip(s.export)) +
      "<h2>Your log's addresses</h2><div class=panel><table class=addr><tbody>" + [["Your log", s.log], ["Log id on tree heads", s.logId], ["Your checkpoints", s.checkpoints || "published after your first append"], ["The log's keys", s.keys + (s.keyid ? " (current keyid " + s.keyid.slice(0, 12) + "…)" : "")]].map(([k, v]) => "<tr><th>" + esc(k) + "</th><td class=mono>" + esc(v) + "</td></tr>").join("") + "</tbody></table></div>" +
      "<h2>What this log does not do</h2><p class=muted>Hold receipt contents; forge a receipt, since your gateway key signs those; or, today, countersign with a second independent witness. <a href=\\"https://agent-custody.dev/receipts/#what-a-receipt-proves-and-what-it-does-not\\" target=\\"_blank\\" rel=\\"noopener\\">What a receipt proves and what it does not.</a></p>";
  };
  document.addEventListener("click", (e) => {
    const b = e.target.closest("button[data-copy]"); if (b) { navigator.clipboard.writeText(b.previousElementSibling.textContent).then(() => { b.textContent = "Copied"; setTimeout(() => { b.textContent = "Copy"; }, 1500); }); return; }
    if (drawerOpen() && !e.target.closest("#menuBtn") && (!e.target.closest("nav") || e.target.closest("nav a"))) setDrawer(false);
    if (e.target.closest("#userMenu a")) $("userMenu").hidePopover();
  });
  $("toDash").onclick = () => enter();
  $("signout").onclick = async () => { $("userMenu").hidePopover(); await api("POST", "/api/logout", {}); location.hash = ""; show("auth"); };
  const render = (o) => {
    $("tenantTag").textContent = o.tenant; $("tenantTag").hidden = false; $("planTag").textContent = o.plan + " plan"; $("planTag").hidden = false;
    const pct = o.quota ? o.used / o.quota : 0;
    $("cUsed").className = "card " + (o.quota === null ? "ok" : pct >= 1 ? "bad" : pct >= .8 ? "warn" : "ok");
    $("vUsed").textContent = fmt(o.used); $("sUsed").textContent = o.quota === null ? "no allowance on " + o.plan : "of " + fmt(o.quota) + " on " + o.plan + (pct >= 1 ? ": appends are refused until next month" : "");
    $("vSize").textContent = fmt(o.treeSize);
    $("firstReceipt").hidden = o.treeSize > 0; $("ovCards").hidden = o.treeSize === 0;
    const live = o.keys.filter((k) => !k.revokedAt).length; $("vKeys").textContent = live; $("sKeys").textContent = o.keys.length - live + " revoked"; $("nKeys").textContent = live;
    $("cCp").className = "card " + (o.latestCheckpoint ? (Date.now() - Date.parse(o.latestCheckpoint.signedAt) < 7 * 3600e3 ? "ok" : "warn") : "warn");
    $("vCp").textContent = o.latestCheckpoint ? "size " + fmt(o.latestCheckpoint.treeSize) : "none yet"; $("sCp").textContent = o.latestCheckpoint ? "signed " + ago(o.latestCheckpoint.signedAt) : "published after your first append";
    $("urls").innerHTML = [["Append here", o.urls.log], ["Log id on tree heads", o.logId], ["The log's keys", o.urls.keys], ["Your checkpoints", o.urls.checkpoints || "(not published)"], ["Current root", o.rootHash || "none until the first append"]].map(([k, v]) => "<tr><th>" + esc(k) + "</th><td class=mono>" + esc(v) + "</td></tr>").join("");
    $("audit").innerHTML = o.audit.map((e) => "<tr><td>" + esc(e.at.replace("T", " ").slice(0, 16)) + "</td><td class=mono>" + esc(e.actor) + "</td><td>" + esc(e.action) + "</td><td class=muted>" + esc(Object.entries(e.detail).map(([k, v]) => k + "=" + v).join(" ")) + "</td></tr>").join("") || "<tr><td colspan=4 class=muted>nothing yet</td></tr>";
    const max = Math.max(1, ...o.months.map((m) => m.appends));
    $("bars").innerHTML = o.months.map((m) => "<div class=bar><span class=mono>" + fmt(m.appends) + "</span><i style=\\"height:" + Math.max(2, Math.round(100 * m.appends / max)) + "%\\"></i><b>" + esc(m.month.slice(2)) + "</b></div>").join("");
    $("usageNote").textContent = "Appends per calendar month, UTC. Your plan allows " + (o.quota === null ? "any number" : fmt(o.quota)) + " a month; the count resets on the first.";
    $("keyRows").innerHTML = o.keys.map((k) => "<tr><td>" + esc(k.label) + "</td><td class=mono>" + esc(k.hash) + "</td><td>" + esc(k.createdAt.slice(0, 10)) + "</td><td>" + (k.revokedAt ? "revoked " + esc(k.revokedAt.slice(0, 10)) : "live") + "</td><td>" + (k.revokedAt || !can("admin") ? "" : "<button class=quiet data-revoke=\\"" + esc(k.hash) + "\\">Revoke</button>") + "</td></tr>").join("");
    $("billingPanel").innerHTML = o.plan === "free"
      ? "<p>You are on the <b>free</b> plan: ten thousand appends a month, no card.</p><p>The <b>team</b> plan is <b>$50 a month</b>: a million appends, email support within two working days, the same export and audit trail. No availability commitment yet, and the design fails closed: when the log is unreachable your gateway withholds pre-committed calls.</p>" + (o.stripe ? (can("owner") ? "<button id=upgrade>Upgrade to team, $50/month</button>" : "<p class=muted>An owner upgrades the plan.</p>") : "<p class=muted>Card payments are not switched on for this portal yet; email us and we move the plan by hand.</p>")
      : "<p>You are on the <b>" + esc(o.plan) + "</b> plan" + (o.billing ? " (subscription " + esc(o.billing.status) + ")" : "") + ".</p>" + (o.stripe && o.billing && can("owner") ? "<button class=quiet id=manage>Manage billing</button>" : "");
    $("exportCmd").textContent = o.exportCommand; renderSetup($("setupPane"), o.setup, false);
    const up = $("upgrade"); if (up) up.onclick = async () => { try { const r = await api("POST", "/api/checkout", {}); location.href = r.url; } catch (err) { $("billingMsg").className = "msg err"; $("billingMsg").textContent = err.message; } };
    const mg = $("manage"); if (mg) mg.onclick = async () => { try { const r = await api("POST", "/api/billing-portal", {}); location.href = r.url; } catch (err) { $("billingMsg").className = "msg err"; $("billingMsg").textContent = err.message; } };
  };
  const load = async () => { render(await api("GET", "/api/overview")); await loadPolicies(); await loadMembers(); };
  const recoveryLeft = (n) => { $("recoveryLeft").textContent = n === 1 ? "1 recovery code is left." : n + " recovery codes are left."; };
  const showCodes = (codes) => { $("recoveryCodes").textContent = codes.join("\\n"); $("recoveryBox").hidden = false; recoveryLeft(codes.length); };
  const mfaShow = (on, left) => { $("mfaState").textContent = on ? "on" : "off"; $("mfaStart").hidden = on; $("mfaOffForm").hidden = !on; $("recoveryForm").hidden = !on; $("mfaSetupBox").hidden = true; if (!on) $("recoveryBox").hidden = true; if (left !== undefined) recoveryLeft(left); };
  $("mfaStart").onclick = async () => { try { const r = await api("POST", "/api/mfa/setup", {}); $("mfaQr").innerHTML = r.qr; $("mfaSecret").textContent = r.secret; $("mfaUri").textContent = r.uri; $("mfaSetupBox").hidden = false; $("mfaStart").hidden = true; $("accountMsg").textContent = ""; } catch (err) { note("accountMsg", err.message, false); } };
  $("mfaOnForm").onsubmit = async (e) => { e.preventDefault(); try { const r = await api("POST", "/api/mfa/enable", { code: $("mfaOnCode").value }); $("mfaOnCode").value = ""; mfaShow(true); showCodes(r.recoveryCodes); note("accountMsg", "Two-step sign-in is on.", true); } catch (err) { note("accountMsg", err.message, false); } };
  $("mfaOffForm").onsubmit = async (e) => { e.preventDefault(); try { await api("POST", "/api/mfa/disable", { code: $("mfaOffCode").value }); $("mfaOffCode").value = ""; mfaShow(false); note("accountMsg", "Two-step sign-in is off.", true); } catch (err) { note("accountMsg", err.message, false); } };
  $("recoveryForm").onsubmit = async (e) => { e.preventDefault(); try { const r = await api("POST", "/api/mfa/recovery", { code: $("recoveryCode").value }); $("recoveryCode").value = ""; showCodes(r.recoveryCodes); note("accountMsg", "New recovery codes are made. The old codes no longer work.", true); } catch (err) { note("accountMsg", err.message, false); } };
  $("pwMail").hidden = !MAIL; $("pwNoMail").hidden = MAIL;
  $("pwForm").onsubmit = async (e) => { e.preventDefault(); try { await api("POST", "/api/password/change", { current: $("pwCurrent").value, password: $("pwNew").value }); $("pwCurrent").value = ""; $("pwNew").value = ""; note("pwMsg", "Your password is changed. Other sessions are signed out.", true); } catch (err) { note("pwMsg", err.message, false); } };
  const roleOptions = (cur) => ROLES.filter((r) => r !== "owner" || can("owner")).map((r) => "<option" + (r === cur ? " selected" : "") + ">" + r + "</option>").join("");
  const loadMembers = async () => {
    const r = await api("GET", "/api/members");
    $("nMembers").textContent = r.members.length;
    $("inviteRole").innerHTML = roleOptions("readonly");
    $("memberRows").innerHTML = r.members.map((m) => "<tr><td>" + esc(m.email) + "</td><td>" + (can("admin") && (m.role !== "owner" || can("owner")) ? "<select data-setrole=" + m.id + ">" + roleOptions(m.role) + "</select>" : esc(m.role)) + "</td><td>" + esc(m.joinedAt.slice(0, 10)) + "</td><td>" + (m.mfa ? "on" : "off") + "</td><td>" + (can("admin") && (m.role !== "owner" || can("owner")) ? "<button class=link data-rmmember=" + m.id + ">Remove</button>" : "") + "</td></tr>").join("");
    $("inviteRows").innerHTML = r.invites.map((i) => "<tr><td>" + esc(i.email) + "</td><td>" + esc(i.role) + "</td><td class=mono>" + esc(i.invitedBy) + "</td><td>" + esc(i.createdAt.slice(0, 10)) + "</td><td>" + (can("admin") ? "<button class=link data-rminvite=\\"" + esc(i.email) + "\\">Cancel</button>" : "") + "</td></tr>").join("") || "<tr><td colspan=5 class=muted>none</td></tr>";
  };
  const membersDo = async (path, body, done) => { try { await api("POST", path, body); note("membersMsg", done, true); await loadMembers(); } catch (err) { note("membersMsg", err.message, false); await loadMembers(); } };
  $("inviteForm").onsubmit = (e) => { e.preventDefault(); membersDo("/api/members", { email: $("inviteEmail").value, role: $("inviteRole").value }, "Invite sent to " + $("inviteEmail").value + ".").then(() => { $("inviteEmail").value = ""; }); };
  document.addEventListener("change", (e) => { const s = e.target.closest("select[data-setrole]"); if (s) membersDo("/api/members/" + s.dataset.setrole + "/role", { role: s.value }, "Role changed."); });
  document.addEventListener("click", async (e) => {
    const rm = e.target.closest("button[data-rmmember]"); if (rm && confirm("Remove this member? They lose access to the tenant at once.")) { membersDo("/api/members/" + rm.dataset.rmmember + "/remove", {}, "Member removed."); return; }
    const ri = e.target.closest("button[data-rminvite]"); if (ri) { membersDo("/api/invites/remove", { email: ri.dataset.rminvite }, "Invite cancelled."); return; }
    const ac = e.target.closest("button[data-accept]"); if (ac) { try { await api("POST", "/api/invites/accept", { tenant: ac.dataset.accept }); await enter(); } catch (err) { note("onboardMsg", err.message, false); } }
  });
  const enter = async () => {
    try {
      const me = await api("GET", "/api/me");
      accountNotice(me);
      if (me.tenant === null) { $("onboardWho").textContent = me.email; $("invites").hidden = !(me.invites || []).length; $("inviteList").innerHTML = (me.invites || []).map((i) => "<p>Join <b>" + esc(i.tenant) + "</b> as " + esc(i.role) + " <button type=button data-accept=\\"" + esc(i.tenant) + "\\">Accept</button></p>").join(""); if (me.profile) { for (const k of ["name", "company", "role"]) if (me.profile[k]) $(k).value = me.profile[k]; } previewTenant(); show("onboard"); return; }
      $("who").textContent = me.email; myRole = me.role; $("mintForm").hidden = !can("admin"); $("policyForm").hidden = !can("reviewer"); $("inviteBox").hidden = !can("admin") || !!(me.sso && me.sso.enforced); mfaShow(me.mfa, me.recoveryCodes); show("app"); await load(); route();
    }
    catch (err) { if (err.status === 401) { show("auth"); if (location.hash === "#register" && !registering) authTab(true); if (new URLSearchParams(location.search).get("mfa") === "1") askCode(); } else { show("app"); $("who").textContent = err.message; } }
  };
  const accountNotice = (me) => {
    const parts = [];
    if (me.emailVerified === false && me.mail) parts.push("Verify your email address: we sent a link to " + me.email + ". <button type=button id=resendVerify>Send it again</button>");
    const unlinked = (me.providers || []).filter((p) => !(me.identities || []).includes(p));
    if (unlinked.length) parts.push("Sign in faster next time:" + unlinked.map((p) => "<a href='/auth/" + p + "?link=1'>Link " + (p === "github" ? "GitHub" : "Google") + "</a>").join(""));
    $("notice").innerHTML = parts.join(" &middot; ");
    $("notice").hidden = parts.length === 0;
    const b = document.getElementById("resendVerify");
    if (b) b.onclick = async () => { b.disabled = true; try { await api("POST", "/api/verify-email/resend", {}); b.textContent = "Sent"; } catch (e) { b.textContent = e.message; } };
  };
  const sha256hex = async (text) => [...new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text)))].map((b) => b.toString(16).padStart(2, "0")).join("");
  const loadPolicies = async () => {
    const r = await api("GET", "/api/policies");
    $("nPolicies").textContent = r.policies.length || "";
    $("policyRows").innerHTML = r.policies.map((p) => "<tr><td>" + esc(p.name) + "</td><td class=mono>" + esc(p.digest.slice(0, 16)) + "…</td><td>" + p.bytes + "</td><td>" + esc(p.createdAt.slice(0, 10)) + "</td><td class=mono>" + esc(p.createdBy.replace(/^portal:/, "")) + "</td><td><button class=link data-viewpol=\\"" + esc(p.id) + "\\">View</button>" + (can("reviewer") ? " <button class=link data-rmpol=\\"" + esc(p.id) + "\\">Remove</button>" : "") + "</td></tr>").join("") || "<tr><td colspan=6 class=muted>No versions published yet. Receipts keep their digests either way; a name is for the people reading them.</td></tr>";
  };
  $("policyText").oninput = async () => { const t = $("policyText").value; $("policyDigestPreview").textContent = t ? "sha256 " + (await sha256hex(t)).slice(0, 16) + "…" : ""; };
  $("policyForm").onsubmit = async (e) => {
    e.preventDefault(); $("policiesMsg").className = "msg";
    try { const r = await api("POST", "/api/policies", { name: $("policyName").value, text: $("policyText").value }); $("policiesMsg").className = "msg ok"; $("policiesMsg").textContent = "Published " + r.policy.name + " as " + r.policy.digest.slice(0, 16) + "…"; $("policyName").value = ""; $("policyText").value = ""; $("policyDigestPreview").textContent = ""; await loadPolicies(); }
    catch (err) { $("policiesMsg").className = "msg err"; $("policiesMsg").textContent = err.message; }
  };
  $("matchForm").onsubmit = async (e) => {
    e.preventDefault(); $("matchOut").className = "msg";
    try {
      const raw = $("matchIn").value.trim(); let digest = raw;
      if (!/^[0-9a-f]{64}$/i.test(raw)) { const b = JSON.parse(raw); const payload = b.envelope ? b.envelope.payload : b.payload; const st = JSON.parse(atob(payload)); digest = st.predicate && st.predicate.policy ? st.predicate.policy.policyDigest : ""; if (!digest) throw new Error("this receipt carries no policy decision"); }
      const r = await api("GET", "/api/policies?digest=" + encodeURIComponent(digest));
      $("matchOut").className = r.match ? "msg ok" : "msg"; $("matchOut").textContent = r.match ? "Decided by \\"" + r.match.name + "\\", published " + r.match.createdAt.slice(0, 10) + " (" + digest.slice(0, 16) + "…)" : "No published version has digest " + digest.slice(0, 16) + "…; publish the file the gateway loaded to name it.";
    } catch (err) { $("matchOut").className = "msg err"; $("matchOut").textContent = err.message; }
  };
  document.addEventListener("click", async (e) => {
    const v = e.target.closest("button[data-viewpol]"); if (v) { try { const r = await api("GET", "/api/policies/" + v.dataset.viewpol); $("policyViewName").textContent = r.policy.name + " · " + r.policy.digest; $("policyViewText").textContent = r.policy.text; $("policyView").hidden = false; } catch (err) { $("policiesMsg").className = "msg err"; $("policiesMsg").textContent = err.message; } return; }
    const rm = e.target.closest("button[data-rmpol]"); if (rm && confirm("Remove this published version? Receipts keep their digests; only the name goes.")) { try { await api("POST", "/api/policies/" + rm.dataset.rmpol + "/remove", {}); $("policyView").hidden = true; await loadPolicies(); } catch (err) { $("policiesMsg").className = "msg err"; $("policiesMsg").textContent = err.message; } }
  });
  $("mintForm").onsubmit = async (e) => { e.preventDefault(); try { const r = await api("POST", "/api/keys", { label: $("label").value }); $("mintedTok").textContent = r.token; $("minted").hidden = false; $("keysMsg").className = "msg ok"; $("keysMsg").textContent = "minted " + r.label + ", stored as hash " + r.tokenHash; await load(); } catch (err) { $("keysMsg").className = "msg err"; $("keysMsg").textContent = err.message; } };
  $("copyMinted").onclick = () => navigator.clipboard.writeText($("mintedTok").textContent);
  document.addEventListener("click", async (e) => { const b = e.target.closest("button[data-revoke]"); if (!b) return; if (!confirm("Revoke key " + b.dataset.revoke + "? A gateway using it stops appending at once.")) return; try { await api("POST", "/api/keys/" + b.dataset.revoke + "/revoke", {}); $("keysMsg").className = "msg ok"; $("keysMsg").textContent = "revoked"; await load(); } catch (err) { $("keysMsg").className = "msg err"; $("keysMsg").textContent = err.message; } });
  if (new URLSearchParams(location.search).get("upgraded")) history.replaceState(null, "", "/#billing");
  enter();
})();
</script>
`;
