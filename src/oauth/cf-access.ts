/**
 * Cloudflare Access JWT verification.
 *
 * When CF Access protects /authorize, it forwards the request with a signed
 * JWT in the `Cf-Access-Jwt-Assertion` header (or `CF_Authorization` cookie).
 * Verifying it proves the request actually came through CF and lets us read
 * the authenticated user's email.
 *
 * We fetch the CF Access JWKS once and cache it. Keys rotate infrequently;
 * we refresh on cache miss (unknown kid) and on a 10-minute TTL. Cache-miss
 * refreshes are rate-limited and deduplicated so unauthenticated tokens with
 * random kids cannot be turned into outbound fetch amplification.
 *
 * Spec: https://developers.cloudflare.com/cloudflare-one/identity/authorization-cookie/validating-json/
 */

import {
  createPublicKey,
  createVerify,
  type KeyObject,
} from "node:crypto";

export interface CFAccessConfig {
  teamDomain: string;        // e.g. "your-team.cloudflareaccess.com"
  audience: string;          // Application AUD tag from CF Access
  requireEmailMatch: boolean;
}

interface JWK {
  kty: string;
  kid: string;
  alg?: string;
  use?: string;
  n: string;
  e: string;
}

interface Claims {
  iss: string;
  aud: string | string[];
  exp: number;
  nbf?: number;
  iat?: number;
  email?: string;
  sub?: string;
  identity_nonce?: string;
}

const JWKS_TTL_MS = 10 * 60 * 1000;
const JWKS_FETCH_TIMEOUT_MS = 10_000;
// An unknown kid may only trigger one outbound JWKS fetch per minute; anything
// arriving inside that window is rejected instead of refetching.
const FORCED_REFRESH_MIN_INTERVAL_MS = 60 * 1000;
// Tolerance applied to both exp and nbf so a slightly fast or slow host clock
// does not spuriously reject valid tokens.
const CLOCK_SKEW_SEC = 60;

export class CFAccessVerifier {
  private keys = new Map<string, KeyObject>();
  private lastFetched = 0;
  private lastForcedRefresh = 0;
  private inflight: Promise<void> | null = null;

  constructor(private readonly cfg: CFAccessConfig) {}

  get issuer(): string {
    return `https://${this.cfg.teamDomain}`;
  }

  /**
   * Verify a CF Access JWT. Throws on any failure.
   * Returns the authenticated user's email (or empty string if service token).
   */
  async verify(token: string): Promise<{ email: string; sub: string }> {
    const [headerB64, payloadB64, signatureB64] = token.split(".");
    if (!headerB64 || !payloadB64 || !signatureB64) {
      throw new Error("Malformed JWT");
    }
    const header = parseJsonB64Url(headerB64);
    const payload = parseJsonB64Url(payloadB64) as Claims;

    if (header.alg !== "RS256") {
      throw new Error(`Unsupported alg: ${header.alg}`);
    }

    let key = await this.getKey(header.kid);
    if (!key) {
      await this.refresh(true);
      key = await this.getKey(header.kid);
      if (!key) throw new Error(`Unknown kid: ${header.kid}`);
    }

    const signingInput = `${headerB64}.${payloadB64}`;
    const signature = Buffer.from(signatureB64, "base64url");
    const verifier = createVerify("RSA-SHA256");
    verifier.update(signingInput);
    verifier.end();
    if (!verifier.verify(key, signature)) {
      throw new Error("Signature verification failed");
    }

    const now = Math.floor(Date.now() / 1000);
    if (typeof payload.exp !== "number" || payload.exp + CLOCK_SKEW_SEC < now) {
      throw new Error("Token expired");
    }
    // nbf is optional in CF Access tokens, but when present it must be honoured.
    if (payload.nbf !== undefined) {
      if (typeof payload.nbf !== "number" || payload.nbf - CLOCK_SKEW_SEC > now) {
        throw new Error("Token not yet valid");
      }
    }
    if (payload.iss !== this.issuer) {
      throw new Error(`Bad issuer: ${payload.iss}`);
    }
    const audList = Array.isArray(payload.aud) ? payload.aud : [payload.aud];
    if (!audList.includes(this.cfg.audience)) {
      throw new Error("Bad audience");
    }

    return {
      email: payload.email ?? "",
      sub: payload.sub ?? "",
    };
  }

  private async getKey(kid: string): Promise<KeyObject | null> {
    if (Date.now() - this.lastFetched > JWKS_TTL_MS) await this.refresh(false);
    return this.keys.get(kid) ?? null;
  }

  private async refresh(force: boolean): Promise<void> {
    if (!force && Date.now() - this.lastFetched < JWKS_TTL_MS) return;

    // Concurrent callers share a single outbound request. Without this, a burst
    // of tokens carrying unknown kids would each issue their own JWKS fetch.
    if (this.inflight) return this.inflight;

    if (force) {
      if (Date.now() - this.lastForcedRefresh < FORCED_REFRESH_MIN_INTERVAL_MS) {
        throw new Error("JWKS refresh rate-limited; rejecting unknown kid");
      }
      // Stamped before the fetch so a failing endpoint cannot be retried in a
      // tight loop either.
      this.lastForcedRefresh = Date.now();
    }

    // The in-flight promise is always cleared once settled, so a rejected fetch
    // is never cached and poisons no later call: the next caller retries.
    const pending = this.fetchKeys();
    this.inflight = pending;
    try {
      await pending;
    } finally {
      if (this.inflight === pending) this.inflight = null;
    }
  }

  private async fetchKeys(): Promise<void> {
    const url = `${this.issuer}/cdn-cgi/access/certs`;
    // A hung CF endpoint must not stall /authorize while we are holding the
    // user's submitted panel credentials, so the fetch is bounded.
    let res: Awaited<ReturnType<typeof fetch>>;
    try {
      res = await fetch(url, {
        signal: AbortSignal.timeout(JWKS_FETCH_TIMEOUT_MS),
      });
    } catch (err) {
      if (isAbortError(err)) {
        throw new Error(
          `JWKS fetch timed out after ${JWKS_FETCH_TIMEOUT_MS}ms`,
        );
      }
      const msg = err instanceof Error ? err.message : String(err);
      throw new Error(`JWKS fetch failed: ${msg}`);
    }
    if (!res.ok) throw new Error(`JWKS fetch failed: ${res.status}`);
    const doc = (await res.json()) as { keys: JWK[] };
    const next = new Map<string, KeyObject>();
    for (const jwk of doc.keys ?? []) {
      if (jwk.kty !== "RSA" || !jwk.kid) continue;
      try {
        const key = createPublicKey({ key: jwk as any, format: "jwk" });
        next.set(jwk.kid, key);
      } catch {
        // skip malformed key
      }
    }
    this.keys = next;
    this.lastFetched = Date.now();
  }
}

/**
 * fetch() surfaces an AbortSignal.timeout() as a DOMException whose name varies
 * across Node releases ("TimeoutError" or "AbortError"), sometimes only on the
 * wrapped `cause`, so both are checked.
 */
function isAbortError(err: unknown): boolean {
  const named = (e: unknown): boolean =>
    e instanceof Error && (e.name === "TimeoutError" || e.name === "AbortError");
  return named(err) || (err instanceof Error && named(err.cause));
}

function parseJsonB64Url(segment: string): any {
  return JSON.parse(Buffer.from(segment, "base64url").toString("utf8"));
}

/**
 * Extract the CF Access JWT from the request. CF sends it in a header;
 * browsers that went through the Access challenge also have it as a cookie.
 */
export function extractCFToken(req: import("node:http").IncomingMessage): string | null {
  const header = req.headers["cf-access-jwt-assertion"];
  if (typeof header === "string" && header) return header;
  const cookie = req.headers.cookie;
  if (!cookie) return null;
  for (const part of cookie.split(";")) {
    const [name, ...rest] = part.trim().split("=");
    if (name === "CF_Authorization") return rest.join("=");
  }
  return null;
}
