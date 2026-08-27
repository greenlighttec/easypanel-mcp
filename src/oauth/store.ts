/**
 * OAuth 2.1 storage: clients, authorization codes, access/refresh tokens.
 *
 * Persists to a JSON file so tokens survive restarts. In-memory cache is
 * the source of truth; disk is a write-through backup.
 *
 * This is a single-tenant-ish store: small deployments only. If you ever
 * need horizontal scaling, swap this for Redis.
 *
 * Every map here is a null-prototype object and every lookup is guarded with
 * Object.hasOwn. A plain object literal would resolve keys like "constructor"
 * or "toString" through Object.prototype and hand a forged entry back to the
 * caller, which for a bearer token means an unauthenticated remote crash.
 */

import { randomBytes, createHash } from "node:crypto";
import { promises as fs } from "node:fs";
import path from "node:path";

export interface OAuthClient {
  client_id: string;
  client_secret?: string;
  client_name?: string;
  redirect_uris: string[];
  token_endpoint_auth_method: "none" | "client_secret_post" | "client_secret_basic";
  created_at: number;
  /**
   * True for clients created through RFC 7591 dynamic registration, which is
   * open to anyone. The consent screen warns the user about these.
   */
  dynamically_registered?: boolean;
}

export interface AuthCode {
  code: string;
  client_id: string;
  redirect_uri: string;
  code_challenge: string;
  code_challenge_method: "S256";
  scope?: string;
  easypanel_token: string;
  easypanel_url: string;
  user_email: string;
  expires_at: number;
}

/**
 * An /authorize request parked server-side while the user authenticates.
 * The login page only carries the opaque id, so the OAuth parameters cannot
 * be swapped between rendering the consent screen and submitting it.
 */
export interface PendingAuthorization {
  id: string;
  client_id: string;
  redirect_uri: string;
  state?: string;
  code_challenge: string;
  code_challenge_method: string;
  scope?: string;
  expires_at: number;
}

export interface AccessToken {
  access_token: string;
  refresh_token: string;
  client_id: string;
  scope?: string;
  easypanel_token: string;
  easypanel_url: string;
  user_email: string;
  expires_at: number;
  /** After this the refresh token is dead too and the whole record is swept. */
  refresh_expires_at: number;
  /** Rotation lineage: every token minted from one login shares this id. */
  family_id: string;
}

/** A refresh token that has been rotated away. Replaying one is a breach signal. */
interface RetiredRefresh {
  family_id: string;
  retired_at: number;
}

interface StoreData {
  clients: Record<string, OAuthClient>;
  codes: Record<string, AuthCode>;
  tokens: Record<string, AccessToken>;
  refresh_index: Record<string, string>;
  pending: Record<string, PendingAuthorization>;
  retired_refresh: Record<string, RetiredRefresh>;
}

const CODE_TTL_MS = 10 * 60 * 1000;
const ACCESS_TTL_MS = 60 * 60 * 1000;
/**
 * How long a refresh token stays usable. The record holds a plaintext Easypanel
 * session, so this is deliberately short - it replaces the old 30-day retention
 * window that kept dead sessions on disk for a month.
 */
const REFRESH_TTL_MS = 24 * 60 * 60 * 1000;
const PENDING_TTL_MS = 10 * 60 * 1000;
/** Hard cap so unauthenticated GET /authorize traffic cannot grow the store. */
const MAX_PENDING = 500;
const SWEEP_INTERVAL_MS = 5 * 60 * 1000;
/** Reuse detection window, and a hard cap so the retired set cannot grow forever. */
const RETIRED_REFRESH_TTL_MS = 7 * 24 * 60 * 60 * 1000;
const MAX_RETIRED_REFRESH = 1000;

/** Null-prototype map: a miss must be a miss, even for "constructor"/"__proto__". */
function emptyMap<T>(): Record<string, T> {
  return Object.create(null) as Record<string, T>;
}

function emptyData(): StoreData {
  return {
    clients: emptyMap<OAuthClient>(),
    codes: emptyMap<AuthCode>(),
    tokens: emptyMap<AccessToken>(),
    refresh_index: emptyMap<string>(),
    pending: emptyMap<PendingAuthorization>(),
    retired_refresh: emptyMap<RetiredRefresh>(),
  };
}

/**
 * JSON.parse yields ordinary prototyped objects, so hydrated state has to be
 * copied key by key into a null-prototype map rather than assigned wholesale.
 */
function copyOwn<T>(target: Record<string, T>, source: unknown): void {
  if (!source || typeof source !== "object") return;
  for (const [k, v] of Object.entries(source as Record<string, T>)) {
    target[k] = v;
  }
}

export class OAuthStore {
  private data: StoreData = emptyData();
  private writeQueue: Promise<void> = Promise.resolve();
  /** Set while a write is queued but has not started; shared by later callers. */
  private queuedWrite?: Promise<void>;
  private sweepTimer?: NodeJS.Timeout;

  constructor(private readonly storePath: string) {}

  async load(): Promise<void> {
    try {
      const raw = await fs.readFile(this.storePath, "utf8");
      const parsed = JSON.parse(raw) as Partial<StoreData> | null;
      const fresh = emptyData();
      if (parsed && typeof parsed === "object") {
        copyOwn(fresh.clients, parsed.clients);
        copyOwn(fresh.codes, parsed.codes);
        copyOwn(fresh.tokens, parsed.tokens);
        copyOwn(fresh.refresh_index, parsed.refresh_index);
        copyOwn(fresh.pending, parsed.pending);
        copyOwn(fresh.retired_refresh, parsed.retired_refresh);
      }
      this.data = fresh;
      this.upgradeLegacyTokens();
    } catch (e: any) {
      if (e.code !== "ENOENT") throw e;
    }
    if (this.sweep()) await this.persist();
    this.startSweeper();
  }

  /** State written by older builds has no rotation family and no refresh expiry. */
  private upgradeLegacyTokens(): void {
    for (const key of Object.keys(this.data.tokens)) {
      const entry = this.data.tokens[key];
      if (!entry.family_id) entry.family_id = randomBytes(16).toString("hex");
      if (typeof entry.refresh_expires_at !== "number") entry.refresh_expires_at = entry.expires_at;
    }
  }

  /**
   * Serializes writes through a single chain so two concurrent callers never
   * interleave temp-file writes to the same path. The returned promise settles
   * once this state is on disk, so credential-issuing paths can await it.
   *
   * Callers arriving while a write is queued but not yet started share it: that
   * write snapshots the data when it runs, so it already contains their change.
   * Without the sharing, a burst of requests would queue one full snapshot each.
   */
  private persist(): Promise<void> {
    if (this.queuedWrite) return this.queuedWrite;
    const next = this.writeQueue
      .then(async () => {
        this.queuedWrite = undefined;
        const snapshot = JSON.stringify(this.data);
        await fs.mkdir(path.dirname(this.storePath), { recursive: true });
        const tmp = `${this.storePath}.tmp`;
        await fs.writeFile(tmp, snapshot, { mode: 0o600 });
        await fs.rename(tmp, this.storePath);
      })
      .catch((err) => {
        console.error("OAuth store persist failed:", err);
      });
    this.queuedWrite = next;
    this.writeQueue = next;
    return next;
  }

  /** Unref'd so the periodic sweep never keeps the process alive on its own. */
  private startSweeper(): void {
    if (this.sweepTimer) return;
    this.sweepTimer = setInterval(() => {
      if (this.sweep()) void this.persist();
    }, SWEEP_INTERVAL_MS);
    this.sweepTimer.unref();
  }

  /** Drops everything past its lifetime. Returns true if anything was removed. */
  private sweep(): boolean {
    const now = Date.now();
    let changed = false;

    for (const [k, v] of Object.entries(this.data.codes)) {
      if (v.expires_at < now) {
        delete this.data.codes[k];
        changed = true;
      }
    }
    for (const [k, v] of Object.entries(this.data.pending)) {
      if (v.expires_at < now) {
        delete this.data.pending[k];
        changed = true;
      }
    }
    // A token record is only kept while its refresh token can still be used;
    // past that it is just a plaintext Easypanel session sitting on disk.
    for (const [k, v] of Object.entries(this.data.tokens)) {
      if (v.refresh_expires_at < now) {
        delete this.data.tokens[k];
        delete this.data.refresh_index[v.refresh_token];
        changed = true;
      }
    }
    for (const [k, v] of Object.entries(this.data.retired_refresh)) {
      if (v.retired_at + RETIRED_REFRESH_TTL_MS < now) {
        delete this.data.retired_refresh[k];
        changed = true;
      }
    }
    // Index entries whose token is gone (e.g. removed by an older build).
    for (const [rt, at] of Object.entries(this.data.refresh_index)) {
      if (!Object.hasOwn(this.data.tokens, at)) {
        delete this.data.refresh_index[rt];
        changed = true;
      }
    }
    return changed;
  }

  async registerClient(input: {
    client_name?: string;
    redirect_uris: string[];
    token_endpoint_auth_method?: OAuthClient["token_endpoint_auth_method"];
  }): Promise<OAuthClient> {
    const client: OAuthClient = {
      client_id: randomBytes(16).toString("hex"),
      client_name: input.client_name,
      redirect_uris: input.redirect_uris,
      token_endpoint_auth_method: input.token_endpoint_auth_method ?? "none",
      created_at: Date.now(),
      dynamically_registered: true,
    };
    if (client.token_endpoint_auth_method !== "none") {
      client.client_secret = randomBytes(32).toString("hex");
    }
    this.data.clients[client.client_id] = client;
    await this.persist();
    return client;
  }

  getClient(client_id: string): OAuthClient | undefined {
    if (!Object.hasOwn(this.data.clients, client_id)) return undefined;
    return this.data.clients[client_id];
  }

  /** Parks an /authorize request under an unguessable id until the user logs in. */
  async createPendingAuth(input: Omit<PendingAuthorization, "id" | "expires_at">): Promise<string> {
    const id = randomBytes(32).toString("base64url");
    this.data.pending[id] = {
      ...input,
      id,
      expires_at: Date.now() + PENDING_TTL_MS,
    };
    this.trimPending();
    await this.persist();
    return id;
  }

  /** Non-destructive read, used to re-render the consent screen after a bad login. */
  getPendingAuth(id: string): PendingAuthorization | undefined {
    if (!Object.hasOwn(this.data.pending, id)) return undefined;
    const entry = this.data.pending[id];
    if (entry.expires_at < Date.now()) return undefined;
    return entry;
  }

  consumePendingAuth(id: string): PendingAuthorization | undefined {
    if (!Object.hasOwn(this.data.pending, id)) return undefined;
    const entry = this.data.pending[id];
    delete this.data.pending[id];
    void this.persist();
    if (entry.expires_at < Date.now()) return undefined;
    return entry;
  }

  async createAuthCode(input: Omit<AuthCode, "code" | "expires_at">): Promise<string> {
    const code = randomBytes(32).toString("base64url");
    this.data.codes[code] = {
      ...input,
      code,
      expires_at: Date.now() + CODE_TTL_MS,
    };
    await this.persist();
    return code;
  }

  consumeAuthCode(code: string): AuthCode | undefined {
    if (!Object.hasOwn(this.data.codes, code)) return undefined;
    const entry = this.data.codes[code];
    delete this.data.codes[code];
    // Not awaited: the caller immediately issues tokens, and that write is
    // awaited on the same queue, so this deletion reaches disk with it.
    void this.persist();
    if (entry.expires_at < Date.now()) return undefined;
    return entry;
  }

  async issueTokens(input: {
    client_id: string;
    scope?: string;
    easypanel_token: string;
    easypanel_url: string;
    user_email: string;
    /** Set when rotating, so the new token stays in its predecessor's family. */
    family_id?: string;
  }): Promise<AccessToken> {
    const access_token = randomBytes(32).toString("base64url");
    const refresh_token = randomBytes(32).toString("base64url");
    const now = Date.now();
    const entry: AccessToken = {
      access_token,
      refresh_token,
      client_id: input.client_id,
      scope: input.scope,
      easypanel_token: input.easypanel_token,
      easypanel_url: input.easypanel_url,
      user_email: input.user_email,
      expires_at: now + ACCESS_TTL_MS,
      refresh_expires_at: now + REFRESH_TTL_MS,
      family_id: input.family_id ?? randomBytes(16).toString("hex"),
    };
    this.data.tokens[access_token] = entry;
    this.data.refresh_index[refresh_token] = access_token;
    await this.persist();
    return entry;
  }

  getAccessToken(access_token: string): AccessToken | undefined {
    if (!Object.hasOwn(this.data.tokens, access_token)) return undefined;
    const entry = this.data.tokens[access_token];
    if (entry.expires_at < Date.now()) return undefined;
    return entry;
  }

  async rotateRefreshToken(refresh_token: string, client_id: string): Promise<AccessToken | undefined> {
    // OAuth 2.1 reuse detection: a refresh token we already rotated away must
    // never work again. Seeing one means it leaked, so the entire family dies.
    if (Object.hasOwn(this.data.retired_refresh, refresh_token)) {
      const retired = this.data.retired_refresh[refresh_token];
      console.error(`OAuth refresh token reuse detected; revoking token family ${retired.family_id}`);
      await this.revokeFamily(retired.family_id);
      return undefined;
    }

    if (!Object.hasOwn(this.data.refresh_index, refresh_token)) return undefined;
    const existingAccess = this.data.refresh_index[refresh_token];
    if (!Object.hasOwn(this.data.tokens, existingAccess)) return undefined;
    const prior = this.data.tokens[existingAccess];
    if (prior.client_id !== client_id) return undefined;
    if (prior.refresh_expires_at < Date.now()) return undefined;

    delete this.data.tokens[existingAccess];
    delete this.data.refresh_index[refresh_token];
    this.retireRefreshToken(refresh_token, prior.family_id);

    return this.issueTokens({
      client_id: prior.client_id,
      scope: prior.scope,
      easypanel_token: prior.easypanel_token,
      easypanel_url: prior.easypanel_url,
      user_email: prior.user_email,
      family_id: prior.family_id,
    });
  }

  async revokeToken(token: string): Promise<void> {
    // Accepts an access token, a live refresh token, or an already-retired one.
    let family_id: string | undefined;
    if (Object.hasOwn(this.data.tokens, token)) {
      family_id = this.data.tokens[token].family_id;
    } else if (Object.hasOwn(this.data.refresh_index, token)) {
      const access = this.data.refresh_index[token];
      if (Object.hasOwn(this.data.tokens, access)) {
        family_id = this.data.tokens[access].family_id;
      } else {
        delete this.data.refresh_index[token];
        await this.persist();
        return;
      }
    } else if (Object.hasOwn(this.data.retired_refresh, token)) {
      family_id = this.data.retired_refresh[token].family_id;
    }
    if (!family_id) return;
    await this.revokeFamily(family_id);
  }

  /** Drops every token minted from one login, live and retired alike. */
  private async revokeFamily(family_id: string): Promise<void> {
    for (const [k, v] of Object.entries(this.data.tokens)) {
      if (v.family_id !== family_id) continue;
      delete this.data.tokens[k];
      delete this.data.refresh_index[v.refresh_token];
    }
    for (const [k, v] of Object.entries(this.data.retired_refresh)) {
      if (v.family_id === family_id) delete this.data.retired_refresh[k];
    }
    await this.persist();
  }

  /** Oldest-first eviction; /authorize is unauthenticated, so this must be bounded. */
  private trimPending(): void {
    const keys = Object.keys(this.data.pending);
    if (keys.length <= MAX_PENDING) return;
    keys.sort((a, b) => this.data.pending[a].expires_at - this.data.pending[b].expires_at);
    for (const k of keys.slice(0, keys.length - MAX_PENDING)) {
      delete this.data.pending[k];
    }
  }

  private retireRefreshToken(refresh_token: string, family_id: string): void {
    this.data.retired_refresh[refresh_token] = { family_id, retired_at: Date.now() };
    const keys = Object.keys(this.data.retired_refresh);
    if (keys.length <= MAX_RETIRED_REFRESH) return;
    // Oldest-first eviction keeps the reuse-detection set bounded.
    keys.sort((a, b) => this.data.retired_refresh[a].retired_at - this.data.retired_refresh[b].retired_at);
    for (const k of keys.slice(0, keys.length - MAX_RETIRED_REFRESH)) {
      delete this.data.retired_refresh[k];
    }
  }
}

export function sha256Base64Url(input: string): string {
  return createHash("sha256").update(input).digest("base64url");
}
