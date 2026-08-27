/**
 * HTTP server wrapper for MCP — enables remote deployment.
 *
 * Two auth modes:
 *   - "bearer"  single shared MCP_API_KEY, single EASYPANEL_TOKEN for all callers
 *   - "oauth"   per-user OAuth 2.1 flow, each user logs in with their Easypanel
 *                credentials and gets their own bound access token
 *
 * A new MCP session is bound to whatever EasyPanelClient the auth layer resolves.
 * In OAuth mode, if Easypanel rejects a call as unauthorized, we revoke the
 * bound OAuth tokens and drop any sessions using them so the client is forced
 * to re-authenticate.
 */

import { createServer } from "node:http";
import { createHash, timingSafeEqual } from "node:crypto";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { EasyPanelClient } from "./client.js";
import { OAuthHandler } from "./oauth/handler.js";
import { OAuthStore } from "./oauth/store.js";
import { CFAccessVerifier, type CFAccessConfig } from "./oauth/cf-access.js";

export interface HttpServerOptions {
  port: number;
  createMcpServer: (client: EasyPanelClient) => McpServer;
  easypanelUrl: string;
  authMode: "bearer" | "oauth";
  bearerApiKey?: string;
  bearerEasypanelToken?: string;
  oauthIssuer?: string;
  oauthStorePath?: string;
  /** Extra headers to attach to every backend Easypanel call (e.g. CF service tokens). */
  backendHeaders?: Record<string, string>;
  /** If set, /authorize POST will verify a Cloudflare Access JWT. */
  cfAccess?: CFAccessConfig;
}

interface SessionEntry {
  transport: StreamableHTTPServerTransport;
  server: McpServer;
  bearer?: string;
}

interface ResolvedAuth {
  client: EasyPanelClient;
  bearer?: string;
}

/**
 * Defensive cap on live MCP sessions. Clients that vanish without closing their
 * transport would otherwise grow the map without bound; refusing new sessions is
 * preferable to running the process out of memory.
 */
const MAX_SESSIONS = 1000;

export async function startHttpServer(opts: HttpServerOptions) {
  const sessions = new Map<string, SessionEntry>();
  /** OAuth mode only: bearer access_token -> set of session-ids created under it. */
  const bearerSessions = new Map<string, Set<string>>();

  let oauth: OAuthHandler | undefined;
  let store: OAuthStore | undefined;
  if (opts.authMode === "oauth") {
    if (!opts.oauthIssuer) {
      throw new Error("OAUTH_ISSUER_URL is required when EASYPANEL_AUTH_MODE=oauth");
    }
    store = new OAuthStore(opts.oauthStorePath ?? "./.easypanel-mcp-oauth.json");
    await store.load();
    const cfAccessVerifier = opts.cfAccess ? new CFAccessVerifier(opts.cfAccess) : undefined;
    oauth = new OAuthHandler({
      issuer: opts.oauthIssuer.replace(/\/+$/, ""),
      easypanelUrl: opts.easypanelUrl,
      store,
      backendHeaders: opts.backendHeaders,
      cfAccessVerifier,
      cfAccessRequireEmailMatch: opts.cfAccess?.requireEmailMatch,
    });
  }

  /** Drop a session from both maps; keeps bearerSessions from retaining empty sets. */
  function forgetSession(sid: string, entry: SessionEntry): void {
    sessions.delete(sid);
    if (!entry.bearer) return;
    const set = bearerSessions.get(entry.bearer);
    if (!set) return;
    set.delete(sid);
    if (set.size === 0) bearerSessions.delete(entry.bearer);
  }

  function revokeBearer(bearer: string): void {
    if (!store) return;
    store.revokeToken(bearer);
    const sids = bearerSessions.get(bearer);
    if (!sids) return;
    for (const sid of sids) {
      const entry = sessions.get(sid);
      if (entry) {
        try { entry.transport.close(); } catch { /* noop */ }
        sessions.delete(sid);
      }
    }
    bearerSessions.delete(bearer);
  }

  const logLevel = (process.env.LOG_LEVEL || "info").toLowerCase();
  const logAccess = logLevel !== "silent";
  const logDebug = logLevel === "debug";

  // Comma-separated exact-match Origin allowlist. Empty means "not configured".
  const allowedOrigins = (process.env.MCP_ALLOWED_ORIGINS || "")
    .split(",")
    .map((o) => o.trim())
    .filter((o) => o.length > 0);

  const bindHost = process.env.MCP_BIND_HOST || "0.0.0.0";

  const httpServer = createServer(async (req, res) => {
    const started = Date.now();
    // Never log req.url: API keys, OAuth authorization codes and other secrets
    // travel in query strings, and the access log is written at the default log
    // level. Only the pathname is safe to record.
    const pathname = requestPathname(req);

    try {
      if (logAccess) {
        const fwd = req.headers["x-forwarded-for"];
        const ip = (Array.isArray(fwd) ? fwd[0] : fwd)?.toString().split(",")[0].trim()
          || req.socket.remoteAddress || "-";
        const ua = req.headers["user-agent"] || "-";
        const origin = req.headers["origin"] || "-";
        res.on("finish", () => {
          const ms = Date.now() - started;
          console.log(`[${new Date().toISOString()}] ${req.method} ${pathname} ${res.statusCode} ${ms}ms ip=${ip} origin=${origin} ua="${ua}"`);
        });
        if (logDebug) {
          const SENSITIVE = new Set([
            "authorization",
            "cookie",
            "cf-access-jwt-assertion",
            "cf-access-client-id",
            "cf-access-client-secret",
            "proxy-authorization",
            "x-api-key",
            "x-forwarded-authorization",
          ]);
          const safe: Record<string, unknown> = {};
          for (const [k, v] of Object.entries(req.headers)) {
            safe[k] = SENSITIVE.has(k.toLowerCase()) ? "[redacted]" : v;
          }
          console.log(`[${new Date().toISOString()}] REQ headers:`, JSON.stringify(safe));
        }
      }

      // Origin handling. The MCP spec calls out Origin validation to defeat DNS
      // rebinding: a page in the victim's browser resolves an attacker domain to
      // this server's address and drives it with the victim's network position.
      // With MCP_ALLOWED_ORIGINS set we echo only allowlisted origins and refuse
      // anything else. Without it we keep the permissive "*" for backward
      // compatibility, but still refuse any request that carries an Origin that
      // is not loopback — real MCP clients are not browsers and send no Origin
      // header at all, so only a browser-driven (i.e. rebinding) caller is
      // affected.
      const reqOrigin = req.headers.origin;
      if (allowedOrigins.length > 0) {
        if (reqOrigin && allowedOrigins.includes(reqOrigin)) {
          res.setHeader("Access-Control-Allow-Origin", reqOrigin);
          res.setHeader("Vary", "Origin");
        } else if (reqOrigin) {
          res.writeHead(403, { "Content-Type": "application/json" });
          res.end(JSON.stringify({ error: "Origin not allowed." }));
          return;
        }
      } else if (reqOrigin && !isLoopbackOrigin(reqOrigin)) {
        res.writeHead(403, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ error: "Origin not allowed. Set MCP_ALLOWED_ORIGINS to permit browser origins." }));
        return;
      } else {
        res.setHeader("Access-Control-Allow-Origin", "*");
      }
      res.setHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS, DELETE");
      res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization, Mcp-Session-Id, Mcp-Protocol-Version");
      res.setHeader("Access-Control-Expose-Headers", "Mcp-Session-Id, WWW-Authenticate");

      if (req.method === "OPTIONS") {
        res.writeHead(204);
        res.end();
        return;
      }

      // Unauthenticated on purpose — container health checks depend on it — so it
      // must not disclose auth mode, session counts or any other configuration.
      if (pathname === "/health") {
        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ status: "ok" }));
        return;
      }

      if (oauth && await oauth.handle(req, res)) return;

      if (pathname !== "/mcp") {
        res.writeHead(404);
        res.end("Not found. MCP endpoint: /mcp");
        return;
      }

      const auth = resolveAuth(req, res, opts, store, revokeBearer);
      if (!auth) return;

      const sessionId = req.headers["mcp-session-id"] as string | undefined;

      if (sessionId && sessions.has(sessionId)) {
        const session = sessions.get(sessionId)!;
        if (opts.authMode === "oauth" && session.bearer && session.bearer !== auth.bearer) {
          // Session was created under a different bearer — don't let another
          // user's token reuse it.
          res.writeHead(401, { "Content-Type": "application/json" });
          res.end(JSON.stringify({ error: "Session does not belong to this token. Please reinitialize." }));
          return;
        }
        await session.transport.handleRequest(req, res);
        return;
      }

      if (sessionId && !sessions.has(sessionId)) {
        res.writeHead(404, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ error: "Session not found. Please reinitialize." }));
        return;
      }

      if (sessions.size >= MAX_SESSIONS) {
        console.error(`[${new Date().toISOString()}] Refusing new MCP session: session cap reached (${sessions.size}/${MAX_SESSIONS})`);
        res.writeHead(503, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ error: "Server at session capacity. Try again later." }));
        return;
      }

      const transport = new StreamableHTTPServerTransport({
        sessionIdGenerator: () => crypto.randomUUID(),
        onsessioninitialized: (id) => {
          sessions.set(id, { transport, server, bearer: auth.bearer });
          if (auth.bearer) {
            let set = bearerSessions.get(auth.bearer);
            if (!set) { set = new Set(); bearerSessions.set(auth.bearer, set); }
            set.add(id);
          }
          if (logAccess) console.log(`[${new Date().toISOString()}] MCP session opened: ${id}`);
        },
      });

      const server = opts.createMcpServer(auth.client);

      transport.onclose = () => {
        for (const [sid, entry] of sessions.entries()) {
          if (entry.transport !== transport) continue;
          forgetSession(sid, entry);
        }
      };

      await server.connect(transport);
      await transport.handleRequest(req, res);
    } catch (e) {
      // A malformed request must never take the process down: without this the
      // rejection from this async handler would be unhandled.
      const msg = e instanceof Error ? e.message : String(e);
      console.error(`[${new Date().toISOString()}] Request handler error on ${req.method} ${pathname}: ${msg}`);
      if (res.headersSent) {
        res.destroy();
        return;
      }
      res.writeHead(400, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ error: "Bad request" }));
    }
  });

  httpServer.listen(opts.port, bindHost, () => {
    console.log(`EasyPanel MCP server running at http://${bindHost}:${opts.port}/mcp`);
    console.log(`Bind host: ${bindHost}`);
    console.log(`Auth mode: ${opts.authMode}`);
    if (allowedOrigins.length > 0) {
      console.log(`Allowed origins: ${allowedOrigins.join(", ")}`);
    }
    if (opts.authMode === "oauth") {
      console.log(`OAuth issuer: ${opts.oauthIssuer}`);
    }
  });
}

/** Pathname of the request, with the query string (and any secrets in it) dropped. */
function requestPathname(req: import("node:http").IncomingMessage): string {
  try {
    return new URL(req.url || "/", `http://${req.headers.host || "localhost"}`).pathname;
  } catch {
    return "/";
  }
}

/**
 * Loopback origins are the only browser origins accepted when no allowlist is
 * configured: a rebinding attack always arrives with the attacker's own origin.
 */
function isLoopbackOrigin(origin: string): boolean {
  try {
    const host = new URL(origin).hostname.replace(/^\[|\]$/g, "");
    return host === "localhost"
      || host.endsWith(".localhost")
      || host === "::1"
      || /^127\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(host);
  } catch {
    return false;
  }
}

/**
 * Constant-time secret comparison. Digesting both sides first gives two buffers
 * of equal length, so timingSafeEqual can never throw on a length mismatch and
 * the length of the supplied key does not leak.
 */
function secretsMatch(a: string, b: string): boolean {
  const da = createHash("sha256").update(a, "utf8").digest();
  const db = createHash("sha256").update(b, "utf8").digest();
  return timingSafeEqual(da, db);
}

function resolveAuth(
  req: import("node:http").IncomingMessage,
  res: import("node:http").ServerResponse,
  opts: HttpServerOptions,
  store: OAuthStore | undefined,
  revokeBearer: (bearer: string) => void,
): ResolvedAuth | null {
  const authHeader = req.headers.authorization;
  const bearer = authHeader?.startsWith("Bearer ") ? authHeader.slice(7) : null;

  if (opts.authMode === "oauth") {
    if (!bearer) {
      sendUnauthorized(res, opts.oauthIssuer!, "missing_token");
      return null;
    }
    const token = store!.getAccessToken(bearer);
    if (!token) {
      sendUnauthorized(res, opts.oauthIssuer!, "invalid_token");
      return null;
    }
    const client = new EasyPanelClient(token.easypanel_url, token.easypanel_token, {
      onAuthFailure: () => revokeBearer(bearer),
      extraHeaders: opts.backendHeaders,
    });
    return { client, bearer };
  }

  // bearer mode. Fail closed: with no key configured there is nothing to check
  // against, and serving an authorized client would hand every anonymous caller
  // the operator's EASYPANEL_TOKEN. The Authorization header is the only
  // accepted form — a key in the query string ends up in proxy and access logs.
  const apiKey = opts.bearerApiKey?.trim() ? opts.bearerApiKey : null;
  if (!apiKey) {
    res.writeHead(401, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ error: "Server misconfigured: MCP_API_KEY is not set. Refusing all requests." }));
    return null;
  }
  if (!bearer || !secretsMatch(bearer, apiKey)) {
    res.writeHead(401, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ error: "Unauthorized. Set Authorization: Bearer <MCP_API_KEY>" }));
    return null;
  }
  const client = new EasyPanelClient(opts.easypanelUrl, opts.bearerEasypanelToken!, {
    extraHeaders: opts.backendHeaders,
  });
  return { client };
}

function sendUnauthorized(
  res: import("node:http").ServerResponse,
  issuer: string,
  reason: "missing_token" | "invalid_token" = "missing_token",
): void {
  // Matches the format produced by the reference TypeScript SDK's auth
  // middleware and Cloudflare's workers-oauth-provider, both of which are
  // verified working with Claude's connector. Includes realm, error,
  // error_description, and resource_metadata.
  const metadataUrl = `${issuer}/.well-known/oauth-protected-resource/mcp`;
  const errorCode = "invalid_token";
  const errorDesc = reason === "missing_token"
    ? "Missing Authorization header"
    : "Invalid or expired access token";
  res.setHeader(
    "WWW-Authenticate",
    `Bearer realm="OAuth", error="${errorCode}", error_description="${errorDesc}", resource_metadata="${metadataUrl}"`,
  );
  res.writeHead(401, { "Content-Type": "application/json" });
  res.end(JSON.stringify({ error: errorCode, error_description: errorDesc }));
}
