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
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { EasyPanelClient } from "./client.js";
import { OAuthHandler } from "./oauth/handler.js";
import { OAuthStore } from "./oauth/store.js";

export interface HttpServerOptions {
  port: number;
  createMcpServer: (client: EasyPanelClient) => McpServer;
  easypanelUrl: string;
  authMode: "bearer" | "oauth";
  bearerApiKey?: string;
  bearerEasypanelToken?: string;
  oauthIssuer?: string;
  oauthStorePath?: string;
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
    oauth = new OAuthHandler({
      issuer: opts.oauthIssuer.replace(/\/+$/, ""),
      easypanelUrl: opts.easypanelUrl,
      store,
    });
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

  const httpServer = createServer(async (req, res) => {
    res.setHeader("Access-Control-Allow-Origin", "*");
    res.setHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS, DELETE");
    res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization, Mcp-Session-Id");
    res.setHeader("Access-Control-Expose-Headers", "Mcp-Session-Id, WWW-Authenticate");

    if (req.method === "OPTIONS") {
      res.writeHead(204);
      res.end();
      return;
    }

    if (req.url === "/health") {
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify({
        status: "ok",
        tools: 40,
        auth_mode: opts.authMode,
        sessions: sessions.size,
      }));
      return;
    }

    if (oauth && await oauth.handle(req, res)) return;

    const pathname = new URL(req.url || "/", `http://${req.headers.host}`).pathname;
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

    const transport = new StreamableHTTPServerTransport({
      sessionIdGenerator: () => crypto.randomUUID(),
      onsessioninitialized: (id) => {
        sessions.set(id, { transport, server, bearer: auth.bearer });
        if (auth.bearer) {
          let set = bearerSessions.get(auth.bearer);
          if (!set) { set = new Set(); bearerSessions.set(auth.bearer, set); }
          set.add(id);
        }
      },
    });

    const server = opts.createMcpServer(auth.client);

    transport.onclose = () => {
      for (const [sid, entry] of sessions.entries()) {
        if (entry.transport !== transport) continue;
        sessions.delete(sid);
        if (entry.bearer) bearerSessions.get(entry.bearer)?.delete(sid);
      }
    };

    await server.connect(transport);
    await transport.handleRequest(req, res);
  });

  httpServer.listen(opts.port, "0.0.0.0", () => {
    console.log(`EasyPanel MCP server running at http://0.0.0.0:${opts.port}/mcp`);
    console.log(`Auth mode: ${opts.authMode}`);
    if (opts.authMode === "oauth") {
      console.log(`OAuth issuer: ${opts.oauthIssuer}`);
    }
  });
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
      sendUnauthorized(res, opts.oauthIssuer!);
      return null;
    }
    const token = store!.getAccessToken(bearer);
    if (!token) {
      sendUnauthorized(res, opts.oauthIssuer!, "invalid_token");
      return null;
    }
    const client = new EasyPanelClient(token.easypanel_url, token.easypanel_token, {
      onAuthFailure: () => revokeBearer(bearer),
    });
    return { client, bearer };
  }

  // bearer mode
  if (opts.bearerApiKey) {
    const url = new URL(req.url || "/", `http://${req.headers.host}`);
    const queryKey = url.searchParams.get("api_key");
    if (bearer !== opts.bearerApiKey && queryKey !== opts.bearerApiKey) {
      res.writeHead(401, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ error: "Unauthorized. Set Authorization: Bearer <MCP_API_KEY>" }));
      return null;
    }
  }
  const client = new EasyPanelClient(opts.easypanelUrl, opts.bearerEasypanelToken!);
  return { client };
}

function sendUnauthorized(
  res: import("node:http").ServerResponse,
  issuer: string,
  errorCode: "invalid_token" | "" = "",
): void {
  const metadataUrl = `${issuer}/.well-known/oauth-protected-resource`;
  const parts = [`Bearer realm="mcp"`, `resource_metadata="${metadataUrl}"`];
  if (errorCode) parts.push(`error="${errorCode}"`);
  res.setHeader("WWW-Authenticate", parts.join(", "));
  res.writeHead(401, { "Content-Type": "application/json" });
  res.end(JSON.stringify({
    error: "unauthorized",
    error_description: "Obtain an access token via the OAuth flow.",
    resource_metadata: metadataUrl,
  }));
}
