/**
 * HTTP server wrapper for MCP — enables remote deployment.
 *
 * Two auth modes:
 *   - "bearer"  single shared MCP_API_KEY, single EASYPANEL_TOKEN for all callers
 *   - "oauth"   per-user OAuth 2.1 flow, each user logs in with their Easypanel
 *                credentials and gets their own bound access token
 *
 * A new MCP session is bound to whatever EasyPanelClient the auth layer resolves.
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

export async function startHttpServer(opts: HttpServerOptions) {
  const sessions = new Map<
    string,
    { transport: StreamableHTTPServerTransport; server: McpServer }
  >();

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

    // Resolve caller's EasyPanelClient from Authorization.
    const client = resolveClient(req, res, opts, store);
    if (!client) return;

    const sessionId = req.headers["mcp-session-id"] as string | undefined;

    if (sessionId && sessions.has(sessionId)) {
      const session = sessions.get(sessionId)!;
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
        sessions.set(id, { transport, server });
      },
    });

    const server = opts.createMcpServer(client);

    transport.onclose = () => {
      const id = [...sessions.entries()].find(([, v]) => v.transport === transport)?.[0];
      if (id) sessions.delete(id);
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

function resolveClient(
  req: import("node:http").IncomingMessage,
  res: import("node:http").ServerResponse,
  opts: HttpServerOptions,
  store: OAuthStore | undefined,
): EasyPanelClient | null {
  const auth = req.headers.authorization;
  const bearer = auth?.startsWith("Bearer ") ? auth.slice(7) : null;

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
    return new EasyPanelClient(token.easypanel_url, token.easypanel_token);
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
  return new EasyPanelClient(opts.easypanelUrl, opts.bearerEasypanelToken!);
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
