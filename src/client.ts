import http from "node:http";
import https from "node:https";

export interface EasyPanelClientOptions {
  /**
   * Invoked when the Easypanel API rejects a call as unauthenticated/forbidden
   * (HTTP 401/403 or tRPC code UNAUTHORIZED/FORBIDDEN). Fire-and-forget; used
   * by the OAuth layer to revoke the bound access+refresh token so the next
   * MCP call forces a re-login.
   */
  onAuthFailure?: () => void;
  /**
   * Extra headers to send on every request. Intended for things like
   * Cloudflare Access service tokens (CF-Access-Client-Id / CF-Access-Client-Secret)
   * so the shim can reach an Easypanel API that sits behind CF Zero Trust.
   */
  extraHeaders?: Record<string, string>;
}

export class EasyPanelClient {
  private baseUrl: string;
  private token: string | null = null;
  private onAuthFailure?: () => void;
  private extraHeaders: Record<string, string>;

  constructor(baseUrl: string, token?: string, opts?: EasyPanelClientOptions) {
    this.baseUrl = baseUrl.replace(/\/+$/, "");
    this.token = token ?? null;
    this.onAuthFailure = opts?.onAuthFailure;
    this.extraHeaders = opts?.extraHeaders ?? {};
  }

  async login(email: string, password: string): Promise<string> {
    const result = await this.mutation("auth.login", { email, password });
    this.token = result.token as string;
    return this.token;
  }

  /**
   * Authenticate against Easypanel's login endpoint and return the unwrapped
   * payload — e.g. `{ token }` on success, or `{ twoFactorEnabled: true }` when
   * the account has 2FA and no (valid) code was supplied yet.
   *
   * Easypanel serves login at `POST /api/rpc/auth/login` (slash-separated,
   * `rpc` not `trpc`) with a `{ json: <input> }` body and a `{ json: <output> }`
   * response envelope — a different scheme from the `/api/trpc/<router>.<proc>`
   * tool API. We also tolerate the legacy tRPC envelope so this keeps working
   * if the endpoint is ever served either way.
   */
  authLogin(email: string, password: string, code?: string): Promise<any> {
    const input: Record<string, unknown> = { email, password };
    if (code) input.code = code;
    const url = new URL(`${this.baseUrl}/api/rpc/auth/login`);
    const mod = url.protocol === "https:" ? https : http;
    const bodyStr = JSON.stringify({ json: input });

    return new Promise((resolve, reject) => {
      const headers: Record<string, string> = {
        "Content-Type": "application/json",
        "Content-Length": Buffer.byteLength(bodyStr).toString(),
        ...this.extraHeaders,
      };
      const req = mod.request(url, { method: "POST", headers }, (res) => {
        const status = res.statusCode ?? 0;
        let data = "";
        res.on("data", (chunk) => (data += chunk));
        res.on("end", () => {
          let parsed: any;
          try {
            parsed = data ? JSON.parse(data) : undefined;
          } catch {
            reject(new Error(`auth login returned a non-JSON response (HTTP ${status}) from ${url.pathname} — likely an intermediary (proxy/gateway) rather than Easypanel. Body: ${data.slice(0, 300)}`));
            return;
          }
          // rpc envelope: { json: <data>, meta? }. Fall back to legacy tRPC
          // ({ result: { data: { json } } }) and to a bare object.
          const payload =
            parsed?.json !== undefined ? parsed.json
            : parsed?.result?.data?.json !== undefined ? parsed.result.data.json
            : parsed;
          // An error envelope, or a 4xx/5xx that carries no usable payload.
          const errEnvelope = parsed?.error ?? parsed?.json?.error;
          const usable = payload && (payload.token !== undefined || payload.twoFactorEnabled !== undefined);
          if (errEnvelope || (status >= 400 && !usable)) {
            const msg = errEnvelope?.message ?? errEnvelope?.json?.message ?? `HTTP ${status}`;
            reject(new Error(`auth login rejected: ${msg}. Response: ${JSON.stringify(parsed).slice(0, 300)}`));
            return;
          }
          resolve(payload);
        });
      });
      req.on("error", reject);
      req.write(bodyStr);
      req.end();
    });
  }

  async query(procedure: string, input?: Record<string, unknown>): Promise<unknown> {
    let url = `${this.baseUrl}/api/trpc/${procedure}`;
    if (input) {
      url += `?input=${encodeURIComponent(JSON.stringify({ json: input }))}`;
    }
    return this.request("GET", url);
  }

  async mutation(procedure: string, input: Record<string, unknown>): Promise<any> {
    const url = `${this.baseUrl}/api/trpc/${procedure}`;
    return this.request("POST", url, { json: input });
  }

  private fireAuthFailure(): void {
    if (!this.onAuthFailure) return;
    try { this.onAuthFailure(); } catch { /* swallow */ }
  }

  private request(method: string, url: string, body?: unknown): Promise<any> {
    return new Promise((resolve, reject) => {
      const parsed = new URL(url);
      const mod = parsed.protocol === "https:" ? https : http;
      const headers: Record<string, string> = {
        "Content-Type": "application/json",
        ...this.extraHeaders,
      };
      if (this.token) {
        headers["Authorization"] = `Bearer ${this.token}`;
      }
      const bodyStr = body ? JSON.stringify(body) : undefined;
      if (bodyStr) headers["Content-Length"] = Buffer.byteLength(bodyStr).toString();

      const req = mod.request(parsed, { method, headers }, (res) => {
        const status = res.statusCode ?? 0;
        let data = "";
        res.on("data", (chunk) => (data += chunk));
        res.on("end", () => {
          const httpAuthFailed = status === 401 || status === 403;

          let parsed: any;
          try {
            parsed = data ? JSON.parse(data) : undefined;
          } catch {
            if (httpAuthFailed) this.fireAuthFailure();
            // A non-JSON body on a 401/403 is almost always an upstream gateway
            // (e.g. a Cloudflare Access challenge/redirect page), not Easypanel.
            reject(new Error(httpAuthFailed
              ? `Backend rejected with HTTP ${status} and a non-JSON body. Easypanel's tRPC layer returns JSON, so this is an intermediary (proxy/gateway such as Cloudflare Access) rather than Easypanel itself. Body: ${data.slice(0, 300)}`
              : `Invalid response (HTTP ${status}): ${data.slice(0, 500)}`));
            return;
          }

          // tRPC batches ([{...}]) when the client uses batching; unwrap the
          // first entry so a batched envelope isn't mistaken for a bare payload.
          const env = Array.isArray(parsed) ? parsed[0] : parsed;

          const trpcCode =
            env?.error?.json?.data?.code ??
            env?.error?.data?.code ??
            env?.error?.code;
          const trpcAuthFailed = trpcCode === "UNAUTHORIZED" || trpcCode === "FORBIDDEN";
          if (httpAuthFailed || trpcAuthFailed) this.fireAuthFailure();

          if (env?.error) {
            const msg = env.error?.json?.message ?? env.error?.message ?? JSON.stringify(env.error);
            reject(new Error(`tRPC error: ${msg}`));
            return;
          }

          // Success envelope: superjson nests the value under result.data.json;
          // a plain (transformer-less) tRPC response puts it at result.data.
          const dataNode = env?.result?.data;
          if (dataNode !== undefined) {
            resolve(dataNode?.json !== undefined ? dataNode.json : dataNode);
            return;
          }

          // No recognizable tRPC envelope. On a 401/403 this is a gateway
          // rejection (e.g. an expired Cloudflare Access service token) that
          // never reached Easypanel — surface it instead of returning a
          // tokenless "success" that later reads as "Login returned no token".
          if (httpAuthFailed) {
            reject(new Error(`Backend rejected with HTTP ${status} and no tRPC envelope. Easypanel's tRPC layer returns an {error} or {result} envelope, so a bare ${status} points at an intermediary (proxy/gateway) rather than Easypanel itself. Body: ${JSON.stringify(parsed).slice(0, 300)}`));
            return;
          }

          resolve(parsed);
        });
      });
      req.on("error", reject);
      if (bodyStr) req.write(bodyStr);
      req.end();
    });
  }
}
