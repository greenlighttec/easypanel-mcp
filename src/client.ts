import http from "node:http";
import https from "node:https";

/** Default per-request timeout; overridable with EASYPANEL_TIMEOUT_MS. */
const DEFAULT_TIMEOUT_MS = 30_000;

/** Hard cap on a single response body, so a hostile panel cannot exhaust memory. */
const MAX_RESPONSE_BYTES = 32 * 1024 * 1024;

/**
 * A tRPC procedure is a dotted path of identifiers ("projects.listWithServices").
 * Anything else — most importantly ".." segments or slashes — must never reach the
 * URL, because the procedure string is model-controlled via the trpc_raw tool and
 * the request carries the Authorization header.
 */
const PROCEDURE_PATTERN = /^[A-Za-z][A-Za-z0-9_]*(\.[A-Za-z][A-Za-z0-9_]*)+$/;

/**
 * EASYPANEL_TIMEOUT_MS is operator-supplied and may be empty or garbage; anything
 * that is not a positive finite number falls back to the default.
 */
function resolveTimeoutMs(): number {
  const raw = process.env.EASYPANEL_TIMEOUT_MS;
  if (raw === undefined) return DEFAULT_TIMEOUT_MS;
  const parsed = Number(raw);
  if (!Number.isFinite(parsed) || parsed <= 0) return DEFAULT_TIMEOUT_MS;
  return parsed;
}

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

  async query(procedure: string, input?: Record<string, unknown>): Promise<unknown> {
    this.assertProcedure(procedure);
    let url = `${this.baseUrl}/api/trpc/${procedure}`;
    if (input) {
      url += `?input=${encodeURIComponent(JSON.stringify({ json: input }))}`;
    }
    return this.request("GET", url, procedure);
  }

  async mutation(procedure: string, input: Record<string, unknown>): Promise<any> {
    this.assertProcedure(procedure);
    const url = `${this.baseUrl}/api/trpc/${procedure}`;
    return this.request("POST", url, procedure, { json: input });
  }

  /**
   * Rejects anything that would escape /api/trpc/ once interpolated into the path
   * (traversal, slashes, query/fragment injection). Called by query() and mutation()
   * before the URL is built; both are async, so the throw surfaces as a rejection.
   */
  private assertProcedure(procedure: string): void {
    if (!PROCEDURE_PATTERN.test(procedure)) {
      throw new Error(
        `Invalid procedure name: ${JSON.stringify(procedure)}. ` +
          `Expected a dotted tRPC path such as "projects.listWithServices".`,
      );
    }
  }

  private fireAuthFailure(): void {
    if (!this.onAuthFailure) return;
    try { this.onAuthFailure(); } catch { /* swallow */ }
  }

  private request(method: string, url: string, procedure: string, body?: unknown): Promise<any> {
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

      // Single settle path: the timeout, the "error" event and the response can all
      // fire for one request (destroying a request emits "error"), so the first one
      // wins and the timer is always cleared — otherwise the process cannot exit.
      const timeoutMs = resolveTimeoutMs();
      let settled = false;
      let timer: NodeJS.Timeout | undefined;
      const settle = (fn: () => void): void => {
        if (settled) return;
        settled = true;
        if (timer !== undefined) {
          clearTimeout(timer);
          timer = undefined;
        }
        fn();
      };
      const succeed = (value: unknown): void => settle(() => resolve(value));
      const fail = (error: Error): void => settle(() => reject(error));

      const req = mod.request(parsed, { method, headers }, (res) => {
        const status = res.statusCode ?? 0;
        // Decode as UTF-8 at the stream level: concatenating raw Buffers as strings
        // corrupts any multi-byte character that straddles a chunk boundary.
        res.setEncoding("utf8");
        let data = "";
        let bytes = 0;
        res.on("data", (chunk: string) => {
          bytes += Buffer.byteLength(chunk, "utf8");
          if (bytes > MAX_RESPONSE_BYTES) {
            req.destroy();
            fail(new Error(
              `Response too large for ${procedure}: exceeded ${MAX_RESPONSE_BYTES} bytes`,
            ));
            return;
          }
          data += chunk;
        });
        res.on("error", (err: Error) => fail(err));
        res.on("end", () => {
          if (settled) return;
          const httpAuthFailed = status === 401 || status === 403;

          let json: unknown;
          let jsonParsed = false;
          try {
            json = JSON.parse(data);
            jsonParsed = true;
          } catch { /* not JSON; handled below */ }

          // Only an object body can carry a tRPC envelope.
          const envelope =
            jsonParsed && json !== null && typeof json === "object"
              ? (json as Record<string, any>)
              : undefined;

          const trpcCode =
            envelope?.error?.json?.data?.code ??
            envelope?.error?.data?.code ??
            envelope?.error?.code;
          const trpcAuthFailed = trpcCode === "UNAUTHORIZED" || trpcCode === "FORBIDDEN";
          if (httpAuthFailed || trpcAuthFailed) this.fireAuthFailure();

          // A tRPC error envelope carries a far more useful message than the bare
          // status line, so it wins even when the status is itself an error.
          if (envelope?.error) {
            const msg =
              envelope.error?.json?.message ?? envelope.error?.message ?? JSON.stringify(envelope.error);
            fail(new Error(`tRPC error: ${msg}`));
            return;
          }

          // Redirects are never followed: replaying the Authorization header to
          // another origin would leak the token. This is what an operator sees when
          // EASYPANEL_URL is http:// on a panel that redirects to https://.
          if (status >= 300 && status < 400) {
            const location = res.headers.location;
            fail(new Error(
              `HTTP ${status} redirect for ${procedure}` +
                (location ? ` to ${location}` : "") +
                `. Redirects are not followed; set EASYPANEL_URL to ${location ?? "the redirect target"}.`,
            ));
            return;
          }

          if (status >= 400) {
            fail(new Error(`HTTP ${status} for ${procedure}: ${data.slice(0, 200)}`));
            return;
          }

          // A null body used to throw on property access and land in the catch below;
          // keep it an invalid response.
          if (!jsonParsed || json === null) {
            fail(new Error(`Invalid response: ${data.slice(0, 500)}`));
            return;
          }
          if (!envelope) {
            succeed(json);
            return;
          }

          if (envelope.result !== undefined) {
            const result = envelope.result;
            const payload =
              result !== null && typeof result === "object"
                ? (result as Record<string, unknown>).data
                : undefined;
            // "json" present means a real value — including null, false or 0. Absent
            // means a void procedure, whose transport envelope must not leak out.
            if (payload !== null && typeof payload === "object" && "json" in payload) {
              succeed((payload as Record<string, unknown>).json);
            } else {
              succeed(null);
            }
            return;
          }

          succeed(envelope);
        });
      });
      req.on("error", (err: Error) => fail(err));

      timer = setTimeout(() => {
        req.destroy();
        fail(new Error(`Request timed out after ${timeoutMs}ms: ${procedure}`));
      }, timeoutMs);

      if (bodyStr) req.write(bodyStr);
      req.end();
    });
  }
}
