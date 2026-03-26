import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { isInitializeRequest } from "@modelcontextprotocol/sdk/types.js";
import express from "express";
import type http from "http";
import crypto from "crypto";
import { TokenManager } from "../auth/tokenManager.js";
import { CalendarRegistry } from "../services/CalendarRegistry.js";
import { renderAuthSuccess, renderAuthError, loadWebFile } from "../web/templates.js";

/**
 * Security headers for HTML responses
 * Note: HTTP mode is designed for localhost development/testing only.
 * For production deployments, use stdio mode with Claude Desktop.
 */
const SECURITY_HEADERS = {
  'Content-Security-Policy': "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; frame-ancestors 'none'",
  'X-Frame-Options': 'DENY',
  'X-Content-Type-Options': 'nosniff',
  'Referrer-Policy': 'strict-origin-when-cross-origin',
  'X-XSS-Protection': '1; mode=block'
};

/**
 * Validate if an origin is from localhost
 * Properly parses the URL to prevent bypass via subdomains like localhost.attacker.com
 * Exported for testing
 */
export function isLocalhostOrigin(origin: string): boolean {
  try {
    const url = new URL(origin);
    const hostname = url.hostname;
    // Only allow exact localhost or 127.0.0.1
    return hostname === 'localhost' || hostname === '127.0.0.1';
  } catch {
    // Invalid URL - reject
    return false;
  }
}

export interface HttpTransportConfig {
  port?: number;
  host?: string;
  path?: string;
  debug?: boolean;

  // Existing calendar-mcp features
  allowedOriginsForAccounts?: string[];
  publicBaseUrl?: string;

  // Gmail-mcp style DNS-rebinding options for /mcp
  enableDnsRebindingProtection?: boolean;
  allowedHosts?: string[];
  allowedOrigins?: string[];
}

export class HttpTransportHandler {
  private config: HttpTransportConfig;
  private tokenManager: TokenManager;
  private debug: boolean;
  private allowedOriginsForAccounts: Set<string>;
  private publicBaseUrl: string | null;
  private createMcpServer: () => McpServer;

  constructor(
    config: HttpTransportConfig = {},
    tokenManager: TokenManager,
    createMcpServer: () => McpServer
  ) {
    this.config = config;
    this.tokenManager = tokenManager;
    this.debug = config.debug === true;
    this.allowedOriginsForAccounts = new Set(
      (config.allowedOriginsForAccounts ?? [])
        .map(o => o.trim())
        .filter(o => o.length > 0)
    );
    this.publicBaseUrl = config.publicBaseUrl ? config.publicBaseUrl.trim().replace(/\/+$/, '') : null;
    this.createMcpServer = createMcpServer;
  }

  private debugLog(message: string): void {
    if (!this.debug) return;
    process.stderr.write(`[http][debug] ${message}\n`);
  }

  private installDebugCapture(
    requestId: string,
    req: http.IncomingMessage,
    res: http.ServerResponse
  ): { getRequestBody: () => string; getResponseBody: () => string } {
    const maxBytes = 16 * 1024;

    let reqBytes = 0;
    const reqChunks: Buffer[] = [];
    const onReqData = (chunk: Buffer) => {
      if (reqBytes >= maxBytes) return;
      const slice = chunk.length + reqBytes > maxBytes ? chunk.subarray(0, maxBytes - reqBytes) : chunk;
      reqChunks.push(slice);
      reqBytes += slice.length;
    };
    // Safe: multiple 'data' listeners can observe the same stream.
    if (typeof (req as any).on === 'function') {
      (req as any).on('data', onReqData);
    }

    let resBytes = 0;
    const resChunks: Buffer[] = [];
    const captureResChunk = (chunk: unknown) => {
      if (resBytes >= maxBytes) return;
      if (typeof chunk === 'string') {
        const b = Buffer.from(chunk);
        const slice = b.length + resBytes > maxBytes ? b.subarray(0, maxBytes - resBytes) : b;
        resChunks.push(slice);
        resBytes += slice.length;
        return;
      }
      if (Buffer.isBuffer(chunk)) {
        const slice = chunk.length + resBytes > maxBytes ? chunk.subarray(0, maxBytes - resBytes) : chunk;
        resChunks.push(slice);
        resBytes += slice.length;
      }
    };

    // Monkeypatch response write/end for capture (defensive: tests may provide mocks).
    const originalWrite = (res as any).write?.bind(res);
    const originalEnd = (res as any).end?.bind(res);

    if (typeof originalWrite === 'function') {
      (res as any).write = (chunk: any, ...args: any[]) => {
        try { captureResChunk(chunk); } catch { /* ignore */ }
        return originalWrite(chunk, ...args);
      };
    }

    if (typeof originalEnd === 'function') {
      (res as any).end = (chunk?: any, ...args: any[]) => {
        try { captureResChunk(chunk); } catch { /* ignore */ }
        return originalEnd(chunk, ...args);
      };
    }

    const getRequestBody = () => {
      if (reqChunks.length === 0) return '';
      return Buffer.concat(reqChunks).toString('utf-8');
    };
    const getResponseBody = () => {
      if (resChunks.length === 0) return '';
      return Buffer.concat(resChunks).toString('utf-8');
    };

    // Cleanup listeners on finish/close (best-effort)
    if (typeof (res as any).on === 'function') {
      (res as any).on('close', () => {
        try { (req as any).off?.('data', onReqData); } catch { /* ignore */ }
        this.debugLog(`request ${requestId} debug capture closed`);
      });
    }

    return { getRequestBody, getResponseBody };
  }

  private isAllowedOriginForAccounts(origin: string): boolean {
    // Always allow localhost origins for backwards compatibility / local dev.
    if (isLocalhostOrigin(origin)) return true;
    // If no allowlist is configured, keep the default strict behavior.
    if (this.allowedOriginsForAccounts.size === 0) return false;
    // Exact origin match (scheme + host + optional port).
    return this.allowedOriginsForAccounts.has(origin);
  }

  private isAllowedOriginForMcp(origin: string, allowedOrigins: string[]): boolean {
    if (allowedOrigins.length > 0) {
      return allowedOrigins.includes(origin);
    }
    // Default strict behavior for browser-originated requests.
    return isLocalhostOrigin(origin);
  }

  private getOAuthRedirectUri(accountId: string, host: string, port: number): string {
    if (this.publicBaseUrl) {
      return `${this.publicBaseUrl}/oauth2callback?account=${encodeURIComponent(accountId)}`;
    }
    return `http://${host}:${port}/oauth2callback?account=${encodeURIComponent(accountId)}`;
  }

  /**
   * Creates an OAuth2Client configured for the given account.
   * Consolidates credential loading and redirect URI construction.
   */
  private async createOAuth2Client(accountId: string, host: string, port: number): Promise<import('google-auth-library').OAuth2Client> {
    const { OAuth2Client } = await import('google-auth-library');
    const { loadCredentials } = await import('../auth/client.js');
    const { client_id, client_secret } = await loadCredentials();
    return new OAuth2Client(
      client_id,
      client_secret,
      this.getOAuthRedirectUri(accountId, host, port)
    );
  }

  /**
   * Generates an OAuth authorization URL with standard settings.
   */
  private generateOAuthUrl(client: import('google-auth-library').OAuth2Client): string {
    return client.generateAuthUrl({
      access_type: 'offline',
      scope: ['https://www.googleapis.com/auth/calendar'],
      prompt: 'consent'
    });
  }

  /**
   * Validates an account ID format.
   * Throws an error if the format is invalid.
   */
  private async validateAccountId(accountId: string): Promise<void> {
    const { validateAccountId } = await import('../auth/paths.js') as any;
    validateAccountId(accountId);
  }

  private createBadRequestResponse(message: string): object {
    return {
      jsonrpc: "2.0",
      error: { code: -32000, message },
      id: null,
    };
  }

  private isInitializePayload(payload: unknown): boolean {
    if (Array.isArray(payload)) {
      return payload.some((m) => isInitializeRequest(m));
    }
    return isInitializeRequest(payload);
  }

  async connect(): Promise<void> {
    const port = this.config.port || 3000;
    const host = this.config.host || '127.0.0.1';
    const mcpPath = this.config.path || '/mcp';

    const enableDnsRebindingProtection = this.config.enableDnsRebindingProtection === true;
    const allowedHosts = (this.config.allowedHosts ?? []).map(v => v.trim()).filter(Boolean);
    const allowedOrigins = (this.config.allowedOrigins ?? []).map(v => v.trim()).filter(Boolean);

    interface SessionState {
      server: McpServer;
      transport: StreamableHTTPServerTransport;
    }

    const sessions = new Map<string, SessionState>();

    const getTransportForRequest = async (
      req: express.Request,
      requestBody: unknown
    ): Promise<StreamableHTTPServerTransport | null> => {
      const sessionIdHeader = req.headers["mcp-session-id"];
      const sessionId = typeof sessionIdHeader === "string" ? sessionIdHeader.trim() : null;

      if (sessionId) {
        const state = sessions.get(sessionId);
        return state ? state.transport : null;
      }

      if (req.method !== "POST" || !this.isInitializePayload(requestBody)) {
        return null;
      }

      const newSessionId = crypto.randomUUID();
      const sessionServer = this.createMcpServer();
      const transport = new StreamableHTTPServerTransport({
        sessionIdGenerator: () => newSessionId,
        enableDnsRebindingProtection,
        allowedHosts: allowedHosts.length ? allowedHosts : undefined,
        allowedOrigins: allowedOrigins.length ? allowedOrigins : undefined,
      });

      transport.onclose = () => sessions.delete(newSessionId);
      transport.onerror = (err: Error) => process.stderr.write(`Streamable HTTP transport error: ${err.message}\n`);

      await sessionServer.connect(transport);
      sessions.set(newSessionId, { server: sessionServer, transport });
      return transport;
    };

    const app = express();
    app.use(express.json({ limit: "4mb" }));

    // Origin validation + minimal CORS (mostly for browser-based `/api/accounts`).
    app.use((req, res, next) => {
      const origin = req.headers.origin;
      if (origin) {
        const isAccountsApi = req.path === '/api/accounts' || req.path.startsWith('/api/accounts/');
        const isMcp = req.path === mcpPath;
        const originAllowed = isAccountsApi
          ? this.isAllowedOriginForAccounts(origin)
          : isMcp
            ? this.isAllowedOriginForMcp(origin, allowedOrigins)
            : isLocalhostOrigin(origin);

        if (!originAllowed) {
          this.debugLog(`origin rejected: path=${req.path} origin=${origin}`);
          res.status(403).json({
            error: 'Forbidden: Invalid origin',
            message: 'Origin header validation failed'
          });
          return;
        }
      }

      if (origin) res.setHeader('Access-Control-Allow-Origin', origin);
      res.setHeader('Access-Control-Allow-Methods', 'GET, POST, DELETE, OPTIONS');
      res.setHeader('Access-Control-Allow-Headers', 'Content-Type, mcp-session-id, mcp-protocol-version');
      if (req.method === 'OPTIONS') {
        res.status(200).end();
        return;
      }
      next();
    });

    app.get("/healthz", (_req, res) => {
      res.status(200).json({ status: "ok", sessions: sessions.size });
    });

    // Backwards-compat endpoint (old http.ts had /health)
    app.get("/health", (_req, res) => {
      res.status(200).json({
        status: 'healthy',
        server: 'google-calendar-mcp',
        timestamp: new Date().toISOString()
      });
    });

    // Serve Account Management UI
    app.get(["/", "/accounts"], async (_req, res) => {
      try {
        const html = await loadWebFile('accounts.html');
        res.status(200).set({
          'Content-Type': 'text/html; charset=utf-8',
          ...SECURITY_HEADERS
        }).send(html);
      } catch (error) {
        res.status(500).json({
          error: 'Failed to load UI',
          message: error instanceof Error ? error.message : String(error)
        });
      }
    });

    // Serve shared CSS
    app.get("/styles.css", async (_req, res) => {
      try {
        const css = await loadWebFile('styles.css');
        res.status(200).set({
          'Content-Type': 'text/css; charset=utf-8',
          ...SECURITY_HEADERS
        }).send(css);
      } catch {
        res.status(404).type('text/plain').send('CSS file not found');
      }
    });

    // GET /api/accounts - List all authenticated accounts
    app.get("/api/accounts", async (_req, res) => {
      try {
        const accounts = await this.tokenManager.listAccounts();
        res.status(200).json({ accounts });
      } catch (error) {
        res.status(500).json({
          error: 'Failed to list accounts',
          message: error instanceof Error ? error.message : String(error)
        });
      }
    });

    // POST /api/accounts - Add new account (get OAuth URL)
    app.post("/api/accounts", async (req, res) => {
      try {
        const accountId = (req.body as any)?.accountId;

        if (!accountId || typeof accountId !== 'string') {
          res.status(400).json({
            error: 'Invalid request',
            message: 'accountId is required and must be a string'
          });
          return;
        }

        try {
          await this.validateAccountId(accountId);
        } catch (error) {
          res.status(400).json({
            error: 'Invalid account ID',
            message: error instanceof Error ? error.message : String(error)
          });
          return;
        }

        const oauth2Client = await this.createOAuth2Client(accountId, host, port);
        const authUrl = this.generateOAuthUrl(oauth2Client);

        res.status(200).json({ authUrl, accountId });
      } catch (error) {
        res.status(500).json({
          error: 'Failed to initiate OAuth flow',
          message: error instanceof Error ? error.message : String(error)
        });
      }
    });

    // POST /api/accounts/:id/reauth - Re-authenticate account
    app.post("/api/accounts/:id/reauth", async (req, res) => {
      const accountId = req.params.id;
      try {
        await this.validateAccountId(accountId);
        const oauth2Client = await this.createOAuth2Client(accountId, host, port);
        const authUrl = this.generateOAuthUrl(oauth2Client);
        res.status(200).json({ authUrl, accountId });
      } catch (error) {
        res.status(500).json({
          error: 'Failed to initiate re-authentication',
          message: error instanceof Error ? error.message : String(error)
        });
      }
    });

    // DELETE /api/accounts/:id - Remove account
    app.delete("/api/accounts/:id", async (req, res) => {
      const accountId = req.params.id;
      try {
        await this.validateAccountId(accountId);

        const originalMode = this.tokenManager.getAccountMode();
        try {
          this.tokenManager.setAccountMode(accountId);
          await this.tokenManager.clearTokens();
        } finally {
          this.tokenManager.setAccountMode(originalMode);
        }

        CalendarRegistry.getInstance().clearCache();

        res.status(200).json({
          success: true,
          accountId,
          message: 'Account removed successfully'
        });
      } catch (error) {
        res.status(500).json({
          error: 'Failed to remove account',
          message: error instanceof Error ? error.message : String(error)
        });
      }
    });

    // GET /oauth2callback - OAuth callback handler
    app.get("/oauth2callback", async (req, res) => {
      try {
        const code = typeof req.query.code === 'string' ? req.query.code : null;
        const accountId = typeof req.query.account === 'string' ? req.query.account : null;

        if (!code) {
          res.status(400).type('text/html').send('<h1>Error</h1><p>Authorization code missing</p>');
          return;
        }

        if (!accountId) {
          res.status(400).type('text/html').send('<h1>Error</h1><p>Account ID missing</p>');
          return;
        }

        const oauth2Client = await this.createOAuth2Client(accountId, host, port);
        const { tokens } = await oauth2Client.getToken(code);

        oauth2Client.setCredentials(tokens);
        let email = 'unknown';
        try {
          const tokenInfo = await oauth2Client.getTokenInfo(tokens.access_token || '');
          email = tokenInfo.email || 'unknown';
        } catch {
          // Email retrieval failed, continue with 'unknown'
        }

        const originalMode = this.tokenManager.getAccountMode();
        try {
          this.tokenManager.setAccountMode(accountId);
          await this.tokenManager.saveTokens(tokens, email !== 'unknown' ? email : undefined);
        } finally {
          this.tokenManager.setAccountMode(originalMode);
        }

        CalendarRegistry.getInstance().clearCache();

        // Compute allowed origin for postMessage (localhost only)
        const postMessageOrigin = `http://${host}:${port}`;

        const successHtml = await renderAuthSuccess({
          accountId,
          email: email !== 'unknown' ? email : undefined,
          showCloseButton: true,
          postMessageOrigin
        });
        res.status(200).set({
          'Content-Type': 'text/html; charset=utf-8',
          ...SECURITY_HEADERS
        }).send(successHtml);
      } catch (error) {
        const errorHtml = await renderAuthError({
          errorMessage: error instanceof Error ? error.message : String(error),
          showCloseButton: true
        });
        res.status(500).set({
          'Content-Type': 'text/html; charset=utf-8',
          ...SECURITY_HEADERS
        }).send(errorHtml);
      }
    });

    const handleMcpRequest = async (req: express.Request, res: express.Response): Promise<void> => {
      const requestId = `${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 8)}`;
      const debugCapture = this.debug ? this.installDebugCapture(requestId, req as any, res as any) : null;

      this.debugLog(
        `request ${requestId} ${req.method} ${req.originalUrl} ` +
        `origin=${req.headers.origin ?? '-'} host=${req.headers.host ?? '-'} ` +
        `accept=${req.headers.accept ?? '-'} content-length=${req.headers['content-length'] ?? '-'} ` +
        `content-type=${(req.headers['content-type'] as string | undefined) ?? '-'} ` +
        `mcp-session-id=${(req.headers['mcp-session-id'] as string | undefined) ?? '-'}`
      );

      // Validate Accept header for MCP requests (spec requirement)
      if (req.method === 'POST' || req.method === 'GET') {
        const acceptHeader = req.headers.accept;
        if (
          acceptHeader &&
          !acceptHeader.includes('application/json') &&
          !acceptHeader.includes('text/event-stream') &&
          !acceptHeader.includes('*/*')
        ) {
          res.status(406).json({
            error: 'Not Acceptable',
            message: 'Accept header must include application/json or text/event-stream'
          });
          return;
        }
      }

      try {
        const transport = await getTransportForRequest(req, req.body);
        if (!transport) {
          const sessionId = req.headers["mcp-session-id"];
          const message = sessionId
            ? "Bad Request: Unknown or expired session. Send an initialize request to start a new session."
            : "Bad Request: Server not initialized. Send an initialize request first.";
          res.status(400).json(this.createBadRequestResponse(message));
          return;
        }
        await transport.handleRequest(req as any, res as any, req.body);
      } catch (error) {
        const message = error instanceof Error ? error.message : String(error);
        process.stderr.write(`Error handling request: ${message}\n`);
        if (this.debug && error instanceof Error && error.stack) {
          process.stderr.write(`${error.stack}\n`);
        }
        if (!res.headersSent) {
          res.status(500).json({
            jsonrpc: '2.0',
            error: { code: -32603, message: 'Internal server error' },
            id: null,
          });
        }
      } finally {
        if (debugCapture && (res.statusCode ?? 200) >= 400) {
          this.debugLog(`request ${requestId} /mcp request body (truncated): ${debugCapture.getRequestBody() || '<empty>'}`);
          this.debugLog(`request ${requestId} /mcp response body (truncated): ${debugCapture.getResponseBody() || '<empty>'}`);
        }
      }
    };

    app.post(mcpPath, handleMcpRequest);
    app.get(mcpPath, handleMcpRequest);
    app.delete(mcpPath, handleMcpRequest);

    await new Promise<void>((resolve, reject) => {
      const httpServer = app.listen(port, host, () => {
        process.stderr.write(`Google Calendar MCP Streamable HTTP server listening ${JSON.stringify({ host, port, path: mcpPath })}\n`);
        resolve();
      });
      // Important for test runners: don't keep the process alive due to open server handles.
      // In production, this has no negative effect (server still accepts connections).
      if (typeof (httpServer as any).unref === 'function') {
        (httpServer as any).unref();
      }
      httpServer.on("error", reject);
    });
  }
}

