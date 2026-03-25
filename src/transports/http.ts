import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import http from "http";
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
  debug?: boolean;
  allowedOriginsForAccounts?: string[];
  publicBaseUrl?: string;
}

export class HttpTransportHandler {
  private server: McpServer;
  private config: HttpTransportConfig;
  private tokenManager: TokenManager;
  private debug: boolean;
  private allowedOriginsForAccounts: Set<string>;
  private publicBaseUrl: string | null;

  constructor(
    server: McpServer,
    config: HttpTransportConfig = {},
    tokenManager: TokenManager
  ) {
    this.server = server;
    this.config = config;
    this.tokenManager = tokenManager;
    this.debug = config.debug === true;
    this.allowedOriginsForAccounts = new Set(
      (config.allowedOriginsForAccounts ?? [])
        .map(o => o.trim())
        .filter(o => o.length > 0)
    );
    this.publicBaseUrl = config.publicBaseUrl ? config.publicBaseUrl.trim().replace(/\/+$/, '') : null;
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

  private parseRequestBody(req: http.IncomingMessage): Promise<any> {
    return new Promise((resolve, reject) => {
      let body = '';
      req.on('data', chunk => body += chunk.toString());
      req.on('end', () => {
        try {
          resolve(body ? JSON.parse(body) : {});
        } catch (error) {
          reject(new Error('Invalid JSON in request body'));
        }
      });
      req.on('error', reject);
    });
  }

  async connect(): Promise<void> {
    const port = this.config.port || 3000;
    const host = this.config.host || '127.0.0.1';

    // Configure transport for stateless mode to allow multiple initialization cycles
    const transport = new StreamableHTTPServerTransport({
      sessionIdGenerator: undefined // Stateless mode - allows multiple initializations
    });

    await this.server.connect(transport);

    // Create HTTP server to handle the StreamableHTTP transport
    const httpServer = http.createServer(async (req, res) => {
      const requestId = `${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 8)}`;
      const debugCapture =
        this.debug && (req.url === '/mcp' || (req.url || '').startsWith('/mcp?'))
          ? this.installDebugCapture(requestId, req, res)
          : null;

      this.debugLog(
        `request ${requestId} ${req.method} ${req.url} ` +
        `origin=${req.headers.origin ?? '-'} host=${req.headers.host ?? '-'} ` +
        `accept=${req.headers.accept ?? '-'} content-length=${req.headers['content-length'] ?? '-'} ` +
        `mcp-session-id=${(req.headers['mcp-session-id'] as string | undefined) ?? '-'}`
      );
      // Log final response status for debugging gateway/server issues.
      // This helps distinguish "service returned 500" from "gateway returned 500".
      if (typeof (res as any).on === 'function') {
        (res as any).on('finish', () => {
          this.debugLog(`request ${requestId} finished status=${res.statusCode} headersSent=${res.headersSent}`);
          if (debugCapture && res.statusCode >= 400) {
            const reqBody = debugCapture.getRequestBody();
            const resBody = debugCapture.getResponseBody();
            if (reqBody) {
              this.debugLog(`request ${requestId} /mcp request body (truncated): ${reqBody}`);
            }
            if (resBody) {
              this.debugLog(`request ${requestId} /mcp response body (truncated): ${resBody}`);
            }
          }
        });
      }

      // Validate Origin header to prevent DNS rebinding attacks (MCP spec requirement)
      const origin = req.headers.origin;

      // For requests with Origin header, validate it using proper URL parsing
      // This prevents bypass via subdomains like localhost.attacker.com
      if (origin) {
        const url = req.url || '/';
        const isAccountsApi = url === '/api/accounts' || url.startsWith('/api/accounts/');
        const originAllowed = isAccountsApi
          ? this.isAllowedOriginForAccounts(origin)
          : isLocalhostOrigin(origin);

        if (!originAllowed) {
          this.debugLog(`request ${requestId} rejected: invalid origin`);
          res.writeHead(403, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({
            error: 'Forbidden: Invalid origin',
            message: 'Origin header validation failed'
          }));
          return;
        }
      }

      // Basic request size limiting (prevent DoS)
      const contentLength = parseInt(req.headers['content-length'] || '0', 10);
      const maxRequestSize = 10 * 1024 * 1024; // 10MB limit
      if (contentLength > maxRequestSize) {
        this.debugLog(`request ${requestId} rejected: payload too large (${contentLength})`);
        res.writeHead(413, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({
          error: 'Payload Too Large',
          message: 'Request size exceeds maximum allowed size'
        }));
        return;
      }

      // Handle CORS - restrict to localhost only for security
      // HTTP mode is designed for local development/testing only
      const allowedCorsOrigin = origin && isLocalhostOrigin(origin)
        ? origin
        : `http://${host}:${port}`;
      res.setHeader('Access-Control-Allow-Origin', allowedCorsOrigin);
      res.setHeader('Access-Control-Allow-Methods', 'GET, POST, DELETE, OPTIONS');
      res.setHeader('Access-Control-Allow-Headers', 'Content-Type, mcp-session-id');
      
      if (req.method === 'OPTIONS') {
        res.writeHead(200);
        res.end();
        return;
      }

      // Validate Accept header for MCP requests (spec requirement)
      if (req.method === 'POST' || req.method === 'GET') {
        const acceptHeader = req.headers.accept;
        if (acceptHeader && !acceptHeader.includes('application/json') && !acceptHeader.includes('text/event-stream') && !acceptHeader.includes('*/*')) {
          this.debugLog(`request ${requestId} rejected: unacceptable accept header (${acceptHeader})`);
          res.writeHead(406, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({
            error: 'Not Acceptable',
            message: 'Accept header must include application/json or text/event-stream'
          }));
          return;
        }
      }

      // Serve Account Management UI
      if (req.method === 'GET' && (req.url === '/' || req.url === '/accounts')) {
        try {
          const html = await loadWebFile('accounts.html');
          res.writeHead(200, {
            'Content-Type': 'text/html; charset=utf-8',
            ...SECURITY_HEADERS
          });
          res.end(html);
        } catch (error) {
          res.writeHead(500, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({
            error: 'Failed to load UI',
            message: error instanceof Error ? error.message : String(error)
          }));
        }
        return;
      }

      // Serve shared CSS
      if (req.method === 'GET' && req.url === '/styles.css') {
        try {
          const css = await loadWebFile('styles.css');
          res.writeHead(200, {
            'Content-Type': 'text/css; charset=utf-8',
            ...SECURITY_HEADERS
          });
          res.end(css);
        } catch (error) {
          res.writeHead(404, { 'Content-Type': 'text/plain' });
          res.end('CSS file not found');
        }
        return;
      }

      // Account Management API Endpoints

      // GET /api/accounts - List all authenticated accounts
      if (req.method === 'GET' && req.url === '/api/accounts') {
        try {
          const accounts = await this.tokenManager.listAccounts();
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ accounts }));
        } catch (error) {
          res.writeHead(500, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({
            error: 'Failed to list accounts',
            message: error instanceof Error ? error.message : String(error)
          }));
        }
        return;
      }

      // POST /api/accounts - Add new account (get OAuth URL)
      if (req.method === 'POST' && req.url === '/api/accounts') {
        try {
          const body = await this.parseRequestBody(req);
          const accountId = body.accountId;

          if (!accountId || typeof accountId !== 'string') {
            res.writeHead(400, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({
              error: 'Invalid request',
              message: 'accountId is required and must be a string'
            }));
            return;
          }

          // Validate account ID format
          try {
            await this.validateAccountId(accountId);
          } catch (error) {
            res.writeHead(400, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({
              error: 'Invalid account ID',
              message: error instanceof Error ? error.message : String(error)
            }));
            return;
          }

          // Generate OAuth URL for this account
          const oauth2Client = await this.createOAuth2Client(accountId, host, port);
          const authUrl = this.generateOAuthUrl(oauth2Client);

          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({
            authUrl,
            accountId
          }));
        } catch (error) {
          res.writeHead(500, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({
            error: 'Failed to initiate OAuth flow',
            message: error instanceof Error ? error.message : String(error)
          }));
        }
        return;
      }

      // GET /oauth2callback - OAuth callback handler
      if (req.method === 'GET' && req.url?.startsWith('/oauth2callback')) {
        try {
          // Use configured host/port instead of req.headers.host for security
          const url = new URL(req.url, `http://${host}:${port}`);
          const code = url.searchParams.get('code');
          const accountId = url.searchParams.get('account');

          if (!code) {
            res.writeHead(400, { 'Content-Type': 'text/html' });
            res.end('<h1>Error</h1><p>Authorization code missing</p>');
            return;
          }

          if (!accountId) {
            res.writeHead(400, { 'Content-Type': 'text/html' });
            res.end('<h1>Error</h1><p>Account ID missing</p>');
            return;
          }

          // Exchange code for tokens
          const oauth2Client = await this.createOAuth2Client(accountId, host, port);
          const { tokens } = await oauth2Client.getToken(code);

          // Get user email before saving tokens
          oauth2Client.setCredentials(tokens);
          let email = 'unknown';
          try {
            const tokenInfo = await oauth2Client.getTokenInfo(tokens.access_token || '');
            email = tokenInfo.email || 'unknown';
          } catch {
            // Email retrieval failed, continue with 'unknown'
          }

          // Save tokens for this account with cached email
          const originalMode = this.tokenManager.getAccountMode();
          try {
            this.tokenManager.setAccountMode(accountId);
            await this.tokenManager.saveTokens(tokens, email !== 'unknown' ? email : undefined);
          } finally {
            this.tokenManager.setAccountMode(originalMode);
          }

          // Invalidate calendar registry cache since accounts changed
          CalendarRegistry.getInstance().clearCache();

          // Compute allowed origin for postMessage (localhost only)
          const postMessageOrigin = `http://${host}:${port}`;

          const successHtml = await renderAuthSuccess({
            accountId,
            email: email !== 'unknown' ? email : undefined,
            showCloseButton: true,
            postMessageOrigin
          });
          res.writeHead(200, {
            'Content-Type': 'text/html; charset=utf-8',
            ...SECURITY_HEADERS
          });
          res.end(successHtml);
        } catch (error) {
          const errorHtml = await renderAuthError({
            errorMessage: error instanceof Error ? error.message : String(error),
            showCloseButton: true
          });
          res.writeHead(500, {
            'Content-Type': 'text/html; charset=utf-8',
            ...SECURITY_HEADERS
          });
          res.end(errorHtml);
        }
        return;
      }

      // DELETE /api/accounts/:id - Remove account
      if (req.method === 'DELETE' && req.url?.startsWith('/api/accounts/')) {
        const accountId = req.url.substring('/api/accounts/'.length);

        try {
          // Validate account ID format
          await this.validateAccountId(accountId);

          // Switch to account and clear tokens
          const originalMode = this.tokenManager.getAccountMode();
          try {
            this.tokenManager.setAccountMode(accountId);
            await this.tokenManager.clearTokens();
          } finally {
            this.tokenManager.setAccountMode(originalMode);
          }

          // Invalidate calendar registry cache since accounts changed
          CalendarRegistry.getInstance().clearCache();

          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({
            success: true,
            accountId,
            message: 'Account removed successfully'
          }));
        } catch (error) {
          res.writeHead(500, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({
            error: 'Failed to remove account',
            message: error instanceof Error ? error.message : String(error)
          }));
        }
        return;
      }

      // POST /api/accounts/:id/reauth - Re-authenticate account
      if (req.method === 'POST' && req.url?.match(/^\/api\/accounts\/[^/]+\/reauth$/)) {
        const accountId = req.url.split('/')[3];

        try {
          // Validate account ID format
          await this.validateAccountId(accountId);

          // Generate OAuth URL for re-authentication
          const oauth2Client = await this.createOAuth2Client(accountId, host, port);
          const authUrl = this.generateOAuthUrl(oauth2Client);

          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({
            authUrl,
            accountId
          }));
        } catch (error) {
          res.writeHead(500, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({
            error: 'Failed to initiate re-authentication',
            message: error instanceof Error ? error.message : String(error)
          }));
        }
        return;
      }

      // Handle health check endpoint
      if (req.method === 'GET' && req.url === '/health') {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({
          status: 'healthy',
          server: 'google-calendar-mcp',
          timestamp: new Date().toISOString()
        }));
        return;
      }

      try {
        this.debugLog(`request ${requestId} transport.handleRequest start`);
        await transport.handleRequest(req, res);
        this.debugLog(`request ${requestId} transport.handleRequest done`);
      } catch (error) {
        const message = error instanceof Error ? error.message : String(error);
        process.stderr.write(`Error handling request: ${message}\n`);
        if (this.debug && error instanceof Error && error.stack) {
          process.stderr.write(`${error.stack}\n`);
        }
        if (!res.headersSent) {
          res.writeHead(500, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({
            jsonrpc: '2.0',
            error: {
              code: -32603,
              message: 'Internal server error',
            },
            id: null,
          }));
        }
      }
    });

    httpServer.listen(port, host, () => {
      process.stderr.write(`Google Calendar MCP Server listening on http://${host}:${port}\n`);
    });
  }
} 