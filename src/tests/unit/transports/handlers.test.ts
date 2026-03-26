import { EventEmitter } from 'events';
import { beforeEach, describe, expect, it, vi } from 'vitest';

const state = vi.hoisted(() => ({
  requestHandler: undefined as ((req: any, res: any) => Promise<void>) | undefined,
  transport: undefined as { handleRequest: ReturnType<typeof vi.fn> } | undefined,
  listen: vi.fn(),
  clearCache: vi.fn(),
  renderAuthSuccess: vi.fn(async () => '<html>success</html>'),
  renderAuthError: vi.fn(async () => '<html>error</html>'),
  loadWebFile: vi.fn(async (name: string) => `file:${name}`),
  validateAccountId: vi.fn(),
  loadCredentials: vi.fn(async () => ({ client_id: 'client-id', client_secret: 'client-secret' })),
  lastOAuthRedirectUri: undefined as string | undefined,
}));

vi.mock('@modelcontextprotocol/sdk/server/streamableHttp.js', () => ({
  StreamableHTTPServerTransport: class MockStreamableHTTPServerTransport {
    handleRequest = vi.fn(async () => undefined);
    onclose: (() => void) | undefined;
    onerror: ((err: Error) => void) | undefined;
    constructor(_opts?: any) {
      state.transport = this;
    }
  }
}));

vi.mock('@modelcontextprotocol/sdk/server/stdio.js', () => ({
  StdioServerTransport: class MockStdioServerTransport {}
}));

vi.mock('express', async () => {
  const routes = new Map<string, any>();

  const app = {
    use: vi.fn((mw: any) => {
      // store as a "catch-all" handler under key "*"
      const existing = routes.get('*');
      if (existing) {
        // chain middlewares in insertion order
        routes.set('*', async (req: any, res: any, next: any) => existing(req, res, () => mw(req, res, next)));
      } else {
        routes.set('*', mw);
      }
    }),
    get: vi.fn((path: any, handler: any) => {
      if (Array.isArray(path)) {
        for (const p of path) routes.set(`GET ${p}`, handler);
        return;
      }
      routes.set(`GET ${path}`, handler);
    }),
    post: vi.fn((path: any, handler: any) => routes.set(`POST ${path}`, handler)),
    delete: vi.fn((path: any, handler: any) => routes.set(`DELETE ${path}`, handler)),
    listen: vi.fn((_port: number, _host: string, cb?: () => void) => {
      if (cb) cb();
      return { on: vi.fn() };
    }),
    __routes: routes,
  };

  const expressDefault: any = () => app;
  expressDefault.json = vi.fn(() => (_req: any, _res: any, next: any) => next());
  return { default: expressDefault };
});

vi.mock('../../../web/templates.js', () => ({
  renderAuthSuccess: state.renderAuthSuccess,
  renderAuthError: state.renderAuthError,
  loadWebFile: state.loadWebFile
}));

vi.mock('../../../services/CalendarRegistry.js', () => ({
  CalendarRegistry: {
    getInstance: vi.fn(() => ({
      clearCache: state.clearCache
    }))
  }
}));

vi.mock('../../../auth/paths.js', () => ({
  validateAccountId: state.validateAccountId
}));

vi.mock('../../../auth/client.js', () => ({
  loadCredentials: state.loadCredentials
}));

vi.mock('google-auth-library', () => ({
  OAuth2Client: class MockOAuth2Client {
    redirectUri: string | undefined;
    constructor(_clientId: string, _clientSecret: string, redirectUri?: string) {
      this.redirectUri = redirectUri;
      state.lastOAuthRedirectUri = redirectUri;
    }
    generateAuthUrl = vi.fn(() => 'https://auth.example.com');
    getToken = vi.fn(async () => ({ tokens: { access_token: 'token', refresh_token: 'refresh' } }));
    setCredentials = vi.fn();
    getTokenInfo = vi.fn(async () => ({ email: 'person@example.com' }));
  }
}));

import { HttpTransportHandler } from '../../../transports/http.js';
import { StdioTransportHandler } from '../../../transports/stdio.js';

function createMockResponse() {
  return {
    headers: {} as Record<string, string>,
    statusCode: 0,
    body: '',
    headersSent: false,
    status: vi.fn(function (this: any, statusCode: number) {
      this.statusCode = statusCode;
      return this;
    }),
    json: vi.fn(function (this: any, payload: any) {
      this.headersSent = true;
      this.body += JSON.stringify(payload);
      return this;
    }),
    type: vi.fn(function (this: any, contentType: string) {
      this.headers['Content-Type'] = contentType;
      return this;
    }),
    set: vi.fn(function (this: any, headers: Record<string, string>) {
      Object.assign(this.headers, headers);
      return this;
    }),
    send: vi.fn(function (this: any, body: string) {
      this.headersSent = true;
      this.body += body;
      return this;
    }),
    setHeader: vi.fn(function (this: any, key: string, value: string) {
      this.headers[key] = value;
    }),
    writeHead: vi.fn(function (this: any, statusCode: number, headers?: Record<string, string>) {
      this.statusCode = statusCode;
      this.headersSent = true;
      if (headers) {
        Object.assign(this.headers, headers);
      }
    }),
    end: vi.fn(function (this: any, chunk?: string) {
      if (chunk) {
        this.body += chunk;
      }
    }),
  };
}

function createMockRequest(input: {
  method: string;
  url: string;
  headers?: Record<string, string>;
}) {
  const req = new EventEmitter() as any;
  req.method = input.method;
  req.url = input.url;
  req.path = input.url.split('?')[0];
  req.originalUrl = input.url;
  req.headers = input.headers ?? {};
  req.body = (req.headers['content-type'] === 'application/json' || req.headers['content-type'] === 'application/json; charset=utf-8')
    ? {}
    : undefined;
  req.query = {};
  return req;
}

async function invokeHandler(req: any, res: any): Promise<void> {
  const expressModule: any = await import('express');
  const routes: Map<string, any> = (expressModule.default() as any).__routes;

  const mw = routes.get('*');
  const key = `${req.method} ${req.path}`;
  const handler = routes.get(key);
  if (!handler) {
    throw new Error(`No route registered for ${key}`);
  }

  if (mw) {
    await new Promise<void>((resolve) => mw(req, res, resolve));
  }
  await handler(req, res);
}

describe('Transport Handlers', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    state.requestHandler = undefined;
    state.transport = undefined;
    state.listen.mockImplementation((_port: number, _host: string, callback?: () => void) => {
      if (callback) {
        callback();
      }
    });
  });

  it('connects stdio transport through server.connect', async () => {
    const server = { connect: vi.fn(async () => undefined) } as any;
    const handler = new StdioTransportHandler(server);

    await handler.connect();

    expect(server.connect).toHaveBeenCalledTimes(1);
  });

  it('rejects requests from non-localhost origins', async () => {
    const tokenManager = { listAccounts: vi.fn(), getAccountMode: vi.fn(), setAccountMode: vi.fn(), clearTokens: vi.fn(), saveTokens: vi.fn() } as any;
    const handler = new HttpTransportHandler({ port: 3999, host: '127.0.0.1' }, tokenManager, () => ({ connect: vi.fn(async () => undefined) } as any));
    await handler.connect();

    const req = createMockRequest({
      method: 'GET',
      url: '/healthz',
      headers: { origin: 'https://attacker.example.com', accept: 'application/json' }
    });
    const res = createMockResponse();

    await invokeHandler(req, res);

    expect(res.statusCode).toBe(403);
    expect(res.body).toContain('Invalid origin');
  });

  it('returns health payload and sets localhost CORS defaults', async () => {
    const tokenManager = { listAccounts: vi.fn(), getAccountMode: vi.fn(), setAccountMode: vi.fn(), clearTokens: vi.fn(), saveTokens: vi.fn() } as any;
    const handler = new HttpTransportHandler({ port: 4001, host: '127.0.0.1' }, tokenManager, () => ({ connect: vi.fn(async () => undefined) } as any));
    await handler.connect();

    const req = createMockRequest({
      method: 'GET',
      url: '/healthz',
      headers: { accept: 'application/json' }
    });
    const res = createMockResponse();

    await invokeHandler(req, res);

    expect(res.statusCode).toBe(200);
    expect(JSON.parse(res.body).status).toBe('ok');
  });

  it('returns account list via API endpoint', async () => {
    const tokenManager = {
      listAccounts: vi.fn(async () => [{ id: 'work', status: 'active' }]),
      getAccountMode: vi.fn(),
      setAccountMode: vi.fn(),
      clearTokens: vi.fn(),
      saveTokens: vi.fn()
    } as any;
    const handler = new HttpTransportHandler({}, tokenManager, () => ({ connect: vi.fn(async () => undefined) } as any));
    await handler.connect();

    const req = createMockRequest({
      method: 'GET',
      url: '/api/accounts',
      headers: { origin: 'http://localhost', accept: 'application/json' }
    });
    const res = createMockResponse();

    await invokeHandler(req, res);

    expect(tokenManager.listAccounts).toHaveBeenCalledTimes(1);
    expect(res.statusCode).toBe(200);
    expect(JSON.parse(res.body).accounts).toEqual([{ id: 'work', status: 'active' }]);
  });

  it('allows /api/accounts from configured non-localhost origins', async () => {
    const tokenManager = {
      listAccounts: vi.fn(async () => [{ id: 'work', status: 'active' }]),
      getAccountMode: vi.fn(),
      setAccountMode: vi.fn(),
      clearTokens: vi.fn(),
      saveTokens: vi.fn()
    } as any;
    const handler = new HttpTransportHandler({
      allowedOriginsForAccounts: ['https://gateway.example.com']
    }, tokenManager, () => ({ connect: vi.fn(async () => undefined) } as any));
    await handler.connect();

    const req = createMockRequest({
      method: 'GET',
      url: '/api/accounts',
      headers: { origin: 'https://gateway.example.com', accept: 'application/json' }
    });
    const res = createMockResponse();

    await invokeHandler(req, res);

    expect(res.statusCode).toBe(200);
    expect(JSON.parse(res.body).accounts).toEqual([{ id: 'work', status: 'active' }]);
  });

  it('still rejects /mcp from configured non-localhost origins', async () => {
    const tokenManager = { listAccounts: vi.fn(), getAccountMode: vi.fn(), setAccountMode: vi.fn(), clearTokens: vi.fn(), saveTokens: vi.fn() } as any;
    const handler = new HttpTransportHandler({
      allowedOriginsForAccounts: ['https://gateway.example.com']
    }, tokenManager, () => ({ connect: vi.fn(async () => undefined) } as any));
    await handler.connect();

    const req = createMockRequest({
      method: 'POST',
      url: '/mcp',
      headers: { origin: 'https://gateway.example.com', accept: 'application/json' }
    });
    const res = createMockResponse();

    await invokeHandler(req, res);

    expect(res.statusCode).toBe(403);
    expect(res.body).toContain('Invalid origin');
  });

  it('creates OAuth URL for POST /api/accounts', async () => {
    const tokenManager = { listAccounts: vi.fn(), getAccountMode: vi.fn(), setAccountMode: vi.fn(), clearTokens: vi.fn(), saveTokens: vi.fn() } as any;
    const handler = new HttpTransportHandler({ port: 4000, host: 'localhost' }, tokenManager, () => ({ connect: vi.fn(async () => undefined) } as any));
    await handler.connect();

    const req = createMockRequest({
      method: 'POST',
      url: '/api/accounts',
      headers: { origin: 'http://localhost', accept: 'application/json', 'content-length': '25' }
    });
    const res = createMockResponse();

    req.headers['content-type'] = 'application/json';
    req.body = { accountId: 'work' };
    await invokeHandler(req, res);

    expect(state.validateAccountId).toHaveBeenCalledWith('work');
    expect(res.statusCode).toBe(200);
    const payload = JSON.parse(res.body);
    expect(payload.accountId).toBe('work');
    expect(payload.authUrl).toBe('https://auth.example.com');
  });

  it('uses public base URL for OAuth redirect URI when configured', async () => {
    const tokenManager = { listAccounts: vi.fn(), getAccountMode: vi.fn(), setAccountMode: vi.fn(), clearTokens: vi.fn(), saveTokens: vi.fn() } as any;
    const handler = new HttpTransportHandler({
      port: 4000,
      host: '0.0.0.0',
      publicBaseUrl: 'https://calendar.example.com'
    }, tokenManager, () => ({ connect: vi.fn(async () => undefined) } as any));
    await handler.connect();

    const req = createMockRequest({
      method: 'POST',
      url: '/api/accounts',
      headers: { origin: 'http://localhost', accept: 'application/json', 'content-length': '25' }
    });
    const res = createMockResponse();

    req.headers['content-type'] = 'application/json';
    req.body = { accountId: 'work' };
    await invokeHandler(req, res);

    expect(res.statusCode).toBe(200);
    expect(state.lastOAuthRedirectUri).toBe('https://calendar.example.com/oauth2callback?account=work');

  });

  it('returns 500 when MCP transport request handling throws', async () => {
    const tokenManager = { listAccounts: vi.fn(), getAccountMode: vi.fn(), setAccountMode: vi.fn(), clearTokens: vi.fn(), saveTokens: vi.fn() } as any;
    const handler = new HttpTransportHandler({}, tokenManager, () => ({ connect: vi.fn(async () => undefined) } as any));
    await handler.connect();

    if (!state.transport) {
      throw new Error('Transport mock not initialized');
    }
    state.transport.handleRequest.mockRejectedValueOnce(new Error('boom'));

    const req = createMockRequest({
      method: 'POST',
      url: '/mcp',
      headers: { origin: 'http://localhost', accept: 'application/json' }
    });
    const res = createMockResponse();

    await invokeHandler(req, res);

    expect(res.statusCode).toBe(500);
    expect(res.body).toContain('Internal server error');
  });
});
