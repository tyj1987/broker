// Secret Broker VS Code extension — TypeScript client.
// Zero npm deps: uses Node's built-in https + tls modules for mTLS.
//
// 7 commands:
//   health, list, get, resolve, proxy, sshExec, login

import * as https from 'node:https';
import * as tls from 'node:tls';
import * as fs from 'node:fs';
import * as crypto from 'node:crypto';

// ============================================================
// Types
// ============================================================
export interface BrokerConfig {
  endpoint: string;
  clientCert: string;
  clientKey: string;
  caCert: string;
  /**
   * If true, skip TLS certificate verification. NOT recommended for production.
   * Useful for local development with self-signed certs.
   */
  verifyTls?: boolean;
  /**
   * V4.1.1: max automatic retries on retryable errors (5xx / 429 / connection).
   * Defaults to 2 (i.e. up to 3 total attempts).
   * Set to 0 to disable retries.
   */
  maxRetries?: number;
  /**
   * V4.1.1: base backoff in ms; doubled on each retry. Defaults to 500ms.
   */
  retryBackoffMs?: number;
}

export interface SecretListItem {
  name: string;
  type: string;
}

export interface HealthResponse {
  ok: boolean;
  version: string;
}

export interface SSHExecResult {
  ok: boolean;
  exitCode: number;
  stdout: string;
  stderr: string;
  duration_ms: number;
}

export interface LoginResponse {
  session_token: string;
  mfa_required?: boolean;
  mfa_token?: string;
}

// ============================================================
// Errors (V4.1.1 — parity with Python/Go/CLI SDKs)
//
// Before V4.1.1: BrokerError had op/status/body/message (3 fields).
// V4.1.1 adds: code, requestId, retryAfter + isRetryable getter,
// toString(), toJSON() (body omitted, may contain secrets).
// ============================================================
export class BrokerError extends Error {
  /** Broker-specific error code from response body (e.g. "auth_failed"). Empty if unknown. */
  public code: string;
  /** X-Request-Id response header (correlate with broker audit logs). */
  public requestId: string;
  /** Retry-After response header (seconds), 0 if absent. */
  public retryAfter: number;
  /** Raw redacted response body. */
  public body: string;
  /** Logical operation that failed (e.g. "get_secret"). */
  public op: string;
  /** HTTP status code (0 for connection errors). */
  public status: number;

  constructor(
    op: string,
    status: number,
    body: string,
    message?: string,
    options?: { code?: string; requestId?: string; retryAfter?: number }
  ) {
    super(message || `broker: ${op} failed: HTTP ${status}`);
    this.name = 'BrokerError';
    this.op = op;
    this.status = status;
    // V4.1.1: ALWAYS redact body at construction (defense in depth).
    // Even if caller forgot to redact, secrets never leak into logs/UI.
    this.body = redact(body || '');
    this.code = options?.code || '';
    this.requestId = options?.requestId || '';
    this.retryAfter = options?.retryAfter || 0;
  }

  /** True if this error is worth retrying (5xx / 429 / connection). */
  get isRetryable(): boolean {
    if (this.status === 429) return true;
    if (this.status >= 500 && this.status < 600) return true;
    return false;
  }

  /** Human-readable string with status + code + request_id + retry_after. */
  toString(): string {
    const meta: string[] = [];
    if (this.status) meta.push(`status=${this.status}`);
    if (this.code) meta.push(`code=${this.code}`);
    if (this.requestId) meta.push(`request_id=${this.requestId}`);
    if (this.retryAfter > 0) meta.push(`retry_after=${this.retryAfter}s`);
    const suffix = meta.length ? ` [${meta.join(' ')}]` : '';
    return `${this.name}: ${this.message}${suffix}`;
  }

  /** Structured representation for logging / audit export. Body omitted (may contain secrets). */
  toJSON(): Record<string, unknown> {
    return {
      error_type: this.name,
      op: this.op,
      message: this.message,
      status: this.status,
      code: this.code,
      request_id: this.requestId,
      retry_after: this.retryAfter,
      is_retryable: this.isRetryable,
    };
  }
}

export class BrokerConnectionError extends Error {
  public op: string;
  public cause: Error;
  public requestId: string;
  /** Always true — connection failures are always worth retrying. */
  public readonly isRetryable: boolean = true;

  constructor(op: string, cause: Error, requestId: string = '') {
    super(`broker: connection failed in ${op}: ${cause.message}`);
    this.name = 'BrokerConnectionError';
    this.op = op;
    this.cause = cause;
    this.requestId = requestId;
  }

  toString(): string {
    const rid = this.requestId ? ` request_id=${this.requestId}` : '';
    return `${this.name}: ${this.message}${rid}`;
  }

  toJSON(): Record<string, unknown> {
    return {
      error_type: this.name,
      op: this.op,
      message: this.message,
      cause: this.cause.message,
      request_id: this.requestId,
      is_retryable: true,
    };
  }
}

/**
 * Parse a broker error response into a BrokerError.
 * @param status - HTTP status code
 * @param headers - response headers (lowercased keys)
 * @param body - response body (parsed JSON or string)
 * @param op - logical operation name
 */
export function parseBrokerError(
  status: number,
  headers: Record<string, string | string[] | undefined>,
  body: unknown,
  op: string = ''
): BrokerError {
  const requestId = String(headers['x-request-id'] || '');
  const retryAfter = parseInt(String(headers['retry-after'] || '0'), 10) || 0;

  let code = '';
  let message = `HTTP ${status}`;
  let rawBody = '';

  if (body && typeof body === 'object') {
    const obj = body as { error?: unknown; message?: unknown; code?: unknown };
    if (obj.error && typeof obj.error === 'object') {
      const e = obj.error as { code?: unknown; message?: unknown };
      code = String(e.code || '');
      message = String(e.message || message);
    } else if (typeof obj.error === 'string') {
      message = obj.error;
    } else if (typeof obj.message === 'string') {
      message = obj.message;
    }
    if (typeof obj.code === 'string') code = obj.code;
    rawBody = JSON.stringify(body);
  } else if (typeof body === 'string') {
    rawBody = body;
    if (body) message = body;
  }

  return new BrokerError(op, status, redact(rawBody), message, {
    code, requestId, retryAfter,
  });
}

// ============================================================
// Redaction (zero credential leakage in UI / logs)
// ============================================================
const REDACT_PATTERNS: Array<[RegExp, string]> = [
  [/(gh[pousr]_[A-Za-z0-9]{20,})/g, '[REDACTED_GITHUB]'],
  [/(sk-[A-Za-z0-9]{20,})/g, '[REDACTED_OPENAI]'],
  [/(sk-ant-[A-Za-z0-9_\-]{20,})/g, '[REDACTED_ANTHROPIC]'],
  [/(AKIA[A-Z0-9]{12,})/g, '[REDACTED_AWS]'],
  [/(ASIA[A-Z0-9]{12,})/g, '[REDACTED_AWS_STS]'],
  [/(eyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,})/g, '[REDACTED_JWT]'],
];

export function redact(s: string): string {
  if (!s) return s;
  let out = s;
  for (const [rx, repl] of REDACT_PATTERNS) {
    out = out.replace(rx, repl);
  }
  return out;
}

// ============================================================
// Retry (V4.1.1)
// ============================================================
function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

// ============================================================
// Client
// ============================================================
export class BrokerClient {
  private sessionCookie: string | null = null;
  private maxRetries: number;
  private retryBackoffMs: number;

  constructor(private config: BrokerConfig) {
    if (!config.endpoint) throw new Error('endpoint required');
    if (!config.endpoint.startsWith('https://')) {
      throw new Error('endpoint must be https://');
    }
    this.maxRetries = config.maxRetries ?? 2;
    this.retryBackoffMs = config.retryBackoffMs ?? 500;
  }

  private buildContext(): tls.SecureContext {
    const ctx = tls.createSecureContext({
      ca: this.config.caCert ? fs.readFileSync(this.config.caCert) : undefined,
      cert: this.config.clientCert ? fs.readFileSync(this.config.clientCert) : undefined,
      key: this.config.clientKey ? fs.readFileSync(this.config.clientKey) : undefined,
      minVersion: 'TLSv1.2' as tls.SecureVersion,
    });
    return ctx;
  }

  private isVerifyDisabled(): boolean {
    return this.config.verifyTls === true;
  }

  /**
   * Get a copy of this client's config. Used internally for testing.
   */
  getConfig(): Readonly<BrokerConfig> { return this.config; }

  /**
   * V4.1.1: get current maxRetries config.
   */
  getMaxRetries(): number { return this.maxRetries; }

  /**
   * V4.1.1: get current retryBackoffMs config.
   */
  getRetryBackoffMs(): number { return this.retryBackoffMs; }

  /**
   * V4.1.1: low-level mTLS request with structured error + retry.
   * Retries on connection errors, 5xx, 429 (up to maxRetries times).
   * Honors Retry-After header if present.
   */
  private async mtlsRequest<T = any>(
    op: string,
    method: string,
    path: string,
    body?: any,
    query?: Record<string, string | number | undefined>
  ): Promise<{ status: number; body: T | string; requestId: string }> {
    let lastErr: Error | null = null;
    const totalAttempts = this.maxRetries + 1;

    for (let attempt = 0; attempt < totalAttempts; attempt++) {
      try {
        return await this.requestOnce<T>(op, method, path, body, query);
      } catch (e: any) {
        lastErr = e;
        // Only retry on retryable errors + if we have attempts left
        const isConn = e instanceof BrokerConnectionError;
        const isRetryableBroker = e instanceof BrokerError && e.isRetryable;
        if (!isConn && !isRetryableBroker) throw e;
        if (attempt === totalAttempts - 1) throw e;

        // Compute backoff: prefer Retry-After header on BrokerError, else exponential
        let waitMs = this.retryBackoffMs * Math.pow(2, attempt);
        if (e instanceof BrokerError && e.retryAfter > 0) {
          waitMs = e.retryAfter * 1000;
        }
        await sleep(waitMs);
      }
    }
    // Should not reach here, but satisfy TS
    throw lastErr || new Error('mtlsRequest: no attempts made');
  }

  private async requestOnce<T = any>(
    op: string,
    method: string,
    path: string,
    body?: any,
    query?: Record<string, string | number | undefined>
  ): Promise<{ status: number; body: T | string; requestId: string }> {
    const u = new URL(path, this.config.endpoint);
    if (query) {
      for (const [k, v] of Object.entries(query)) {
        if (v !== undefined) u.searchParams.set(k, String(v));
      }
    }
    const headers: Record<string, string> = {
      'accept': 'application/json',
      'user-agent': 'secret-broker-vscode/4.1.1',
      'x-request-id': `vscode-${crypto.randomUUID()}`,
    };
    let payload: Buffer | undefined;
    if (body !== undefined && body !== null) {
      payload = Buffer.from(JSON.stringify(body), 'utf8');
      headers['content-type'] = 'application/json';
      headers['content-length'] = String(payload.length);
    }
    if (this.sessionCookie) {
      headers['cookie'] = `broker_session=${this.sessionCookie}`;
    }
    return new Promise((resolve, reject) => {
      const ctx = this.buildContext();
      // V4.1.1: cast secureContext (Node supports it, @types/node lags)
      const req = https.request(
        {
          method,
          hostname: u.hostname,
          // V4.1.1: cast port to string (URL.port is string, fallback was number)
          port: u.port || '443',
          path: u.pathname + u.search,
          headers,
          secureContext: ctx,
          rejectUnauthorized: !this.isVerifyDisabled(),
        } as any,
        (res) => {
          const chunks: Buffer[] = [];
          res.on('data', (c) => chunks.push(c));
          res.on('end', () => {
            const raw = Buffer.concat(chunks).toString('utf8');
            const status = res.statusCode || 0;
            const reqId = String(res.headers['x-request-id'] || headers['x-request-id']);
            if (status >= 400) {
              let parsed: unknown = raw;
              if (raw && (res.headers['content-type'] || '').toString().includes('json')) {
                try { parsed = JSON.parse(raw); } catch { /* keep string */ }
              }
              const e = parseBrokerError(status, res.headers, parsed, op);
              // Override requestId with response header (if present)
              if (reqId) e.requestId = reqId;
              return reject(e);
            }
            let parsed: T | string = raw;
            if (raw && (res.headers['content-type'] || '').toString().includes('json')) {
              try { parsed = JSON.parse(raw) as T; } catch { /* keep string */ }
            }
            resolve({ status, body: parsed, requestId: reqId });
          });
        }
      );
      const requestId = headers['x-request-id'];
      req.on('error', (e) => reject(new BrokerConnectionError(op, e, requestId)));
      req.setTimeout(30_000, () => {
        req.destroy(new Error('timeout after 30s'));
      });
      if (payload) req.write(payload);
      req.end();
    });
  }

  // ------------------------------------------------------------------
  // 7 calling surfaces (now route through mtlsRequest for retry)
  // ------------------------------------------------------------------
  async health(): Promise<HealthResponse> {
    const r = await this.mtlsRequest<HealthResponse>('health', 'GET', '/health');
    return r.body as HealthResponse;
  }

  async list(): Promise<SecretListItem[]> {
    const r = await this.mtlsRequest<SecretListItem[]>('list', 'GET', '/api/v1/secrets');
    return (r.body as SecretListItem[]) || [];
  }

  async getSecret(name: string, version?: string): Promise<string> {
    const r = await this.mtlsRequest<{ name: string; value: any }>(
      'get_secret', 'POST', '/api/v1/secrets/resolve', { name, version }
    );
    const b = r.body as { name: string; value: any };
    return typeof b.value === 'string' ? b.value : JSON.stringify(b.value);
  }

  async resolveBulk(names: string[]): Promise<Record<string, string>> {
    const r = await this.mtlsRequest<{ values: Record<string, string> }>(
      'resolve', 'POST', '/api/v1/secrets/resolve_bulk', { names }
    );
    return (r.body as { values: Record<string, string> }).values || {};
  }

  async proxy(
    service: string,
    method: string,
    subPath: string,
    body?: any,
    query?: Record<string, string>
  ): Promise<{ status: number; body: any }> {
    const p = subPath.startsWith('/') ? subPath : '/' + subPath;
    return this.mtlsRequest<any>('proxy', method, `/api/v1/proxy/${encodeURIComponent(service)}${p}`, body, query);
  }

  async sshExec(target: string, command: string, secretName = 'ssh.connection'): Promise<SSHExecResult> {
    const r = await this.mtlsRequest<SSHExecResult>('ssh_exec', 'POST', '/api/v1/ssh/exec', {
      target, command, secret_name: secretName,
    });
    return r.body as SSHExecResult;
  }

  async login(username: string, password: string, mfaToken?: string, mfaCode?: string): Promise<LoginResponse> {
    const r = await this.mtlsRequest<LoginResponse>('login', 'POST', '/api/v1/login', {
      username, password, mfa_token: mfaToken, mfa_code: mfaCode,
    });
    const b = r.body as LoginResponse;
    if (b.session_token) this.sessionCookie = b.session_token;
    return b;
  }

  async logout(): Promise<void> {
    if (!this.sessionCookie) return;
    try {
      await this.mtlsRequest('logout', 'POST', '/api/v1/logout', {});
    } finally {
      this.sessionCookie = null;
    }
  }

  hasSession(): boolean {
    return !!this.sessionCookie;
  }
}
