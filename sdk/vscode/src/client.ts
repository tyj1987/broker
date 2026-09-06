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
// Errors
// ============================================================
export class BrokerError extends Error {
  constructor(
    public op: string,
    public status: number,
    public body: string,
    message?: string
  ) {
    super(message || `broker: ${op} failed: HTTP ${status}`);
  }
}

export class BrokerConnectionError extends Error {
  constructor(op: string, cause: Error) {
    super(`broker: connection failed in ${op}: ${cause.message}`);
  }
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
// Client
// ============================================================
export class BrokerClient {
  private sessionCookie: string | null = null;

  constructor(private config: BrokerConfig) {
    if (!config.endpoint) throw new Error('endpoint required');
    if (!config.endpoint.startsWith('https://')) {
      throw new Error('endpoint must be https://');
    }
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

  private async request<T = any>(
    op: string,
    method: string,
    path: string,
    body?: any,
    query?: Record<string, string | number | undefined>
  ): Promise<{ status: number; body: T | string }> {
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
      const req = https.request(
        {
          method,
          hostname: u.hostname,
          port: u.port || 443,
          path: u.pathname + u.search,
          headers,
          secureContext: ctx,
          rejectUnauthorized: !this.isVerifyDisabled(),
        },
        (res) => {
          const chunks: Buffer[] = [];
          res.on('data', (c) => chunks.push(c));
          res.on('end', () => {
            const raw = Buffer.concat(chunks).toString('utf8');
            const status = res.statusCode || 0;
            if (status >= 400) {
              return reject(new BrokerError(op, status, redact(raw)));
            }
            let parsed: T | string = raw;
            if (raw && (res.headers['content-type'] || '').toString().includes('json')) {
              try { parsed = JSON.parse(raw) as T; } catch { /* keep string */ }
            }
            resolve({ status, body: parsed });
          });
        }
      );
      req.on('error', (e) => reject(new BrokerConnectionError(op, e)));
      req.setTimeout(30_000, () => {
        req.destroy(new Error('timeout after 30s'));
      });
      if (payload) req.write(payload);
      req.end();
    });
  }

  // ------------------------------------------------------------------
  // 7 calling surfaces
  // ------------------------------------------------------------------
  async health(): Promise<HealthResponse> {
    const r = await this.request<HealthResponse>('health', 'GET', '/health');
    return r.body as HealthResponse;
  }

  async list(): Promise<SecretListItem[]> {
    const r = await this.request<SecretListItem[]>('list', 'GET', '/api/v1/secrets');
    return (r.body as SecretListItem[]) || [];
  }

  async getSecret(name: string, version?: string): Promise<string> {
    const r = await this.request<{ name: string; value: any }>(
      'get_secret', 'POST', '/api/v1/secrets/resolve', { name, version }
    );
    const b = r.body as { name: string; value: any };
    return typeof b.value === 'string' ? b.value : JSON.stringify(b.value);
  }

  async resolveBulk(names: string[]): Promise<Record<string, string>> {
    const r = await this.request<{ values: Record<string, string> }>(
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
    return this.request<any>('proxy', method, `/api/v1/proxy/${encodeURIComponent(service)}${p}`, body, query);
  }

  async sshExec(target: string, command: string, secretName = 'ssh.connection'): Promise<SSHExecResult> {
    const r = await this.request<SSHExecResult>('ssh_exec', 'POST', '/api/v1/ssh/exec', {
      target, command, secret_name: secretName,
    });
    return r.body as SSHExecResult;
  }

  async login(username: string, password: string, mfaToken?: string, mfaCode?: string): Promise<LoginResponse> {
    const r = await this.request<LoginResponse>('login', 'POST', '/api/v1/login', {
      username, password, mfa_token: mfaToken, mfa_code: mfaCode,
    });
    const b = r.body as LoginResponse;
    if (b.session_token) this.sessionCookie = b.session_token;
    return b;
  }

  async logout(): Promise<void> {
    if (!this.sessionCookie) return;
    try {
      await this.request('logout', 'POST', '/api/v1/logout', {});
    } finally {
      this.sessionCookie = null;
    }
  }

  hasSession(): boolean {
    return !!this.sessionCookie;
  }
}
