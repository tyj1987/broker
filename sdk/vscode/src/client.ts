// Secret Broker VS Code extension — TypeScript client.
// Zero npm deps: uses Node's built-in https + tls modules for mTLS.
//
// 7 commands:
//   health, list, get, resolve, proxy, sshExec, login

import * as https from 'node:https';
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
  /** Test-only escape hatch. Production configurations must leave this false. */
  insecureSkipVerify?: boolean;
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
  mfa_required?: boolean;
  mfa_token?: string;
}

export interface OperationRequest {
  provider: string;
  operation_id: string;
  account_ref: string;
  environment: 'development' | 'staging' | 'production';
  typed_parameters: Record<string, unknown>;
  otp?: Record<string, unknown>;
  approval_request_id?: string;
}

export interface ApprovalResponse {
  id: string;
  requester: string;
  provider: string;
  operation_id: string;
  account_ref: string;
  environment: string;
  resource_ref: string;
  required_approvals: number;
  approvals: Array<{ approved_by: string; approved_at: string }>;
  status: 'pending' | 'approved' | 'rejected' | 'expired' | 'consumed';
  created_at: string;
  expires_at: string;
}

export interface OperationResponse {
  id: string;
  provider: string;
  operation_id: string;
  status: 'waiting' | 'received' | 'consuming' | 'completed' | 'failed' | 'expired' | 'revoked';
  result?: Record<string, unknown>;
  error?: Record<string, unknown>;
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

  private isVerifyDisabled(): boolean {
    return this.config.insecureSkipVerify === true;
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
      'user-agent': 'secret-broker-vscode/4.2.0',
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
      const req = https.request(
        {
          method,
          hostname: u.hostname,
          port: u.port ? Number(u.port) : 443,
          path: u.pathname + u.search,
          headers,
          ca: this.config.caCert ? fs.readFileSync(this.config.caCert) : undefined,
          cert: this.config.clientCert ? fs.readFileSync(this.config.clientCert) : undefined,
          key: this.config.clientKey ? fs.readFileSync(this.config.clientKey) : undefined,
          minVersion: 'TLSv1.2',
          rejectUnauthorized: !this.isVerifyDisabled(),
        },
        (res) => {
          const setCookies = res.headers['set-cookie'] || [];
          for (const header of setCookies) {
            const match = /^broker_session=([^;]*)/.exec(header);
            if (match) this.sessionCookie = match[1] || null;
          }
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
    const requestBody: Record<string, unknown> = { method: method.toUpperCase(), path: p };
    if (body !== undefined) requestBody.body = body;
    if (query) requestBody.query = query;
    return this.request<any>('proxy', 'POST', `/api/v1/proxy/${encodeURIComponent(service)}`, requestBody);
  }

  async createOperation(operation: OperationRequest): Promise<OperationResponse> {
    const r = await this.request<OperationResponse>(
      'create_operation', 'POST', '/api/v2/operations', operation
    );
    return r.body as OperationResponse;
  }

  async getOperation(id: string): Promise<OperationResponse> {
    const r = await this.request<OperationResponse>(
      'get_operation', 'GET', `/api/v2/operations/${encodeURIComponent(id)}`
    );
    return r.body as OperationResponse;
  }

  async createApproval(operation: OperationRequest): Promise<ApprovalResponse> {
    const request = {
      provider: operation.provider,
      operation_id: operation.operation_id,
      account_ref: operation.account_ref,
      environment: operation.environment,
      typed_parameters: operation.typed_parameters,
    };
    const r = await this.request<ApprovalResponse>('create_approval', 'POST', '/api/v2/approvals', request);
    return r.body as ApprovalResponse;
  }

  async listApprovals(): Promise<ApprovalResponse[]> {
    const r = await this.request<{ approvals: ApprovalResponse[] }>('list_approvals', 'GET', '/api/v2/approvals');
    return (r.body as { approvals: ApprovalResponse[] }).approvals;
  }

  async decideApproval(id: string, decision: 'approve' | 'reject'): Promise<ApprovalResponse> {
    if (!id || (decision !== 'approve' && decision !== 'reject')) {
      throw new Error('approval id and decision must be provided');
    }
    throw new Error('approval decisions require the WebAuthn browser workbench; no request was sent');
  }

  async sshExec(target: string, command: string, secretName = 'ssh.connection'): Promise<SSHExecResult> {
    const r = await this.request<SSHExecResult>('ssh_exec', 'POST', '/api/v1/ssh/exec', {
      target, command, secret_name: secretName,
    });
    return r.body as SSHExecResult;
  }

  async login(username: string, password: string, mfaToken?: string, mfaCode?: string): Promise<LoginResponse> {
    if (!!mfaToken !== !!mfaCode) throw new Error('mfaToken and mfaCode must be provided together');
    const r = mfaToken
      ? await this.request<LoginResponse>('login_mfa', 'POST', '/api/v1/login/mfa', {
          mfa_token: mfaToken, code: mfaCode,
        })
      : await this.request<LoginResponse>('login', 'POST', '/api/v1/login', { client: username, password });
    const b = r.body as LoginResponse;
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
