import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import { resolve } from 'node:path';
import { Readable } from 'node:stream';

import {
  createGoogleDriveDocumentReadAdapter,
  GOOGLE_DRIVE_DOCUMENT_READ_CONTRACT,
} from '../broker/adapters/google-drive-document-read.js';
import { createGoogleDriveDocumentReadExecutor } from '../broker/adapters/google-drive-document-read-executor.js';
import { ApprovalBroker } from '../broker/lib/approvals-v2.js';
import { AutomationTaskBroker } from '../broker/lib/automation-tasks.js';
import { loadToolRegistry } from '../broker/lib/tool-registry.js';
import { V2Error } from '../broker/lib/operations-v2.js';

const NOW = Date.parse('2026-09-09T10:00:00Z');
const FILE_ID = '1AbCdEfGhIjKlMnOpQrStUvWxYz_12345';
const SCOPE = 'https://www.googleapis.com/auth/drive.file';
const parameters = { resource_ref: FILE_ID };
const context = {
  accountRef: 'drive-report-reader',
  environment: 'production',
  execution: {
    tool: 'google_drive.document.read@1.0.0',
    target: FILE_ID,
    environment: 'production',
  },
  signal: new AbortController().signal,
};
const validLease = () => ({
  token: 'unit-drive-token',
  account_ref: 'drive-report-reader',
  environment: 'production',
  file_id: FILE_ID,
  scope: SCOPE,
  expires_at: new Date(NOW + 60_000).toISOString(),
});
const approved = (content = 'Approved report.') => ({
  account_ref: 'drive-report-reader',
  environment: 'production',
  file_id: FILE_ID,
  classification: 'approved',
  content,
  redactions: 0,
});
const response = (body = 'Approved report.') => ({
  status: 200,
  headers: { 'content-type': 'text/plain; charset=utf-8' },
  body,
});
const expectCode = (code) => (error) => error instanceof V2Error && error.code === code;

let tokenInput;
let requestInput;
let filterInput;
const adapter = createGoogleDriveDocumentReadAdapter({
  now: () => NOW,
  tokenProvider: async (input) => {
    tokenInput = input;
    return validLease();
  },
  request: async (input) => {
    requestInput = input;
    return response();
  },
  contentFilter: async (input) => {
    filterInput = input;
    return approved(input.content);
  },
});
assert.deepEqual(await adapter(parameters, context), {
  file_id: FILE_ID,
  mime_type: 'text/plain',
  content: 'Approved report.',
  redactions: 0,
});
assert.deepEqual(tokenInput, {
  account_ref: 'drive-report-reader',
  environment: 'production',
  file_id: FILE_ID,
  scope: SCOPE,
  signal: context.signal,
});
assert.equal(requestInput.origin, 'https://www.googleapis.com');
assert.equal(requestInput.method, 'GET');
assert.equal(requestInput.path, `/drive/v3/files/${FILE_ID}/export?mimeType=text%2Fplain`);
assert.equal(requestInput.headers.Authorization, 'Bearer unit-drive-token');
assert.equal(requestInput.redirect, 'manual');
assert.equal(requestInput.max_response_bytes, 1024 * 1024);
assert.deepEqual(filterInput, {
  account_ref: 'drive-report-reader',
  environment: 'production',
  file_id: FILE_ID,
  mime_type: 'text/plain',
  content: 'Approved report.',
  signal: context.signal,
});

assert.throws(() => createGoogleDriveDocumentReadAdapter(), TypeError);
assert.throws(() => createGoogleDriveDocumentReadAdapter({ request: async () => {} }), TypeError);
assert.throws(
  () =>
    createGoogleDriveDocumentReadAdapter({
      request: async () => {},
      tokenProvider: async () => validLease(),
    }),
  TypeError,
);
assert.throws(
  () =>
    createGoogleDriveDocumentReadAdapter({
      request: async () => {},
      tokenProvider: async () => validLease(),
      contentFilter: async () => approved(),
      now: 1,
    }),
  TypeError,
);
for (const changed of [
  null,
  {},
  { resource_ref: '' },
  { resource_ref: '../document' },
  { resource_ref: FILE_ID, mime_type: 'application/pdf' },
  { resource_ref: FILE_ID, url: 'https://attacker.invalid' },
]) {
  await assert.rejects(
    adapter(changed, context),
    (error) =>
      error instanceof V2Error &&
      ['google_drive_invalid_request', 'google_drive_invalid_file'].includes(error.code),
  );
}
for (const execution of [
  { ...context.execution, tool: 'google_drive.file.download@1.0.0' },
  { ...context.execution, target: '1OtherDriveFileReference' },
  { ...context.execution, environment: 'staging' },
]) {
  await assert.rejects(
    adapter(parameters, { ...context, execution }),
    expectCode('google_drive_execution_binding_mismatch'),
  );
}
await assert.rejects(
  adapter(parameters, { ...context, accountRef: '' }),
  expectCode('google_drive_account_unavailable'),
);

const withLease = (lease) =>
  createGoogleDriveDocumentReadAdapter({
    now: () => NOW,
    tokenProvider: async () => lease,
    request: async () => response(),
    contentFilter: async (input) => approved(input.content),
  });
for (const [lease, code] of [
  [null, 'google_drive_credential_unavailable'],
  [{ ...validLease(), token: '' }, 'google_drive_credential_unavailable'],
  [{ ...validLease(), account_ref: 'other-account' }, 'google_drive_credential_unavailable'],
  [{ ...validLease(), environment: 'staging' }, 'google_drive_credential_unavailable'],
  [{ ...validLease(), file_id: '1OtherDriveFileReference' }, 'google_drive_credential_unavailable'],
  [
    { ...validLease(), scope: 'https://www.googleapis.com/auth/drive.readonly' },
    'google_drive_credential_unavailable',
  ],
  [
    { ...validLease(), expires_at: new Date(NOW).toISOString() },
    'google_drive_credential_expiry_invalid',
  ],
  [
    { ...validLease(), expires_at: new Date(NOW + 300_001).toISOString() },
    'google_drive_credential_expiry_invalid',
  ],
]) {
  await assert.rejects(withLease(lease)(parameters, context), expectCode(code));
}
await assert.rejects(
  createGoogleDriveDocumentReadAdapter({
    now: () => NOW,
    tokenProvider: async () => {
      throw new Error('Bearer canary-drive-credential-material');
    },
    request: async () => response(),
    contentFilter: async () => approved(),
  })(parameters, context),
  (error) =>
    expectCode('google_drive_credential_unavailable')(error) && !error.message.includes('canary'),
);

const withResponse = (upstreamResponse) =>
  createGoogleDriveDocumentReadAdapter({
    now: () => NOW,
    tokenProvider: async () => validLease(),
    request: async () => upstreamResponse,
    contentFilter: async (input) => approved(input.content),
  });
for (const [status, code] of [
  [301, 'google_drive_redirect_denied'],
  [401, 'google_drive_credential_rejected'],
  [403, 'google_drive_forbidden'],
  [404, 'google_drive_not_found'],
  [429, 'google_drive_rate_limited'],
  [500, 'google_drive_upstream_error'],
]) {
  await assert.rejects(
    withResponse({ status, headers: {}, body: '' })(parameters, context),
    expectCode(code),
  );
}
for (const upstreamResponse of [
  { status: 200, headers: { 'content-type': 'application/json' }, body: '{}' },
  response(Buffer.from([0xff])),
  response('bad\u0000text'),
]) {
  await assert.rejects(
    withResponse(upstreamResponse)(parameters, context),
    expectCode('google_drive_invalid_response'),
  );
}
await assert.rejects(
  withResponse(response(Buffer.alloc(1024 * 1024 + 1, 65)))(parameters, context),
  expectCode('google_drive_response_too_large'),
);
await assert.rejects(
  createGoogleDriveDocumentReadAdapter({
    now: () => NOW,
    tokenProvider: async () => validLease(),
    request: async () => {
      throw new Error('request failed with Bearer canary-drive-token-value');
    },
    contentFilter: async () => approved(),
  })(parameters, context),
  (error) => expectCode('google_drive_unavailable')(error) && !error.message.includes('canary'),
);
await assert.rejects(
  createGoogleDriveDocumentReadAdapter({
    now: () => NOW,
    tokenProvider: async () => validLease(),
    request: async () => {
      throw new V2Error('transport_policy_denied', 'safe', 403);
    },
    contentFilter: async () => approved(),
  })(parameters, context),
  expectCode('transport_policy_denied'),
);

const withFilter = (contentFilter, body = 'Approved report.') =>
  createGoogleDriveDocumentReadAdapter({
    now: () => NOW,
    tokenProvider: async () => validLease(),
    request: async () => response(body),
    contentFilter,
  });
for (const result of [
  null,
  { ...approved(), account_ref: 'other-account' },
  { ...approved(), environment: 'staging' },
  { ...approved(), file_id: '1OtherDriveFileReference' },
  { ...approved(), classification: 'denied' },
  { ...approved(), content: 1 },
  { ...approved(), redactions: -1 },
  { ...approved(), raw_content: 'not allowed' },
]) {
  await assert.rejects(
    withFilter(async () => result)(parameters, context),
    expectCode('google_drive_content_denied'),
  );
}
await assert.rejects(
  withFilter(async () => {
    throw new Error('filter failed on ghp_CanarySecretValue1234567890');
  })(parameters, context),
  (error) =>
    expectCode('google_drive_content_filter_unavailable')(error) &&
    !error.message.includes('CanarySecretValue'),
);
await assert.rejects(
  withFilter(async () => approved('x'.repeat(1024 * 1024 + 1)))(parameters, context),
  expectCode('google_drive_filtered_response_too_large'),
);
const secret = 'ghp_CanarySecretValue1234567890';
const redactedResult = await withFilter(
  async (input) => approved(input.content),
  `Report ${secret}`,
)(parameters, context);
assert.equal(redactedResult.content.includes(secret), false);
assert.equal(redactedResult.content, 'Report ghp_***');
assert.equal(redactedResult.redactions, 1);

const transportCalls = [];
const executor = createGoogleDriveDocumentReadExecutor({
  now: () => NOW,
  tokenProvider: async () => validLease(),
  contentFilter: async (input) => approved(input.content),
  resolveHost: async () => [{ address: '142.250.72.234', family: 4 }],
  requestImpl: (options, callback) => {
    const request = new EventEmitter();
    request.setTimeout = () => {};
    request.destroy = () => {};
    request.end = () => {
      transportCalls.push(options);
      const upstream = Readable.from(['Approved report.']);
      upstream.statusCode = 200;
      upstream.headers = { 'content-type': 'text/plain; charset=utf-8' };
      queueMicrotask(() => callback(upstream));
    };
    return request;
  },
});
assert.equal((await executor(parameters, context)).content, 'Approved report.');
assert.equal(transportCalls[0].hostname, 'www.googleapis.com');
assert.equal(transportCalls[0].rejectUnauthorized, true);

const registry = loadToolRegistry(resolve(import.meta.dirname, '../tools/registry.json'));
const events = [];
let calls = 0;
const taskBroker = new AutomationTaskBroker({
  toolRegistry: registry,
  authorize: async (operation) => ({
    allow:
      operation.provider === 'google_drive' &&
      operation.operationId === 'document.read' &&
      operation.accountRef === 'drive-report-reader' &&
      operation.environment === 'production' &&
      operation.typedParameters?.resource_ref === FILE_ID,
    ttlMs: 60_000,
  }),
  approvalBroker: new ApprovalBroker(),
  executors: new Map([
    [
      'google_drive.document.read@1.0.0',
      createGoogleDriveDocumentReadAdapter({
        now: () => NOW,
        tokenProvider: async () => validLease(),
        request: async () => response(`Quarterly report ${secret}`),
        contentFilter: async (input) => {
          calls += 1;
          return approved(input.content);
        },
      }),
    ],
  ]),
  onEvent: (event) => events.push(event),
});
const actor = {
  name: 'report-agent',
  context: {
    via: 'workload_identity',
    client: { role: 'operator', principal_type: 'workload', security_profile: 'strict' },
  },
};
const task = await taskBroker.create(actor, {
  tool: 'google_drive.document.read',
  tool_version: '1.0.0',
  account_ref: 'drive-report-reader',
  environment: 'production',
  idempotency_key: 'google-drive-read-task-0001',
  parameters,
});
assert.equal(task.state, 'READY');
const completed = await taskBroker.run(actor, task.id);
assert.equal(completed.state, 'SUCCEEDED');
assert.equal(completed.result.content, 'Quarterly report ghp_***');
assert.equal(calls, 1);
assert.deepEqual(
  taskBroker.eventsFor(actor, task.id).map((event) => event.state),
  ['REQUESTED', 'READY', 'EXECUTING', 'SUCCEEDED'],
);
for (const event of events) {
  const encoded = JSON.stringify(event);
  assert.equal(encoded.includes(secret), false);
  assert.equal(encoded.includes('unit-drive-token'), false);
  assert.equal(encoded.includes('typed_parameters'), false);
}
await assert.rejects(taskBroker.run(actor, task.id), expectCode('invalid_state'));
assert.equal(calls, 1);

assert.deepEqual(GOOGLE_DRIVE_DOCUMENT_READ_CONTRACT, {
  tool: 'google_drive.document.read@1.0.0',
  origin: 'https://www.googleapis.com',
  method: 'GET',
  path_template: '/drive/v3/files/{file_id}/export?mimeType=text%2Fplain',
  scope: SCOPE,
  mime_type: 'text/plain',
  maximum_response_bytes: 1024 * 1024,
  maximum_token_ttl_seconds: 300,
  content_filter_required: true,
});

console.log(
  'google drive read: file binding, least-privilege lease, filtering and task loop passed',
);
