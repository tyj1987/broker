import { V2Error } from '../lib/operations-v2.js';

const TOOL = 'postgresql.database.inspect@1.0.0';
const QUERY_ID = 'database.inspect.v1';
const TARGET_REF_RE = /^[a-z0-9][a-z0-9._-]{0,127}$/;
const IDENTIFIER_RE = /^[A-Za-z_][A-Za-z0-9_.-]{0,62}$/;
const RESULT_KEYS = new Set([
  'target_ref',
  'database',
  'server_version_num',
  'in_recovery',
  'current_user',
  'transaction_read_only',
  'role_superuser',
  'role_bypass_rls',
  'role_create_db',
  'role_create_role',
  'role_replication',
]);

function fail(code, message, status = 400) {
  throw new V2Error(code, message, status);
}

function validateParameters(parameters) {
  if (
    !parameters ||
    typeof parameters !== 'object' ||
    Array.isArray(parameters) ||
    Object.keys(parameters).length !== 1 ||
    !Object.hasOwn(parameters, 'resource_ref')
  ) {
    fail('postgresql_invalid_request', 'PostgreSQL inspection accepts only resource_ref');
  }
  if (typeof parameters.resource_ref !== 'string' || !TARGET_REF_RE.test(parameters.resource_ref)) {
    fail('postgresql_invalid_target', 'PostgreSQL target reference is invalid');
  }
  return parameters.resource_ref;
}

function validateResult(result, targetRef) {
  if (!result || typeof result !== 'object' || Array.isArray(result)) {
    fail('postgresql_invalid_response', 'PostgreSQL runner returned an invalid result', 502);
  }
  if (Object.keys(result).some((key) => !RESULT_KEYS.has(key))) {
    fail('postgresql_invalid_response', 'PostgreSQL runner returned unexpected fields', 502);
  }
  if (result.target_ref !== targetRef) {
    fail(
      'postgresql_scope_mismatch',
      'PostgreSQL result does not match the authorized target',
      502,
    );
  }
  if (
    !IDENTIFIER_RE.test(result.database || '') ||
    !IDENTIFIER_RE.test(result.current_user || '')
  ) {
    fail('postgresql_invalid_response', 'PostgreSQL runner returned an invalid identity', 502);
  }
  if (
    !Number.isSafeInteger(result.server_version_num) ||
    result.server_version_num < 100000 ||
    result.server_version_num > 999999 ||
    typeof result.in_recovery !== 'boolean'
  ) {
    fail('postgresql_invalid_response', 'PostgreSQL runner returned invalid server metadata', 502);
  }
  const privilegeFields = [
    'role_superuser',
    'role_bypass_rls',
    'role_create_db',
    'role_create_role',
    'role_replication',
  ];
  if (
    result.transaction_read_only !== true ||
    privilegeFields.some((field) => typeof result[field] !== 'boolean' || result[field] !== false)
  ) {
    fail(
      'postgresql_read_only_boundary_failed',
      'PostgreSQL runner did not prove the required read-only role boundary',
      502,
    );
  }
  return {
    target_ref: targetRef,
    database: result.database,
    server_version_num: result.server_version_num,
    in_recovery: result.in_recovery,
    current_user: result.current_user,
    read_only_enforced: true,
  };
}

export function createPostgresqlDatabaseInspectAdapter({ runner } = {}) {
  if (typeof runner !== 'function') {
    throw new TypeError('PostgreSQL inspection requires an isolated query runner capability');
  }

  return async function postgresqlDatabaseInspect(parameters, context = {}) {
    const targetRef = validateParameters(parameters);
    if (
      context.execution?.tool !== TOOL ||
      context.execution?.target !== targetRef ||
      context.execution?.environment !== context.environment
    ) {
      fail(
        'postgresql_execution_binding_mismatch',
        'Execution capability is not bound to this PostgreSQL target',
        403,
      );
    }
    if (typeof context.accountRef !== 'string' || !context.accountRef) {
      fail('postgresql_account_unavailable', 'PostgreSQL account binding is unavailable', 503);
    }

    let result;
    try {
      result = await runner({
        query_id: QUERY_ID,
        account_ref: context.accountRef,
        environment: context.environment,
        target_ref: targetRef,
        transaction: 'read_only',
        statement_timeout_ms: 5000,
        lock_timeout_ms: 1000,
        maximum_rows: 1,
        signal: context.signal,
      });
    } catch {
      fail('postgresql_runner_unavailable', 'PostgreSQL runner is unavailable', 502);
    }
    return validateResult(result, targetRef);
  };
}

export const POSTGRESQL_DATABASE_INSPECT_CONTRACT = Object.freeze({
  tool: TOOL,
  query_id: QUERY_ID,
  arbitrary_sql: false,
  credential_export: false,
  transaction: 'read_only',
  statement_timeout_ms: 5000,
  lock_timeout_ms: 1000,
  maximum_rows: 1,
  forbidden_role_attributes: Object.freeze([
    'SUPERUSER',
    'BYPASSRLS',
    'CREATEDB',
    'CREATEROLE',
    'REPLICATION',
  ]),
});
