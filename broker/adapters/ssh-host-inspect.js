import { V2Error } from '../lib/operations-v2.js';

const TOOL = 'ssh.host.inspect@1.0.0';
const OPERATION_ID = 'host.inspect';
const TARGET_REF_RE = /^[a-z0-9][a-z0-9._-]{0,127}$/;
const HOSTNAME_RE = /^[a-zA-Z0-9](?:[a-zA-Z0-9.-]{0,251}[a-zA-Z0-9])?$/;
const SERVICE_STATES = new Set(['active', 'inactive', 'failed', 'unknown']);
const RESULT_KEYS = new Set([
  'target_ref',
  'hostname',
  'uptime_seconds',
  'load_1m',
  'disk_used_percent',
  'service_state',
]);

function fail(code, message, status = 400) {
  throw new V2Error(code, message, status);
}

function validateParameters(parameters) {
  if (!parameters || typeof parameters !== 'object' || Array.isArray(parameters)) {
    fail('ssh_invalid_request', 'SSH host inspection parameters are invalid');
  }
  const keys = Object.keys(parameters);
  if (keys.length !== 1 || keys[0] !== 'resource_ref') {
    fail('ssh_invalid_request', 'SSH host inspection accepts only resource_ref');
  }
  if (typeof parameters.resource_ref !== 'string' || !TARGET_REF_RE.test(parameters.resource_ref)) {
    fail('ssh_invalid_target', 'SSH target reference is invalid');
  }
  return parameters.resource_ref;
}

function finiteNumber(value, minimum, maximum, field) {
  if (typeof value !== 'number' || !Number.isFinite(value) || value < minimum || value > maximum) {
    fail('ssh_invalid_response', `SSH runner returned an invalid ${field}`, 502);
  }
  return value;
}

function projectResult(result, targetRef) {
  if (!result || typeof result !== 'object' || Array.isArray(result)) {
    fail('ssh_invalid_response', 'SSH runner returned an invalid result', 502);
  }
  if (Object.keys(result).some((key) => !RESULT_KEYS.has(key))) {
    fail('ssh_invalid_response', 'SSH runner returned unexpected fields', 502);
  }
  if (result.target_ref !== targetRef) {
    fail('ssh_scope_mismatch', 'SSH runner result does not match the authorized target', 502);
  }
  if (typeof result.hostname !== 'string' || !HOSTNAME_RE.test(result.hostname)) {
    fail('ssh_invalid_response', 'SSH runner returned an invalid hostname', 502);
  }
  const uptimeSeconds = finiteNumber(result.uptime_seconds, 0, Number.MAX_SAFE_INTEGER, 'uptime');
  if (!Number.isSafeInteger(uptimeSeconds)) {
    fail('ssh_invalid_response', 'SSH runner returned an invalid uptime', 502);
  }
  const load = finiteNumber(result.load_1m, 0, 1_000_000, 'load');
  const disk = finiteNumber(result.disk_used_percent, 0, 100, 'disk usage');
  if (!SERVICE_STATES.has(result.service_state)) {
    fail('ssh_invalid_response', 'SSH runner returned an invalid service state', 502);
  }
  return {
    target_ref: targetRef,
    hostname: result.hostname,
    uptime_seconds: uptimeSeconds,
    load_1m: load,
    disk_used_percent: disk,
    service_state: result.service_state,
  };
}

export function createSshHostInspectAdapter({ runner } = {}) {
  if (typeof runner !== 'function') {
    throw new TypeError('SSH host inspection requires an isolated runner capability');
  }

  return async function sshHostInspect(parameters, context = {}) {
    const targetRef = validateParameters(parameters);
    if (
      context.execution?.tool !== TOOL ||
      context.execution?.target !== targetRef ||
      context.execution?.environment !== context.environment
    ) {
      fail(
        'ssh_execution_binding_mismatch',
        'Execution capability is not bound to this SSH target',
        403,
      );
    }
    if (typeof context.accountRef !== 'string' || !context.accountRef) {
      fail('ssh_account_unavailable', 'SSH account binding is unavailable', 503);
    }

    let result;
    try {
      result = await runner({
        operation_id: OPERATION_ID,
        account_ref: context.accountRef,
        environment: context.environment,
        target_ref: targetRef,
        signal: context.signal,
      });
    } catch {
      fail('ssh_runner_unavailable', 'SSH runner is unavailable', 502);
    }
    return projectResult(result, targetRef);
  };
}

export const SSH_HOST_INSPECT_CONTRACT = Object.freeze({
  tool: TOOL,
  operation_id: OPERATION_ID,
  input_fields: Object.freeze(['resource_ref']),
  output_fields: Object.freeze([...RESULT_KEYS]),
  arbitrary_command: false,
  credential_export: false,
  required_host_key_checking: 'strict',
});
