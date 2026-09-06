export const SECURITY_PROFILES = Object.freeze(['strict', 'controlled', 'compatibility']);

export function securityProfile(config) {
  const value = String(config?.security_profile || 'strict').toLowerCase();
  return SECURITY_PROFILES.includes(value) ? value : 'strict';
}

export function permits(config, capability) {
  const profile = securityProfile(config);
  const matrix = {
    strict: new Set(['typed_operations', 'mtls', 'trusted_proxy', 'workload_identity']),
    controlled: new Set(['typed_operations', 'legacy_proxy', 'mtls', 'trusted_proxy', 'workload_identity', 'passkey', 'api_key']),
    compatibility: new Set(['typed_operations', 'legacy_proxy', 'secret_resolve', 'ssh_exec', 'mtls', 'trusted_proxy', 'workload_identity', 'passkey', 'api_key', 'password']),
  };
  return matrix[profile].has(capability);
}

export function tlsAuthorizationPolicy(config) {
  const requireAuthorizedPeer = securityProfile(config) !== 'compatibility';
  return Object.freeze({
    requestCert: true,
    rejectUnauthorized: requireAuthorizedPeer,
    minVersion: 'TLSv1.3',
  });
}

export function resolveOperation(service, operationId, parameters = {}) {
  const operation = service?.operations?.[operationId];
  if (!operation) throw new Error('Unknown or disabled operation');
  if (!parameters || typeof parameters !== 'object' || Array.isArray(parameters)) {
    throw new Error('Operation parameters must be an object');
  }
  const allowed = new Set(operation.allowed_parameters || []);
  const required = new Set(operation.required_parameters || []);
  const query = {};
  for (const [name, value] of Object.entries(parameters || {})) {
    if (!allowed.has(name)) throw new Error(`Parameter is not allowed: ${name}`);
    if (!['string', 'number', 'boolean'].includes(typeof value) ||
        (typeof value === 'number' && !Number.isFinite(value)) ||
        String(value).length > 2048) {
      throw new Error(`Parameter has an invalid value: ${name}`);
    }
    query[name] = value;
  }
  for (const name of required) {
    if (query[name] === undefined || query[name] === null || query[name] === '') throw new Error(`Missing required parameter: ${name}`);
  }
  return {
    method: validateOperationMethod(operation.method),
    path: validateOperationPath(operation.path),
    query,
    allowBody: operation.allow_body === true,
    maxBodyBytes: validateMaxBodyBytes(operation.max_body_bytes),
    environment: String(operation.environment || service.environment || 'default'),
    resource: operation.resource_parameter
      ? String(query[operation.resource_parameter] ?? '')
      : String(operation.resource || '*'),
    providerAction: operation.provider_action,
    apiVersion: operation.api_version,
    serviceCode: operation.service_code,
    region: operation.region,
  };
}

const OPERATION_ID_RE = /^[a-z][a-z0-9_.-]{0,63}$/;
const PARAMETER_NAME_RE = /^[A-Za-z][A-Za-z0-9_.-]{0,127}$/;
const OPERATION_METHODS = new Set(['GET', 'POST', 'PUT', 'PATCH', 'DELETE']);

function validateOperationMethod(value) {
  const method = String(value || 'GET').toUpperCase();
  if (!OPERATION_METHODS.has(method)) throw new Error(`Unsupported operation method: ${method}`);
  return method;
}

function validateOperationPath(value) {
  const path = String(value || '/');
  if (!path.startsWith('/') || path.startsWith('//') || path.includes('\\') ||
      /[\u0000-\u001f\u007f]/.test(path) || path.includes('?') || path.includes('#')) {
    throw new Error('Operation path must be a clean relative path without query or fragment');
  }
  return path;
}

function validateMaxBodyBytes(value) {
  const max = value === undefined ? 64 * 1024 : Number(value);
  if (!Number.isSafeInteger(max) || max < 0 || max > 1024 * 1024) {
    throw new Error('Operation max_body_bytes must be an integer between 0 and 1048576');
  }
  return max;
}

function normalizeParameterNames(value, label) {
  if (value === undefined) return [];
  if (!Array.isArray(value)) throw new Error(`${label} must be an array`);
  const out = [];
  for (const raw of value) {
    const name = String(raw);
    if (!PARAMETER_NAME_RE.test(name)) throw new Error(`Invalid operation parameter name: ${name}`);
    if (!out.includes(name)) out.push(name);
  }
  return out;
}

/**
 * Sanitize an administrator-supplied typed-operation catalog before it is
 * persisted. Unknown fields are dropped and executable URL/header input is
 * never accepted here.
 */
export function normalizeOperations(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new Error('operations must be an object');
  }
  const out = {};
  for (const [operationId, raw] of Object.entries(value)) {
    if (!OPERATION_ID_RE.test(operationId)) throw new Error(`Invalid operation id: ${operationId}`);
    if (!raw || typeof raw !== 'object' || Array.isArray(raw)) {
      throw new Error(`Operation ${operationId} must be an object`);
    }
    const allowed = normalizeParameterNames(raw.allowed_parameters, 'allowed_parameters');
    const required = normalizeParameterNames(raw.required_parameters, 'required_parameters');
    if (required.some(name => !allowed.includes(name))) {
      throw new Error(`Operation ${operationId} has a required parameter that is not allowed`);
    }
    const operation = {
      method: validateOperationMethod(raw.method),
      path: validateOperationPath(raw.path),
      allowed_parameters: allowed,
      required_parameters: required,
      allow_body: raw.allow_body === true,
      max_body_bytes: validateMaxBodyBytes(raw.max_body_bytes),
    };
    if (raw.environment !== undefined) {
      const environment = String(raw.environment);
      if (!/^[a-z][a-z0-9_-]{0,31}$/.test(environment)) throw new Error(`Invalid operation environment: ${environment}`);
      operation.environment = environment;
    }
    if (raw.resource !== undefined) {
      const resource = String(raw.resource);
      if (!resource || resource.length > 512 || /[\u0000-\u001f\u007f]/.test(resource)) throw new Error('Invalid operation resource');
      operation.resource = resource;
    }
    if (raw.resource_parameter !== undefined) {
      const resourceParameter = String(raw.resource_parameter);
      if (!allowed.includes(resourceParameter)) throw new Error(`Operation ${operationId} resource_parameter must be allowed`);
      operation.resource_parameter = resourceParameter;
    }
    for (const [input, output] of [['provider_action', 'provider_action'], ['api_version', 'api_version'], ['service_code', 'service_code'], ['region', 'region']]) {
      if (raw[input] === undefined) continue;
      const fixed = String(raw[input]);
      if (!/^[A-Za-z0-9_.-]{1,128}$/.test(fixed)) throw new Error(`Invalid operation ${input}`);
      operation[output] = fixed;
    }
    out[operationId] = operation;
  }
  if (Object.keys(out).length === 0) throw new Error('operations must not be empty');
  return out;
}
