import { resolveOperation } from './security-profile.js';
import { canInvokeOperation } from '../can-proxy.js';

function denied(statusCode, message) {
  const error = new Error(message);
  error.statusCode = statusCode;
  return error;
}

export function prepareReadOnlyServiceTest({ serviceName, service, body, context }) {
  const operationId = typeof body?.operation_id === 'string' ? body.operation_id : '';
  let request;
  try { request = resolveOperation(service, operationId, body?.parameters); }
  catch (error) { throw denied(400, `Invalid test operation: ${error.message}`); }
  if (request.method !== 'GET' || request.allowBody) {
    throw denied(403, 'Service tests are limited to typed read-only GET operations');
  }
  const attributes = {
    serviceName,
    operationId,
    path: request.path,
    method: request.method,
    environment: request.environment,
    resource: request.resource,
  };
  if (!canInvokeOperation(context, attributes, { strict: true })) {
    throw denied(403, 'Test operation is not allowed for this identity');
  }
  return { operationId, request, attributes };
}
