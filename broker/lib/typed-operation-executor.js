import { canInvokeOperation } from '../can-proxy.js';
import { canInvokeApiKeyOperation } from '../api-keys.js';
import { resolveOperation, securityProfile } from './security-profile.js';

function denied(status, message) {
  return { ok: false, status, message };
}

export async function executeTypedOperation({
  config,
  ctx,
  serviceName,
  operationId,
  payload = {},
  guardCredential,
  callUpstream,
  audit = () => {},
}) {
  const svc = config?.services?.[serviceName];
  if (!svc) return denied(404, `Unknown service: ${serviceName}`);

  let request;
  try {
    request = resolveOperation(svc, operationId, payload.parameters);
  } catch (error) {
    audit({ action: 'operation', cn: ctx?.cn, fp: ctx?.fp, service: serviceName, operation: operationId, status: 'denied', reason: error.message });
    return denied(400, error.message);
  }

  if (payload.body !== undefined && !request.allowBody) {
    return denied(400, 'This operation does not accept a request body');
  }
  if (payload.body !== undefined && Buffer.byteLength(JSON.stringify(payload.body)) > request.maxBodyBytes) {
    return denied(413, 'Operation body exceeds its configured limit');
  }

  const attributes = {
    serviceName,
    operationId,
    path: request.path,
    method: request.method,
    environment: request.environment,
    resource: request.resource,
  };
  if ((ctx?.apiKey && !canInvokeApiKeyOperation(ctx.apiKey, serviceName, operationId)) ||
      !canInvokeOperation(ctx, attributes, { strict: securityProfile(config) === 'strict' })) {
    audit({
      action: 'operation', cn: ctx?.cn, fp: ctx?.fp, service: serviceName, operation: operationId,
      environment: request.environment, resource: request.resource,
      status: 'denied', reason: 'operation_policy',
    });
    return denied(403, 'Operation is not allowed for this identity');
  }

  if (Array.isArray(svc.allow_methods) &&
      !svc.allow_methods.map(value => String(value).toUpperCase()).includes(request.method)) {
    return denied(403, 'Operation method is not allowed for this service');
  }

  const guard = guardCredential(svc);
  if (!guard?.allowed) {
    return denied(503, `Service ${serviceName} is unavailable because its credential is not healthy`);
  }

  const operationService = {
    ...svc,
    name: serviceName,
    ...(request.providerAction ? { action: request.providerAction } : {}),
    ...(request.apiVersion ? { api_version: request.apiVersion } : {}),
    ...(request.serviceCode ? { service_code: request.serviceCode } : {}),
    ...(request.region ? { region: request.region } : {}),
  };

  try {
    const result = await callUpstream(
      operationService,
      request.method,
      request.path,
      request.query,
      {},
      payload.body,
      { serviceName },
    );
    audit({
      action: 'operation', cn: ctx?.cn, fp: ctx?.fp, service: serviceName, operation: operationId,
      status: result.status < 400 ? 'ok' : 'error', upstream_status: result.status,
    });
    return { ok: true, result };
  } catch (error) {
    audit({ action: 'operation', cn: ctx?.cn, fp: ctx?.fp, service: serviceName, operation: operationId, status: 'error', error: error.message });
    return denied(502, 'Typed upstream operation failed');
  }
}
