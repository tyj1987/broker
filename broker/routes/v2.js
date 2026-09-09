import { V2Error, canonicalJson } from '../lib/operations-v2.js';

function identityView(ctx) {
  if (!ctx?.clientName) return null;
  return {
    name: ctx.clientName,
    isAdmin: ctx.client?.role === 'admin',
    context: ctx,
  };
}
function signedRequest(req, routePath, body = null) {
  return {
    timestamp: req.headers['x-broker-device-timestamp'],
    nonce: req.headers['x-broker-device-nonce'],
    signature: req.headers['x-broker-device-signature'],
    method: req.method,
    path: routePath,
    body: body === null ? '' : canonicalJson(body),
  };
}

function claimDualControlApproval(approvalBroker, identity, input) {
  const claim = approvalBroker.claimFor(identity, input);
  const approvers = new Set((claim?.grants || []).map((grant) => grant?.approved_by).filter(Boolean));
  if (!claim || approvers.size < 2 || approvers.has(identity.name)) {
    if (claim) approvalBroker.markFailed(claim.id);
    throw new V2Error('approval_required', 'two independent approvals are required', 403);
  }
  return claim;
}

function deviceEnrollmentApproval(body) {
  return {
    provider: 'broker', operation_id: 'device.enroll', account_ref: 'control-plane', environment: 'production',
    typed_parameters: {
      resource_ref: 'device-registration', label: body?.label,
      platform: body?.platform, capabilities: body?.capabilities || [],
    },
    approval_request_id: body?.approval_request_id,
  };
}

function deviceStateApproval(deviceId, body) {
  return {
    provider: 'broker', operation_id: 'device.state', account_ref: 'control-plane', environment: 'production',
    typed_parameters: { resource_ref: 'device-state', device_id: deviceId, state: body?.state },
    approval_request_id: body?.approval_request_id,
  };
}

export function createV2Routes(deps) {
  const {
    operationBroker, approvalBroker, taskBroker, webAuthnService, getIdentity, readBody, send, audit,
    makeSession, sessionCookieHeader, authorizeApprovalRequest, consumeRateLimit,
    requireBrowserMutation,
  } = deps;
  const mandatoryAudit = (event) => {
    try {
      return audit(event, { mandatory: true });
    } catch {
      throw new V2Error('audit_unavailable', 'mandatory audit storage is unavailable', 503);
    }
  };

  return async function handleV2(req, res, route) {
    const { method, pathname } = route;
    if (!pathname.startsWith('/api/v2/')) return false;

    let requestContext = null;
    try {
      requestContext = getIdentity(req);
      if (requestContext && (typeof consumeRateLimit !== 'function' || !consumeRateLimit(requestContext))) {
        throw new V2Error('rate_limited', 'request rate limit exceeded', 429);
      }

      if (method === 'POST' && pathname === '/api/v2/auth/webauthn/begin') {
        const body = await readBody(req);
        const result = await webAuthnService.beginAuthentication(body);
        try {
          mandatoryAudit({ action: 'webauthn_authentication_begin', status: 'ok', client: body?.client });
        } catch (error) {
          webAuthnService.rollbackFlowCreation(result.flow_id, 'authentication', String(body?.client || ''));
          throw error;
        }
        send(res, 200, result);
        return true;
      }

      if (method === 'POST' && pathname === '/api/v2/auth/webauthn/finish') {
        const result = await webAuthnService.finishAuthentication(await readBody(req));
        const cn = `${result.clientName}@webauthn`;
        mandatoryAudit({
          action: 'webauthn_authentication', status: 'verified', cn,
          client: result.clientName, credential_id: result.credential.id,
        });
        const token = makeSession({
          cn, fp: result.credential.id, clientName: result.clientName,
          client: result.client, cert: { subject: { CN: cn } }, authFactors: ['webauthn'],
        });
        res.setHeader('Set-Cookie', sessionCookieHeader(token));
        send(res, 200, {
          expires_in: 600,
          strict_ready: result.strictReady,
          credential: result.credential,
        });
        return true;
      }

      if (method === 'POST' && pathname === '/api/v2/me/webauthn/registration/begin') {
        const ctx = getIdentity(req);
        const identity = identityView(ctx);
        if (!identity) throw new V2Error('unauthorized', 'authenticated identity required', 401);
        const body = await readBody(req);
        mandatoryAudit({ action: 'webauthn_registration_begin_intent', status: 'authorized', cn: ctx.cn });
        const result = await webAuthnService.beginRegistration(identity, body);
        try {
          mandatoryAudit({ action: 'webauthn_registration_begin', status: 'ok', cn: ctx.cn });
        } catch (error) {
          webAuthnService.rollbackFlowCreation(result.flow_id, 'registration', identity.name);
          throw error;
        }
        send(res, 200, result);
        return true;
      }

      if (method === 'POST' && pathname === '/api/v2/me/webauthn/registration/finish') {
        const ctx = getIdentity(req);
        const identity = identityView(ctx);
        if (!identity) throw new V2Error('unauthorized', 'authenticated identity required', 401);
        const result = await webAuthnService.finishRegistration(identity, await readBody(req));
        audit({ action: 'webauthn_registration_finish', status: 'ok', cn: ctx.cn, credential_id: result.credential.id });
        send(res, 201, result);
        return true;
      }

      if (method === 'GET' && pathname === '/api/v2/me/webauthn/credentials') {
        const ctx = getIdentity(req);
        const identity = identityView(ctx);
        if (!identity) throw new V2Error('unauthorized', 'authenticated identity required', 401);
        const credentials = webAuthnService.list(ctx.client);
        audit({ action: 'v2_webauthn_credential_list', status: 'ok', cn: ctx.cn, count: credentials.length });
        send(res, 200, {
          credentials,
          strict_ready: webAuthnService.strictReady(ctx.client),
        });
        return true;
      }

      if (method === 'GET' && pathname === '/api/v2/tools') {
        const ctx = getIdentity(req);
        const identity = identityView(ctx);
        if (!identity) throw new V2Error('unauthorized', 'authenticated identity required', 401);
        if (!taskBroker || typeof taskBroker.listTools !== 'function') {
          throw new V2Error('task_broker_unavailable', 'task broker is unavailable', 503);
        }
        const tools = taskBroker.listTools(identity);
        audit({ action: 'v2_tool_list', status: 'ok', cn: ctx.cn, count: tools.length });
        send(res, 200, { registry_version: 1, tools });
        return true;
      }

      if (method === 'POST' && pathname === '/api/v2/tasks') {
        const ctx = getIdentity(req);
        const identity = identityView(ctx);
        if (!identity) throw new V2Error('unauthorized', 'authenticated identity required', 401);
        if (!taskBroker) throw new V2Error('task_broker_unavailable', 'task broker is unavailable', 503);
        const taskBody = await readBody(req);
        mandatoryAudit({ action: 'v2_task_create_intent', status: 'attempt', cn: ctx.cn, tool: taskBody?.tool });
        const result = await taskBroker.create(identity, taskBody);
        audit({ action: 'v2_task_create', status: result.state, cn: ctx.cn, task_id: result.id, risk_level: result.risk_level });
        send(res, 202, result);
        return true;
      }

      const taskEventsMatch = /^\/api\/v2\/tasks\/([a-f0-9-]+)\/events$/.exec(pathname);
      if (method === 'GET' && taskEventsMatch) {
        const ctx = getIdentity(req);
        const identity = identityView(ctx);
        if (!identity) throw new V2Error('unauthorized', 'authenticated identity required', 401);
        if (!taskBroker) throw new V2Error('task_broker_unavailable', 'task broker is unavailable', 503);
        const events = taskBroker.eventsFor(identity, taskEventsMatch[1]);
        audit({ action: 'v2_task_event_list', status: 'ok', cn: ctx.cn, task_id: taskEventsMatch[1], count: events.length });
        send(res, 200, { events });
        return true;
      }

      const taskActionMatch = /^\/api\/v2\/tasks\/([a-f0-9-]+)\/(run|cancel)$/.exec(pathname);
      if (method === 'POST' && taskActionMatch) {
        const ctx = getIdentity(req);
        const identity = identityView(ctx);
        if (!identity) throw new V2Error('unauthorized', 'authenticated identity required', 401);
        if (!taskBroker) throw new V2Error('task_broker_unavailable', 'task broker is unavailable', 503);
        const taskBody = await readBody(req);
        if (!taskBody || typeof taskBody !== 'object' || Array.isArray(taskBody) || Object.keys(taskBody).length !== 0) {
          throw new V2Error('invalid_request', 'task action body must be an empty object');
        }
        mandatoryAudit({ action: `v2_task_${taskActionMatch[2]}_intent`, status: 'attempt', cn: ctx.cn, task_id: taskActionMatch[1] });
        const result = taskActionMatch[2] === 'run'
          ? await taskBroker.run(identity, taskActionMatch[1])
          : taskBroker.cancel(identity, taskActionMatch[1]);
        audit({
          action: `v2_task_${taskActionMatch[2]}`, status: result.state, cn: ctx.cn,
          task_id: result.id, execution_id: result.execution_id, tool: result.tool,
          target: result.target, environment: result.environment, risk_level: result.risk_level,
          latency_ms: result.latency_ms, error: result.error?.code,
        });
        send(res, 200, result);
        return true;
      }

      const taskMatch = /^\/api\/v2\/tasks\/([a-f0-9-]+)$/.exec(pathname);
      if (method === 'GET' && taskMatch) {
        const ctx = getIdentity(req);
        const identity = identityView(ctx);
        if (!identity) throw new V2Error('unauthorized', 'authenticated identity required', 401);
        if (!taskBroker) throw new V2Error('task_broker_unavailable', 'task broker is unavailable', 503);
        const result = taskBroker.get(identity, taskMatch[1]);
        audit({ action: 'v2_task_get', status: 'ok', cn: ctx.cn, task_id: result.id, task_state: result.state });
        send(res, 200, result);
        return true;
      }

      if (method === 'POST' && pathname === '/api/v2/operations') {
        const ctx = getIdentity(req);
        const identity = identityView(ctx);
        if (!identity) throw new V2Error('unauthorized', 'authenticated identity required', 401);
        const body = await readBody(req);
        mandatoryAudit({ action: 'v2_operation_create_intent', status: 'authorized', cn: ctx.cn, provider: body?.provider });
        const claim = approvalBroker.claimFor(identity, body);
        const authorizedIdentity = claim ? {
          ...identity,
          context: {
            ...identity.context,
            approvalGrants: [...(identity.context.approvalGrants || []), ...claim.grants],
          },
        } : identity;
        let result;
        try {
          result = await operationBroker.createOperation(authorizedIdentity, body);
        } catch (error) {
          if (claim) approvalBroker.markFailed(claim.id);
          throw error;
        }
        try {
          mandatoryAudit({ action: 'v2_operation_create', status: 'ok', cn: ctx.cn, operation_id: result.id, provider: result.provider });
        } catch (error) {
          operationBroker.rollbackOperationCreation(identity, result.id);
          if (claim) approvalBroker.releaseClaim(claim.id);
          throw error;
        }
        if (claim) approvalBroker.markSucceeded(claim.id);
        send(res, 202, result);
        return true;
      }

      if (method === 'POST' && pathname === '/api/v2/approvals') {
        const ctx = getIdentity(req);
        const identity = identityView(ctx);
        if (!identity) throw new V2Error('unauthorized', 'authenticated identity required', 401);
        const body = await readBody(req);
        if (typeof authorizeApprovalRequest !== 'function') {
          throw new V2Error('policy_unavailable', 'approval policy enforcement is unavailable', 503);
        }
        const authorization = await authorizeApprovalRequest({
          identity,
          provider: body?.provider,
          operationId: body?.operation_id,
          accountRef: body?.account_ref,
          environment: body?.environment,
          typedParameters: body?.typed_parameters,
        });
        if (!authorization?.allow) {
          throw new V2Error('forbidden', authorization?.reason || 'policy_denied', 403);
        }
        mandatoryAudit({ action: 'v2_approval_create_intent', status: 'authorized', cn: ctx.cn, provider: body?.provider });
        const result = approvalBroker.create(identity, body);
        try {
          mandatoryAudit({ action: 'v2_approval_create', status: 'ok', cn: ctx.cn, approval_id: result.id });
        } catch (error) {
          approvalBroker.rollbackCreation(identity, result.id);
          throw error;
        }
        send(res, 201, result);
        return true;
      }

      if (method === 'GET' && pathname === '/api/v2/approvals') {
        const ctx = getIdentity(req);
        const identity = identityView(ctx);
        if (!identity) throw new V2Error('unauthorized', 'authenticated identity required', 401);
        const approvals = approvalBroker.list(identity);
        audit({ action: 'v2_approval_list', status: 'ok', cn: ctx.cn, count: approvals.length });
        send(res, 200, { approvals });
        return true;
      }

      const approvalMatch = /^\/api\/v2\/approvals\/([a-f0-9-]+)\/decision$/.exec(pathname);
      if (method === 'POST' && approvalMatch) {
        const ctx = getIdentity(req);
        const identity = identityView(ctx);
        if (!identity) throw new V2Error('unauthorized', 'authenticated identity required', 401);
        if (typeof requireBrowserMutation !== 'function') {
          throw new V2Error('browser_origin_unavailable', 'trusted browser enforcement is unavailable', 503);
        }
        requireBrowserMutation(req, ctx);
        const body = await readBody(req);
        if (!body || typeof body !== 'object' || Array.isArray(body)
          || Object.keys(body).length !== 1 || !['approve', 'reject'].includes(body.decision)) {
          throw new V2Error('invalid_request', 'decision body must contain only approve or reject');
        }
        mandatoryAudit({ action: 'v2_approval_decision_intent', status: 'authorized', cn: ctx.cn, approval_id: approvalMatch[1] });
        const result = approvalBroker.decideAndAudit(identity, approvalMatch[1], body?.decision, (decision) => {
          mandatoryAudit({ action: 'v2_approval_decision', status: decision.status, cn: ctx.cn, approval_id: decision.id });
        });
        send(res, 200, result);
        return true;
      }

      const approvalCancelMatch = /^\/api\/v2\/approvals\/([a-f0-9-]+)\/cancel$/.exec(pathname);
      if (method === 'POST' && approvalCancelMatch) {
        const ctx = getIdentity(req);
        const identity = identityView(ctx);
        if (!identity) throw new V2Error('unauthorized', 'authenticated identity required', 401);
        const cancelBody = await readBody(req);
        if (!cancelBody || typeof cancelBody !== 'object' || Array.isArray(cancelBody)
          || Object.keys(cancelBody).length !== 0) {
          throw new V2Error('invalid_request', 'approval cancellation body must be an empty object');
        }
        mandatoryAudit({ action: 'v2_approval_cancel_intent', status: 'authorized', cn: ctx.cn, approval_id: approvalCancelMatch[1] });
        const result = approvalBroker.cancelAndAudit(identity, approvalCancelMatch[1], (cancelled) => {
          mandatoryAudit({ action: 'v2_approval_cancel', status: cancelled.status, cn: ctx.cn, approval_id: cancelled.id });
        });
        send(res, 200, result);
        return true;
      }

      const operationMatch = /^\/api\/v2\/operations\/([a-f0-9-]+)$/.exec(pathname);
      if (method === 'GET' && operationMatch) {
        const ctx = getIdentity(req);
        const identity = identityView(ctx);
        if (!identity) throw new V2Error('unauthorized', 'authenticated identity required', 401);
        const result = operationBroker.getOperation(identity, operationMatch[1]);
        audit({
          action: 'v2_operation_get', status: 'ok', cn: ctx.cn,
          operation_id: result.id, provider: result.provider, operation_status: result.status,
        });
        send(res, 200, result);
        return true;
      }

      if (method === 'POST' && pathname === '/api/v2/browser/otp/claim') {
        const ctx = getIdentity(req);
        const identity = identityView(ctx);
        if (!identity) throw new V2Error('unauthorized', 'authenticated identity required', 401);
        if (ctx.via !== 'api_key') throw new V2Error('identity_denied', 'browser bridge API key required', 403);
        if (!ctx.apiKey?.scopes?.includes('browser:otp:fill')) throw new V2Error('scope_denied', 'browser bridge scope required', 403);
        const body = await readBody(req);
        mandatoryAudit({ action: 'v2_browser_otp_claim_intent', status: 'authorized', cn: ctx.cn, provider: body?.provider });
        const result = operationBroker.claimBrowserOtpAndAudit(identity, body, (claim) => {
          mandatoryAudit({ action: 'v2_browser_otp_claim', status: 'ok', cn: ctx.cn, provider: claim.provider, operation_id: claim.operation_id });
        });
        send(res, 200, result);
        return true;
      }

      if (method === 'POST' && pathname === '/api/v2/browser/otp/finish') {
        const ctx = getIdentity(req);
        const identity = identityView(ctx);
        if (!identity) throw new V2Error('unauthorized', 'authenticated identity required', 401);
        if (ctx.via !== 'api_key') throw new V2Error('identity_denied', 'browser bridge API key required', 403);
        if (!ctx.apiKey?.scopes?.includes('browser:otp:fill')) throw new V2Error('scope_denied', 'browser bridge scope required', 403);
        const body = await readBody(req);
        mandatoryAudit({ action: 'v2_browser_otp_finish_intent', status: 'authorized', cn: ctx.cn });
        const result = operationBroker.finishBrowserOtpAndAudit(identity, body, (completion) => {
          mandatoryAudit({
            action: 'v2_browser_otp_finish', status: completion.status, cn: ctx.cn,
            operation_id: completion.operation_id,
          });
        });
        send(res, 200, result);
        return true;
      }

      if (method === 'POST' && pathname === '/api/v2/devices/enroll/begin') {
        const ctx = getIdentity(req);
        const identity = identityView(ctx);
        if (!identity) throw new V2Error('unauthorized', 'authenticated identity required', 401);
        if (!['mtls', 'session'].includes(ctx.via)) {
          throw new V2Error('step_up_required', 'device enrollment requires an interactive identity', 403);
        }
        const body = await readBody(req);
        if (!identity.isAdmin || ctx.client?.security_profile !== 'strict'
          || !ctx.authFactors?.includes('webauthn')) {
          throw new V2Error(
            'step_up_required',
            'device enrollment requires a strict administrator with WebAuthn step-up',
            403,
          );
        }
        mandatoryAudit({ action: 'v2_device_enroll_begin_intent', status: 'authorized', cn: ctx.cn, platform: body?.platform });
        const claim = claimDualControlApproval(approvalBroker, identity, deviceEnrollmentApproval(body));
        let result;
        try {
          result = operationBroker.beginEnrollment(identity.name, body);
        } catch (error) {
          approvalBroker.markFailed(claim.id);
          throw error;
        }
        try {
          mandatoryAudit({ action: 'v2_device_enroll_begin', status: 'ok', cn: ctx.cn, enrollment_id: result.enrollment_id });
        } catch (error) {
          operationBroker.rollbackEnrollment(identity.name, result.enrollment_id);
          approvalBroker.releaseClaim(claim.id);
          throw error;
        }
        approvalBroker.markSucceeded(claim.id);
        send(res, 201, result);
        return true;
      }

      if (method === 'POST' && pathname === '/api/v2/devices/enroll/finish') {
        // The high-entropy challenge is a five-minute pairing secret, and the
        // device separately proves possession of its generated private key.
        const body = await readBody(req);
        mandatoryAudit({ action: 'v2_device_enroll_finish_intent', status: 'authorized', enrollment_id: body?.enrollment_id });
        const result = await operationBroker.completeEnrollment(null, body);
        audit({ action: 'v2_device_enroll_finish', status: 'ok', device_id: result.id, platform: result.platform });
        send(res, 201, result);
        return true;
      }

      if (method === 'GET' && pathname === '/api/v2/devices') {
        const ctx = getIdentity(req);
        const identity = identityView(ctx);
        if (!identity) throw new V2Error('unauthorized', 'authenticated identity required', 401);
        if (ctx.apiKey || ctx.via === 'api_key') throw new V2Error('identity_denied', 'device inventory requires an interactive identity without bearer delegation', 403);
        const devices = operationBroker.listDevices(identity);
        audit({ action: 'v2_device_list', status: 'ok', cn: ctx.cn, count: devices.length });
        send(res, 200, { devices });
        return true;
      }

      const deviceMatch = /^\/api\/v2\/devices\/([a-f0-9-]+)$/.exec(pathname);
      if (method === 'PATCH' && deviceMatch) {
        const ctx = getIdentity(req);
        const identity = identityView(ctx);
        if (!identity) throw new V2Error('unauthorized', 'authenticated identity required', 401);
        if (!['mtls', 'session'].includes(ctx.via)) {
          throw new V2Error('step_up_required', 'device state changes require an interactive identity', 403);
        }
        const body = await readBody(req);
        if (!identity.isAdmin || ctx.client?.security_profile !== 'strict'
          || !ctx.authFactors?.includes('webauthn')) {
          throw new V2Error('step_up_required', 'device state changes require a strict administrator with WebAuthn step-up', 403);
        }
        mandatoryAudit({ action: 'v2_device_state_intent', status: 'authorized', cn: ctx.cn, device_id: deviceMatch[1], device_state: body?.state });
        const claim = claimDualControlApproval(approvalBroker, identity, deviceStateApproval(deviceMatch[1], body));
        let result;
        try {
          result = await operationBroker.setDeviceState(identity.name, deviceMatch[1], body?.state, identity.isAdmin);
          approvalBroker.markSucceeded(claim.id);
        } catch (error) {
          approvalBroker.markFailed(claim.id);
          throw error;
        }
        audit({ action: 'v2_device_state', status: 'ok', cn: ctx.cn, device_id: result.id, device_state: result.state });
        send(res, 200, result);
        return true;
      }

      const selfSuspendMatch = /^\/api\/v2\/devices\/([a-f0-9-]+)\/suspend$/.exec(pathname);
      if (method === 'POST' && selfSuspendMatch) {
        const body = await readBody(req);
        if (!body || typeof body !== 'object' || Array.isArray(body) || Object.keys(body).length !== 0) {
          throw new V2Error('invalid_request', 'device suspension body must be an empty object');
        }
        const deviceId = selfSuspendMatch[1];
        operationBroker.verifyDeviceRequest(deviceId, signedRequest(req, pathname, body));
        mandatoryAudit({ action: 'v2_device_self_suspend_intent', status: 'authorized', device_id: deviceId });
        const result = await operationBroker.suspendDevice(deviceId);
        audit({ action: 'v2_device_self_suspend', status: 'ok', device_id: deviceId });
        send(res, 200, result);
        return true;
      }

      const taskListMatch = /^\/api\/v2\/devices\/([a-f0-9-]+)\/otp-tasks$/.exec(pathname);
      if (method === 'GET' && taskListMatch) {
        const deviceId = taskListMatch[1];
        operationBroker.verifyDeviceRequest(deviceId, signedRequest(req, pathname));
        const tasks = operationBroker.listDeviceOtpTasks(deviceId);
        audit({ action: 'v2_device_otp_task_list', status: 'ok', device_id: deviceId, count: tasks.length });
        send(res, 200, { tasks });
        return true;
      }

      const submitMatch = /^\/api\/v2\/devices\/([a-f0-9-]+)\/otp-tasks\/([a-f0-9-]+)\/submit$/.exec(pathname);
      if (method === 'POST' && submitMatch) {
        const body = await readBody(req);
        const [deviceId, taskId] = submitMatch.slice(1);
        operationBroker.verifyDeviceRequest(deviceId, signedRequest(req, pathname, body));
        mandatoryAudit({ action: 'v2_otp_submit_intent', status: 'authorized', device_id: deviceId, operation_id: taskId });
        const result = operationBroker.submitOtpAndAudit(deviceId, taskId, body || {}, (received) => {
          mandatoryAudit({ action: 'v2_otp_received', status: 'ok', device_id: deviceId, operation_id: received.operation_id });
        });
        send(res, 202, result);
        return true;
      }

      const workerClaimMatch = /^\/api\/v2\/devices\/([a-f0-9-]+)\/browser-leases\/claim$/.exec(pathname);
      if (method === 'POST' && workerClaimMatch) {
        const body = await readBody(req);
        const deviceId = workerClaimMatch[1];
        operationBroker.verifyDeviceRequest(deviceId, signedRequest(req, pathname, body));
        mandatoryAudit({ action: 'v2_browser_lease_claim_intent', status: 'authorized', device_id: deviceId });
        const result = operationBroker.claimBrowserOperationAndAudit(deviceId, (lease) => {
          mandatoryAudit({ action: 'v2_browser_lease_claim', status: 'ok', device_id: deviceId, operation_id: lease.operation.id });
        });
        send(res, 200, result);
        return true;
      }

      const workerOtpMatch = /^\/api\/v2\/devices\/([a-f0-9-]+)\/browser-leases\/([a-f0-9-]+)\/otp$/.exec(pathname);
      if (method === 'POST' && workerOtpMatch) {
        const body = await readBody(req);
        const [deviceId, leaseId] = workerOtpMatch.slice(1);
        operationBroker.verifyDeviceRequest(deviceId, signedRequest(req, pathname, body));
        mandatoryAudit({ action: 'v2_browser_lease_otp_intent', status: 'authorized', device_id: deviceId, lease_id: leaseId });
        const result = operationBroker.claimBrowserOperationOtpAndAudit(deviceId, leaseId, body?.receipt, () => {
          mandatoryAudit({ action: 'v2_browser_lease_otp', status: 'ok', device_id: deviceId, lease_id: leaseId });
        });
        send(res, 200, result);
        return true;
      }

      const workerCompleteMatch = /^\/api\/v2\/devices\/([a-f0-9-]+)\/browser-leases\/([a-f0-9-]+)\/complete$/.exec(pathname);
      if (method === 'POST' && workerCompleteMatch) {
        const body = await readBody(req);
        const [deviceId, leaseId] = workerCompleteMatch.slice(1);
        operationBroker.verifyDeviceRequest(deviceId, signedRequest(req, pathname, body));
        mandatoryAudit({ action: 'v2_browser_lease_complete_intent', status: 'authorized', device_id: deviceId, lease_id: leaseId });
        const result = operationBroker.completeBrowserOperationAndAudit(deviceId, leaseId, body, (completion) => {
          mandatoryAudit({ action: 'v2_browser_lease_complete', status: completion.status, device_id: deviceId, operation_id: completion.operation_id });
        });
        send(res, 200, result);
        return true;
      }

      throw new V2Error('not_found', 'v2 endpoint not found', 404);
    } catch (error) {
      const safe = error instanceof V2Error
        ? error
        : new V2Error('internal_error', 'request could not be processed', 500);
      audit({
        action: 'v2_request', status: 'denied', reason: safe.code, path: pathname,
        cn: requestContext?.cn, actor: requestContext?.clientName,
      });
      send(res, safe.status, { error: safe.code, message: safe.message, status: safe.status });
      return true;
    }
  };
}
