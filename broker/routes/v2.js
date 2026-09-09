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

export function createV2Routes(deps) {
  const {
    operationBroker, approvalBroker, webAuthnService, getIdentity, readBody, send, audit,
    makeSession, sessionCookieHeader, authorizeApprovalRequest, consumeRateLimit,
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

    try {
      const initialContext = getIdentity(req);
      if (initialContext && (typeof consumeRateLimit !== 'function' || !consumeRateLimit(initialContext))) {
        throw new V2Error('rate_limited', 'request rate limit exceeded', 429);
      }

      if (method === 'POST' && pathname === '/api/v2/auth/webauthn/begin') {
        const result = await webAuthnService.beginAuthentication(await readBody(req));
        send(res, 200, result);
        return true;
      }

      if (method === 'POST' && pathname === '/api/v2/auth/webauthn/finish') {
        const result = await webAuthnService.finishAuthentication(await readBody(req));
        const cn = `${result.clientName}@webauthn`;
        const token = makeSession({
          cn, fp: result.credential.id, clientName: result.clientName,
          client: result.client, cert: { subject: { CN: cn } }, authFactors: ['webauthn'],
        });
        res.setHeader('Set-Cookie', sessionCookieHeader(token));
        audit({ action: 'webauthn_authentication', status: 'ok', cn, client: result.clientName });
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
        const result = await webAuthnService.beginRegistration(identity, await readBody(req));
        audit({ action: 'webauthn_registration_begin', status: 'ok', cn: ctx.cn });
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
        send(res, 200, {
          credentials: webAuthnService.list(ctx.client),
          strict_ready: webAuthnService.strictReady(ctx.client),
        });
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
          if (claim) approvalBroker.consume(claim.id);
        } catch (error) {
          if (claim) approvalBroker.release(claim.id);
          throw error;
        }
        audit({ action: 'v2_operation_create', status: 'ok', cn: ctx.cn, operation_id: result.id, provider: result.provider });
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
        audit({ action: 'v2_approval_create', status: 'ok', cn: ctx.cn, approval_id: result.id });
        send(res, 201, result);
        return true;
      }

      if (method === 'GET' && pathname === '/api/v2/approvals') {
        const ctx = getIdentity(req);
        const identity = identityView(ctx);
        if (!identity) throw new V2Error('unauthorized', 'authenticated identity required', 401);
        send(res, 200, { approvals: approvalBroker.list(identity) });
        return true;
      }

      const approvalMatch = /^\/api\/v2\/approvals\/([a-f0-9-]+)\/decision$/.exec(pathname);
      if (method === 'POST' && approvalMatch) {
        const ctx = getIdentity(req);
        const identity = identityView(ctx);
        if (!identity) throw new V2Error('unauthorized', 'authenticated identity required', 401);
        const body = await readBody(req);
        mandatoryAudit({ action: 'v2_approval_decision_intent', status: 'authorized', cn: ctx.cn, approval_id: approvalMatch[1] });
        const result = approvalBroker.decide(identity, approvalMatch[1], body?.decision);
        audit({ action: 'v2_approval_decision', status: result.status, cn: ctx.cn, approval_id: result.id });
        send(res, 200, result);
        return true;
      }

      const operationMatch = /^\/api\/v2\/operations\/([a-f0-9-]+)$/.exec(pathname);
      if (method === 'GET' && operationMatch) {
        const ctx = getIdentity(req);
        const identity = identityView(ctx);
        if (!identity) throw new V2Error('unauthorized', 'authenticated identity required', 401);
        send(res, 200, operationBroker.getOperation(identity, operationMatch[1]));
        return true;
      }

      if (method === 'POST' && pathname === '/api/v2/browser/otp/claim') {
        const ctx = getIdentity(req);
        const identity = identityView(ctx);
        if (!identity) throw new V2Error('unauthorized', 'authenticated identity required', 401);
        if (ctx.via !== 'api_key') throw new V2Error('identity_denied', 'browser bridge API key required', 403);
        if (!ctx.apiKey?.scopes?.includes('browser:otp:fill')) throw new V2Error('scope_denied', 'browser bridge scope required', 403);
        const result = operationBroker.claimBrowserOtp(identity, await readBody(req));
        audit({ action: 'v2_browser_otp_claim', status: 'ok', cn: ctx.cn, provider: result.provider });
        send(res, 200, result);
        return true;
      }

      if (method === 'POST' && pathname === '/api/v2/browser/otp/finish') {
        const ctx = getIdentity(req);
        const identity = identityView(ctx);
        if (!identity) throw new V2Error('unauthorized', 'authenticated identity required', 401);
        if (ctx.via !== 'api_key') throw new V2Error('identity_denied', 'browser bridge API key required', 403);
        if (!ctx.apiKey?.scopes?.includes('browser:otp:fill')) throw new V2Error('scope_denied', 'browser bridge scope required', 403);
        const result = operationBroker.finishBrowserOtp(identity, await readBody(req));
        audit({ action: 'v2_browser_otp_finish', status: 'ok', cn: ctx.cn, operation_id: result.id, completed: result.status === 'completed' });
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
        if (body?.platform === 'browser-worker'
          && (!identity.isAdmin || ctx.client?.security_profile !== 'strict'
            || !ctx.authFactors?.includes('webauthn'))) {
          throw new V2Error(
            'step_up_required',
            'browser worker enrollment requires a strict administrator with WebAuthn step-up',
            403,
          );
        }
        mandatoryAudit({ action: 'v2_device_enroll_begin_intent', status: 'authorized', cn: ctx.cn, platform: body?.platform });
        const result = operationBroker.beginEnrollment(identity.name, body);
        audit({ action: 'v2_device_enroll_begin', status: 'ok', cn: ctx.cn, enrollment_id: result.enrollment_id });
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
        send(res, 200, { devices: operationBroker.listDevices(identity.name, identity.isAdmin) });
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
        mandatoryAudit({ action: 'v2_device_state_intent', status: 'authorized', cn: ctx.cn, device_id: deviceMatch[1], device_state: body?.state });
        const result = await operationBroker.setDeviceState(identity.name, deviceMatch[1], body?.state, identity.isAdmin);
        audit({ action: 'v2_device_state', status: 'ok', cn: ctx.cn, device_id: result.id, device_state: result.state });
        send(res, 200, result);
        return true;
      }

      const taskListMatch = /^\/api\/v2\/devices\/([a-f0-9-]+)\/otp-tasks$/.exec(pathname);
      if (method === 'GET' && taskListMatch) {
        const deviceId = taskListMatch[1];
        operationBroker.verifyDeviceRequest(deviceId, signedRequest(req, pathname));
        send(res, 200, { tasks: operationBroker.listDeviceOtpTasks(deviceId) });
        return true;
      }

      const submitMatch = /^\/api\/v2\/devices\/([a-f0-9-]+)\/otp-tasks\/([a-f0-9-]+)\/submit$/.exec(pathname);
      if (method === 'POST' && submitMatch) {
        const body = await readBody(req);
        const [deviceId, taskId] = submitMatch.slice(1);
        operationBroker.verifyDeviceRequest(deviceId, signedRequest(req, pathname, body));
        mandatoryAudit({ action: 'v2_otp_submit_intent', status: 'authorized', device_id: deviceId, operation_id: taskId });
        const result = operationBroker.submitOtp(deviceId, taskId, body || {});
        audit({ action: 'v2_otp_received', status: 'ok', device_id: deviceId, operation_id: result.operation_id });
        send(res, 202, result);
        return true;
      }

      const workerClaimMatch = /^\/api\/v2\/devices\/([a-f0-9-]+)\/browser-leases\/claim$/.exec(pathname);
      if (method === 'POST' && workerClaimMatch) {
        const body = await readBody(req);
        const deviceId = workerClaimMatch[1];
        operationBroker.verifyDeviceRequest(deviceId, signedRequest(req, pathname, body));
        mandatoryAudit({ action: 'v2_browser_lease_claim_intent', status: 'authorized', device_id: deviceId });
        const result = operationBroker.claimBrowserOperation(deviceId);
        audit({ action: 'v2_browser_lease_claim', status: 'ok', device_id: deviceId, operation_id: result.operation.id });
        send(res, 200, result);
        return true;
      }

      const workerOtpMatch = /^\/api\/v2\/devices\/([a-f0-9-]+)\/browser-leases\/([a-f0-9-]+)\/otp$/.exec(pathname);
      if (method === 'POST' && workerOtpMatch) {
        const body = await readBody(req);
        const [deviceId, leaseId] = workerOtpMatch.slice(1);
        operationBroker.verifyDeviceRequest(deviceId, signedRequest(req, pathname, body));
        mandatoryAudit({ action: 'v2_browser_lease_otp_intent', status: 'authorized', device_id: deviceId, lease_id: leaseId });
        const result = operationBroker.claimBrowserOperationOtp(deviceId, leaseId, body?.receipt);
        audit({ action: 'v2_browser_lease_otp', status: 'ok', device_id: deviceId, lease_id: leaseId });
        send(res, 200, result);
        return true;
      }

      const workerCompleteMatch = /^\/api\/v2\/devices\/([a-f0-9-]+)\/browser-leases\/([a-f0-9-]+)\/complete$/.exec(pathname);
      if (method === 'POST' && workerCompleteMatch) {
        const body = await readBody(req);
        const [deviceId, leaseId] = workerCompleteMatch.slice(1);
        operationBroker.verifyDeviceRequest(deviceId, signedRequest(req, pathname, body));
        mandatoryAudit({ action: 'v2_browser_lease_complete_intent', status: 'authorized', device_id: deviceId, lease_id: leaseId });
        const result = operationBroker.completeBrowserOperation(deviceId, leaseId, body);
        audit({ action: 'v2_browser_lease_complete', status: result.status, device_id: deviceId, operation_id: result.id });
        send(res, 200, result);
        return true;
      }

      throw new V2Error('not_found', 'v2 endpoint not found', 404);
    } catch (error) {
      const safe = error instanceof V2Error
        ? error
        : new V2Error('internal_error', 'request could not be processed', 500);
      audit({ action: 'v2_request', status: 'denied', reason: safe.code, path: pathname });
      send(res, safe.status, { error: safe.code, message: safe.message, status: safe.status });
      return true;
    }
  };
}
