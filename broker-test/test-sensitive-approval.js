import { createSensitiveApprovalStore, payloadDigest } from '../broker/lib/sensitive-approval.js';

let passed = 0, failed = 0;
function ok(name, value) { if (value) { passed++; console.log('  PASS ', name); } else { failed++; console.error('  FAIL ', name); } }
async function rejects(name, fn) { try { await fn(); ok(name, false); } catch { ok(name, true); } }

let now = 1_700_000_000_000;
const store = createSensitiveApprovalStore({ now: () => now });
const payload = { role: 'developer', enabled: false };
ok('digest stable', payloadDigest(payload) === payloadDigest({ enabled: false, role: 'developer' }));

const requesterGrant = store.issueReauth({ clientName: 'admin-a', sessionId: 'session-a', method: 'webauthn', credentialId: 'key-a' });
const request = store.requestApproval({ requester: 'admin-a', action: 'client.update', resource: 'client.target', payload, reauthGrant: requesterGrant.grant, sessionId: 'session-a' });
ok('approval request created', !!request.approval_id);
await rejects('reauth grant is one-time', () => store.requestApproval({ requester: 'admin-a', action: 'x', resource: 'y', payload: {}, reauthGrant: requesterGrant.grant, sessionId: 'session-a' }));

const approverGrant = store.issueReauth({ clientName: 'admin-b', sessionId: 'session-b', method: 'webauthn', credentialId: 'key-b' });
await rejects('requester cannot self-approve', () => store.approve({ approvalId: request.approval_id, approver: 'admin-a', role: 'admin', reauthGrant: approverGrant.grant, sessionId: 'session-b' }));
const approved = store.approve({ approvalId: request.approval_id, approver: 'admin-b', role: 'admin', reauthGrant: approverGrant.grant, sessionId: 'session-b' });
ok('distinct admin approval accepted', approved.ready && approved.approvals === 1);

const sharedStore = createSensitiveApprovalStore({ now: () => now });
const sharedRequester = sharedStore.issueReauth({ clientName: 'admin-a', sessionId: 'a', method: 'webauthn', credentialId: 'shared-key' });
const sharedRequest = sharedStore.requestApproval({ requester: 'admin-a', action: 'x', resource: 'y', payload: {}, reauthGrant: sharedRequester.grant, sessionId: 'a' });
const sharedApprover = sharedStore.issueReauth({ clientName: 'admin-b', sessionId: 'b', method: 'webauthn', credentialId: 'shared-key' });
await rejects('same physical authenticator cannot satisfy dual control', () => sharedStore.approve({ approvalId: sharedRequest.approval_id, approver: 'admin-b', role: 'admin', reauthGrant: sharedApprover.grant, sessionId: 'b' }));

await rejects('payload tampering rejected', () => store.consumeApproval({ approvalId: request.approval_id, requester: 'admin-a', action: 'client.update', resource: 'client.target', payload: { role: 'admin' } }));
ok('bound approval consumed', store.consumeApproval({ approvalId: request.approval_id, requester: 'admin-a', action: 'client.update', resource: 'client.target', payload }) === true);
await rejects('approval cannot replay', () => store.consumeApproval({ approvalId: request.approval_id, requester: 'admin-a', action: 'client.update', resource: 'client.target', payload }));

const expiring = createSensitiveApprovalStore({ now: () => now });
const expGrant = expiring.issueReauth({ clientName: 'admin-a', sessionId: 's', method: 'webauthn', credentialId: 'k' });
now += 5 * 60 * 1000 + 1;
ok('expired reauth rejected', expiring.verifyReauth(expGrant.grant, { clientName: 'admin-a', sessionId: 's' }) === false);
await rejects('wrong session rejected', () => {
  const g = expiring.issueReauth({ clientName: 'admin-a', sessionId: 'right', method: 'webauthn', credentialId: 'k' });
  return expiring.requestApproval({ requester: 'admin-a', action: 'x', resource: 'y', payload: {}, reauthGrant: g.grant, sessionId: 'wrong' });
});
await rejects('invalid reauth context rejected', () => store.issueReauth({ clientName: 'a', sessionId: 's', method: 'totp' }));

const validationStore = createSensitiveApprovalStore({ now: () => now });
const missingFieldsGrant = validationStore.issueReauth({ clientName: 'admin-a', sessionId: 's1', method: 'webauthn', credentialId: 'k1' });
await rejects('approval action and resource required', () => validationStore.requestApproval({ requester: 'admin-a', payload: {}, reauthGrant: missingFieldsGrant.grant, sessionId: 's1' }));
const roleRequester = validationStore.issueReauth({ clientName: 'admin-a', sessionId: 's2', method: 'webauthn', credentialId: 'k1' });
const roleRequest = validationStore.requestApproval({ requester: 'admin-a', action: 'x', resource: 'y', payload: {}, reauthGrant: roleRequester.grant, sessionId: 's2' });
const nonAdminGrant = validationStore.issueReauth({ clientName: 'user-b', sessionId: 's3', method: 'webauthn', credentialId: 'k2' });
await rejects('non-admin approver rejected', () => validationStore.approve({ approvalId: roleRequest.approval_id, approver: 'user-b', role: 'developer', reauthGrant: nonAdminGrant.grant, sessionId: 's3' }));
const bindingRequester = validationStore.issueReauth({ clientName: 'admin-c', sessionId: 's4', method: 'webauthn', credentialId: 'k3' });
const bindingRequest = validationStore.requestApproval({ requester: 'admin-c', action: 'rotate', resource: 'secret.a', payload: {}, reauthGrant: bindingRequester.grant, sessionId: 's4' });
const bindingApprover = validationStore.issueReauth({ clientName: 'admin-d', sessionId: 's5', method: 'webauthn', credentialId: 'k4' });
validationStore.approve({ approvalId: bindingRequest.approval_id, approver: 'admin-d', role: 'admin', reauthGrant: bindingApprover.grant, sessionId: 's5' });
await rejects('operation binding mismatch rejected', () => validationStore.consumeApproval({ approvalId: bindingRequest.approval_id, requester: 'admin-c', action: 'delete', resource: 'secret.a', payload: {} }));
await rejects('unapproved request cannot be consumed', () => {
  const g = validationStore.issueReauth({ clientName: 'admin-e', sessionId: 's6', method: 'webauthn', credentialId: 'k5' });
  const r = validationStore.requestApproval({ requester: 'admin-e', action: 'x', resource: 'z', payload: {}, reauthGrant: g.grant, sessionId: 's6' });
  return validationStore.consumeApproval({ approvalId: r.approval_id, requester: 'admin-e', action: 'x', resource: 'z', payload: {} });
});

console.log(`\n${passed} passed, ${failed} failed`);
process.exit(failed ? 1 : 0);
