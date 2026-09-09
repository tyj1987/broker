// WebAuthn-session approval workbench. Decisions remain in the browser and are
// never delegated to a desktop/mobile device key or API key.
(() => {
  'use strict';

  let currentIdentity = null;

  function setApprovalStatus(message, kind = '') {
    const status = document.getElementById('approval-status');
    if (!status) return;
    status.textContent = message;
    status.className = `status ${kind}`.trim();
  }

  function appendCell(row, value) {
    const cell = document.createElement('td');
    cell.textContent = value == null ? '' : String(value);
    row.appendChild(cell);
    return cell;
  }

  async function decideApproval(id, decision) {
    const verb = decision === 'approve' ? 'approve' : 'reject';
    if (!window.confirm(`Confirm ${verb} for this bound request?`)) return;
    setApprovalStatus('Submitting decision…', 'warn');
    try {
      await api(`/api/v2/approvals/${encodeURIComponent(id)}/decision`, {
        method: 'POST', body: { decision },
      });
      setApprovalStatus(`Request ${verb === 'approve' ? 'approved' : 'rejected'}.`, 'ok');
      await loadApprovals();
    } catch (error) {
      setApprovalStatus(`Decision denied: ${error.message || error}`, 'err');
    }
  }

  function actionButtons(approval) {
    const wrap = document.createElement('div');
    wrap.className = 'approval-actions';
    const canDecide = approval.status === 'pending'
      && currentIdentity?.via === 'session'
      && currentIdentity?.auth_factors?.includes('webauthn')
      && approval.requester !== currentIdentity?.client_name;
    if (!canDecide) {
      wrap.textContent = approval.status === 'pending' ? 'WebAuthn approver required' : '—';
      return wrap;
    }
    for (const decision of ['approve', 'reject']) {
      const button = document.createElement('button');
      button.type = 'button';
      button.className = decision === 'reject' ? 'btn btn-danger btn-sm' : 'btn btn-primary btn-sm';
      button.textContent = decision === 'approve' ? 'Approve' : 'Reject';
      button.addEventListener('click', () => decideApproval(approval.id, decision));
      wrap.appendChild(button);
    }
    return wrap;
  }

  async function loadApprovals() {
    const body = document.querySelector('#approvals-table tbody');
    if (!body) return;
    body.replaceChildren();
    setApprovalStatus('Loading…');
    try {
      const result = await api('/api/v2/approvals');
      const approvals = Array.isArray(result.approvals) ? result.approvals : [];
      for (const approval of approvals) {
        const row = document.createElement('tr');
        appendCell(row, approval.provider);
        appendCell(row, approval.operation_id);
        appendCell(row, approval.account_ref);
        appendCell(row, approval.environment);
        appendCell(row, approval.resource_ref);
        appendCell(row, approval.requester);
        appendCell(row, `${approval.approvals?.length || 0}/${approval.required_approvals}`);
        appendCell(row, approval.status);
        const actions = document.createElement('td');
        actions.appendChild(actionButtons(approval));
        row.appendChild(actions);
        body.appendChild(row);
      }
      if (approvals.length === 0) {
        const row = document.createElement('tr');
        const cell = appendCell(row, 'No visible approval requests.');
        cell.colSpan = 9;
        body.appendChild(row);
      }
      setApprovalStatus(`${approvals.length} request(s).`);
    } catch (error) {
      setApprovalStatus(`Unable to load approvals: ${error.message || error}`, 'err');
    }
  }

  subscribeBrokerIdentity((value) => { currentIdentity = value; });
  document.addEventListener('tabchange', (event) => {
    if (event.detail?.tab === 'approvals') loadApprovals();
  });
  document.getElementById('btn-refresh-approvals')?.addEventListener('click', loadApprovals);
})();
