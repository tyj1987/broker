import { invoke } from '@tauri-apps/api/core';
import './style.css';

const el = <T extends HTMLElement>(id: string) => document.getElementById(id) as T;
const value = (id: string) => el<HTMLInputElement | HTMLSelectElement>(id).value.trim();
const show = (message: string) => { el<HTMLPreElement>('result').textContent = message; };
let lastOperationID = '';

el<HTMLButtonElement>('approvals').onclick = async () => {
  try { await invoke('open_approvals'); show('Approval workbench opened in the default browser.'); }
  catch { show('The approval workbench could not be opened.'); }
};

el<HTMLButtonElement>('health').onclick = async () => {
  try {
    const response = await invoke<{ status: string }>('broker_health');
    el('status').textContent = response.status === 'ok' ? 'Broker available' : 'Broker unavailable';
  } catch { el('status').textContent = 'Broker unavailable'; }
};

el<HTMLButtonElement>('save-key').onclick = async () => {
  const field = el<HTMLInputElement>('api-key');
  const secret = field.value;
  field.value = '';
  if (!secret.startsWith('mb_') || secret.length < 24) return show('The key format is invalid.');
  try {
    await invoke('store_api_key', { secret });
    show('Credential stored in the operating system credential store.');
  } catch { show('Credential could not be stored.'); }
};

el<HTMLButtonElement>('delete-key').onclick = async () => {
  try { await invoke('delete_api_key'); show('Local credential removed.'); }
  catch { show('No local credential was removed.'); }
};

el<HTMLButtonElement>('save-browser-key').onclick = async () => {
  const field = el<HTMLInputElement>('browser-key');
  const secret = field.value;
  field.value = '';
  if (!secret.startsWith('mb_') || secret.length < 24) return show('The bridge key format is invalid.');
  try { await invoke('store_browser_bridge_key', { secret }); show('Browser bridge credential stored locally.'); }
  catch { show('Browser bridge credential could not be stored.'); }
};

el<HTMLButtonElement>('delete-browser-key').onclick = async () => {
  try { await invoke('delete_browser_bridge_key'); show('Browser bridge credential removed.'); }
  catch { show('No browser bridge credential was removed.'); }
};

el<HTMLButtonElement>('create').onclick = async () => {
  const request = {
    provider: value('provider'), operation_id: value('operation'), account_ref: value('account'),
    environment: value('environment'), typed_parameters: { resource_ref: value('resource') },
  };
  try {
    const operation = await invoke<Record<string, unknown>>('create_operation', { request });
    lastOperationID = typeof operation.id === 'string' ? operation.id : '';
    el<HTMLButtonElement>('refresh-operation').disabled = !lastOperationID;
    show(JSON.stringify(operation, null, 2));
  } catch { show('The operation was denied or could not be created.'); }
};

el<HTMLButtonElement>('refresh-operation').onclick = async () => {
  if (!lastOperationID) return;
  try {
    const operation = await invoke<Record<string, unknown>>('get_operation', { operationId: lastOperationID });
    show(JSON.stringify(operation, null, 2));
  } catch { show('The operation status is unavailable.'); }
};
