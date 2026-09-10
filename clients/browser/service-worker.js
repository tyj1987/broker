const NATIVE_HOST = 'com.secretbroker.browser';
const ADAPTERS = new Map([
  ['https://account.aliyun.com', { provider: 'aliyun', selectors: ['input[name="code"]', 'input[autocomplete="one-time-code"]'] }],
  ['https://cloud.tencent.com', { provider: 'tencent', selectors: ['input[name="verifyCode"]', 'input[autocomplete="one-time-code"]'] }],
]);

function nativeRequest(message) {
  return new Promise((resolve, reject) => {
    chrome.runtime.sendNativeMessage(NATIVE_HOST, message, (response) => {
      const error = chrome.runtime.lastError;
      if (error || !response) reject(new Error('native_host_unavailable'));
      else resolve(response);
    });
  });
}

async function fillInMainFrame(tabId, provider, code, selectors) {
  const results = await chrome.scripting.executeScript({
    target: { tabId, frameIds: [0] },
    func: (expectedProvider, otp, fixedSelectors) => {
      if (!['aliyun', 'tencent'].includes(expectedProvider) || !/^[0-9]{4,10}$/.test(otp)) return false;
      const input = fixedSelectors.map((selector) => document.querySelector(selector)).find(Boolean);
      if (!(input instanceof HTMLInputElement) || input.disabled || input.readOnly) return false;
      input.focus(); input.value = otp;
      input.dispatchEvent(new Event('input', { bubbles: true }));
      input.dispatchEvent(new Event('change', { bubbles: true }));
      return true;
    },
    args: [provider, code, selectors],
  });
  return results[0]?.result === true;
}

chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
  if (message?.type !== 'fill-approved-otp') return false;
  (async () => {
    if (!/^[a-z0-9][a-z0-9._:-]{0,127}$/.test(message.account_ref || '')) throw new Error('account_denied');
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (!tab?.id || !tab.url) throw new Error('tab_unavailable');
    const url = new URL(tab.url);
    const adapter = ADAPTERS.get(url.origin);
    if (!adapter) throw new Error('origin_denied');
    const document = await chrome.scripting.executeScript({
      target: { tabId: tab.id, frameIds: [0] }, func: () => ({ origin: location.origin }),
    });
    const binding = { tab_id: tab.id, frame_id: 0, document_id: document[0]?.documentId, origin: url.origin, provider: adapter.provider, account_ref: message.account_ref };
    if (!binding.document_id || document[0]?.result?.origin !== binding.origin) throw new Error('document_changed');
    const payload = await nativeRequest({ type: 'consume-approved-otp', ...binding });
    const valid = payload && payload.type === 'approved-otp'
      && payload.tab_id === binding.tab_id && payload.frame_id === 0 && payload.document_id === binding.document_id
      && payload.origin === binding.origin && payload.provider === binding.provider
      && payload.account_ref === binding.account_ref
      && Number(payload.expires_at_ms) > Date.now() && Number(payload.expires_at_ms) <= Date.now() + 120000
      && /^[0-9]{4,10}$/.test(payload.code);
    if (!valid) throw new Error('binding_denied');
    const ok = await fillInMainFrame(tab.id, adapter.provider, payload.code, adapter.selectors);
    payload.code = '';
    const finished = await nativeRequest({ type: 'complete-approved-otp', receipt: payload.receipt, completed: ok });
    if (finished?.type !== 'otp-completion' || finished.completed !== ok) throw new Error('completion_failed');
    return { ok };
  })().then(sendResponse, () => sendResponse({ ok: false }));
  return true;
});
