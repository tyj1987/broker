const status = document.getElementById('status');
document.getElementById('fill').addEventListener('click', async () => {
  const accountRef = document.getElementById('account').value.trim();
  if (!/^[a-z0-9][a-z0-9._:-]{0,127}$/.test(accountRef)) {
    status.textContent = 'Enter a valid account reference.';
    return;
  }
  status.textContent = 'Requesting an approved code…';
  const response = await chrome.runtime.sendMessage({ type: 'fill-approved-otp', account_ref: accountRef }).catch(() => null);
  status.textContent = response?.ok ? 'Code filled in the active page.' : 'No matching approved operation is available.';
});
