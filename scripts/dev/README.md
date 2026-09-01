# Dev scripts — local broker smoke testing

> Tools for running the broker locally and exercising the 8 calling surfaces
> without writing custom client code.

## When to use

- You just merged broker code and want to verify the server still responds.
- You're onboarding a new contributor and want them to see the broker in
  action without installing the SDK.
- You're debugging a regression and want a quick reproducer.

## Files

| File | Purpose | Cross-platform |
|------|---------|----------------|
| `start-broker.ps1` | Generate ephemeral self-signed PKI, write dev config, start broker detached | Windows |
| `start-broker.sh` | Same for Linux/macOS (TODO — not in this commit) | *nix |
| `smoke-test.py` | 5-endpoint smoke test (Python urllib, no extra deps) | All |
| `run-curl.py` | Single-endpoint helper for use as `python run-curl.py me` | All |
| `dev-test.ps1` | PowerShell wrapper around Git Bash curl (OpenSSL backend) | Windows |
| `dev-test.cmd` | cmd.exe wrapper around Git Bash curl (OpenSSL backend) | Windows |

## Quick start (Windows)

```powershell
# 1. Start broker (generates PKI if missing, writes dev config, starts detached)
.\scripts\dev\start-broker.ps1

# 2. Wait 5 seconds
Start-Sleep -Seconds 5

# 3. Verify with smoke test
python E:\broker\scripts\dev\smoke-test.py
#   expected output: 5 PASS lines, 0 FAIL

# 4. Try individual endpoints
python E:\broker\scripts\dev\run-curl.py me
python E:\broker\scripts\dev\run-curl.py resolve
```

## Why this exists (and not just docs)

The Windows built-in `curl.exe` (Schannel backend) does not support PEM
client certs and crashes with LSA errors on P12. Git for Windows ships a
separate `curl.exe` linked against OpenSSL that handles PEM correctly.
`run-curl.py` is the path of least resistance: pure stdlib, no
cert-store gymnastics, works in any PowerShell session.

## What it does NOT do

- It does NOT generate production-grade PKI. For that, use
  `scripts/broker/init-ca.ps1` (Windows) or `scripts/broker/init-ca.sh`
  (Linux). Those scripts are part of the broker repository proper.
- It does NOT enable MFA. The dev config sets `mfa_policy.enabled: false`
  so login is frictionless. See `secrets/broker.yaml.example` for the
  full prod-style config.
- It does NOT sign the audit log. The audit log is plain JSONL in dev.
  See `broker/lib/audit-policy.js` for the production chain.

## Cleanup

```powershell
# Stop broker
Get-NetTCPConnection -LocalPort 8443 | ForEach-Object {
  Stop-Process -Id $_.OwningProcess -Force
}

# Wipe dev PKI + config (regenerate next time)
Remove-Item E:\broker\pki -Recurse -Force
Remove-Item E:\broker\secrets\broker.yaml, E:\broker\secrets\secrets-detail.json -Force
```

## License

MIT (same as broker).
