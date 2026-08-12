# v2.0.0 - Secret Broker

## TL;DR

The v1 stack (SOPS + age + Docker + dual cloud + CI) is still here, but the
headline feature now is a **Secret Broker** — a small mTLS HTTPS service that
sits between you (or your AI tools) and every external API. The broker holds
the SOPS-encrypted credentials, you hold a client cert. AI assistants call
`secret-broker proxy <service> ...` and the broker injects the right token
into the request. Plaintext secrets never leave the broker process.

## What changed vs v1.0.0

### New: `broker/` - the Secret Broker server
- `server.js` - mTLS HTTPS on :8443, routes:
  - `GET  /health` - no auth, returns SOPS load state
  - `GET  /api/v1/identity` - returns the caller's CN + cert fingerprint
  - `GET  /api/v1/secrets` - list secrets the caller is allowed to resolve
  - `POST /api/v1/secrets/resolve` - resolve one secret to plaintext (audited)
  - `POST /api/v1/proxy/:service` - **proxy mode**: AI's call goes out with the
    right credentials injected, the plaintext never appears in the response
  - `GET  /api/v1/audit` - paginated audit log (admin only)
  - `POST /api/v1/rotate/:name` - kick off a rotation (admin only)
- Loads `secrets/broker.yaml` and `secrets/common.env` through SOPS at boot
- JSON Lines audit log under `audit/`, daily rotation, hash chain friendly
- `dashboard/` - small static page (vanilla JS) for browsing visible secrets
  and checking the audit log

### New: `cli/` - the Secret Broker client
- `secret-broker.js` - single-file Node CLI, no third-party deps
- Subcommands: `health`, `identity`, `list`, `get`, `proxy`, `exec`, `pki`
- `proxy` is the recommended default for any AI tool
- `exec` injects secrets as env vars into a child process and forgets them
  when the child exits
- `pki` wraps the cert scripts for issue / revoke / list / show

### New: PKI under `pki/`
- `scripts/broker/init-ca.ps1` - one-time root CA setup
- `scripts/broker/issue-server-cert.ps1` - signs the broker's TLS cert
- `scripts/broker/issue-client-cert.ps1` - signs per-device client certs,
  can auto-append the fingerprint to `broker.yaml`
- `scripts/broker/revoke-cert.ps1` - adds a cert to the CRL

### New: `secrets/broker.yaml.example`
- Documented template for `services:` and `clients:` blocks
- `services` covers github_token, bearer, header, aliyun_v2, tencent_v3,
  ssh_exec - each with the right credential injection strategy
- `clients` matches by cert fingerprint, supports `allowed_resolve`,
  `allowed_proxy` (per service + path regex), and rate limits

### New: deployment paths for the broker
- `infra/aliyun/broker.tf` + `broker-variables.tf` - 2C2G ECS in cn-hangzhou,
  encrypted data disk, EIP, security group that only opens 22 (admin IP) and
  8443 (mTLS-gated public)
- `infra/tencent/broker.tf` + `broker-variables.tf` - same shape in
  ap-shanghai, sits cold as a failover target
- `docker-compose.yml` - broker is the default service now, demo app moved
  into a `example` profile
- `infra/aliyun/cloud-init.sh` - first-boot script that installs Docker +
  SOPS + age and prints a README for whoever is doing the initial setup

### Updated
- `.sops.yaml` - new `.*broker\.yaml$` rule so the encrypted config file
  decrypts without having to pass `--age` on the command line
- `.github/workflows/ci.yml` - new jobs for broker-test, CLI syntax check,
  and a broker image build that fails the build if a `.env` or `.key`
  snuck into the image
- `.github/workflows/deploy.yml` - builds and pushes the broker image to
  both Aliyun ACR and Tencent TCR, runs both Terraform applies on a `v*` tag
- `.gitignore` - now also excludes `pki/**` keys/certs, `audit/*.jsonl`,
  and `.broker/` (client config dir)
- `README.md` - rewritten to lead with the broker, quick start is a 3-step
  flow, security model is up top

## Security model recap

- AI tools never get plaintext secrets
- Client certs are device-bound; lose a laptop, `secret-broker pki revoke`
- mTLS is the gate on the wire, ACL in `broker.yaml` is the gate in app logic
- Every `resolve` and `proxy` call lands in `audit/audit-YYYY-MM-DD.jsonl`
- All rate-limited per cert fingerprint
- CA private key stays on the broker server, never in the repo, never on a
  client machine

## How to upgrade from v1

1. Pull this tag
2. Run `scripts/broker/init-ca.ps1` once on the machine that will host the
   broker (your existing one or a new ECS)
3. Issue yourself a server cert and a client cert
4. Copy `secrets/broker.yaml.example` to `secrets/broker.yaml`, edit, then
   `sops --encrypt --in-place secrets/broker.yaml`
5. `docker compose up -d broker`
6. Install the CLI on every machine that needs to talk to the broker, drop
   the client cert + key + CA cert into `~/.broker/`, write
   `~/.broker/config.json`
7. `secret-broker health` to confirm

Full walkthrough is in `README.md`. Architecture deep-dive is in
`docs/04-secret-broker.md`.
