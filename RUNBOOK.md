# RUNBOOK

> Operational procedures for my-first-app.
> Read this when something is on fire, before you rotate keys,
> or when you set up the project on a new machine.

---

## 1. First-time setup on a new machine

```powershell
# 1. Install all required tools
scoop install age sops git go-task direnv gitleaks nodejs
# winget fallback: winget install FiloSottile.age Mozilla.SOPS OpenJS.NodeJS.LTS

# 2. Add direnv to your PowerShell profile
pwsh -File scripts/install-direnv-hook.ps1
# Restart PowerShell.

# 3. Clone the repo and bootstrap
git clone https://github.com/<you>/my-first-app.git
cd my-first-app
pwsh -File bootstrap.ps1
# (It will skip age key generation if a USB drive with key-b-backup.txt
#  is plugged in and copied to ~/.config/sops/age/key-b-backup.txt.)
```

The bootstrap script is idempotent. Run it on every new dev box.

---

## 2. Day-to-day ops

### View the current decrypted secrets

```powershell
task secrets:view
```

### Edit a secret

```powershell
task secrets:edit
# Opens secrets\common.env in $EDITOR. SOPS handles decrypt/edit/encrypt.
# Add a new key=value, save, commit, push.
git add secrets\common.env
git commit -m "rotate OpenAI key"
git push
```

### Decrypt to .env (for tools that don't understand SOPS)

```powershell
task secrets:export
# Writes .env (gitignored). Safe to delete with task clean.
```

### Run the local stack

```powershell
task dev
# Decrypts .env, starts postgres + redis + app.
# Visit http://localhost:3000/health
```

### Stop the local stack

```powershell
# From the directory task dev is running in: Ctrl-C
# Or from another terminal:
docker compose down
```

---

## 3. Backup & restore

### Back up age private keys

```powershell
task backup:keys
# Or with a custom destination:
pwsh -File scripts/backup-keys.ps1 -Destination E:\keys-backup
```

This copies both `key-a.txt` and `key-b-backup.txt` to the destination
and writes a `README.txt` index with the public keys.

### Copy to a USB drive (recommended)

1. Plug in the USB drive (e.g. `E:`).
2. `task backup:keys -Destination E:\keys-backup`
3. Verify the files are on the USB drive.
4. Eject the USB drive.
5. Store the USB drive somewhere physically safe (safe, deposit box,
   with a trusted family member).

### Restore from USB on a new machine

1. Plug in the USB drive.
2. Copy `key-a.txt` and `key-b-backup.txt` to `~/.config/sops/age/`.
3. Clone the repo.
4. `sops --decrypt secrets\common.env` should work immediately.

### Disconnected USB = no recovery

If you lose BOTH your development machine AND the USB drive with the
backup key, **all encrypted secrets are unrecoverable**. There is no
backdoor. The system is designed this way on purpose — the trade-off
is security for recoverability. Keep the USB in a separate physical
location.

---

## 4. Rotate age keys

Every 6-12 months, or immediately if you suspect a key was leaked.

```powershell
task secrets:rotate
```

What it does:
1. Generates a new `key-a.txt` (replaces old).
2. Archives the old key to `~/.config/sops/age/archive-<timestamp>/`.
3. Replaces the old public key in `.sops.yaml` with the new one.
4. Re-encrypts every `secrets/*.env` file with the new key.
5. Commits the change (you do this).

**Manual steps after rotation:**

```powershell
git add -A
git commit -m "rotate age key"
git push
# Re-copy the new key-a.txt to your USB drive.
```

**Important**: the OLD key file is still in `archive-<timestamp>/`. Keep
it until you have verified that:
- The new encrypted files decrypt with the new key on a second machine.
- All services that consume those secrets (CI, local dev, production)
  have picked up the new key.

Then delete the archive.

---

## 5. Production deployment

### Prerequisites (one-time, per cloud)

#### Aliyun
1. Create a RAM role with OIDC trust for GitHub Actions.
2. Grant the role permission to: `kms:Decrypt`, `acr:*`, `cs:*`,
   `vpc:*`, `rds:*`, `oss:*`.
3. Create a Container Registry namespace.
4. Create a Terraform state OSS bucket (encrypted with KMS).
5. Add to GitHub repository secrets:
   - `ALIYUN_OIDC_PROVIDER_ARN`
   - `ALIYUN_OIDC_ROLE_ARN`
   - `ALIYUN_ACR_USERNAME`
   - `ALIYUN_ACR_PASSWORD`

#### Tencent
1. Create a CAM role / sub-account.
2. Grant permissions: `kms`, `tcr`, `tke`, `vpc`, `postgres`,
   `cos`, `cvm`.
3. Create a TCR instance and namespace.
4. Create a Terraform state COS bucket.
5. Add to GitHub repository secrets:
   - `TENCENTCLOUD_SECRET_ID`
   - `TENCENTCLOUD_SECRET_KEY`
   - `TENCENT_TCR_USERNAME`
   - `TENCENT_TCR_PASSWORD`

### Deploy

```powershell
git tag v1.0.0
git push --tags
# GitHub Actions automatically:
#   1. Builds the image
#   2. Pushes to both Aliyun ACR and Tencent TCR
#   3. Decrypts secrets/prod.env using the cloud's KMS
#   4. Applies Terraform in both regions
```

### Manual deploy (without CI)

```powershell
# Set up cloud credentials
$env:ALIBABA_CLOUD_ACCESS_KEY_ID = "..."
$env:ALIBABA_CLOUD_ACCESS_KEY_SECRET = "..."
# (Or for Tencent)
$env:TENCENTCLOUD_SECRET_ID = "..."
$env:TENCENTCLOUD_SECRET_KEY = "..."

# Build + push + deploy
task deploy TAG=v1.0.0
```

---

## 6. Incident response

### Secret accidentally committed in plaintext

1. **Rotate the secret immediately.** Treat it as compromised.
2. Remove the file from git history:
   ```powershell
   git filter-repo --path secrets/secret-leaked.txt --invert-paths
   git push --force
   ```
3. Update `.sops.yaml` and re-encrypt with a new key if the leaked
   value was an age key.
4. Notify the team.

### Age key stolen or lost

- **Stolen**: Treat all secrets as compromised. Rotate every secret
  in `secrets/`. Generate a new key, update `.sops.yaml`,
  re-encrypt everything.
- **Lost but not stolen**: You can still decrypt with the backup
  key B. Generate a new key A to replace the lost one.
  `task secrets:rotate`.

### Cloud KMS accidentally deleted

If the cloud KMS key that decrypts `secrets/prod.env` is deleted,
**all production secrets are unrecoverable**. This is why
`.sops.yaml` always includes a local fallback key — production
should be the only place where KMS is the sole key.

If this happens, you must:
1. Generate new strong random values for every secret.
2. Update `secrets/prod.env` with the new values.
3. Re-apply Terraform with the new values.

### Both private keys lost

This is unrecoverable. Generate new strong random values for
every secret and start over. The encrypted files are still in git
history, but they are now permanent ciphertext.

**This is why the USB backup is non-negotiable.**

---

## 7. Monitoring

### Start Uptime Kuma

```powershell
docker compose -f monitoring/uptime-kuma.yml up -d
# Open http://localhost:3001
```

Add monitors for:
- `https://<your-domain>/health` (HTTP probe)
- `<db-host>:5432` (TCP probe)
- `<cache-host>:6379` (TCP probe)
- `<your-domain>` (TLS cert expiry)

Configure a notification channel: WeChat, DingTalk, Telegram, Slack,
or email.

### Start Prometheus + Grafana (optional)

```powershell
docker compose -f monitoring/uptime-kuma.yml --profile metrics up -d
# Prometheus: http://localhost:9090
# Grafana:    http://localhost:3000 (default admin / change-me-on-first-login)
```

---

## 8. Disaster recovery checklist

Run this checklist every quarter to make sure the system still
recovers from a fresh machine.

- [ ] Plug in USB with backup key.
- [ ] On a different machine (or VM):
  - [ ] `scoop install age sops git go-task direnv nodejs`
  - [ ] Copy `key-b-backup.txt` from USB to `~/.config/sops/age/`.
  - [ ] Clone the repo.
  - [ ] `sops --decrypt secrets\common.env` succeeds.
  - [ ] `task dev` starts the stack.
  - [ ] `curl http://localhost:3000/health` shows
        `secrets_loaded: { database: true, redis: true, jwt: true }`.
- [ ] If any step fails, the system is not actually recoverable. Fix
  the gap before going back to normal work.

---

## 9. Reference

- SOPS docs: https://github.com/getsops/sops
- age docs: https://age-encryption.org
- Taskfile: https://taskfile.dev
- Terraform: https://developer.hashicorp.com/terraform
- Aliyun KMS: https://www.alibabacloud.com/help/en/kms
- Tencent KMS: https://www.tencentcloud.com/document/product/573
