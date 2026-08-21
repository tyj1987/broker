# Phase F — Backup inventory & dependency probes

**Version**: 3.8.0  
**Constraint**: zero new npm dependencies.

## Backup manifest

```js
import { buildBackupManifest, writeBackupManifest, redactConfigForExport } from './lib/backup.js';

const manifest = buildBackupManifest({
  configPath,
  secretsSopsPath,
  ageKeyPath,   // marked sensitive — no sha256 of private material
  caCert, caKey, serverCert, serverKey,
  auditDir,
  clientsDir,
});
writeBackupManifest('/var/backups/broker', paths);
```

Admin API (when wired):

- `GET /api/v1/ops/backup-manifest`
- `GET /api/v1/ops/config-export` — passwords/TOTP/API secrets redacted

**Never** commit age private keys or CA keys; manifest only inventories presence.

## Dependency probes

```js
import { runProbes, probesFromConfig } from './lib/probes.js';

const specs = probesFromConfig(CONFIG);
// services.X.healthcheck.url or services.X.probe.{host,port}
const { ok, probes } = await runProbes(specs);
```

`/ready` accepts `deps.runReadyProbes` and returns 503 if critical probes fail.

Disable: `READY_PROBES=0`.

## Wire

1. Pass `runReadyProbes: () => runProbes(probesFromConfig(CONFIG))` into health deps.
2. Register `handleOps` after auth with `backupPaths`.
3. Optional cron: `writeBackupManifest` weekly.

## Tests

```bash
cd broker && npm run test:backup
npm run test:modular
```
