# Phase E — Operations hardening

**Version**: 3.7.0  
**Constraint**: zero new npm dependencies.

## Graceful shutdown

```js
import { installGracefulShutdown, rejectIfShuttingDown } from './lib/shutdown.js';
import { stopCronLoop } from './cron-tasks.js';

const server = https.createServer(tlsOpts, handler);
server.listen(PORT);

const { shuttingDown, shutdown } = installGracefulShutdown({
  server,
  onShutdown: [() => stopCronLoop()],
  // timeout: SHUTDOWN_TIMEOUT_MS (default 15000)
});

// start of handle():
if (rejectIfShuttingDown(shuttingDown, res, jsonError)) return;
```

Handles `SIGTERM` / `SIGINT`: stop cron → `server.close()` → exit 0; force exit after timeout.

## Config validation

```js
import { validateBrokerConfig, formatValidationReport } from './lib/config-validate.js';

const result = validateBrokerConfig(CONFIG);
if (!result.ok) {
  console.error(formatValidationReport(result));
  process.exit(1);
}
for (const w of result.warnings) console.warn(formatValidationReport({ errors: [], warnings: [w] }));
```

Checks: clients map + roles, password-login consistency, service `base_url`, admin presence (warn).

## Path preflight

```js
import { preflightPaths } from './lib/config-validate.js';
import { existsSync } from 'node:fs';

const pf = preflightPaths({
  configPath: CONFIG_PATH,
  ageKey: AGE_KEY_PATH,
  caCert: CA_CERT,
  serverCert: SERVER_CERT,
  serverKey: SERVER_KEY,
}, { existsSync });
```

## Env

| Variable | Default | Meaning |
|----------|---------|---------|
| `SHUTDOWN_TIMEOUT_MS` | `15000` | Force exit after graceful drain |

## Tests

```bash
cd broker && npm run test:ops
npm run test:modular
```

## Next (Phase F ideas)

- Backup/export of config+PKI checklist
- Chaos-friendly readiness (dependency probes)
- Optional external secret sync adapters
