// broker-test/test-migration.js — required startup security migration

import { migrateV2ToV3 } from '../broker/migrate-v2-to-v3.js';
import { verifyPasswordCompat } from '../broker/totp.js';

let pass = 0;
let fail = 0;
function ok(name, cond) {
  if (cond) {
    pass++;
    console.log(`  PASS  ${name}`);
  } else {
    fail++;
    console.error(`  FAIL  ${name}`);
  }
}

console.log('[v2 -> v3 migration]');

{
  const config = {
    clients: {
      alice: {
        role: 'developer',
        password: 'legacy-password-123',
      },
    },
  };
  const audits = [];
  let persisted = 0;
  const result = await migrateV2ToV3(
    config,
    'Z:/definitely-missing-clients-dir',
    (event) => audits.push(event),
    async () => {
      persisted++;
    },
  );

  ok('migration reports changed', result.changed === true);
  ok(
    'plaintext password is replaced with scrypt',
    config.clients.alice.password.startsWith('scrypt$'),
  );
  ok(
    'migrated hash verifies original password',
    verifyPasswordCompat('legacy-password-123', config.clients.alice.password),
  );
  ok(
    'migrated hash rejects wrong password',
    !verifyPasswordCompat('wrong-password', config.clients.alice.password),
  );
  ok('schema_version is upgraded', config.schema_version === 3);
  ok('migration persists exactly once', persisted === 1);
  ok(
    'successful migration is audited',
    audits.some((event) => event.action === 'migration' && event.status === 'ok'),
  );
}

{
  const config = {
    schema_version: 3,
    notifications: { sms: null, email: null },
    api_keys: [],
    healthcheck: { enabled: true, schedule: '04:00', alert_channels: ['sse'] },
    clients: {
      alice: {
        role: 'developer',
        password: 'scrypt$16384$8$1$ZmFrZXNhbHQ=$ZmFrZWhhc2g=',
        password_set_at: '2026-09-01T00:00:00.000Z',
        preferred_2fa: 'none',
      },
    },
  };
  let persisted = 0;
  const result = await migrateV2ToV3(
    config,
    'Z:/definitely-missing-clients-dir',
    () => {},
    async () => {
      persisted++;
    },
  );
  ok('already-migrated config is idempotent', result.changed === false);
  ok('idempotent migration does not persist', persisted === 0);
}

{
  const config = {
    clients: {
      alice: {
        role: 'developer',
        password: 'legacy-password-456',
      },
    },
  };
  const audits = [];
  let threw = false;
  try {
    await migrateV2ToV3(
      config,
      'Z:/definitely-missing-clients-dir',
      (event) => audits.push(event),
      async () => {
        throw new Error('encrypted persistence unavailable');
      },
    );
  } catch (err) {
    threw = /persistence unavailable/.test(String(err?.message || err));
  }
  ok('persistence failure is propagated', threw);
  ok(
    'failed persistence is audited',
    audits.some((event) => event.action === 'migration' && event.status === 'error'),
  );
}

console.log(`\n=== Total: ${pass} passed, ${fail} failed ===`);
process.exit(fail > 0 ? 1 : 0);
