import { runtimeConfig } from '../broker/lib/runtime-config.js';

let pass = 0; let fail = 0;
function ok(name, value) { if (value) { pass++; console.log('  PASS ', name); } else { fail++; console.error('  FAIL ', name); } }
const defaults = { configPath: 'default/config', secretsPath: 'default/secrets', secretsDetailPath: 'default/detail', pkiDir: 'default/pki', auditDir: 'default/audit', tlsCert: 'default/cert', tlsKey: 'default/key', tlsCa: 'default/ca', tlsCrl: 'default/crl' };

{
  const cfg = runtimeConfig({ BROKER_PORT: '9443', BROKER_BIND: '127.0.0.1', BROKER_CONFIG_PATH: '/run/config.yaml', BROKER_SECRETS_PATH: '/run/common.env', BROKER_SECRETS_DETAIL_PATH: '/run/detail.json', BROKER_PKI_DIR: '/run/pki', BROKER_AUDIT_DIR: '/run/audit', BROKER_TLS_CERT: '/run/tls.crt', BROKER_TLS_KEY: '/run/tls.key', BROKER_CA_CERT: '/run/ca.crt', BROKER_TLS_CRL: '/run/crl.pem', BROKER_HEALTH_SOCKET_PATH: '/tmp/health.sock' }, defaults);
  ok('canonical prefixed deployment variables are honored', cfg.port === 9443 && cfg.host === '127.0.0.1' && cfg.configPath === '/run/config.yaml' && cfg.tlsCa === '/run/ca.crt');
  ok('all mounted paths use prefixed contract', cfg.secretsPath === '/run/common.env' && cfg.secretsDetailPath === '/run/detail.json' && cfg.pkiDir === '/run/pki' && cfg.auditDir === '/run/audit' && cfg.tlsCert === '/run/tls.crt' && cfg.tlsKey === '/run/tls.key' && cfg.tlsCrl === '/run/crl.pem' && cfg.healthSocketPath === '/tmp/health.sock');
}
{
  const cfg = runtimeConfig({ PORT: '8444', HOST: 'localhost', CONFIG_PATH: 'legacy/config', TLS_CERT: 'legacy/cert', TLS_KEY: 'legacy/key', TLS_CA: 'legacy/ca' }, defaults);
  ok('legacy installer variables remain supported', cfg.port === 8444 && cfg.host === 'localhost' && cfg.configPath === 'legacy/config' && cfg.tlsCa === 'legacy/ca');
}
{
  const cfg = runtimeConfig({ BROKER_PORT: '9443', PORT: '8444', BROKER_CONFIG_PATH: 'canonical', CONFIG_PATH: 'legacy' }, defaults);
  ok('canonical variables take precedence', cfg.port === 9443 && cfg.configPath === 'canonical');
}
{
  let rejected = false;
  try { runtimeConfig({ BROKER_PORT: '0' }, defaults); } catch { rejected = true; }
  ok('invalid port fails closed', rejected);
}
console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
