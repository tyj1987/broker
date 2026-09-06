// Runtime environment contract shared by Compose, Helm, and the legacy ECS
// installer. Prefixed variables are canonical; unprefixed names remain a
// deliberate compatibility fallback for the shell installer.
export function runtimeConfig(env = process.env, defaults = {}) {
  const value = (...names) => {
    for (const name of names) {
      if (env[name] !== undefined && env[name] !== '') return env[name];
    }
    return undefined;
  };
  const portRaw = value('BROKER_PORT', 'PORT') ?? '8443';
  const port = Number(portRaw);
  if (!Number.isInteger(port) || port < 1 || port > 65535) throw new Error('BROKER_PORT must be an integer between 1 and 65535');
  return {
    port,
    host: String(value('BROKER_BIND', 'HOST') ?? '0.0.0.0'),
    configPath: String(value('BROKER_CONFIG_PATH', 'CONFIG_PATH') ?? defaults.configPath ?? ''),
    secretsPath: String(value('BROKER_SECRETS_PATH', 'SECRETS_PATH') ?? defaults.secretsPath ?? ''),
    secretsDetailPath: String(value('BROKER_SECRETS_DETAIL_PATH', 'SECRETS_DETAIL_PATH') ?? defaults.secretsDetailPath ?? ''),
    pkiDir: String(value('BROKER_PKI_DIR', 'PKI_DIR') ?? defaults.pkiDir ?? ''),
    ageKeyFile: value('BROKER_AGE_KEY_FILE', 'AGE_KEY_FILE', 'SOPS_AGE_KEY_FILE'),
    auditDir: String(value('BROKER_AUDIT_DIR', 'AUDIT_DIR') ?? defaults.auditDir ?? ''),
    tlsCert: String(value('BROKER_TLS_CERT', 'TLS_CERT') ?? defaults.tlsCert ?? ''),
    tlsKey: String(value('BROKER_TLS_KEY', 'TLS_KEY') ?? defaults.tlsKey ?? ''),
    tlsCa: String(value('BROKER_CA_CERT', 'TLS_CA') ?? defaults.tlsCa ?? ''),
    tlsCrl: String(value('BROKER_TLS_CRL', 'TLS_CRL') ?? defaults.tlsCrl ?? ''),
    healthSocketPath: String(value('BROKER_HEALTH_SOCKET_PATH', 'HEALTH_SOCKET_PATH') ?? ''),
  };
}
