// One-time client certificate bundle construction.

import { buildZip } from './zip.js';

const CLIENT_NAME_RE = /^[A-Za-z0-9._-]{1,64}$/;

export function createClientBundle({ name, certPem, keyPem, caPem }) {
  if (!CLIENT_NAME_RE.test(String(name || ''))) throw new Error('Invalid client name');
  for (const [field, value] of Object.entries({ certPem, keyPem, caPem })) {
    if (typeof value !== 'string' || !value.trim()) throw new Error(`${field} is required`);
  }

  const installSh = [
    '#!/bin/sh',
    `# install.sh for ${name} — Secret Broker client bundle`,
    '# Usage: sh install.sh /opt/secret-broker/pki/clients',
    '',
    'set -eu',
    'DEST="${1:-/opt/secret-broker/pki/clients}"',
    'umask 077',
    'mkdir -p "$DEST"',
    `cat > "$DEST/${name}.crt" <<'CERT_EOF'`,
    certPem,
    'CERT_EOF',
    `cat > "$DEST/${name}.key" <<'KEY_EOF'`,
    keyPem,
    'KEY_EOF',
    'cat > "$DEST/ca.crt" <<\'CA_EOF\'',
    caPem,
    'CA_EOF',
    `chmod 600 "$DEST/${name}.key"`,
    `chmod 644 "$DEST/${name}.crt" "$DEST/ca.crt"`,
    'echo "Installed to $DEST"',
    '',
  ].join('\n');

  return buildZip([
    { name: `${name}.crt`, data: certPem },
    { name: `${name}.key`, data: keyPem },
    { name: 'ca.crt', data: caPem },
    { name: 'install.sh', data: installSh },
  ]);
}
