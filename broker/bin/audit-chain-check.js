#!/usr/bin/env node

import { isAbsolute } from 'node:path';
import { loadAuditChainStateSync } from '../lib/audit-hash-chain.js';

const auditDir = process.env.AUDIT_DIR;

if (!auditDir || !isAbsolute(auditDir)) {
  console.error('audit chain check requires an absolute AUDIT_DIR');
  process.exitCode = 64;
} else {
  try {
    const state = loadAuditChainStateSync(auditDir, { chainOnly: true });
    console.log(`audit_chain_verified=yes files=${state.files} events=${state.count}`);
  } catch {
    console.error('audit_chain_verified=no');
    process.exitCode = 65;
  }
}
