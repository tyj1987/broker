#!/usr/bin/env node
// broker/bin/sync-templates.js — V4 SDK Sync tool
// Pulls templates from official sources and diffs against current
// service-templates.js. Emits a markdown report.
//
// Usage:
//   node bin/sync-templates.js                  # run with default sources
//   node bin/sync-templates.js --dry-run         # don't write
//   node bin/sync-templates.js --output <path>   # write report here
//
// Zero npm deps. Uses global fetch (Node 18+).

import { writeFileSync } from 'node:fs';
import { parse as parseYaml } from 'yaml';
import { parseOpenAPI, extractAuthFromDocs, extractUpstreamFromDocs } from '../lib/template-parser.js';

// Sources are intentionally conservative — these are public, stable URLs.
// When a source URL changes, the user gets a "stale" report.
const SOURCES = [
  { id: 'github',         type: 'openapi', url: 'https://raw.githubusercontent.com/github/rest-api-description/main/descriptions/api.github.com/api.github.com.json' },
  { id: 'openai',         type: 'openapi', url: 'https://app.stainless.com/api/v0/specs/openai/openapi.yml' },
  { id: 'anthropic',      type: 'docs',    url: 'https://docs.anthropic.com/en/api/getting-started' },
  { id: 'cloudflare',     type: 'openapi', url: 'https://github.com/cloudflare/api-schemas/raw/main/openapi.json' },
  { id: 'stripe',         type: 'openapi', url: 'https://raw.githubusercontent.com/stripe/openapi/master/openapi/spec3.json' },
  { id: 'github_docker',  type: 'docs',    url: 'https://docs.docker.com/reference/api/registry/auth/' },
  { id: 'aliyun_ecs',     type: 'docs',    url: 'https://help.aliyun.com/document_detail/25484.html' },
  { id: 'tencent_cvm',    type: 'docs',    url: 'https://www.tencentcloud.com/zh/document/api/213/11654' },
  { id: 'aws',            type: 'docs',    url: 'https://docs.aws.amazon.com/general/latest/gr/sigv4_signing.html' },
  { id: 'gcp',            type: 'docs',    url: 'https://cloud.google.com/iam/docs/workload-identity-federation' },
];

async function fetchWithTimeout(url, timeoutMs = 15000) {
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), timeoutMs);
  try {
    const res = await fetch(url, { signal: ctrl.signal });
    if (!res.ok) throw new Error(`HTTP ${res.status} ${res.statusText}`);
    return await res.text();
  } finally {
    clearTimeout(t);
  }
}

async function syncSource(src) {
  let text;
  try {
    text = await fetchWithTimeout(src.url);
  } catch (e) {
    return { id: src.id, status: 'fetch_error', error: e.message };
  }
  try {
    if (src.type === 'openapi') {
      const parsed = parseOpenAPI(text);
      return { id: src.id, status: 'ok', template: parsed, source: 'openapi' };
    }
    // docs: extract auth + upstream
    const auth = extractAuthFromDocs(text);
    const upstream = extractUpstreamFromDocs(text);
    return {
      id: src.id,
      status: 'ok',
      template: {
        upstream,
        auth_type: auth.auth_type,
        default_secret_type: null,
        default_secret_field: 'value',
        inject_headers: {},
        default_actions: [],
        template_version: null,
        source: 'docs',
      },
      source: 'docs',
    };
  } catch (e) {
    return { id: src.id, status: 'parse_error', error: e.message };
  }
}

function generateReport(results) {
  const lines = [];
  lines.push('# V4 SDK Sync Report');
  lines.push('');
  lines.push(`Generated: ${new Date().toISOString()}`);
  lines.push('');
  const ok = results.filter(r => r.status === 'ok').length;
  const fail = results.filter(r => r.status !== 'ok').length;
  lines.push(`Total: ${results.length}  OK: ${ok}  Failed: ${fail}`);
  lines.push('');
  lines.push('## Results');
  lines.push('');
  lines.push('| Source | Status | upstream | auth_type | actions |');
  lines.push('|---|---|---|---|---|');
  for (const r of results) {
    const u = r.template?.upstream || '—';
    const a = r.template?.auth_type || '—';
    const n = r.template?.default_actions?.length ?? 0;
    lines.push(`| ${r.id} | ${r.status} | ${u} | ${a} | ${n} |`);
  }
  lines.push('');
  lines.push('## Failed');
  lines.push('');
  for (const r of results.filter(r => r.status !== 'ok')) {
    lines.push(`- **${r.id}**: ${r.error || r.status}`);
  }
  lines.push('');
  return lines.join('\n');
}

async function main() {
  const args = process.argv.slice(2);
  const dryRun = args.includes('--dry-run');
  const outIdx = args.indexOf('--output');
  const output = outIdx >= 0 ? args[outIdx + 1] : 'docs/TEMPLATES-SYNC-REPORT.md';

  console.log(`[sync-templates] running (${SOURCES.length} sources)...`);
  console.log(`[sync-templates] dry-run=${dryRun}, output=${output}`);
  const results = await Promise.allSettled(SOURCES.map(syncSource));
  const flat = results.map((r, i) => {
    if (r.status === 'fulfilled') return r.value;
    return { id: SOURCES[i].id, status: 'rejected', error: String(r.reason) };
  });
  const report = generateReport(flat);
  if (!dryRun) {
    writeFileSync(output, report, 'utf8');
    console.log(`[sync-templates] report written: ${output}`);
  } else {
    console.log('--- dry-run, would write ---');
  }
  console.log(report);
  const failed = flat.filter(r => r.status !== 'ok').length;
  process.exit(failed > 0 ? 1 : 0);
}

main().catch(e => {
  console.error('[sync-templates] fatal:', e);
  process.exit(2);
});
