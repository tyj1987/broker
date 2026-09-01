#!/usr/bin/env node
// broker/bin/openapi-generate.js — emit docs/openapi.yaml from openapi-spec.js
// Usage:
//   node bin/openapi-generate.js
//   node bin/openapi-generate.js --out path/to/openapi.yaml
//   node bin/openapi-generate.js --json  (emit JSON instead)

import { writeFileSync, mkdirSync } from 'node:fs';
import { dirname } from 'node:path';
import { parse as parseYaml, stringify as stringifyYaml } from 'yaml';
import OPENAPI_SPEC from '../lib/openapi-spec.js';

const args = process.argv.slice(2);
const outIdx = args.indexOf('--out');
const output = outIdx >= 0 ? args[outIdx + 1] : 'docs/openapi.yaml';
const asJson = args.includes('--json');

const text = asJson ? JSON.stringify(OPENAPI_SPEC, null, 2) : stringifyYaml(OPENAPI_SPEC);
// Ensure parent dir exists (CI fresh checkout doesn't have docs/)
mkdirSync(dirname(output), { recursive: true });
writeFileSync(output, text, 'utf8');
console.log(`[openapi-generate] wrote ${output} (${text.length} bytes, ${asJson ? 'json' : 'yaml'})`);

// 顺便输出一些元数据
const pathCount = Object.keys(OPENAPI_SPEC.paths).length;
const schemaCount = Object.keys(OPENAPI_SPEC.components.schemas).length;
console.log(`[openapi-generate] ${pathCount} paths, ${schemaCount} schemas, OpenAPI ${OPENAPI_SPEC.openapi}`);
