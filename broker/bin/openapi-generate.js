import { mkdirSync, writeFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { stringify } from 'yaml';
import { OPENAPI_SPEC } from '../lib/openapi-spec.js';

const here = dirname(fileURLToPath(import.meta.url));
const output = resolve(here, '../../contracts/openapi.yaml');
mkdirSync(dirname(output), { recursive: true });
writeFileSync(output, stringify(OPENAPI_SPEC), { encoding: 'utf8', mode: 0o644 });
console.log(`generated ${output}`);
