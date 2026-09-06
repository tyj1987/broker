import { readFileSync, readdirSync } from 'node:fs';
import { resolve } from 'node:path';

const root = resolve(import.meta.dirname, '..', '.github', 'workflows');
const failures = [];
for (const file of readdirSync(root).filter((name) => /\.ya?ml$/i.test(name))) {
  const text = readFileSync(resolve(root, file), 'utf8');
  if (/\b(?:curl|wget)\b[^\n]*(?:github\.com\/[^\s]+\/releases\/download|raw\.githubusercontent\.com)/i.test(text)) {
    failures.push(`${file}: executable downloads from release URLs are forbidden; use a pinned action or verify signature and checksum`);
  }
  if (/smoke test passed/i.test(text) && /\|\|\s*true|\bWARN:/i.test(text)) {
    failures.push(`${file}: smoke tests must not report success after ignored failures`);
  }
  for (const [index, line] of text.split(/\r?\n/).entries()) {
    const match = line.match(/\buses:\s*([^\s#]+)/);
    if (!match || match[1].startsWith('./')) continue;
    const at = match[1].lastIndexOf('@');
    const revision = at >= 0 ? match[1].slice(at + 1) : '';
    if (!/^[0-9a-f]{40}$/i.test(revision)) {
      failures.push(`${file}:${index + 1}: action is not pinned to a 40-character commit SHA: ${match[1]}`);
    }
  }
}

if (failures.length) {
  console.error(failures.join('\n'));
  process.exit(1);
}
console.log('All external GitHub Actions are pinned to immutable commit SHAs.');
