// broker-test/test-brace-count.js
import { readFileSync } from 'node:fs';
const content = readFileSync('broker/lib/openapi-spec.js', 'utf8');
const lines = content.split('\n');
// Just show every line with non-zero delta
let cumulative = 0;
for (let i = 0; i < lines.length; i++) {
  const opens = (lines[i].match(/\{/g) || []).length;
  const closes = (lines[i].match(/\}/g) || []).length;
  const delta = opens - closes;
  cumulative += delta;
  if (cumulative < 0 || delta !== 0) {
    console.log(`line ${i+1}: delta=${delta} cum=${cumulative}: ${lines[i].substring(0, 120)}`);
  }
}
console.log('Final cumulative:', cumulative);
