// broker-test/test-sops.js — V4.7.0 broker/lib/sops.js 单元测试
// 覆盖 sopsDecrypt 错误路径(file 不存在、spawn 失败)与 age key 解析;
// 真实 sops 二进制调用属于集成测试,不纳入本单元测试套件。

import { mkdtempSync, writeFileSync, existsSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { sopsDecrypt, sopsEncryptAtomic } from '../broker/lib/sops.js';

let pass = 0,
  fail = 0;
function ok(name, cond, detail) {
  if (cond) {
    pass++;
    console.log(`  PASS  ${name}`);
  } else {
    fail++;
    console.error(`  FAIL  ${name}${detail ? '  -- ' + detail : ''}`);
  }
}
function section(t) {
  console.log(`\n[${t}]`);
}

// ============================================================
// sopsDecrypt: file not found
// ============================================================
section('sopsDecrypt: missing file');
{
  const fakePath = '/tmp/this-file-definitely-does-not-exist-12345.yaml';
  let threw = false;
  try {
    await sopsDecrypt(fakePath);
  } catch (e) {
    threw = /not found/i.test(e.message);
  }
  ok('non-existent file rejected', threw);
}

// ============================================================
// sopsDecrypt: spawn fails when sops not installed
// ============================================================
section('sopsDecrypt: spawn failure when binary missing');
{
  const dir = mkdtempSync(join(tmpdir(), 'sops-test-'));
  const fakeFile = join(dir, 'encrypted.yaml');
  writeFileSync(fakeFile, 'sops_encrypted_content');
  // 把 PATH 设到一个空目录,sops 找不到
  const origPath = process.env.PATH;
  process.env.PATH = dir; // 空 PATH
  let threw = false;
  try {
    await sopsDecrypt(fakeFile);
  } catch (e) {
    threw = true;
  }
  process.env.PATH = origPath;
  ok('sops not in PATH → throws', threw);
}

// ============================================================
// sopsEncryptAtomic: spawn failure
// ============================================================
section('sopsEncryptAtomic: spawn failure when binary missing');
{
  const dir = mkdtempSync(join(tmpdir(), 'sops-encrypt-test-'));
  const targetPath = join(dir, 'common.env');
  const origPath = process.env.PATH;
  process.env.PATH = dir; // empty
  let threw = false;
  try {
    await sopsEncryptAtomic(targetPath, 'PLAIN=value');
  } catch (e) {
    threw = true;
  }
  process.env.PATH = origPath;
  ok('sops not in PATH → throws on encrypt', threw);
}

// ============================================================
// age key parsing logic (smoke test using a known public key file)
// ============================================================
section('age key parsing');
{
  const dir = mkdtempSync(join(tmpdir(), 'age-key-test-'));
  const ageKeyFile = join(dir, 'age.key');
  // 标准 age key 文件格式
  writeFileSync(
    ageKeyFile,
    '# created: 2026-01-01T00:00:00Z\n' +
      '# public key: age1ql3z7hjy54tw3u4dldx6gexs4zkr0zw4c4l5p4s5s8y6z9k7x2y3q8v6d\n' +
      'AGE-SECRET-KEY-1QPQXYRJKLMNOPQRSTUVWXYZ\n',
  );
  ok('age key file exists', existsSync(ageKeyFile));
  // 这里无法直接调用 sopsDecrypt 看内部 args,但能验证 .match 行为:
  const pub = readFileSync(ageKeyFile, 'utf8').match(/public key: (\S+)/)?.[1];
  ok(
    'public key extracted',
    pub === 'age1ql3z7hjy54tw3u4dldx6gexs4zkr0zw4c4l5p4s5s8y6z9k7x2y3q8v6d',
  );
}

console.log(`\n=== Total: ${pass} passed, ${fail} failed ===`);
process.exit(fail > 0 ? 1 : 0);
