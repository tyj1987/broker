import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, rmSync, cpSync, symlinkSync, readdirSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { spawnSync } from 'node:child_process';
import { generateKeyPairSync, sign, createHash } from 'node:crypto';
import { readRecoveryServiceInput, runRecoveryServiceCheck, RECOVERY_SERVICE_PATHS } from '../broker/bin/audit-recovery-service-check.js';
import { packageRecovery, RECOVERY_FILES } from '../broker/bin/package-audit-recovery.js';
import { createAuditAnchorRequest, createAuditAnchorSigningInput, attachAuditAnchorSignature } from '../broker/lib/audit-anchor.js';
import { sealEvent, GENESIS_HASH } from '../broker/lib/audit-hash-chain.js';

let passed = 0;
async function test(name, run) { await run(); passed++; console.log(`PASS ${name}`); }
const work = mkdtempSync(join(tmpdir(), 'recovery-service-'));
const root = fileURLToPath(new URL('../broker/', import.meta.url));
const now = Date.now();
const { privateKey, publicKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
const der = publicKey.export({ type: 'spki', format: 'der' });
const audit = join(work, 'audit'); mkdirSync(audit);
const event = sealEvent({ action: 'synthetic' }, GENESIS_HASH);
writeFileSync(join(audit, 'audit-chain-1.jsonl'), JSON.stringify(event)+'\n', { mode: 0o600 });
const stream = 'synthetic-recovery'; const keyId = 'test-key'; const algorithm = 'ecdsa-p256-sha256';
const request = createAuditAnchorRequest({ files: 1, count: 1, lastHash: event.hash },
  { streamId: stream, sequence: 1, previousAnchorDigest: GENESIS_HASH, now: () => now });
const anchor = attachAuditAnchorSignature(request, { algorithm, key_id: keyId,
  value: sign('sha256', createAuditAnchorSigningInput(request, { algorithm, keyId }), privateKey).toString('base64url') });
const config = { version: 1, purpose: 'secret-broker.audit-recovery-check', stream_id: stream,
  audit_directory: audit, trusted_keys: [{ key_id: keyId, public_key_spki_der_base64: der.toString('base64'),
    public_key_sha256: createHash('sha256').update(der).digest('hex') }], revoked_key_ids: [],
  store_timeout_ms: 100, deadline_ms: 1000, page_size: 2, max_anchors: 10 };
const checkpoint = { version: 1, purpose: 'secret-broker.audit-recovery-checkpoint', stream_id: stream,
  sequence: 1, payload_digest: anchor.payload_digest, issued_at_ms: now-1000, expires_at_ms: now+60000 };
const encode = value => Buffer.from(JSON.stringify(value));
const args = ['--config', RECOVERY_SERVICE_PATHS.config];
const store = { readHead: async () => ({ current: anchor, previous: null }),
  readPage: async () => ({ anchors: [anchor] }), publish: () => assert.fail('read-only service must not publish') };
const input = path => encode(path === RECOVERY_SERVICE_PATHS.config ? config : checkpoint);
const dir = { isDirectory: () => true, isSymbolicLink: () => false, uid: 0, mode: 0o40755 };
const file = { uid: 0, gid: 1234, mode: 0o100440, nlink: 1 };
const readerOptions = { stat: () => dir, realpath: path => path, groups: [1234], fstat: () => file,
  read: (_p, _l, _m, options) => { assert.equal(options.effectiveUid, 0); assert.equal(options.sensitive, false); options.fstatImpl(1); return Buffer.from('public pins'); } };
try {
  await test('service executes real signed recovery chain before success', async () => {
    const output=[]; const seen=[];
    const result=await runRecoveryServiceCheck(args, { read: (path, label, max) => { seen.push([path,max]); return input(path); },
      createStore: () => store, now: () => now, writeOutput: value => output.push(value) });
    assert.equal(result.status,'checkpoint_verified'); assert.equal(output.length,1);
    assert.deepEqual(seen, [[RECOVERY_SERVICE_PATHS.config,32768],[RECOVERY_SERVICE_PATHS.checkpoint,4096]]);
    assert.equal(JSON.parse(output[0]).sequence,1);
    for(const raw of [stream,keyId,anchor.payload_digest,audit,'synthetic']) assert.equal(output[0].includes(raw),false);
  });
  await test('each service invocation reads a new checkpoint', async () => {
    let reads=0;
    const deps={read: path => { if(path===RECOVERY_SERVICE_PATHS.checkpoint)reads++;return input(path); },createStore:()=>store,now:()=>now,writeOutput:()=>{}};
    await runRecoveryServiceCheck(args,deps);await runRecoveryServiceCheck(args,deps);assert.equal(reads,2);
  });
  for (const bad of [null, [], ['--config'], ['--config','/tmp/other'], ['--config',RECOVERY_SERVICE_PATHS.config,'extra'], ['--checkpoint-file',RECOVERY_SERVICE_PATHS.checkpoint]]) {
    await test('service refuses alternative arguments before input access', async () => {
      let reads=0; await assert.rejects(runRecoveryServiceCheck(bad,{read:()=>{reads++;}}));assert.equal(reads,0);
    });
  }
  await test('expired checkpoint prevents any store creation',async()=>{
    let calls=0;await assert.rejects(runRecoveryServiceCheck(args,{read:input,now:()=>checkpoint.expires_at_ms,createStore:()=>{calls++;return store;}}),{code:'recovery_checkpoint_expired'});assert.equal(calls,0);
  });
  await test('revoked key and corrupt chain cannot become ready',async()=>{
    const altered={...config,revoked_key_ids:[keyId]};const output=[];
    await assert.rejects(runRecoveryServiceCheck(args,{read:path=>path===RECOVERY_SERVICE_PATHS.config?encode(altered):input(path),createStore:()=>store,now:()=>now,writeOutput:x=>output.push(x)}));assert.equal(output.length,0);
  });
  await test('service input uses root-owned descriptor and group-only read contract',()=>{
    assert.equal(readRecoveryServiceInput(RECOVERY_SERVICE_PATHS.config,'config',32768,readerOptions).toString(),'public pins');
  });
  for(const overrides of [
    {stat:()=>({...dir,isDirectory:()=>false})},{stat:()=>({...dir,isSymbolicLink:()=>true})},{stat:()=>({...dir,uid:1234})},
    {stat:()=>({...dir,mode:0o40777})},{realpath:()=>'/elsewhere'},
    {fstat:()=>({...file,uid:1234})},{fstat:()=>({...file,nlink:2})},{fstat:()=>({...file,mode:0o100640})},
    {fstat:()=>({...file,mode:0o100444})},{groups:[]},
  ]) await test('unsafe service input contract rejected',()=>assert.throws(()=>readRecoveryServiceInput(RECOVERY_SERVICE_PATHS.checkpoint,'checkpoint',4096,{...readerOptions,...overrides})));
  await test('arbitrary service input path rejected',()=>assert.throws(()=>readRecoveryServiceInput('/tmp/private','input',100,readerOptions)));
  await test('actual service command returns fixed failure outside configured host',()=>{
    const child=spawnSync(process.execPath,['--jitless',join(root,'bin/audit-recovery-service-check.js'),'--other','synthetic-private'],{encoding:'utf8',timeout:5000});
    assert.equal(child.status,1);assert.equal(child.stdout,'');assert.ok(child.stderr.includes('"code":"recovery_check_failed"'));assert.equal(child.stderr.includes('synthetic-private'),false);
  });

  const copy=join(work,'broker'); mkdirSync(copy);
  for(const name of ['package.json',...RECOVERY_FILES]){mkdirSync(join(copy,name,'..'),{recursive:true});writeFileSync(join(copy,name),readFileSync(join(root,name)));}
  mkdirSync(join(copy,'node_modules'),{recursive:true});cpSync(join(root,'node_modules/yaml'),join(copy,'node_modules/yaml'),{recursive:true});
  await test('isolated package contains only closed recovery dependency set',()=>{
    const result=packageRecovery(copy);assert.ok(result.files>RECOVERY_FILES.length);
    const manifest=JSON.parse(readFileSync(join(copy,'recovery-runtime/manifest.json')));
    for(const name of Object.keys(manifest.files))assert.ok(name==='package.json'||RECOVERY_FILES.includes(name)||name.startsWith('node_modules/yaml/'));
    assert.equal(Object.keys(manifest.files).some(name=>/signer|server\.js|\.env/.test(name)),false);
    assert.deepEqual(packageRecovery(copy,{verify:true}),result);
  });
  await test('isolated package really runs with jitless Node and its own yaml dependency',()=>{
    const script=`import {runRecoveryServiceCheck} from ${JSON.stringify(pathToFileURL(join(copy,'recovery-runtime/bin/audit-recovery-service-check.js')).href)};
      const cfg=${JSON.stringify(config)}, pin=${JSON.stringify(checkpoint)}, anchor=${JSON.stringify(anchor)};
      await runRecoveryServiceCheck(${JSON.stringify(args)}, {read:p=>Buffer.from(JSON.stringify(p.endsWith('/recovery.json')?cfg:pin)),
        createStore:()=>({readHead:async()=>({current:anchor,previous:null}),readPage:async()=>({anchors:[anchor]})}),now:()=>${now}});`;
    const child=spawnSync(process.execPath,['--jitless','--disable-proto=throw','--no-addons','--input-type=module','-e',script],{encoding:'utf8',timeout:5000,cwd:work,env:{PATH:'/usr/bin:/bin'}});
    assert.equal(child.status,0,child.stderr);assert.equal(JSON.parse(child.stdout).status,'checkpoint_verified');
  });
  await test('packager refuses overwriting an existing artifact',()=>assert.throws(()=>packageRecovery(copy)));
  await test('manifest-only forgery cannot hide modified package code',()=>{
    const script=join(copy,'recovery-runtime/bin/audit-recovery-service-check.js');const saved=readFileSync(script);writeFileSync(script,'synthetic modified');
    const manifestPath=join(copy,'recovery-runtime/manifest.json'), manifest=JSON.parse(readFileSync(manifestPath));const original=readFileSync(manifestPath);
    manifest.files['bin/audit-recovery-service-check.js']=createHash('sha256').update('synthetic modified').digest('hex');writeFileSync(manifestPath,JSON.stringify(manifest));
    try{assert.throws(()=>packageRecovery(copy,{verify:true}));}finally{writeFileSync(script,saved);writeFileSync(manifestPath,original);}
  });
  await test('extra file cannot enter the recovery package',()=>{
    const extra=join(copy,'recovery-runtime/unwanted.js');writeFileSync(extra,'unwanted');try{assert.throws(()=>packageRecovery(copy,{verify:true}));}finally{rmSync(extra);}
  });
  await test('missing package member cannot be accepted',()=>{
    const member=join(copy,'recovery-runtime/lib/redact.js');const bytes=readFileSync(member);rmSync(member);try{assert.throws(()=>packageRecovery(copy,{verify:true}));}finally{writeFileSync(member,bytes);}
  });
  if(process.platform!=='win32')await test('linked dependency tree rejected',()=>{
    const dist=join(copy,'node_modules/yaml/dist');const backup=join(copy,'dist-copy');cpSync(dist,backup,{recursive:true});rmSync(dist,{recursive:true});symlinkSync(backup,dist);
    try{assert.throws(()=>packageRecovery(copy,{verify:true}));}finally{rmSync(dist);cpSync(backup,dist,{recursive:true});}
  });
  await test('package CLI verifies the real isolated build with default path resolution',()=>{
    const command=join(copy,'bin/package-audit-recovery.js');writeFileSync(command,readFileSync(join(root,'bin/package-audit-recovery.js')));
    const child=spawnSync(process.execPath,[command,'--verify'],{encoding:'utf8',timeout:5000});
    assert.equal(child.status,0,child.stderr);assert.equal(JSON.parse(child.stdout).status,'recovery_package_verified');
  });
  await test('missing or malformed manifest fails package validation',()=>{
    const path=join(copy,'recovery-runtime/manifest.json');const bytes=readFileSync(path);
    for(const content of ['{}','{"version":2,"files":{}}']){
      writeFileSync(path,content);assert.throws(()=>packageRecovery(copy,{verify:true}));
    }
    writeFileSync(path,bytes);
  });
  await test('locked dependency version mismatch cannot be packaged',()=>{
    rmSync(join(copy,'recovery-runtime'),{recursive:true});
    const path=join(copy,'node_modules/yaml/package.json');const bytes=readFileSync(path);
    const value=JSON.parse(bytes);value.version='0.0.0';writeFileSync(path,JSON.stringify(value));
    try{assert.throws(()=>packageRecovery(copy));}finally{writeFileSync(path,bytes);}
  });
  await test('package CLI builds and verifies from a fresh output path',()=>{
    const child=spawnSync(process.execPath,[join(copy,'bin/package-audit-recovery.js')],{encoding:'utf8',timeout:5000});
    assert.equal(child.status,0,child.stderr);assert.equal(JSON.parse(child.stdout).status,'recovery_package_verified');
  });
  await test('package command rejects arguments without publishing',()=>{
    const child=spawnSync(process.execPath,[join(root,'bin/package-audit-recovery.js'),'--unexpected'],{encoding:'utf8',timeout:5000});assert.equal(child.status,1);assert.equal(child.stderr.trim(),'recovery_package_invalid');
  });
  assert.equal(readdirSync(work).some(name=>name.startsWith('.recovery-package-')),false);
  console.log(`audit recovery service: ${passed} checks passed`);
} finally {rmSync(work,{recursive:true,force:true});}
