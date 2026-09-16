import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, rmSync, cpSync, symlinkSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { spawnSync } from 'node:child_process';
import { generateKeyPairSync, sign, createHash } from 'node:crypto';
import { runExporterServiceCheck, EXPORTER_CONFIG } from '../broker/bin/audit-exporter-service-check.js';
import { parseAuditAnchorExporterConfig } from '../broker/lib/audit-anchor-exporter-runtime.js';
import { packageExporter, EXPORTER_FILES } from '../broker/bin/package-audit-exporter.js';
import { createAuditAnchorSigningInput } from '../broker/lib/audit-anchor.js';
import { sealEvent, GENESIS_HASH } from '../broker/lib/audit-hash-chain.js';
import { readAuditRecoveryChainSnapshot } from '../broker/lib/audit-recovery-chain.js';
const root = fileURLToPath(new URL('../broker/', import.meta.url));
const work = mkdtempSync(join(tmpdir(), 'exporter-service-'));
const audit = join(work, 'audit'); mkdirSync(audit);
const event = sealEvent({ action: 'synthetic-export' }, GENESIS_HASH);
writeFileSync(join(audit, 'audit-chain-1.jsonl'), JSON.stringify(event)+'\n');
const { privateKey, publicKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
const der = publicKey.export({ type: 'spki', format: 'der' });
const doc = { version: 1, purpose: 'secret-broker.audit-anchor-exporter', audit_directory: '/var/lib/secret-broker/audit',
  stream_id: 'synthetic-export', algorithm: 'ecdsa-p256-sha256', active_key_id: 'test-key', trusted_keys: [{ key_id: 'test-key',
    public_key_spki_der_base64: der.toString('base64'), public_key_sha256: createHash('sha256').update(der).digest('hex') }],
  revoked_key_ids: [], signer_timeout_ms: 100, store_timeout_ms: 100, export_deadline_ms: 1000, interval_ms: 60000 };
const parsed = d => parseAuditAnchorExporterConfig(JSON.stringify(d));
const args = ['--config', EXPORTER_CONFIG];
let passes = 0;
async function test(name, fn) { await fn(); passes++; console.log(`PASS ${name}`); }
function setup() {
  let saved = null, previous = null;
  const state = { signed: 0, published: 0, reads: 0, outputs: [] };
  const signer = { async signAnchor(request) {
    state.signed++;
    return { algorithm: doc.algorithm, key_id: doc.active_key_id,
      value: sign('sha256', createAuditAnchorSigningInput(request, { algorithm: doc.algorithm, keyId: doc.active_key_id }), privateKey).toString('base64url') };
  } };
  const store = {
    async readHead() { state.reads++; return { current: structuredClone(saved), previous: structuredClone(previous) }; },
    async publish({ envelope }) { previous = saved; saved = structuredClone(envelope); state.published++; return { status: 'published' }; },
  };
  const deps = { readConfig: async () => parsed(doc), createSigner: () => signer, createStore: () => store,
    readSnapshot: () => readAuditRecoveryChainSnapshot(audit), writeOutput: x => state.outputs.push(x) };
  return { state, signer, store, deps };
}
try {
  await test('real P-256 publication plus read-back precedes the only output', async () => {
    const { deps, state } = setup(); const result = await runExporterServiceCheck(args, deps);
    assert.deepEqual(result, { status: 'anchor_verified', sequence: 1, interval_ms: 60000 });
    assert.equal(state.reads, 2); assert.equal(state.signed, 1); assert.equal(state.published, 1);
    assert.equal(Object.isFrozen(result), true); assert.deepEqual(JSON.parse(state.outputs[0]), result);
    assert.equal(state.outputs[0].includes('synthetic-export'), false);
  });
  await test('exact retry verifies existing publication without re-signing', async () => {
    const { deps, state } = setup(); await runExporterServiceCheck(args, deps); await runExporterServiceCheck(args, deps);
    assert.equal(state.published, 1); assert.equal(state.signed, 1); assert.equal(state.reads, 4);
  });
  await test('subsequent chain snapshot creates and confirms the next sequence', async () => {
    const { deps, state } = setup(); await runExporterServiceCheck(args, deps);
    const next = sealEvent({ action: 'next' }, event.hash);
    const path = join(audit,'audit-chain-1.jsonl'); const bytes = readFileSync(path);
    writeFileSync(path, bytes + JSON.stringify(next)+'\n');
    try { assert.equal((await runExporterServiceCheck(args, deps)).sequence, 2); assert.equal(state.published, 2); }
    finally { writeFileSync(path, bytes); }
  });
  for (const bad of [null, [], ['--config'], ['--config','/tmp/wrong'], ['--other',EXPORTER_CONFIG], [...args,'extra']]) {
    await test('invalid arguments never read config', async () => {
      let reads=0; await assert.rejects(runExporterServiceCheck(bad, {readConfig:()=>{reads++;}})); assert.equal(reads,0);
    });
  }
  for (const signal of [{}, AbortSignal.abort()]) await test('invalid/pre-aborted signal has no side effects', async () => {
    const {deps,state}=setup();await assert.rejects(runExporterServiceCheck(args,{...deps,signal}));assert.equal(state.published,0);
  });
  await test('abort during config read prevents all work', async()=>{
    const {deps,state}=setup();const controller=new AbortController();
    await assert.rejects(runExporterServiceCheck(args,{...deps,signal:controller.signal,readConfig:async()=>{controller.abort();return parsed(doc);}}));assert.equal(state.reads,0);
  });
  for(const kind of ['receipt-only','changed-current','changed-previous'])await test(`${kind} cannot become ready`,async()=>{
    const {deps,store,state}=setup();const read=store.readHead;
    store.readHead=async()=>{const value=await read();if(state.reads===2){
      if(kind==='receipt-only')value.current=null;
      if(kind==='changed-current')value.current.payload_digest='f'.repeat(64);
      if(kind==='changed-previous')value.previous={};
    }return value;};
    await assert.rejects(runExporterServiceCheck(args,deps));assert.equal(state.outputs.length,0);assert.equal(state.published,1);
  });
  for(const stage of ['snapshot','signer','publish','readback','output'])await test(`${stage} errors never reflect raw detail`,async()=>{
    const {deps,signer,store,state}=setup();const explode=()=>{throw new Error('synthetic-private-detail');};
    if(stage==='snapshot')deps.readSnapshot=explode;
    if(stage==='signer')signer.signAnchor=explode;
    if(stage==='publish')store.publish=explode;
    if(stage==='output')deps.writeOutput=explode;
    if(stage==='readback'){const read=store.readHead;store.readHead=async()=>{if(state.reads>0)explode();return read();};}
    await assert.rejects(runExporterServiceCheck(args,deps),e=>e.message==='Audit exporter iteration unavailable');assert.equal(state.outputs.length,0);
  });
  await test('incorrect signatures are rejected before publication',async()=>{
    const {deps,signer,state}=setup();const sign=signer.signAnchor;
    signer.signAnchor=async request=>({...await sign(request),value:Buffer.alloc(64).toString('base64url')});
    await assert.rejects(runExporterServiceCheck(args,deps));assert.equal(state.published,0);
  });
  for(const stage of ['signer','readback'])await test(`non-settling ${stage} is bounded`,async()=>{
    const {deps,signer,store,state}=setup();const hang=()=>new Promise(()=>{});
    if(stage==='signer')signer.signAnchor=hang;else{const read=store.readHead;store.readHead=()=>state.reads?hang():read();}
    await assert.rejects(runExporterServiceCheck(args,deps));assert.equal(state.outputs.length,0);
  });
  await test('abort while signer is pending releases caller',async()=>{
    const {deps,signer,state}=setup();const controller=new AbortController();
    signer.signAnchor=async()=>{controller.abort();return new Promise(()=>{});};
    await assert.rejects(runExporterServiceCheck(args,{...deps,signal:controller.signal}));assert.equal(state.outputs.length,0);
  });
  await test('slow synchronous snapshot cannot return late success',async()=>{
    const {deps,state}=setup();deps.readSnapshot=()=>{Atomics.wait(new Int32Array(new SharedArrayBuffer(4)),0,0,1050);return readAuditRecoveryChainSnapshot(audit);};
    await assert.rejects(runExporterServiceCheck(args,deps));assert.equal(state.signed,0);
  });
  await test('config is reloaded and revocation stops the next round',async()=>{
    const {deps,state}=setup();await runExporterServiceCheck(args,deps);
    deps.readConfig=async()=>parsed({...doc, trusted_keys:[{...doc.trusted_keys[0],public_key_sha256:'a'.repeat(64)}]});
    await assert.rejects(runExporterServiceCheck(args,deps));assert.equal(state.published,1);
  });
  await test('default output emits only the canonical safe record',async()=>{
    const {deps}=setup();delete deps.writeOutput;const original=process.stdout.write;const lines=[];
    process.stdout.write=x=>{lines.push(x);return true;};
    try{await runExporterServiceCheck(args,deps);}finally{process.stdout.write=original;}
    assert.deepEqual(lines,['{"status":"anchor_verified","sequence":1,"interval_ms":60000}\n']);
  });
  await test('real process failure emits only stable code',()=>{
    const child=spawnSync(process.execPath,[join(root,'bin/audit-exporter-service-check.js'),'--other','synthetic-private-detail'],{encoding:'utf8',timeout:5000});
    assert.equal(child.status,1);assert.equal(child.stdout,'');assert.deepEqual(JSON.parse(child.stderr),{status:'failed',code:'anchor_exporter_failed'});
  });
  const copy=join(work,'broker');mkdirSync(copy);
  for(const name of ['package.json',...EXPORTER_FILES]){mkdirSync(join(copy,name,'..'),{recursive:true});writeFileSync(join(copy,name),readFileSync(join(root,name)));}
  mkdirSync(join(copy,'node_modules'));cpSync(join(root,'node_modules/yaml'),join(copy,'node_modules/yaml'),{recursive:true});
  writeFileSync(join(copy,'bin/package-audit-exporter.js'),readFileSync(join(root,'bin/package-audit-exporter.js')));
  await test('closed exporter runtime builds and byte-verifies independently',()=>{
    const result=packageExporter(copy);assert.ok(result.files>10);assert.deepEqual(packageExporter(copy,{verify:true}),result);
    assert.throws(()=>packageExporter(copy));
    const cli=spawnSync(process.execPath,[join(copy,'bin/package-audit-exporter.js'),'--verify'],{encoding:'utf8'});assert.equal(cli.status,0);
    const invalid=spawnSync(process.execPath,[join(copy,'bin/package-audit-exporter.js'),'--bad'],{encoding:'utf8'});assert.equal(invalid.status,1);
  });
  await test('manifest forgery cannot replace tested source bytes',()=>{
    const target=join(copy,'exporter-runtime/lib/redact.js');const bytes=readFileSync(target);const mp=join(copy,'exporter-runtime/manifest.json');const raw=readFileSync(mp);const manifest=JSON.parse(raw);
    writeFileSync(target,'forged');manifest.files['lib/redact.js']=createHash('sha256').update('forged').digest('hex');writeFileSync(mp,JSON.stringify(manifest));
    try{assert.throws(()=>packageExporter(copy,{verify:true}));}finally{writeFileSync(target,bytes);writeFileSync(mp,raw);}
  });
  await test('extra and missing package members cannot be authorized',()=>{
    const extra=join(copy,'exporter-runtime/extra.js');writeFileSync(extra,'extra');assert.throws(()=>packageExporter(copy,{verify:true}));rmSync(extra);
    const member=join(copy,'exporter-runtime/lib/redact.js');const bytes=readFileSync(member);rmSync(member);assert.throws(()=>packageExporter(copy,{verify:true}));writeFileSync(member,bytes);
  });
  await test('malformed manifest and dependency version are rejected',()=>{
    const path=join(copy,'exporter-runtime/manifest.json');const original=readFileSync(path);writeFileSync(path,'{}');assert.throws(()=>packageExporter(copy,{verify:true}));writeFileSync(path,original);
    rmSync(join(copy,'exporter-runtime'),{recursive:true});const pkg=join(copy,'node_modules/yaml/package.json');const bytes=readFileSync(pkg);writeFileSync(pkg,JSON.stringify({...JSON.parse(bytes),version:'0.0.0'}));assert.throws(()=>packageExporter(copy));writeFileSync(pkg,bytes);
  });
  if(process.platform!=='win32')await test('linked parser cannot enter package',()=>{
    const folder=join(copy,'node_modules/yaml/dist');const backup=join(copy,'dist-backup');cpSync(folder,backup,{recursive:true});rmSync(folder,{recursive:true});symlinkSync(backup,folder);
    try{assert.throws(()=>packageExporter(copy));}finally{rmSync(folder);cpSync(backup,folder,{recursive:true});}
  });
  await test('packaged service loads its closure with hardened Node flags',()=>{
    const built=spawnSync(process.execPath,[join(copy,'bin/package-audit-exporter.js')],{encoding:'utf8'});assert.equal(built.status,0);
    const script=`import {runExporterServiceCheck} from ${JSON.stringify(pathToFileURL(join(copy,'exporter-runtime/bin/audit-exporter-service-check.js')).href)}; await runExporterServiceCheck([]);`;
    const child=spawnSync(process.execPath,['--jitless','--disable-proto=throw','--no-addons','--input-type=module','-e',script],{encoding:'utf8',cwd:work,env:{PATH:'/usr/bin:/bin'}});
    assert.equal(child.status,1);assert.ok(child.stderr.includes('Audit exporter iteration unavailable'));assert.ok(!child.stderr.includes('ERR_MODULE_NOT_FOUND'));
  });
  console.log(`audit exporter service: ${passes} checks passed`);
} finally {rmSync(work,{recursive:true,force:true});}
