// CI ONLY. In-memory synthetic signing/store fixture; never a production backend.
import net from 'node:net';
import { writeFileSync, chmodSync, chownSync } from 'node:fs';
import { generateKeyPairSync, sign, createHash } from 'node:crypto';
import { sealEvent, GENESIS_HASH } from '../broker/lib/audit-hash-chain.js';
const [exporterGid, recoveryGid, signerGid, storeGid] = process.argv.slice(2).map(Number);
if (process.getuid() !== 0 || ![exporterGid,recoveryGid,signerGid,storeGid].every(n=>Number.isSafeInteger(n)&&n>0)) throw new Error('CI fixture configuration invalid');
const {privateKey,publicKey}=generateKeyPairSync('ec',{namedCurve:'P-256'});
const der=publicKey.export({type:'spki',format:'der'});
const stream='ci-synthetic-audit',key='ci-synthetic-key',algorithm='ecdsa-p256-sha256';
const pin={key_id:key,public_key_spki_der_base64:der.toString('base64'),public_key_sha256:createHash('sha256').update(der).digest('hex')};
const config={version:1,purpose:'secret-broker.audit-anchor-exporter',audit_directory:'/var/lib/secret-broker/audit',stream_id:stream,algorithm,active_key_id:key,trusted_keys:[pin],revoked_key_ids:[],signer_timeout_ms:2000,store_timeout_ms:2000,export_deadline_ms:10000,interval_ms:60000};
const put=(path,value,gid)=>{writeFileSync(path,JSON.stringify(value)+'\n',{mode:0o440});chownSync(path,0,gid);chmodSync(path,0o440);};
put('/etc/secret-broker/audit/exporter.json',config,exporterGid);
put('/etc/secret-broker/audit/recovery.json',{version:1,purpose:'secret-broker.audit-recovery-check',audit_directory:config.audit_directory,stream_id:stream,trusted_keys:[pin],revoked_key_ids:[],store_timeout_ms:2000,deadline_ms:10000,page_size:2,max_anchors:100},recoveryGid);
const event=sealEvent({action:'ci-synthetic-only'},GENESIS_HASH);
writeFileSync('/var/lib/secret-broker/audit/audit-chain-ci.jsonl',JSON.stringify(event)+'\n',{mode:0o400});
const records=[];let signed=0,published=0;
const stats=()=>writeFileSync('/run/broker-ci-fixture/stats.json',JSON.stringify({signed,published}),{mode:0o600});stats();
function listen(path,gid,handle){
 const server=net.createServer({allowHalfOpen:true},socket=>{
  let bytes=0,body='';socket.setTimeout(3000,()=>socket.destroy());
  socket.on('data',b=>{bytes+=b.length;if(bytes>24*1024){socket.destroy();return;}body+=b;});
  socket.on('error',()=>{});
  socket.on('end',()=>{try{socket.end(JSON.stringify(handle(JSON.parse(body)))+'\n');}catch{socket.destroy();}});
 });
 server.listen(path,()=>{chownSync(path,0,gid);chmodSync(path,0o660);});return server;
}
const signer=listen('/run/secret-broker-audit-anchor/signer.sock',signerGid,req=>{
 if(req.version!==2||req.key_id!==key||req.algorithm!==algorithm||req.stream_id!==stream)throw new Error('invalid synthetic signing request');
 signed++;stats();return {version:2,purpose:req.purpose,algorithm,key_id:key,payload_digest:req.payload_digest,signature:sign('sha256',Buffer.from(req.signing_input,'base64url'),privateKey).toString('base64url')};
});
const store=listen('/run/secret-broker-audit-store/store.sock',storeGid,req=>{
 if(req.version!==1||req.stream_id!==stream)throw new Error('invalid synthetic store request');
 let result;
 if(req.operation==='read_head')result={current:records.at(-1)??null,previous:records.at(-2)??null};
 else if(req.operation==='read_page')result={anchors:records.filter(a=>a.payload.sequence>req.parameters.after_sequence&&a.payload.sequence<=req.parameters.through_sequence).slice(0,req.parameters.limit)};
 else if(req.operation==='publish'){
  const env=req.parameters.envelope;
  if(env.payload.sequence!==records.length+1||req.parameters.expected_previous_digest!==(records.at(-1)?.payload_digest??GENESIS_HASH))throw new Error('synthetic conflict');
  records.push(env);published++;stats();result={status:'published'};
  // Fixture-issued checkpoint is NOT independent production trust evidence.
  put('/etc/secret-broker/audit/recovery-checkpoint.json',{version:1,purpose:'secret-broker.audit-recovery-checkpoint',stream_id:stream,sequence:env.payload.sequence,payload_digest:env.payload_digest,issued_at_ms:Date.now()-1000,expires_at_ms:Date.now()+600000},recoveryGid);
 }else throw new Error('operation forbidden in fixture');
 return {version:1,purpose:req.purpose,request_id:req.request_id,operation:req.operation,status:'ok',stream_id:stream,result};
});
process.once('SIGTERM',()=>{signer.close();store.close();});
