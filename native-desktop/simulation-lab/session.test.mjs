import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtemp,mkdir,readFile,writeFile} from 'node:fs/promises';
import {join} from 'node:path';
import {fileURLToPath} from 'node:url';
import {spawn} from 'node:child_process';
import {runStoredSession} from './session.mjs';

const lab=fileURLToPath(new URL('.',import.meta.url));
const tmp=join(lab,'tmp');await mkdir(tmp,{recursive:true});
const fixture=()=>readFile(new URL('./fixtures/windows-x64.json',import.meta.url),'utf8').then(JSON.parse);
async function directory(){return join(await mkdtemp(join(tmp,'session-')),'store');}
test('stored sessions keep one identity and one model revision across reopened processes',async()=>{
  const root=await directory(),profile=await fixture();
  const a=await runStoredSession(root,{providerKind:'local_mock',initialProfile:profile});
  const b=await runStoredSession(root,{providerKind:'local_mock'});
  assert.equal(a.store.environmentId,b.store.environmentId);assert.equal(a.modelDigest,b.modelDigest);
  assert.deepEqual(a.observed,b.observed);assert.notEqual(a.probe.pid,b.probe.pid);
  assert.equal(b.consistency.snapshotPinned,true);assert.equal(b.consistency.end.verified,true);assert.equal(b.consistency.end.unchanged,true);
  assert.equal(b.officialClientConnected,false);assert.equal(b.targetServiceContacted,false);
});
test('explicit revision update takes effect as a complete snapshot and never silently downgrades',async()=>{
  const root=await directory(),profile=await fixture();
  const a=await runStoredSession(root,{providerKind:'local_mock',initialProfile:profile});
  const changed=structuredClone(profile);changed.revision++;changed.hardware.memoryMiB*=2;
  const b=await runStoredSession(root,{providerKind:'local_mock',updatedProfile:changed});
  assert.equal(b.store.revision,profile.revision+1);assert.notEqual(a.modelDigest,b.modelDigest);
  assert.equal(b.observed.hardware.memoryMiB,changed.hardware.memoryMiB);
  await assert.rejects(runStoredSession(root,{providerKind:'local_mock',updatedProfile:profile}));
  const c=await runStoredSession(root,{providerKind:'local_mock'});
  assert.equal(c.modelDigest,b.modelDigest);assert.equal(c.store.revision,b.store.revision);
});
test('session cannot replace a missing vendor adapter with local metadata',async()=>{
  const root=await directory();await assert.rejects(runStoredSession(root,{providerKind:'vendor_adapter',initialProfile:await fixture()}),/VENDOR_ADAPTER_NOT_CONNECTED_NO_MOCK_FALLBACK/);
});
test('fixed CLI initializes once and reopens the same store without a profile argument',async()=>{
  const root=await directory();
  const invoke=args=>new Promise((resolve,reject)=>{
    const child=spawn(process.execPath,[join(lab,'session.mjs'),...args],{shell:false,windowsHide:true,cwd:lab,stdio:['ignore','pipe','pipe']});let output='',errors='';
    const timer=setTimeout(()=>{child.kill();reject(Error('SESSION_CLI_TIMEOUT'));},15000);
    child.stdout.on('data',b=>{output+=b.toString();if(output.length>131072){child.kill();reject(Error('SESSION_CLI_OUTPUT_LIMIT'));}});child.stderr.on('data',b=>{errors+=b.toString();});
    child.on('error',e=>{clearTimeout(timer);reject(e);});child.on('close',code=>{clearTimeout(timer);if(code!==0)reject(Error('SESSION_CLI_FAILED '+errors));else{try{resolve(JSON.parse(output));}catch(e){reject(e);}}});
  });
  const a=await invoke(['--provider','local_mock','--store',root,'--profile',join(lab,'fixtures','windows-x64.json')]);
  const b=await invoke(['--provider','local_mock','--store',root]);assert.equal(a.modelDigest,b.modelDigest);assert.equal(a.store.revision,b.store.revision);
});
