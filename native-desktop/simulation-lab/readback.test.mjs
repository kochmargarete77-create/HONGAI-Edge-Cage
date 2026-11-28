import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {runLocalReadback} from './readback.mjs';

const load=async name=>JSON.parse(await readFile(new URL('./fixtures/'+name,import.meta.url),'utf8'));
test('independent process reads every model surface; evidence stays local',async()=>{
  for(const name of ['windows-x64.json','macos-arm64.json']){
    const profile=await load(name),report=await runLocalReadback(profile,{providerKind:'local_mock'});
    assert.equal(report.matched,true);assert.equal(Object.keys(report.observed).length,7);
    assert.deepEqual(report.observed,report.expected);
    assert.equal(report.evidenceLevel,'LOCAL_SIMULATOR_READBACK');assert.equal(report.executionHost,process.platform);
    assert.equal(report.officialClientConnected,false);assert.equal(report.targetServiceContacted,false);
    assert.equal(report.nativeHardwareReadPathsValidated,false);assert.equal(report.customerReady,false);
    assert.notEqual(report.probe.pid,process.pid);assert.equal(report.probe.exitCode,0);
  }
});
test('restarts keep the same model and use fresh challenges and actual child processes',async()=>{
  const profile=await load('windows-x64.json');
  const a=await runLocalReadback(profile,{providerKind:'local_mock'}),b=await runLocalReadback(profile,{providerKind:'local_mock'});
  assert.equal(a.modelDigest,b.modelDigest);assert.deepEqual(a.observed,b.observed);
  assert.notEqual(a.challenge,b.challenge);assert.notEqual(a.runId,b.runId);assert.equal(a.probe.codeDigest,b.probe.codeDigest);
  const changed=structuredClone(profile);changed.revision++;changed.hardware.memoryMiB*=2;
  const c=await runLocalReadback(changed,{providerKind:'local_mock'});
  assert.equal(a.probe.codeDigest,c.probe.codeDigest);assert.notEqual(a.modelDigest,c.modelDigest);
  assert.notDeepEqual(a.observed.hardware,c.observed.hardware);
});
test('missing vendor connector cannot silently fall back to local simulation',async()=>{
  const profile=await load('windows-x64.json');
  for(const kind of [undefined,'vendor_adapter','unknown'])await assert.rejects(runLocalReadback(profile,{providerKind:kind}),/VENDOR_ADAPTER_NOT_CONNECTED_NO_MOCK_FALLBACK/);
});
test('stale challenges, timeout, output overflow and changed observations fail visibly',async()=>{
  const profile=await load('windows-x64.json');
  for(const [fault,code,timeoutMs]of[['stale','IDENTITY_OR_REPLAY',10000],['silent','TIMEOUT',250],['oversized','FRAME_LIMIT',10000],['mutate','READBACK_MISMATCH',10000]]){
    await assert.rejects(runLocalReadback(profile,{providerKind:'local_mock',fault,timeoutMs}),new RegExp(code));
  }
});
