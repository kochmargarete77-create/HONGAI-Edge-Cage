import assert from 'node:assert/strict';
import {spawn} from 'node:child_process';
import {createHash} from 'node:crypto';
import {mkdir,mkdtemp,readFile,realpath,writeFile} from 'node:fs/promises';
import {join} from 'node:path';
import {fileURLToPath} from 'node:url';
import {loadModelInput} from './model-input.mjs';
import {runStoredSession} from './session.mjs';
import {runLocalReadback} from './readback.mjs';
import {evaluateCoherence} from './coherence.mjs';

const lab=await realpath(fileURLToPath(new URL('.',import.meta.url)));
if(process.platform==='win32'&&!/^[DE]:\\/i.test(lab))throw Error('PROJECT_DRIVE_REQUIRED');
const out=join(lab,'out');await mkdir(out,{recursive:true});
const temporary=join(lab,'tmp');await mkdir(temporary,{recursive:true});
const runRoot=await mkdtemp(join(temporary,'native-ci-'));
for(const key of ['TEMP','TMP','TMPDIR'])process.env[key]=runRoot;
process.env.HONGAI_MODEL_STORE_TEST_ROOT=join(runRoot,'store-tests');
const tests=['model.test.mjs','model-input.test.mjs','model-store.test.mjs','readback.test.mjs','session.test.mjs','platform-matrix.test.mjs','coherence.test.mjs'];
const fixtures=['windows-x64.json','macos-arm64.json','macos-x64.json'];
const sourceFiles=['model.mjs','model-input.mjs','model-store.mjs','readback.mjs','probe.mjs','session.mjs','coherence.mjs','ci-validate.mjs',...tests,...fixtures.map(f=>'fixtures/'+f)];
const summary={schema:'hongai.local-simulation-native-validation.v1',startedUtc:new Date().toISOString(),host:{platform:process.platform,architecture:process.arch,nodeVersion:process.version},sourceCommit:process.env.GITHUB_SHA??null,runnerLabel:process.env.HONGAI_LAB_RUNNER_LABEL??'local',evidenceLevel:'LOCAL_SIMULATOR_READBACK',officialClientConnected:false,vendorAdapterStatus:'NOT_CONNECTED',targetServiceContacted:false,nativeHardwareReadPathsValidated:false,powerLossDurabilityVerified:false,hostNetworkModified:false,hostIdentifiersModified:false,customerReady:false,result:'FAILED'};
async function suite(){
  return new Promise((resolve,reject)=>{
    const child=spawn(process.execPath,['--test','--test-concurrency=1','--test-reporter=tap',...tests],{cwd:lab,shell:false,windowsHide:true,stdio:['ignore','pipe','pipe']});
    const buffers={stdout:[],stderr:[]};let total=0,failed=null;
    const stop=message=>{failed??=Error(message);child.kill();};
    const timer=setTimeout(()=>stop('TEST_TIMEOUT'),180000);
    for(const key of ['stdout','stderr'])child[key].on('data',chunk=>{total+=chunk.length;if(total>2097152)stop('TEST_OUTPUT_LIMIT');else buffers[key].push(chunk);});
    child.on('error',()=>stop('TEST_PROCESS_FAILED'));
    child.on('close',code=>{clearTimeout(timer);if(failed)reject(failed);else resolve({code,stdout:Buffer.concat(buffers.stdout).toString('utf8'),stderr:Buffer.concat(buffers.stderr).toString('utf8')});});
  });
}
try{
  const expectedPlatform=process.env.HONGAI_LAB_EXPECT_PLATFORM,expectedArch=process.env.HONGAI_LAB_EXPECT_ARCH;
  if(expectedPlatform)assert.equal(process.platform,expectedPlatform);
  if(expectedArch)assert.equal(process.arch,expectedArch);
  const result=await suite();await writeFile(join(out,'tests.tap'),result.stdout);await writeFile(join(out,'tests.stderr.txt'),result.stderr);
  const counts=Object.fromEntries(['tests','pass','fail','cancelled','skipped','todo'].map(key=>[key,Number(result.stdout.match(new RegExp('^# '+key+' (\\d+)$','m'))?.[1]??-1)]));
  summary.tests=counts;assert.equal(result.code,0,'TEST_PROCESS_NONZERO');assert.equal(counts.tests,37,'TEST_INVENTORY_CHANGED_REQUIRES_REVIEW');assert.equal(counts.pass,37);
  for(const key of ['fail','cancelled','skipped','todo'])assert.equal(counts[key],0);
  summary.sessions=[];
  for(const fixture of fixtures){
    const profile=await loadModelInput(join(lab,'fixtures',fixture)),store=join(runRoot,fixture.replace('.json',''));
    const first=await runStoredSession(store,{providerKind:'local_mock',initialProfile:profile});
    const reopened=await runStoredSession(store,{providerKind:'local_mock'});
    assert.equal(first.modelDigest,reopened.modelDigest);assert.deepEqual(first.observed,reopened.observed);assert.notEqual(first.runId,reopened.runId);assert.equal(reopened.consistency.end.unchanged,true);
    const revised=structuredClone(profile);revised.revision++;
    const updated=await runStoredSession(store,{providerKind:'local_mock',updatedProfile:revised});
    assert.equal(updated.store.revision,revised.revision);assert.notEqual(first.modelDigest,updated.modelDigest);assert.equal(updated.consistency.end.unchanged,true);
    const rawA=await runLocalReadback(profile,{providerKind:'local_mock'}),rawB=await runLocalReadback(profile,{providerKind:'local_mock'});
    const coherence=evaluateCoherence(profile,[rawA,rawB]);assert.equal(coherence.status,'PASS');assert.equal(coherence.localReadbackComplete,true);assert.equal(coherence.fullEnvironmentAccepted,false);
    await writeFile(join(out,fixture.replace('.json','-sessions.json')),JSON.stringify({first,reopened,updated,coherence},null,2)+'\n');
    summary.sessions.push({fixture,stableIdentity:true,reopenedObservationsIdentical:true,explicitRevisionUpdateVerified:true,modelDigests:[first.modelDigest,updated.modelDigest],childPids:[first.probe.pid,reopened.probe.pid,updated.probe.pid]});
  }
  summary.sourceFiles=await Promise.all(sourceFiles.map(async path=>{const bytes=await readFile(join(lab,path));return {path,bytes:bytes.length,sha256:createHash('sha256').update(bytes).digest('hex')};}));
  summary.result='PASS';
}catch(error){summary.failureCode=/^[A-Z0-9_]{1,100}$/.test(error?.message??'')?error.message:'VALIDATION_FAILED_SEE_LOCAL_TEST_EVIDENCE';process.exitCode=1;}
summary.finishedUtc=new Date().toISOString();await writeFile(join(out,'validation.json'),JSON.stringify(summary,null,2)+'\n');process.stdout.write(JSON.stringify(summary)+'\n');
