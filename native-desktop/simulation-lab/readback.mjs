import {spawn} from 'node:child_process';
import {createHash,randomBytes,randomUUID} from 'node:crypto';
import {readFile} from 'node:fs/promises';
import {fileURLToPath} from 'node:url';
import {SURFACES,validateModel,createLocalProvider,profileDigest} from './model.mjs';

const probePath=fileURLToPath(new URL('./probe.mjs',import.meta.url));
const sha=value=>createHash('sha256').update(value).digest('hex');
const fail=code=>Object.assign(new Error(code),{code});

export async function runLocalReadback(profile,{providerKind,timeoutMs=10000,fault='none'}={}){
  if(providerKind!=='local_mock')throw fail('VENDOR_ADAPTER_NOT_CONNECTED_NO_MOCK_FALLBACK');
  if(!Number.isInteger(timeoutMs)||timeoutMs<100||timeoutMs>30000||!['none','stale','silent','oversized','mutate'].includes(fault))throw fail('LAB_RUN_OPTIONS_INVALID');
  const model=validateModel(profile),provider=createLocalProvider(model,{kind:'local_mock'});
  const expected=Object.fromEntries(SURFACES.map(surface=>[surface,provider.observe(surface)]));
  const codeDigest=sha(await readFile(probePath)),runId=randomUUID(),challenge=randomBytes(24).toString('hex');
  const began=new Date().toISOString(),minimalEnv={};
  for(const name of ['SystemRoot','SYSTEMROOT','WINDIR','TEMP','TMP','TMPDIR'])if(process.env[name])minimalEnv[name]=process.env[name];
  const child=spawn(process.execPath,[probePath,fault],{shell:false,cwd:fileURLToPath(new URL('.',import.meta.url)),windowsHide:true,env:minimalEnv,stdio:['pipe','pipe','pipe']});
  child.stdout.setEncoding('utf8');
  const frames=[];let buffer='',bytes=0,stderrBytes=0,stderrHash=createHash('sha256'),complete=null,error=null,requestIndex=0;
  return await new Promise((resolve,reject)=>{
    function stop(code){if(!error)error=fail(code);child.stdin.destroy();if(child.exitCode===null)child.kill();}
    const timer=setTimeout(()=>stop('LOCAL_PROVIDER_READBACK_TIMEOUT'),timeoutMs);
    child.on('error',()=>stop('LOCAL_PROBE_PROCESS_START_FAILED'));
    child.stdin.on('error',()=>{if(!complete)stop('LOCAL_PROVIDER_PIPE_CLOSED');});
    child.stderr.on('data',data=>{stderrBytes+=data.length;if(stderrBytes>8192){stop('LOCAL_PROBE_STDERR_LIMIT');return;}stderrHash.update(data);});
    child.stdout.on('data',data=>{
      bytes+=Buffer.byteLength(data);if(bytes>256*1024){stop('LOCAL_PROTOCOL_OUTPUT_LIMIT');return;}
      buffer+=data;if(Buffer.byteLength(buffer)>32768&&!buffer.includes('\n')){stop('LOCAL_PROTOCOL_FRAME_LIMIT');return;}
      for(;;){const end=buffer.indexOf('\n');if(end<0)break;const line=buffer.slice(0,end);buffer=buffer.slice(end+1);if(Buffer.byteLength(line)>32768){stop('LOCAL_PROTOCOL_FRAME_LIMIT');return;}
        let value;try{value=JSON.parse(line);}catch{stop('LOCAL_PROTOCOL_JSON_INVALID');return;}
        frames.push(value);if(frames.length>16||value.version!==1||value.runId!==runId||value.challenge!==challenge){stop('LOCAL_PROTOCOL_IDENTITY_OR_REPLAY_FAILURE');return;}
        if(value.type==='read'){
          const surface=SURFACES[requestIndex];
          if(complete||!surface||value.surface!==surface||value.requestId!=='r'+requestIndex){stop('LOCAL_PROTOCOL_READ_SEQUENCE_INVALID');return;}
          let result;try{result=provider.observe(surface);}catch{stop('LOCAL_PROVIDER_SURFACE_UNAVAILABLE');return;}
          requestIndex++;child.stdin.write(JSON.stringify({type:'value',version:1,runId,challenge,requestId:value.requestId,surface,value:result})+'\n');
        }else if(value.type==='complete'){
          if(complete||requestIndex!==SURFACES.length||sha(JSON.stringify(value.observed))!==value.observedDigest){stop('LOCAL_PROTOCOL_COMPLETION_INVALID');return;}
          complete=value;child.stdin.end();
        }else{stop('LOCAL_PROTOCOL_MESSAGE_NOT_SUPPORTED');return;}
      }
    });
    child.on('close',(exitCode,signal)=>{
      clearTimeout(timer);if(error){reject(error);return;}
      if(exitCode!==0||!complete||buffer.trim()){reject(fail('LOCAL_PROBE_DID_NOT_COMPLETE'));return;}
      if(JSON.stringify(expected)!==JSON.stringify(complete.observed)){reject(fail('LOCAL_MODEL_READBACK_MISMATCH'));return;}
      resolve({schema:'hongai.local-simulation-readback.v1',evidenceLevel:'LOCAL_SIMULATOR_READBACK',providerKind:'local_mock',runId,challenge,modelDigest:profileDigest(model),executionHost:process.platform,targetModel:model.platform??model.system??null,probe:{pid:child.pid,codeDigest,exitCode,signal,startedUtc:began,finishedUtc:new Date().toISOString(),protocolDigest:sha(JSON.stringify(frames)),stderrDigest:stderrHash.digest('hex')},expected,observed:complete.observed,matched:true,officialClientConnected:false,vendorAdapterStatus:'NOT_CONNECTED',targetServiceContacted:false,nativeHardwareReadPathsValidated:false,hostIdentifiersModified:false,hostNetworkModified:false,customerReady:false});
    });
    child.stdin.write(JSON.stringify({type:'start',version:1,runId,challenge,surfaces:SURFACES})+'\n');
  });
}
