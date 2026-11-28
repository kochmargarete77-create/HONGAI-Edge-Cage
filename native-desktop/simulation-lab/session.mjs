import {isAbsolute,resolve,parse} from 'node:path';
import {pathToFileURL} from 'node:url';
import {createModelStore,readModelStore,updateModelStore} from './model-store.mjs';
import {profileDigest} from './model.mjs';
import {runLocalReadback} from './readback.mjs';
import {loadModelInput} from './model-input.mjs';

const failure=code=>Object.assign(new Error(code),{code});
function safeCode(error){const code=error?.code||error?.message;return typeof code==='string'&&/^[A-Z0-9_]{1,100}$/.test(code)?code:'MODEL_SESSION_FAILED_NO_RAW_DETAILS';}

/** One committed model snapshot supplies every observation in this session. */
export async function runStoredSession(directory,{providerKind,initialProfile,updatedProfile}={}){
  if(providerKind!=='local_mock')throw failure('VENDOR_ADAPTER_NOT_CONNECTED_NO_MOCK_FALLBACK');
  if(initialProfile!==undefined&&updatedProfile!==undefined)throw failure('MODEL_SESSION_OPTIONS_CONFLICT');
  let snapshot;
  if(initialProfile!==undefined)snapshot=await createModelStore(directory,initialProfile);
  else if(updatedProfile!==undefined)snapshot=await updateModelStore(directory,updatedProfile);
  else snapshot=await readModelStore(directory);
  if(snapshot.modelDigest!==profileDigest(snapshot.profile))throw failure('MODEL_SESSION_SNAPSHOT_DIGEST_INVALID');
  const report=await runLocalReadback(snapshot.profile,{providerKind:'local_mock'});
  let end;
  try{
    const current=await readModelStore(directory);
    end={verified:true,revision:current.revision,modelDigest:current.modelDigest,unchanged:current.headDigest===snapshot.headDigest};
  }catch(error){end={verified:false,code:safeCode(error)};}
  return {...report,schema:'hongai.stored-simulation-session.v1',store:{environmentId:snapshot.environmentId,revision:snapshot.revision,modelDigest:snapshot.modelDigest,headDigest:snapshot.headDigest,recovery:snapshot.recovery,budget:snapshot.budget,powerLossDurabilityVerified:false},consistency:{snapshotPinned:true,allSurfacesFromOneRevision:true,end},customerReady:false};
}

async function cli(args){
  const options=new Map();
  for(let i=0;i<args.length;i+=2){
    const key=args[i],value=args[i+1];
    if(!['--provider','--store','--profile','--apply-profile'].includes(key)||options.has(key)||!value||value.startsWith('--'))throw failure('MODEL_SESSION_ARGUMENTS_INVALID');
    options.set(key,value);
  }
  const directory=options.get('--store');
  if(options.get('--provider')!=='local_mock'||!directory||!isAbsolute(directory)||directory===parse(directory).root)throw failure('EXPLICIT_LOCAL_PROVIDER_AND_ABSOLUTE_STORE_REQUIRED');
  if(process.platform==='win32'&&!/^[DE]:\\/i.test(directory))throw failure('LAB_PROJECT_STORAGE_REQUIRES_D_OR_E');
  if(options.has('--profile')&&options.has('--apply-profile'))throw failure('MODEL_SESSION_OPTIONS_CONFLICT');
  const load=async path=>loadModelInput(resolve(path));
  const initialProfile=options.has('--profile')?await load(options.get('--profile')):undefined;
  const updatedProfile=options.has('--apply-profile')?await load(options.get('--apply-profile')):undefined;
  const result=await runStoredSession(directory,{providerKind:'local_mock',initialProfile,updatedProfile});
  process.stdout.write(JSON.stringify(result,null,2)+'\n');
}
if(process.argv[1]&&import.meta.url===pathToFileURL(resolve(process.argv[1])).href){
  cli(process.argv.slice(2)).catch(error=>{process.stderr.write(safeCode(error)+'\n');process.exitCode=2;});
}
