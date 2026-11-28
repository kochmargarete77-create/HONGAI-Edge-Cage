import {resolve} from 'node:path';
import {runLocalReadback} from './readback.mjs';
import {loadModelInput} from './model-input.mjs';

const args=process.argv.slice(2);
if(args.length!==4||args[0]!=='--provider'||args[1]!=='local_mock'||args[2]!=='--profile'){
  process.stderr.write('USAGE: node demo.mjs --provider local_mock --profile <local-fixture.json>\n');process.exitCode=2;
}else{
  try{
    const profile=await loadModelInput(resolve(args[3]));
    process.stdout.write(JSON.stringify(await runLocalReadback(profile,{providerKind:'local_mock'}),null,2)+'\n');
  }catch(error){const code=error.code||error.message;process.stderr.write(/^[A-Z0-9_]{1,100}$/.test(code)?code+'\n':'LOCAL_LAB_RUN_FAILED\n');process.exitCode=2;}
}
