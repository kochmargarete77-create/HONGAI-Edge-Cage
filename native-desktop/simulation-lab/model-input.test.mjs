import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdir,mkdtemp,writeFile} from 'node:fs/promises';
import {join} from 'node:path';
import {fileURLToPath} from 'node:url';
import {loadModelInput} from './model-input.mjs';

const tmp=fileURLToPath(new URL('./tmp/',import.meta.url));await mkdir(tmp,{recursive:true});
test('input is a regular bounded JSON file and malformed contents are not exposed',async()=>{
  const dir=await mkdtemp(join(tmp,'input-')),file=join(dir,'model.json');
  await writeFile(file,'{"fixture":true}');assert.deepEqual(await loadModelInput(file),{fixture:true});
  await writeFile(file,'SENSITIVE_TEXT_NOT_A_MODEL');await assert.rejects(loadModelInput(file),error=>error.message==='MODEL_JSON_INVALID');
  await writeFile(file,Buffer.alloc(65537));await assert.rejects(loadModelInput(file),/MODEL_INPUT_LIMIT/);
  await assert.rejects(loadModelInput(dir),/REGULAR_MODEL_INPUT_REQUIRED/);
});
