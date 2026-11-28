import {open,lstat,constants} from 'node:fs/promises';

const limit=65536;
const fail=code=>Object.assign(new Error(code),{code});
/** Read at most limit+1 bytes, even if a file grows while it is being read. */
export async function loadModelInput(path){
  const before=await lstat(path);
  if(!before.isFile()||before.isSymbolicLink())throw fail('REGULAR_MODEL_INPUT_REQUIRED');
  if(before.size>limit)throw fail('MODEL_INPUT_LIMIT');
  const handle=await open(path,constants.O_RDONLY|(constants.O_NOFOLLOW||0));
  try{
    const current=await handle.stat();
    if(!current.isFile()||current.dev!==before.dev||current.ino!==before.ino)throw fail('MODEL_INPUT_CHANGED');
    if(current.size>limit)throw fail('MODEL_INPUT_LIMIT');
    const buffer=Buffer.alloc(limit+1);let offset=0;
    while(offset<buffer.length){const {bytesRead}=await handle.read(buffer,offset,buffer.length-offset,null);if(!bytesRead)break;offset+=bytesRead;}
    if(offset>limit)throw fail('MODEL_INPUT_LIMIT');
    try{return JSON.parse(buffer.subarray(0,offset).toString('utf8'));}catch{throw fail('MODEL_JSON_INVALID');}
  }finally{await handle.close();}
}
