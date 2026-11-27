'use strict';
// Research core only. The trusted host owns this object; the MCP client receives
// opaque handles and cannot invoke grant/revoke/seal/takeProposal.
const fs=require('fs'),path=require('path'),crypto=require('crypto');
class SafeFailure extends Error {constructor(code){super(code);this.code=code;}}
const reject=code=>{throw new SafeFailure(code);};
class CapabilityVault {
  constructor({environmentId,sensitiveTokens=[]}){
    if(typeof environmentId!=='string'||!environmentId||environmentId.length>128)reject('INVALID_ENVIRONMENT');
    this.environmentId=environmentId;this.tokens=sensitiveTokens.filter(x=>typeof x==='string'&&x.length>=3).slice(0,256);
    this.objects=new Map();this.proposals=new Map();this.etagKey=crypto.randomBytes(32);
  }
  grant(file,{label='Approved file',ttlSeconds=900,allowEditProposal=false}={}){
    let fd;
    try{
      if(this.objects.size>=64)reject('GRANT_BUDGET_REACHED');
      if(typeof file!=='string'||!path.isAbsolute(file)||typeof label!=='string'||label.length>96||/[\\/\r\n]/.test(label)||!Number.isInteger(ttlSeconds)||ttlSeconds<1||ttlSeconds>3600)reject('INVALID_GRANT');
      const absolute=path.resolve(file),real=fs.realpathSync.native(absolute),same=process.platform==='win32'?real.toLowerCase()===absolute.toLowerCase():real===absolute;
      if(!same)reject('LINK_PATH_NOT_ALLOWED');
      const before=fs.lstatSync(absolute);
      if(!before.isFile()||before.isSymbolicLink()||before.nlink!==1||before.size>1048576)reject('UNSUPPORTED_OBJECT');
      fd=fs.openSync(absolute,fs.constants.O_RDONLY|(fs.constants.O_NOFOLLOW||0));
      const current=fs.fstatSync(fd);
      if(!current.isFile()||current.ino!==before.ino||current.dev!==before.dev||current.nlink!==1)reject('OBJECT_CHANGED_DURING_GRANT');
      const id='obj_'+crypto.randomBytes(24).toString('base64url');
      this.objects.set(id,{fd,file:absolute,label,expires:Date.now()+ttlSeconds*1000,allowEditProposal:allowEditProposal===true});
      return {objectId:id,label,rights:allowEditProposal?['read','propose_edit']:['read']};
    }catch(e){if(fd!==undefined)fs.closeSync(fd);if(e instanceof SafeFailure)throw e;reject('OBJECT_NOT_GRANTED');}
  }
  _get(id){const object=this.objects.get(id);if(!object)reject('OBJECT_NOT_GRANTED');if(Date.now()>=object.expires){this.revoke(id);reject('OBJECT_EXPIRED');}return object;}
  _read(object){
    try{
      const stat=fs.fstatSync(object.fd);if(!stat.isFile()||stat.nlink!==1||stat.size>1048576)reject('OBJECT_STATE_UNSUPPORTED');
      const bytes=Buffer.alloc(stat.size);let offset=0;
      while(offset<bytes.length){const n=fs.readSync(object.fd,bytes,offset,bytes.length-offset,offset);if(!n)reject('OBJECT_CHANGED_DURING_READ');offset+=n;}
      return bytes;
    }catch(e){if(e instanceof SafeFailure)throw e;reject('OBJECT_READ_FAILED');}
  }
  _mask(text){for(const token of this.tokens)text=text.split(token).join('[REDACTED_ENVIRONMENT]');return text;}
  call(name,args){
    try{
      if(!args||typeof args!=='object'||Array.isArray(args))reject('INVALID_ARGUMENTS');
      if(!['read_object','propose_edit'].includes(name))reject('TOOL_NOT_AVAILABLE');
      const allowed=name==='read_object'?['objectId','offset','length']:['objectId','expectedEtag','text'];
      if(Object.keys(args).some(k=>!allowed.includes(k)))reject('UNEXPECTED_ARGUMENT');
      const object=this._get(args.objectId),bytes=this._read(object),etag=crypto.createHmac('sha256',this.etagKey).update(args.objectId).update(bytes).digest('hex');
      if(name==='read_object'){
        const offset=args.offset===undefined?0:args.offset,length=args.length===undefined?65536:args.length;
        if(!Number.isInteger(offset)||!Number.isInteger(length)||offset<0||length<1||length>65536)reject('INVALID_RANGE');
        // Decode/mask the complete bounded object before slicing so an offset
        // cannot expose a sensitive literal by splitting it over requests.
        const text=new TextDecoder('utf-8',{fatal:true}).decode(bytes),masked=Buffer.from(this._mask(text));
        if(offset>masked.length)reject('INVALID_RANGE');
        return {objectId:args.objectId,label:object.label,text:masked.subarray(offset,offset+length).toString('utf8'),etag};
      }
      if(!object.allowEditProposal)reject('EDIT_NOT_GRANTED');
      if(args.expectedEtag!==etag)reject('OBJECT_VERSION_CHANGED');
      if(typeof args.text!=='string'||Buffer.byteLength(args.text)>1048576)reject('INVALID_EDIT');
      if(this.proposals.size>=32)reject('PROPOSAL_BUDGET_REACHED');
      const proposalId='edit_'+crypto.randomBytes(24).toString('base64url');
      this.proposals.set(proposalId,{objectId:args.objectId,expectedEtag:etag,text:args.text,expires:object.expires});
      return {proposalId,requiresTrustedHostCommit:true,fileWritten:false};
    }catch(e){if(e instanceof SafeFailure)throw e;reject('OBJECT_OPERATION_FAILED');}
  }
  takeProposal(id){const proposal=this.proposals.get(id);this.proposals.delete(id);if(!proposal||Date.now()>=proposal.expires)reject('PROPOSAL_UNAVAILABLE');this._get(proposal.objectId);return proposal;}
  revoke(id){const object=this.objects.get(id);if(object){fs.closeSync(object.fd);this.objects.delete(id);}for(const [key,p] of this.proposals)if(p.objectId===id)this.proposals.delete(key);}
  seal(key){
    if(!Buffer.isBuffer(key)||key.length!==32)reject('HOST_KEY_REQUIRED');
    const records=Array.from(this.objects.entries()).map(([id,o])=>({id,file:o.file,label:o.label,expires:o.expires,allowEditProposal:o.allowEditProposal}));
    const iv=crypto.randomBytes(12),cipher=crypto.createCipheriv('aes-256-gcm',key,iv);cipher.setAAD(Buffer.from('HONGAI-CAPABILITY-V1|'+this.environmentId));
    const ciphertext=Buffer.concat([cipher.update(JSON.stringify(records),'utf8'),cipher.final()]);
    return {schema:'hongai.sealed-capabilities.v1',iv:iv.toString('base64'),ciphertext:ciphertext.toString('base64'),tag:cipher.getAuthTag().toString('base64')};
  }
  static inspectSealed(bundle,key,environmentId){
    try{if(bundle.schema!=='hongai.sealed-capabilities.v1'||!Buffer.isBuffer(key)||key.length!==32)reject('SEALED_GRANTS_REJECTED');const d=crypto.createDecipheriv('aes-256-gcm',key,Buffer.from(bundle.iv,'base64'));d.setAAD(Buffer.from('HONGAI-CAPABILITY-V1|'+environmentId));d.setAuthTag(Buffer.from(bundle.tag,'base64'));return JSON.parse(Buffer.concat([d.update(Buffer.from(bundle.ciphertext,'base64')),d.final()]).toString('utf8'));}catch(e){reject('SEALED_GRANTS_REJECTED');}
  }
  close(){for(const id of Array.from(this.objects.keys()))this.revoke(id);}
}
function createMcpHandler(vault){
  let initialized=false;
  const tools=[{name:'read_object',description:'Read an explicitly granted object; no paths or ambient file enumeration.',inputSchema:{type:'object',properties:{objectId:{type:'string'},offset:{type:'integer'},length:{type:'integer'}},required:['objectId'],additionalProperties:false}},{name:'propose_edit',description:'Propose an edit to an authorized object; trusted host commits separately.',inputSchema:{type:'object',properties:{objectId:{type:'string'},expectedEtag:{type:'string'},text:{type:'string'}},required:['objectId','expectedEtag','text'],additionalProperties:false}}];
  return message=>{
    if(!message||message.jsonrpc!=='2.0'||typeof message.method!=='string')return {jsonrpc:'2.0',id:null,error:{code:-32600,message:'Invalid request'}};
    if(message.method==='notifications/initialized')return null;
    if(message.id===undefined)return null;
    const id=message.id===undefined?null:message.id;
    if(message.method==='initialize'){initialized=true;return {jsonrpc:'2.0',id,result:{protocolVersion:'2025-11-25',capabilities:{tools:{}},serverInfo:{name:'HONGAI Object Privacy Preview',version:'0.1.0'}}};}
    if(!initialized)return {jsonrpc:'2.0',id,error:{code:-32000,message:'Initialize required'}};
    if(message.method==='tools/list')return {jsonrpc:'2.0',id,result:{tools}};
    if(message.method!=='tools/call')return {jsonrpc:'2.0',id,error:{code:-32601,message:'Method not available'}};
    try{const result=vault.call(message.params.name,message.params.arguments);return {jsonrpc:'2.0',id,result:{content:[{type:'text',text:JSON.stringify(result)}],isError:false}};}catch(e){return {jsonrpc:'2.0',id,result:{content:[{type:'text',text:e instanceof SafeFailure?e.code:'OPERATION_FAILED'}],isError:true}};}
  };
}
module.exports={CapabilityVault,createMcpHandler};
