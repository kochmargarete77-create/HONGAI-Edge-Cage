'use strict';
const fs=require('fs'),assert=require('assert'),cp=require('child_process'),path=require('path');
const root=__dirname,route=require('./routing-policy.js');
const policy=JSON.parse(fs.readFileSync(path.join(root,'routing-policy.json'),'utf8'));
const suite=JSON.parse(fs.readFileSync(path.join(root,'test-cases.json'),'utf8'));
const actual=suite.cases.map(c=>{
    const r=route(Object.assign({},suite.base,c.set),policy),ids=r.findings.map(x=>x.id);
    assert.strictEqual(r.state,c.state,c.name);
    for(const id of c.has||[]) assert(ids.includes(id),c.name+': missing '+id);
    for(const id of c.lacks||[]) assert(!ids.includes(id),c.name+': unexpected '+id);
    for(const key of ['fullDesktopAccepted','networkAccepted','automaticApplyAllowed','hostNetworkSettingsChanged','loginStateChanged','networkRequestsMade','remoteProcessPresenceProvesConnection']) assert.strictEqual(r[key],false);
    return {name:c.name,report:r};
});
if(process.platform==='win32'){
    const ps=path.join(process.env.SystemRoot,'System32','WindowsPowerShell','v1.0','powershell.exe');
    const out=cp.execFileSync(ps,['-NoLogo','-NoProfile','-ExecutionPolicy','Bypass','-File',path.join(root,'Test-Routing.ps1'),'-Json'],{encoding:'utf8'});
    assert.deepStrictEqual(JSON.parse(out),actual,'PS5.1 and JavaScript routing must agree');
}
console.log('PASS '+actual.length+' fixtures'+(process.platform==='win32'?' and PS5.1/JavaScript parity':''));
