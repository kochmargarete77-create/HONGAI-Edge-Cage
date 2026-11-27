'use strict';
const fs=require('fs'),path=require('path'),cp=require('child_process'),assert=require('assert'),validate=require('./deployment-contract.js');
const suite=JSON.parse(fs.readFileSync(path.join(__dirname,'test-cases.json'),'utf8'));
const results=suite.cases.map(c=>{
    const request=Object.assign({},suite.request,c.request),report=Object.assign({},suite.report,c.report),handoff=Object.assign({},suite.handoff,c.handoff);
    handoff.generatedAt=new Date(Date.now()+(handoff.generatedAt==='TEST_OLD'?-3600000:handoff.generatedAt==='TEST_FUTURE'?3600000:0)).toISOString();
    let actual='OK';try{const r=validate(request,report,handoff);if(r.handoffRefreshRequired)actual='OK_REFRESH';assert.strictEqual(r.fullDesktopAccepted,false);assert.strictEqual(r.networkAcceptedByThisCheck,false);}catch(e){actual=e.message;}
    assert.strictEqual(actual,c.expected,c.name);return {name:c.name,result:actual};
});
if(process.platform==='win32'){
    const ps=path.join(process.env.SystemRoot,'System32','WindowsPowerShell','v1.0','powershell.exe');
    const actual=JSON.parse(cp.execFileSync(ps,['-NoLogo','-NoProfile','-ExecutionPolicy','Bypass','-File',path.join(__dirname,'Test-DeploymentContract.ps1'),'-Json'],{encoding:'utf8'}));
    assert.deepStrictEqual(actual,results,'PS5/JS contract parity');
}
console.log('PASS '+results.length+' deployment contract cases'+(process.platform==='win32'?' and native PowerShell parity':''));
