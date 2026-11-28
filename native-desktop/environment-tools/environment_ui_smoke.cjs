// Synthetic UI fixture only; never run against customer profiles or accounts.
const fs=require('node:fs'),path=require('node:path'),{spawn}=require('node:child_process');
const chrome=process.env.HONGAI_BROWSER_FIXTURE_PATH,url=process.env.HONGAI_UI_TEST_URL,out=process.env.HONGAI_UI_TEST_OUTPUT;
if(!chrome||!url||!out)throw Error('UI_FIXTURE_ENV_REQUIRED');
const browser=spawn(chrome,['--headless=new','--remote-debugging-pipe','--user-data-dir='+path.join(out,'browser-profile'),'--no-first-run','--no-default-browser-check','--disable-background-networking','--disable-component-update','--disable-default-apps','--disable-extensions','--disable-sync','--disable-gpu','--disable-breakpad','--renderer-process-limit=1','--js-flags=--max-old-space-size=128','about:blank'],{windowsHide:true,stdio:['ignore','ignore','pipe','pipe','pipe']});
let seq=0,buffer='',stderr='';const pending=new Map();
browser.stderr.on('data',x=>{if(stderr.length<10000)stderr+=x.toString()});
browser.stdio[4].on('data',b=>{buffer+=b.toString();for(;;){const i=buffer.indexOf('\0');if(i<0)break;const raw=buffer.slice(0,i);buffer=buffer.slice(i+1);if(!raw)continue;const m=JSON.parse(raw);if(m.id&&pending.has(m.id)){const p=pending.get(m.id);pending.delete(m.id);clearTimeout(p.timer);m.error?p.reject(Error('CDP_REQUEST_FAILED')):p.resolve(m.result)}}});
function call(method,params={},sessionId){return new Promise((resolve,reject)=>{const id=++seq,timer=setTimeout(()=>{pending.delete(id);reject(Error('CDP_REQUEST_TIMEOUT'))},15000);pending.set(id,{resolve,reject,timer});browser.stdio[3].write(JSON.stringify({id,method,params,...(sessionId?{sessionId}:{})})+'\0')})}
const sleep=n=>new Promise(r=>setTimeout(r,n));
const watchdog=setTimeout(()=>{browser.kill();process.exit(2)},55000);
(async()=>{
 const {targetId}=await call('Target.createTarget',{url:'about:blank'}),{sessionId}=await call('Target.attachToTarget',{targetId,flatten:true});const c=(m,p={})=>call(m,p,sessionId);const ev=async expression=>(await c('Runtime.evaluate',{expression,returnByValue:true,awaitPromise:true})).result.value;
 await c('Page.enable');await c('Runtime.enable');await c('Emulation.setDeviceMetricsOverride',{width:1280,height:960,deviceScaleFactor:1,mobile:false});await c('Page.navigate',{url});
 async function until(expr){for(let i=0;i<80;i++){if(await ev(expr))return;await sleep(100)}throw Error('UI_EXPECTATION_TIMEOUT')}
 await until('document.readyState==="complete" && document.getElementById("settings")!==null');
 await ev(`(()=>{document.getElementById('proxy').value='http://127.0.0.1:17896';document.getElementById('exit').value='198.51.100.45';document.getElementById('assessment').checked=true;document.getElementById('settings').requestSubmit();})()`);
 await until('document.getElementById("configuration").classList.contains("hidden")');
 await ev('document.getElementById("probe").click()');await until('document.getElementById("proxy-state").textContent==="回显符合工单"');
 await ev('document.getElementById("launch").click()');await until('document.getElementById("message").textContent.includes("账号登录和业务验证")');
 const report={scope:'SYNTHETIC_UI_NO_ACCOUNT_NO_OFFICIAL_CLIENT_LAUNCH',settingsSaved:true,proxyFixtureFlow:true,activationFixtureFlow:true,desktopFits:await ev('document.documentElement.scrollWidth<=innerWidth')};
 const downloads=path.join(out,'downloads');fs.mkdirSync(downloads,{recursive:true});await call('Browser.setDownloadBehavior',{behavior:'allow',downloadPath:downloads});await ev('document.getElementById("support").click()');await until('document.getElementById("message").textContent.includes("诊断单已导出")');
 const supportFile=path.join(downloads,'HONGAI-Support.json');for(let n=0;n<50&&!fs.existsSync(supportFile);n++)await sleep(100);const support=JSON.parse(fs.readFileSync(supportFile,'utf8'));if(support.schema!=='hongai.environment-support.v1'||support.containsCredentials!==false||support.containsRawIPOrPaths!==false||support.fullEnvironmentAccepted!==false||JSON.stringify(support).includes('198.51.100.45'))throw Error('SUPPORT_EXPORT_SCOPE_FAILED');report.supportDownloadVerified=true;
 let shot=await c('Page.captureScreenshot',{format:'png',captureBeyondViewport:false});fs.writeFileSync(path.join(out,'ui-desktop.png'),Buffer.from(shot.data,'base64'));
 await c('Emulation.setDeviceMetricsOverride',{width:390,height:844,deviceScaleFactor:1,mobile:true});await ev('window.scrollTo(0,0)');await sleep(100);report.narrowFits=await ev('document.documentElement.scrollWidth<=innerWidth');shot=await c('Page.captureScreenshot',{format:'png',captureBeyondViewport:false});fs.writeFileSync(path.join(out,'ui-narrow.png'),Buffer.from(shot.data,'base64'));
 report.passed=report.desktopFits&&report.narrowFits;fs.writeFileSync(path.join(out,'ui-smoke-result.json'),JSON.stringify(report,null,2));if(!report.passed)throw Error('UI_OVERFLOW');console.log(JSON.stringify(report));
})().catch(e=>{console.error(e.message);process.exitCode=1}).finally(async()=>{try{await call('Browser.close')}catch{}await sleep(300);if(browser.exitCode===null)browser.kill();clearTimeout(watchdog);fs.writeFileSync(path.join(out,'browser-stderr.txt'),stderr)});
