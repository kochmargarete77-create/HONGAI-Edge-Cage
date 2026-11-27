/* ES5: native JXA on macOS, Node only for tests. Does not execute request data. */
function hongaiDeploymentContract(request,report,handoff) {
    function fail(s){throw new Error(s);}
    function keys(o,names){return o && Object.keys(o).length===names.length && Object.keys(o).every(function(k){return names.indexOf(k)!==-1;});}
    if(!keys(request,['schema','caseId','environmentReport','handoffFile','workspace']) || request.schema!=='hongai.agent-deployment-request.v1') fail('INVALID_REQUEST_SCHEMA_OR_UNEXPECTED_FIELD');
    if(typeof request.caseId!=='string' || !/^[A-Za-z0-9][A-Za-z0-9_-]{2,63}$/.test(request.caseId)) fail('INVALID_CASE_ID');
    ['environmentReport','handoffFile','workspace'].forEach(function(k){if(typeof request[k]!=='string' || !request[k].trim() || /[\x00-\x1f"]/.test(request[k])) fail('INVALID_REQUEST_PATH');});
    ['schema','case_id','phase','desktop_stage','readiness_score','ready_for_handoff','host_ready_for_stage2','login_attempted','source_evidence_complete','local_evidence_complete','failed_hard_gates'].forEach(function(k){if(!report || !Object.prototype.hasOwnProperty.call(report,k)) fail('ENVIRONMENT_REPORT_FIELDS_MISSING');});
    if(report.schema!=='HONGAI-READINESS-RESULT-2.1' || report.case_id!==request.caseId || report.phase!=='FINAL' || report.desktop_stage!=='PREDEPLOY') fail('NEED_MATCHING_FINAL_PREDEPLOY_REPORT');
    if(typeof report.readiness_score!=='number' || report.readiness_score!==100) fail('ENVIRONMENT_SCORE_MUST_BE_NUMERIC_100');
    ['ready_for_handoff','host_ready_for_stage2','source_evidence_complete','local_evidence_complete'].forEach(function(k){if(report[k]!==true) fail('ENVIRONMENT_EVIDENCE_NOT_ACCEPTED');});
    if(report.login_attempted!==false || !Array.isArray(report.failed_hard_gates) || report.failed_hard_gates.length) fail('ENVIRONMENT_HARD_GATE_NOT_ACCEPTED');
    if(!keys(handoff,['version','tool','loopback','expectedEgressIp','routeId','generatedAt'])) fail('INVALID_HANDOFF_FIELDS_NO_SUBSCRIPTIONS_OR_SECRETS');
    if(!keys(handoff.loopback,['protocol','host','mixedPort'])) fail('INVALID_LOOPBACK_FIELDS');
    var p=handoff.loopback.mixedPort;
    if(handoff.version!==1 || handoff.tool!=='clash' || handoff.loopback.host!=='127.0.0.1' || handoff.loopback.protocol!=='http' || typeof p!=='number' || p%1 || p<1024 || p>65535 || !/^[a-f0-9]{24}$/.test(handoff.routeId)) fail('INVALID_HANDOFF_VALUES');
    if(typeof handoff.expectedEgressIp!=='string' || !/^\d{1,3}(\.\d{1,3}){3}$/.test(handoff.expectedEgressIp)) fail('INVALID_PUBLIC_IPV4');
    var o=handoff.expectedEgressIp.split('.').map(Number);
    if(o.some(function(x){return x>255;}) || o[0]===0 || o[0]>=224 || [10,127].indexOf(o[0])!==-1 || o[0]===169&&o[1]===254 || o[0]===192&&o[1]===168 || o[0]===172&&o[1]>=16&&o[1]<=31 || o[0]===100&&o[1]>=64&&o[1]<=127) fail('INVALID_PUBLIC_IPV4');
    var date=Date.parse(handoff.generatedAt),age=Date.now()-date;
    if(!isFinite(date) || age < -30000) fail('INVALID_HANDOFF_TIME');
    return {handoffRefreshRequired:age>600000,networkAcceptedByThisCheck:false,fullDesktopAccepted:false};
}
if(typeof module!=='undefined') module.exports=hongaiDeploymentContract;
