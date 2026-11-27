/* Pure ES5 evaluator shared by the macOS JXA collector and Node-based CI. */
function hongaiRoute(facts, policy) {
    if (!policy || policy.schema !== 'hongai.device-routing-policy.v1') throw new Error('UNSUPPORTED_POLICY_SCHEMA');
    function number(v) { return typeof v === 'number' && isFinite(v); }
    function test(c) {
        var v = Object.prototype.hasOwnProperty.call(facts, c.field) ? facts[c.field] : null;
        var known = v !== null && typeof v !== 'undefined';
        switch (c.op) {
            case 'missing': return !known;
            case 'eq': return known && v === c.value;
            case 'in': return known && c.value.indexOf(v) !== -1;
            case 'notIn': return !known || c.value.indexOf(v) === -1;
            case 'lt': return number(v) && v < c.value;
            case 'gte': return number(v) && v >= c.value;
            default: throw new Error('UNKNOWN_POLICY_OPERATOR');
        }
    }
    var findings = [], state = 'UNVERIFIED_CANDIDATE', i, j, r, match;
    for (i = 0; i < policy.rules.length; i++) {
        r = policy.rules[i]; match = true;
        for (j = 0; j < r.when.length; j++) if (!test(r.when[j])) { match = false; break; }
        if (match) findings.push({id: r.id, severity: r.severity, next: r.next});
    }
    var levels = ['REVIEW', 'PRODUCT_GAP', 'BLOCK'];
    var states = ['REVIEW_REQUIRED', 'PRODUCT_REVIEW_REQUIRED', 'BLOCKED'];
    for (i = 0; i < levels.length; i++) for (j = 0; j < findings.length; j++) if (findings[j].severity === levels[i]) state = states[i];
    return {schema:'hongai.device-intake.v1',policyRevision:policy.revision,state:state,facts:facts,findings:findings,
        fullDesktopAccepted:false,networkAccepted:false,automaticApplyAllowed:false,hostNetworkSettingsChanged:false,
        loginStateChanged:false,networkRequestsMade:false,remoteProcessPresenceProvesConnection:false,
        signatureAndRuntimeAcceptance:'NOT_PERFORMED'};
}
if (typeof module !== 'undefined') module.exports = hongaiRoute;
