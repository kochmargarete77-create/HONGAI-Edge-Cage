/* Runs with system JXA only. No Automation/Accessibility permission is requested. */
ObjC.import('Foundation');
function readText(path) {
    var text = $.NSString.stringWithContentsOfFileEncodingError(path, $.NSUTF8StringEncoding, null);
    if (!text) throw new Error('CANNOT_READ_POLICY_FILES');
    return ObjC.unwrap(text);
}
function run(argv) {
    var root=argv[0],target=argv[1] || 'NetworkAssessment',mode=argv[2] || 'NotRequired';
    if (['NetworkAssessment','DesktopPilot','FullDesktop'].indexOf(target) === -1 || ['NotRequired','Unknown','Cloud','LocalVM'].indexOf(mode) === -1) throw new Error('INVALID_ARGUMENTS');
    function command(path,args) {
        try {
            var task=$.NSTask.alloc.init,pipe=$.NSPipe.pipe;
            task.launchPath=path;task.arguments=args;task.standardOutput=pipe;task.standardError=$.NSFileHandle.fileHandleWithNullDevice;
            task.launch;
            var data=pipe.fileHandleForReading.readDataToEndOfFile;
            task.waitUntilExit;
            if (task.terminationStatus !== 0) return null;
            return ObjC.unwrap($.NSString.alloc.initWithDataEncoding(data,$.NSUTF8StringEncoding)).trim();
        } catch(e) { return null; }
    }
    function exists(path) { return Boolean($.NSFileManager.defaultManager.fileExistsAtPath(path)); }
    var os=command('/usr/bin/sw_vers',['-productVersion']);
    var processArch=command('/usr/bin/uname',['-m']);
    var arm=command('/usr/sbin/sysctl',['-n','hw.optional.arm64']);
    var translated=command('/usr/sbin/sysctl',['-n','sysctl.proc_translated']);
    var total=command('/usr/sbin/sysctl',['-n','hw.memsize']);
    var home=ObjC.unwrap($.NSHomeDirectory());
    var facts={platform:'Mac',target:target,coworkMode:mode,osVersion:os,macMajor:os?parseInt(os.split('.')[0],10):null,
        hardwareArchitecture:arm==='1'?'arm64':processArch==='x86_64'?'x64':null,
        processArchitecture:processArch,rosettaTranslated:translated==='1',totalMemoryGB:total?Math.round(Number(total)/1073741824*100)/100:null,
        freeMemoryGB:null,dataVolumeFreeGB:null,officialInstallKind:'NOT_FOUND_STANDARD_LOCATIONS',officialVersion:null,
        managedPolicyPresent:null,existingClaudeStatePresent:null,tunCandidateCount:null,remoteToolProcessPresent:null,
        collector:'SYSTEM_JXA',collectionLimitations:['MDM_NOT_FULLY_INSPECTED','AVAILABLE_MEMORY_NOT_ESTIMATED','TUN_ROUTES_NOT_INSPECTED','ALTERNATE_APP_LOCATIONS_NOT_INSPECTED']};
    var disk=command('/bin/df',['-Pk',root]);
    if(disk){var lines=disk.split('\n'),cols=lines[lines.length-1].trim().split(/\s+/);if(cols.length>=4 && /^\d+$/.test(cols[3])) facts.dataVolumeFreeGB=Math.round(Number(cols[3])/1048576*100)/100;}
    var appPaths=['/Applications/Claude.app',home+'/Applications/Claude.app'];
    for(var i=0;i<appPaths.length;i++) if(exists(appPaths[i])){
        facts.officialInstallKind='APP_BUNDLE_IDENTITY_NOT_VERIFIED';
        var info=$.NSDictionary.dictionaryWithContentsOfFile(appPaths[i]+'/Contents/Info.plist');
        if(info){var v=info.objectForKey('CFBundleShortVersionString');if(v) facts.officialVersion=String(ObjC.unwrap(v));}
        break;
    }
    facts.existingClaudeStatePresent=exists(home+'/Library/Application Support/Claude') || exists(home+'/Library/Preferences/com.anthropic.claudefordesktop.plist');
    facts.managedPolicyPresent=exists('/Library/Managed Preferences/com.anthropic.claudefordesktop.plist')?true:null;
    var remote=command('/usr/bin/pgrep',['-i','ToDesk|TeamViewer|Sunlogin|RustDesk']);
    facts.remoteToolProcessPresent=remote!==null;
    /* Only trusted sibling code is loaded. No customer document or network content is evaluated. */
    eval(readText(root+'/routing-policy.js'));
    return JSON.stringify(hongaiRoute(facts,JSON.parse(readText(root+'/routing-policy.json'))),null,2);
}
