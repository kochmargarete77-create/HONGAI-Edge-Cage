ObjC.import('Foundation');
function run(argv){
    var root=argv[0],file=argv[1],action=argv[2]||'check',fm=$.NSFileManager.defaultManager;
    var result={schema:'hongai.agent-deployment-plan.v1',platform:'Mac',phase:'CHECKING',nextAction:'',fullDesktopAccepted:false,networkAcceptedByThisCheck:false,hostNetworkSettingsChanged:false,loginStateChanged:false,installerStarted:false,humanOnlyActions:['NORMAL_MAC_INSTALL_AUTHORIZATION_IF_REQUIRED','CUSTOMER_ACCOUNT_LOGIN_LATER'],writesPerformed:[]};
    function text(path){var s=$.NSString.stringWithContentsOfFileEncodingError(path,$.NSUTF8StringEncoding,null);if(!s)throw new Error('READ_LOCAL_FILE_FAILED');return ObjC.unwrap(s);}
    function json(path){if(typeof path!=='string'||path[0]!=='/'||/[\x00-\x1f"]/.test(path))throw new Error('LOCAL_ABSOLUTE_JSON_REQUIRED');var a=fm.attributesOfItemAtPathError(path,null);if(!a||Number(ObjC.unwrap(a.objectForKey('NSFileSize')))>262144)throw new Error('LOCAL_SMALL_JSON_REQUIRED');try{return JSON.parse(text(path));}catch(e){throw new Error('LOCAL_JSON_READ_OR_PARSE_FAILED_CONTENT_NOT_LOGGED');}}
    function command(path,args){var p=$.NSTask.alloc.init,pipe=$.NSPipe.pipe;p.launchPath=path;p.arguments=args;p.standardOutput=pipe;p.standardError=$.NSFileHandle.fileHandleWithNullDevice;p.launch;var data=pipe.fileHandleForReading.readDataToEndOfFile;p.waitUntilExit;if(p.terminationStatus!==0)throw new Error('CHECK_FAILED_'+path.split('/').pop());return ObjC.unwrap($.NSString.alloc.initWithDataEncoding(data,$.NSUTF8StringEncoding)).trim();}
    function exists(path){return Boolean(fm.fileExistsAtPath(path));}
    try{
        if(['check','install'].indexOf(action)===-1)throw new Error('ACTION_MUST_BE_CHECK_OR_INSTALL');
        if(command('/usr/bin/id',['-u'])==='0')throw new Error('RUN_AS_CUSTOMER_USER_NOT_ROOT');
        var req=json(file),report=json(req.environmentReport),handoff=json(req.handoffFile);
        eval(text(root+'/deployment-contract.js'));
        var validated=hongaiDeploymentContract(req,report,handoff);
        var os=command('/usr/bin/sw_vers',['-productVersion']);if(parseInt(os.split('.')[0],10)<13)throw new Error('MACOS_VERSION_NOT_SUPPORTED');
        var home=ObjC.unwrap($.NSHomeDirectory()),workspace=req.workspace;
        if(workspace[0]!=='/'||!exists(workspace)||workspace==='/'||workspace===home||workspace.indexOf('/System/')===0||workspace.indexOf('/Library/')===0||workspace.indexOf('/Applications/')===0||workspace===root)throw new Error('SELECT_SPECIFIC_NON_SYSTEM_PROJECT_FOLDER');
        var ws=$.NSURL.fileURLWithPath(workspace);if(ObjC.unwrap(ws.URLByResolvingSymlinksInPath.path)!==ObjC.unwrap(ws.URLByStandardizingPath.path))throw new Error('WORKSPACE_LINK_PATH_REJECTED');
        var workspaceAttributes=fm.attributesOfItemAtPathError(workspace,null);
        if(!workspaceAttributes||ObjC.unwrap(workspaceAttributes.objectForKey('NSFileType'))!=='NSFileTypeDirectory')throw new Error('WORKSPACE_MUST_BE_DIRECTORY');
        var pkg=root+'/HONGAI-CAGE-Desktop-0.3.0-build9-macOS-Universal.pkg';
        if(command('/usr/bin/shasum',['-a','256',pkg]).split(/\s+/)[0]!=='fb4b2f48c2f8e319273fed2f97837d1c0cc4ba4b4ecdcfcbeb6ac737d2de34de')throw new Error('SETUP_HASH_MISMATCH_DO_NOT_RUN');
        var app='/Applications/HONG AI CAGE Desktop.app',dataRoot=home+'/Library/Application Support/HONGAI-CAGE-Desktop';
        if(workspace===dataRoot||workspace.indexOf(dataRoot+'/')===0||dataRoot.indexOf(workspace+'/')===0||home.indexOf(workspace+'/')===0)throw new Error('WORKSPACE_OVERLAPS_PROTECTED_STORAGE');
        result.caseId=req.caseId;
        if(!exists(app)){
            result.phase='NEEDS_INSTALLER';result.nextAction='RUN_PKG_WITH_AVAILABLE_COMPUTER_USE_FOR_ORDINARY_UI_ONLY';
            if(action==='install'){command('/usr/bin/open',[pkg]);result.installerStarted=true;result.phase='WAITING_INSTALLER_UI';result.nextAction='COMPLETE_INSTALLER_UI_THEN_RERUN_CHECK_DO_NOT_DISABLE_GATEKEEPER';}
        }else{
            var info=$.NSDictionary.dictionaryWithContentsOfFile(app+'/Contents/Info.plist');
            if(!info||ObjC.unwrap(info.objectForKey('CFBundleIdentifier'))!=='com.hongai.cage.desktop.pilot')throw new Error('INSTALLED_APP_IDENTITY_MISMATCH');
            if(String(ObjC.unwrap(info.objectForKey('CFBundleVersion')))!=='9')throw new Error('INSTALLED_CAGE_VERSION_REVIEW_REQUIRED_NO_AUTOMATIC_REINSTALL');
            if(ObjC.unwrap($.NSURL.fileURLWithPath(app).URLByResolvingSymlinksInPath.path)!==app)throw new Error('INSTALLED_APP_LINK_PATH_REJECTED');
            command('/usr/bin/codesign',['--verify','--strict',app]);
            var configured=false;
            if(exists(dataRoot+'/enrolled-handoff.json')&&exists(dataRoot+'/workspace.json')){
                var saved=json(dataRoot+'/enrolled-handoff.json'),savedFolder=json(dataRoot+'/workspace.json');
                configured=saved.routeId===handoff.routeId&&saved.expectedEgressIp===handoff.expectedEgressIp&&saved.loopback.mixedPort===handoff.loopback.mixedPort&&savedFolder.workspace===workspace;
            }
            if(configured){result.phase='SAVED_CONFIGURATION_PRESENT';result.nextAction='OPEN_CAGE_ONCE_AND_VERIFY_UNAUTHENTICATED_SESSION_STATUS';}
            else if(validated.handoffRefreshRequired){result.phase='NEEDS_FRESH_HANDOFF';result.nextAction='REGENERATE_HANDOFF_USING_INSTALLED_GENERATOR_WITH_SAME_APPROVED_PORT_AND_IP_DO_NOT_REINSTALL';}
            else{result.phase='NEEDS_FIRST_CONFIGURATION';result.nextAction='USE_COMPUTER_USE_TO_IMPORT_HANDOFF_AND_SELECT_APPROVED_WORKSPACE_ONCE';}
            result.launcher=app;result.handoffFile=req.handoffFile;result.workspace=workspace;
        }
    }catch(e){result.phase='BLOCKED';result.error=String(e.message||e);result.nextAction='CLASSIFY_ONE_ERROR_DO_NOT_REPAIR_HOST_NETWORK_OR_RETRY_INSTALL_IN_A_LOOP';}
    return JSON.stringify(result,null,2);
}
