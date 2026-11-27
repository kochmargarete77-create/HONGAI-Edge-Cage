"""Read-only coordinator checks on disposable CI. Does not install or accept CAGE."""
import datetime
import hashlib
import json
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile

def main():
    if os.environ.get('GITHUB_ACTIONS') != 'true':
        raise RuntimeError('DISPOSABLE_CI_ONLY')
    root=pathlib.Path(__file__).resolve().parent
    windows=sys.platform=='win32'
    name='HONGAI-CAGE-Desktop-0.3.0-pilot.4-Windows-x64-Setup.exe' if windows else 'HONGAI-CAGE-Desktop-0.3.0-build9-macOS-Universal.pkg'
    source_name=name if windows else 'HONGAI-CAGE-Desktop-macOS-Universal-PILOT.pkg'
    source=list(pathlib.Path(sys.argv[1]).rglob(source_name))
    assert len(source)==1, source
    setup=root/name
    shutil.copyfile(source[0],setup)
    try:
        with tempfile.TemporaryDirectory(prefix='hongai-coordinator-fixture-',dir=os.environ['RUNNER_TEMP']) as folder:
            folder=pathlib.Path(folder)
            workspace=folder/'Project';workspace.mkdir()
            suite=json.loads((root/'test-cases.json').read_text())
            report=suite['report'];handoff=suite['handoff']
            handoff['generatedAt']=datetime.datetime.now(datetime.timezone.utc).isoformat().replace('+00:00','Z')
            report_file=folder/'fixture-report.json';handoff_file=folder/'clash-handoff.json';request_file=folder/'deployment-request.json'
            report_file.write_text(json.dumps(report));handoff_file.write_text(json.dumps(handoff))
            request=dict(suite['request'],environmentReport=str(report_file),handoffFile=str(handoff_file),workspace=str(workspace))
            request_file.write_text(json.dumps(request))
            if windows:
                ps=str(pathlib.Path(os.environ['SystemRoot'])/'System32/WindowsPowerShell/v1.0/powershell.exe')
                args=[ps,'-NoLogo','-NoProfile','-ExecutionPolicy','Bypass','-File',str(root/'Start-Deployment-Windows.ps1'),'-RequestFile',str(request_file)]
            else:
                args=['bash',str(root/'Start-Deployment-Mac.command'),str(request_file),'check']
            def check(expected):
                result=subprocess.run(args,text=True,capture_output=True,timeout=45)
                try: r=json.loads(result.stdout)
                except Exception: print(result.stdout,result.stderr);raise
                assert r['phase']==expected,r
                assert not any(r[k] for k in ('installerStarted','fullDesktopAccepted','networkAcceptedByThisCheck','hostNetworkSettingsChanged','loginStateChanged'))
                assert r['writesPerformed']==[]
                return r
            r=check('NEEDS_INSTALLER')
            assert r['caseId']==request['caseId']
            report['case_id']='WRONG-CASE';report_file.write_text(json.dumps(report));r=check('BLOCKED')
            assert 'NEED_MATCHING_FINAL_PREDEPLOY_REPORT' in r['error'],r
            report['case_id']=request['caseId'];report_file.write_text(json.dumps(report))
            before=setup.read_bytes()
            setup.write_bytes(before+b'TAMPER_FIXTURE')
            r=check('BLOCKED');assert 'SETUP_HASH_MISMATCH' in r['error'],r
            setup.write_bytes(before)
            request_file.write_text('MALFORMED_FIXTURE_SECRET_NOT_FOR_OUTPUT')
            r=check('BLOCKED')
            assert 'LOCAL_JSON_READ_OR_PARSE_FAILED' in r['error'],r
            assert 'MALFORMED_FIXTURE_SECRET_NOT_FOR_OUTPUT' not in json.dumps(r)
            print(json.dumps({'scope':'READ_ONLY_COORDINATOR_NOT_INSTALLATION','actualReferencePackageHash':hashlib.sha256(before).hexdigest(),'validRequest':'NEEDS_INSTALLER','wrongCase':'BLOCKED','tamperedInstaller':'BLOCKED','installerLaunched':False,'hostNetworkSettingsChanged':False,'customerAccepted':False}))
    finally:
        setup.unlink(missing_ok=True)

if __name__=='__main__': main()
