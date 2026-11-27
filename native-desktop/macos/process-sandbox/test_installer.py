"""Install, inspect, open native UI, and uninstall this package on disposable CI only."""
import json
import os
import pathlib
import plistlib
import subprocess
import tempfile
import datetime
import shutil
import socket
import time


def run(command, **kwargs):
    result=subprocess.run(command, check=False, capture_output=True, text=True, timeout=kwargs.pop('timeout',120), **kwargs)
    if result.returncode:
        print(result.stdout[-6000:],flush=True)
        print(result.stderr[-6000:],flush=True)
    result.check_returncode()
    return result


def main():
    if os.environ.get("GITHUB_ACTIONS") != "true" or os.environ.get("RUNNER_OS") != "macOS":
        raise RuntimeError("DISPOSABLE_GITHUB_CI_ONLY_DO_NOT_RUN_ON_CUSTOMER_HOST")
    base=pathlib.Path(__file__).resolve().parent
    package=base / "build/HONGAI-CAGE-Desktop-macOS-Universal-PILOT.pkg"
    application=pathlib.Path("/Applications/HONG AI CAGE Desktop.app")
    receipt="com.hongai.cage.desktop.pilot"
    if application.exists():
        raise RuntimeError("INSTALL_TARGET_ALREADY_EXISTS_DO_NOT_OVERWRITE")
    installed=False
    official=pathlib.Path('/Applications/Claude.app')
    own_data=pathlib.Path.home() / 'Library/Application Support/HONGAI-CAGE-Desktop'
    if official.exists() or own_data.exists():
        raise RuntimeError('DAILY_LAUNCH_TEST_TARGET_ALREADY_EXISTS')
    official_added=False
    user_official=pathlib.Path.home() / 'Applications/Claude.app'
    user_official_added=False
    if user_official.exists():
        raise RuntimeError('OFFICIAL_USER_APPLICATION_ALREADY_EXISTS')
    try:
        run(["sudo","/usr/sbin/installer","-pkg",str(package),"-target","/"])
        installed=True
        info=plistlib.loads((application / "Contents/Info.plist").read_bytes())
        if info["CFBundleIdentifier"] != receipt:
            raise RuntimeError("INSTALL_OWNERSHIP_MISMATCH")
        run(["/usr/bin/codesign","--verify","--strict",str(application)])
        run(["/usr/sbin/pkgutil","--pkg-info",receipt])
        executable=application / "Contents/MacOS/HongAICage"
        run(["/usr/bin/lipo",str(executable),"-verify_arch","arm64","x86_64"])
        environment=dict(os.environ)
        environment["HONGAI_UI_SNAPSHOT"]=str(base / "build/installed-native-ui.png")
        result=run([str(executable),"--ui-smoke-test"],env=environment)
        if "PASS installed native UI" not in result.stdout:
            raise RuntimeError("NATIVE_UI_SMOKE_NOT_CONFIRMED")
        print(result.stdout.strip(),flush=True)
        run(['sudo','/usr/bin/ditto',str(base / 'build/official-fixture/Claude.app'),str(official)])
        official_added=True
        with tempfile.TemporaryDirectory(prefix='hongai-daily-launch-') as project,socket.socket() as endpoint:
            endpoint.bind(('127.0.0.1',0))
            own_data.mkdir(parents=True,mode=0o700)
            (own_data / 'enrolled-handoff.json').write_text(json.dumps({'version':1,'tool':'clash','loopback':{'protocol':'http','host':'127.0.0.1','mixedPort':endpoint.getsockname()[1]},'expectedEgressIp':'8.8.8.8','routeId':'0123456789abcdef01234567','generatedAt':datetime.datetime.now(datetime.timezone.utc).isoformat().replace('+00:00','Z')}))
            (own_data / 'workspace.json').write_text(json.dumps({'workspace':project}))
            daily=run([str(executable),'--daily-launch-smoke-test'])
            if 'PASS daily automatic launch' not in daily.stdout:
                raise RuntimeError('DAILY_SAVED_CONFIGURATION_LAUNCH_NOT_ACCEPTED')
            print(daily.stdout.strip(),flush=True)
            time.sleep(2)
            cached=run([str(executable),'--daily-launch-smoke-test'])
            if 'PASS daily automatic launch' not in cached.stdout:
                raise RuntimeError('VERIFIED_SNAPSHOT_REUSE_FAILED')
            print('PASS second daily launch reuses the signed private official snapshot',flush=True)
            # Exercise the actual product downloader and user-directory install,
            # rather than assuming a preinstalled official app on every client.
            run(['sudo','/bin/rm','-rf',str(official)])
            official_added=False
            user_official_added=True
            installed_official=run([str(executable),'--official-install-smoke-test'],timeout=240)
            if 'PASS official first-install' not in installed_official.stdout:
                raise RuntimeError('OFFICIAL_FIRST_INSTALL_NOT_CONFIRMED')
            print(installed_official.stdout.strip(),flush=True)
            user_daily=run([str(executable),'--daily-launch-smoke-test'])
            if 'PASS daily automatic launch' not in user_daily.stdout:
                raise RuntimeError('USER_APPLICATION_DAILY_START_FAILED')
            print('PASS official user-directory installation launches in the same process boundary',flush=True)
        print(json.dumps({"installer":"PASS","universal":"PASS","signature":"AD_HOC_VALID","nativeUI":"PASS",
                          "loginAttempted":False,"hostNetworkSettingsChanged":False,"customerAccepted":False}),flush=True)
    finally:
        if user_official_added and user_official.exists() and not user_official.is_symlink():
            info=plistlib.loads((user_official / 'Contents/Info.plist').read_bytes())
            if info.get('CFBundleIdentifier') == 'com.anthropic.claudefordesktop':
                shutil.rmtree(user_official)
        log=own_data / 'temp/official-daily-start.log'
        if log.exists():
            print('OFFICIAL_DAILY_START_DIAGNOSTIC',log.read_text(errors='replace')[-8000:],flush=True)
        if official_added:
            info=plistlib.loads((official / 'Contents/Info.plist').read_bytes())
            if info.get('CFBundleIdentifier') == 'com.anthropic.claudefordesktop' and not official.is_symlink():
                run(['sudo','/bin/rm','-rf',str(official)])
        if (official_added or user_official_added) and own_data.exists() and not own_data.is_symlink():
            shutil.rmtree(own_data)
        if installed and application.exists():
            info=plistlib.loads((application / "Contents/Info.plist").read_bytes())
            if info.get("CFBundleIdentifier") == receipt and not application.is_symlink():
                # This exact fresh CI installation is the sole deletion target.
                run(["sudo","/bin/rm","-rf",str(application)])
                run(["sudo","/usr/sbin/pkgutil","--forget",receipt])
                print("PASS exact test installation and receipt removed",flush=True)


if __name__ == "__main__":
    main()
