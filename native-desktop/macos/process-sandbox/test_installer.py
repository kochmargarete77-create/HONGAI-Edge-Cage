"""Install, inspect, open native UI, and uninstall this package on disposable CI only."""
import json
import os
import pathlib
import plistlib
import subprocess
import tempfile


def run(command, **kwargs):
    return subprocess.run(command, check=True, capture_output=True, text=True, timeout=120, **kwargs)


def main():
    base=pathlib.Path(__file__).resolve().parent
    package=base / "build/HONGAI-CAGE-Desktop-macOS-Universal-PILOT.pkg"
    application=pathlib.Path("/Applications/HONG AI CAGE Desktop.app")
    receipt="com.hongai.cage.desktop.pilot"
    if application.exists():
        raise RuntimeError("INSTALL_TARGET_ALREADY_EXISTS_DO_NOT_OVERWRITE")
    installed=False
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
        print(json.dumps({"installer":"PASS","universal":"PASS","signature":"AD_HOC_VALID","nativeUI":"PASS",
                          "loginAttempted":False,"hostNetworkSettingsChanged":False,"customerAccepted":False}),flush=True)
    finally:
        if installed and application.exists():
            info=plistlib.loads((application / "Contents/Info.plist").read_bytes())
            if info.get("CFBundleIdentifier") == receipt and not application.is_symlink():
                # This exact fresh CI installation is the sole deletion target.
                run(["sudo","/bin/rm","-rf",str(application)])
                run(["sudo","/usr/sbin/pkgutil","--forget",receipt])
                print("PASS exact test installation and receipt removed",flush=True)


if __name__ == "__main__":
    main()
