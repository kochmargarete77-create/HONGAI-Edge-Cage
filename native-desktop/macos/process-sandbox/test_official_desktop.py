"""Bounded official-app offline smoke test on disposable macOS CI hosts only."""
import hashlib
import json
import os
import pathlib
import plistlib
import re
import shutil
import signal
import socket
import subprocess
import tempfile
import time
import urllib.request


def run(command, **kwargs):
    return subprocess.run(command, check=True, capture_output=True, text=True, timeout=90, **kwargs)


def main():
    with tempfile.TemporaryDirectory(prefix="hongai-official-desktop-") as temp:
        root = pathlib.Path(temp).resolve()
        image = root / "Claude.zip"
        # Official CDN release, SHA independently pinned from Homebrew's published cask.
        url = "https://downloads.claude.ai/releases/darwin/universal/7.37095.0/Claude-bc368c812ec26d3a5740519cc4d5cb69bbe43025.zip"
        expected_sha = "800806556cacece6bdacbb9f3aef1849a9ed8d6fc2ee0eb2ed881a098d094eab"
        with urllib.request.urlopen(url, timeout=60) as response, image.open("wb") as output:
            if not response.url.startswith("https://"):
                raise RuntimeError("OFFICIAL_DOWNLOAD_REQUIRES_TLS")
            shutil.copyfileobj(response, output, 1024 * 1024)
        with image.open("rb") as source:
            actual_sha = hashlib.file_digest(source, "sha256").hexdigest()
        if actual_sha != expected_sha:
            raise RuntimeError("OFFICIAL_DOWNLOAD_HASH_MISMATCH")
        print("OFFICIAL_ZIP_SHA256", actual_sha, flush=True)
        mount = root / "mounted"
        mount.mkdir()
        mounted = False
        process = None
        # Bound but deliberately not listening: this test never contacts Claude or logs in.
        endpoint = socket.socket()
        endpoint.bind(("127.0.0.1", 0))
        port = endpoint.getsockname()[1]
        try:
            run(["/usr/bin/ditto", "-x", "-k", str(image), str(mount)])
            source = mount / "Claude.app"
            app = root / "Claude.app"
            run(["/usr/bin/ditto", str(source), str(app)])
            run(["/usr/bin/codesign", "--verify", "--deep", "--strict", "--verbose=2", str(app)])
            requirement = 'anchor apple generic and identifier "com.anthropic.claudefordesktop"'
            run(["/usr/bin/codesign", "--verify", "-R=" + requirement, str(app)])
            details = run(["/usr/bin/codesign", "-d", "--verbose=4", str(app)]).stderr
            if not re.search(r"Authority=Developer ID Application: Anthropic", details):
                raise RuntimeError("EXPECTED_ANTHROPIC_SIGNING_AUTHORITY")
            print("OFFICIAL_SIGNING", " | ".join(x for x in details.splitlines() if x.startswith(("Identifier=", "Authority=", "TeamIdentifier=", "CDHash="))), flush=True)
            info = plistlib.loads((app / "Contents/Info.plist").read_bytes())
            executable = app / "Contents/MacOS" / info["CFBundleExecutable"]
            workspace = root / "workspace"
            workspace.mkdir()
            profile_data = workspace / "profile"
            profile_data.mkdir()
            profile = root / "official.sb"
            home = pathlib.Path.home()
            denied = [home / "Library/Application Support/Claude", home / ".claude", home / ".config/clash", home / ".config/mihomo"]
            if any(any(c in str(p) for c in ('"', "\\", "\n", "\r")) for p in [workspace, *denied]):
                raise RuntimeError("UNSAFE_PROFILE_PATH")
            profile.write_text(
                '(version 1)\n(allow default)\n(deny network*)\n'
                f'(allow network-outbound (remote tcp "localhost:{port}"))\n'
                '(deny appleevent-send)\n'
                '(deny mach-lookup (global-name "com.apple.nsurlsessiond") (global-name "com.apple.lsd.open"))\n'
                + "".join(f'(deny file-read* file-write* (subpath "{p}"))\n' for p in denied)
            )
            environment = {"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "HOME": str(workspace), "TMPDIR": str(workspace),
                           "HTTP_PROXY": f"http://127.0.0.1:{port}", "HTTPS_PROXY": f"http://127.0.0.1:{port}", "NO_PROXY": ""}
            log = (root / "official.log").open("wb")
            command = ["/usr/bin/sandbox-exec", "-f", str(profile), str(executable),
                       f"--user-data-dir={profile_data}", f"--proxy-server=http://127.0.0.1:{port}",
                       "--proxy-bypass-list=<-loopback>", "--disable-quic", "--no-first-run"]
            process = subprocess.Popen(command, env=environment, cwd=workspace, stdout=log, stderr=subprocess.STDOUT, start_new_session=True)
            time.sleep(8)
            result = process.poll()
            rows = subprocess.run(["/bin/ps", "-axo", "pid=,pgid=,comm="], capture_output=True, text=True, timeout=10).stdout
            owned = [line.strip() for line in rows.splitlines() if len(line.split()) > 2 and line.split()[1] == str(process.pid)]
            print("OFFICIAL_PROCESS_GROUP_COUNT", len(owned), flush=True)
            if result is not None:
                log.flush()
                print((root / "official.log").read_text(errors="replace")[-10000:], flush=True)
                raise RuntimeError(f"OFFICIAL_DESKTOP_EXITED code={result}")
            print(json.dumps({"officialOfflineStart": "PASS", "processCount": len(owned), "loginAttempted": False,
                              "hostNetworkSettingsChanged": False, "customerAccepted": False}), flush=True)
        finally:
            if process is not None:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                process.wait(timeout=10)
            endpoint.close()
            if mounted:
                subprocess.run(["/usr/bin/hdiutil", "detach", str(mount)], check=False, timeout=30)


if __name__ == "__main__":
    main()
