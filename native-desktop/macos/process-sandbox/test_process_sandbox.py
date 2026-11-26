"""Development-only inheritable process-boundary test; never edits host network settings."""
import json
import errno
import os
import pathlib
import socket
import subprocess
import sys
import tempfile


def worker(args):
    mode = args[0]
    if mode == "nested":
        return subprocess.run([sys.executable, __file__, "--worker", *args[1:]], check=False).returncode
    try:
        if mode == "connect":
            with socket.create_connection((args[1], int(args[2])), timeout=1.5):
                return 0
        if mode == "udp":
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
                client.sendto(b"own fixture", (args[1], int(args[2])))
                return 0
        if mode == "read":
            pathlib.Path(args[1]).read_text()
            return 0
        if mode == "write":
            pathlib.Path(args[1]).write_text("owned fixture")
            return 0
    except OSError as error:
        return 13 if error.errno in (errno.EPERM, errno.EACCES) else 20
    return 64


def main():
    sandbox = pathlib.Path("/usr/bin/sandbox-exec")
    if not sandbox.exists():
        raise RuntimeError("PROCESS_SANDBOX_UNAVAILABLE; do not enable this backend")
    with tempfile.TemporaryDirectory(prefix="hongai-process-boundary-") as temp:
        root = pathlib.Path(temp).resolve()
        protected = root / "ungranted"
        protected.mkdir()
        secret = protected / "fixture.txt"
        secret.write_text("owned fixture, not user data")
        profile = root / "boundary.sb"
        first = socket.socket()
        second = socket.socket()
        ipv6 = socket.socket(socket.AF_INET6)
        try:
            first.bind(("127.0.0.1", 0)); first.listen(32)
            second.bind(("127.0.0.1", 0)); second.listen(32)
            ipv6.bind(("::1", 0)); ipv6.listen(32)
            port = first.getsockname()[1]
            other = second.getsockname()[1]
            six = ipv6.getsockname()[1]
            # Runtime values are numeric or a generated local path; reject profile syntax injection.
            if any(char in str(protected) for char in ['"', "\\", "\n", "\r"]):
                raise RuntimeError("UNSAFE_FIXTURE_PATH")
            profile.write_text(
                '(version 1)\n(allow default)\n(deny network*)\n'
                f'(allow network-outbound (remote tcp "localhost:{port}"))\n'
                f'(deny file-read* file-write* (subpath "{protected}"))\n'
            )
            checks = []

            def check(label, arguments, expected, restricted=True):
                command = [sys.executable, str(pathlib.Path(__file__).resolve()), "--worker", *arguments]
                if restricted:
                    command = [str(sandbox), "-f", str(profile), *command]
                result = subprocess.run(command, timeout=12, check=False, capture_output=True, text=True)
                if result.returncode != expected:
                    raise RuntimeError(f"{label}: expected={expected} actual={result.returncode} stderr={result.stderr[-1200:]}")
                checks.append(label)
                print("PASS", label, flush=True)

            check("baseline selected port", ["connect", "127.0.0.1", str(port)], 0, False)
            check("baseline alternate port", ["connect", "127.0.0.1", str(other)], 0, False)
            check("baseline IPv6", ["connect", "::1", str(six)], 0, False)
            check("selected proxy permitted", ["connect", "127.0.0.1", str(port)], 0)
            check("alternate localhost port denied", ["connect", "127.0.0.1", str(other)], 13)
            check("IPv6 denied", ["connect", "::1", str(six)], 13)
            check("UDP denied even on selected port", ["udp", "127.0.0.1", str(port)], 13)
            check("nested MCP-like child stays restricted", ["nested", "connect", "127.0.0.1", str(other)], 13)
            check("nested child can use selected proxy", ["nested", "connect", "127.0.0.1", str(port)], 0)
            check("ungranted fixture denied", ["read", str(secret)], 13)
            check("approved workspace write allowed", ["write", str(root / "workspace-result.txt")], 0)
            first.close()
            check("proxy stopped stays unavailable", ["connect", "127.0.0.1", str(port)], 20)
            check("proxy stopped never opens alternate port", ["connect", "127.0.0.1", str(other)], 13)
            report = {"passed": len(checks), "customerAccepted": False,
                      "scope": "own child fixtures only; not official desktop acceptance",
                      "backend": "sandbox-exec-development-only", "networkSettingsChanged": False}
            print(json.dumps(report), flush=True)
        finally:
            first.close(); second.close(); ipv6.close()


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--worker":
        sys.exit(worker(sys.argv[2:]))
    main()

