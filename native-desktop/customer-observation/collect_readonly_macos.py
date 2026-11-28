#!/usr/bin/env python3
"""Bounded, passive macOS observation. No installer, network requests or elevation."""

import argparse
import datetime
import ipaddress
import json
import math
import os
from pathlib import Path, PurePosixPath, PureWindowsPath
import re
import secrets
import selectors
import subprocess
import sys
import time
from dataclasses import dataclass


MAX_DURATION_SECONDS = 1800
MAX_SAMPLES = 180
MAX_OUTPUT_BYTES = 5 * 1024 * 1024
SUMMARY_RESERVE = 64 * 1024
SCHEMA = "hongai.passive-observation.v1"
ROLES = ("claude", "cowork", "mihomo", "clash", "todesk")
SOURCES = ("READ_ONLY_LOCAL_COMMAND", "SYNTHETIC_FIXED_FIXTURE")
TCP_STATES = {"CLOSED", "LISTEN", "SYN_SENT", "SYN_RECV", "SYN_RCVD", "ESTABLISHED", "CLOSE_WAIT", "FIN_WAIT_1", "CLOSING", "LAST_ACK", "FIN_WAIT_2", "TIME_WAIT", "BOUND", "IDLE"}
MAC_SYSTEM_TREES = ("/System", "/Library", "/Applications", "/bin", "/sbin", "/usr", "/etc", "/var", "/private", "/tmp", "/dev", "/cores", "/Network")


class SafeError(Exception):
    pass


def utc_now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def plan(duration, interval):
    if not isinstance(duration, int) or isinstance(duration, bool) or not 10 <= duration <= MAX_DURATION_SECONDS:
        raise SafeError("DURATION_MUST_BE_10_TO_1800_SECONDS")
    if not isinstance(interval, int) or isinstance(interval, bool) or not 10 <= interval <= 300:
        raise SafeError("INTERVAL_MUST_BE_10_TO_300_SECONDS")
    return min(MAX_SAMPLES, math.ceil(duration / interval))


def blocked_macos_path(path):
    path = PurePosixPath(str(path))
    return path == PurePosixPath("/") or path in (PurePosixPath("/Users"), PurePosixPath("/Volumes")) or any(path == PurePosixPath(tree) or PurePosixPath(tree) in path.parents for tree in MAC_SYSTEM_TREES)


def validate_output_parent(raw):
    if not isinstance(raw, str) or "\0" in raw:
        raise SafeError("APPROVED_ABSOLUTE_OUTPUT_PARENT_REQUIRED")
    if PureWindowsPath(raw).drive.upper() == "C:":
        raise SafeError("C_DRIVE_OUTPUT_REJECTED")
    candidate = Path(raw)
    if not candidate.is_absolute() or ".." in candidate.parts:
        raise SafeError("APPROVED_ABSOLUTE_OUTPUT_PARENT_REQUIRED")
    if sys.platform == "darwin" and blocked_macos_path(candidate):
        raise SafeError("SYSTEM_OUTPUT_PARENT_REJECTED")
    try:
        resolved = candidate.resolve(strict=True)
        if candidate != resolved or not resolved.is_dir():
            raise SafeError("SYMBOLIC_OR_ALIAS_OUTPUT_PARENT_REJECTED")
        for component in [candidate] + list(candidate.parents):
            if component.is_symlink():
                raise SafeError("SYMBOLIC_OR_ALIAS_OUTPUT_PARENT_REJECTED")
        if sys.platform == "darwin":
            home = Path.home().resolve(strict=True)
            if resolved == home or resolved == home / "Library" or home / "Library" in resolved.parents or resolved == home / "Applications" or home / "Applications" in resolved.parents:
                raise SafeError("DEDICATED_PROJECT_OUTPUT_PARENT_REQUIRED")
    except SafeError:
        raise
    except OSError:
        raise SafeError("APPROVED_OUTPUT_PARENT_UNAVAILABLE") from None
    return resolved


def role_for_comm(command):
    name = command.replace("\\", "/").rsplit("/", 1)[-1].lower()
    if re.fullmatch(r"cowork(?:[-_ ](?:svc|service|helper))?", name):
        return "cowork"
    if re.fullmatch(r"claude(?: helper(?: \([^\r\n]{1,40}\))?)?", name) or "/claude.app/contents/" in command.lower():
        return "claude"
    if re.fullmatch(r"(?:verge-)?mihomo(?:[-_][a-z0-9]+)?", name):
        return "mihomo"
    if name in {"clash", "clashx", "clashx pro", "clash verge", "clash-verge", "clash verge rev", "flclash"}:
        return "clash"
    if re.fullmatch(r"(?:todesk(?:[_ -](?:service|desktop|helper|session))?|com\.todesk\.[a-z0-9_.-]+)", name):
        return "todesk"
    return None


@dataclass
class ProcessObservation:
    roles: dict
    claude_pids: tuple
    valid_rows: int
    invalid_rows: int

    def public_summary(self, source, command_status="OBSERVED", reason=None):
        if source not in SOURCES:
            raise SafeError("EXPLICIT_OBSERVATION_SOURCE_REQUIRED")
        status = "NOT_OBSERVED" if not self.valid_rows else "PARTIAL" if self.invalid_rows or command_status == "PARTIAL" else "OBSERVED" if any(item["processCount"] for item in self.roles.values()) else "EMPTY"
        code = reason or ("PROCESS_ROWS_NOT_PARSED" if not self.valid_rows else "SOME_PROCESS_ROWS_NOT_PARSED" if self.invalid_rows else "VISIBLE_ROLE_AGGREGATES")
        return {"status": status, "code": code, "source": source,
                "scope": "NAME_HINT_ONLY_NOT_SIGNATURE_VERIFIED_OR_ALL_DESCENDANTS", "roles": self.roles,
                "unparsedRowCount": self.invalid_rows}


def parse_ps_output(text):
    """Pure parser. PIDs are returned only for the caller's in-memory lsof filter."""
    roles = {role: {"processCount": 0, "cpuPercent": 0.0, "workingSetBytesTotal": 0,
                    "cpuStatus": "EMPTY", "memoryStatus": "EMPTY"} for role in ROLES}
    pids, seen, valid, invalid = [], set(), 0, 0
    for line in text.splitlines():
        if not line.strip() or re.match(r"^\s*PID\s+PPID\s+", line):
            continue
        match = re.match(r"^\s*([0-9]{1,10})\s+([0-9]{1,10})\s+(.+?)\s+([0-9]+(?:\.[0-9]+)?)\s+([0-9]+)\s*$", line)
        if not match:
            invalid += 1
            continue
        pid, parent = int(match[1]), int(match[2])
        cpu, rss = float(match[4]), int(match[5])
        if pid < 1 or parent < 0 or pid in seen or not math.isfinite(cpu) or cpu > 100000 or rss > 2 ** 48:
            invalid += 1
            continue
        seen.add(pid)
        valid += 1
        role = role_for_comm(match[3])
        if role:
            item = roles[role]
            item["processCount"] += 1
            item["cpuPercent"] += cpu
            item["workingSetBytesTotal"] += rss * 1024
            item["cpuStatus"] = item["memoryStatus"] = "OBSERVED"
            if role == "claude":
                pids.append(pid)
    for item in roles.values():
        item["cpuPercent"] = round(item["cpuPercent"], 3)
    return ProcessObservation(roles, tuple(pids), valid, invalid)


def remote_class(endpoint):
    """Classify numeric remote endpoint without DNS or returning its address."""
    if not isinstance(endpoint, str) or ":" not in endpoint:
        return "other", "other"
    address, port = endpoint.rsplit(":", 1)
    port_class = port if port in ("443", "80") else "other"
    address = address.strip("[]").split("%", 1)[0]
    try:
        ip = ipaddress.ip_address(address)
    except ValueError:
        return "other", port_class
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        ip = ip.ipv4_mapped
    if ip.is_loopback:
        return "loopback", port_class
    if ip.is_link_local:
        return "linklocal", port_class
    private = ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16") if ip.version == 4 else ("fc00::/7",)
    if any(ip in ipaddress.ip_network(network) for network in private):
        return "private", port_class
    special = ("100.64.0.0/10", "192.0.2.0/24", "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24") if ip.version == 4 else ("2001:db8::/32", "2001:2::/48")
    if any(ip in ipaddress.ip_network(network) for network in special) or ip.is_reserved:
        return "reserved_or_benchmark", port_class
    if ip.is_global and not (ip.is_multicast or ip.is_unspecified or ip.is_reserved):
        return "public", port_class
    return "other", port_class


def parse_lsof_output(text, allowed_pids, source, command_status="OBSERVED", reason=None):
    """Pure parser; only fixed-category counters leave this function."""
    if source not in SOURCES:
        raise SafeError("EXPLICIT_OBSERVATION_SOURCE_REQUIRED")
    allowed = set(allowed_pids)
    groups = {}
    current_pid, record = None, None

    def flush():
        if not record or current_pid not in allowed:
            return
        family = record.get("family")
        if family not in ("IPv4", "IPv6"):
            return
        state = record.get("state")
        state = state if state in TCP_STATES else "other"
        name = record.get("name", "")
        remote = name.split("->", 1)[1] if "->" in name else ""
        category, port = remote_class(remote)
        key = (state, family, port, category)
        groups[key] = groups.get(key, 0) + 1

    for line in text.splitlines():
        if not line:
            continue
        prefix, value = line[0], line[1:]
        if prefix == "p":
            flush()
            current_pid = int(value) if re.fullmatch(r"[0-9]{1,10}", value) else None
            record = None
        elif prefix == "f":
            flush()
            record = {}
        elif record is not None:
            if prefix == "t":
                record["family"] = value
            elif prefix == "n":
                record["name"] = value
            elif prefix == "T" and value.startswith("ST="):
                record["state"] = value[3:]
    flush()
    counts = [{"state": state, "ipVersion": family, "remotePortClass": port,
               "remoteAddressClass": category, "count": count}
              for (state, family, port, category), count in sorted(groups.items())]
    return {"status": "PARTIAL" if command_status == "PARTIAL" else "OBSERVED" if counts else "EMPTY", "code": reason or "VISIBLE_CLAUDE_TCP_CATEGORIES", "source": source,
            "scope": "VISIBLE_CLAUDE_TCP_SOCKETS_ONLY_NOT_REQUESTS_OR_PACKETS", "connectionsCount": sum(item["count"] for item in counts), "categories": counts}


def parse_os_metadata(sw_vers, uname):
    version = re.search(r"^ProductVersion:\s*([0-9]{1,3}(?:\.[0-9]{1,3}){1,2})\s*$", sw_vers, re.MULTILINE)
    match = re.fullmatch(r"Darwin\s+([0-9]{1,3}(?:\.[0-9]{1,3}){1,2})\s+(arm64|x86_64)\s*", uname)
    return {"status": "OBSERVED" if version and match else "PARTIAL" if version or match else "NOT_OBSERVED",
            "platform": "darwin", "productVersion": version[1] if version else "NOT_OBSERVED",
            "kernelRelease": match[1] if match else "NOT_OBSERVED",
            "architecture": match[2] if match else "NOT_OBSERVED"}


def common_record(session_id, utc_iso, record_type):
    if not isinstance(session_id, str) or not re.fullmatch(r"[a-f0-9]{32}", session_id):
        raise SafeError("SESSION_ID_INVALID")
    if not isinstance(utc_iso, str) or not re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{3}Z", utc_iso):
        raise SafeError("UTC_TIMESTAMP_REQUIRED")
    return {"schema": SCHEMA, "recordType": record_type, "sessionId": session_id, "utcISO": utc_iso}


def make_header(session_id, utc_iso, os_metadata, duration, interval, *, source):
    """Pure record constructor; fixtures must explicitly select synthetic source."""
    if source not in SOURCES:
        raise SafeError("EXPLICIT_OBSERVATION_SOURCE_REQUIRED")
    plan(duration, interval)
    return {**common_record(session_id, utc_iso, "header"), "source": source,
            "synthetic": source == "SYNTHETIC_FIXED_FIXTURE",
            "collector": {"platform": "darwin", "version": "0.1.0", "mode": "PASSIVE_READ_ONLY", "roleClassification": "NAME_HINT_NOT_SIGNATURE_VERIFICATION"},
            "os": os_metadata, "limits": {"durationSeconds": duration, "intervalSeconds": interval, "maxSamples": MAX_SAMPLES, "maxOutputBytes": MAX_OUTPUT_BYTES}}


def make_sample(session_id, utc_iso, sample_index, elapsed_seconds, process_summary, tcp_summary):
    return {**common_record(session_id, utc_iso, "sample"), "sampleIndex": sample_index,
            "elapsedSeconds": round(elapsed_seconds, 3), "processes": process_summary, "tcp": tcp_summary}


def make_footer(session_id, utc_iso, samples_written, elapsed_seconds, completion_code):
    return {**common_record(session_id, utc_iso, "footer"),
            "elapsedSeconds": round(elapsed_seconds, 3), "samplesWritten": samples_written, "completionCode": completion_code,
            "rawProcessMetadataExported": False, "rawNetworkAddressesExported": False,
            "hostNetworkModified": False, "officialClientModified": False, "accountStateReadOrModified": False,
            "scope": "PASSIVE_VISIBLE_ROLE_AND_TCP_CATEGORY_COUNTS_NOT_ALL_TRAFFIC_OR_ACCOUNT_CAUSALITY"}


def allowed_command(argv):
    if argv in (["/usr/bin/sw_vers"], ["/usr/bin/uname", "-s", "-r", "-m"], ["/bin/ps", "-axo", "pid,ppid,comm,%cpu,rss"]):
        return True
    return (len(argv) == 8 and argv[:4] == ["/usr/sbin/lsof", "-nP", "-a", "-p"] and
            bool(re.fullmatch(r"[0-9]{1,10}(?:,[0-9]{1,10}){0,127}", argv[4])) and
            all(0 < int(pid) < 2 ** 31 for pid in argv[4].split(",")) and
            argv[5:] == ["-iTCP", "-FpfntT", "-l"])


@dataclass
class CommandResult:
    status: str
    reason: str
    stdout: str = ""
    returncode: int = -1


def run_bounded(argv, timeout_seconds=3.0, stdout_limit=512 * 1024):
    if not allowed_command(argv):
        raise SafeError("COMMAND_NOT_ALLOWLISTED")
    if timeout_seconds <= 0:
        return CommandResult("NOT_OBSERVED", "OBSERVATION_WINDOW_ENDED")
    process = None
    selector = selectors.DefaultSelector()
    try:
        process = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                   shell=False, env={"LC_ALL": "C", "LANG": "C", "TZ": "UTC"})
        for stream, kind in ((process.stdout, "stdout"), (process.stderr, "stderr")):
            os.set_blocking(stream.fileno(), False)
            selector.register(stream, selectors.EVENT_READ, kind)
        deadline, output, error_bytes = time.monotonic() + min(timeout_seconds, 5.0), bytearray(), 0
        reason = None
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                reason = "COMMAND_TIMEOUT"
                break
            for key, _ in selector.select(min(remaining, 0.2)):
                try:
                    chunk = os.read(key.fd, 16384)
                except BlockingIOError:
                    continue
                if not chunk:
                    selector.unregister(key.fileobj)
                elif key.data == "stdout":
                    if len(output) + len(chunk) > stdout_limit:
                        reason = "COMMAND_OUTPUT_LIMIT"
                        break
                    output.extend(chunk)
                else:
                    error_bytes += len(chunk)
                    if error_bytes > 8192:
                        reason = "COMMAND_ERROR_OUTPUT_LIMIT"
                        break
            if reason:
                break
        if reason:
            process.kill()
            return CommandResult("NOT_OBSERVED", reason)
        try:
            code = process.wait(timeout=max(0.01, deadline - time.monotonic()))
        except subprocess.TimeoutExpired:
            process.kill()
            return CommandResult("NOT_OBSERVED", "COMMAND_TIMEOUT")
        if code not in (0, 1) or (code == 1 and argv[0] != "/usr/sbin/lsof"):
            return CommandResult("NOT_OBSERVED", "COMMAND_NOT_SUCCESSFUL")
        text = output.decode("utf-8", errors="replace")
        if code == 1 and not text.strip():
            return CommandResult("NOT_OBSERVED", "NO_VISIBLE_TCP_RECORDS_OR_PERMISSION_UNAVAILABLE")
        partial = code == 1 or error_bytes > 0
        return CommandResult("PARTIAL" if partial else "OBSERVED", "COMMAND_REPORTED_PARTIAL_VISIBILITY" if partial else "BOUNDED_LOCAL_COMMAND_FINISHED", text, code)
    except OSError:
        return CommandResult("NOT_OBSERVED", "COMMAND_UNAVAILABLE_OR_NOT_PERMITTED")
    finally:
        selector.close()
        if process:
            if process.poll() is None:
                process.kill()
            try:
                process.wait(timeout=1)
            except (OSError, subprocess.TimeoutExpired):
                pass
            for stream in (process.stdout, process.stderr):
                if stream:
                    stream.close()


class ExclusiveSession:
    """Anchored, new-only session; never edits an existing parent or output."""
    def __init__(self, parent):
        before = parent.stat()
        self.parent_fd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        self.session_fd = None
        self.stream = None
        self.bytes_written = 0
        try:
            opened = os.fstat(self.parent_fd)
            if (before.st_dev, before.st_ino) != (opened.st_dev, opened.st_ino):
                raise SafeError("OUTPUT_PARENT_IDENTITY_CHANGED")
            self.session_id = secrets.token_hex(16)
            self.name = "session-" + self.session_id
            os.mkdir(self.name, 0o700, dir_fd=self.parent_fd)
            info = os.stat(self.name, dir_fd=self.parent_fd, follow_symlinks=False)
            self.session_fd = os.open(self.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=self.parent_fd)
            opened = os.fstat(self.session_fd)
            if (info.st_dev, info.st_ino) != (opened.st_dev, opened.st_ino) or opened.st_uid != os.getuid():
                raise SafeError("SESSION_DIRECTORY_IDENTITY_CHANGED")
            descriptor = os.open("observation.ndjson", os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=self.session_fd)
            self.stream = os.fdopen(descriptor, "wb")
        except Exception:
            self.close()
            raise

    def sample(self, value, reserve=SUMMARY_RESERVE):
        encoded = (json.dumps(value, ensure_ascii=True, separators=(",", ":")) + "\n").encode("ascii")
        if self.bytes_written + len(encoded) > MAX_OUTPUT_BYTES - reserve:
            return False
        self.stream.write(encoded)
        self.stream.flush()
        self.bytes_written += len(encoded)
        return True

    def summary(self, value):
        encoded = (json.dumps(value, ensure_ascii=True, indent=2) + "\n").encode("ascii")
        if len(encoded) > SUMMARY_RESERVE or self.bytes_written + len(encoded) > MAX_OUTPUT_BYTES:
            raise SafeError("TOTAL_OUTPUT_LIMIT")
        descriptor = os.open("summary.json", os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=self.session_fd)
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(encoded)
        self.bytes_written += len(encoded)

    def close(self):
        if self.stream:
            self.stream.close()
            self.stream = None
        if self.session_fd is not None:
            os.close(self.session_fd)
            self.session_fd = None
        if self.parent_fd is not None:
            os.close(self.parent_fd)
            self.parent_fd = None


def collect(parent, duration, interval, *, evidence_source="READ_ONLY_LOCAL_COMMAND"):
    if evidence_source not in SOURCES:
        raise SafeError("EXPLICIT_OBSERVATION_SOURCE_REQUIRED")
    samples = plan(duration, interval)
    session = ExclusiveSession(parent)
    start, started, count, stop = time.monotonic(), utc_now(), 0, "WINDOW_COMPLETE"
    deadline = start + duration
    remaining = lambda: max(0.0, min(3.0, deadline - time.monotonic()))
    try:
        sw = run_bounded(["/usr/bin/sw_vers"], remaining(), 8192)
        uname = run_bounded(["/usr/bin/uname", "-s", "-r", "-m"], remaining(), 8192)
        metadata = parse_os_metadata(sw.stdout, uname.stdout)
        if metadata["status"] == "OBSERVED" and (sw.status != "OBSERVED" or uname.status != "OBSERVED"):
            metadata["status"] = "PARTIAL"
        header = make_header(session.session_id, started, metadata, duration, interval, source=evidence_source)
        if not session.sample(header):
            raise SafeError("HEADER_OUTPUT_LIMIT")
        try:
            for index in range(samples):
                pause = start + index * interval - time.monotonic()
                if pause > 0:
                    time.sleep(min(pause, max(0, deadline - time.monotonic())))
                if time.monotonic() >= deadline:
                    break
                ps = run_bounded(["/bin/ps", "-axo", "pid,ppid,comm,%cpu,rss"], remaining())
                processes = parse_ps_output(ps.stdout) if ps.status in ("OBSERVED", "PARTIAL") else None
                process_summary = processes.public_summary(evidence_source, ps.status, ps.reason) if processes else {"status": "NOT_OBSERVED", "code": ps.reason, "source": evidence_source, "roles": {}}
                tcp = {"status": "NOT_OBSERVED", "code": "NO_VISIBLE_CLAUDE_PROCESS", "connectionsCount": 0, "categories": []}
                if processes and processes.claude_pids:
                    if len(processes.claude_pids) > 128:
                        tcp = {"status": "NOT_OBSERVED", "code": "CLAUDE_PROCESS_LIMIT", "connectionsCount": 0, "categories": []}
                    else:
                        pids = ",".join(str(pid) for pid in processes.claude_pids)
                        sockets = run_bounded(["/usr/sbin/lsof", "-nP", "-a", "-p", pids, "-iTCP", "-FpfntT", "-l"], remaining())
                        tcp = parse_lsof_output(sockets.stdout, processes.claude_pids, evidence_source, sockets.status, sockets.reason) if sockets.status in ("OBSERVED", "PARTIAL") else {"status": "NOT_OBSERVED", "code": sockets.reason, "source": evidence_source, "connectionsCount": 0, "categories": []}
                sample = make_sample(session.session_id, utc_now(), index + 1, time.monotonic() - start, process_summary, tcp)
                if not session.sample(sample):
                    stop = "TOTAL_OUTPUT_LIMIT"
                    break
                count += 1
            if stop == "WINDOW_COMPLETE" and time.monotonic() < deadline:
                time.sleep(max(0.0, deadline - time.monotonic()))
        except KeyboardInterrupt:
            stop = "USER_INTERRUPTED_OBSERVER_ONLY"
        result = make_footer(session.session_id, utc_now(), count, time.monotonic() - start, stop)
        if not session.sample(result, reserve=SUMMARY_RESERVE // 2):
            raise SafeError("FOOTER_OUTPUT_LIMIT")
        session.summary({"header": header, "footer": result})
        return {"status": "OBSERVATION_FINISHED", "sessionName": session.name, "samplesWritten": count, "completionCode": stop}
    finally:
        session.close()


class SafeArgumentParser(argparse.ArgumentParser):
    def error(self, message):
        raise SafeError("ARGUMENTS_INVALID_NO_RAW_VALUES_EXPORTED")


def main(argv=None):
    try:
        if sys.platform != "darwin":
            raise SafeError("MACOS_REQUIRED_NOT_STARTED")
        if sys.version_info < (3, 8):
            raise SafeError("PYTHON3_8_OR_NEWER_REQUIRED_NOT_STARTED")
        parser = SafeArgumentParser(prog="collect_readonly_macos.py", description=__doc__)
        parser.add_argument("--output-parent", required=True, help="existing absolute approved project directory; no symbolic/alias paths")
        parser.add_argument("--duration-seconds", type=int, default=300)
        parser.add_argument("--interval-seconds", type=int, default=10)
        args = parser.parse_args(argv)
        plan(args.duration_seconds, args.interval_seconds)
        result = collect(validate_output_parent(args.output_parent), args.duration_seconds, args.interval_seconds)
        print(json.dumps(result))
        return 0
    except SafeError as error:
        print(json.dumps({"status": "NOT_STARTED_OR_INCOMPLETE", "code": str(error)}))
        return 2
    except KeyboardInterrupt:
        print(json.dumps({"status": "INCOMPLETE", "code": "USER_INTERRUPTED_OBSERVER_ONLY"}))
        return 2
    except Exception:
        print(json.dumps({"status": "INCOMPLETE", "code": "OBSERVER_UNAVAILABLE_NO_RAW_DETAILS_EXPORTED"}))
        return 2


if __name__ == "__main__":
    sys.exit(main())
