"""Summarize passive diagnostic metadata; never infer account or hardware identity."""
import argparse
import datetime as dt
import json
import math
import os
from pathlib import Path
import re
import stat
import sys

SCHEMA = "hongai.passive-observation.v1"
MAX_BYTES = 5 * 1024 * 1024
STATUSES = {"OBSERVED", "EMPTY", "NOT_OBSERVED", "PARTIAL"}
ROLES = ("claude", "cowork", "mihomo", "clash", "todesk")


class SafeError(Exception):
    pass


def _object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise SafeError("LOG_DUPLICATE_JSON_MEMBER")
        result[key] = value
    return result


def _constant(_):
    raise SafeError("LOG_NONFINITE_NUMBER")


def _number(value, minimum=0, maximum=10 ** 12):
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value) or value < minimum or value > maximum:
        raise SafeError("LOG_NUMBER_INVALID")
    return value


def _integer(value, maximum=1000):
    if not isinstance(value, int) or isinstance(value, bool) or value < 0 or value > maximum:
        raise SafeError("LOG_INTEGER_INVALID")
    return value


def _utc(value):
    if not isinstance(value, str) or not re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,7})?(?:Z|\+00:00)", value):
        raise SafeError("LOG_UTC_INVALID")
    try:
        return dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        raise SafeError("LOG_UTC_INVALID") from None


def summarize_bytes(data):
    if len(data) > MAX_BYTES:
        raise SafeError("LOG_BYTE_LIMIT")
    try:
        text = data.decode("utf-8-sig")
    except UnicodeError:
        raise SafeError("LOG_UTF8_REQUIRED") from None
    lines = text.splitlines()
    if len(lines) > 182:
        raise SafeError("LOG_RECORD_LIMIT")
    records = []
    for line in lines:
        if not line.strip():
            continue
        if len(line.encode("utf-8")) > 131072:
            raise SafeError("LOG_LINE_LIMIT")
        try:
            item = json.loads(line, object_pairs_hook=_object, parse_constant=_constant)
        except (ValueError, RecursionError):
            raise SafeError("LOG_JSON_INVALID") from None
        if not isinstance(item, dict) or item.get("schema") != SCHEMA or item.get("recordType") not in {"header", "sample", "footer"}:
            raise SafeError("LOG_SCHEMA_INVALID")
        if not isinstance(item.get("sessionId"), str) or not re.fullmatch(r"[a-f0-9]{32}", item["sessionId"]):
            raise SafeError("LOG_SESSION_ID_INVALID")
        _utc(item.get("utcISO"))
        records.append(item)
    if not records or records[0]["recordType"] != "header":
        raise SafeError("LOG_HEADER_REQUIRED")
    session = records[0]["sessionId"]
    if any(item["sessionId"] != session for item in records):
        raise SafeError("LOG_MIXED_SESSIONS")
    if sum(item["recordType"] == "header" for item in records) != 1:
        raise SafeError("LOG_MULTIPLE_HEADERS")
    synthetic = records[0].get("synthetic")
    declared_source = records[0].get("source")
    known_sources = {"READ_ONLY_LOCAL_COMMAND", "SYNTHETIC_FIXED_FIXTURE"}
    sources = set()
    for item in records:
        candidates = [item]
        for key in ("processes", "tcp"):
            if isinstance(item.get(key), dict):
                candidates.append(item[key])
        for candidate in candidates:
            if "source" in candidate:
                value = candidate["source"]
                if not isinstance(value, str) or value not in known_sources:
                    raise SafeError("LOG_PROVENANCE_SOURCE_INVALID")
                sources.add(value)
        if "synthetic" in item and (not isinstance(item["synthetic"], bool) or item["synthetic"] is not synthetic):
            raise SafeError("LOG_PROVENANCE_CONFLICT")
    if len(sources) > 1 or (synthetic is True and "READ_ONLY_LOCAL_COMMAND" in sources) or (synthetic is False and "SYNTHETIC_FIXED_FIXTURE" in sources):
        raise SafeError("LOG_PROVENANCE_CONFLICT")
    if declared_source == "SYNTHETIC_FIXED_FIXTURE" and synthetic is not True:
        raise SafeError("LOG_PROVENANCE_CONFLICT")
    if declared_source == "READ_ONLY_LOCAL_COMMAND" and synthetic is not False:
        raise SafeError("LOG_PROVENANCE_CONFLICT")
    footers = [item for item in records if item["recordType"] == "footer"]
    if len(footers) > 1 or (footers and records[-1]["recordType"] != "footer"):
        raise SafeError("LOG_FOOTER_ORDER_INVALID")
    samples = [item for item in records if item["recordType"] == "sample"]
    if len(samples) > 180:
        raise SafeError("LOG_SAMPLE_LIMIT")
    hints, protocol_issues = [], []
    utc_start = _utc(records[0]["utcISO"])
    utc_end = _utc(footers[0]["utcISO"]) if footers else None
    elapsed_end = _number(footers[0]["elapsedSeconds"],0,1900) if footers and "elapsedSeconds" in footers[0] else None
    if utc_end is not None and utc_end < utc_start:
        protocol_issues.append({"code":"HEADER_FOOTER_UTC_ORDER_INVALID"})
    if not samples:
        hints.append({"code": "NO_SAMPLES_REVIEW", "meaning": "NO_ACTIVITY_CONCLUSION_POSSIBLE"})
    observed_process_samples = observed_tcp_samples = partial_process_samples = partial_tcp_samples = 0
    previous = None
    limits = records[0].get("limits", {})
    if not isinstance(limits, dict):
        raise SafeError("LOG_LIMITS_RECORD_INVALID")
    interval = limits.get("intervalSeconds", 10)
    interval = _number(interval, 1, 1800)
    for index, sample in enumerate(samples, 1):
        _integer(sample.get("sampleIndex"), 180)
        if sample.get("sampleIndex") != index:
            raise SafeError("LOG_SAMPLE_SEQUENCE_INVALID")
        elapsed = _number(sample.get("elapsedSeconds"), 0, 1900)
        utc_current = _utc(sample["utcISO"])
        if utc_current < utc_start or (utc_end is not None and utc_current > utc_end):
            protocol_issues.append({"code":"SAMPLE_OUTSIDE_DECLARED_UTC_WINDOW","sampleIndex":index})
        if elapsed_end is not None and elapsed > elapsed_end:
            protocol_issues.append({"code":"SAMPLE_AFTER_DECLARED_ELAPSED_WINDOW","sampleIndex":index})
        processes, tcp = sample.get("processes"), sample.get("tcp")
        if not isinstance(processes, dict) or not isinstance(tcp, dict) or processes.get("status") not in STATUSES or tcp.get("status") not in STATUSES:
            raise SafeError("LOG_OBSERVATION_STATUS_INVALID")
        roles = processes.get("roles", {})
        if not isinstance(roles, dict) or any(role not in ROLES for role in roles):
            raise SafeError("LOG_ROLE_INVALID")
        counts = {}
        for role, metrics in roles.items():
            if not isinstance(metrics, dict):
                raise SafeError("LOG_ROLE_METRICS_INVALID")
            value = metrics.get("processCount")
            if value is None and processes["status"] in {"NOT_OBSERVED", "PARTIAL"}:
                counts[role] = None
            else:
                counts[role] = _integer(value)
        process_contradiction = processes["status"] == "EMPTY" and any(count for count in counts.values() if count is not None)
        if process_contradiction:
            protocol_issues.append({"code": "EMPTY_PROCESS_STATE_HAS_NONZERO_COUNT", "sampleIndex": index})
        if processes["status"] in {"OBSERVED", "EMPTY"}:
            if not process_contradiction:
                observed_process_samples += 1
            if set(roles) != set(ROLES):
                raise SafeError("LOG_OBSERVED_ROLE_SET_INCOMPLETE")
        elif processes["status"] == "PARTIAL":
            partial_process_samples += 1
        if tcp["status"] in {"OBSERVED", "EMPTY", "PARTIAL"}:
            connection_count = _integer(tcp.get("connectionsCount"), 1000000)
            categories = tcp.get("categories", [])
            if not isinstance(categories, list) or len(categories) > 1024:
                raise SafeError("LOG_TCP_CATEGORIES_INVALID")
            total = 0
            for category in categories:
                if not isinstance(category, dict):
                    raise SafeError("LOG_TCP_CATEGORY_INVALID")
                total += _integer(category.get("count"), 1000000)
            tcp_contradiction = total != connection_count or (tcp["status"] == "EMPTY" and connection_count != 0)
            if total != connection_count:
                protocol_issues.append({"code": "TCP_CATEGORY_TOTAL_DISAGREES", "sampleIndex": index})
            if tcp["status"] == "EMPTY" and connection_count != 0:
                protocol_issues.append({"code": "EMPTY_TCP_STATE_HAS_NONZERO_COUNT", "sampleIndex": index})
            if tcp_contradiction:
                pass
            elif tcp["status"] == "PARTIAL":
                partial_tcp_samples += 1
            else:
                observed_tcp_samples += 1
        if not process_contradiction and processes["status"] in {"OBSERVED", "EMPTY"} and counts.get("claude", 0) and counts.get("clash", 0) + counts.get("mihomo", 0) == 0:
            hints.append({"code": "PROXY_NAME_ROLE_NOT_VISIBLE_WHILE_APP_ROLE_VISIBLE", "sampleIndex": index, "meaning": "REVIEW_ONLY_NOT_ROUTE_OR_LEAK_PROOF"})
        current = {"elapsed": elapsed, "utc": _utc(sample["utcISO"]), "counts": counts, "processStatus": "NOT_OBSERVED" if process_contradiction else processes["status"]}
        if previous:
            gap = elapsed - previous["elapsed"]
            if gap < 0:
                protocol_issues.append({"code": "MONOTONIC_TIMELINE_REVERSED", "sampleIndex": index})
            elif gap > max(interval * 2, interval + 5):
                hints.append({"code": "OBSERVATION_GAP", "sampleIndex": index, "meaning": "MISSING_WINDOW_NOT_NO_ACTIVITY"})
            utc_gap = (current["utc"] - previous["utc"]).total_seconds()
            if abs(utc_gap - gap) > 5:
                hints.append({"code": "UTC_AND_ELAPSED_TIMELINES_DIFFER", "sampleIndex": index, "meaning": "CLOCK_ADJUSTMENT_OR_CAPTURE_DELAY_REQUIRES_REVIEW"})
            if current["processStatus"] in {"OBSERVED", "EMPTY"} and previous["processStatus"] in {"OBSERVED", "EMPTY"} and current["counts"].get("claude") != previous["counts"].get("claude"):
                hints.append({"code": "APP_NAME_ROLE_COUNT_CHANGED", "sampleIndex": index, "meaning": "NOT_LOGIN_STATE_OR_DEVICE_ID_CHANGE_PROOF"})
        previous = current
    if footers and _integer(footers[0].get("samplesWritten"), 180) != len(samples):
        protocol_issues.append({"code": "FOOTER_SAMPLE_COUNT_DISAGREES"})
    complete = bool(footers) and not protocol_issues
    completion = footers[0].get("completionCode") if footers else None
    if not isinstance(completion, str):
        completion = None
    if completion in {"DURATION_COMPLETE", "WINDOW_COMPLETE"}:
        outcome = "COLLECTOR_REPORTED_WINDOW_FINISHED"
    elif completion in {"SAMPLE_LIMIT_REACHED", "OUTPUT_LIMIT_REACHED", "TOTAL_OUTPUT_LIMIT"}:
        outcome = "COLLECTOR_LIMIT_REACHED"
    elif completion in {"USER_INTERRUPTED_OBSERVER_ONLY", "COLLECTOR_INTERRUPTED", "COLLECTOR_FAILED_FIXED_CODE_NO_RAW_ERROR"}:
        outcome = "COLLECTOR_STOPPED_EARLY"
    else:
        outcome = "NOT_ESTABLISHED"
    known_completions = {"DURATION_COMPLETE", "WINDOW_COMPLETE", "SAMPLE_LIMIT_REACHED", "OUTPUT_LIMIT_REACHED", "TOTAL_OUTPUT_LIMIT", "USER_INTERRUPTED_OBSERVER_ONLY", "COLLECTOR_INTERRUPTED", "COLLECTOR_FAILED_FIXED_CODE_NO_RAW_ERROR"}
    provenance = "SYNTHETIC_FIXED_FIXTURE" if synthetic is True and declared_source == "SYNTHETIC_FIXED_FIXTURE" else "COLLECTOR_DECLARED_PASSIVE_NOT_ATTESTED" if synthetic is False and declared_source == "READ_ONLY_LOCAL_COMMAND" else "UNSPECIFIED_SOURCE_NOT_OBSERVATION_PROOF"
    return {
        "schema": "hongai.passive-observation-analysis.v1", "sessionId": session,
        "scope": "PASSIVE_DIAGNOSTIC_METADATA_ONLY", "sampleCount": len(samples),
        "captureStructure": "COMPLETE_RECORD_SEQUENCE" if complete else "INCOMPLETE_OR_INCONSISTENT_RECORD_SEQUENCE",
        "captureOutcome": outcome,
        "completionCode": completion if completion in known_completions else "UNSPECIFIED_OR_UNKNOWN_FIXED_CODE",
        "evidenceProvenance": provenance,
        "protocolIssues": protocol_issues, "reviewHints": hints,
        "coverage": {
            "processNameRoles": {"observedSamples": observed_process_samples, "partialSamples": partial_process_samples, "notObservedSamples": len(samples)-observed_process_samples-partial_process_samples},
            "tcpMetadata": {"observedSamples": observed_tcp_samples, "partialSamples": partial_tcp_samples, "notObservedSamples": len(samples)-observed_tcp_samples-partial_tcp_samples},
            "httpsRequestPayload": "NOT_OBSERVED", "allDestinations": "NOT_ESTABLISHED", "mcpInvocations": "NOT_OBSERVED_BY_SOCKET_COUNTS",
            "hardwareReadPaths": "NOT_OBSERVED", "softwareFingerprintReadPaths": "NOT_OBSERVED", "accountState": "NOT_READ",
            "customerModelConsistency": "NO_CUSTOMER_MODEL_READBACK_IN_THIS_LOG", "proxyEgressEnforcement": "NOT_ESTABLISHED_BY_ROLE_OR_TCP_COUNTS"
        },
        "rawIdentifiersOrPayloadsIncludedInAnalysis": False, "sourceLogPrivacyCertified": False,
        "officialClientReadCoverageCompleted": False, "hardwareSimulationVerified": False,
        "accountRiskOrBanCauseInferred": False, "fullEnvironmentAccepted": False, "customerReady": False,
    }


def _path(value, for_output=False):
    path = Path(value)
    if not path.is_absolute() or path == Path(path.anchor):
        raise SafeError("EXPLICIT_ABSOLUTE_FILE_REQUIRED")
    if for_output and os.name == "nt" and path.drive.upper() not in {"D:", "E:"}:
        raise SafeError("OUTPUT_DATA_DRIVE_REQUIRED")
    for part in [path.parent, *path.parent.parents]:
        info = part.lstat()
        if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
            raise SafeError("LINKED_PARENT_NOT_ALLOWED")
    return path


def read_bounded(value, *, maximum_bytes=MAX_BYTES):
    if type(maximum_bytes) is not int or not 1 <= maximum_bytes <= MAX_BYTES:
        raise SafeError("LOG_READ_BUDGET_INVALID")
    path = _path(value)
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400 or info.st_size > maximum_bytes:
        raise SafeError("REGULAR_BOUNDED_LOG_REQUIRED")
    descriptor = os.open(str(path), os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        opened = os.fstat(descriptor)
        if (opened.st_dev, opened.st_ino) != (info.st_dev, info.st_ino):
            raise SafeError("LOG_CHANGED_DURING_OPEN")
        with os.fdopen(descriptor, "rb", closefd=False) as stream:
            data = stream.read(maximum_bytes+1)
        if len(data) > maximum_bytes:
            raise SafeError("LOG_BYTE_LIMIT")
        return data
    finally:
        os.close(descriptor)


class SafeParser(argparse.ArgumentParser):
    def error(self, message):
        raise SafeError("ANALYSIS_ARGUMENTS_INVALID")


def main(argv=None):
    try:
        parser = SafeParser(description=__doc__)
        parser.add_argument("--input", required=True)
        parser.add_argument("--output", required=True)
        args = parser.parse_args(argv)
        result = summarize_bytes(read_bounded(args.input))
        path = _path(args.output, for_output=True)
        data = (json.dumps(result, indent=2, ensure_ascii=True)+"\n").encode("ascii")
        descriptor = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(data)
        print(json.dumps({"status": "ANALYSIS_CREATED", "sampleCount": result["sampleCount"], "fullEnvironmentAccepted": False}))
        return 0
    except SafeError as error:
        print(json.dumps({"status": "ANALYSIS_NOT_COMPLETED", "code": str(error)}))
        return 2
    except Exception:
        print(json.dumps({"status": "ANALYSIS_NOT_COMPLETED", "code": "ANALYSIS_FAILED_NO_RAW_DETAILS_EXPORTED"}))
        return 2


if __name__ == "__main__":
    sys.exit(main())
