"""Validate private-text-free event annotations and align sampling windows only."""

import datetime as dt
import json
import math
import re

from analyse_observation import SafeError, summarize_bytes


SCHEMA = "hongai.passive-activity-events.v1"
ALIGNMENT_SCHEMA = "hongai.passive-activity-alignment.v1"
MAX_BYTES = 64 * 1024
MAX_EVENTS = 200
CLOCK_TOLERANCE_SECONDS = 1.0
KINDS = frozenset({"chat", "download", "tool_use", "app_opened", "app_closed", "visible_error"})
SOURCES = frozenset({"customer_reported", "visible_ui"})
RESULTS = frozenset({"completed", "failed", "unknown"})
CODES = frozenset({"NONE", "NETWORK_ERROR", "HTTP_401", "HTTP_403", "HTTP_429", "LOGIN_SCREEN_SHOWN", "OTHER_UNCLASSIFIED"})
ENUMS = {"kind": KINDS, "source": SOURCES, "result": RESULTS, "code": CODES}
_UTC = re.compile(r"(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,7}))?(Z|\+00:00)")
_SESSION = re.compile(r"[a-f0-9]{32}")
_EPOCH = dt.datetime(1970, 1, 1, tzinfo=dt.timezone.utc)


def _object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise SafeError("ACTIVITY_DUPLICATE_JSON_MEMBER")
        result[key] = value
    return result


def _constant(_):
    raise SafeError("ACTIVITY_NONFINITE_NUMBER")


def _float(value):
    number = float(value)
    if not math.isfinite(number):
        raise SafeError("ACTIVITY_NONFINITE_NUMBER")
    return number


def _loads(data):
    try:
        return json.loads(data, object_pairs_hook=_object, parse_constant=_constant, parse_float=_float)
    except (ValueError, TypeError, RecursionError, OverflowError):
        raise SafeError("ACTIVITY_JSON_INVALID") from None


def _session(value):
    if not isinstance(value, str) or not _SESSION.fullmatch(value):
        raise SafeError("ACTIVITY_SESSION_ID_INVALID")
    return value


def _utc(value):
    """Return equivalent Z spelling and exact 100ns ticks, without precision loss."""
    if not isinstance(value, str):
        raise SafeError("ACTIVITY_UTC_INVALID")
    match = _UTC.fullmatch(value)
    if not match:
        raise SafeError("ACTIVITY_UTC_INVALID")
    try:
        year, month, day, hour, minute, second = map(int, match.groups()[:6])
        whole = dt.datetime(year, month, day, hour, minute, second, tzinfo=dt.timezone.utc)
    except ValueError:
        raise SafeError("ACTIVITY_UTC_INVALID") from None
    delta = whole - _EPOCH
    fraction = match.group(7) or ""
    ticks = (delta.days * 86400 + delta.seconds) * 10_000_000 + int(fraction.ljust(7, "0") or "0")
    # Keep all supplied fractional digits; do not round event timestamps to a
    # neighboring sample or truncate the seventh Windows timestamp digit.
    normalized = value[:-6] + "Z" if value.endswith("+00:00") else value
    return normalized, ticks


def _elapsed(value):
    if isinstance(value, bool) or not isinstance(value, (int, float)) or value < 0 or value > 1900 or not math.isfinite(value):
        raise SafeError("ACTIVITY_ELAPSED_SECONDS_INVALID")
    return value


def _template_metadata(value):
    # Optional known template metadata is never copied into normalized events.
    # instructions is explicitly ignored text, not an event/free-form note.
    if "instructions" in value:
        if not isinstance(value["instructions"], str):
            raise SafeError("ACTIVITY_TEMPLATE_METADATA_INVALID")
        try:
            if len(value["instructions"].encode("utf-8")) > 4096:
                raise SafeError("ACTIVITY_TEMPLATE_METADATA_INVALID")
        except UnicodeError:
            raise SafeError("ACTIVITY_TEMPLATE_METADATA_INVALID") from None
    if "eventFields" not in value:
        return
    fields = value["eventFields"]
    if not isinstance(fields, dict) or set(fields) != set(ENUMS):
        raise SafeError("ACTIVITY_TEMPLATE_METADATA_INVALID")
    for key, allowed in ENUMS.items():
        labels = fields[key]
        if not isinstance(labels, list) or not all(isinstance(label, str) for label in labels) or len(labels) != len(allowed) or set(labels) != allowed:
            raise SafeError("ACTIVITY_TEMPLATE_METADATA_INVALID")


def parse_activity_events(data, expected_session_id):
    """Normalize the latest event template, rejecting unknown event fields."""
    expected = _session(expected_session_id)
    if not isinstance(data, bytes):
        raise SafeError("ACTIVITY_BYTES_REQUIRED")
    if len(data) > MAX_BYTES:
        raise SafeError("ACTIVITY_BYTE_LIMIT")
    try:
        text = data.decode("utf-8-sig")
    except UnicodeError:
        raise SafeError("ACTIVITY_UTF8_REQUIRED") from None
    value = _loads(text)
    if not isinstance(value, dict) or set(value) - {"schema", "sessionId", "events", "eventFields", "instructions"}:
        raise SafeError("ACTIVITY_TOP_LEVEL_FIELDS_INVALID")
    if value.get("schema") != SCHEMA:
        raise SafeError("ACTIVITY_SCHEMA_INVALID")
    if _session(value.get("sessionId")) != expected:
        raise SafeError("ACTIVITY_SESSION_MISMATCH")
    _template_metadata(value)
    events = value.get("events")
    if not isinstance(events, list) or len(events) > MAX_EVENTS:
        raise SafeError("ACTIVITY_EVENT_LIMIT_OR_TYPE")
    normalized = []
    required = {"utcISO", "kind", "source", "result", "code"}
    for index, event in enumerate(events, 1):
        if not isinstance(event, dict) or not required <= set(event) or set(event) - required - {"elapsedSeconds"}:
            raise SafeError("ACTIVITY_EVENT_FIELDS_INVALID")
        selected = {"eventIndex": index, "utcISO": _utc(event["utcISO"])[0]}
        for key, allowed in ENUMS.items():
            if not isinstance(event[key], str) or event[key] not in allowed:
                raise SafeError("ACTIVITY_EVENT_ENUM_INVALID")
            selected[key] = event[key]
        if "elapsedSeconds" in event:
            selected["elapsedSeconds"] = _elapsed(event["elapsedSeconds"])
        normalized.append(selected)
    return {"schema": SCHEMA, "sessionId": expected, "events": normalized}


def _observation_records(data):
    # summarize_bytes has already validated byte/line/count/schema/session
    # bounds. Reparse only to extract fixed time/index fields, never payloads.
    records = []
    for line in data.decode("utf-8-sig").splitlines():
        if line.strip():
            records.append(_loads(line))
    return records


def link_events(observation_bytes, event_bytes):
    """Return temporal association only; never infer routes, account or ban cause."""
    if not isinstance(observation_bytes, bytes):
        raise SafeError("OBSERVATION_BYTES_REQUIRED")
    summary = summarize_bytes(observation_bytes)
    normalized = parse_activity_events(event_bytes, summary["sessionId"])
    records = _observation_records(observation_bytes)
    header = records[0]
    footers = [record for record in records if record["recordType"] == "footer"]
    samples = [record for record in records if record["recordType"] == "sample"]
    start_utc, start_tick = _utc(header["utcISO"])
    end_utc, end_tick = _utc(footers[0]["utcISO"]) if footers else (None, None)
    elapsed_end = _elapsed(footers[0]["elapsedSeconds"]) if footers and "elapsedSeconds" in footers[0] else None
    interval = float(header.get("limits", {}).get("intervalSeconds", 10))
    nearby_radius = min(30.0, max(1.0, interval))
    issues = []
    if summary["captureStructure"] != "COMPLETE_RECORD_SEQUENCE":
        issues.append("OBSERVATION_SEQUENCE_INCOMPLETE_OR_INCONSISTENT")
    if summary["protocolIssues"]:
        issues.append("OBSERVATION_PROTOCOL_ISSUES_REQUIRE_REVIEW")
    if not samples:
        issues.append("NO_SAMPLES_FOR_EVENT_ALIGNMENT")
    safe_samples = []
    previous_tick, previous_elapsed = start_tick, None
    anchor_tick = anchor_elapsed = None
    for sample in samples:
        _, tick = _utc(sample["utcISO"])
        elapsed = _elapsed(sample["elapsedSeconds"])
        if tick < previous_tick or (end_tick is not None and tick > end_tick):
            issues.append("OBSERVATION_UTC_ORDER_INVALID")
        if previous_elapsed is not None and elapsed <= previous_elapsed:
            issues.append("OBSERVATION_ELAPSED_NOT_STRICTLY_INCREASING")
        if elapsed_end is not None and elapsed > elapsed_end:
            issues.append("OBSERVATION_ELAPSED_WINDOW_INVALID")
        if anchor_tick is None:
            anchor_tick, anchor_elapsed = tick, elapsed
        else:
            difference = (tick - anchor_tick) / 10_000_000 - (elapsed - anchor_elapsed)
            if abs(difference) > CLOCK_TOLERANCE_SECONDS:
                issues.append("OBSERVATION_CLOCK_AXES_DISAGREE")
        safe_samples.append({"sampleIndex": sample["sampleIndex"], "tick": tick, "elapsed": elapsed})
        previous_tick, previous_elapsed = tick, elapsed
    if end_tick is not None and end_tick < previous_tick:
        issues.append("OBSERVATION_UTC_ORDER_INVALID")
    if elapsed_end is not None and anchor_tick is not None and end_tick is not None:
        footer_difference = (end_tick - anchor_tick) / 10_000_000 - (elapsed_end - anchor_elapsed)
        if abs(footer_difference) > CLOCK_TOLERANCE_SECONDS:
            issues.append("OBSERVATION_CLOCK_AXES_DISAGREE")
    issues = sorted(set(issues))
    aligned = []
    for event in normalized["events"]:
        item = dict(event)
        _, event_tick = _utc(event["utcISO"])
        item["utcWindowStatus"] = "WINDOW_UNAVAILABLE" if end_tick is None else "IN_WINDOW" if start_tick <= event_tick <= end_tick else "OUTSIDE_WINDOW"
        has_elapsed = "elapsedSeconds" in event
        item["elapsedWindowStatus"] = "NOT_PROVIDED" if not has_elapsed else "WINDOW_UNAVAILABLE" if elapsed_end is None else "IN_WINDOW" if 0 <= event["elapsedSeconds"] <= elapsed_end else "OUTSIDE_WINDOW"
        difference = None
        if has_elapsed and anchor_tick is not None:
            difference = (event_tick - anchor_tick) / 10_000_000 - (event["elapsedSeconds"] - anchor_elapsed)
            # A declared tolerance is shown, not an invisible timestamp rewrite.
            item["clockAgreement"] = "EXACT" if abs(difference) < 1e-9 else "WITHIN_DECLARED_TOLERANCE" if abs(difference) <= CLOCK_TOLERANCE_SECONDS else "MISMATCH"
        else:
            item["clockAgreement"] = "UTC_ONLY" if not has_elapsed else "NO_OBSERVATION_ANCHOR"
        item["utcElapsedDifferenceSeconds"] = None if difference is None else round(difference, 7)
        codes = list(issues)
        if anchor_tick is None:
            item["sampleWindowStatus"] = "NO_SAMPLES"
        elif event_tick < anchor_tick:
            item["sampleWindowStatus"] = "BEFORE_FIRST_SAMPLE"
            # Header UTC has no corresponding monotonic elapsed anchor.
            # Preparation delay and a clock adjustment cannot be distinguished
            # there; do not attach an earlier event to a later first sample.
            codes.append("EVENT_PRECEDES_FIRST_OBSERVED_SAMPLE_NO_ALIGNMENT")
        else:
            item["sampleWindowStatus"] = "AT_OR_AFTER_FIRST_SAMPLE"
        if item["utcWindowStatus"] != "IN_WINDOW":
            codes.append("EVENT_UTC_OUTSIDE_WINDOW" if item["utcWindowStatus"] == "OUTSIDE_WINDOW" else "UTC_WINDOW_NOT_ESTABLISHED")
        if has_elapsed and item["elapsedWindowStatus"] != "IN_WINDOW":
            codes.append("EVENT_ELAPSED_OUTSIDE_WINDOW" if item["elapsedWindowStatus"] == "OUTSIDE_WINDOW" else "ELAPSED_WINDOW_NOT_ESTABLISHED")
        if item["clockAgreement"] in {"MISMATCH", "NO_OBSERVATION_ANCHOR"}:
            codes.append("EVENT_CLOCK_AXES_DISAGREE_OR_UNOBSERVED")
        eligible = not codes
        nearby = []
        if eligible:
            for sample in safe_samples:
                distance = abs(event_tick - sample["tick"]) / 10_000_000
                if distance <= nearby_radius and (not has_elapsed or abs(event["elapsedSeconds"] - sample["elapsed"]) <= nearby_radius):
                    nearby.append((distance, sample["sampleIndex"]))
            nearby = sorted(nearby)[:2]
        item["alignmentStatus"] = "NOT_ALIGNED" if not eligible else "ALIGNED_BOTH_CLOCKS" if has_elapsed else "ALIGNED_UTC_ONLY"
        item["alignmentCodes"] = sorted(set(codes))
        item["nearbySampleIndices"] = sorted(index for _, index in nearby)
        item["nearbySampleStatus"] = "NOT_LINKED" if not eligible else "NEARBY_SAMPLES_WITHIN_DECLARED_RADIUS" if nearby else "NO_SAMPLE_WITHIN_DECLARED_RADIUS"
        aligned.append(item)
    return {
        "schema": ALIGNMENT_SCHEMA, "sessionId": summary["sessionId"],
        "scope": "ANNOTATION_TO_PASSIVE_SAMPLING_TIME_ONLY_NOT_CAUSALITY",
        "annotationsStatus": "EVENT_ANNOTATIONS_PROVIDED" if aligned else "NO_EVENT_ANNOTATIONS_NOT_NO_ACTIVITY",
        "eventCount": len(aligned), "events": aligned,
        "observationWindow": {
            "utcStart": start_utc, "utcEnd": end_utc, "elapsedStartSeconds": 0,
            "elapsedEndSeconds": elapsed_end, "sampleCount": len(samples),
            "earliestSampleUtcISO": _utc(samples[0]["utcISO"])[0] if samples else None,
            "headerElapsedAnchor": "NOT_RECORDED",
            "captureStructure": summary["captureStructure"], "captureOutcome": summary["captureOutcome"],
            "evidenceProvenance": summary["evidenceProvenance"],
            "clockToleranceSeconds": CLOCK_TOLERANCE_SECONDS, "nearbySampleRadiusSeconds": nearby_radius,
        },
        "alignmentIssues": issues, "rawIdentifiersOrPayloadsIncluded": False,
        "eventSourcesAttested": False, "mcpInvocationVerified": False,
        "sourceLogPrivacyCertified": False, "accountRiskOrBanCauseInferred": False,
        "fullEnvironmentAccepted": False, "customerReady": False,
    }
