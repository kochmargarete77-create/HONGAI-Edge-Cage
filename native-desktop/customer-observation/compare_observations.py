"""Pure comparison of passive observation summaries, without identity or risk inference."""

import hashlib
import json
import math
import re


INPUT_SCHEMA = "hongai.passive-observation-analysis.v1"
MAX_SUMMARIES = 32
MAX_JSON_BYTES = 5 * 1024 * 1024
SCOPES = {"same_case_operator_declared", "independent_sessions"}
PROVENANCE = {"SYNTHETIC_FIXED_FIXTURE", "COLLECTOR_DECLARED_PASSIVE_NOT_ATTESTED", "UNSPECIFIED_SOURCE_NOT_OBSERVATION_PROOF"}
DIMENSIONS = ("processNameRoles", "tcpMetadata")
COUNTS = ("observedSamples", "partialSamples", "notObservedSamples")
STRUCTURES = {"COMPLETE_RECORD_SEQUENCE", "INCOMPLETE_OR_INCONSISTENT_RECORD_SEQUENCE"}
OUTCOMES = {"COLLECTOR_REPORTED_WINDOW_FINISHED", "COLLECTOR_LIMIT_REACHED", "COLLECTOR_STOPPED_EARLY", "NOT_ESTABLISHED"}
COMPLETIONS = {"DURATION_COMPLETE", "WINDOW_COMPLETE", "SAMPLE_LIMIT_REACHED", "OUTPUT_LIMIT_REACHED", "TOTAL_OUTPUT_LIMIT", "USER_INTERRUPTED_OBSERVER_ONLY", "COLLECTOR_INTERRUPTED", "COLLECTOR_FAILED_FIXED_CODE_NO_RAW_ERROR", "UNSPECIFIED_OR_UNKNOWN_FIXED_CODE"}
FALSE_FLAGS = {"rawIdentifiersOrPayloadsIncludedInAnalysis", "sourceLogPrivacyCertified", "officialClientReadCoverageCompleted", "hardwareSimulationVerified", "accountRiskOrBanCauseInferred", "fullEnvironmentAccepted", "customerReady"}
TOP_FIELDS = {"schema", "sessionId", "scope", "sampleCount", "captureStructure", "captureOutcome", "completionCode", "evidenceProvenance", "protocolIssues", "reviewHints", "coverage"} | FALSE_FLAGS
UNMEASURED_COVERAGE = {
    "httpsRequestPayload": "NOT_OBSERVED", "allDestinations": "NOT_ESTABLISHED",
    "mcpInvocations": "NOT_OBSERVED_BY_SOCKET_COUNTS", "hardwareReadPaths": "NOT_OBSERVED",
    "softwareFingerprintReadPaths": "NOT_OBSERVED", "accountState": "NOT_READ",
    "customerModelConsistency": "NO_CUSTOMER_MODEL_READBACK_IN_THIS_LOG",
    "proxyEgressEnforcement": "NOT_ESTABLISHED_BY_ROLE_OR_TCP_COUNTS",
}


class SafeError(Exception):
    pass


def _json_copy(value, depth=0, ancestors=None, budget=None):
    """Accept plain JSON data only; never invoke caller serialization methods."""
    if budget is None:
        budget = [0, 0]
    def charge(length):
        budget[1] += length
        if budget[1] > MAX_JSON_BYTES:
            raise SafeError("COMPARISON_INPUT_BYTE_LIMIT")
    budget[0] += 1
    if budget[0] > 200000 or depth > 12:
        raise SafeError("COMPARISON_JSON_COMPLEXITY_LIMIT")
    kind = type(value)
    if value is None or kind is bool:
        charge(5)
        return value
    if kind is int:
        if abs(value) > 2 ** 53 - 1:
            raise SafeError("COMPARISON_JSON_NUMBER_INVALID")
        charge(len(str(value)))
        return value
    if kind is float:
        if not math.isfinite(value):
            raise SafeError("COMPARISON_JSON_NUMBER_INVALID")
        charge(len(json.dumps(value)))
        return value
    if kind is str:
        if len(value) > 4096:
            raise SafeError("COMPARISON_JSON_TEXT_LIMIT")
        # One bounded leaf at a time; do not allocate a whole oversized JSON
        # encoding merely to discover the final total exceeds its limit.
        charge(len(json.dumps(value, ensure_ascii=True)))
        return value
    if kind not in (dict, list):
        raise SafeError("COMPARISON_PLAIN_JSON_DATA_REQUIRED")
    if len(value) > (1024 if kind is list else 32):
        raise SafeError("COMPARISON_JSON_COLLECTION_LIMIT")
    charge(2 + max(0, len(value) - 1))
    ancestors = set() if ancestors is None else ancestors
    identity = id(value)
    if identity in ancestors:
        raise SafeError("COMPARISON_CYCLIC_DATA_REJECTED")
    ancestors.add(identity)
    try:
        if kind is list:
            return [_json_copy(item, depth + 1, ancestors, budget) for item in value]
        if any(type(key) is not str for key in value):
            raise SafeError("COMPARISON_JSON_STRING_KEYS_REQUIRED")
        for key in value:
            if len(key) > 128:
                raise SafeError("COMPARISON_JSON_KEY_LIMIT")
            charge(len(json.dumps(key, ensure_ascii=True)) + 1)
        return {key: _json_copy(item, depth + 1, ancestors, budget) for key, item in value.items()}
    finally:
        ancestors.remove(identity)


def _integer(value, maximum):
    if type(value) is not int or not 0 <= value <= maximum:
        raise SafeError("COMPARISON_COUNT_INVALID")
    return value


def _diagnostics(value, hint=False):
    if type(value) is not list or len(value) > 1024:
        raise SafeError("COMPARISON_DIAGNOSTIC_LIST_INVALID")
    allowed = {"code", "sampleIndex", "meaning"} if hint else {"code", "sampleIndex"}
    for item in value:
        if type(item) is not dict or set(item) - allowed or "code" not in item or type(item["code"]) is not str or not re.fullmatch(r"[A-Z0-9_]{1,100}", item["code"]):
            raise SafeError("COMPARISON_DIAGNOSTIC_RECORD_INVALID")
        if "sampleIndex" in item:
            if _integer(item["sampleIndex"], 180) == 0:
                raise SafeError("COMPARISON_DIAGNOSTIC_RECORD_INVALID")
        if "meaning" in item and (type(item["meaning"]) is not str or not re.fullmatch(r"[A-Z0-9_]{1,160}", item["meaning"])):
            raise SafeError("COMPARISON_DIAGNOSTIC_RECORD_INVALID")


def _validate(summary):
    if type(summary) is not dict or set(summary) != TOP_FIELDS:
        raise SafeError("COMPARISON_SUMMARY_FIELDS_INVALID")
    if summary["schema"] != INPUT_SCHEMA:
        raise SafeError("COMPARISON_INPUT_SCHEMA_UNSUPPORTED")
    if type(summary["sessionId"]) is not str or not re.fullmatch(r"[a-f0-9]{32}", summary["sessionId"]):
        raise SafeError("COMPARISON_SESSION_ID_INVALID")
    if summary["scope"] != "PASSIVE_DIAGNOSTIC_METADATA_ONLY" or any(summary[key] is not False for key in FALSE_FLAGS):
        raise SafeError("COMPARISON_INPUT_SCOPE_OR_CLAIMS_INVALID")
    for field, allowed in (("captureStructure", STRUCTURES), ("captureOutcome", OUTCOMES), ("completionCode", COMPLETIONS), ("evidenceProvenance", PROVENANCE)):
        if type(summary[field]) is not str or summary[field] not in allowed:
            raise SafeError("COMPARISON_INPUT_STATE_UNSUPPORTED")
    count = _integer(summary["sampleCount"], 180)
    _diagnostics(summary["protocolIssues"])
    _diagnostics(summary["reviewHints"], hint=True)
    for diagnostic in summary["protocolIssues"] + summary["reviewHints"]:
        if diagnostic.get("sampleIndex", 0) > count:
            raise SafeError("COMPARISON_DIAGNOSTIC_SAMPLE_OUT_OF_RANGE")
    if summary["captureStructure"] == "COMPLETE_RECORD_SEQUENCE" and summary["protocolIssues"]:
        raise SafeError("COMPARISON_CAPTURE_STRUCTURE_CONFLICT")
    completion = summary["completionCode"]
    expected_outcome = "COLLECTOR_REPORTED_WINDOW_FINISHED" if completion in {"DURATION_COMPLETE", "WINDOW_COMPLETE"} else "COLLECTOR_LIMIT_REACHED" if completion in {"SAMPLE_LIMIT_REACHED", "OUTPUT_LIMIT_REACHED", "TOTAL_OUTPUT_LIMIT"} else "COLLECTOR_STOPPED_EARLY" if completion in {"USER_INTERRUPTED_OBSERVER_ONLY", "COLLECTOR_INTERRUPTED", "COLLECTOR_FAILED_FIXED_CODE_NO_RAW_ERROR"} else "NOT_ESTABLISHED"
    if summary["captureOutcome"] != expected_outcome:
        raise SafeError("COMPARISON_CAPTURE_OUTCOME_CONFLICT")
    coverage = summary["coverage"]
    if type(coverage) is not dict or set(coverage) != set(DIMENSIONS) | set(UNMEASURED_COVERAGE):
        raise SafeError("COMPARISON_COVERAGE_FIELDS_INVALID")
    for key, expected in UNMEASURED_COVERAGE.items():
        if coverage[key] != expected:
            raise SafeError("COMPARISON_UNMEASURED_SCOPE_CHANGED")
    for dimension in DIMENSIONS:
        values = coverage[dimension]
        if type(values) is not dict or set(values) != set(COUNTS):
            raise SafeError("COMPARISON_COVERAGE_COUNTS_INVALID")
        if sum(_integer(values[key], 180) for key in COUNTS) != count:
            raise SafeError("COMPARISON_COVERAGE_TOTAL_DISAGREES")


def _fraction(value, count):
    return round(value / count, 6) if count else None


def _view(summary):
    count = summary["sampleCount"]
    coverage = {}
    for dimension in DIMENSIONS:
        values = summary["coverage"][dimension]
        coverage[dimension] = {
            **values,
            "observedFraction": _fraction(values["observedSamples"], count),
            "partialFraction": _fraction(values["partialSamples"], count),
            "notObservedFraction": _fraction(values["notObservedSamples"], count),
            "observationStatus": "NOT_TESTED" if count == 0 or values["notObservedSamples"] == count else "PARTIAL_METADATA_ONLY" if values["partialSamples"] or values["notObservedSamples"] else "OBSERVED_METADATA_ONLY",
        }
    encoded = json.dumps(summary, ensure_ascii=True, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
    return {"sessionId": summary["sessionId"], "canonicalSummaryDigest": hashlib.sha256(encoded).hexdigest(),
            "evidenceProvenance": summary["evidenceProvenance"], "sampleCount": count,
            "captureStructure": summary["captureStructure"], "captureOutcome": summary["captureOutcome"],
            "completionCode": summary["completionCode"], "protocolIssueCount": len(summary["protocolIssues"]),
            "reviewHintCount": len(summary["reviewHints"]), "coverage": coverage}


def compare_summaries(summaries, *, comparison_scope):
    """Compare caller-ordered metadata; no chronology, account or device inference.

    Different provenance classes are rejected, not silently pooled. Session IDs
    and canonical digests are trace labels, not proof of independent collection.
    """
    if type(comparison_scope) is not str or comparison_scope not in SCOPES:
        raise SafeError("EXPLICIT_COMPARISON_SCOPE_REQUIRED")
    if type(summaries) is not list:
        raise SafeError("COMPARISON_SUMMARY_LIST_REQUIRED")
    if len(summaries) > MAX_SUMMARIES:
        raise SafeError("COMPARISON_SESSION_LIMIT")
    copies = _json_copy(summaries)
    encoded = json.dumps(copies, ensure_ascii=True, separators=(",", ":"), allow_nan=False).encode()
    if len(encoded) > MAX_JSON_BYTES:
        raise SafeError("COMPARISON_INPUT_BYTE_LIMIT")
    seen, sources = set(), set()
    for summary in copies:
        _validate(summary)
        session = summary["sessionId"]
        if session in seen:
            raise SafeError("COMPARISON_DUPLICATE_SESSION_REJECTED")
        seen.add(session)
        sources.add(summary["evidenceProvenance"])
    if len(sources) > 1:
        raise SafeError("COMPARISON_MIXED_EVIDENCE_PROVENANCE_REJECTED")
    views = [_view(summary) for summary in copies]
    differences = []
    for earlier, later in zip(views, views[1:]):
        coverage = {}
        for dimension in DIMENSIONS:
            first, second = earlier["coverage"][dimension], later["coverage"][dimension]
            coverage[dimension] = {key: second[key] - first[key] for key in COUNTS}
            a, b = first["observedFraction"], second["observedFraction"]
            coverage[dimension]["observedFractionDifference"] = round(b - a, 6) if a is not None and b is not None else None
        differences.append({"fromSessionId": earlier["sessionId"], "toSessionId": later["sessionId"],
                            "sampleCountDifference": later["sampleCount"] - earlier["sampleCount"],
                            "protocolIssueCountDifference": later["protocolIssueCount"] - earlier["protocolIssueCount"],
                            "reviewHintCountDifference": later["reviewHintCount"] - earlier["reviewHintCount"],
                            "captureStateChanged": (earlier["captureStructure"], earlier["captureOutcome"], earlier["completionCode"]) != (later["captureStructure"], later["captureOutcome"], later["completionCode"]),
                            "coverageCountDifferences": coverage})
    meaningful_sessions = sum(view["sampleCount"] > 0 for view in views)
    status = "NOT_TESTED" if len(views) < 2 or meaningful_sessions == 0 else "PARTIAL_METADATA_COMPARISON" if meaningful_sessions < 2 else "COMPARED_METADATA_ONLY"
    return {
        "schema": "hongai.passive-observation-comparison.v1", "status": status,
        "comparisonScope": comparison_scope, "declaredDistinctSessionCount": len(views),
        "evidenceProvenance": next(iter(sources)) if sources else "NO_INPUT_SUMMARIES",
        "provenanceGroupingPolicy": "MIXED_PROVENANCE_REJECTED",
        "inputOrderMeaning": "CALLER_SUPPLIED_ORDER_NOT_VERIFIED_CHRONOLOGY",
        "sameCaseRelationship": "OPERATOR_DECLARED_ONLY" if comparison_scope == "same_case_operator_declared" else "NOT_ASSUMED",
        "sameDeviceOrAccountAssumed": False, "independentCaptureVerified": False,
        "deviceContinuity": "NOT_ESTABLISHED", "accountContinuity": "NOT_ESTABLISHED",
        "crossSessionComparability": {
            "samplingInterval": "NOT_AVAILABLE_IN_ANALYSIS_SCHEMA",
            "windowDuration": "NOT_AVAILABLE_IN_ANALYSIS_SCHEMA",
            "utcOrderOrOverlap": "NOT_AVAILABLE_IN_ANALYSIS_SCHEMA",
            "sourceLogIdentity": "NOT_AVAILABLE_IN_ANALYSIS_SCHEMA",
            "canonicalSummaryDigestMeaning": "SUMMARY_CONTENT_TRACE_ONLY_NOT_SOURCE_LOG_ATTESTATION",
        },
        "codes": ["INSUFFICIENT_DISTINCT_SESSIONS"] if len(views) < 2 else ["NO_NONEMPTY_OBSERVATION_WINDOWS"] if meaningful_sessions == 0 else [],
        "sessions": views, "adjacentInputDifferences": differences,
        "observedCountMeaning": "OBSERVED_AND_EMPTY_GROUPED_BY_UPSTREAM_ANALYZER",
        "unmeasuredCoverage": dict(UNMEASURED_COVERAGE),
        "environmentScoreIssued": False, "coverageChangeMeansRiskImprovement": False,
        "accountRiskOrBanCauseInferred": False, "hardwareOrRegionInferred": False,
        "sourceLogPrivacyCertified": False, "officialClientReadCoverageCompleted": False,
        "fullEnvironmentAccepted": False, "customerReady": False,
    }
