"""Synthetic contracts using actual passive collector builders and analyzer."""

import copy
import importlib.util
import json
from pathlib import Path
import sys
import unittest


def module(name, leaf):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(leaf))
    result = importlib.util.module_from_spec(spec)
    sys.modules[name] = result
    spec.loader.exec_module(result)
    return result


collector = module("comparison_fixture_collector", "collect_readonly_macos.py")
analyzer = module("comparison_fixture_analyzer", "analyse_observation.py")
comparison = module("comparison_module", "compare_observations.py")


def summary(session="a" * 32, statuses=("OBSERVED", "PARTIAL"), *, tcp_statuses=None, synthetic=True, complete=True, proxy_visible=True, bad_footer_count=False):
    # Source is explicit; no command, account, network request or host mutation.
    source = "SYNTHETIC_FIXED_FIXTURE" if synthetic else "READ_ONLY_LOCAL_COMMAND"
    metadata = collector.parse_os_metadata("ProductVersion: 15.6\n", "Darwin 24.6.0 arm64\n")
    records = [collector.make_header(session, "2026-11-28T00:00:00.000Z", metadata, 300, 10, source=source)]
    for index, status in enumerate(statuses):
        roles = {role: {"processCount": 1 if role == "claude" or (role == "clash" and proxy_visible) else 0} for role in collector.ROLES} if status != "NOT_OBSERVED" else {}
        processes = {"status": status, "roles": roles}
        tcp = {"status": (tcp_statuses or statuses)[index], "connectionsCount": 0, "categories": []}
        records.append(collector.make_sample(session, "2026-11-28T00:00:%02d.000Z" % (index * 10), index + 1, index * 10, processes, tcp))
    if complete:
        records.append(collector.make_footer(session, "2026-11-28T00:01:00.000Z", len(statuses) + int(bad_footer_count), 60, "WINDOW_COMPLETE"))
    return analyzer.summarize_bytes(("\n".join(json.dumps(record) for record in records) + "\n").encode())


class ObservationComparisonTests(unittest.TestCase):
    def test_real_analyzer_contract_compares_metadata_and_preserves_provenance(self):
        first = summary(statuses=("OBSERVED", "NOT_OBSERVED"))
        second = summary("b" * 32, statuses=("OBSERVED", "PARTIAL", "NOT_OBSERVED"))
        result = comparison.compare_summaries([first, second], comparison_scope="same_case_operator_declared")
        self.assertEqual(result["status"], "COMPARED_METADATA_ONLY")
        self.assertEqual(result["evidenceProvenance"], "SYNTHETIC_FIXED_FIXTURE")
        self.assertEqual(result["sessions"][0]["coverage"]["tcpMetadata"]["notObservedFraction"], 0.5)
        self.assertEqual(result["adjacentInputDifferences"][0]["coverageCountDifferences"]["tcpMetadata"]["partialSamples"], 1)
        self.assertEqual(result["sameCaseRelationship"], "OPERATOR_DECLARED_ONLY")
        self.assertFalse(result["sameDeviceOrAccountAssumed"])
        self.assertFalse(result["independentCaptureVerified"])
        self.assertEqual(result["deviceContinuity"], "NOT_ESTABLISHED")
        self.assertEqual(result["crossSessionComparability"]["utcOrderOrOverlap"], "NOT_AVAILABLE_IN_ANALYSIS_SCHEMA")
        self.assertFalse(result["customerReady"])
        self.assertEqual(result["inputOrderMeaning"], "CALLER_SUPPLIED_ORDER_NOT_VERIFIED_CHRONOLOGY")

    def test_scope_is_explicit_and_independent_sessions_imply_no_shared_identity(self):
        with self.assertRaises(TypeError):
            comparison.compare_summaries([])
        for scope in (None, "same_account", "same_machine", True):
            with self.assertRaises(comparison.SafeError):
                comparison.compare_summaries([], comparison_scope=scope)
        result = comparison.compare_summaries([summary(), summary("b" * 32)], comparison_scope="independent_sessions")
        self.assertEqual(result["sameCaseRelationship"], "NOT_ASSUMED")

    def test_same_input_or_same_session_never_counts_as_another_validation(self):
        original = summary()
        for duplicate in (original, copy.deepcopy(original)):
            with self.assertRaisesRegex(comparison.SafeError, "DUPLICATE_SESSION"):
                comparison.compare_summaries([original, duplicate], comparison_scope="independent_sessions")
        modified = copy.deepcopy(original)
        modified["reviewHints"] = []
        with self.assertRaisesRegex(comparison.SafeError, "DUPLICATE_SESSION"):
            comparison.compare_summaries([original, modified], comparison_scope="same_case_operator_declared")

    def test_different_evidence_sources_are_rejected_instead_of_silently_pooled(self):
        synthetic = summary()
        declared = summary("b" * 32, synthetic=False)
        unspecified = copy.deepcopy(declared)
        unspecified["sessionId"] = "c" * 32
        unspecified["evidenceProvenance"] = "UNSPECIFIED_SOURCE_NOT_OBSERVATION_PROOF"
        for pair in ([synthetic, declared], [declared, unspecified]):
            with self.assertRaisesRegex(comparison.SafeError, "MIXED_EVIDENCE_PROVENANCE"):
                comparison.compare_summaries(pair, comparison_scope="independent_sessions")

    def test_unobserved_empty_and_incomplete_windows_remain_unmeasured(self):
        for inputs in ([], [summary()], [summary(statuses=()), summary("b" * 32, statuses=())]):
            result = comparison.compare_summaries(inputs, comparison_scope="independent_sessions")
            self.assertEqual(result["status"], "NOT_TESTED")
        empty = summary(statuses=())
        partial = summary("b" * 32, statuses=("NOT_OBSERVED",), complete=False)
        result = comparison.compare_summaries([empty, partial], comparison_scope="same_case_operator_declared")
        self.assertEqual(result["status"], "PARTIAL_METADATA_COMPARISON")
        self.assertIsNone(result["sessions"][0]["coverage"]["tcpMetadata"]["observedFraction"])
        self.assertEqual(result["sessions"][1]["coverage"]["tcpMetadata"]["observationStatus"], "NOT_TESTED")
        self.assertEqual(result["sessions"][1]["captureOutcome"], "NOT_ESTABLISHED")

    def test_fewer_hints_and_better_coverage_are_not_a_risk_score_or_causal_claim(self):
        first = summary(proxy_visible=False, bad_footer_count=True)
        second = summary("b" * 32, statuses=("OBSERVED", "OBSERVED"), proxy_visible=True)
        result = comparison.compare_summaries([first, second], comparison_scope="same_case_operator_declared")
        difference = result["adjacentInputDifferences"][0]
        self.assertLess(difference["reviewHintCountDifference"], 0)
        self.assertLess(difference["protocolIssueCountDifference"], 0)
        for flag in ("environmentScoreIssued", "coverageChangeMeansRiskImprovement", "accountRiskOrBanCauseInferred", "hardwareOrRegionInferred", "fullEnvironmentAccepted"):
            self.assertFalse(result[flag])

    def test_unknown_schema_fields_scope_claims_and_inconsistent_counts_fail(self):
        original = summary()
        for mutate in (
            lambda value: value.update(schema="unknown.schema"),
            lambda value: value.update(extraField="SHOULD_NOT_BE_REEXPORTED"),
            lambda value: value.update(customerReady=True),
            lambda value: value.update(captureOutcome="COLLECTOR_LIMIT_REACHED"),
            lambda value: value["coverage"]["tcpMetadata"].update(observedSamples=180),
            lambda value: value.update(sampleCount=True),
            lambda value: value.update(sampleCount=float("nan")),
        ):
            value = copy.deepcopy(original)
            mutate(value)
            with self.assertRaises(comparison.SafeError):
                comparison.compare_summaries([value], comparison_scope="independent_sessions")

    def test_non_json_cycles_and_excessive_records_are_rejected_without_custom_hooks(self):
        class NotPlain(dict):
            def items(self):
                raise AssertionError("must not call custom hooks")
        for value in ([NotPlain(summary())], [object()], [b"raw"], "not-list"):
            with self.assertRaises(comparison.SafeError):
                comparison.compare_summaries(value, comparison_scope="independent_sessions")
        cycle = []
        cycle.append(cycle)
        with self.assertRaisesRegex(comparison.SafeError, "CYCLIC"):
            comparison.compare_summaries(cycle, comparison_scope="independent_sessions")
        with self.assertRaisesRegex(comparison.SafeError, "SESSION_LIMIT"):
            comparison.compare_summaries([summary()] * 33, comparison_scope="independent_sessions")
        with self.assertRaisesRegex(comparison.SafeError, "JSON_KEY_LIMIT"):
            comparison.compare_summaries([{"x" * 10000: None}], comparison_scope="independent_sessions")
        oversized = {"first": ["x" * 4096] * 650, "second": ["x" * 4096] * 650}
        with self.assertRaisesRegex(comparison.SafeError, "INPUT_BYTE_LIMIT"):
            comparison.compare_summaries([oversized], comparison_scope="independent_sessions")


if __name__ == "__main__":
    unittest.main()
