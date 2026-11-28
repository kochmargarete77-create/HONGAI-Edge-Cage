import json
from pathlib import Path
import tempfile
import unittest
from analyse_observation import summarize_bytes, read_bounded, SafeError, SCHEMA


def fixtures():
    common = {"schema": SCHEMA, "sessionId": "a"*32}
    header = dict(common, recordType="header", utcISO="2026-11-28T00:00:00Z", synthetic=True, source="SYNTHETIC_FIXED_FIXTURE", limits={"intervalSeconds": 10})
    def sample(index, seconds, claude=1, proxy=1, status="OBSERVED"):
        roles = {role: {"processCount": 0} for role in ("claude", "cowork", "mihomo", "clash", "todesk")}
        roles["claude"]["processCount"] = claude
        roles["mihomo"]["processCount"] = proxy
        return dict(common, recordType="sample", sampleIndex=index, utcISO="2026-11-28T00:00:%02dZ" % seconds, elapsedSeconds=seconds,
                    processes={"status": status, "roles": roles}, tcp={"status": "NOT_OBSERVED", "connectionsCount": None, "categories": []})
    return [header, sample(1, 0), sample(2, 10), dict(common, recordType="footer", utcISO="2026-11-28T00:00:11Z", samplesWritten=2, completionCode="WINDOW_COMPLETE")]


def encode(records):
    return ("\n".join(json.dumps(record) for record in records)+"\n").encode()


class AnalysisTests(unittest.TestCase):
    def test_header_footer_and_sample_windows_are_validated_even_without_events(self):
        records=fixtures()
        records[0]["utcISO"]="2026-11-28T00:00:02Z"
        result=summarize_bytes(encode(records))
        self.assertIn({"code":"SAMPLE_OUTSIDE_DECLARED_UTC_WINDOW","sampleIndex":1},result["protocolIssues"])
        records=fixtures();records[-1]["utcISO"]="2026-11-27T23:59:59Z"
        self.assertIn({"code":"HEADER_FOOTER_UTC_ORDER_INVALID"},summarize_bytes(encode(records))["protocolIssues"])

    def test_footer_elapsed_window_cannot_finish_before_an_observed_sample(self):
        records=fixtures();records[-1]["elapsedSeconds"]=5
        result=summarize_bytes(encode(records))
        self.assertIn({"code":"SAMPLE_AFTER_DECLARED_ELAPSED_WINDOW","sampleIndex":2},result["protocolIssues"])
        self.assertEqual(result["captureStructure"],"INCOMPLETE_OR_INCONSISTENT_RECORD_SEQUENCE")

    def test_source_conflicts_cannot_upgrade_synthetic_data_to_customer_observation(self):
        records = fixtures()
        records[0]["synthetic"] = False
        with self.assertRaisesRegex(SafeError, "PROVENANCE_CONFLICT"):
            summarize_bytes(encode(records))
        records = fixtures()
        records[1]["tcp"]["source"] = "READ_ONLY_LOCAL_COMMAND"
        with self.assertRaisesRegex(SafeError, "PROVENANCE_CONFLICT"):
            summarize_bytes(encode(records))
        records = fixtures(); del records[0]["source"]
        self.assertEqual(summarize_bytes(encode(records))["evidenceProvenance"], "UNSPECIFIED_SOURCE_NOT_OBSERVATION_PROOF")

    def test_empty_labels_with_nonzero_counts_are_protocol_issues_not_full_coverage(self):
        records = fixtures()
        records[1]["processes"]["status"] = "EMPTY"
        records[1]["tcp"] = {"status":"EMPTY", "connectionsCount":1,"categories":[{"count":1}]}
        report = summarize_bytes(encode(records))
        self.assertEqual(report["captureStructure"], "INCOMPLETE_OR_INCONSISTENT_RECORD_SEQUENCE")
        self.assertEqual(report["coverage"]["processNameRoles"]["notObservedSamples"],1)
        self.assertEqual(report["coverage"]["tcpMetadata"]["notObservedSamples"],2)
        self.assertEqual(len(report["protocolIssues"]),2)

    def test_complete_metadata_never_certifies_hardware_routes_or_accounts(self):
        result = summarize_bytes(encode(fixtures()))
        self.assertEqual(result["captureStructure"], "COMPLETE_RECORD_SEQUENCE")
        self.assertEqual(result["coverage"]["tcpMetadata"]["notObservedSamples"], 2)
        self.assertFalse(result["officialClientReadCoverageCompleted"])
        self.assertFalse(result["fullEnvironmentAccepted"])
        self.assertEqual(result["evidenceProvenance"], "SYNTHETIC_FIXED_FIXTURE")
        self.assertEqual(result["reviewHints"], [])

    def test_missing_footer_and_partial_visibility_are_not_success_or_zero_activity(self):
        records = fixtures()[:-1]
        records[1]["processes"]["status"] = "PARTIAL"
        result = summarize_bytes(encode(records))
        self.assertEqual(result["captureStructure"], "INCOMPLETE_OR_INCONSISTENT_RECORD_SEQUENCE")
        self.assertEqual(result["coverage"]["processNameRoles"]["partialSamples"], 1)

    def test_unknown_process_counts_remain_unknown_after_permission_failure(self):
        records = fixtures()
        records[1]["processes"]["status"] = "NOT_OBSERVED"
        for metrics in records[1]["processes"]["roles"].values():
            metrics["processCount"] = None
        result = summarize_bytes(encode(records))
        self.assertEqual(result["coverage"]["processNameRoles"]["notObservedSamples"], 1)
        self.assertEqual(result["reviewHints"], [])

    def test_role_disappearance_is_a_review_hint_and_not_a_leak_or_ban_cause(self):
        records = fixtures()
        records[2]["processes"]["roles"]["mihomo"]["processCount"] = 0
        result = summarize_bytes(encode(records))
        self.assertEqual(result["reviewHints"][0]["code"], "PROXY_NAME_ROLE_NOT_VISIBLE_WHILE_APP_ROLE_VISIBLE")
        self.assertFalse(result["accountRiskOrBanCauseInferred"])

    def test_corrupt_sequences_and_counts_do_not_produce_a_closed_environment_claim(self):
        records = fixtures()
        records[-1]["samplesWritten"] = 1
        records[2]["elapsedSeconds"] = 0
        result = summarize_bytes(encode(records))
        self.assertIn({"code": "FOOTER_SAMPLE_COUNT_DISAGREES"}, result["protocolIssues"])
        self.assertFalse(result["fullEnvironmentAccepted"])
        records[2]["sampleIndex"] = 7
        with self.assertRaisesRegex(SafeError, "SEQUENCE"):
            summarize_bytes(encode(records))

    def test_duplicate_json_members_mixed_sessions_and_nonfinite_values_are_rejected(self):
        records = fixtures()
        bad = encode(records).replace(b'"recordType": "header"', b'"recordType":"sample","recordType":"header"', 1)
        with self.assertRaisesRegex(SafeError, "DUPLICATE"):
            summarize_bytes(bad)
        records[2]["sessionId"] = "b"*32
        with self.assertRaisesRegex(SafeError, "MIXED_SESSIONS"):
            summarize_bytes(encode(records))
        records = fixtures(); records[1]["elapsedSeconds"] = float("nan")
        with self.assertRaisesRegex(SafeError, "NONFINITE"):
            summarize_bytes(encode(records))

    def test_unknown_private_input_is_not_echoed_or_certified(self):
        records = fixtures()
        records[1]["unselectedPrivateText"] = "SYNTHETIC_PRIVATE_CUSTOMER_NOTE_123456"
        result = summarize_bytes(encode(records))
        self.assertNotIn("SYNTHETIC_PRIVATE_CUSTOMER_NOTE_123456", json.dumps(result))
        self.assertFalse(result["sourceLogPrivacyCertified"])

    def test_failed_footer_does_not_turn_structure_into_a_completed_capture(self):
        records = fixtures()
        records[-1]["completionCode"] = "COLLECTOR_FAILED_FIXED_CODE_NO_RAW_ERROR"
        result = summarize_bytes(encode(records))
        self.assertEqual(result["captureStructure"], "COMPLETE_RECORD_SEQUENCE")
        self.assertEqual(result["captureOutcome"], "COLLECTOR_STOPPED_EARLY")
        self.assertEqual(result["completionCode"], "COLLECTOR_FAILED_FIXED_CODE_NO_RAW_ERROR")
        records = [records[0], records[-1]]; records[-1]["samplesWritten"] = 0
        self.assertEqual(summarize_bytes(encode(records))["reviewHints"][0]["code"], "NO_SAMPLES_REVIEW")

    def test_input_and_record_budgets_and_file_reader_are_bounded(self):
        with self.assertRaisesRegex(SafeError, "BYTE_LIMIT"):
            summarize_bytes(b"x"*(5*1024*1024+1))
        with self.assertRaisesRegex(SafeError, "RECORD_LIMIT"):
            summarize_bytes(b"\n"*183)
        base = Path(__file__).resolve().parent / "tmp"
        base.mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(dir=str(base)) as root:
            file = Path(root)/"fixture.ndjson"
            file.write_bytes(encode(fixtures()))
            self.assertEqual(summarize_bytes(read_bounded(str(file)))["sampleCount"], 2)


if __name__ == "__main__":
    unittest.main()
