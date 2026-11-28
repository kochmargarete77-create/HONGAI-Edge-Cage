import copy
import json
from pathlib import Path
import unittest

from activity_events import parse_activity_events, link_events, SafeError, SCHEMA, ENUMS, MAX_BYTES


SESSION = "a" * 32


def event(**changes):
    value = {"utcISO": "2026-11-28T00:00:05Z", "elapsedSeconds": 5,
             "kind": "chat", "source": "customer_reported", "result": "completed", "code": "NONE"}
    value.update(changes)
    return value


def annotations(events=None, **changes):
    value = {"schema": SCHEMA, "sessionId": SESSION, "events": [event()] if events is None else events}
    value.update(changes)
    return json.dumps(value).encode()


def observation_records():
    common = {"schema": "hongai.passive-observation.v1", "sessionId": SESSION}
    header = dict(common, recordType="header", utcISO="2026-11-28T00:00:00Z",
                  source="SYNTHETIC_FIXED_FIXTURE", synthetic=True,
                  limits={"durationSeconds": 20, "intervalSeconds": 10, "maxSamples": 180, "maxOutputBytes": 5242880})
    def sample(index, seconds):
        roles = {role: {"processCount": 0} for role in ("claude", "cowork", "mihomo", "clash", "todesk")}
        roles["claude"]["processCount"] = 1
        roles["mihomo"]["processCount"] = 1
        return dict(common, recordType="sample", sampleIndex=index, utcISO="2026-11-28T00:00:%02dZ" % seconds,
                    elapsedSeconds=seconds, processes={"status": "OBSERVED", "roles": roles},
                    tcp={"status": "NOT_OBSERVED", "connectionsCount": None, "categories": []})
    return [header, sample(1, 0), sample(2, 10), dict(common, recordType="footer", utcISO="2026-11-28T00:00:20Z", elapsedSeconds=20, samplesWritten=2, completionCode="DURATION_COMPLETE")]


def encode(records):
    return ("\n".join(json.dumps(record) for record in records) + "\n").encode()


class ActivityEventsTests(unittest.TestCase):
    def test_latest_template_is_accepted_and_metadata_is_not_exported(self):
        template = json.loads(Path(__file__).with_name("02-事件记录模板.json").read_bytes())
        template["sessionId"] = SESSION
        template["events"] = [event()]
        parsed = parse_activity_events(json.dumps(template).encode(), SESSION)
        self.assertEqual(set(parsed), {"schema", "sessionId", "events"})
        self.assertEqual(parsed["events"][0]["eventIndex"], 1)
        self.assertNotIn("instructions", json.dumps(parsed))
        template["instructions"] = "SYNTHETIC_IGNORED_TEMPLATE_METADATA_NOT_EXPORTED"
        self.assertNotIn(template["instructions"], json.dumps(parse_activity_events(json.dumps(template).encode(), SESSION)))

    def test_strict_event_fields_and_exact_enums_reject_private_free_text(self):
        for key in ("notes", "path", "url", "account", "prompt", "filename", "error", "payload", "processId"):
            with self.subTest(key=key), self.assertRaisesRegex(SafeError, "FIELDS_INVALID") as error:
                parse_activity_events(annotations([event(**{key: "SYNTHETIC_PRIVATE_NO_ECHO"})]), SESSION)
            self.assertNotIn("SYNTHETIC_PRIVATE_NO_ECHO", str(error.exception))
        for key in ENUMS:
            for invalid in ("UNRECOGNIZED_FIXED_LOOKING_CODE", "SYNTHETIC_PRIVATE_NO_ECHO", 1, None, ["chat"]):
                with self.subTest(key=key, invalid=invalid), self.assertRaisesRegex(SafeError, "ENUM_INVALID"):
                    parse_activity_events(annotations([event(**{key: invalid})]), SESSION)

    def test_duplicate_keys_nonfinite_numbers_depth_encoding_and_bounds_are_rejected(self):
        cases = [
            annotations().replace(b'"kind": "chat"', b'"kind":"chat","kind":"chat"'),
            annotations([event(elapsedSeconds=float("nan"))]),
            annotations([event(elapsedSeconds=float("inf"))]),
            annotations().replace(b'"elapsedSeconds": 5', b'"elapsedSeconds":1e999'),
            b"{\xff}", b"[" * 1500 + b"]" * 1500,
            b"x" * (MAX_BYTES + 1), annotations([event() for _ in range(201)]),
        ]
        for data in cases:
            with self.subTest(length=len(data)), self.assertRaises(SafeError):
                parse_activity_events(data, SESSION)
        self.assertEqual(len(parse_activity_events(annotations([event() for _ in range(200)]), SESSION)["events"]), 200)

    def test_sessions_and_template_metadata_remain_strict(self):
        for expected, data in (("b" * 32, annotations()), ("invalid", annotations()), (SESSION, annotations(sessionId="REPLACE_WITH_COLLECTOR_SESSION_ID")), (SESSION, annotations(extraPrivateField="SYNTHETIC_PRIVATE_NO_ECHO"))):
            with self.assertRaises(SafeError):
                parse_activity_events(data, expected)
        bad_fields = {name: sorted(values) for name, values in ENUMS.items()}
        bad_fields["source"].append("automatic_inference")
        with self.assertRaisesRegex(SafeError, "METADATA"):
            parse_activity_events(annotations(eventFields=bad_fields), SESSION)

    def test_utc_and_elapsed_validate_independently_and_preserve_seven_digit_precision(self):
        for invalid in ("2026-02-30T00:00:00Z", "2026-11-28T00:00:05+08:00", "2026-11-28 00:00:05", "2026-11-28T00:00:60Z"):
            with self.assertRaisesRegex(SafeError, "UTC_INVALID"):
                parse_activity_events(annotations([event(utcISO=invalid)]), SESSION)
        for invalid in (-1, True, "5", 1901, 10**500, None):
            with self.assertRaisesRegex(SafeError, "ELAPSED"):
                parse_activity_events(annotations([event(elapsedSeconds=invalid)]), SESSION)
        parsed = parse_activity_events(annotations([event(utcISO="2026-11-28T00:00:05.1234567+00:00")]), SESSION)
        self.assertEqual(parsed["events"][0]["utcISO"], "2026-11-28T00:00:05.1234567Z")

    def test_valid_events_link_only_to_bounded_nearby_sample_indices_without_causality(self):
        result = link_events(encode(observation_records()), annotations())
        item = result["events"][0]
        self.assertEqual(item["alignmentStatus"], "ALIGNED_BOTH_CLOCKS")
        self.assertEqual(item["clockAgreement"], "EXACT")
        self.assertEqual(item["nearbySampleIndices"], [1, 2])
        self.assertFalse(result["mcpInvocationVerified"])
        self.assertFalse(result["accountRiskOrBanCauseInferred"])
        self.assertFalse(result["fullEnvironmentAccepted"])

    def test_utc_only_event_has_explicit_weaker_alignment_not_an_invented_elapsed_time(self):
        value = event(source="visible_ui", code="LOGIN_SCREEN_SHOWN", kind="visible_error", result="unknown")
        del value["elapsedSeconds"]
        item = link_events(encode(observation_records()), annotations([value]))["events"][0]
        self.assertEqual(item["alignmentStatus"], "ALIGNED_UTC_ONLY")
        self.assertEqual(item["clockAgreement"], "UTC_ONLY")
        self.assertEqual(item["elapsedWindowStatus"], "NOT_PROVIDED")
        self.assertNotIn("elapsedSeconds", item)

    def test_outside_window_and_conflicting_clocks_are_not_clamped_or_attached(self):
        values = [event(utcISO="2026-11-28T00:00:21Z", elapsedSeconds=21), event(utcISO="2026-11-28T00:00:05Z", elapsedSeconds=19)]
        result = link_events(encode(observation_records()), annotations(values))
        for original, linked in zip(values, result["events"]):
            self.assertEqual(linked["alignmentStatus"], "NOT_ALIGNED")
            self.assertEqual(linked["nearbySampleIndices"], [])
            self.assertEqual(linked["utcISO"], original["utcISO"])
            self.assertEqual(linked["elapsedSeconds"], original["elapsedSeconds"])
        self.assertEqual(result["events"][0]["utcWindowStatus"], "OUTSIDE_WINDOW")
        self.assertEqual(result["events"][1]["clockAgreement"], "MISMATCH")

    def test_declared_clock_tolerance_reports_difference_instead_of_rewriting_time(self):
        value = event(utcISO="2026-11-28T00:00:05.2500000Z")
        item = link_events(encode(observation_records()), annotations([value]))["events"][0]
        self.assertEqual(item["clockAgreement"], "WITHIN_DECLARED_TOLERANCE")
        self.assertEqual(item["utcElapsedDifferenceSeconds"], 0.25)
        self.assertEqual(item["utcISO"], value["utcISO"])

    def test_partial_capture_clock_reversal_and_protocol_issues_block_automatic_linking(self):
        partial = observation_records()[:-1]
        reversed_utc = observation_records(); reversed_utc[2]["utcISO"] = "2026-11-27T23:59:59Z"
        shifted_clock = observation_records(); shifted_clock[2]["utcISO"] = "2026-11-28T00:00:15Z"
        mismatched_count = observation_records(); mismatched_count[-1]["samplesWritten"] = 1
        for records in (partial, reversed_utc, shifted_clock, mismatched_count):
            with self.subTest(records=len(records)):
                result = link_events(encode(records), annotations())
                self.assertEqual(result["events"][0]["alignmentStatus"], "NOT_ALIGNED")
                self.assertTrue(result["alignmentIssues"])
                self.assertEqual(result["events"][0]["nearbySampleIndices"], [])

    def test_sparse_sample_radius_is_bounded_and_empty_annotations_do_not_claim_no_activity(self):
        records = observation_records(); records[0]["limits"]["intervalSeconds"] = 1800
        records[-1]["utcISO"] = "2026-11-28T00:03:00Z"; records[-1]["elapsedSeconds"] = 180
        item = link_events(encode(records), annotations([event(utcISO="2026-11-28T00:02:00Z", elapsedSeconds=120)]))["events"][0]
        self.assertEqual(item["nearbySampleIndices"], [])
        self.assertEqual(item["nearbySampleStatus"], "NO_SAMPLE_WITHIN_DECLARED_RADIUS")
        result = link_events(encode(observation_records()), annotations([]))
        self.assertEqual(result["annotationsStatus"], "NO_EVENT_ANNOTATIONS_NOT_NO_ACTIVITY")

    def test_actual_observation_validator_runs_and_private_unknown_log_fields_are_not_echoed(self):
        records = observation_records(); records[1]["customerPrivateField"] = "SYNTHETIC_PRIVATE_NO_ECHO"
        result = link_events(encode(records), annotations())
        self.assertNotIn("SYNTHETIC_PRIVATE_NO_ECHO", json.dumps(result))
        records[0]["schema"] = "not-observation"
        with self.assertRaisesRegex(SafeError, "LOG_SCHEMA"):
            link_events(encode(records), annotations())
        with self.assertRaisesRegex(SafeError, "SESSION_MISMATCH"):
            link_events(encode(observation_records()), annotations(sessionId="b" * 32))

    def test_before_first_sample_has_no_monotonic_anchor_and_is_not_attached(self):
        records = observation_records()
        records[1]["utcISO"] = "2026-11-28T00:00:10Z"
        records[2]["utcISO"] = "2026-11-28T00:00:20Z"
        records[-1]["utcISO"] = "2026-11-28T00:00:30Z"
        before_first = event(); del before_first["elapsedSeconds"]
        after_first = event(utcISO="2026-11-28T00:00:15Z", elapsedSeconds=5)
        result = link_events(encode(records), annotations([before_first, after_first]))
        early, later = result["events"]
        self.assertEqual(early["utcWindowStatus"], "IN_WINDOW")
        self.assertEqual(early["sampleWindowStatus"], "BEFORE_FIRST_SAMPLE")
        self.assertEqual(early["alignmentStatus"], "NOT_ALIGNED")
        self.assertEqual(early["nearbySampleIndices"], [])
        self.assertIn("EVENT_PRECEDES_FIRST_OBSERVED_SAMPLE_NO_ALIGNMENT", early["alignmentCodes"])
        self.assertEqual(result["observationWindow"]["earliestSampleUtcISO"], "2026-11-28T00:00:10Z")
        self.assertEqual(result["observationWindow"]["headerElapsedAnchor"], "NOT_RECORDED")
        self.assertEqual(later["alignmentStatus"], "ALIGNED_BOTH_CLOCKS")
        self.assertEqual(result["alignmentIssues"], [])


if __name__ == "__main__":
    unittest.main()
