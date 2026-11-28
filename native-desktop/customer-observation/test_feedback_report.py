import copy
import hashlib
import json
import os
from pathlib import Path
import tempfile
import subprocess
import sys
import unittest
from feedback_report import build_feedback,render_feedback,write_feedback,SafeError
from test_activity_events import observation_records,encode,annotations,event


class FeedbackReportTests(unittest.TestCase):
    def test_actual_log_event_and_comparison_modules_build_a_single_snapshot_report(self):
        raw=encode(observation_records())
        bundle=build_feedback([raw],event_bytes=annotations())
        self.assertEqual(bundle["inputDigests"][0]["sha256"],hashlib.sha256(raw).hexdigest())
        self.assertEqual(bundle["activityAlignment"]["eventCount"],1)
        self.assertFalse(bundle["fullEnvironmentAccepted"])
        self.assertIn("合成样例",render_feedback(bundle))

    def test_comparison_uses_distinct_sessions_and_duplicate_bytes_never_count_twice(self):
        raw=encode(observation_records())
        with self.assertRaisesRegex(SafeError,"DUPLICATE"):
            build_feedback([raw,raw])
        other=observation_records()
        for record in other:record["sessionId"]="b"*32
        bundle=build_feedback([raw,encode(other)],comparison_scope="same_case_operator_declared")
        self.assertEqual(bundle["comparison"]["declaredDistinctSessionCount"],2)
        self.assertFalse(bundle["comparison"]["sameDeviceOrAccountAssumed"])

    def test_html_is_offline_and_unknown_private_fields_are_not_rendered(self):
        records=observation_records()
        records[1]["privateNote"]='<img src="https://example.invalid/private" onerror="alert(1)">'
        bundle=build_feedback([encode(records)])
        page=render_feedback(bundle)
        self.assertNotIn("example.invalid",page)
        self.assertNotIn("<script",page)
        self.assertNotIn("<img",page)
        self.assertIn("default-src 'none'",page)
        self.assertIn("HONG AI",page)
        self.assertNotIn("score",page.lower())

    def test_report_does_not_accept_claimed_environment_success_or_edited_comparison(self):
        bundle=build_feedback([encode(observation_records())])
        changed=copy.deepcopy(bundle);changed["fullEnvironmentAccepted"]=True
        with self.assertRaisesRegex(SafeError,"SCOPE_CLAIM"):
            render_feedback(changed)
        changed=copy.deepcopy(bundle);changed["comparison"]["environmentScoreIssued"]=True
        with self.assertRaisesRegex(SafeError,"COMPARISON_MISMATCH"):
            render_feedback(changed)

    def test_output_rejects_unknown_private_fields_even_when_added_after_analysis(self):
        bundle=build_feedback([encode(observation_records())],event_bytes=annotations())
        changed=copy.deepcopy(bundle);changed["privateRawPayload"]="SYNTHETIC_PRIVATE_DO_NOT_EXPORT"
        with self.assertRaisesRegex(SafeError,"FIELDS_INVALID"):
            render_feedback(changed)
        changed=copy.deepcopy(bundle);changed["activityAlignment"]["events"][0]["filename"]="SYNTHETIC_PRIVATE_DO_NOT_EXPORT"
        with self.assertRaisesRegex(SafeError,"FIELDS_INVALID"):
            render_feedback(changed)

    def test_unknown_diagnostic_text_cannot_be_smuggled_into_a_saved_report(self):
        bundle=build_feedback([encode(observation_records())])
        bundle["primaryAnalysis"]["protocolIssues"]=[{"code":"SYNTHETIC_PRIVATE_CONTENT"}]
        bundle["primaryAnalysis"]["captureStructure"]="INCOMPLETE_OR_INCONSISTENT_RECORD_SEQUENCE"
        from compare_observations import compare_summaries
        bundle["comparison"]=compare_summaries([bundle["primaryAnalysis"]],comparison_scope="independent_sessions")
        with self.assertRaisesRegex(SafeError,"DIAGNOSTIC_CODE_UNKNOWN"):
            render_feedback(bundle)

    def test_real_cli_generates_report_using_one_read_snapshot_per_input(self):
        root=Path(__file__).resolve().parent/"tmp";root.mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(dir=str(root)) as parent:
            parent=Path(parent)
            raw=encode(observation_records());(parent/"first.ndjson").write_bytes(raw)
            other=observation_records()
            for item in other:item["sessionId"]="b"*32
            (parent/"second.ndjson").write_bytes(encode(other))
            (parent/"events.json").write_bytes(annotations())
            command=[sys.executable,"-B",str(Path(__file__).with_name("feedback_report.py")),"--log",str(parent/"first.ndjson"),"--events",str(parent/"events.json"),"--compare-log",str(parent/"second.ndjson"),"--comparison-scope","same_case_operator_declared","--output-parent",str(parent)]
            completed=subprocess.run(command,cwd=str(Path(__file__).parent),capture_output=True,timeout=8,check=False)
            self.assertEqual(completed.returncode,0,completed.stdout.decode())
            result=json.loads(completed.stdout)
            self.assertEqual(result["status"],"OFFLINE_FEEDBACK_CREATED")
            saved=json.loads((parent/result["relativeDirectory"]/"analysis.json").read_bytes())
            self.assertEqual(saved["inputDigests"][0]["sha256"],hashlib.sha256(raw).hexdigest())
            self.assertEqual(saved["activityAlignment"]["eventCount"],1)
            self.assertEqual(saved["comparison"]["declaredDistinctSessionCount"],2)
            self.assertNotIn(str(parent),json.dumps(saved))
    def test_outside_events_stay_unaligned_and_missing_events_do_not_mean_no_activity(self):
        bundle=build_feedback([encode(observation_records())],event_bytes=annotations([event(utcISO="2026-11-28T00:01:00Z",elapsedSeconds=60)]))
        self.assertIn("未对齐",render_feedback(bundle))
        page=render_feedback(build_feedback([encode(observation_records())]))
        self.assertIn("不能解释为没有聊天",page)

    def test_private_report_outputs_are_new_bounded_and_manifest_hashes_match(self):
        root=Path(__file__).resolve().parent/"tmp";root.mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(dir=str(root)) as parent:
            bundle=build_feedback([encode(observation_records())])
            a=write_feedback(parent,bundle);b=write_feedback(parent,bundle)
            self.assertNotEqual(a["relativeDirectory"],b["relativeDirectory"])
            directory=Path(parent)/a["relativeDirectory"]
            self.assertEqual(set(p.name for p in directory.iterdir()),{"analysis.json","report.html","manifest.json"})
            manifest=json.loads((directory/"manifest.json").read_bytes())
            for item in manifest["files"]:
                self.assertEqual(hashlib.sha256((directory/item["file"]).read_bytes()).hexdigest(),item["sha256"])


if __name__=="__main__":unittest.main()
