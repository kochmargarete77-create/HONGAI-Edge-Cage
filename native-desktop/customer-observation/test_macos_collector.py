"""Synthetic parser/contract tests. Never execute the macOS collection commands."""

import contextlib
import importlib.util
import io
import json
from pathlib import Path
import sys
import unittest
from unittest import mock

spec = importlib.util.spec_from_file_location("readonly_macos_collector", Path(__file__).with_name("collect_readonly_macos.py"))
collector = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = collector
spec.loader.exec_module(collector)

PS = """  PID PPID COMM %CPU RSS
987654 1 /Applications/Claude.app/Contents/MacOS/Claude 15.5 1024
987655 987654 /Applications/Claude.app/Contents/Frameworks/Claude Helper (Renderer) 102.0 2048
987656 1 /Applications/Other.app/Contents/MacOS/cowork-svc 2.0 4096
987657 1 /Users/synthetic-secret-person/Library/verge-mihomo 0.4 1024
987658 1 /Applications/Clash Verge.app/Contents/MacOS/clash-verge 0.1 512
987659 1 /Applications/ToDesk.app/Contents/MacOS/ToDesk_Service 3.0 1024
987660 1 /Users/synthetic-secret-person/private-project-tool 1.0 512
"""
LSOF = """p987654
f10
tIPv4
n192.168.1.2:54321->8.8.8.8:443
TST=ESTABLISHED
f11
tIPv6
n[::1]:55111->[::ffff:192.168.1.3]:80
TST=ESTABLISHED
f12
tIPv4
n127.0.0.1:55000->198.18.0.8:443
TST=SYN_SENT
f13
tIPv6
n[::1]:55001->[fe80::1%en0]:52000
TST=ESTABLISHED
f14
tIPv4
n127.0.0.1:55002->synthetic-secret.example:443
TST=UNRECOGNIZED-PRIVATE-TEXT
p987660
f15
tIPv4
n192.168.1.2:60000->9.9.9.9:443
TST=ESTABLISHED
"""


class MacCollectorSyntheticTests(unittest.TestCase):
    def test_public_record_builders_require_explicit_synthetic_provenance(self):
        session, instant = "b" * 32, "2026-11-27T00:00:00.000Z"
        metadata = collector.parse_os_metadata("ProductVersion: 15.6\n", "Darwin 24.6.0 arm64\n")
        header = collector.make_header(session, instant, metadata, 300, 10, source="SYNTHETIC_FIXED_FIXTURE")
        self.assertTrue(header["synthetic"])
        self.assertEqual(header["source"], "SYNTHETIC_FIXED_FIXTURE")
        with self.assertRaises(collector.SafeError):
            collector.make_header(session, instant, metadata, 300, 10, source="UNKNOWN")
        processes = collector.parse_ps_output(PS).public_summary("SYNTHETIC_FIXED_FIXTURE")
        tcp = collector.parse_lsof_output(LSOF, [987654], "SYNTHETIC_FIXED_FIXTURE")
        sample = collector.make_sample(session, instant, 1, 0.0, processes, tcp)
        footer = collector.make_footer(session, instant, 1, 300.0, "WINDOW_COMPLETE")
        self.assertEqual([header["recordType"], sample["recordType"], footer["recordType"]], ["header", "sample", "footer"])
        self.assertTrue(all(record["sessionId"] == session and record["utcISO"] == instant for record in [header, sample, footer]))

    def test_named_role_cpu_memory_aggregates_do_not_export_process_metadata(self):
        observation = collector.parse_ps_output(PS)
        result = observation.public_summary("SYNTHETIC_FIXED_FIXTURE")
        self.assertEqual(result["status"], "OBSERVED")
        self.assertEqual(result["roles"]["claude"]["processCount"], 2)
        self.assertEqual(result["roles"]["claude"]["cpuPercent"], 117.5)
        self.assertEqual(result["roles"]["claude"]["workingSetBytesTotal"], 3072 * 1024)
        self.assertEqual(set(result["roles"]), set(collector.ROLES))
        self.assertEqual(observation.claude_pids, (987654, 987655))
        encoded = json.dumps(result)
        for secret in ("987654", "987655", "/Applications", "/Users", "synthetic-secret-person", "comm", "ppid"):
            self.assertNotIn(secret, encoded)

    def test_empty_partial_and_unobserved_are_distinct(self):
        self.assertEqual(collector.parse_ps_output("").public_summary("SYNTHETIC_FIXED_FIXTURE")["status"], "NOT_OBSERVED")
        self.assertEqual(collector.parse_ps_output("1 0 /usr/bin/unrelated 0.0 100\n").public_summary("SYNTHETIC_FIXED_FIXTURE")["status"], "EMPTY")
        self.assertEqual(collector.parse_ps_output(PS + "bad row\n").public_summary("SYNTHETIC_FIXED_FIXTURE")["status"], "PARTIAL")
        self.assertEqual(collector.parse_lsof_output("", [987654], "SYNTHETIC_FIXED_FIXTURE")["status"], "EMPTY")
        self.assertEqual(collector.parse_lsof_output(LSOF, [987654], "SYNTHETIC_FIXED_FIXTURE", "PARTIAL")["status"], "PARTIAL")

    def test_address_categories_handle_mapped_ipv6_and_special_ranges_without_dns(self):
        cases = {"[::ffff:192.168.1.2]:443": "private", "[::ffff:127.0.0.1]:80": "loopback",
                 "[fe80::1%en0]:9999": "linklocal", "100.64.1.2:443": "reserved_or_benchmark",
                 "198.19.1.2:443": "reserved_or_benchmark", "192.0.2.4:443": "reserved_or_benchmark",
                 "198.51.100.5:443": "reserved_or_benchmark", "203.0.113.8:443": "reserved_or_benchmark",
                 "[2001:db8::2]:443": "reserved_or_benchmark", "8.8.8.8:443": "public",
                 "synthetic-secret.example:80": "other"}
        for endpoint, expected in cases.items():
            with self.subTest(endpoint=endpoint):
                self.assertEqual(collector.remote_class(endpoint)[0], expected)

    def test_tcp_output_is_fixed_category_counts_filtered_to_in_memory_claude_pids(self):
        result = collector.parse_lsof_output(LSOF, [987654, 987655], "SYNTHETIC_FIXED_FIXTURE")
        self.assertEqual(result["connectionsCount"], 5)
        self.assertEqual(result["source"], "SYNTHETIC_FIXED_FIXTURE")
        self.assertTrue(any(item["state"] == "other" for item in result["categories"]))
        for item in result["categories"]:
            self.assertEqual(set(item), {"state", "ipVersion", "remotePortClass", "remoteAddressClass", "count"})
        encoded = json.dumps(result)
        for secret in ("987654", "192.168", "8.8.8.8", "198.18", "synthetic-secret", "55000", "en0"):
            self.assertNotIn(secret, encoded)

    def test_plan_path_and_command_boundaries_fail_closed(self):
        self.assertEqual(collector.plan(300, 10), 30)
        self.assertEqual(collector.plan(1800, 10), 180)
        for duration, interval in ((1801, 10), (300, 1), (300, 301), (True, 10)):
            with self.assertRaises(collector.SafeError):
                collector.plan(duration, interval)
        for path in ("/", "/System/project", "/private/tmp/project", "/Applications/project", "/Users", "/Volumes"):
            self.assertTrue(collector.blocked_macos_path(path))
        self.assertFalse(collector.blocked_macos_path("/Volumes/ApprovedDisk/Project"))
        with self.assertRaisesRegex(collector.SafeError, "C_DRIVE"):
            collector.validate_output_parent("C:\\SyntheticProject")
        self.assertTrue(collector.allowed_command(["/usr/sbin/lsof", "-nP", "-a", "-p", "1,2", "-iTCP", "-FpfntT", "-l"]))
        self.assertFalse(collector.allowed_command(["/usr/sbin/lsof", "-nP", "-a", "-p", "0", "-iTCP", "-FpfntT", "-l"]))
        for argv in (["/usr/bin/uname", "-a"], ["/bin/ps", "-axo", "args"], ["/usr/bin/curl", "https://example.invalid"]):
            self.assertFalse(collector.allowed_command(argv))

    def test_output_budget_rejects_next_record_without_truncation_or_disk_io(self):
        session = collector.ExclusiveSession.__new__(collector.ExclusiveSession)
        session.stream = io.BytesIO()
        session.bytes_written = collector.MAX_OUTPUT_BYTES - collector.SUMMARY_RESERVE
        self.assertFalse(session.sample({"source": "SYNTHETIC_FIXED_FIXTURE"}))
        self.assertEqual(session.stream.getvalue(), b"")

    def test_unavailable_command_and_non_macos_main_never_export_original_errors(self):
        with mock.patch.object(collector.subprocess, "Popen", side_effect=OSError("synthetic-secret-person 8.8.8.8 /Users/private")):
            result = collector.run_bounded(["/usr/bin/sw_vers"])
        self.assertEqual(result.status, "NOT_OBSERVED")
        self.assertEqual(result.stdout, "")
        self.assertNotIn("synthetic-secret", result.reason)
        output = io.StringIO()
        with mock.patch.object(collector.sys, "platform", "win32"), mock.patch.object(collector.subprocess, "Popen", side_effect=AssertionError("must not collect")), contextlib.redirect_stdout(output):
            self.assertEqual(collector.main([]), 2)
        self.assertEqual(json.loads(output.getvalue())["code"], "MACOS_REQUIRED_NOT_STARTED")

    def test_mocked_collection_contract_has_header_samples_footer_without_real_commands(self):
        class MemorySession:
            def __init__(self, parent):
                self.session_id, self.name = "a" * 32, "synthetic-session"
                self.records, self.saved_summary = [], None
                instances.append(self)
            def sample(self, value, reserve=0):
                self.records.append(value)
                return True
            def summary(self, value):
                self.saved_summary = value
            def close(self):
                pass
        instances, clock = [], [0.0]
        def command(argv, *args):
            self.assertTrue(collector.allowed_command(argv))
            value = "ProductVersion:\t15.6\n" if argv[0].endswith("sw_vers") else "Darwin 24.6.0 arm64\n" if argv[0].endswith("uname") else PS if argv[0].endswith("ps") else LSOF
            return collector.CommandResult("OBSERVED", "SYNTHETIC_COMMAND_FIXTURE", value, 0)
        with mock.patch.object(collector, "ExclusiveSession", MemorySession), mock.patch.object(collector, "run_bounded", side_effect=command), mock.patch.object(collector.time, "monotonic", side_effect=lambda: clock[0]), mock.patch.object(collector.time, "sleep", side_effect=lambda seconds: clock.__setitem__(0, clock[0] + seconds)), mock.patch.object(collector.subprocess, "Popen", side_effect=AssertionError("must not collect")):
            result = collector.collect(Path("/synthetic-approved-project"), 10, 10, evidence_source="SYNTHETIC_FIXED_FIXTURE")
        self.assertEqual(result["samplesWritten"], 1)
        records = instances[0].records
        self.assertEqual([item["recordType"] for item in records], ["header", "sample", "footer"])
        self.assertTrue(all(item["schema"] == "hongai.passive-observation.v1" and item["sessionId"] == "a" * 32 for item in records))
        self.assertTrue(records[0]["synthetic"])
        self.assertEqual(records[0]["source"], "SYNTHETIC_FIXED_FIXTURE")
        self.assertEqual(records[1]["processes"]["source"], "SYNTHETIC_FIXED_FIXTURE")
        self.assertEqual(records[1]["tcp"]["source"], "SYNTHETIC_FIXED_FIXTURE")
        self.assertEqual(records[-1]["elapsedSeconds"], 10)
        # Explicitly tag this generated fixture, never present it as live evidence.
        encoded = json.dumps({"source": "SYNTHETIC_FIXED_FIXTURE", "records": records})
        for secret in ("987654", "192.168", "8.8.8.8", "/Applications", "/Users", "synthetic-secret-person", "synthetic-secret.example"):
            self.assertNotIn(secret, encoded)
        # Feed real collector-built records to the shared analyzer, without
        # executing a native command or manufacturing an alternate log schema.
        analyzer_spec = importlib.util.spec_from_file_location("mac_collector_contract_analyzer", Path(__file__).with_name("analyse_observation.py"))
        analyzer = importlib.util.module_from_spec(analyzer_spec)
        analyzer_spec.loader.exec_module(analyzer)
        result = analyzer.summarize_bytes(("\n".join(json.dumps(item) for item in records) + "\n").encode())
        self.assertEqual(result["captureStructure"], "COMPLETE_RECORD_SEQUENCE")
        self.assertEqual(result["sampleCount"], 1)
        self.assertFalse(result["customerReady"])
        self.assertEqual(result["evidenceProvenance"], "SYNTHETIC_FIXED_FIXTURE")


if __name__ == "__main__":
    unittest.main()
