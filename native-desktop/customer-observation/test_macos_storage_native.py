"""macOS-only filesystem smoke test; no process enumeration or network commands."""
import json
import os
from pathlib import Path
import tempfile
import unittest
from collect_readonly_macos import ExclusiveSession, make_header, make_footer
from analyse_observation import summarize_bytes


class MacNativeStorageTests(unittest.TestCase):
    def test_native_exclusive_session_records_are_bounded_private_and_importable(self):
        self.assertEqual(os.uname().sysname, "Darwin", "This acceptance test requires a native Mac runner")
        base = Path(__file__).resolve().parent / "tmp"
        base.mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(dir=str(base)) as root:
            session = ExclusiveSession(Path(root))
            try:
                header = make_header(session.session_id, "2026-11-28T00:00:00.000Z", {"status": "NOT_OBSERVED"}, 10, 10, source="SYNTHETIC_FIXED_FIXTURE")
                footer = make_footer(session.session_id, "2026-11-28T00:00:10.000Z", 0, 10, "WINDOW_COMPLETE")
                self.assertTrue(session.sample(header))
                self.assertTrue(session.sample(footer))
                session.summary({"header": header, "footer": footer})
                directory = Path(root) / session.name
            finally:
                session.close()
            log = directory / "observation.ndjson"
            self.assertEqual(log.stat().st_mode & 0o777, 0o600)
            self.assertEqual(directory.stat().st_mode & 0o777, 0o700)
            result = summarize_bytes(log.read_bytes())
            self.assertEqual(result["evidenceProvenance"], "SYNTHETIC_FIXED_FIXTURE")
            self.assertEqual(result["reviewHints"][0]["code"], "NO_SAMPLES_REVIEW")
            self.assertEqual(set(item.name for item in directory.iterdir()), {"observation.ndjson", "summary.json"})


if __name__ == "__main__":
    unittest.main()
