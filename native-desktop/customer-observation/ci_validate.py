"""Run fixture-only observer validation; never start live customer collection."""
import argparse
import io
import json
import os
from pathlib import Path
import platform
import sys
import unittest
from analyse_observation import read_bounded, summarize_bytes


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--windows-fixture")
    args = parser.parse_args()
    root = Path(__file__).resolve().parent
    if os.name == "nt" and root.drive.upper() not in {"D:", "E:"}:
        raise RuntimeError("PROJECT_DATA_DRIVE_REQUIRED")
    expected = os.environ.get("HONGAI_OBSERVER_EXPECT_PLATFORM")
    if expected and sys.platform != expected:
        raise RuntimeError("NATIVE_RUNNER_PLATFORM_MISMATCH")
    actual_arch = {"amd64":"x64", "x86_64":"x64", "arm64":"arm64", "aarch64":"arm64"}.get(platform.machine().lower(), "unknown")
    if os.environ.get("HONGAI_OBSERVER_EXPECT_ARCH", actual_arch) != actual_arch:
        raise RuntimeError("NATIVE_RUNNER_ARCHITECTURE_MISMATCH")
    temporary, output = root/"tmp", root/"out"
    temporary.mkdir(exist_ok=True); output.mkdir(exist_ok=True)
    for key in ("TEMP", "TMP", "TMPDIR"):
        os.environ[key] = str(temporary)
    loader = unittest.TestLoader()
    names = ["test_observation_analysis", "test_macos_collector"]
    if sys.platform == "darwin":
        names.append("test_macos_storage_native")
    suite = unittest.TestSuite(loader.loadTestsFromName(name) for name in names)
    stream = io.StringIO()
    result = unittest.TextTestRunner(stream=stream, verbosity=2).run(suite)
    expected_count = 19 if sys.platform == "darwin" else 18
    accepted = result.wasSuccessful() and result.testsRun == expected_count and not result.skipped
    fixture_verified = False
    if sys.platform == "win32":
        if not args.windows_fixture:
            accepted = False
        else:
            report = summarize_bytes(read_bounded(args.windows_fixture))
            fixture_verified = report["evidenceProvenance"] == "SYNTHETIC_FIXED_FIXTURE" and report["sampleCount"] == 2 and report["captureStructure"] == "COMPLETE_RECORD_SEQUENCE" and report["coverage"]["tcpMetadata"]["notObservedSamples"] == 1 and report["fullEnvironmentAccepted"] is False
            accepted = accepted and fixture_verified
    (output/"tests.txt").write_text(stream.getvalue(), encoding="utf-8")
    summary = {"schema":"hongai.passive-observer-validation.v1", "sourceCommit":os.environ.get("GITHUB_SHA"), "result":"PASS" if accepted else "FAIL", "executionHost":{"platform":sys.platform,"architecture":platform.machine(),"python":platform.python_version()}, "unitTests":result.testsRun,"failures":len(result.failures),"errors":len(result.errors),"skipped":len(result.skipped),"source":"SYNTHETIC_FIXED_FIXTURE", "windowsFixtureVerified":fixture_verified,"nativeMacFilesystemTestExecuted":sys.platform=="darwin","processOrTcpLiveCollectionExecuted":False,"accountDataRead":False,"hostNetworkChanged":False,"fullEnvironmentAccepted":False}
    (output/"validation.json").write_text(json.dumps(summary,indent=2)+"\n",encoding="utf-8")
    print(json.dumps(summary))
    if not accepted:
        print(stream.getvalue(), end="")
    return 0 if accepted else 1


if __name__ == "__main__":
    sys.exit(main())
