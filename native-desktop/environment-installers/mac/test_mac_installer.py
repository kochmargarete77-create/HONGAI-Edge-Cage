"""Platform-neutral packaging guard tests; real package checks run on macOS."""

import argparse
import importlib.util
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock


spec = importlib.util.spec_from_file_location("mac_installer", Path(__file__).with_name("mac_installer.py"))
package = importlib.util.module_from_spec(spec)
spec.loader.exec_module(package)


class MacInstallerGuards(unittest.TestCase):
    def test_macho_minimum_is_highest_of_actual_universal_slices(self):
        def native_output(argv, **_):
            if argv[0].endswith("lipo"):
                return "x86_64 arm64\n"
            if "arm64" in argv:
                return "Load command 3\n cmd LC_BUILD_VERSION\n cmdsize 32\n platform 1\n minos 13.0\n sdk 15.0\n"
            return "Load command 2\n cmd LC_VERSION_MIN_MACOSX\n cmdsize 16\n version 12.0\n sdk 15.0\n"
        with mock.patch.object(package, "run", side_effect=native_output):
            archs, minima, minimum = package.mach_metadata(Path("/fixture/runtime"))
        self.assertEqual(set(archs), {"arm64", "x86_64"})
        self.assertEqual(minima, {"arm64": "13.0", "x86_64": "12.0"})
        self.assertEqual(minimum, "13.0")

    def test_thin_or_unknown_runtime_cannot_claim_dual_arch_support(self):
        for architectures in ("arm64\n", "x86_64\n", "arm64 x86_64 i386\n"):
            with self.subTest(architectures=architectures), mock.patch.object(package, "run", return_value=architectures):
                with self.assertRaisesRegex(RuntimeError, "UNIVERSAL_ARM64_X86_64_RUNTIME_REQUIRED"):
                    package.mach_metadata(Path("/fixture/runtime"))

    def test_install_requires_explicit_disposable_ci(self):
        with mock.patch.object(package, "native_only"), mock.patch.dict(os.environ, {"GITHUB_ACTIONS": "false"}):
            with self.assertRaisesRegex(RuntimeError, "EXPLICIT_DISPOSABLE_GITHUB_MAC_CI_NONROOT_USER_REQUIRED"):
                package.ci_install(argparse.Namespace(disposable_ci=True, manifest="/not/read"))

    def test_extra_payload_and_bad_hash_rejected_before_execution(self):
        root = os.environ.get("HONGAI_MAC_PACKAGE_TEST_ROOT")
        if not root:
            self.skipTest("HONGAI_MAC_PACKAGE_TEST_ROOT must select an explicit fixture directory")
        with tempfile.TemporaryDirectory(prefix="mac-installer-", dir=root) as raw:
            fixture = Path(raw)
            app = fixture / package.APP_NAME
            app.mkdir()
            (app / "unexpected-network-helper").write_text("fixture", encoding="utf-8")
            with mock.patch.object(package, "run", side_effect=AssertionError("native command must not run")):
                with self.assertRaisesRegex(RuntimeError, "APP_PAYLOAD_ALLOWLIST_MISMATCH"):
                    package.verify_bundle(app, {})
            runtime = fixture / "runtime"
            runtime.write_bytes(b"fixture only")
            output = fixture / "must-not-exist"
            with mock.patch.object(package, "native_only"):
                with self.assertRaisesRegex(RuntimeError, "INPUT_RUNTIME_SHA256_MISMATCH"):
                    package.build(argparse.Namespace(runtime=str(runtime), sha256="0" * 64,
                                                     version="1.0.0", output=str(output)))
            self.assertFalse(output.exists())


if __name__ == "__main__":
    unittest.main()
