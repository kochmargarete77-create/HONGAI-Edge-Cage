#!/usr/bin/env python3
"""Offline native macOS packaging; never changes host network or Claude.

Build/verify only need Apple build tools and Python 3. Customer runtime does not.
The optional install smoke command is explicitly restricted to disposable CI.
"""

import argparse
import datetime
import hashlib
import html
import json
import os
from pathlib import Path
import platform
import plistlib
import re
import stat
import struct
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET
import zlib


APP_NAME = "HONG AI Environment.app"
APP_ID = "com.hongai.environment.workbench"
PKG_ID = APP_ID + ".pkg"
EXECUTABLE = "hongai-environment"
COMPONENT = "HONGAI-Environment-component.pkg"
ALLOWED_APP_FILES = {
    "Contents/Info.plist", "Contents/PkgInfo", "Contents/MacOS/" + EXECUTABLE,
    "Contents/Resources/HONGAI.icns", "Contents/_CodeSignature/CodeResources",
}


def fail(code):
    raise RuntimeError(code)


def run(argv, allowed=(0,)):
    result = subprocess.run([str(x) for x in argv], stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT, text=True, timeout=180)
    if result.returncode not in allowed:
        # Build evidence may include paths, but contains no account/proxy secrets.
        fail("COMMAND_FAILED: " + str(argv[0]) + "\n" + result.stdout[-6000:])
    return result.stdout


def native_only():
    if sys.platform != "darwin":
        fail("NATIVE_MACOS_BUILD_OR_VERIFICATION_REQUIRED")


def digest(path):
    h = hashlib.sha256()
    with open(path, "rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def real_input(raw):
    path = Path(raw).expanduser()
    if not path.is_absolute() or path.is_symlink() or not path.is_file():
        fail("ABSOLUTE_REGULAR_INPUT_REQUIRED")
    # Parent symlinks are intentionally rejected for predictable build evidence.
    if path.absolute() != path.resolve():
        fail("INPUT_PATH_CONTAINS_SYMLINK_OR_DOT_COMPONENT")
    return path


def new_output(raw):
    path = Path(raw).expanduser()
    if not path.is_absolute() or path.exists() or path.is_symlink():
        fail("NEW_ABSOLUTE_OUTPUT_DIRECTORY_REQUIRED")
    parent = path.parent.resolve(strict=True)
    if path.parent != parent or not parent.is_dir():
        fail("OUTPUT_PARENT_MUST_BE_EXISTING_REAL_DIRECTORY")
    path.mkdir(mode=0o700)
    return path


def check_tree(root):
    if root.is_symlink() or not root.is_dir():
        fail("REAL_DIRECTORY_REQUIRED: " + str(root))
    for path in root.rglob("*"):
        if path.is_symlink() or not (path.is_dir() or path.is_file()):
            fail("UNEXPECTED_LINK_OR_SPECIAL_FILE: " + str(path))


def mach_metadata(binary):
    archs = run(["/usr/bin/lipo", "-archs", binary]).strip().split()
    if set(archs) != {"arm64", "x86_64"} or len(archs) != 2:
        fail("UNIVERSAL_ARM64_X86_64_RUNTIME_REQUIRED")
    minima = {}
    for arch in sorted(archs):
        dump = run(["/usr/bin/otool", "-arch", arch, "-l", binary])
        current = None
        for line in dump.splitlines():
            fields = line.strip().split()
            if len(fields) == 2 and fields[0] == "cmd":
                current = fields[1]
            if len(fields) == 2 and ((current == "LC_BUILD_VERSION" and fields[0] == "minos") or
                                     (current == "LC_VERSION_MIN_MACOSX" and fields[0] == "version")):
                if not re.fullmatch(r"[0-9]+(?:\.[0-9]+){1,2}", fields[1]):
                    fail("MACHO_MINIMUM_OS_INVALID")
                minima[arch] = fields[1]
        if arch not in minima:
            fail("MACHO_MINIMUM_OS_NOT_FOUND: " + arch)
    minimum = max(minima.values(), key=lambda x: tuple(int(n) for n in x.split(".")))
    return archs, minima, minimum


def png_chunk(kind, content):
    return struct.pack(">I", len(content)) + kind + content + struct.pack(">I", zlib.crc32(kind + content) & 0xffffffff)


def icon_png(size):
    # Code-native red HONG AI mark: no external assets or Claude trademark reuse.
    rows = bytearray()
    for y in range(size):
        rows.append(0)
        for x in range(size):
            u, v = x / size, y / size
            rounded = (0.08 <= u <= 0.92 and 0.08 <= v <= 0.92 and
                       (0.18 <= u <= 0.82 or 0.18 <= v <= 0.82 or
                        ((u - (0.18 if u < .5 else .82)) ** 2 +
                         (v - (0.18 if v < .5 else .82)) ** 2) <= .1 ** 2))
            h = (.27 <= u <= .38 or .62 <= u <= .73) and .27 <= v <= .73
            h = h or (.37 <= u <= .63 and .45 <= v <= .55)
            rows.extend((255, 255, 255, 255) if h else ((192, 29, 47, 255) if rounded else (0, 0, 0, 0)))
    return (b"\x89PNG\r\n\x1a\n" + png_chunk(b"IHDR", struct.pack(">IIBBBBB", size, size, 8, 6, 0, 0, 0)) +
            png_chunk(b"IDAT", zlib.compress(bytes(rows), 9)) + png_chunk(b"IEND", b""))


def make_icon(stage, target):
    iconset = stage / "HONGAI.iconset"
    iconset.mkdir()
    for base in (16, 32, 128, 256, 512):
        for scale in (1, 2):
            suffix = "@2x" if scale == 2 else ""
            (iconset / ("icon_%dx%d%s.png" % (base, base, suffix))).write_bytes(icon_png(base * scale))
    run(["/usr/bin/iconutil", "-c", "icns", "-o", target, iconset])


def document(title, text):
    return ("<!doctype html><html><meta charset='utf-8'><title>" + html.escape(title) +
            "</title><style>body{font:14px -apple-system,Arial;line-height:1.65;padding:18px;color:#232329}"
            "h1{color:#b81e35;font-size:24px}p{margin:12px 0}</style><h1>" + html.escape(title) +
            "</h1>" + "".join("<p>" + html.escape(p) + "</p>" for p in text) + "</html>\n")


def write_json(path, value):
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def build(args):
    native_only()
    source = real_input(args.runtime)
    if not re.fullmatch(r"[a-fA-F0-9]{64}", args.sha256) or digest(source) != args.sha256.lower():
        fail("INPUT_RUNTIME_SHA256_MISMATCH")
    if not re.fullmatch(r"[0-9]{1,4}\.[0-9]{1,4}\.[0-9]{1,6}", args.version):
        fail("NUMERIC_THREE_COMPONENT_VERSION_REQUIRED")
    icon_source = real_input(args.icon) if getattr(args, "icon", None) else None
    if icon_source:
        header = icon_source.read_bytes()
        if len(header) < 8 or len(header) > 8 * 1024 * 1024 or header[:4] != b"icns" or struct.unpack(">I", header[4:8])[0] != len(header):
            fail("VALID_ICNS_ICON_REQUIRED")
    archs, minima, minimum = mach_metadata(source)
    out = new_output(args.output)
    stage = out / "build-evidence"
    stage.mkdir(mode=0o700)
    payload = stage / "payload"
    app = payload / APP_NAME
    for directory in (app / "Contents/MacOS", app / "Contents/Resources"):
        directory.mkdir(parents=True)
    executable = app / "Contents/MacOS" / EXECUTABLE
    # ditto retains source xattrs including com.apple.quarantine, if present.
    run(["/usr/bin/ditto", "--rsrc", "--extattr", source, executable])
    executable.chmod(0o755)
    info = {
        "CFBundleDevelopmentRegion": "en", "CFBundleDisplayName": "HONG AI Environment",
        "CFBundleName": "HONG AI Environment", "CFBundleIdentifier": APP_ID,
        "CFBundleExecutable": EXECUTABLE, "CFBundlePackageType": "APPL",
        "CFBundleShortVersionString": args.version, "CFBundleVersion": args.version,
        "CFBundleIconFile": "HONGAI.icns", "LSMinimumSystemVersion": minimum,
        "LSBackgroundOnly": True, "NSHighResolutionCapable": True,
        "NSHumanReadableCopyright": "HONG AI. Independent environment preparation workbench.",
    }
    (app / "Contents/Info.plist").write_bytes(plistlib.dumps(info))
    (app / "Contents/PkgInfo").write_bytes(b"APPL????")
    icon_target = app / "Contents/Resources/HONGAI.icns"
    if icon_source:
        run(["/usr/bin/ditto", "--rsrc", "--extattr", icon_source, icon_target])
    else:
        make_icon(stage, icon_target)
    # Do not inherit a restrictive CI umask into an admin-owned /Applications
    # payload: standard customers must be able to traverse/read their own app.
    for directory in [app] + [p for p in app.rglob("*") if p.is_dir()]:
        directory.chmod(0o755)
    for file in [p for p in app.rglob("*") if p.is_file()]:
        file.chmod(0o755 if file == executable else 0o644)
    # Ad-hoc integrity only; not a Developer ID, notarization, or Gatekeeper approval.
    run(["/usr/bin/codesign", "--force", "--sign", "-", "--timestamp=none", app])
    (app / "Contents/_CodeSignature").chmod(0o755)
    (app / "Contents/_CodeSignature/CodeResources").chmod(0o644)
    run(["/usr/bin/codesign", "--verify", "--deep", "--strict", app])
    resources = stage / "resources"
    resources.mkdir()
    texts = {
        "Welcome.html": ("HONG AI Environment", [
            "Native preparation and diagnostic workbench for macOS. The official Claude app keeps its original installation, signature and normal update path.",
            "This package installs only HONG AI Environment.app into /Applications. It does not install Claude, change networking, remove sessions or install a login/background service."]),
        "ReadMe.html": ("Before installation", [
            "This pilot package is unsigned and not notarized. Its app has an ad-hoc integrity signature only. Normal macOS approval may be required; no protection setting or quarantine marker is removed.",
            "Close the HONG AI workbench using its Stop control before upgrading. Keep any required Clash service and remote support connection running. The installer never launches a user process.",
            "After installation, open HONG AI Environment from Applications. Initial setup and diagnostics open in the default browser. A saved, validated setup can request normal activation of the official Claude desktop app.",
            "The management interface is a local browser workbench, not a replacement Claude UI, a hardware simulator, a virtual machine or system-wide outbound firewall."]),
        "Conclusion.html": ("Installation complete", [
            "Open /Applications/HONG AI Environment.app yourself as your normal user. The installer does not sign into Claude or initialize customer data as administrator.",
            "User data is created at ~/Library/Application Support/HONGAI-Environment. macOS Keychain prompts may appear during customer-side initialization. Official Claude account/session data is not modified.",
            "No account-level acceptance or ban-prevention guarantee is included. Package integrity and installation acceptance are separate from customer login and workflow acceptance."]),
    }
    for name, (title, paragraphs) in texts.items():
        (resources / name).write_text(document(title, paragraphs), encoding="utf-8")
    component_plist = stage / "component.plist"
    run(["/usr/bin/pkgbuild", "--analyze", "--root", payload, component_plist])
    components = plistlib.loads(component_plist.read_bytes())
    if len(components) != 1 or components[0].get("RootRelativeBundlePath") != APP_NAME:
        fail("UNEXPECTED_COMPONENT_ANALYSIS")
    components[0].update({"BundleIsRelocatable": False, "BundleHasStrictIdentifier": True,
                          "BundleVersionChecked": True, "BundleOverwriteAction": "upgrade"})
    component_plist.write_bytes(plistlib.dumps(components))
    run(["/usr/bin/pkgbuild", "--root", payload, "--component-plist", component_plist,
         "--identifier", PKG_ID, "--version", args.version, "--ownership", "recommended",
         "--install-location", "/Applications", stage / COMPONENT])
    distribution = stage / "Distribution.xml"
    distribution.write_text("""<?xml version="1.0" encoding="utf-8"?>
<installer-gui-script minSpecVersion="2">
  <title>HONG AI Environment</title>
  <welcome file="Welcome.html"/><readme file="ReadMe.html"/><conclusion file="Conclusion.html"/>
  <options customize="never" require-scripts="false" hostArchitectures="arm64,x86_64"/>
  <domains enable_anywhere="false" enable_currentUserHome="false" enable_localSystem="true"/>
  <volume-check><allowed-os-versions><os-version min="%s"/></allowed-os-versions></volume-check>
  <choices-outline><line choice="workbench"/></choices-outline>
  <choice id="workbench" visible="false"><pkg-ref id="%s"/></choice>
  <pkg-ref id="%s" version="%s" onConclusion="none">%s</pkg-ref>
</installer-gui-script>
""" % (minimum, PKG_ID, PKG_ID, args.version, COMPONENT), encoding="utf-8")
    package = out / ("HONGAI-Environment-macOS-" + args.version + "-unsigned.pkg")
    run(["/usr/bin/productbuild", "--distribution", distribution, "--resources", resources,
         "--package-path", stage, package])
    final_app = out / APP_NAME
    run(["/usr/bin/ditto", "--rsrc", "--extattr", app, final_app])
    zip_path = out / ("HONGAI-Environment-macOS-" + args.version + "-app.zip")
    run(["/usr/bin/ditto", "-c", "-k", "--sequesterRsrc", "--keepParent", final_app, zip_path])
    manifest = {
        "schema": "hongai.macos-installer.v1", "version": args.version,
        "scope": "PREPARATION_DIAGNOSTIC_FRONTEND", "createdUTC": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "buildHost": {"system": platform.system(), "release": platform.release(), "machine": platform.machine()},
        "runtimeInputSHA256": digest(source), "bundledRuntimeSHA256": digest(final_app / "Contents/MacOS" / EXECUTABLE),
        "appIconSHA256": digest(icon_target), "appIconSource": "SUPPLIED_ICNS" if icon_source else "GENERATED_RED_H_MARK",
        "architectures": sorted(archs), "minimumOSByArchitecture": minima, "minimumOS": minimum,
        "appName": APP_NAME, "appIdentifier": APP_ID, "packageIdentifier": PKG_ID,
        "packageFile": package.name, "packageSHA256": digest(package),
        "appZipFile": zip_path.name, "appZipSHA256": digest(zip_path),
        "packageSigned": False, "appSignature": "AD_HOC_INTEGRITY_ONLY", "notarized": False,
        "officialClaudeBundled": False, "hostNetworkModified": False, "accountDataBundled": False,
        "postinstallRunsUserProcess": False, "loginItemInstalled": False,
        "hardwareSimulation": False, "nativeAllEgressEnforcement": False,
        "authenticatedBusinessAccepted": False, "fullEnvironmentAccepted": False,
        "nativePackageInstallation": "NOT_RUN", "interactiveGatekeeperApproval": "NOT_RUN",
    }
    write_json(out / "installer-manifest.json", manifest)
    verify_bundle(final_app, manifest)
    verify_package(package, manifest, stage)
    print(json.dumps({"status": "BUILT_AND_STATICALLY_VERIFIED_INSTALL_NOT_RUN", "output": str(out)}, ensure_ascii=False))


def verify_bundle(app, manifest):
    check_tree(app)
    actual = {p.relative_to(app).as_posix() for p in app.rglob("*") if p.is_file()}
    if actual != ALLOWED_APP_FILES:
        fail("APP_PAYLOAD_ALLOWLIST_MISMATCH: " + repr(sorted(actual)))
    info = plistlib.loads((app / "Contents/Info.plist").read_bytes())
    expected = {"CFBundleIdentifier": APP_ID, "CFBundleExecutable": EXECUTABLE,
                "CFBundleVersion": manifest["version"], "CFBundleShortVersionString": manifest["version"],
                "LSMinimumSystemVersion": manifest["minimumOS"], "LSBackgroundOnly": True}
    if any(info.get(k) != v for k, v in expected.items()):
        fail("APP_METADATA_MISMATCH")
    binary = app / "Contents/MacOS" / EXECUTABLE
    if digest(binary) != manifest["bundledRuntimeSHA256"] or not os.access(binary, os.X_OK):
        fail("APP_EXECUTABLE_HASH_OR_MODE_MISMATCH")
    if stat.S_IMODE(binary.stat().st_mode) != 0o755:
        fail("APP_EXECUTABLE_MODE_MUST_BE_0755")
    if digest(app / "Contents/Resources/HONGAI.icns") != manifest["appIconSHA256"]:
        fail("APP_ICON_SHA256_MISMATCH")
    archs, minima, minimum = mach_metadata(binary)
    if sorted(archs) != manifest["architectures"] or minima != manifest["minimumOSByArchitecture"] or minimum != manifest["minimumOS"]:
        fail("APP_MACHO_METADATA_MISMATCH")
    run(["/usr/bin/codesign", "--verify", "--deep", "--strict", app])
    signature = run(["/usr/bin/codesign", "-d", "--verbose=4", app])
    if "Signature=adhoc" not in signature or "TeamIdentifier=not set" not in signature:
        fail("APP_EXPECTED_ADHOC_SIGNATURE_NOT_FOUND")


def verify_component_reference(distribution, version):
    """Accept only our embedded component, before/after productbuild normalization.

    productbuild prefixes embedded payload references with '#' and appends a
    separate same-ID pkg-ref/bundle-version record. Neither is a remote URL.
    """
    top_refs = distribution.findall("pkg-ref")
    definitions = [ref for ref in top_refs if (ref.text or "").strip()]
    if len(definitions) != 1:
        fail("PACKAGE_COMPONENT_REFERENCE_MISMATCH")
    definition = definitions[0]
    if (definition.get("id") != PKG_ID or definition.get("version") != version or
            definition.text.strip() not in (COMPONENT, "#" + COMPONENT) or len(definition)):
        fail("PACKAGE_COMPONENT_REFERENCE_MISMATCH")
    metadata_count = 0
    for ref in distribution.findall(".//pkg-ref"):
        if ref.get("id") != PKG_ID:
            fail("PACKAGE_COMPONENT_REFERENCE_MISMATCH")
        if ref is definition:
            continue
        if (ref.text or "").strip() or ref.attrib != {"id": PKG_ID}:
            fail("PACKAGE_COMPONENT_REFERENCE_MISMATCH")
        if ref in top_refs:
            metadata_count += 1
            if metadata_count > 1 or len(ref) != 1 or ref[0].tag != "bundle-version" or len(ref[0]) != 1:
                fail("PACKAGE_COMPONENT_METADATA_MISMATCH")
            bundle = ref[0][0]
            expected = {"CFBundleShortVersionString": version, "CFBundleVersion": version,
                        "id": APP_ID, "path": APP_NAME}
            if bundle.tag != "bundle" or bundle.attrib != expected or len(bundle):
                fail("PACKAGE_COMPONENT_METADATA_MISMATCH")
        elif len(ref):
            fail("PACKAGE_COMPONENT_REFERENCE_MISMATCH")


def verify_package(package, manifest, evidence):
    if package.is_symlink() or not package.is_file():
        fail("REGULAR_PACKAGE_FILE_REQUIRED")
    if digest(package) != manifest["packageSHA256"]:
        fail("PACKAGE_SHA256_MISMATCH")
    # A flat productbuild package without a Signature XAR member is unsigned.
    entries = run(["/usr/bin/xar", "-tf", package]).splitlines()
    if any(p.startswith("/") or ".." in p.split("/") for p in entries):
        fail("PACKAGE_ARCHIVE_PATH_INVALID")
    if any("signature" in p.lower().split("/") for p in entries):
        fail("UNEXPECTED_PACKAGE_SIGNATURE_MEMBER")
    signature_check = run(["/usr/sbin/pkgutil", "--check-signature", package], allowed=(0, 1))
    (evidence / "pkgutil-signature.txt").write_text(signature_check, encoding="utf-8")
    expanded = Path(tempfile.mkdtemp(prefix="verify-package-", dir=str(evidence))) / "expanded"
    run(["/usr/sbin/pkgutil", "--expand-full", package, expanded])
    check_tree(expanded)
    distribution = ET.parse(expanded / "Distribution").getroot()
    if distribution.findall(".//script") or distribution.findall(".//installation-check"):
        fail("PACKAGE_DISTRIBUTION_MUST_NOT_EXECUTE_SCRIPTS")
    domains = distribution.find("domains")
    if domains is None or domains.attrib != {"enable_anywhere": "false", "enable_currentUserHome": "false", "enable_localSystem": "true"}:
        fail("PACKAGE_DOMAIN_MUST_BE_LOCAL_SYSTEM_ONLY")
    options = distribution.find("options")
    if options is None or options.get("require-scripts") != "false":
        fail("PACKAGE_SCRIPTS_POLICY_INVALID")
    verify_component_reference(distribution, manifest["version"])
    pkg = expanded / COMPONENT
    info = ET.parse(pkg / "PackageInfo").getroot()
    if info.get("identifier") != PKG_ID or info.get("version") != manifest["version"] or info.get("install-location") != "/Applications":
        fail("PACKAGE_INSTALL_LOCATION_OR_IDENTITY_MISMATCH")
    if info.find("scripts") is not None or (pkg / "Scripts").exists():
        fail("PACKAGE_INSTALL_SCRIPTS_FORBIDDEN")
    payload = pkg / "Payload"
    if {p.name for p in payload.iterdir()} != {APP_NAME}:
        fail("PACKAGE_PAYLOAD_MUST_ONLY_CONTAIN_OWN_APP")
    verify_bundle(payload / APP_NAME, manifest)


def load_manifest(path):
    raw = real_input(path)
    manifest = json.loads(raw.read_text(encoding="utf-8"))
    if manifest.get("schema") != "hongai.macos-installer.v1" or manifest.get("packageSigned") is not False or manifest.get("notarized") is not False:
        fail("MANIFEST_SCOPE_OR_SIGNING_MISMATCH")
    for name in ("packageFile", "appZipFile"):
        if not isinstance(manifest.get(name), str) or Path(manifest[name]).name != manifest[name]:
            fail("MANIFEST_ARTIFACT_NAME_INVALID")
    return raw.parent, manifest


def verify(args):
    native_only()
    base, manifest = load_manifest(args.manifest)
    evidence = Path(tempfile.mkdtemp(prefix="verification-", dir=str(base)))
    verify_bundle(base / APP_NAME, manifest)
    verify_package(base / manifest["packageFile"], manifest, evidence)
    archive = base / manifest["appZipFile"]
    if archive.is_symlink() or not archive.is_file() or digest(archive) != manifest["appZipSHA256"]:
        fail("APP_ZIP_SHA256_MISMATCH")
    extracted = evidence / "zip-expanded"
    run(["/usr/bin/ditto", "-x", "-k", archive, extracted])
    check_tree(extracted)
    if {p.name for p in extracted.iterdir()} != {APP_NAME}:
        fail("APP_ZIP_MUST_ONLY_CONTAIN_OWN_APP")
    verify_bundle(extracted / APP_NAME, manifest)
    report = {"status": "STATIC_VERIFICATION_PASS", "packageInstallation": "NOT_RUN",
              "interactiveGatekeeperApproval": "NOT_RUN", "customerLogin": "NOT_RUN"}
    write_json(evidence / "verification.json", report)
    print(json.dumps(report))


def ci_install(args):
    native_only()
    if not args.disposable_ci or os.environ.get("GITHUB_ACTIONS") != "true" or os.geteuid() == 0:
        fail("EXPLICIT_DISPOSABLE_GITHUB_MAC_CI_NONROOT_USER_REQUIRED")
    base, manifest = load_manifest(args.manifest)
    installed = Path("/Applications") / APP_NAME
    user_data = Path.home() / "Library/Application Support/HONGAI-Environment"
    if installed.exists() or installed.is_symlink() or user_data.exists():
        fail("CI_REQUIRES_NO_EXISTING_HONGAI_APP_OR_DATA")
    existing_receipt = subprocess.run(["/usr/sbin/pkgutil", "--pkg-info", PKG_ID],
                                      stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    if existing_receipt.returncode == 0:
        fail("CI_REQUIRES_NO_EXISTING_HONGAI_PACKAGE_RECEIPT")
    # Verify before any privileged action. This script never starts `use` or Claude.
    verify(args)
    # A data sentinel is created as the normal CI user, in the original default
    # location. Installation, update and own-app removal must leave it unchanged.
    user_data.mkdir(mode=0o700)
    sentinel = user_data / "PACKAGE_INSTALL_SCOPE_SENTINEL.txt"
    sentinel.write_text("Fixture only; no account/configuration data.\n", encoding="utf-8")
    sentinel.chmod(0o600)
    sentinel_hash = digest(sentinel)
    sentinel_uid = sentinel.stat().st_uid

    def check_sentinel():
        if user_data.is_symlink() or sentinel.is_symlink() or digest(sentinel) != sentinel_hash or sentinel.stat().st_uid != sentinel_uid:
            fail("PACKAGE_OPERATION_CHANGED_INDEPENDENT_USER_DATA")

    log = run(["/usr/bin/sudo", "-n", "/usr/sbin/installer", "-pkg", base / manifest["packageFile"], "-target", "/"])
    (base / "ci-installer.txt").write_text(log, encoding="utf-8")
    verify_bundle(installed, manifest)
    version = run([installed / "Contents/MacOS" / EXECUTABLE, "version"])
    json.loads(version)
    check_sentinel()
    receipt = run(["/usr/sbin/pkgutil", "--pkg-info-plist", PKG_ID])
    info = plistlib.loads(receipt.encode())
    if info.get("pkg-version") != manifest["version"]:
        fail("INSTALLED_RECEIPT_VERSION_MISMATCH")
    # Build a real next-version package from the same already verified runtime.
    # Different CFBundleVersion and CodeResources ensure this is an app upgrade,
    # not a repeated extraction of the same payload.
    numbers = [int(n) for n in manifest["version"].split(".")]
    numbers[-1] += 1
    next_version = ".".join(str(n) for n in numbers)
    upgrade_output = base / "ci-upgrade-package"
    build(argparse.Namespace(runtime=str(base / APP_NAME / "Contents/MacOS" / EXECUTABLE),
                             sha256=manifest["bundledRuntimeSHA256"], version=next_version,
                             icon=str(base / APP_NAME / "Contents/Resources/HONGAI.icns"),
                             output=str(upgrade_output)))
    upgrade_base, upgrade_manifest = load_manifest(upgrade_output / "installer-manifest.json")
    upgrade_log = run(["/usr/bin/sudo", "-n", "/usr/sbin/installer", "-pkg",
                       upgrade_base / upgrade_manifest["packageFile"], "-target", "/"])
    (base / "ci-upgrade.txt").write_text(upgrade_log, encoding="utf-8")
    verify_bundle(installed, upgrade_manifest)
    json.loads(run([installed / "Contents/MacOS" / EXECUTABLE, "version"]))
    check_sentinel()
    upgraded_receipt = plistlib.loads(run(["/usr/sbin/pkgutil", "--pkg-info-plist", PKG_ID]).encode())
    if upgraded_receipt.get("pkg-version") != next_version:
        fail("UPGRADE_RECEIPT_VERSION_MISMATCH")
    # Recoverable own-app removal; no customer/application data deletion. The
    # ephemeral runner is disposed by CI. Never use this command on a real Mac.
    recovery = base / "ci-uninstall-recovery"
    recovery.mkdir(mode=0o700)
    run(["/usr/bin/sudo", "-n", "/bin/mv", installed, recovery / APP_NAME])
    run(["/usr/bin/sudo", "-n", "/usr/sbin/pkgutil", "--forget", PKG_ID])
    if installed.exists():
        fail("OWN_APP_UNINSTALL_INCOMPLETE")
    verify_bundle(recovery / APP_NAME, upgrade_manifest)
    check_sentinel()
    report = {"status": "NATIVE_PACKAGE_INSTALL_UPGRADE_RECOVERABLE_UNINSTALL_PASS", "architecture": platform.machine(),
              "officialClaudeLaunched": False, "customerDataInitialized": False,
              "interactiveGatekeeperApproval": "NOT_RUN", "customerLogin": "NOT_RUN",
              "independentDataRootSentinel": "UNCHANGED_SAME_USER_AND_DIRECTORY",
              "installedVersion": manifest["version"], "upgradedVersion": next_version,
              "recoveredApp": str(recovery / APP_NAME), "receiptIdentifier": PKG_ID}
    write_json(base / "ci-install-report.json", report)
    print(json.dumps(report))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    b = commands.add_parser("build")
    b.add_argument("--runtime", required=True, help="absolute path to tested universal Go runtime")
    b.add_argument("--sha256", required=True, help="trusted runtime artifact SHA-256")
    b.add_argument("--version", required=True, help="numeric X.Y.Z; increase for every new customer build")
    b.add_argument("--output", required=True, help="new absolute output directory; parent must exist")
    b.add_argument("--icon", help="optional absolute trusted branded .icns file; copied before final signing")
    b.set_defaults(action=build)
    v = commands.add_parser("verify")
    v.add_argument("--manifest", required=True)
    v.set_defaults(action=verify)
    c = commands.add_parser("ci-install")
    c.add_argument("--manifest", required=True)
    c.add_argument("--disposable-ci", action="store_true")
    c.set_defaults(action=ci_install)
    args = parser.parse_args()
    try:
        args.action(args)
    except (RuntimeError, OSError, ValueError, subprocess.TimeoutExpired) as error:
        print(str(error), file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
