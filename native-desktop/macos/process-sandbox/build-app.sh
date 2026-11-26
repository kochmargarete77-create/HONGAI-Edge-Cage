#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")"
destination="${1:-$PWD/build}"
mkdir -p "$destination"
destination="$(cd "$destination" && pwd)"
app="$destination/HONG AI CAGE Desktop.app"
mkdir -p "$app/Contents/MacOS" "$app/Contents/Resources" "$app/Contents/Helpers"
for architecture in arm64 x86_64; do
  xcrun swiftc -O -target "$architecture-apple-macos13.0" -framework AppKit -framework Network HongAICage.swift -o "$destination/cage-$architecture"
  xcrun clang -O2 -target "$architecture-apple-macos13.0" session.c -o "$destination/session-$architecture"
done
xcrun lipo -create "$destination/cage-arm64" "$destination/cage-x86_64" -output "$app/Contents/MacOS/HongAICage"
xcrun lipo -create "$destination/session-arm64" "$destination/session-x86_64" -output "$app/Contents/Helpers/CageSession"
cat > "$app/Contents/Info.plist" <<'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>CFBundleIdentifier</key><string>com.hongai.cage.desktop.pilot</string>
<key>CFBundleName</key><string>HONG AI CAGE Desktop</string>
<key>CFBundleExecutable</key><string>HongAICage</string>
<key>CFBundlePackageType</key><string>APPL</string>
<key>CFBundleShortVersionString</key><string>0.3.0</string>
<key>CFBundleVersion</key><string>7</string>
<key>LSMinimumSystemVersion</key><string>13.0</string>
<key>NSHighResolutionCapable</key><true/>
</dict></plist>
PLIST
/usr/bin/codesign --force --sign - "$app/Contents/Helpers/CageSession"
/usr/bin/codesign --force --sign - "$app"
/usr/bin/codesign --verify --strict "$app"
/usr/bin/lipo "$app/Contents/MacOS/HongAICage" -verify_arch arm64 x86_64
"$app/Contents/MacOS/HongAICage" --verify-policy > "$destination/runtime-policy.sb"
"$app/Contents/MacOS/HongAICage" --broker-self-test
"$app/Contents/MacOS/HongAICage" --storage-self-test
# Verify that the generated production profile is accepted by the real macOS sandbox parser.
/usr/bin/sandbox-exec -f "$destination/runtime-policy.sb" /usr/bin/true
package_root="$destination/package-root"
mkdir -p "$package_root/Applications"
/usr/bin/ditto "$app" "$package_root/Applications/HONG AI CAGE Desktop.app"
/usr/bin/pkgbuild --analyze --root "$package_root" "$destination/components.plist"
python3 - "$destination/components.plist" <<'PY'
import plistlib,sys
path=sys.argv[1]
with open(path,'rb') as source:
    components=plistlib.load(source)
for component in components:
    component['BundleIsRelocatable']=False
    component['BundleIsVersionChecked']=True
    component['BundleHasStrictIdentifier']=True
with open(path,'wb') as output:
    plistlib.dump(components,output)
PY
/usr/bin/pkgbuild --root "$package_root" --component-plist "$destination/components.plist" --install-location / --identifier com.hongai.cage.desktop.pilot --version 0.3.0 "$destination/HONGAI-CAGE-Desktop-macOS-Universal-PILOT.pkg"
/usr/bin/shasum -a 256 "$destination/HONGAI-CAGE-Desktop-macOS-Universal-PILOT.pkg" > "$destination/SHA256SUMS.txt"
printf '%s\n' 'AD_HOC_SIGNED=true' 'NOTARIZED=false' 'CUSTOMER_ACCEPTED=false' 'OFFICIAL_CLAUDE_REQUIRED=true' > "$destination/BUILD-STATUS.txt"
