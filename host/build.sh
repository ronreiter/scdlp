#!/usr/bin/env bash
set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
DIST="$REPO/dist"
APP="$DIST/scdlp.app"
EXT_SRC="$DIST/Scdlp.systemextension"
SIGN_ID="${SCDLP_SIGN_ID:--}"

if [[ ! -d "$EXT_SRC" ]]; then
    echo "error: $EXT_SRC missing — run extension/build.sh first" >&2
    exit 1
fi

# 1. Compile the Swift host.
echo "==> building scdlp-host"
mkdir -p "$DIST"
swiftc -O -target x86_64-apple-macos13 -o "$DIST/scdlp-host" "$REPO/host/main.swift"
# Universal binary: also build arm64 and lipo. (Skip on Intel-only build hosts.)
if /usr/bin/arch -arm64 true 2>/dev/null; then
    swiftc -O -target arm64-apple-macos13 -o "$DIST/scdlp-host-arm64" "$REPO/host/main.swift"
    lipo -create "$DIST/scdlp-host" "$DIST/scdlp-host-arm64" -output "$DIST/scdlp-host.fat"
    mv "$DIST/scdlp-host.fat" "$DIST/scdlp-host"
    rm "$DIST/scdlp-host-arm64"
fi

# 2. Lay out the .app bundle.
echo "==> assembling $APP"
rm -rf "$APP"
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources" "$APP/Contents/Library/SystemExtensions"
cp "$REPO/host/Info.plist" "$APP/Contents/Info.plist"
mv "$DIST/scdlp-host" "$APP/Contents/MacOS/scdlp-host"
chmod +x "$APP/Contents/MacOS/scdlp-host"

# 3. Embed the extension.
cp -R "$EXT_SRC" "$APP/Contents/Library/SystemExtensions/"

# 4. Sign the host (the extension was signed in extension/build.sh).
echo "==> codesigning host"
codesign --force --options runtime --timestamp=none \
    --sign "$SIGN_ID" \
    --entitlements "$REPO/host/Scdlp.entitlements" \
    "$APP/Contents/MacOS/scdlp-host"
codesign --force --options runtime --timestamp=none \
    --sign "$SIGN_ID" \
    --entitlements "$REPO/host/Scdlp.entitlements" \
    "$APP"

echo "==> done: $APP"
echo "==> activate with: $APP/Contents/MacOS/scdlp-host activate"
