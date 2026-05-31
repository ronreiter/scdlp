#!/usr/bin/env bash
set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
DIST="$REPO/dist"
APP="$DIST/scdlp-helper.app"
SIGN_ID="${SCDLP_SIGN_ID:--}"

echo "==> building scdlp-helper"
mkdir -p "$DIST"
swiftc -O -target x86_64-apple-macos13 -o "$DIST/scdlp-helper" "$REPO/helper/main.swift"
if /usr/bin/arch -arm64 true 2>/dev/null; then
    swiftc -O -target arm64-apple-macos13 -o "$DIST/scdlp-helper-arm64" "$REPO/helper/main.swift"
    lipo -create "$DIST/scdlp-helper" "$DIST/scdlp-helper-arm64" -output "$DIST/scdlp-helper.fat"
    mv "$DIST/scdlp-helper.fat" "$DIST/scdlp-helper"
    rm "$DIST/scdlp-helper-arm64"
fi

echo "==> assembling $APP"
rm -rf "$APP"
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources"
cp "$REPO/helper/Info.plist" "$APP/Contents/Info.plist"
mv "$DIST/scdlp-helper" "$APP/Contents/MacOS/scdlp-helper"
chmod +x "$APP/Contents/MacOS/scdlp-helper"

TIMESTAMP_FLAG="--timestamp=none"
[ "$SIGN_ID" != "-" ] && TIMESTAMP_FLAG="--timestamp"
echo "==> codesigning helper ($SIGN_ID)"
codesign --force --options runtime $TIMESTAMP_FLAG --sign "$SIGN_ID" "$APP"

echo "==> done: $APP"
echo "    launch with: open \"$APP\""
