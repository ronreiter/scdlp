#!/usr/bin/env bash
set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
DIST="$REPO/dist"
BUNDLE="$DIST/io.sentra.scdlp.extension.systemextension"
EXEC="io.sentra.scdlp.extension"

# Sign identity & team ID come from env. For ad-hoc/dev set:
#   export SCDLP_SIGN_ID="-"          # ad-hoc; works for SIP-relaxed test only
#   export SCDLP_TEAM_ID="UNSIGNED"
SIGN_ID="${SCDLP_SIGN_ID:--}"
TEAM_ID="${SCDLP_TEAM_ID:-UNSIGNED}"

# 1. Build the Go agent with ESF hook enabled. CGO_ENABLED is default on darwin.
echo "==> building agent binary"
GOOS=darwin go build -trimpath -o "$DIST/$EXEC" "$REPO/cmd/scdlp-agent"

# 2. Lay out the bundle.
echo "==> assembling $BUNDLE"
rm -rf "$BUNDLE"
mkdir -p "$BUNDLE/Contents/MacOS" "$BUNDLE/Contents/_CodeSignature"
cp "$REPO/extension/Info.plist" "$BUNDLE/Contents/Info.plist"
mv "$DIST/$EXEC" "$BUNDLE/Contents/MacOS/$EXEC"
chmod +x "$BUNDLE/Contents/MacOS/$EXEC"

# 3. Sign with the requested identity.
echo "==> codesigning ($SIGN_ID)"
codesign --force --options runtime --timestamp=none \
    --sign "$SIGN_ID" \
    --entitlements "$REPO/extension/Scdlp.entitlements" \
    "$BUNDLE"

# 4. Verify.
echo "==> verifying"
codesign --verify --deep --strict --verbose=2 "$BUNDLE"
codesign --display --entitlements - "$BUNDLE" 2>&1 | grep -i endpoint || true

echo "==> done: $BUNDLE"
