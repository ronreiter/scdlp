#!/bin/bash
# Local build → sign → notarize → staple → install → activate cycle for scdlp.
# No GitHub Actions. Requires: keychain profile "scdlp-notary" (notarytool),
# the Developer ID cert, and the embedded provisioning profiles in place.
set -euo pipefail
cd "$(dirname "$0")"

export PATH="/opt/homebrew/bin:$PATH"
export SDKROOT="/Applications/Xcode.app/Contents/Developer/Platforms/MacOSX.platform/Developer/SDKs/MacOSX.sdk"
export SCDLP_SIGN_ID="Developer ID Application: Ron Reiter (8BKF8DY7Y4)"
export SCDLP_TEAM_ID="8BKF8DY7Y4"

echo "==> build + sign"
task bundle:prod >/tmp/scdlp-build.log 2>&1 || { tail -30 /tmp/scdlp-build.log; exit 1; }

echo "==> notarize (waits)"
rm -f dist/scdlp.zip
ditto -c -k --keepParent dist/scdlp.app dist/scdlp.zip
xcrun notarytool submit dist/scdlp.zip --keychain-profile "scdlp-notary" --wait | tail -3

echo "==> staple"
xcrun stapler staple dist/scdlp.app >/dev/null && echo "stapled"

echo "==> install to /Applications"
rm -rf /Applications/scdlp.app
ditto dist/scdlp.app /Applications/scdlp.app
/System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/LaunchServices.framework/Versions/A/Support/lsregister -f /Applications/scdlp.app

echo "==> activate"
( "/Applications/scdlp.app/Contents/MacOS/scdlp-host" activate & HPID=$!; \
  for i in $(seq 1 30); do kill -0 $HPID 2>/dev/null || break; sleep 1; done; \
  kill $HPID 2>/dev/null; wait $HPID 2>/dev/null ) 2>&1 | head
echo "==> done"
