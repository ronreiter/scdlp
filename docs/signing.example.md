# scdlp signing configuration

Copy this file to `docs/signing.md` (which is gitignored) and fill in your values.

## Required identities

You need two pieces from Apple:

1. **Developer ID Application** certificate — installed in the login keychain.
   Verify with: `security find-identity -v -p codesigning | grep 'Developer ID Application'`
2. **`com.apple.developer.endpoint-security.client`** entitlement, granted to
   your Team ID for `io.sentra.scdlp.extension`. Request via
   https://developer.apple.com/contact/request/system-extension/. Apple usually
   replies in 2–8 weeks.

## Local environment

Once you have both, set:

```bash
# In your shell profile or a per-session `.envrc`:
export SCDLP_SIGN_ID="Developer ID Application: Your Company Name (TEAMID12345)"
export SCDLP_TEAM_ID="TEAMID12345"
```

Then:

```bash
make bundle
make activate
```

The first `activate` will prompt the user to approve the System Extension and
grant Full Disk Access in System Settings → Privacy & Security.

## Verifying the entitlement landed

After `make extension`, the codesign verify output should include
`com.apple.developer.endpoint-security.client`. If it doesn't, the entitlement
file isn't being read; check `extension/Scdlp.entitlements` is present and
that `codesign` reports no errors.

## Notarization (production only)

Local dev does not require notarization. For distribution:

```bash
xcrun notarytool submit dist/scdlp.app --wait \
    --apple-id you@example.com \
    --team-id "$SCDLP_TEAM_ID" \
    --password "@keychain:AC_PASSWORD"
xcrun stapler staple dist/scdlp.app
```
