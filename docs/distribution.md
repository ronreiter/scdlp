# Distribution setup (one-time, for the repo owner)

This document walks you through the secrets and Apple ID configuration the
GitHub Actions `release` workflow needs to produce a signed + notarized
`.dmg` on every push to `main`.

## Required GitHub Actions secrets

Set these at **Settings → Secrets and variables → Actions** in the GitHub repo.

| Secret name | Value | Where to get it |
|---|---|---|
| `APPLE_DEVELOPER_ID_CERT_P12` | base64-encoded `.p12` of the Developer ID Application cert + private key | Export from Keychain Access; see below |
| `APPLE_DEVELOPER_ID_CERT_PASSWORD` | The passphrase you set when exporting | Whatever you typed during export |
| `APPLE_KEYCHAIN_PASSWORD` | Any string (e.g. a generated 32-byte hex) | Used only to lock the throwaway CI keychain |
| `APPLE_HOST_PROFILE` | base64 of `host/embedded.provisionprofile` | `base64 -i host/embedded.provisionprofile \| pbcopy` |
| `APPLE_EXT_PROFILE` | base64 of `extension/embedded.provisionprofile` | `base64 -i extension/embedded.provisionprofile \| pbcopy` |
| `APPLE_ID` | Your Apple ID email | The same one you use to log in to developer.apple.com |
| `APPLE_TEAM_ID` | `8BKF8DY7Y4` | Your Developer Team ID |
| `APPLE_APP_SPECIFIC_PASSWORD` | An app-specific password from appleid.apple.com | See below |

## Exporting the Developer ID cert as .p12

1. Open **Keychain Access**.
2. In "login" keychain, **My Certificates** category, find `Developer ID Application: Ron Reiter (8BKF8DY7Y4)`.
3. **Right-click → Export…** → file format **Personal Information Exchange (.p12)**.
4. Set a passphrase. Save somewhere safe.
5. Base64-encode it for the secret:
   ```bash
   base64 -i ~/Downloads/scdlp-dev-id.p12 | pbcopy
   ```
   Paste into the `APPLE_DEVELOPER_ID_CERT_P12` secret.

## Creating an app-specific password for notarytool

1. Sign in at https://appleid.apple.com.
2. **Sign-In and Security → App-Specific Passwords → Generate**.
3. Label it `scdlp-ci-notarize` or similar.
4. Copy the password (formatted like `abcd-efgh-ijkl-mnop`).
5. Paste into the `APPLE_APP_SPECIFIC_PASSWORD` secret.

This is required because `xcrun notarytool submit` against your Apple ID
requires either 2FA + an app-specific password, or a notarytool API key.

## What the release workflow does

`.github/workflows/release.yml` runs on every push to `main`:

1. `go test ./...` — full suite.
2. Decode the cert + profiles from secrets.
3. Set up an ephemeral keychain (deleted on completion).
4. `task bundle:prod` — produces the signed `dist/scdlp.app`.
5. `xcrun notarytool submit --wait` — sends to Apple for malware scan + signature verification, waits up to 15 min.
6. `xcrun stapler staple` — attaches the notarization ticket so the .app works offline.
7. `hdiutil create` — packs into `dist/scdlp.dmg`.
8. Sign + notarize + staple the .dmg too.
9. `gh release create latest dist/scdlp.dmg` — replaces the `latest` release, also creates a versioned tag for history.

The stable URL anyone can use:
`https://github.com/ronreiter/scdlp/releases/latest/download/scdlp.dmg`

## CI cost note

macOS runners on GitHub Actions are billable: free accounts get 2000 min/month
on Linux but only 200 min/month on macOS at a 10x multiplier (so effectively
~20 wall-clock min of macOS time/month free; the rest is paid).

Each release build takes \~6–10 min (most of it waiting for Apple's notary
service). Push 5× a day for a month = ~150 build min = within free budget.
Push 30× a day = ~$0.08/build × 900 builds = ~$72/mo. Cap with branch rules
if it becomes an issue.

`ci.yml` (the test-only workflow that fires on PRs and non-main pushes) is
much faster (~2 min, no notarize wait).

## Local fallback: build a release without CI

If GitHub Actions is unavailable or you want to validate before pushing:

```bash
# 1. Build + sign (uses your local cert + profiles)
task bundle:prod

# 2. Notarize manually
ditto -c -k --keepParent dist/scdlp.app dist/scdlp.zip
xcrun notarytool submit dist/scdlp.zip \
    --apple-id you@example.com \
    --team-id 8BKF8DY7Y4 \
    --password "@keychain:notarytool-password" \
    --wait
xcrun stapler staple dist/scdlp.app

# 3. Pack as .dmg
hdiutil create -volname scdlp \
    -srcfolder dist/scdlp.app \
    -ov -format UDZO dist/scdlp.dmg
```

Store the notarytool password in your keychain once:
```bash
xcrun notarytool store-credentials notarytool-password \
    --apple-id you@example.com \
    --team-id 8BKF8DY7Y4
# then enter the app-specific password when prompted
```
