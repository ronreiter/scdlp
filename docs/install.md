# Installing scdlp on a new Mac

This is the short version for someone who's never touched the source — point them at the link below and that's it.

## Direct download

```
https://github.com/ronreiter/scdlp/releases/latest/download/scdlp.dmg
```

That URL always serves the most recent build from `main`. Each commit produces a fresh signed + notarized `.dmg`.

## Install steps

1. **Download** the `.dmg` from the URL above.
2. **Open** it. You'll see `scdlp.app` and an `Applications` shortcut.
3. **Drag** `scdlp.app` onto the `Applications` shortcut. Eject the `.dmg`.
4. **Open** Launchpad (or `/Applications` in Finder) → double-click **scdlp**.
   - The first time you open it, Gatekeeper will say *"scdlp is an app downloaded from the Internet. Are you sure you want to open it?"* Click **Open**.
   - The app is signed by Ron Reiter (Team ID `8BKF8DY7Y4`) and notarized by Apple, so the dialog is the usual download warning, not a "this is from an unidentified developer" block.
5. **Approve the System Extension.** macOS pops a notification:
   *"System Extension Blocked — scdlp tried to load a new system extension. Open System Settings to approve."*
   Click the notification (or open **System Settings → General → Login Items & Extensions → Endpoint Security Extensions**), and toggle on the scdlp extension.
6. **Grant Full Disk Access.** macOS will prompt you (or you go to **System Settings → Privacy & Security → Full Disk Access** and add `scdlp` from the list). Without FDA, scdlp can't read protected files for content classification, but it'll still work for path-tier rules.

## What you should see

Once approved, scdlp runs invisibly as a system extension. To check it's alive:

```bash
systemextensionsctl list | grep sentra
# Expected: 8BKF8DY7Y4 io.sentra.scdlp.extension ... [activated enabled]
```

To watch live decisions (requires `sudo`):

```bash
sudo tail -F "/Library/Application Support/scdlp/extension.log"
```

## Uninstall

```bash
systemextensionsctl uninstall 8BKF8DY7Y4 io.sentra.scdlp.extension
# Then drag /Applications/scdlp.app to Trash
sudo rm -rf "/Library/Application Support/scdlp"
```

## Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| Gatekeeper says "unidentified developer" | DMG was edited / corrupted in transit | Re-download from the link above |
| System Extension prompt never appears | Old version still installed | Uninstall first (see above), then re-open the app |
| `extension.log` shows restart-loop entries | Bug in the daemon (please report) | `systemextensionsctl uninstall …` and grab the IPS files at `/Library/Logs/DiagnosticReports/io.sentra.scdlp.extension-*.ips` |
| Doesn't intercept reads of `~/.aws/credentials` | Full Disk Access not granted to the extension | System Settings → Privacy & Security → Full Disk Access → add scdlp |

## What it's doing

scdlp watches every file open on the system via Apple's Endpoint Security framework. When a process tries to read a file that contains secrets (AWS credentials, SSH keys, npm tokens, JWTs, etc.), scdlp checks an allowlist of `(process-ancestry, file-category)` rules. Unknown combinations are denied — defeating the npm/pip/cargo postinstall pattern of reading `~/.aws/credentials` from a malicious package's lifecycle script.

See the [README](../README.md) for architecture details.
