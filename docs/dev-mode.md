# scdlp dev mode — running ESF without the Apple entitlement

You can run scdlp's Endpoint Security backend against the live kernel **without**
the `com.apple.developer.endpoint-security.client` entitlement by disabling
Apple's Apple Mobile File Integrity (AMFI) on your dev Mac. This is intrusive.
Do not do it on a machine you use for anything sensitive.

## What you're trading

AMFI is the kernel subsystem that enforces:

- Only code signed by Apple-trusted identities can run with restricted
  entitlements.
- The kernel rejects `es_new_client()` from any binary missing the ESF
  entitlement.

Disabling it lets you sign your binary with a self-signed cert (or ad-hoc)
and still get a working ESF client. It also disables many other kernel
integrity checks. You will get warnings on every boot.

## How to disable (Apple Silicon, macOS 13+)

1. Boot into Recovery: hold the power button at boot until you see Options.
2. Open Terminal from Utilities.
3. Run:

   ```
   csrutil enable --without amfi --without nvram
   ```

4. Reboot into the normal OS.
5. In a regular Terminal:

   ```bash
   sudo nvram boot-args="amfi_get_out_of_my_way=0x1"
   ```

6. Reboot one more time.

## How to disable (Intel, macOS 13+)

1. Boot into Recovery: ⌘+R at startup.
2. Utilities → Terminal.
3. Run `csrutil disable` (a complete SIP disable is required on Intel — there
   is no `--without amfi` granularity).
4. Reboot.

## How to verify

```bash
csrutil status
nvram boot-args
```

You should see `System Integrity Protection status: System Integrity Protection
is off.` (Intel) or a partial-disable list including `Apple Mobile File
Integrity: disabled` (Apple Silicon), and `boot-args` should contain
`amfi_get_out_of_my_way=0x1`.

## Run scdlp under dev mode

```bash
task bundle      # build extension + host .app (ad-hoc signed by default)
task install     # cp to /Applications + lsregister
task activate    # request macOS to install the extension (sudo)
```

The `sudo` is required because un-entitled ES clients also need to run as root.

After `activate`, open System Settings → Privacy & Security and approve the
System Extension. Then grant `dist/scdlp.app` (or the extension target) Full
Disk Access.

Verify scdlp is enforcing:

```bash
sudo log stream --predicate 'process == "Scdlp"' --info
```

In another terminal:

```bash
cat ~/.aws/credentials   # should be ALLOWED if your shell chain is allowlisted,
                          # or DENIED with EACCES otherwise — and the log line above
                          # shows the decision.
```

## How to revert

Apple Silicon (full revert):

1. Recovery → Terminal.
2. `csrutil clear` and reboot.
3. `sudo nvram -d boot-args`.

Intel:

1. Recovery → Terminal.
2. `csrutil enable` and reboot.

Verify with `csrutil status` — should report fully enabled.

## Don't ship code that depends on dev mode

Anything that only works with AMFI disabled is not shippable. Treat dev mode
as a temporary diagnostic — the production path is the Apple entitlement.
