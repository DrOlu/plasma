# Updates and signing

## Checking and applying updates

```powershell
plasma update check    # exit 0 = current, 2 = update available
plasma update apply    # download → verify SHA-256 → verify signer → install → rotate
```

The repository is public, so both commands work **anonymously**. A token is
still accepted (`--token-env`) for private forks.

What `apply` does, in order:

1. fetches the latest release metadata,
2. downloads the exe and `SHA256SUMS`,
3. verifies the SHA-256 of the downloaded bytes,
4. **verifies the Authenticode signer against thumbprints pinned inside the
   installed binary** — mismatch or unsigned aborts with exit 2 and the
   staged installer is never executed,
5. runs the new exe's own `install --force --root <same root>`,
6. rotates the canonical bin copy (rename-while-running is legal on Windows;
   overwriting a running exe is not).

`--allow-unsigned` exists for development only.

## The two trust anchors

| Anchor | What it protects against |
|---|---|
| `SHA256SUMS` published with the release | corrupted download, truncated transfer |
| **Pinned signer thumbprint** baked into the installed exe | a compromised release page / repository: an attacker who can replace both the exe and the sums still cannot forge a signature matching the pin |

Default pin (self-signed project certificate, valid to 2036):

```text
BC67B990A783702D0C4761D557A58F9AD4534A68
```

Rotate or extend the set without rebuilding:

```powershell
$env:PLASMA_SIGNER_THUMBPRINTS = "BC67...,AB12...,CD34..."
plasma update apply
```

Verification reports the signer thumbprint and the chain status. Trust-chain
status is informational: a lab box may not have the signer's root imported,
but the **pin** is what matters.

## Release signing in CI

`release.yml` signs the Windows exe with Authenticode **before** SHA-256
sums are computed, when repository secrets exist:

| Secret | Purpose |
|---|---|
| `SIGNING_PFX_BASE64` | the PKCS#12 bundle, base64-encoded |
| `SIGNING_PFX_PASSWORD` | its password |

The workflow imports the certificate into the ephemeral runner's trust
stores (so `signtool verify /pa` exercises the real chain), signs with a
DigiCert RFC 3161 timestamp, verifies, then hashes the **signed** file.
Without secrets, the release proceeds unsigned.

## Signpath Foundation (publicly trusted signing)

The project has applied to [SignPath Foundation](https://signpath.org) for
free OSS code signing. Once approved:

- Plasma's certificate is issued to the Foundation (HSM-held key), the
  publisher shown by Windows becomes *SignPath Foundation*, and SmartScreen
  reputation can accrue;
- `release.yml` switches to
  `signpath/github-action-submit-signing-request` (the wiring is prepared in
  `docs/SIGNPATH_APPLICATION.md`);
- the Foundation thumbprint is added to the pin set above (or passed via
  `PLASMA_SIGNER_THUMBPRINTS` during the overlap).

Note the honest caveat: a publicly trusted certificate removes the "Unknown
publisher" warning and lets reputation build — it does **not** guarantee
instant SmartScreen silence for a brand-new publisher.

## Verifying a build yourself

Windows:

```powershell
Get-AuthenticodeSignature .\plasma-1.2.0-windows-x64.exe |
  Select-Object Status, SignerCertificate
```

Any OS with `osslsigncode`:

```bash
osslsigncode verify -in plasma-1.2.0-windows-x64.exe
```

Both should show the Hyperspace (or SignPath Foundation) signer and a verified timestamp.
