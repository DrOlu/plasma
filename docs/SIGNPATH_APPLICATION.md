# SignPath Foundation — application package for Plasma

Everything needed to apply for free OSS code signing at
<https://signpath.org/> (the form is "Request signing" on the site).
Fill nothing in a hurry — the answers below are the accurate ones.

## Project facts (copy into the application form)

| Field | Value |
|---|---|
| Project name | Plasma |
| Repository | https://github.com/DrOlu/plasma (public) |
| License | MIT (`LICENSE`) — OSI-approved |
| Maintainer | DrOlu (GitHub account) |
| Project description | A lake-less Windows EDR: on-box sensors normalize Sysmon/ETW/identity events into one JSONL contract; a desk-side CLI asks questions, correlates across hosts, and performs human-gated, reversible response. No cloud backend, no log lake. |
| Release page | https://github.com/DrOlu/plasma/releases |
| Artifacts to sign | `plasma-<version>-windows-x64.exe` (single-file Windows x64 executable, built by GitHub Actions from the tagged commit) |
| Build system | GitHub Actions — `.github/workflows/release.yml` (PyInstaller build on `windows-latest`, SHA256SUMS published with each release) |
| Documentation | `README.md` + `~/.claude/skills/plasma` operational skill (public mirror: DrOlu/agent-skills/skills/plasma) |

## Eligibility checklist (their stated conditions)

- [x] No malware / PUP — detection logic only; sensors are read-only.
- [x] OSI-approved license (MIT) with no commercial dual-licensing.
- [x] No proprietary components in the signed artifact (PyInstaller bundle
      of `plasma/` package + MIT/Apache-2.0 sensor payloads; see
      `THIRD_PARTY_NOTICES.md`).
- [x] Actively maintained (releases v1.0.0, v1.1.0; CI on every push).
- [x] Already released in the form to be signed (Windows x64 exe assets).
- [x] Documented (README + release notes + CHANGELOG).

## What SignPath will do

- Issue the code signing certificate **to SignPath Foundation** (their
  terms): the publisher shown on Windows will be *SignPath Foundation*,
  not "Hyperspace Technologies". The private key lives in their HSM.
- Verify the binary was built from this repository through the signing
  request origin (GitHub Actions workflow → SignPath).

## Integration after approval (GitHub Actions)

Replace the PFX signing step in `.github/workflows/release.yml` with the
SignPath submission action (job runs only when the repository variable
`SIGNPATH_ENABLED` is `true`):

```yaml
  signpath:
    needs: windows-x64            # build job uploads the exe as an artifact
    if: vars.SIGNPATH_ENABLED == 'true'
    runs-on: ubuntu-latest
    permissions:
      contents: read
      actions: read
    steps:
      - uses: actions/download-artifact@v4
        with:
          name: plasma-windows-x64   # unsigned exe
          path: unsigned
      - uses: signpath/github-action-submit-signing-request@v1
        with:
          api-token: ${{ secrets.SIGNPATH_API_TOKEN }}
          organization-id: ${{ vars.SIGNPATH_ORG_ID }}
          project-slug: ${{ vars.SIGNPATH_PROJECT_SLUG }}
          signing-policy-slug: ${{ vars.SIGNPATH_POLICY_SLUG }}
          artifact-configuration-slug: ${{ vars.SIGNPATH_ARTIFACT_SLUG }}
          github-artifact-id: ${{ steps.upload.outputs.artifact-id }}
          wait-for-completion: true
          output-artifact-directory: signed
```

Then hash the **signed** exe and publish it. Keep SHA256SUMS generation
after signing.

## Signer pinning (already implemented in 1.2.0)

`plasma update apply` refuses to execute a downloaded update unless its
Authenticode signer matches thumbprints pinned in the installed binary
(`plasma/update.py: DEFAULT_SIGNER_THUMBPRINTS`, override with
`PLASMA_SIGNER_THUMBPRINTS`). After SignPath is live, add the SignPath
certificate's thumbprint to that set (or rotate the set via the env var
while both signing methods overlap).

## Interim signing (works today, free)

Self-signed with the Hyperspace Technologies certificate (SHA-1
`BC:67:B9:90:A7:83:70:2D:0C:47:61:D5:57:A5:8F:9A:D4:53:4A:68`).
`release.yml` signs automatically when the repository secrets
`SIGNING_PFX_BASE64` and `SIGNING_PFX_PASSWORD` exist; otherwise the
release proceeds unsigned. Import `hyperspace.crt` into *Trusted
Publishers* on managed machines to make the signature report `Valid`
there.
