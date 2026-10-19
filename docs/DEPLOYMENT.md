# Deploying Plasma

## 0. Fetch the WHIDS payload (AGPL-3.0)

```bash
mkdir -p sensors/whids
curl -fsSL -A "plasma-deploy" -o whids-bundle.zip \
  https://github.com/0xrawsec/whids/releases/download/v1.7.0/whids-v1.7.0-release-bundle.zip
unzip -o -q whids-bundle.zip -d whids-bundle
find whids-bundle -name "whids.exe" -exec cp {} sensors/whids/whids.exe \;
```

The pin in `sensors/sentinel.pin.json` records the expected SHA256; the
installer re-verifies it before executing the setup.

## 1. Build the bundle (CI or workstation)

```bash
pip install -e .[dev]
plasma bundle build --out dist --version 0.2.0 \
  --engines ./engines --platform windows-x86_64 \
  --sentinel-payload sensors/sentinel \
  --binary ./dist/plasma
```

### Single self-contained Windows x64 executable (primary artifact)

Build on Windows (PyInstaller does not cross-compile):

```powershell
pip install -e ".[dev,build]" neuralos==3.10.2
python -c "from needle.agent import fetch; fetch.download_platform('windows-x86_64','engines',generation=3)"
# copy needle3.cact from the installed needle package into engines/windows-x86_64/
python tools/build_embedded_windows.py `
  --engine-dir engines/windows-x86_64 `
  --sentinel-payload sensors/sentinel `
  --dist dist --name plasma
```

Result: `dist/plasma.exe` (~57 MB) containing the Python runtime, Pydantic, the
frozen instance, the Windows engine + weights, and the WHIDS payload.

```powershell
.\plasma.exe status --events C:\ProgramData\Plasma\data\events.jsonl
.\plasma.exe ask --prompt "critical alerts"
.\plasma.exe install --dry-run
.\plasma.exe install
```

Native executables are embedded gzipped (`needle.gz`, `whids.exe.gz`)
and materialized to a temp directory at runtime; this keeps the embedded
SHA256 manifest valid even though PyInstaller rewrites native binaries.

`--engines` expects `<platform>/needle.exe|needle`, `needle3.cact` (weights),
and optionally `libneedle.a` / `needle.h`.

Fetch the engine on a build host:

```bash
pip install neuralos==3.10.2
python -c "from needle.agent import fetch; fetch.download_platform('windows-x86_64', 'engines', generation=3)"
python -c "import needle, os, shutil; shutil.copy(os.path.join(os.path.dirname(needle.__file__),'needle3.cact'), 'engines/windows-x86_64/')"
```

## 2. Verify

```bash
plasma manifest verify --dir dist/plasma-0.1.0
```

The verifier checks every listed hash and rejects missing or extra files.

## 3. Install on an endpoint

```powershell
# Plan first — writes nothing
.\packaging\install.ps1 -Bundle .\dist\plasma-0.1.0 -DryRun

# Apply — verifies hashes, checks WHIDS, stages the version, flips `current`
.\packaging\install.ps1 -Bundle .\dist\plasma-0.1.0 `
  -EventsPath C:\ProgramData\Plasma\data\events.jsonl
```

Behaviour:

* integrity failure → exit 2, nothing written;
* WHIDS service missing and a verified payload is present → the installer
  deploys `whids.exe`, runs `whids -install`, and waits for the `Whids`
  service (fail closed, exit 3);
* `-SkipWhidsInstall` leaves sensor installation to the site;
* required sensor still missing → exit 3 (use `-SkipSensorCheck` only in a lab);
* existing target without `-Force` → exit 4;
* versioned install at `C:\ProgramData\Plasma\instances\plasma-<version>`;
* `current` junction flips atomically; rollback = point it back.

## 4. Post-install verification

```powershell
.\packaging\verify.ps1 -Bundle C:\ProgramData\Plasma\current `
  -EventsPath C:\ProgramData\Plasma\data\events.jsonl `
  -Engine C:\ProgramData\Plasma\current\engines\windows-x86_64\needle.exe `
  -Model  C:\ProgramData\Plasma\current\engines\windows-x86_64\needle3.cact
```

Exit codes: 0 pass, 5 coverage below gate, 6 selection mismatch, 7 truth mismatch.

## 5. Ask questions

```powershell
$env:PLASMA_ENGINE = 'C:\ProgramData\Plasma\current\engines\windows-x86_64\needle.exe'
$env:PLASMA_MODEL  = 'C:\ProgramData\Plasma\current\engines\windows-x86_64\needle3.cact'
plasma ask --bundle C:\ProgramData\Plasma\current --prompt "what happened on WS1?"
```

## 6. Wire WHIDS intelligence (two-way)

```powershell
# Alerts -> Plasma
plasma.exe whids pull --root "C:\Program Files\Whids" `
  --out C:\ProgramData\Plasma\data\events.jsonl

# Plasma indicators -> WHIDS gene rule
plasma.exe whids push --events C:\ProgramData\Plasma\data\events.jsonl --min-confidence 8
plasma.exe whids push --events C:\ProgramData\Plasma\data\events.jsonl --min-confidence 8 `
  --apply --reason "IR-2026-042" --restart-service

plasma.exe whids status
```

Push behaviour:

* dry-run unless `--apply`;
* excludes RFC1918/loopback/link-local/reserved IPs and benign domains;
* merges gene expressions with the existing rule, cap `--max-indicators`;
* writes a timestamped backup and appends to `whids-intel-journal.jsonl`;
* restarts the WHIDS service only with `--restart-service`;
* WHIDS owns response actions — Plasma stays advisory.

## 7. Fleet updates

Ship a new bundle version, install alongside, verify, flip `current`, keep the
old version for rollback. Never edit files inside an installed version.
