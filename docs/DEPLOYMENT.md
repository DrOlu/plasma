# Deploying Plasma

## 1. Build the bundle (CI or workstation)

```bash
pip install -e .[dev]
plasma bundle build --out dist --version 0.1.0 \
  --engines ./engines --platform windows-x86_64
```

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

# Apply — verifies hashes, checks Sentinel, stages the version, flips `current`
.\packaging\install.ps1 -Bundle .\dist\plasma-0.1.0 `
  -EventsPath C:\ProgramData\Plasma\data\events.jsonl
```

Behaviour:

* integrity failure → exit 2, nothing written;
* required sensor (Sentinel) missing → exit 3 (use `-SkipSensorCheck` only in a lab);
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

## 6. Fleet updates

Ship a new bundle version, install alongside, verify, flip `current`, keep the
old version for rollback. Never edit files inside an installed version.
