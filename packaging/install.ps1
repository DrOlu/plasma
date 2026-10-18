<#
.SYNOPSIS
  Plasma bundle installer (verify -> dependency check -> staged copy -> flip).

.DESCRIPTION
  Installs a frozen Plasma bundle under a versioned directory and points a
  `current` junction at it. The installer is safe by default:

    1. every file is SHA256-verified against manifest.json;
    2. required sensor dependencies are checked (Sentinel service);
    3. -DryRun prints the exact plan and writes nothing.

  Exit codes: 0 success/dry-run, 2 manifest verification failed,
  3 required sensor missing, 4 install target conflict.

.EXAMPLE
  .\install.ps1 -Bundle .\plasma-0.1.0 -DryRun
  .\install.ps1 -Bundle .\plasma-0.1.0 -EventsPath C:\ProgramData\Plasma\data\events.jsonl
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$Bundle,
    [string]$InstallRoot = $(if ($env:ProgramData) { Join-Path $env:ProgramData 'Plasma' } else { Join-Path $HOME '.plasma' }),
    [string]$EventsPath = '',
    [switch]$DryRun,
    [switch]$SkipSensorCheck,
    [switch]$SkipSentinelInstall,
    [switch]$Force
)

$ErrorActionPreference = 'Stop'
function Out-Plan($obj) { $obj | ConvertTo-Json -Depth 8 }

$bundlePath = (Resolve-Path -LiteralPath $Bundle).Path
$manifestPath = Join-Path $bundlePath 'manifest.json'
if (-not (Test-Path -LiteralPath $manifestPath)) {
    Out-Plan @{ ok = $false; error = "manifest.json not found in $bundlePath" }
    exit 2
}
$manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json

# ---- 1. integrity ---------------------------------------------------------
$missing = @(); $mismatched = @(); $checked = 0
foreach ($prop in $manifest.files.PSObject.Properties) {
    $rel = $prop.Name; $expected = [string]$prop.Value
    $path = Join-Path $bundlePath $rel
    if (-not (Test-Path -LiteralPath $path)) { $missing += $rel; continue }
    $actual = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()
    $checked++
    if ($actual -ne $expected.ToLowerInvariant()) {
        $mismatched += @{ path = $rel; expected = $expected.Substring(0, 16); actual = $actual.Substring(0, 16) }
    }
}
$recorded = @($manifest.files.PSObject.Properties.Name)
# Runtime artifacts are never part of the frozen manifest.
function Test-RuntimeArtifact($rel) {
    return ($rel -match '(^|/)__pycache__/' -or $rel -match '\.py[co]$' -or
            $rel -match '(^|/)\.DS_Store$' -or $rel -match '(^|/)\.tool_index\.json$')
}
$present = @(Get-ChildItem -LiteralPath $bundlePath -Recurse -File |
    ForEach-Object { $_.FullName.Substring($bundlePath.Length + 1).Replace('\', '/') } |
    Where-Object { $_ -ne 'manifest.json' -and -not (Test-RuntimeArtifact $_) })
$extra = @($present | Where-Object { $_ -notin $recorded })
$integrityOk = ($missing.Count -eq 0 -and $mismatched.Count -eq 0 -and $extra.Count -eq 0)

if (-not $integrityOk) {
    Out-Plan @{
        ok = $false; stage = 'integrity'; checked = $checked
        missing = $missing; mismatched = $mismatched; extra = $extra
    }
    exit 2
}

# ---- 2. sensor dependencies ----------------------------------------------
$sensors = $manifest.sensor_requirements
$sensorState = @()
$requiredMissing = @()
$plannedActions = @()
$sentinelWillInstall = $false
foreach ($name in @('sentinel', 'sysmon', 'sealighter')) {
    $req = $sensors.$name
    if ($null -eq $req) { continue }
    $presentSensor = $false
    if ($name -eq 'sentinel' -and $IsWindows) {
        $svc = Get-Service -ErrorAction SilentlyContinue | Where-Object { $_.Name -like 'Sentinel*' -or $_.DisplayName -like '*Sentinel*' } | Select-Object -First 1
        $presentSensor = ($null -ne $svc)
    }

    if ($name -eq 'sentinel' -and -not $presentSensor -and $IsWindows -and -not $SkipSentinelInstall) {
        $pinPath = Join-Path $bundlePath 'sensors/sentinel.pin.json'
        $payload = $null
        if (Test-Path -LiteralPath $pinPath) {
            $pin = Get-Content -LiteralPath $pinPath -Raw | ConvertFrom-Json
            $setup = Join-Path $bundlePath (Join-Path 'sensors/sentinel' $pin.payload.file)
            if (Test-Path -LiteralPath $setup) {
                $hash = (Get-FileHash -LiteralPath $setup -Algorithm SHA256).Hash.ToLowerInvariant()
                if ($hash -ne ([string]$pin.payload.sha256).ToLowerInvariant()) {
                    Out-Plan @{ ok = $false; stage = 'sentinel_payload'; error = 'Sentinel setup hash mismatch'; expected = $pin.payload.sha256; actual = $hash }
                    exit 2
                }
                $payload = @{ setup = $setup; args = @($pin.payload.silent_args); version = [string]$pin.version }
                $sentinelWillInstall = $true
                $plannedActions += "install Sentinel $($pin.version) (silent): $setup"
            }
        }
        if (-not $payload) {
            $plannedActions += "Sentinel payload absent and service not installed"
        } elseif (-not $DryRun) {
            $argList = @($payload.args)
            $proc = Start-Process -FilePath $payload.setup -ArgumentList $argList -Wait -PassThru
            if ($proc.ExitCode -ne 0) {
                Out-Plan @{ ok = $false; stage = 'sentinel_install'; error = "Sentinel setup exited $($proc.ExitCode)" }
                exit 3
            }
            $deadline = (Get-Date).AddSeconds(30)
            do {
                $svc = Get-Service -ErrorAction SilentlyContinue | Where-Object { $_.Name -like 'Sentinel*' -or $_.DisplayName -like '*Sentinel*' } | Select-Object -First 1
                $presentSensor = ($null -ne $svc)
                if (-not $presentSensor) { Start-Sleep -Seconds 2 }
            } while (-not $presentSensor -and (Get-Date) -lt $deadline)
            $sentinelWillInstall = $presentSensor
        }
    }

    $sensorState += @{
        sensor = $name; required = [bool]$req.required; present = $presentSensor
        will_install = ($name -eq 'sentinel' -and $sentinelWillInstall)
        mode = "$($req.install)$($req.mode)"
    }
    if ($req.required -and -not $presentSensor -and -not $sentinelWillInstall -and -not $SkipSensorCheck) {
        $requiredMissing += $name
    }
}
if ($requiredMissing.Count -gt 0) {
    Out-Plan @{ ok = $false; stage = 'sensors'; missing_required = $requiredMissing; sensors = $sensorState }
    exit 3
}

# ---- 3. plan --------------------------------------------------------------
$version = [string]$manifest.version
$target = Join-Path (Join-Path $InstallRoot 'instances') "plasma-$version"
$current = Join-Path $InstallRoot 'current'
$configPath = Join-Path $InstallRoot 'config.json'
if (-not $EventsPath) { $EventsPath = Join-Path $InstallRoot 'data/events.jsonl' }

$plan = @{
    ok = $true
    dry_run = [bool]$DryRun
    product = [string]$manifest.product
    version = $version
    bundle = $bundlePath
    install_root = $InstallRoot
    target = $target
    current = $current
    config = $configPath
    events_path = $EventsPath
    files_verified = $checked
    probes = $manifest.instance.probes
    sensors = $sensorState
    actions = @(
        "create $target",
        "copy $checked verified files",
        "write $configPath",
        "point $current -> $target"
    ) + $plannedActions
}
if ($DryRun) { Out-Plan $plan; exit 0 }

# ---- 4. apply -------------------------------------------------------------
if (Test-Path -LiteralPath $target) {
    if (-not $Force) {
        Out-Plan @{ ok = $false; stage = 'target'; error = "target already exists: $target (use -Force to replace)"; plan = $plan }
        exit 4
    }
}
New-Item -ItemType Directory -Force -Path $target | Out-Null
foreach ($rel in $recorded) {
    $src = Join-Path $bundlePath $rel
    $dst = Join-Path $target $rel
    New-Item -ItemType Directory -Force -Path (Split-Path $dst -Parent) | Out-Null
    Copy-Item -LiteralPath $src -Destination $dst -Force
}
New-Item -ItemType Directory -Force -Path (Split-Path $configPath -Parent) | Out-Null
$config = @{
    product = 'Plasma'
    version = $version
    instance = $target
    events_path = $EventsPath
    retention_days = 7
    response = @{ mode = 'advisory'; require_human_approval = $true }
    sensors = @{
        sentinel = @{ required = $true; min_version = '3.3.0' }
        sysmon = @{ required = $false }
        sealighter = @{ required = $false; mode = 'on-demand' }
    }
}
$config | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $configPath -Encoding UTF8

if ($IsWindows) {
    if (Test-Path -LiteralPath $current) {
        $item = Get-Item -LiteralPath $current -Force
        if ($item.LinkType -eq 'Junction' -or $item.LinkType -eq 'SymbolicLink') {
            Remove-Item -LiteralPath $current -Force
        } else {
            Out-Plan @{ ok = $false; stage = 'current'; error = "$current exists and is not a link; refusing to replace" }
            exit 4
        }
    }
    New-Item -ItemType Junction -Path $current -Target $target | Out-Null
} else {
    $link = Join-Path $InstallRoot 'current'
    if (Test-Path -LiteralPath $link) { Remove-Item -LiteralPath $link -Force }
    New-Item -ItemType SymbolicLink -Path $link -Target $target | Out-Null
}

Out-Plan @{ ok = $true; installed = $target; current = $current; config = $configPath; files = $checked }
exit 0
