<#
.SYNOPSIS
  Plasma post-install verification: coverage, selection, truth check.

.DESCRIPTION
  Runs the Phase-4 contract on a bundle:
    1. coverage  >= 95% of the local event store parses through the shape checks;
    2. selection  three phrasings select the intended probe (needs the engine);
    3. truth      one relayed count equals a direct count of the source.

  Exit codes: 0 pass, 5 coverage below gate, 6 selection mismatch, 7 truth mismatch.

.EXAMPLE
  .\verify.ps1 -Bundle C:\ProgramData\Plasma\current -EventsPath C:\ProgramData\Plasma\data\events.jsonl
  .\verify.ps1 -Bundle .\plasma-0.1.0 -Engine .\engines\windows-x86_64\needle.exe -Model .\engines\windows-x86_64\needle3.cact
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$Bundle,
    [string]$EventsPath = $env:PLASMA_EVENTS,
    [string]$Engine = $env:PLASMA_ENGINE,
    [string]$Model = $env:PLASMA_MODEL,
    [double]$CoverageGate = 95.0
)

$ErrorActionPreference = 'Stop'
$bridge = Join-Path $Bundle 'instance/bridge.ps1'
$menu = Join-Path $Bundle 'instance/needle_menu.json'
if (-not (Test-Path -LiteralPath $bridge)) { @{ ok = $false; error = "bridge not found: $bridge" } | ConvertTo-Json; exit 2 }

$report = @{ ok = $false; bundle = (Resolve-Path $Bundle).Path; checks = @{} }

# 1. coverage
$covArgs = @('-NoProfile', '-File', $bridge, '-Coverage')
if ($EventsPath) { $covArgs += @('-EventsPath', $EventsPath) }
$cov = (& pwsh @covArgs | ConvertFrom-Json)
$report.checks.coverage = $cov
$covOk = ($cov.coverage_pct -ge $CoverageGate)
$report.checks.coverage_ok = $covOk

# 2. selection
$selection = @()
if ($Engine -and $Model) {
    $cases = @(
        @{ q = 'show me the alerts'; expect = 'plasma_alerts' },
        @{ q = 'any persistence mechanisms'; expect = 'plasma_persistence' },
        @{ q = 'what processes ran'; expect = 'plasma_processes' }
    )
    foreach ($case in $cases) {
        $out = & $Engine --model $Model --tools $menu --prompt $case.q 2>$null | ConvertFrom-Json
        $pick = if ($out.function_calls -and $out.function_calls.Count -gt 0) { $out.function_calls[0].name } else { $null }
        $selection += @{ q = $case.q; expect = $case.expect; got = $pick; ok = ($pick -eq $case.expect) }
    }
}
$report.checks.selection = $selection
$selOk = ($selection.Count -eq 0) -or (@($selection | Where-Object { -not $_.ok }).Count -eq 0)

# 3. truth check (event count vs raw line count)
$truthOk = $true
if ($EventsPath -and (Test-Path -LiteralPath $EventsPath)) {
    $lines = @(Get-Content -LiteralPath $EventsPath | Where-Object { $_.Trim() }).Count
    $overviewArgs = @('-NoProfile', '-File', $bridge, '-Tool', 'plasma_overview')
    if ($EventsPath) { $overviewArgs += @('-EventsPath', $EventsPath) }
    $overview = (& pwsh @overviewArgs | ConvertFrom-Json)
    $truthOk = ([int]$overview.events -eq [int]$lines)
    $report.checks.truth = @{ relayed = $overview.events; source_lines = $lines; ok = $truthOk }
}
$report.checks.selection_ok = $selOk
$report.checks.truth_ok = $truthOk
$report.ok = ($covOk -and $selOk -and $truthOk)
$report | ConvertTo-Json -Depth 10
if (-not $covOk) { exit 5 }
if (-not $selOk) { exit 6 }
if (-not $truthOk) { exit 7 }
exit 0
