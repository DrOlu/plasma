<#
.SYNOPSIS
  Plasma frozen-instance bridge for PowerShell-only endpoints.

.DESCRIPTION
  Executes one probe from needle_menu.json against the local normalized
  event store. Pydantic is a build-time artifact; this file carries the
  generated shape checks that enforce the same contract at runtime.

  Contract: read-only probes, ROW_CAP rows per answer, errors are data,
  the event store is chosen by -EventsPath then $env:PLASMA_EVENTS then
  C:\ProgramData\Plasma\data\events.jsonl.

.EXAMPLE
  .\bridge.ps1 -Tool plasma_overview
  .\bridge.ps1 -Tool plasma_alerts -ArgsJson '{"severity":"critical"}'
  .\bridge.ps1 -Coverage
#>
[CmdletBinding()]
param(
    [string]$Tool,
    [string]$ArgsJson = '{}',
    [string]$EventsPath = $env:PLASMA_EVENTS,
    [switch]$Coverage,
    [switch]$List
)

$ErrorActionPreference = 'Stop'
$ROW_CAP = 25
$KINDS = @('alert','auth','dns','file','image_load','network','process','registry')
$SEVERITIES = @('info','low','medium','high','critical')
$SOURCES = @('sentinel','sysmon','sealighter','plasma')
$ACTIONS = @('allowed','blocked','quarantined','killed','logged')
$DIGEST_FIELDS = @('ts','host','source','kind','event_id','severity','user','process','pid','parent','cmdline','dest_ip','dest_port','dns_query','file_path','file_hash','registry_path','technique','alert_id','score','action','description')

$script:Validation = @{ parsed = 0; failed = 0; errors = @() }

function Resolve-EventsPath {
    if ($EventsPath) { return $EventsPath }
    $candidates = @()
    $candidates += (Join-Path $PSScriptRoot 'events.jsonl')
    $candidates += (Join-Path (Split-Path $PSScriptRoot -Parent) 'samples/plasma_events.jsonl')
    if ($env:ProgramData) { $candidates += (Join-Path $env:ProgramData 'Plasma/data/events.jsonl') }
    $candidates += '/var/lib/plasma/events.jsonl'
    foreach ($c in $candidates) { if ($c -and (Test-Path -LiteralPath $c)) { return $c } }
    return $candidates[0]
}

function Test-EventShape {
    param($Row)
    if ($null -eq $Row) { return 'null row' }
    foreach ($f in @('ts','host','source','kind','event_id','severity')) {
        if ($null -eq $Row.$f -or "$($Row.$f)" -eq '') { return "missing $f" }
    }
    if ($Row.host -notmatch '^[A-Za-z0-9][A-Za-z0-9._-]{0,62}$') { return 'bad host' }
    if ($Row.source -notin $SOURCES) { return "bad source: $($Row.source)" }
    if ($Row.kind -notin $KINDS) { return "bad kind: $($Row.kind)" }
    if ($Row.severity -notin $SEVERITIES) { return "bad severity: $($Row.severity)" }
    if (-not ($Row.event_id -as [int])) { return 'bad event_id' }
    if ($null -ne $Row.technique -and $Row.technique -notmatch '^T\d{4}(\.\d{3})?$') { return 'bad technique' }
    if ($null -ne $Row.file_hash -and $Row.file_hash -notmatch '^[A-Fa-f0-9]{64}$') { return 'bad file_hash' }
    if ($null -ne $Row.score -and ([double]$Row.score -lt 0 -or [double]$Row.score -gt 1)) { return 'bad score' }
    if ($null -ne $Row.dest_port -and ([int]$Row.dest_port -lt 0 -or [int]$Row.dest_port -gt 65535)) { return 'bad dest_port' }
    if ($null -ne $Row.action -and $Row.action -notin $ACTIONS) { return 'bad action' }
    return $null
}

function Read-Events {
    $path = Resolve-EventsPath
    if (-not (Test-Path -LiteralPath $path)) {
        return @{ rows = @(); error = "event store not found: $path" }
    }
    $rows = @()
    $script:Validation = @{ parsed = 0; failed = 0; errors = @() }
    foreach ($line in [System.IO.File]::ReadLines($path)) {
        if ([string]::IsNullOrWhiteSpace($line)) { continue }
        try { $obj = $line | ConvertFrom-Json } catch {
            $script:Validation.failed++
            if ($script:Validation.errors.Count -lt 5) { $script:Validation.errors += "json: $($_.Exception.Message)" }
            continue
        }
        $problem = Test-EventShape $obj
        if ($problem) {
            $script:Validation.failed++
            if ($script:Validation.errors.Count -lt 5) { $script:Validation.errors += $problem }
        } else {
            $rows += $obj
            $script:Validation.parsed++
        }
    }
    return @{ rows = $rows; error = $null }
}

function Get-Digest {
    param($Row)
    $out = [ordered]@{}
    foreach ($f in $DIGEST_FIELDS) {
        if ($null -ne $Row.$f -and "$($Row.$f)" -ne '') { $out[$f] = $Row.$f }
    }
    [pscustomobject]$out
}

function Get-Capped {
    param($Rows)
    @($Rows | Select-Object -First $ROW_CAP | ForEach-Object { Get-Digest $_ })
}

function Sort-Newest { param($Rows) @($Rows | Sort-Object -Property ts -Descending) }

function Match-Text {
    param($Value, $Needle)
    if (-not $Needle) { return $true }
    return ("$Value" -like "*$Needle*")
}

function Get-CountMap {
    param($Rows, [scriptblock]$Key)
    $map = [ordered]@{}
    foreach ($r in $Rows) {
        $k = & $Key $r
        if ($null -eq $k -or "$k" -eq '') { $k = 'unknown' }
        if ($map.Contains($k)) { $map[$k] = [int]$map[$k] + 1 } else { $map[$k] = 1 }
    }
    $map.GetEnumerator() | Sort-Object -Property Value -Descending | Select-Object -First $ROW_CAP |
        ForEach-Object { [pscustomobject]@{ name = $_.Key; count = $_.Value } }
}

function Get-EntityValue {
    param($Row, $Kind)
    switch ($Kind) {
        'host' { $Row.host }
        'process' { $Row.process }
        'parent' { $Row.parent }
        'user' { $Row.user }
        'ip' { $Row.dest_ip }
        'dns' { $Row.dns_query }
        'file' { $Row.file_path }
        'registry' { $Row.registry_path }
        'technique' { $Row.technique }
    }
}

function Invoke-Probe {
    param([string]$Name, $ProbeArgs)

    $read = Read-Events
    if ($read.error) { return @{ error = $read.error } }
    $rows = @($read.rows)

    switch ($Name) {
        'plasma_overview' {
            $alerts = @($rows | Where-Object { $_.kind -eq 'alert' })
            return @{
                events = $rows.Count
                alerts = $alerts.Count
                killed = @($alerts | Where-Object { $_.action -eq 'killed' }).Count
                by_kind = @(Get-CountMap $rows { param($r) $r.kind })
                by_severity = @(Get-CountMap $rows { param($r) $r.severity })
                by_host = @(Get-CountMap $rows { param($r) $r.host })
                by_source = @(Get-CountMap $rows { param($r) $r.source })
                techniques = @(Get-CountMap @($rows | Where-Object { $_.technique }) { param($r) $r.technique })
                coverage_pct = if ($script:Validation.parsed + $script:Validation.failed -gt 0) {
                    [math]::Round(100.0 * $script:Validation.parsed / ($script:Validation.parsed + $script:Validation.failed), 2) } else { 0 }
            }
        }
        'plasma_recent' {
            if ($ProbeArgs.host) { $rows = @($rows | Where-Object { Match-Text $_.host $ProbeArgs.host }) }
            $ordered = @(Sort-Newest $rows)
            $limit = if ($ProbeArgs.limit) { [math]::Min([math]::Max([int]$ProbeArgs.limit, 1), $ROW_CAP) } else { 10 }
            return @{ returned = [math]::Min($limit, $ordered.Count); events = @(Get-Capped ($ordered | Select-Object -First $limit)) }
        }
        'plasma_alerts' {
            $a = @($rows | Where-Object { $_.kind -eq 'alert' })
            if ($ProbeArgs.severity) { $a = @($a | Where-Object { $_.severity -eq $ProbeArgs.severity }) }
            if ($ProbeArgs.technique) { $a = @($a | Where-Object { Match-Text $_.technique $ProbeArgs.technique }) }
            return @{
                count = $a.Count
                by_technique = @(Get-CountMap $a { param($r) $r.technique })
                by_severity = @(Get-CountMap $a { param($r) $r.severity })
                by_action = @(Get-CountMap $a { param($r) $r.action })
                alerts = @(Get-Capped (Sort-Newest $a))
            }
        }
        'plasma_processes' {
            $p = @($rows | Where-Object { $_.kind -in @('process','image_load') })
            if ($ProbeArgs.host) { $p = @($p | Where-Object { Match-Text $_.host $ProbeArgs.host }) }
            if ($ProbeArgs.process) { $p = @($p | Where-Object { Match-Text $_.process $ProbeArgs.process }) }
            if ($ProbeArgs.user) { $p = @($p | Where-Object { Match-Text $_.user $ProbeArgs.user }) }
            return @{
                count = $p.Count
                by_process = @(Get-CountMap $p { param($r) $r.process })
                by_technique = @(Get-CountMap $p { param($r) $r.technique })
                events = @(Get-Capped (Sort-Newest $p))
            }
        }
        'plasma_network' {
            $n = @($rows | Where-Object { $_.kind -eq 'network' })
            if ($ProbeArgs.dest_ip) { $n = @($n | Where-Object { Match-Text $_.dest_ip $ProbeArgs.dest_ip }) }
            if ($ProbeArgs.dest_port) { $n = @($n | Where-Object { [int]$_.dest_port -eq [int]$ProbeArgs.dest_port }) }
            return @{
                count = $n.Count
                by_destination = @(Get-CountMap $n { param($r) "$($r.dest_ip):$($r.dest_port)" })
                by_process = @(Get-CountMap $n { param($r) $r.process })
                connections = @(Get-Capped (Sort-Newest $n))
            }
        }
        'plasma_dns' {
            $d = @($rows | Where-Object { $_.kind -eq 'dns' })
            if ($ProbeArgs.query) { $d = @($d | Where-Object { Match-Text $_.dns_query $ProbeArgs.query }) }
            return @{
                count = $d.Count
                by_query = @(Get-CountMap $d { param($r) $r.dns_query })
                lookups = @(Get-Capped (Sort-Newest $d))
            }
        }
        'plasma_persistence' {
            $h = @($rows | Where-Object {
                $_.kind -eq 'registry' -or ($_.kind -eq 'file' -and $_.technique) -or
                ($_.technique -and $_.technique -match '^T(154|1053)')
            })
            return @{
                count = $h.Count
                by_technique = @(Get-CountMap $h { param($r) $r.technique })
                by_artifact = @(Get-CountMap $h { param($r) if ($r.registry_path) { 'registry' } else { 'file' } })
                events = @(Get-Capped (Sort-Newest $h))
            }
        }
        'plasma_search' {
            if (-not $ProbeArgs.text) { return @{ error = 'text is required' } }
            $text = $ProbeArgs.text
            $h = @($rows | Where-Object {
                (Match-Text $_.cmdline $text) -or (Match-Text $_.description $text) -or
                (Match-Text $_.file_path $text) -or (Match-Text $_.file_hash $text) -or
                (Match-Text $_.registry_path $text) -or
                (Match-Text $_.dns_query $text) -or (Match-Text $_.user $text) -or
                (Match-Text $_.process $text) -or (Match-Text $_.image $text) -or
                (Match-Text $_.technique $text) -or (Match-Text $_.alert_id $text)
            })
            return @{ count = $h.Count; query = $text; events = @(Get-Capped (Sort-Newest $h)) }
        }
        'plasma_graph_overview' {
            $nodeKinds = @('host','process','parent','user','ip','dns','file','registry','technique')
            $nodes = [ordered]@{}
            foreach ($k in $nodeKinds) {
                $vals = @($rows | ForEach-Object { Get-EntityValue $_ $k } | Where-Object { $_ })
                $unique = @($vals | Sort-Object -Unique)
                $nodes[$k] = @{ count = $unique.Count; top = @($unique | Select-Object -First 10) }
            }
            $edgeTypes = [ordered]@{}
            foreach ($r in $rows) {
                if ($r.process -and $r.host) { $edgeTypes['runs_on'] = 1 + $(if ($edgeTypes.Contains('runs_on')) { $edgeTypes['runs_on'] } else { 0 }) }
                if ($r.process -and $r.parent) { $edgeTypes['spawned_by'] = 1 + $(if ($edgeTypes.Contains('spawned_by')) { $edgeTypes['spawned_by'] } else { 0 }) }
                if ($r.dest_ip) { $edgeTypes['connects_to'] = 1 + $(if ($edgeTypes.Contains('connects_to')) { $edgeTypes['connects_to'] } else { 0 }) }
                if ($r.dns_query) { $edgeTypes['resolves'] = 1 + $(if ($edgeTypes.Contains('resolves')) { $edgeTypes['resolves'] } else { 0 }) }
                if ($r.file_path) { $edgeTypes['writes_file'] = 1 + $(if ($edgeTypes.Contains('writes_file')) { $edgeTypes['writes_file'] } else { 0 }) }
                if ($r.registry_path) { $edgeTypes['writes_registry'] = 1 + $(if ($edgeTypes.Contains('writes_registry')) { $edgeTypes['writes_registry'] } else { 0 }) }
                if ($r.technique) { $edgeTypes['exhibits'] = 1 + $(if ($edgeTypes.Contains('exhibits')) { $edgeTypes['exhibits'] } else { 0 }) }
            }
            return @{ events = $rows.Count; nodes = $nodes; edges = $edgeTypes; disjoint = @() }
        }
        'plasma_graph_neighbors' {
            if (-not $ProbeArgs.node) { return @{ error = 'node is required' } }
            $needle = [string]$ProbeArgs.node
            $nodeKinds = @('host','process','parent','user','ip','dns','file','registry','technique')
            $hits = @($rows | Where-Object {
                $hit = $false
                foreach ($k in $nodeKinds) { if (Match-Text (Get-EntityValue $_ $k) $needle) { $hit = $true } }
                $hit
            })
            if ($hits.Count -eq 0) { return @{ node = $needle; found = $false; neighbors = @{} } }
            $neighbors = [ordered]@{}
            foreach ($k in $nodeKinds) {
                $vals = @($hits | ForEach-Object { Get-EntityValue $_ $k } | Where-Object { $_ -and -not (Match-Text $_ $needle) })
                if ($vals.Count -gt 0) { $neighbors[$k] = @(Get-CountMap ($vals | ForEach-Object { [pscustomobject]@{ v = $_ } }) { param($r) $r.v }) }
            }
            return @{
                node = $needle; found = $true; events = $hits.Count
                neighbors = $neighbors
                by_technique = @(Get-CountMap $hits { param($r) $r.technique })
                sample_events = @(Get-Capped (Sort-Newest $hits))
            }
        }
        default { return @{ error = "unknown probe: $Name" } }
    }
}

function Get-Coverage {
    $read = Read-Events
    if ($read.error) { return @{ error = $read.error } }
    $total = $script:Validation.parsed + $script:Validation.failed
    $pct = if ($total -gt 0) { [math]::Round(100.0 * $script:Validation.parsed / $total, 2) } else { 0 }
    return @{
        total = $total; parsed = $script:Validation.parsed; failed = $script:Validation.failed
        coverage_pct = $pct; errors = $script:Validation.errors
    }
}

$PROBES = @(
    'plasma_overview','plasma_recent','plasma_alerts','plasma_processes',
    'plasma_network','plasma_dns','plasma_persistence','plasma_search',
    'plasma_graph_overview','plasma_graph_neighbors'
)

if ($List) { @{ probes = $PROBES } | ConvertTo-Json -Depth 5; exit 0 }
if ($Coverage) { Get-Coverage | ConvertTo-Json -Depth 5; exit 0 }
if (-not $Tool) { Write-Error 'Tool is required (or use -Coverage / -List)'; exit 2 }

try { $argsObj = $ArgsJson | ConvertFrom-Json } catch { @{ error = "bad ArgsJson: $($_.Exception.Message)" } | ConvertTo-Json -Depth 5; exit 2 }
$result = Invoke-Probe -Name $Tool -ProbeArgs $argsObj
$result | ConvertTo-Json -Depth 10
