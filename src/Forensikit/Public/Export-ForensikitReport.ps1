function Export-ForensikitReport {
    <#
    .SYNOPSIS
    Generates a human-readable forensic report from a Forensikit run folder.

    .DESCRIPTION
        Produces a Markdown report from an existing Forensikit output folder. The input can be:
      - a per-host folder (<OutputPath>\<RunId>\<ComputerName>) containing run.json, or
      - a run root folder (<OutputPath>\<RunId>) containing one or more host subfolders.

        Additionally, when given an integration root folder (<OutputPath>\integration\<timestamp_guid>)
        containing multiple run folders, it produces a summary report across all runs/hosts.

    Optionally converts Markdown to HTML when ConvertFrom-Markdown is available (PowerShell 7+).

    .PARAMETER Path
    Path to the run root folder or a per-host folder.

    .PARAMETER OutputPath
    Output file path. Defaults to report.md (or report.html) under the provided folder.

    .PARAMETER Format
    Markdown (default) or Html.
    #>

    [CmdletBinding()]
    param(
        [Parameter(Mandatory, Position = 0)]
        [ValidateScript({ Test-Path $_ })]
        [string]$Path,

        [Parameter()]
        [string]$OutputPath,

        [Parameter()]
        [ValidateSet('Markdown', 'Html')]
        [string]$Format = 'Markdown'
    )

    function Get-FSKSafeJson {
        param([Parameter(Mandatory)][string]$JsonPath)
        try {
            (Get-Content -Path $JsonPath -Raw -Encoding UTF8 -ErrorAction Stop) | ConvertFrom-Json -ErrorAction Stop
        } catch {
            $null
        }
    }

    function Get-FSKCsvCount {
        param([Parameter(Mandatory)][string]$CsvPath)
        if (-not (Test-Path $CsvPath)) { return $null }
        try {
            (Import-Csv -Path $CsvPath -ErrorAction Stop).Count
        } catch {
            $null
        }
    }

    function Get-FSKLogStats {
        param([Parameter(Mandatory)][string]$LogPath)

        if (-not (Test-Path $LogPath)) {
            return [pscustomobject]@{ Warn = 0; Error = 0; Tail = @() }
        }

        $lines = Get-Content -Path $LogPath -ErrorAction SilentlyContinue
        $lines = @($lines)

        $warn = @($lines | Where-Object { $_ -match '\[WARN\]' }).Count
        $err  = @($lines | Where-Object { $_ -match '\[ERROR\]' }).Count
        $tail = if ($lines.Count -gt 40) { $lines[-40..-1] } else { $lines }

        [pscustomobject]@{ Warn = $warn; Error = $err; Tail = $tail }
    }

    function Get-FSKHostFoldersFromRoot {
        param([Parameter(Mandatory)][string]$RunRoot)
        $dirs = Get-ChildItem -Path $RunRoot -Directory -ErrorAction SilentlyContinue
        if (-not $dirs) { return @() }

        $hosts = foreach ($d in $dirs) {
            if (Test-Path (Join-Path $d.FullName 'run.json')) { $d.FullName }
        }
        @($hosts)
    }

    function Get-FSKHostFoldersFromIntegrationRoot {
        param([Parameter(Mandatory)][string]$IntegrationRoot)

        $dirs = Get-ChildItem -Path $IntegrationRoot -Directory -ErrorAction SilentlyContinue
        if (-not $dirs) { return @() }

        $hostFolders = New-Object System.Collections.Generic.List[string]
        foreach ($d in $dirs) {
            $hosts = Get-FSKHostFoldersFromRoot -RunRoot $d.FullName
            foreach ($h in @($hosts)) { $hostFolders.Add($h) }
        }
        @($hostFolders.ToArray())
    }

    function Get-FSKIntegrityStats {
        param([Parameter(Mandatory)][string]$IntegrityCsvPath)

        if (-not (Test-Path -LiteralPath $IntegrityCsvPath)) {
            return [pscustomobject]@{ Count = $null; Bytes = $null; Largest = @() }
        }

        try {
            $rows = @(Import-Csv -Path $IntegrityCsvPath -ErrorAction Stop)
            $count = $rows.Count

            $bytes = 0
            foreach ($r in $rows) {
                $len = 0
                if ($null -ne $r.Length -and [long]::TryParse([string]$r.Length, [ref]$len)) {
                    $bytes += $len
                }
            }

            $largest = @(
                $rows |
                    Where-Object { $_.RelativePath } |
                    ForEach-Object {
                        $len = 0
                        [void][long]::TryParse([string]$_.Length, [ref]$len)
                        [pscustomobject]@{ RelativePath = [string]$_.RelativePath; Length = $len }
                    } |
                    Sort-Object -Property Length -Descending |
                    Select-Object -First 10
            )

            return [pscustomobject]@{ Count = $count; Bytes = $bytes; Largest = $largest }
        } catch {
            return [pscustomobject]@{ Count = $null; Bytes = $null; Largest = @() }
        }
    }

    function ConvertTo-FSKMarkdownReport {
        param(
            [Parameter(Mandatory)][string[]]$HostFolders,
            [Parameter(Mandatory)][string]$InputRoot,
            [Parameter(Mandatory)][string]$NowUtc,
            [Parameter()][switch]$SummaryOnly
        )

        $nl = [Environment]::NewLine
        $summaries = foreach ($hostFolder in $HostFolders) {
            $hostName = Split-Path -Path $hostFolder -Leaf
            $runId = Split-Path -Path (Split-Path -Path $hostFolder -Parent) -Leaf

            $meta = $null
            $runJson = Join-Path $hostFolder 'run.json'
            if (Test-Path $runJson) { $meta = Get-FSKSafeJson -JsonPath $runJson }

            $logPath = Join-Path $hostFolder 'logs\collector.log'
            $log = Get-FSKLogStats -LogPath $logPath

            $integrityPath = Join-Path $hostFolder 'integrity.csv'
            $integrity = Get-FSKIntegrityStats -IntegrityCsvPath $integrityPath
            $integrityCount = $integrity.Count
            $procCount = Get-FSKCsvCount -CsvPath (Join-Path $hostFolder 'volatile\processes\processes.csv')
            $tcpCount  = Get-FSKCsvCount -CsvPath (Join-Path $hostFolder 'volatile\network\net_tcp_connections.csv')
            $udpCount  = Get-FSKCsvCount -CsvPath (Join-Path $hostFolder 'volatile\network\net_udp_endpoints.csv')

            $sysCount  = Get-FSKCsvCount -CsvPath (Join-Path $hostFolder 'persistent\eventlogs\System_events.csv')
            $secCount  = Get-FSKCsvCount -CsvPath (Join-Path $hostFolder 'persistent\eventlogs\Security_events.csv')
            $appCount  = Get-FSKCsvCount -CsvPath (Join-Path $hostFolder 'persistent\eventlogs\Application_events.csv')

            $mode = if ($meta -and $meta.Mode) { [string]$meta.Mode } else { 'Unknown' }
            $started = if ($meta -and $meta.StartedUtc) { [string]$meta.StartedUtc } else { '' }
            $ended = if ($meta -and $meta.EndedUtc) { [string]$meta.EndedUtc } else { '' }
            $user = if ($meta -and $meta.User) { [string]$meta.User } else { '' }
            $version = if ($meta -and $meta.Version) { [string]$meta.Version } else { '' }
            $collectors = if ($meta -and $meta.Collectors) { @($meta.Collectors | ForEach-Object { [string]$_ }) } else { @() }

            [pscustomobject]@{
                RunId = $runId
                Host = $hostName
                Mode = $mode
                StartedUtc = $started
                EndedUtc = $ended
                User = $user
                Version = $version
                Collectors = if ($collectors.Count -gt 0) { ($collectors -join ', ') } else { 'Unknown' }
                WarnCount = $log.Warn
                ErrorCount = $log.Error
                LogTail = $log.Tail
                IntegrityCount = $integrityCount
                IntegrityBytes = $integrity.Bytes
                IntegrityLargest = $integrity.Largest
                ProcCount = $procCount
                TcpCount = $tcpCount
                UdpCount = $udpCount
                SysEventCount = $sysCount
                SecEventCount = $secCount
                AppEventCount = $appCount
            }
        }

        $runIds = @($summaries | Select-Object -ExpandProperty RunId -Unique)

        $md = New-Object System.Collections.Generic.List[string]
        $md.Add('# Forensikit Report')
        $md.Add('')
        $md.Add(('GeneratedUtc: {0}' -f $NowUtc))
        $md.Add(('InputPath: {0}' -f $InputRoot))
        if ($runIds.Count -eq 1) {
            $md.Add(('RunId: {0}' -f $runIds[0]))
        } else {
            $md.Add(('Runs: {0}' -f $runIds.Count))
        }
        $md.Add('')

        $md.Add('## Summary')
        $md.Add('')
        $md.Add(('Hosts: {0}' -f $summaries.Count))
        $md.Add(('Warnings: {0}' -f (($summaries | Measure-Object -Property WarnCount -Sum).Sum)))
        $md.Add(('Errors: {0}' -f (($summaries | Measure-Object -Property ErrorCount -Sum).Sum)))
        $md.Add(('Artifacts (integrity rows): {0}' -f (($summaries | Measure-Object -Property IntegrityCount -Sum).Sum)))
        $md.Add(('Artifacts bytes: {0}' -f (($summaries | Measure-Object -Property IntegrityBytes -Sum).Sum)))
        $md.Add('')

        if ($runIds.Count -gt 1) {
            $md.Add('## Per-run Summary')
            $md.Add('')
            $md.Add('| RunId | Hosts | WARN | ERROR | Integrity rows | Integrity bytes |')
            $md.Add('|---|---:|---:|---:|---:|---:|')
            foreach ($rid in ($runIds | Sort-Object)) {
                $rs = @($summaries | Where-Object { $_.RunId -eq $rid })
                $md.Add(('| {0} | {1} | {2} | {3} | {4} | {5} |' -f $rid, $rs.Count, (($rs | Measure-Object -Property WarnCount -Sum).Sum), (($rs | Measure-Object -Property ErrorCount -Sum).Sum), (($rs | Measure-Object -Property IntegrityCount -Sum).Sum), (($rs | Measure-Object -Property IntegrityBytes -Sum).Sum)))
            }
            $md.Add('')
        }

        $md.Add('## Per-host Overview')
        $md.Add('')
        $md.Add('| RunId | Host | Mode | StartedUtc | EndedUtc | WARN | ERROR | Integrity rows | Integrity bytes | Processes | TCP conns | UDP endpoints | Sys events | Sec events | App events |')
        $md.Add('|---|---|---|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|')

        foreach ($h in ($summaries | Sort-Object RunId, Host)) {
            $md.Add(('| {0} | {1} | {2} | {3} | {4} | {5} | {6} | {7} | {8} | {9} | {10} | {11} | {12} | {13} | {14} |' -f $h.RunId, $h.Host, $h.Mode, $h.StartedUtc, $h.EndedUtc, $h.WarnCount, $h.ErrorCount, $h.IntegrityCount, $h.IntegrityBytes, $h.ProcCount, $h.TcpCount, $h.UdpCount, $h.SysEventCount, $h.SecEventCount, $h.AppEventCount))
        }

        $md.Add('')
        $md.Add('## Notes')
        $md.Add('')
        $md.Add('- This report summarizes collected outputs; it does not guarantee forensic completeness.')
        $md.Add('- Review each host''s logs/collector.log for permission or collection warnings.')
        $md.Add('- For event logs, low counts may indicate retention limits or access restrictions.')
        $md.Add('')

        if ($SummaryOnly) {
            return ($md -join $nl)
        }

        foreach ($h in ($summaries | Sort-Object RunId, Host)) {
            $md.Add(('## Host: {0}' -f $h.Host))
            $md.Add('')
            $md.Add(('- RunId: {0}' -f $h.RunId))
            $md.Add(('- Mode: {0}' -f $h.Mode))
            if ($h.Version) { $md.Add(('- Tool version: {0}' -f $h.Version)) }
            if ($h.User) { $md.Add(('- User: {0}' -f $h.User)) }
            if ($h.StartedUtc) { $md.Add(('- StartedUtc: {0}' -f $h.StartedUtc)) }
            if ($h.EndedUtc) { $md.Add(('- EndedUtc: {0}' -f $h.EndedUtc)) }
            $md.Add(('- Collectors: {0}' -f $h.Collectors))
            $md.Add(('- WARN/ERROR: {0}/{1}' -f $h.WarnCount, $h.ErrorCount))
            $md.Add('')
            $md.Add('### Key files')
            $md.Add('')
            $md.Add(('- integrity.csv rows: {0}' -f $h.IntegrityCount))
            $md.Add(('- integrity.csv bytes: {0}' -f $h.IntegrityBytes))
            $md.Add('')
            if ($h.IntegrityLargest -and $h.IntegrityLargest.Count -gt 0) {
                $md.Add('### Largest collected files')
                $md.Add('')
                $md.Add('| RelativePath | Bytes |')
                $md.Add('|---|---:|')
                foreach ($lf in @($h.IntegrityLargest)) {
                    $md.Add(('| {0} | {1} |' -f $lf.RelativePath, $lf.Length))
                }
                $md.Add('')
            }
            $md.Add('')
            $md.Add('### Collector log (tail)')
            $md.Add('')
            $md.Add('```text')
            foreach ($line in $h.LogTail) { $md.Add($line) }
            $md.Add('```')
            $md.Add('')
        }

        ($md -join $nl)
    }

    $resolved = (Resolve-Path -Path $Path).Path
    $hostFolders = @()
    $inputRoot = $resolved
    $summaryOnly = $false

    if (Test-Path (Join-Path $resolved 'run.json')) {
        $hostFolders = @($resolved)
    } else {
        $hostFolders = Get-FSKHostFoldersFromRoot -RunRoot $resolved
        $hostFolders = @($hostFolders)
        if ($hostFolders.Count -eq 0) {
            $hostFolders = Get-FSKHostFoldersFromIntegrationRoot -IntegrationRoot $resolved
            $hostFolders = @($hostFolders)
            if ($hostFolders.Count -eq 0) {
                throw ('No host folders found under "' + $resolved + '" (expected subfolders containing run.json).')
            }
            $summaryOnly = $true
        }
    }

    if (-not $OutputPath -or -not $OutputPath.Trim()) {
        $ext = if ($Format -eq 'Html') { 'html' } else { 'md' }
        $OutputPath = Join-Path $inputRoot ('report.' + $ext)
    }

    $nowUtc = (Get-Date).ToUniversalTime().ToString('o')
    $markdown = ConvertTo-FSKMarkdownReport -HostFolders $hostFolders -InputRoot $inputRoot -NowUtc $nowUtc -SummaryOnly:$summaryOnly

    if ($Format -eq 'Markdown') {
        $markdown | Out-File -FilePath $OutputPath -Encoding UTF8
        return (Resolve-Path -Path $OutputPath).Path
    }

    $htmlBody = $null

    $cmd = Get-Command -Name ConvertFrom-Markdown -ErrorAction SilentlyContinue
    if ($cmd) {
        $html = ConvertFrom-Markdown -InputObject $markdown
        $htmlBody = $html.Html
    } else {
        $pwsh = Get-Command -Name pwsh -ErrorAction SilentlyContinue
        if (-not $pwsh) {
            throw 'Format Html requires ConvertFrom-Markdown (PowerShell 7+). Use -Format Markdown or run under pwsh.'
        }

        $tmpMd = [System.IO.Path]::ChangeExtension([System.IO.Path]::GetTempFileName(), 'md')
        try {
            $markdown | Out-File -FilePath $tmpMd -Encoding UTF8
            $pwshOut = & $pwsh.Source -NoProfile -Command 'param($p) $m = Get-Content -Raw -LiteralPath $p; (ConvertFrom-Markdown -InputObject $m).Html' -Args $tmpMd
            if ($LASTEXITCODE -ne 0) {
                throw ('pwsh failed to convert Markdown to HTML (exit code ' + $LASTEXITCODE + ').')
            }
            $htmlBody = ($pwshOut -join [Environment]::NewLine)
        } finally {
            Remove-Item -LiteralPath $tmpMd -Force -ErrorAction SilentlyContinue
        }
    }
    $docParts = @(
        '<!doctype html>',
        '<html lang="en">',
        '<head>',
        '<meta charset="utf-8">',
        '<meta name="viewport" content="width=device-width, initial-scale=1">',
        '<title>Forensikit Report</title>',
        '<style>body{font-family:Segoe UI,Arial,sans-serif;margin:24px;line-height:1.4} code,pre{font-family:Consolas,monospace} table{border-collapse:collapse} td,th{border:1px solid #ccc;padding:6px 8px;vertical-align:top} th{background:#f5f5f5} pre{background:#f7f7f7;padding:12px;overflow:auto}</style>',
        '</head>',
        '<body>',
        $htmlBody,
        '</body>',
        '</html>'
    )
    ($docParts -join [Environment]::NewLine) | Out-File -FilePath $OutputPath -Encoding UTF8
    return (Resolve-Path -Path $OutputPath).Path
}
