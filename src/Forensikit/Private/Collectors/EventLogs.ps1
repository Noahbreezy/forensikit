function Invoke-FSKCollectEventLogs {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Run,
        [Parameter(Mandatory)]$Logger,
        [Parameter(Mandatory)]$Profile
    )

    $outDir = Join-Path $Run.Persistent 'eventlogs'

    $hours = [int]$Profile.EventLogHours
    if ($hours -lt 1) { $hours = 24 }
    $platform = Get-FSKPlatform

    if ($platform -eq 'Windows') {
        $startTime = (Get-Date).ToUniversalTime().AddHours(-1 * $hours)
        $logs = @('System','Security','Application')

        foreach ($logName in $logs) {
            try {
                $filter = @{ LogName = $logName; StartTime = $startTime }
                $events = Get-WinEvent -FilterHashtable $filter -ErrorAction Stop

                $events | Select-Object TimeCreated, Id, LevelDisplayName, ProviderName, MachineName, Message | Export-Csv -Path (Join-Path $outDir "$logName`_events.csv") -NoTypeInformation -Encoding UTF8
                $events | Select-Object TimeCreated, Id, LevelDisplayName, ProviderName, MachineName, Message | ConvertTo-Json -Depth 4 | Out-File -FilePath (Join-Path $outDir "$logName`_events.json") -Encoding UTF8

                Write-FSKLog -Logger $Logger -Level INFO -Message "Collected event log: $logName (last $hours hours)"
            } catch {
                Write-FSKLog -Logger $Logger -Level WARN -Message "Failed to collect event log: $logName" -Exception $_.Exception
            }
        }

        return
    }

    # Linux/macOS equivalents (best-effort)
    try {
        $sinceIso = (Get-Date).ToUniversalTime().AddHours(-1 * $hours).ToString('o')
        if ($platform -eq 'Linux' -and (Get-Command journalctl -ErrorAction SilentlyContinue)) {
            & journalctl --since $sinceIso --no-pager 2>&1 | Out-File -FilePath (Join-Path $outDir 'journalctl_since.txt') -Encoding UTF8
            try {
                & journalctl --since $sinceIso --no-pager -o json 2>&1 | Out-File -FilePath (Join-Path $outDir 'journalctl_since.jsonl') -Encoding UTF8
            } catch { }
        }

        # Common file-based logs when present
        foreach ($p in @('/var/log/syslog','/var/log/auth.log','/var/log/messages','/var/log/secure')) {
            if (Test-Path $p) {
                try {
                    Get-Content -Path $p -ErrorAction Stop | Out-File -FilePath (Join-Path $outDir (Split-Path $p -Leaf)) -Encoding UTF8
                } catch {
                    Write-FSKLog -Logger $Logger -Level WARN -Message "Failed to read log file $p" -Exception $_.Exception
                }
            }
        }

        if ($platform -eq 'macOS' -and (Get-Command log -ErrorAction SilentlyContinue)) {
            # macOS unified log (can be large; keep scoped by time)
            & log show --style syslog --last ("$hours" + 'h') 2>&1 | Out-File -FilePath (Join-Path $outDir 'macos_log_show.txt') -Encoding UTF8
        }

        Write-FSKLog -Logger $Logger -Level INFO -Message "Collected logs ($platform, last $hours hours)"
    } catch {
        Write-FSKLog -Logger $Logger -Level WARN -Message "Failed to collect logs ($platform)" -Exception $_.Exception
    }
}
