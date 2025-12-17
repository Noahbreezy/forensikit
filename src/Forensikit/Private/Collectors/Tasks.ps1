function Invoke-FSKCollectScheduledTasks {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Run,
        [Parameter(Mandatory)]$Logger
    )

    $outDir = Join-Path $Run.Persistent 'tasks'

    try {
        $platform = Get-FSKPlatform

        if ($platform -ne 'Windows') {
            # Unix scheduled tasks = cron/systemd timers (best-effort)
            try { & crontab -l 2>&1 | Out-File -FilePath (Join-Path $outDir 'crontab_current_user.txt') -Encoding UTF8 } catch { }
            foreach ($p in @('/etc/crontab','/etc/cron.d','/etc/cron.daily','/etc/cron.hourly','/etc/cron.weekly','/etc/cron.monthly')) {
                try {
                    if (Test-Path $p) {
                        if ((Get-Item $p).PSIsContainer) {
                            Get-ChildItem -Path $p -File -ErrorAction SilentlyContinue | ForEach-Object {
                                try { Get-Content -Path $_.FullName -ErrorAction Stop | Out-File -FilePath (Join-Path $outDir ("cron_" + $_.Name + '.txt')) -Encoding UTF8 } catch { }
                            }
                        } else {
                            Get-Content -Path $p -ErrorAction SilentlyContinue | Out-File -FilePath (Join-Path $outDir (Split-Path $p -Leaf)) -Encoding UTF8
                        }
                    }
                } catch { }
            }
            if ($platform -eq 'Linux' -and (Get-Command systemctl -ErrorAction SilentlyContinue)) {
                try { & systemctl list-timers --all 2>&1 | Out-File -FilePath (Join-Path $outDir 'systemctl_timers.txt') -Encoding UTF8 } catch { }
            }

            Write-FSKLog -Logger $Logger -Level INFO -Message "Collected scheduled tasks equivalents ($platform)"
            return
        }

        try {
            $tasks = Get-ScheduledTask -ErrorAction Stop
        } catch {
            Write-FSKLog -Logger $Logger -Level WARN -Message 'ScheduledTasks collector unavailable or access denied' -Exception $_.Exception
            'ScheduledTasks collector unavailable or access denied.' | Out-File -FilePath (Join-Path $outDir 'scheduled_tasks_error.txt') -Encoding UTF8
            return
        }

        $flat = $tasks | ForEach-Object {
            $actions = $_.Actions | ForEach-Object { (($_.Execute + ' ' + ([string]$_.Arguments)).Trim()) } | Where-Object { $_ }
            $triggers = $_.Triggers | ForEach-Object { $_.ToString() }
            [pscustomobject]@{
                TaskName   = $_.TaskName
                TaskPath   = $_.TaskPath
                State      = $_.State
                Enabled    = $_.Enabled
                Actions    = ($actions -join '; ')
                Triggers   = ($triggers -join '; ')
                Author     = $_.Author
                Description= $_.Description
            }
        }

        $flat | Export-Csv -Path (Join-Path $outDir 'scheduled_tasks.csv') -NoTypeInformation -Encoding UTF8
        # Convert the flattened view to JSON; raw ScheduledTask objects can be difficult to serialize on Windows PowerShell 5.1
        $flat | ConvertTo-Json -Depth 6 | Out-File -FilePath (Join-Path $outDir 'scheduled_tasks.json') -Encoding UTF8

        Write-FSKLog -Logger $Logger -Level INFO -Message 'Collected scheduled tasks'
    } catch {
        Write-FSKLog -Logger $Logger -Level WARN -Message 'Failed to fully collect scheduled tasks (partial results may exist)' -Exception $_.Exception
    }
}
