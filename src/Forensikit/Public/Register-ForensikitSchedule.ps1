function Register-ForensikitSchedule {
    <#
    .SYNOPSIS
    Registers a periodic scheduled run of a custom Forensikit profile.

    .DESCRIPTION
    Creates a schedule folder containing a runner script (run.ps1) and (optionally) a copy of the
    provided custom profile, then registers the periodic job:
      - Windows: registers a Scheduled Task
      - Linux: generates systemd user service/timer files (and can install/enable them when available)
      - macOS: generates a LaunchAgent plist (and can attempt to load it)

    .PARAMETER Name
    Schedule name. Used for task/unit names and to create a dedicated schedule folder.

    .PARAMETER CustomProfilePath
    Path to a JSON custom profile.

    .PARAMETER OutputPath
    Base output folder used by each run.

    .PARAMETER Every
    Run interval.

    .PARAMETER StartAt
    Windows-only: first run time. Defaults to now + 5 minutes.

    .PARAMETER CopyProfile
    Copies the profile into the schedule folder so the schedule is self-contained.

    .PARAMETER RunElevated
    Windows-only: attempts to run with highest privileges.

    .PARAMETER Install
    On Linux/macOS, attempts to install and enable/load the generated scheduler artifacts.

    .EXAMPLE
    Register-ForensikitSchedule -Name dailyQuick -CustomProfilePath .\quick_profile.json -Every (New-TimeSpan -Hours 24)
    #>

    [CmdletBinding(SupportsShouldProcess = $true, DefaultParameterSetName = 'Interval')]
    param(
        [Parameter(Mandatory)]
        [ValidatePattern('^[A-Za-z0-9_.-]+$')]
        [string]$Name,

        [Parameter(Mandatory)]
        [ValidateScript({ Test-Path $_ })]
        [string]$CustomProfilePath,

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [string]$OutputPath = (Join-Path $HOME 'ForensikitOutput'),

        [Parameter(Mandatory, ParameterSetName = 'Interval')]
        [ValidateScript({ $_.TotalSeconds -ge 60 })]
        [TimeSpan]$Every,

        [Parameter(ParameterSetName = 'Interval')]
        [DateTime]$StartAt = (Get-Date).AddMinutes(5),

        [Parameter(Mandatory, ParameterSetName = 'Weekly')]
        [System.DayOfWeek[]]$DaysOfWeek,

        [Parameter(Mandatory, ParameterSetName = 'Weekly')]
        [TimeSpan]$At,

        [Parameter(Mandatory, ParameterSetName = 'Monthly')]
        [ValidateRange(1,31)]
        [int[]]$DaysOfMonth,

        [Parameter(Mandatory, ParameterSetName = 'Monthly')]
        [TimeSpan]$AtMonthly,

        [Parameter()]
        [ValidateSet('None','Ndjson')]
        [string]$SiemFormat = 'None',

        [Parameter()]
        [switch]$CopyProfile,

        [Parameter()]
        [switch]$RunElevated,

        [Parameter()]
        [switch]$Install
    )

    $platform = Get-FSKPlatform
    $moduleManifestPath = Get-FSKModuleManifestPath

    $runner = New-FSKScheduleRunner -Name $Name -CustomProfilePath $CustomProfilePath -OutputPath $OutputPath -ModuleManifestPath $moduleManifestPath -SiemFormat $SiemFormat -CopyProfile:$CopyProfile

    $spec = $null
    switch ($PSCmdlet.ParameterSetName) {
        'Interval' { $spec = New-FSKScheduleSpec -Every $Every -StartAt $StartAt }
        'Weekly'   { $spec = New-FSKScheduleSpec -DaysOfWeek $DaysOfWeek -At $At }
        'Monthly'  { $spec = New-FSKScheduleSpec -DaysOfMonth $DaysOfMonth -AtMonthly $AtMonthly }
        default    { throw "Unknown parameter set: $($PSCmdlet.ParameterSetName)" }
    }

    $result = [ordered]@{
        Name = $Name
        Platform = $platform
        ScheduleRoot = $runner.ScheduleRoot
        RunnerScript = $runner.RunnerScript
        ProfilePath = $runner.ProfilePath
        Registered = $false
        Details = $null
        Notes = @()
    }

    switch ($platform) {
        'Windows' {
            $taskName = $null
            if ($spec.Type -eq 'Interval') {
                $taskName = Register-FSKWindowsScheduledTask -Name $Name -RunnerScript $runner.RunnerScript -Every $spec.Every -StartAt $spec.StartAt -RunElevated:$RunElevated
            } elseif ($spec.Type -eq 'Weekly') {
                $taskName = Register-FSKWindowsScheduledTask -Name $Name -RunnerScript $runner.RunnerScript -DaysOfWeek $spec.DaysOfWeek -At $spec.At -RunElevated:$RunElevated
            } elseif ($spec.Type -eq 'Monthly') {
                $taskName = Register-FSKWindowsScheduledTask -Name $Name -RunnerScript $runner.RunnerScript -DaysOfMonth $spec.DaysOfMonth -AtMonthly $spec.At -RunElevated:$RunElevated
            } else {
                throw "Unsupported schedule type: $($spec.Type)"
            }
            $result.Registered = $true
            $result.Details = [pscustomobject]@{ ScheduledTask = $taskName; Spec = $spec }
        }

        'Linux' {
            $units = $null
            if ($spec.Type -eq 'Interval') {
                $units = New-FSKSystemdUserUnits -Name $Name -RunnerScript $runner.RunnerScript -Every $spec.Every
            } elseif ($spec.Type -eq 'Weekly') {
                $days = (ConvertTo-FSKSystemdDayOfWeek -DaysOfWeek $spec.DaysOfWeek) -join ','
                $time = ConvertTo-FSKTimeString -At $spec.At
                $units = New-FSKSystemdUserUnits -Name $Name -RunnerScript $runner.RunnerScript -OnCalendar "$days *-*-* $time"
            } elseif ($spec.Type -eq 'Monthly') {
                $dayList = (@($spec.DaysOfMonth) -join ',')
                $time = ConvertTo-FSKTimeString -At $spec.At
                $units = New-FSKSystemdUserUnits -Name $Name -RunnerScript $runner.RunnerScript -OnCalendar "*-*-$dayList $time"
            } else {
                throw "Unsupported schedule type: $($spec.Type)"
            }
            $userDir = Join-Path $HOME '.config/systemd/user'
            if (-not (Test-Path $userDir)) { New-Item -Path $userDir -ItemType Directory -Force | Out-Null }
            $svcPath = Join-Path $userDir ($units.UnitBase + '.service')
            $timPath = Join-Path $userDir ($units.UnitBase + '.timer')

            if ($PSCmdlet.ShouldProcess($userDir, 'Write systemd user units')) {
                $units.ServiceText | Out-File -FilePath $svcPath -Encoding UTF8 -Force
                $units.TimerText | Out-File -FilePath $timPath -Encoding UTF8 -Force
            }

            $result.Details = [pscustomobject]@{ SystemdService = $svcPath; SystemdTimer = $timPath }
            $result.Notes += "Enable with: systemctl --user daemon-reload; systemctl --user enable --now $($units.UnitBase).timer"

            if ($Install.IsPresent) {
                $systemctl = Get-Command -Name systemctl -ErrorAction SilentlyContinue
                if ($systemctl) {
                    if ($PSCmdlet.ShouldProcess($units.UnitBase, 'Enable systemd user timer')) {
                        & $systemctl.Source --user daemon-reload | Out-Null
                        & $systemctl.Source --user enable --now ($units.UnitBase + '.timer') | Out-Null
                        $result.Registered = $true
                    }
                } else {
                    $result.Notes += 'systemctl not found; units were generated but not enabled.'
                }
            }
        }

        'macOS' {
            $agent = $null
            if ($spec.Type -eq 'Interval') {
                $agent = New-FSKLaunchdAgent -Name $Name -RunnerScript $runner.RunnerScript -Every $spec.Every -WorkingDirectory $runner.ScheduleRoot
            } elseif ($spec.Type -eq 'Weekly') {
                $entries = foreach ($d in @($spec.DaysOfWeek | Sort-Object -Unique)) {
                    @{
                        Weekday = ([int]$d) + 1
                        Hour = ([datetime]::Today.Add($spec.At)).Hour
                        Minute = ([datetime]::Today.Add($spec.At)).Minute
                    }
                }
                $agent = New-FSKLaunchdAgent -Name $Name -RunnerScript $runner.RunnerScript -StartCalendarInterval @($entries) -WorkingDirectory $runner.ScheduleRoot
            } elseif ($spec.Type -eq 'Monthly') {
                $entries = foreach ($day in @($spec.DaysOfMonth | Sort-Object -Unique)) {
                    @{
                        Day = [int]$day
                        Hour = ([datetime]::Today.Add($spec.At)).Hour
                        Minute = ([datetime]::Today.Add($spec.At)).Minute
                    }
                }
                $agent = New-FSKLaunchdAgent -Name $Name -RunnerScript $runner.RunnerScript -StartCalendarInterval @($entries) -WorkingDirectory $runner.ScheduleRoot
            } else {
                throw "Unsupported schedule type: $($spec.Type)"
            }
            $agentDir = Join-Path $HOME 'Library/LaunchAgents'
            if (-not (Test-Path $agentDir)) { New-Item -Path $agentDir -ItemType Directory -Force | Out-Null }
            $plistPath = Join-Path $agentDir ($agent.Label + '.plist')

            if ($PSCmdlet.ShouldProcess($plistPath, 'Write LaunchAgent plist')) {
                $agent.PlistText | Out-File -FilePath $plistPath -Encoding UTF8 -Force
            }

            $result.Details = [pscustomobject]@{ LaunchAgentPlist = $plistPath; Label = $agent.Label }
            $result.Notes += "Load with: launchctl load -w $plistPath"

            if ($Install.IsPresent) {
                $launchctl = Get-Command -Name launchctl -ErrorAction SilentlyContinue
                if ($launchctl) {
                    if ($PSCmdlet.ShouldProcess($agent.Label, 'Load LaunchAgent')) {
                        & $launchctl.Source load -w $plistPath | Out-Null
                        $result.Registered = $true
                    }
                } else {
                    $result.Notes += 'launchctl not found; plist was generated but not loaded.'
                }
            }
        }

        default {
            throw "Unsupported platform for scheduling: $platform"
        }
    }

    return [pscustomobject]$result
}
