Set-StrictMode -Version Latest

function ConvertTo-FSKSystemdDayOfWeek {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [System.DayOfWeek[]]$DaysOfWeek
    )

    $map = @{
        Sunday    = 'Sun'
        Monday    = 'Mon'
        Tuesday   = 'Tue'
        Wednesday = 'Wed'
        Thursday  = 'Thu'
        Friday    = 'Fri'
        Saturday  = 'Sat'
    }

    return @(
        $DaysOfWeek | ForEach-Object { $map[$_.ToString()] } | Where-Object { $_ }
    )
}

function ConvertTo-FSKTimeString {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [TimeSpan]$At
    )

    if ($At.TotalSeconds -lt 0 -or $At.TotalSeconds -ge 24*60*60) {
        throw "At must be within a day (00:00:00 - 23:59:59)"
    }
    return ([datetime]::Today.Add($At)).ToString('HH:mm:ss')
}

function ConvertTo-FSKTaskSchedulerDuration {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [TimeSpan]$TimeSpan
    )

    # Task Scheduler expects ISO-8601 durations (PT6H, PT90M, P1D, etc.) in task XML.
    $totalSeconds = [int][Math]::Round($TimeSpan.TotalSeconds)
    if ($totalSeconds -le 0) {
        throw 'Duration must be greater than zero'
    }

    $days = [int][Math]::Floor($totalSeconds / 86400)
    $rem = $totalSeconds % 86400
    $hours = [int][Math]::Floor($rem / 3600)
    $rem = $rem % 3600
    $minutes = [int][Math]::Floor($rem / 60)
    $seconds = [int]($rem % 60)

    $datePart = if ($days -gt 0) { "P${days}D" } else { 'P' }
    $timeParts = @()
    if ($hours -gt 0) { $timeParts += "${hours}H" }
    if ($minutes -gt 0) { $timeParts += "${minutes}M" }
    if ($seconds -gt 0) { $timeParts += "${seconds}S" }

    if ($days -gt 0 -and $timeParts.Count -eq 0) {
        return $datePart
    }

    if ($timeParts.Count -eq 0) {
        $timeParts = @('0S')
    }

    return ("$datePart" + 'T' + ($timeParts -join ''))
}

function Get-FSKScheduleRoot {
    [CmdletBinding()]
    param()

    $platform = Get-FSKPlatform
    if ($platform -eq 'Windows') {
        if (-not $env:LOCALAPPDATA) {
            return (Join-Path $HOME 'AppData\Local\Forensikit\Schedules')
        }
        return (Join-Path $env:LOCALAPPDATA 'Forensikit\Schedules')
    }

    return (Join-Path $HOME '.config/forensikit/schedules')
}

function Get-FSKModuleManifestPath {
    [CmdletBinding()]
    param()

    $m = Get-Module -Name Forensikit -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($m -and $m.Path -and $m.Path.ToLowerInvariant().EndsWith('.psd1')) {
        return $m.Path
    }

    $candidate = Join-Path $PSScriptRoot '..\Forensikit.psd1'
    if (Test-Path -Path $candidate) {
        return (Resolve-Path -Path $candidate).Path
    }

    return $null
}

function New-FSKScheduleRunner {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$Name,

        [Parameter(Mandatory)]
        [ValidateScript({ Test-Path $_ })]
        [string]$CustomProfilePath,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$OutputPath,

        [Parameter()]
        [ValidateScript({ -not $_ -or (Test-Path $_) })]
        [string]$ModuleManifestPath,

        [Parameter()]
        [ValidateSet('None','Ndjson')]
        [string]$SiemFormat = 'None',

        [Parameter()]
        [switch]$CopyProfile
    )

    $root = Get-FSKScheduleRoot
    $scheduleDir = Join-Path $root $Name
    if (-not (Test-Path $scheduleDir)) {
        New-Item -Path $scheduleDir -ItemType Directory -Force | Out-Null
    }

    $profileToUse = $CustomProfilePath
    if ($CopyProfile.IsPresent) {
        $profileToUse = Join-Path $scheduleDir 'profile.json'
        Copy-Item -Path $CustomProfilePath -Destination $profileToUse -Force
    }

    $runScript = Join-Path $scheduleDir 'run.ps1'
    $metaPath = Join-Path $scheduleDir 'schedule.json'

    $moduleLine = if ($ModuleManifestPath) {
        "Import-Module '$($ModuleManifestPath.Replace("'","''"))' -Force"
    } else {
        "Import-Module Forensikit -Force"
    }

    $siemLine = if ($SiemFormat -eq 'Ndjson') {
        " -SiemFormat Ndjson"
    } else {
        ''
    }

    $scriptBody = @(
        'Set-StrictMode -Version Latest',
        '$ErrorActionPreference = "Stop"',
        '',
        $moduleLine,
        '',
        ('$out = ' + "'$($OutputPath.Replace("'","''"))'"),
        'if (-not (Test-Path -Path $out)) { New-Item -Path $out -ItemType Directory -Force | Out-Null }',
        '',
        ('$profile = ' + "'$($profileToUse.Replace("'","''"))'"),
        'Invoke-ForensicCollector -Mode Custom -CustomProfilePath $profile -OutputPath $out -Confirm:$false' + $siemLine,
        ''
    ) -join [Environment]::NewLine

    $scriptBody | Out-File -FilePath $runScript -Encoding UTF8 -Force

    $meta = [ordered]@{
        name = $Name
        createdUtc = (Get-Date).ToUniversalTime().ToString('o')
        outputPath = $OutputPath
        customProfilePath = $profileToUse
        moduleManifestPath = $ModuleManifestPath
        siemFormat = $SiemFormat
    }
    ($meta | ConvertTo-Json -Depth 4) | Out-File -FilePath $metaPath -Encoding UTF8 -Force

    return [pscustomobject]@{
        Name = $Name
        ScheduleRoot = $scheduleDir
        RunnerScript = $runScript
        ProfilePath = $profileToUse
        MetaPath = $metaPath
    }
}

function Get-FSKPowerShellPath {
    [CmdletBinding()]
    param(
        [Parameter()]
        [ValidateSet('Auto','pwsh','powershell')]
        [string]$Preference = 'Auto'
    )

    if ($Preference -eq 'pwsh' -or $Preference -eq 'Auto') {
        $pwsh = Get-Command -Name pwsh -ErrorAction SilentlyContinue
        if ($pwsh) { return $pwsh.Source }
        if ($Preference -eq 'pwsh') { throw "pwsh not found" }
    }

    $ps = Get-Command -Name powershell -ErrorAction SilentlyContinue
    if ($ps) { return $ps.Source }

    throw "No PowerShell executable found (pwsh or powershell)"
}

function Register-FSKWindowsScheduledTask {
    [CmdletBinding(SupportsShouldProcess = $true, DefaultParameterSetName = 'Interval')]
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][string]$RunnerScript,

        [Parameter(Mandatory, ParameterSetName = 'Interval')][TimeSpan]$Every,
        [Parameter(Mandatory, ParameterSetName = 'Interval')][DateTime]$StartAt,

        [Parameter(Mandatory, ParameterSetName = 'Weekly')][System.DayOfWeek[]]$DaysOfWeek,
        [Parameter(Mandatory, ParameterSetName = 'Weekly')][TimeSpan]$At,

        [Parameter(Mandatory, ParameterSetName = 'Monthly')][ValidateRange(1,31)][int[]]$DaysOfMonth,
        [Parameter(Mandatory, ParameterSetName = 'Monthly')][TimeSpan]$AtMonthly,

        [Parameter()][switch]$RunElevated,
        [Parameter()][string]$PowerShellPath
    )

    $taskName = "Forensikit-$Name"
    $exe = if ($PowerShellPath) { $PowerShellPath } else { Get-FSKPowerShellPath -Preference Auto }

    $taskArgs = "-NoProfile -ExecutionPolicy Bypass -File `"$RunnerScript`""
    $action = New-ScheduledTaskAction -Execute $exe -Argument $taskArgs

    $settings = New-ScheduledTaskSettingsSet -StartWhenAvailable -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries

    $principal = $null
    if ($RunElevated.IsPresent) {
        $principal = New-ScheduledTaskPrincipal -UserId $env:USERNAME -LogonType InteractiveToken -RunLevel Highest
    }

    $registerXml = $null

    $trigger = $null
    switch ($PSCmdlet.ParameterSetName) {
        'Interval' {
            # Use a daily trigger with repetition to avoid invalid Task Scheduler XML durations.
            # Note: Scheduled Tasks doesn't accept an "infinite" repetition duration; daily+duration=1 day repeats indefinitely.
            if ($Every.TotalSeconds -lt 60) {
                throw "Every must be at least 60 seconds on Windows"
            }

            if ($Every.TotalDays -ge 1) {
                $wholeDays = [Math]::Round($Every.TotalDays, 0)
                if ([Math]::Abs($Every.TotalDays - $wholeDays) -gt 1e-9) {
                    throw "On Windows, interval schedules >= 1 day must be whole-day increments (e.g. 24h, 48h)."
                }

                $daysInterval = [uint][Math]::Max(1, [int]$wholeDays)
                $trigger = New-ScheduledTaskTrigger -Daily -At $StartAt -DaysInterval $daysInterval
            } else {
                $trigger = New-ScheduledTaskTrigger -Daily -At $StartAt -DaysInterval 1

                $repClass = Get-CimClass -Namespace Root/Microsoft/Windows/TaskScheduler -ClassName MSFT_TaskRepetitionPattern
                $rep = New-CimInstance -CimClass $repClass -ClientOnly -Property @{
                    Interval = (ConvertTo-FSKTaskSchedulerDuration -TimeSpan $Every)
                    Duration = 'P1D'
                    StopAtDurationEnd = $false
                }
                $trigger.Repetition = $rep
            }
        }
        'Weekly' {
            $dt = [datetime]::Today.Add($At)
            $trigger = New-ScheduledTaskTrigger -Weekly -DaysOfWeek $DaysOfWeek -At $dt
        }
        'Monthly' {
            # ScheduledTasks doesn't expose -Monthly on all Windows versions.
            # Build the task XML with a monthly CalendarTrigger, then register via -Xml.
            $now = Get-Date
            $start = [datetime]::Today.Add($AtMonthly)
            if ($start -lt $now.AddMinutes(1)) {
                $start = $now.AddMinutes(1)
            }

            $days = @($DaysOfMonth | Sort-Object -Unique)
            if ($days.Count -lt 1) {
                throw "DaysOfMonth must include at least one day"
            }

            $months = @(
                'January','February','March','April','May','June',
                'July','August','September','October','November','December'
            )

            $dayXml = foreach ($d in $days) { "        <Day>$d</Day>" }
            $monthXml = foreach ($m in $months) { "        <$m />" }

            $triggersXml = @(
                '<Triggers>',
                '  <CalendarTrigger>',
                "    <StartBoundary>$($start.ToString('s'))</StartBoundary>",
                '    <Enabled>true</Enabled>',
                '    <ScheduleByMonth>',
                '      <DaysOfMonth>',
                ($dayXml -join "`n"),
                '      </DaysOfMonth>',
                '      <Months>',
                ($monthXml -join "`n"),
                '      </Months>',
                '    </ScheduleByMonth>',
                '  </CalendarTrigger>',
                '</Triggers>'
            ) -join "`n"

            $dummy = New-ScheduledTaskTrigger -Once -At $start
            $task = if ($principal) {
                New-ScheduledTask -Action $action -Trigger $dummy -Settings $settings -Principal $principal
            } else {
                New-ScheduledTask -Action $action -Trigger $dummy -Settings $settings
            }

            $xml = Export-ScheduledTask -InputObject $task
            $registerXml = [regex]::Replace($xml, '<Triggers>[\s\S]*?</Triggers>', $triggersXml)
        }
        default {
            throw "Unknown trigger type: $($PSCmdlet.ParameterSetName)"
        }
    }

    if ($PSCmdlet.ShouldProcess($taskName, "Register Scheduled Task")) {
        if ($registerXml) {
            Register-ScheduledTask -TaskName $taskName -Xml $registerXml -Force -ErrorAction Stop | Out-Null
        } elseif ($principal) {
            Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Settings $settings -Principal $principal -Force -ErrorAction Stop | Out-Null
        } else {
            Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Settings $settings -Force -ErrorAction Stop | Out-Null
        }

        return $taskName
    }
}

function Unregister-FSKWindowsScheduledTask {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory)][string]$Name
    )

    $taskName = "Forensikit-$Name"
    if ($PSCmdlet.ShouldProcess($taskName, 'Unregister Scheduled Task')) {
        try {
            Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction Stop
        } catch {
            # ignore missing tasks
        }
    }
}

function New-FSKSystemdUserUnits {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][string]$RunnerScript,
        [Parameter(Mandatory, ParameterSetName = 'Interval')][TimeSpan]$Every,
        [Parameter(Mandatory, ParameterSetName = 'OnCalendar')][ValidateNotNullOrEmpty()][string]$OnCalendar
    )

    $unitBase = "forensikit-$Name"
    $pwshPath = Get-FSKPowerShellPath -Preference pwsh

    $service = @(
        '[Unit]',
        "Description=Forensikit scheduled run ($Name)",
        '',
        '[Service]',
        'Type=oneshot',
        "ExecStart=$pwshPath -NoProfile -File $RunnerScript",
        ''
    ) -join "`n"

    $timerLines = @(
        '[Unit]',
        "Description=Forensikit schedule timer ($Name)",
        '',
        '[Timer]',
        'OnBootSec=1min'
    )

    if ($PSCmdlet.ParameterSetName -eq 'Interval') {
        $seconds = [int][Math]::Max(60, [Math]::Floor($Every.TotalSeconds))
        $timerLines += "OnUnitActiveSec=${seconds}s"
    } else {
        $timerLines += "OnCalendar=$OnCalendar"
    }

    $timerLines += @(
        'Persistent=true',
        '',
        '[Install]',
        'WantedBy=timers.target',
        ''
    )

    $timer = $timerLines -join "`n"

    return [pscustomobject]@{
        UnitBase = $unitBase
        ServiceText = $service
        TimerText = $timer
    }
}

function New-FSKLaunchdAgent {
    [CmdletBinding(DefaultParameterSetName = 'Interval')]
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][string]$RunnerScript,
        [Parameter(Mandatory, ParameterSetName = 'Interval')][TimeSpan]$Every,
        [Parameter(Mandatory, ParameterSetName = 'Calendar')][hashtable[]]$StartCalendarInterval,
        [Parameter(Mandatory)][string]$WorkingDirectory
    )

    $label = "com.forensikit.$Name"
    $pwshPath = Get-FSKPowerShellPath -Preference pwsh

    $seconds = $null
    if ($PSCmdlet.ParameterSetName -eq 'Interval') {
        $seconds = [int][Math]::Max(60, [Math]::Floor($Every.TotalSeconds))
    }
    $stdout = Join-Path $WorkingDirectory 'launchd_stdout.log'
    $stderr = Join-Path $WorkingDirectory 'launchd_stderr.log'

    $calendarXml = ''
    if ($PSCmdlet.ParameterSetName -eq 'Calendar') {
        # launchd accepts either a dict or an array of dicts. We generate an array when multiple entries are provided.
        $entries = @($StartCalendarInterval)
        $entryXml = foreach ($e in $entries) {
            $pairs = @()
            foreach ($k in $e.Keys) {
                $pairs += "      <key>$k</key>"
                $pairs += "      <integer>$($e[$k])</integer>"
            }
            @(
                '    <dict>',
                ($pairs -join "`n"),
                '    </dict>'
            ) -join "`n"
        }

        $calendarXml = @(
            '  <key>StartCalendarInterval</key>',
            '  <array>',
            ($entryXml -join "`n"),
            '  </array>'
        ) -join "`n"
    }

    $intervalXml = ''
    if ($PSCmdlet.ParameterSetName -eq 'Interval') {
        $intervalXml = @(
            '  <key>RunAtLoad</key>',
            '  <true/>',
            '  <key>StartInterval</key>',
            "  <integer>$seconds</integer>"
        ) -join "`n"
    }

    $plist = @(
        '<?xml version="1.0" encoding="UTF-8"?>',
        '<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">',
        '<plist version="1.0">',
        '<dict>',
        '  <key>Label</key>',
        "  <string>$label</string>",
        '  <key>ProgramArguments</key>',
        '  <array>',
        "    <string>$pwshPath</string>",
        '    <string>-NoProfile</string>',
        '    <string>-File</string>',
        "    <string>$RunnerScript</string>",
        '  </array>',
        $intervalXml,
        $calendarXml,
        '  <key>WorkingDirectory</key>',
        "  <string>$WorkingDirectory</string>",
        '  <key>StandardOutPath</key>',
        "  <string>$stdout</string>",
        '  <key>StandardErrorPath</key>',
        "  <string>$stderr</string>",
        '</dict>',
        '</plist>'
    ) -join "`n"

    return [pscustomobject]@{
        Label = $label
        PlistText = $plist
        StdoutPath = $stdout
        StderrPath = $stderr
    }
}

function New-FSKScheduleSpec {
    [CmdletBinding(DefaultParameterSetName = 'Interval')]
    param(
        [Parameter(Mandatory, ParameterSetName = 'Interval')][TimeSpan]$Every,
        [Parameter(Mandatory, ParameterSetName = 'Interval')][DateTime]$StartAt,
        [Parameter(Mandatory, ParameterSetName = 'Weekly')][System.DayOfWeek[]]$DaysOfWeek,
        [Parameter(Mandatory, ParameterSetName = 'Weekly')][TimeSpan]$At,
        [Parameter(Mandatory, ParameterSetName = 'Monthly')][ValidateRange(1,31)][int[]]$DaysOfMonth,
        [Parameter(Mandatory, ParameterSetName = 'Monthly')][TimeSpan]$AtMonthly
    )

    switch ($PSCmdlet.ParameterSetName) {
        'Interval' {
            return [pscustomobject]@{ Type = 'Interval'; Every = $Every; StartAt = $StartAt }
        }
        'Weekly' {
            return [pscustomobject]@{ Type = 'Weekly'; DaysOfWeek = @($DaysOfWeek); At = $At }
        }
        'Monthly' {
            return [pscustomobject]@{ Type = 'Monthly'; DaysOfMonth = @($DaysOfMonth | Sort-Object -Unique); At = $AtMonthly }
        }
        default {
            throw "Unknown schedule spec: $($PSCmdlet.ParameterSetName)"
        }
    }
}
