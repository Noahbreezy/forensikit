function Unregister-ForensikitSchedule {
    <#
    .SYNOPSIS
    Unregisters a Forensikit schedule.

    .DESCRIPTION
    Removes the OS scheduler registration when possible and deletes the schedule folder.

    .PARAMETER Name
    Schedule name.

    .PARAMETER KeepFiles
    Do not delete the schedule folder contents.
    #>

    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory)]
        [ValidatePattern('^[A-Za-z0-9_.-]+$')]
        [string]$Name,

        [Parameter()]
        [switch]$KeepFiles
    )

    $platform = Get-FSKPlatform

    switch ($platform) {
        'Windows' {
            Unregister-FSKWindowsScheduledTask -Name $Name
        }
        'Linux' {
            $unitBase = "forensikit-$Name"
            $systemctl = Get-Command -Name systemctl -ErrorAction SilentlyContinue
            if ($systemctl) {
                try {
                    & $systemctl.Source --user disable --now ($unitBase + '.timer') | Out-Null
                } catch { }
            }
            $userDir = Join-Path $HOME '.config/systemd/user'
            foreach ($p in @(
                (Join-Path $userDir ($unitBase + '.service')),
                (Join-Path $userDir ($unitBase + '.timer'))
            )) {
                if (Test-Path $p) {
                    if ($PSCmdlet.ShouldProcess($p, 'Remove systemd unit')) {
                        Remove-Item -Path $p -Force
                    }
                }
            }
            if ($systemctl) {
                try { & $systemctl.Source --user daemon-reload | Out-Null } catch { }
            }
        }
        'macOS' {
            $label = "com.forensikit.$Name"
            $plistPath = Join-Path (Join-Path $HOME 'Library/LaunchAgents') ($label + '.plist')
            $launchctl = Get-Command -Name launchctl -ErrorAction SilentlyContinue
            if ($launchctl) {
                try { & $launchctl.Source unload -w $plistPath | Out-Null } catch { }
            }
            if (Test-Path $plistPath) {
                if ($PSCmdlet.ShouldProcess($plistPath, 'Remove LaunchAgent plist')) {
                    Remove-Item -Path $plistPath -Force
                }
            }
        }
        default {
            throw "Unsupported platform for scheduling: $platform"
        }
    }

    if (-not $KeepFiles.IsPresent) {
        $scheduleDir = Join-Path (Get-FSKScheduleRoot) $Name
        if (Test-Path $scheduleDir) {
            if ($PSCmdlet.ShouldProcess($scheduleDir, 'Remove schedule folder')) {
                Remove-Item -Path $scheduleDir -Recurse -Force
            }
        }
    }
}
