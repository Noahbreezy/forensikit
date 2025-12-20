function Get-FSKConfig {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateSet('Quick','Full','Deep','Custom')]
        [string]$Mode,

        [Parameter()]
        [string]$CustomProfilePath
    )

    switch ($Mode) {
        'Quick' {
            return [pscustomobject]@{
                Mode = 'Quick'
                Collectors = @('Processes','Network','Users','EventLogs')
                EventLogHours = 24
            }
        }
        'Full' {
            return [pscustomobject]@{
                Mode = 'Full'
                Collectors = @('Processes','Network','Users','EventLogs')
                EventLogHours = 24 * 7
            }
        }
        'Deep' {
            return [pscustomobject]@{
                Mode = 'Deep'
                Collectors = @(
                    'Processes','Network','Users','EventLogs',
                    'Services','ScheduledTasks','Registry','InstalledSoftware','DnsFirewall'
                )
                EventLogHours = 24 * 14
            }
        }
        'Custom' {
            if (-not $CustomProfilePath) {
                throw "-CustomProfilePath is required when -Mode Custom"
            }
            $raw = Get-Content -Path $CustomProfilePath -Raw -Encoding UTF8
            $obj = $raw | ConvertFrom-Json

            if (-not $obj.Collectors) { throw "Custom profile must include Collectors" }
            if (-not $obj.EventLogHours) { $obj | Add-Member -NotePropertyName EventLogHours -NotePropertyValue (24) }
            $obj.Mode = 'Custom'
            return $obj
        }
    }
}

function Get-FSKProfile {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateSet('Quick','Full','Deep','Custom')]
        [string]$Mode,

        [Parameter()]
        [string]$CustomProfilePath
    )

    return Get-FSKConfig @PSBoundParameters
}
