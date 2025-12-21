function New-ForensikitCustomProfile {
    <#
    .SYNOPSIS
    Creates a JSON custom profile file from a built-in mode.

    .DESCRIPTION
    Writes a JSON file containing Collectors and EventLogHours derived from a built-in mode
    (Quick/Full/Deep). This is useful when you want to run defaults but still use a custom profile,
    e.g. for scheduled/periodic runs.

    .PARAMETER Mode
    The built-in mode to use as a template: Quick | Full | Deep.

    .PARAMETER Path
    Output JSON path.

    .EXAMPLE
    New-ForensikitCustomProfile -Mode Quick -Path .\quick_profile.json
    #>

    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory)]
        [ValidateSet('Quick','Full','Deep')]
        [string]$Mode,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$Path
    )

    $cfg = Get-FSKConfig -Mode $Mode
    $obj = [ordered]@{
        Collectors = @($cfg.Collectors)
        EventLogHours = [int]$cfg.EventLogHours
    }

    $json = $obj | ConvertTo-Json -Depth 6
    if ($PSCmdlet.ShouldProcess($Path, 'Write custom profile JSON')) {
        $dir = Split-Path -Path $Path -Parent
        if ($dir -and -not (Test-Path $dir)) { New-Item -Path $dir -ItemType Directory -Force | Out-Null }
        $json | Out-File -FilePath $Path -Encoding UTF8 -Force
    }

    return (Resolve-Path -Path $Path).Path
}
