function New-FSKLogger {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$LogPath
    )

    $dir = Split-Path -Path $LogPath -Parent
    if (-not (Test-Path $dir)) { New-Item -Path $dir -ItemType Directory -Force | Out-Null }

    return [pscustomobject]@{
        Path = $LogPath
    }
}

function Write-FSKLog {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        $Logger,

        [Parameter(Mandatory)]
        [ValidateSet('INFO','WARN','ERROR')]
        [string]$Level,

        [Parameter(Mandatory)]
        [string]$Message,

        [Parameter()]
        [System.Exception]$Exception
    )

    $ts = (Get-Date).ToUniversalTime().ToString('o')
    $line = if ($Exception) {
        "$ts [$Level] $Message | $($Exception.GetType().FullName): $($Exception.Message)"
    } else {
        "$ts [$Level] $Message"
    }

    Add-Content -Path $Logger.Path -Value $line -Encoding UTF8

    switch ($Level) {
        'ERROR' { Write-Error -Message $Message -ErrorAction Continue }
        'WARN'  { Write-Warning $Message }
        default { Write-Verbose $Message }
    }
}
