function New-FSKRunFolder {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$OutputPath,

        [Parameter(Mandatory)]
        [string]$ComputerName,

        [Parameter()]
        [string]$CaseId,

        [Parameter()]
        [string]$RunId
    )

    if (-not $RunId) {
        $stamp = (Get-Date).ToUniversalTime().ToString('yyyyMMdd_HHmmssZ')
        $RunId = if ($CaseId) { "$CaseId`_$stamp" } else { $stamp }
    }

    $root = Join-Path -Path $OutputPath -ChildPath $RunId
    $targetRoot = Join-Path -Path $root -ChildPath $ComputerName

    $folders = @(
        $targetRoot,
        (Join-Path (Join-Path $targetRoot 'volatile') 'processes'),
        (Join-Path (Join-Path $targetRoot 'volatile') 'network'),
        (Join-Path (Join-Path $targetRoot 'persistent') 'users'),
        (Join-Path (Join-Path $targetRoot 'persistent') 'eventlogs'),
        (Join-Path (Join-Path $targetRoot 'persistent') 'services'),
        (Join-Path (Join-Path $targetRoot 'persistent') 'tasks'),
        (Join-Path (Join-Path $targetRoot 'persistent') 'registry'),
        (Join-Path (Join-Path $targetRoot 'persistent') 'software'),
        (Join-Path (Join-Path $targetRoot 'persistent') 'network'),
        (Join-Path $targetRoot 'siem'),
        (Join-Path $targetRoot 'logs')
    )

    foreach ($f in $folders) {
        if (-not (Test-Path $f)) { New-Item -Path $f -ItemType Directory -Force | Out-Null }
    }

    return [pscustomobject]@{
        RunId      = $RunId
        Root       = $targetRoot
        Logs       = (Join-Path $targetRoot 'logs')
        Volatile   = (Join-Path $targetRoot 'volatile')
        Persistent = (Join-Path $targetRoot 'persistent')
    }
}
