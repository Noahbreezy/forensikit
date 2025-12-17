function New-FSKIntegrityLog {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$RootPath,

        [Parameter(Mandatory)]
        [string]$IntegrityCsvPath
    )

    $utcNow = (Get-Date).ToUniversalTime().ToString('o')

    $files = Get-ChildItem -Path $RootPath -File -Recurse
    $rows = foreach ($file in $files) {
        $rel = $file.FullName.Substring($RootPath.Length).TrimStart('\','/')
        $hash = Get-FileHash -Path $file.FullName -Algorithm SHA256
        [pscustomobject]@{
            CollectedUtc = $utcNow
            RelativePath = $rel
            Length       = $file.Length
            Sha256       = $hash.Hash
        }
    }

    $dir = Split-Path -Path $IntegrityCsvPath -Parent
    if (-not (Test-Path $dir)) { New-Item -Path $dir -ItemType Directory -Force | Out-Null }

    $rows | Sort-Object RelativePath | Export-Csv -Path $IntegrityCsvPath -NoTypeInformation -Encoding UTF8
}
