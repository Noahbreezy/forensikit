function New-FSKZip {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$SourceFolder,

        [Parameter(Mandatory)]
        [string]$ZipPath
    )

    $zipDir = Split-Path -Path $ZipPath -Parent
    if (-not (Test-Path $zipDir)) { New-Item -Path $zipDir -ItemType Directory -Force | Out-Null }

    if (Test-Path $ZipPath) { Remove-Item -Path $ZipPath -Force }

    Compress-Archive -Path (Join-Path $SourceFolder '*') -DestinationPath $ZipPath -CompressionLevel Optimal
}
