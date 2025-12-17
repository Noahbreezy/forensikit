function Export-FSKSiemNdjson {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Run,
        [Parameter(Mandatory)]$Config,
        [Parameter(Mandatory)]$Logger,
        [Parameter()]
        [string]$NdjsonPath = (Join-Path $Run.Root 'siem\events.ndjson')
    )

    try {
        $ndjsonDir = Split-Path -Path $NdjsonPath -Parent
        if (-not (Test-Path $ndjsonDir)) { New-Item -Path $ndjsonDir -ItemType Directory -Force | Out-Null }

        $computer = Split-Path -Path $Run.Root -Leaf
        $runId = $Run.RunId
        $platform = Get-FSKPlatform
        $mode = $Config.Mode
        $generatedUtc = (Get-Date).ToUniversalTime().ToString('o')

        $utf8NoBom = New-Object System.Text.UTF8Encoding($false)
        $writer = [System.IO.StreamWriter]::new($NdjsonPath, $false, $utf8NoBom)
        try {
            # Header/meta event
            $meta = [ordered]@{
                schema       = 'forensikit.siem.v1'
                eventType    = 'run_meta'
                generatedUtc = $generatedUtc
                host         = $computer
                runId        = $runId
                mode         = $mode
                platform     = $platform
            }
            $writer.WriteLine(($meta | ConvertTo-Json -Compress -Depth 10))

            # Record events from collected CSVs (streamed)
            $csvFiles = Get-ChildItem -Path $Run.Root -Recurse -File -Filter '*.csv' |
                Where-Object { $_.Name -ne 'integrity.csv' }

            foreach ($csv in $csvFiles) {
                $rel = $csv.FullName.Substring($Run.Root.Length).TrimStart('\','/')
                $parts = $rel -split '[\\/]'
                $collectorHint = if ($parts.Count -ge 2) { $parts[1] } else { $null }

                $i = 0
                Import-Csv -Path $csv.FullName | ForEach-Object {
                    $i++
                    $evt = [ordered]@{
                        schema       = 'forensikit.siem.v1'
                        eventType    = 'record'
                        generatedUtc = $generatedUtc
                        host         = $computer
                        runId        = $runId
                        mode         = $mode
                        platform     = $platform
                        source       = [ordered]@{
                            pathRelative  = $rel
                            format        = 'csv'
                            collectorHint = $collectorHint
                            recordIndex   = $i
                        }
                        record       = $_
                    }

                    $writer.WriteLine(($evt | ConvertTo-Json -Compress -Depth 10))
                }
            }

            # Artifact inventory from integrity.csv (optional; present in most runs)
            $integrity = Join-Path $Run.Root 'integrity.csv'
            if (Test-Path $integrity) {
                Import-Csv -Path $integrity | ForEach-Object {
                    $evt = [ordered]@{
                        schema       = 'forensikit.siem.v1'
                        eventType    = 'artifact'
                        generatedUtc = $generatedUtc
                        host         = $computer
                        runId        = $runId
                        mode         = $mode
                        platform     = $platform
                        artifact     = $_
                    }
                    $writer.WriteLine(($evt | ConvertTo-Json -Compress -Depth 10))
                }
            }
        } finally {
            $writer.Dispose()
        }

        Write-FSKLog -Logger $Logger -Level INFO -Message "Wrote SIEM NDJSON: $NdjsonPath"
        return $NdjsonPath
    } catch {
        Write-FSKLog -Logger $Logger -Level WARN -Message 'Failed to write SIEM NDJSON (non-fatal)' -Exception $_.Exception
        return $null
    }
}

function Merge-FSKSiemNdjson {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateScript({ Test-Path $_ })]
        [string]$RunFolder,

        [Parameter(Mandatory)]
        [string]$MergedNdjsonPath
    )

    $mergedDir = Split-Path -Path $MergedNdjsonPath -Parent
    if (-not (Test-Path $mergedDir)) { New-Item -Path $mergedDir -ItemType Directory -Force | Out-Null }

    $inputs = Get-ChildItem -Path $RunFolder -Recurse -File -Filter 'events.ndjson' | Sort-Object FullName

    $utf8NoBom = New-Object System.Text.UTF8Encoding($false)
    $writer = [System.IO.StreamWriter]::new($MergedNdjsonPath, $false, $utf8NoBom)
    try {
        foreach ($f in $inputs) {
            $reader = [System.IO.StreamReader]::new($f.FullName, $utf8NoBom)
            try {
                while (-not $reader.EndOfStream) {
                    $line = $reader.ReadLine()
                    if ($null -ne $line -and $line.Trim().Length -gt 0) {
                        $writer.WriteLine($line)
                    }
                }
            } finally {
                $reader.Dispose()
            }
        }
    } finally {
        $writer.Dispose()
    }

    return $MergedNdjsonPath
}
