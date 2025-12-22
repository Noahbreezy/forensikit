function Invoke-FSKCollectServices {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Run,
        [Parameter(Mandatory)]$Logger
    )

    $outDir = Join-Path $Run.Persistent 'services'

    try {
        $platform = Get-FSKPlatform

        if ($platform -eq 'Windows') {
            $serviceErrors = @()
            $services = Get-Service -ErrorAction SilentlyContinue -ErrorVariable +serviceErrors
            $services | Select-Object Name, DisplayName, Status, StartType, CanPauseAndContinue, CanStop, ServiceType | Export-Csv -Path (Join-Path $outDir 'services.csv') -NoTypeInformation -Encoding UTF8

            if ($serviceErrors.Count -gt 0) {
                $first = $serviceErrors[0]
                Write-FSKLog -Logger $Logger -Level WARN -Message "Some services could not be queried (non-fatal); output may be partial. Errors: $($serviceErrors.Count)" -Exception $first.Exception
            }

            try {
                Get-CimInstance Win32_SystemDriver | Select-Object Name, DisplayName, State, Status, StartMode, PathName | Export-Csv -Path (Join-Path $outDir 'drivers.csv') -NoTypeInformation -Encoding UTF8
            } catch {
                Write-FSKLog -Logger $Logger -Level WARN -Message 'Driver inventory collection failed (non-fatal)' -Exception $_.Exception
            }
        } elseif ($platform -eq 'Linux') {
            if (Get-Command systemctl -ErrorAction SilentlyContinue) {
                & systemctl list-units --type=service --all 2>&1 | Out-File -FilePath (Join-Path $outDir 'systemctl_list_units.txt') -Encoding UTF8
                & systemctl list-unit-files --type=service 2>&1 | Out-File -FilePath (Join-Path $outDir 'systemctl_unit_files.txt') -Encoding UTF8
            }
            if (Get-Command lsmod -ErrorAction SilentlyContinue) {
                & lsmod 2>&1 | Out-File -FilePath (Join-Path $outDir 'lsmod.txt') -Encoding UTF8
            }
        } elseif ($platform -eq 'macOS') {
            if (Get-Command launchctl -ErrorAction SilentlyContinue) {
                & launchctl list 2>&1 | Out-File -FilePath (Join-Path $outDir 'launchctl_list.txt') -Encoding UTF8
            }
            if (Get-Command kextstat -ErrorAction SilentlyContinue) {
                & kextstat 2>&1 | Out-File -FilePath (Join-Path $outDir 'kextstat.txt') -Encoding UTF8
            }
        }

        Write-FSKLog -Logger $Logger -Level INFO -Message "Collected service/driver info ($platform)"
    } catch {
        Write-FSKLog -Logger $Logger -Level ERROR -Message 'Failed to collect services/drivers' -Exception $_.Exception
    }
}
