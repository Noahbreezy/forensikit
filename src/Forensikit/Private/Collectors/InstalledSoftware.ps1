function Invoke-FSKCollectInstalledSoftware {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Run,
        [Parameter(Mandatory)]$Logger
    )

    $outDir = Join-Path $Run.Persistent 'software'

    $platform = Get-FSKPlatform

    if ($platform -ne 'Windows') {
        try {
            if ($platform -eq 'Linux') {
                if (Get-Command dpkg-query -ErrorAction SilentlyContinue) {
                    & dpkg-query -W -f='${Package}\t${Version}\t${Architecture}\n' 2>&1 | Out-File -FilePath (Join-Path $outDir 'dpkg_packages.txt') -Encoding UTF8
                }
                if (Get-Command rpm -ErrorAction SilentlyContinue) {
                    & rpm -qa 2>&1 | Out-File -FilePath (Join-Path $outDir 'rpm_packages.txt') -Encoding UTF8
                }
                if (Get-Command snap -ErrorAction SilentlyContinue) {
                    & snap list 2>&1 | Out-File -FilePath (Join-Path $outDir 'snap_list.txt') -Encoding UTF8
                }
                if (Get-Command flatpak -ErrorAction SilentlyContinue) {
                    & flatpak list 2>&1 | Out-File -FilePath (Join-Path $outDir 'flatpak_list.txt') -Encoding UTF8
                }
            } elseif ($platform -eq 'macOS') {
                if (Get-Command brew -ErrorAction SilentlyContinue) {
                    & brew list --versions 2>&1 | Out-File -FilePath (Join-Path $outDir 'brew_list_versions.txt') -Encoding UTF8
                }
                if (Test-Path '/Applications') {
                    Get-ChildItem -Path '/Applications' -ErrorAction SilentlyContinue | Select-Object Name, FullName | Export-Csv -Path (Join-Path $outDir 'applications.csv') -NoTypeInformation -Encoding UTF8
                }
            }

            Write-FSKLog -Logger $Logger -Level INFO -Message "Collected installed software inventory ($platform)"
        } catch {
            Write-FSKLog -Logger $Logger -Level WARN -Message "Failed to collect installed software ($platform)" -Exception $_.Exception
        }
        return
    }

    function Get-UninstallEntries {
        param([string[]]$Roots)
        foreach ($root in $Roots) {
            try {
                if (-not (Test-Path $root)) { continue }
                Get-ChildItem -Path $root | ForEach-Object {
                    try {
                        $p = Get-ItemProperty -Path $_.PSPath
                        [pscustomobject]@{
                            Hive          = $root
                            DisplayName   = $p.DisplayName
                            DisplayVersion= $p.DisplayVersion
                            Publisher     = $p.Publisher
                            InstallDate   = $p.InstallDate
                            UninstallString = $p.UninstallString
                        }
                    } catch { }
                }
            } catch { }
        }
    }

    try {
        $roots = @(
            'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall',
            'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall',
            'HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall'
        )

        $entries = Get-UninstallEntries -Roots $roots | Where-Object { $_.DisplayName }
        if ($entries) {
            $entries | Sort-Object DisplayName | Export-Csv -Path (Join-Path $outDir 'installed_software.csv') -NoTypeInformation -Encoding UTF8
        } else {
            'No entries found' | Out-File -FilePath (Join-Path $outDir 'installed_software.csv') -Encoding UTF8
        }

        Write-FSKLog -Logger $Logger -Level INFO -Message 'Collected installed software inventory'
    } catch {
        Write-FSKLog -Logger $Logger -Level ERROR -Message 'Failed to collect installed software' -Exception $_.Exception
    }
}
