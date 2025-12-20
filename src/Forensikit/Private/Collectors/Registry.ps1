function Invoke-FSKCollectRegistry {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Run,
        [Parameter(Mandatory)]$Logger
    )

    $outDir = Join-Path $Run.Persistent 'registry'

    $platform = Get-FSKPlatform

    if ($platform -ne 'Windows') {
        # Non-Windows: collect common persistence/autostart locations (best-effort)
        try {
            $targets = @(
                '/etc/profile',
                '/etc/profile.d',
                '/etc/rc.local',
                '/etc/systemd/system',
                '/lib/systemd/system'
            )

            foreach ($t in $targets) {
                try {
                    if (-not (Test-Path $t)) { continue }
                    if ((Get-Item $t).PSIsContainer) {
                        Get-ChildItem -Path $t -File -ErrorAction SilentlyContinue | Select-Object -First 200 | ForEach-Object {
                            try {
                                Get-Content -Path $_.FullName -ErrorAction Stop | Out-File -FilePath (Join-Path $outDir (($_.Name -replace '[^a-zA-Z0-9_.-]','_') + '.txt')) -Encoding UTF8
                            } catch { }
                        }
                    } else {
                        Get-Content -Path $t -ErrorAction SilentlyContinue | Out-File -FilePath (Join-Path $outDir (Split-Path $t -Leaf)) -Encoding UTF8
                    }
                } catch { }
            }

            # Current user shell startup files
            $userDir = (Resolve-Path -LiteralPath '~').Path
            if ($userDir) {
                foreach ($f in @('.profile','.bash_profile','.bashrc','.zshrc','.zprofile','.config/autostart')) {
                    $p = Join-Path $userDir $f
                    try {
                        if (Test-Path $p) {
                            if ((Get-Item $p).PSIsContainer) {
                                Get-ChildItem -Path $p -File -ErrorAction SilentlyContinue | ForEach-Object {
                                    try { Get-Content -Path $_.FullName -ErrorAction Stop | Out-File -FilePath (Join-Path $outDir ('user_autostart_' + $_.Name + '.txt')) -Encoding UTF8 } catch { }
                                }
                            } else {
                                Get-Content -Path $p -ErrorAction SilentlyContinue | Out-File -FilePath (Join-Path $outDir ('user_' + (Split-Path $p -Leaf) + '.txt')) -Encoding UTF8
                            }
                        }
                    } catch { }
                }
            }

            Write-FSKLog -Logger $Logger -Level INFO -Message "Collected persistence locations ($platform)"
        } catch {
            Write-FSKLog -Logger $Logger -Level WARN -Message "Failed to collect persistence locations ($platform)" -Exception $_.Exception
        }
        return
    }

    $paths = @(
        'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run',
        'HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce',
        'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run',
        'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run',
        'HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce'
    )

    $rows = @()

    foreach ($path in $paths) {
        try {
            if (Test-Path $path) {
                $item = Get-ItemProperty -Path $path
                foreach ($prop in $item.PSObject.Properties) {
                    if ($prop.Name -in 'PSPath','PSParentPath','PSChildName','PSDrive','PSProvider','PSShowComputerName') { continue }
                    $rows += [pscustomobject]@{
                        HivePath = $path
                        Name     = $prop.Name
                        Value    = $prop.Value
                    }
                }
            }
        } catch {
            Write-FSKLog -Logger $Logger -Level WARN -Message "Registry read failed at $path (non-fatal)" -Exception $_.Exception
        }
    }

    try {
        if ($rows.Count -gt 0) {
            $rows | Export-Csv -Path (Join-Path $outDir 'autoruns.csv') -NoTypeInformation -Encoding UTF8
        } else {
            'No autorun entries collected' | Out-File -FilePath (Join-Path $outDir 'autoruns.csv') -Encoding UTF8
        }
        Write-FSKLog -Logger $Logger -Level INFO -Message 'Collected registry autoruns'
    } catch {
        Write-FSKLog -Logger $Logger -Level ERROR -Message 'Failed to write registry autoruns' -Exception $_.Exception
    }
}
