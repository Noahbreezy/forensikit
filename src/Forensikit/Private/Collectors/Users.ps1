function Invoke-FSKCollectUsers {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Run,
        [Parameter(Mandatory)]$Logger
    )

    $outDir = Join-Path $Run.Persistent 'users'

    try {
        $platform = Get-FSKPlatform

        if ($platform -eq 'Windows') {
            cmd /c 'whoami /all' | Out-File -FilePath (Join-Path $outDir 'whoami_all.txt') -Encoding UTF8

            if (Get-Command Get-LocalUser -ErrorAction SilentlyContinue) {
                Get-LocalUser | Select-Object * | Export-Csv -Path (Join-Path $outDir 'local_users.csv') -NoTypeInformation -Encoding UTF8
            } else {
                cmd /c 'net user' | Out-File -FilePath (Join-Path $outDir 'net_user.txt') -Encoding UTF8
            }

            if (Get-Command Get-LocalGroup -ErrorAction SilentlyContinue) {
                Get-LocalGroup | Select-Object * | Export-Csv -Path (Join-Path $outDir 'local_groups.csv') -NoTypeInformation -Encoding UTF8
            }

            if (Get-Command Get-LocalGroupMember -ErrorAction SilentlyContinue) {
                $groups = @()
                try { $groups = Get-LocalGroup | Select-Object -ExpandProperty Name } catch { $groups = @() }
                foreach ($g in $groups) {
                    try {
                        Get-LocalGroupMember -Group $g | Select-Object @{n='Group';e={$g}}, Name, ObjectClass, PrincipalSource, SID | Export-Csv -Path (Join-Path $outDir 'local_group_members.csv') -NoTypeInformation -Append -Encoding UTF8
                    } catch {
                        # ignore individual group failures
                    }
                }
            }
        } else {
            try { & whoami 2>&1 | Out-File -FilePath (Join-Path $outDir 'whoami.txt') -Encoding UTF8 } catch { }
            try { & id 2>&1 | Out-File -FilePath (Join-Path $outDir 'id.txt') -Encoding UTF8 } catch { }

            if (Test-Path '/etc/passwd') {
                Get-Content -Path '/etc/passwd' -ErrorAction SilentlyContinue | Out-File -FilePath (Join-Path $outDir 'etc_passwd.txt') -Encoding UTF8
            }
            if (Test-Path '/etc/group') {
                Get-Content -Path '/etc/group' -ErrorAction SilentlyContinue | Out-File -FilePath (Join-Path $outDir 'etc_group.txt') -Encoding UTF8
            }
            if (Get-Command getent -ErrorAction SilentlyContinue) {
                try { & getent passwd 2>&1 | Out-File -FilePath (Join-Path $outDir 'getent_passwd.txt') -Encoding UTF8 } catch { }
                try { & getent group 2>&1 | Out-File -FilePath (Join-Path $outDir 'getent_group.txt') -Encoding UTF8 } catch { }
            }
        }

        Write-FSKLog -Logger $Logger -Level INFO -Message "Collected user/account data ($platform)"
    } catch {
        Write-FSKLog -Logger $Logger -Level ERROR -Message 'Failed to collect user/account data' -Exception $_.Exception
    }
}
