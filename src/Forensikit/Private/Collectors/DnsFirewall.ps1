function Invoke-FSKCollectDnsFirewall {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Run,
        [Parameter(Mandatory)]$Logger
    )

    $outDir = Join-Path $Run.Persistent 'network'

    try {
        $platform = Get-FSKPlatform

        if ($platform -eq 'Windows') {
            try {
                cmd /c 'ipconfig /displaydns' | Out-File -FilePath (Join-Path $outDir 'dns_cache.txt') -Encoding UTF8
            } catch {
                Write-FSKLog -Logger $Logger -Level WARN -Message 'DNS cache collection failed (non-fatal)' -Exception $_.Exception
            }

            try {
                if (Get-Command Get-NetFirewallRule -ErrorAction SilentlyContinue) {
                    $rules = Get-NetFirewallRule | Select-Object Name, DisplayName, DisplayGroup, Enabled, Direction, Action, Profile, InterfaceType, Program, Service
                    $rules | Export-Csv -Path (Join-Path $outDir 'firewall_rules.csv') -NoTypeInformation -Encoding UTF8
                } else {
                    'Firewall cmdlets unavailable' | Out-File -FilePath (Join-Path $outDir 'firewall_rules.csv') -Encoding UTF8
                }
            } catch {
                Write-FSKLog -Logger $Logger -Level WARN -Message 'Firewall rule collection failed (non-fatal)' -Exception $_.Exception
            }

            Write-FSKLog -Logger $Logger -Level INFO -Message 'Collected DNS cache and firewall rules'
            return
        }

        # Linux/macOS
        try {
            if (Test-Path '/etc/resolv.conf') {
                Get-Content -Path '/etc/resolv.conf' -ErrorAction SilentlyContinue | Out-File -FilePath (Join-Path $outDir 'resolv.conf.txt') -Encoding UTF8
            }
            if (Test-Path '/etc/hosts') {
                Get-Content -Path '/etc/hosts' -ErrorAction SilentlyContinue | Out-File -FilePath (Join-Path $outDir 'hosts.txt') -Encoding UTF8
            }
        } catch { }

        try {
            if (Get-Command ufw -ErrorAction SilentlyContinue) {
                & ufw status verbose 2>&1 | Out-File -FilePath (Join-Path $outDir 'ufw_status.txt') -Encoding UTF8
            }
            if (Get-Command firewall-cmd -ErrorAction SilentlyContinue) {
                & firewall-cmd --list-all 2>&1 | Out-File -FilePath (Join-Path $outDir 'firewalld_list_all.txt') -Encoding UTF8
            }
            if (Get-Command nft -ErrorAction SilentlyContinue) {
                & nft list ruleset 2>&1 | Out-File -FilePath (Join-Path $outDir 'nft_ruleset.txt') -Encoding UTF8
            } elseif (Get-Command iptables -ErrorAction SilentlyContinue) {
                & iptables -S 2>&1 | Out-File -FilePath (Join-Path $outDir 'iptables_rules.txt') -Encoding UTF8
            }
        } catch {
            Write-FSKLog -Logger $Logger -Level WARN -Message 'Firewall rule collection failed (non-fatal)' -Exception $_.Exception
        }

        Write-FSKLog -Logger $Logger -Level INFO -Message "Collected DNS/firewall data ($platform)"
    } catch {
        Write-FSKLog -Logger $Logger -Level ERROR -Message 'Failed to collect DNS/firewall data' -Exception $_.Exception
    }
}
