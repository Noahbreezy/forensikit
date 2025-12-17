function Invoke-FSKCollectNetwork {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Run,
        [Parameter(Mandatory)]$Logger
    )

    $outDir = Join-Path $Run.Volatile 'network'

    try {
        $platform = Get-FSKPlatform

        if ($platform -eq 'Windows') {
            if (Get-Command Get-NetTCPConnection -ErrorAction SilentlyContinue) {
                Get-NetTCPConnection | Select-Object * | Export-Csv -Path (Join-Path $outDir 'net_tcp_connections.csv') -NoTypeInformation -Encoding UTF8
            } else {
                cmd /c 'netstat -ano' | Out-File -FilePath (Join-Path $outDir 'netstat_ano.txt') -Encoding UTF8
            }

            if (Get-Command Get-NetUDPEndpoint -ErrorAction SilentlyContinue) {
                Get-NetUDPEndpoint | Select-Object * | Export-Csv -Path (Join-Path $outDir 'net_udp_endpoints.csv') -NoTypeInformation -Encoding UTF8
            }

            cmd /c 'ipconfig /all' | Out-File -FilePath (Join-Path $outDir 'ipconfig_all.txt') -Encoding UTF8
            cmd /c 'route print' | Out-File -FilePath (Join-Path $outDir 'route_print.txt') -Encoding UTF8
            cmd /c 'arp -a' | Out-File -FilePath (Join-Path $outDir 'arp_a.txt') -Encoding UTF8
            cmd /c 'netstat -abno' | Out-File -FilePath (Join-Path $outDir 'netstat_abno.txt') -Encoding UTF8
        } else {
            # Linux/macOS best-effort equivalents
            if (Get-Command ss -ErrorAction SilentlyContinue) {
                & ss -tulpen | Out-File -FilePath (Join-Path $outDir 'ss_listen.txt') -Encoding UTF8
                & ss -tunap | Out-File -FilePath (Join-Path $outDir 'ss_connections.txt') -Encoding UTF8
            } elseif (Get-Command netstat -ErrorAction SilentlyContinue) {
                & netstat -anp 2>&1 | Out-File -FilePath (Join-Path $outDir 'netstat_anp.txt') -Encoding UTF8
            }

            if (Get-Command ip -ErrorAction SilentlyContinue) {
                & ip addr | Out-File -FilePath (Join-Path $outDir 'ip_addr.txt') -Encoding UTF8
                & ip route | Out-File -FilePath (Join-Path $outDir 'ip_route.txt') -Encoding UTF8
                & ip neigh | Out-File -FilePath (Join-Path $outDir 'ip_neigh.txt') -Encoding UTF8
            } elseif (Get-Command ifconfig -ErrorAction SilentlyContinue) {
                & ifconfig -a 2>&1 | Out-File -FilePath (Join-Path $outDir 'ifconfig_a.txt') -Encoding UTF8
            }
        }

        Write-FSKLog -Logger $Logger -Level INFO -Message "Collected network data ($platform)"
    } catch {
        Write-FSKLog -Logger $Logger -Level ERROR -Message 'Failed to collect network data' -Exception $_.Exception
    }
}
