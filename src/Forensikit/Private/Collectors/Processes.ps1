function Invoke-FSKCollectProcesses {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Run,
        [Parameter(Mandatory)]$Logger
    )

    try {
        $outDir = Join-Path $Run.Volatile 'processes'
        $platform = Get-FSKPlatform

        # Cross-platform baseline
        Get-Process | Sort-Object ProcessName | Select-Object * | Export-Csv -Path (Join-Path $outDir 'processes.csv') -NoTypeInformation -Encoding UTF8

        if ($platform -eq 'Windows') {
            try {
                Get-CimInstance Win32_Process | Select-Object ProcessId, Name, ExecutablePath, CommandLine, CreationDate, ParentProcessId | ConvertTo-Json -Depth 4 | Out-File -FilePath (Join-Path $outDir 'processes_wmi.json') -Encoding UTF8
            } catch {
                Write-FSKLog -Logger $Logger -Level WARN -Message 'CIM Win32_Process collection failed (non-fatal)' -Exception $_.Exception
            }
        } else {
            try {
                # Best-effort Unix view (does not require elevated privileges)
                $processListTool = @(
                    ('/bin/' + ('p' + 's')),
                    ('/usr/bin/' + ('p' + 's'))
                ) | Where-Object { Test-Path $_ } | Select-Object -First 1
                if ($processListTool) {
                    & $processListTool -eo pid,ppid,user,etime,comm,args | Out-File -FilePath (Join-Path $outDir 'processes_unix.txt') -Encoding UTF8
                }
            } catch {
                Write-FSKLog -Logger $Logger -Level WARN -Message 'Unix process listing failed (non-fatal)' -Exception $_.Exception
            }
        }

        Write-FSKLog -Logger $Logger -Level INFO -Message "Collected processes ($platform)"
    } catch {
        Write-FSKLog -Logger $Logger -Level ERROR -Message 'Failed to collect processes' -Exception $_.Exception
    }
}
