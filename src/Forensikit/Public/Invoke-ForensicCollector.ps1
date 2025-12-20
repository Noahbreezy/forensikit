function Invoke-ForensicCollector {
    <#
    .SYNOPSIS
    Collects volatile and persistent evidence from Windows endpoints (local or remote).

    .DESCRIPTION
    Runs locally or remotely via PowerShell Remoting. Builds a structured output folder per target,
    generates an integrity log (SHA256), and compresses results into a ZIP archive. Supports
    fan-out across many hosts via CSV and optional parallelism on PowerShell 7+.

    .PARAMETER Mode
    Quick | Full | Custom. Quick/Full set built-in collector lists; Custom loads a JSON profile
    that defines Collectors and optional EventLogHours.

    .PARAMETER OutputPath
    Base output directory. A new time-stamped run folder is created underneath per computer.

    .PARAMETER CaseId
    Optional string to prefix the run folder/zip for correlation (e.g., a ticket number).

    .PARAMETER ComputerName
    One or more remote computers to collect from via PowerShell Remoting (WinRM). Best supported for Windows targets.

    .PARAMETER ComputerListCsv
    Path to CSV containing a ComputerName column. Rows with empty names are ignored.

    .PARAMETER Credential
    Credential for remote collection. If omitted, current credentials are used.

    .PARAMETER ThrottleLimit
    Concurrency limit for remote fan-out. Applies to -UseParallel and the sequential loop.

    .PARAMETER CustomProfilePath
    JSON profile file for -Mode Custom. Must contain Collectors (array) and optional EventLogHours.

    .PARAMETER UseParallel
    When set and running on PowerShell 7+, remote fan-out uses ForEach-Object -Parallel. Defaults to off.

    .PARAMETER HostName
    PowerShell 7+ only: one or more SSH hostnames for cross-platform remoting (Linux/macOS/Windows with SSH). Uses New-PSSession -HostName.

    .PARAMETER UserName
    PowerShell 7+ only: SSH user name for -HostName remoting.

    .PARAMETER KeyFilePath
    PowerShell 7+ only: SSH private key path for -HostName remoting.

        .PARAMETER SiemFormat
        Optional SIEM-oriented output format. When set to Ndjson, Forensikit writes a per-host NDJSON/JSONL file
        under each target folder (siem\events.ndjson), containing:
            - a run_meta header event
            - record events for each collected CSV row
            - artifact events derived from integrity.csv (if present)

        .PARAMETER MergeSiem
        When SiemFormat is Ndjson and multiple targets are collected in one invocation, also writes a merged NDJSON
        file at <OutputPath>\<RunId>\siem\merged.ndjson by concatenating per-host events.ndjson files.

    .OUTPUTS
    PSCustomObject per target with RunId/Root/Zip/Log when run locally; remote fan-out returns an array of results or error objects.

    .NOTES
    - Event Logs: Security log often requires elevated privileges; failures are logged as warnings and collection continues.
    - Remoting: Ensure WinRM is enabled and accessible, or PowerShell Remoting is permitted; module is copied to remote temp before execution.
    - Parallel: Requires PowerShell 7+ for -UseParallel.

    .EXAMPLE
    Invoke-ForensicCollector -Mode Quick -OutputPath .\Output

    .EXAMPLE
    Invoke-ForensicCollector -Mode Full -ComputerName PC01,PC02 -OutputPath .\Output

    .EXAMPLE
    Invoke-ForensicCollector -Mode Quick -ComputerListCsv .\computers.csv -OutputPath .\Output -ThrottleLimit 16

    .EXAMPLE
    Invoke-ForensicCollector -Mode Custom -CustomProfilePath .\examples\custom_profile.json -OutputPath .\Output -UseParallel -ThrottleLimit 32

    .EXAMPLE
    Invoke-ForensicCollector -Mode Quick -ComputerListCsv .\examples\targets.csv -OutputPath .\Output -UseParallel -ThrottleLimit 16 -SiemFormat Ndjson
    #>

    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory)]
        [ValidateSet('Quick','Full','Deep','Custom')]
        [string]$Mode,

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [string]$OutputPath = (Join-Path -Path (Get-Location) -ChildPath 'Output'),

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [string]$CaseId,

        [Parameter()]
        [string[]]$ComputerName,

        [Parameter()]
        [string[]]$HostName,

        [Parameter()]
        [string]$UserName,

        [Parameter()]
        [ValidateScript({ Test-Path $_ })]
        [string]$KeyFilePath,

        [Parameter()]
        [ValidateScript({ Test-Path $_ })]
        [string]$ComputerListCsv,

        [Parameter()]
        [System.Management.Automation.PSCredential]$Credential,

        [Parameter()]
        [ValidateRange(1,256)]
        [int]$ThrottleLimit = 16,

        [Parameter()]
        [ValidateScript({ Test-Path $_ })]
        [string]$CustomProfilePath,

        [Parameter()]
        [switch]$UseParallel,

        [Parameter()]
        [ValidateSet('None','Ndjson')]
        [string]$SiemFormat = 'None',

        [Parameter()]
        [bool]$MergeSiem = $true
    )

    # Note: -HostName targets may also come from CSV parsing.
    # We validate SSH prerequisites later in Invoke-FSKRemoteFanout so WinRM targets can still run
    # even if SSH prerequisites are missing.

    $winrmTargets = New-Object System.Collections.Generic.List[string]
    $sshTargets = New-Object System.Collections.Generic.List[string]

    if ($ComputerListCsv) {
        $csv = Import-Csv -Path $ComputerListCsv
        foreach ($row in $csv) {
            # Supported columns (case-insensitive in PowerShell):
            # - ComputerName (WinRM target) or HostName (SSH target)
            # - OS: Windows | Linux | macOS | Auto (optional)
            # - Transport: WinRM | SSH | Auto (optional)
            $name = $null
            $transport = 'Auto'

            if ($row.Transport) { $transport = [string]$row.Transport }
            $os = if ($row.OS) { [string]$row.OS } else { 'Auto' }

            if ($row.HostName) {
                $name = [string]$row.HostName
                if ($transport -eq 'Auto' -and $os -eq 'Auto') { $transport = 'SSH' }
            } elseif ($row.ComputerName) {
                $name = [string]$row.ComputerName
            }

            if (-not $name -or -not $name.Trim()) { continue }

            if ($transport -eq 'Auto') {
                switch -Regex ($os) {
                    '^(?i)windows$' { $transport = 'WinRM' }
                    '^(?i)linux$' { $transport = 'SSH' }
                    '^(?i)mac(os)?$' { $transport = 'SSH' }
                    default {
                        # Default to WinRM if no OS/transport provided; user can override with HostName/Transport
                        $transport = 'WinRM'
                    }
                }
            }

            if ($transport -match '^(?i)ssh$') {
                $sshTargets.Add($name.Trim())
            } else {
                $winrmTargets.Add($name.Trim())
            }
        }
    }

    if ($ComputerName) {
        foreach ($c in $ComputerName) {
            if ($c -and $c.Trim()) { $winrmTargets.Add($c.Trim()) }
        }
    }

    if ($HostName) {
        foreach ($h in $HostName) {
            if ($h -and $h.Trim()) { $sshTargets.Add($h.Trim()) }
        }
    }

    $targets = @(
        @($winrmTargets.ToArray()) + @($sshTargets.ToArray()) |
            Where-Object { $_ -and $_.Trim() } |
            Select-Object -Unique
    )

    if (-not (Test-Path -Path $OutputPath)) {
        New-Item -Path $OutputPath -ItemType Directory -Force | Out-Null
    }

    $fskConfig = Get-FSKConfig -Mode $Mode -CustomProfilePath $CustomProfilePath

    if ($targets.Count -gt 0) {
        if ($PSCmdlet.ShouldProcess(($targets -join ','), "Collect forensic evidence (remote)")) {
            # Create a single run id so all hosts land under one output folder and can be merged.
            $stamp = (Get-Date).ToUniversalTime().ToString('yyyyMMdd_HHmmssZ')
            $runId = if ($CaseId) { "$CaseId`_$stamp" } else { $stamp }

            $results = Invoke-FSKRemoteFanout -Targets $targets -CollectorConfig $fskConfig -OutputPath $OutputPath -CaseId $CaseId -RunId $runId -Credential $Credential -ThrottleLimit $ThrottleLimit -UseParallel:$UseParallel -HostNameTargets @($sshTargets.ToArray()) -SshUserName $UserName -SshKeyFilePath $KeyFilePath -SiemFormat $SiemFormat

            if ($SiemFormat -eq 'Ndjson' -and $MergeSiem) {
                try {
                    $mergedPath = Join-Path (Join-Path $OutputPath $runId) 'siem\merged.ndjson'
                    Merge-FSKSiemNdjson -RunFolder (Join-Path $OutputPath $runId) -MergedNdjsonPath $mergedPath | Out-Null
                    Write-Verbose "Merged SIEM NDJSON: $mergedPath"
                } catch {
                    Write-Warning "Failed to merge SIEM NDJSON: $($_.Exception.Message)"
                }
            }

            return $results
        }
        return
    }

    if ($PSCmdlet.ShouldProcess($env:COMPUTERNAME, "Collect forensic evidence (local)")) {
        Invoke-FSKLocalCollection -CollectorConfig $fskConfig -OutputPath $OutputPath -CaseId $CaseId -SiemFormat $SiemFormat
    }
}
