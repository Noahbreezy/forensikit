function Invoke-ForensicCollector {
    <#
    .SYNOPSIS
    Collects volatile and persistent evidence from endpoints (local or remote).

    .DESCRIPTION
    Runs locally or remotely via WinRM (Windows) or SSH (PowerShell 7+). Builds a structured output folder per target,
    generates an integrity log (SHA256), and compresses results into a ZIP archive. Supports
    fan-out across many hosts via CSV and optional parallelism on PowerShell 7+.

    .PARAMETER Mode
    Quick | Full | Deep | Custom. Quick/Full/Deep set built-in collector lists; Custom loads a JSON profile
    that defines Collectors and optional EventLogHours.

    .PARAMETER OutputPath
    Base output directory. A new time-stamped run folder is created underneath per computer.

    .PARAMETER CaseId
    Optional string to prefix the run folder/zip for correlation (e.g., a ticket number).

    .PARAMETER ComputerName
    One or more remote computers to collect from via PowerShell Remoting (WinRM). Best supported for Windows targets.

    .PARAMETER ComputerListCsv
        Path to CSV containing a ComputerName (WinRM) and/or HostName (SSH) column. Rows with empty names are ignored.
        Optional SSH per-target override columns:
            - UserName: SSH username override (empty string means no override)
            - KeyFilePath: SSH private key path override (empty string means no override)
        If CSV overrides are present, Forensikit attempts those first and falls back to the command-level -UserName/-KeyFilePath once if provided.

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
        Defaults to enabled. To disable, pass: -MergeSiem:$false

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
        [switch]$MergeSiem
    )

    # Default behavior: merge per-host NDJSON into a single merged NDJSON for multi-target runs.
    # Users can disable via: -MergeSiem:$false
    if (-not $PSBoundParameters.ContainsKey('MergeSiem')) {
        $MergeSiem = $true
    }

    # Optional: some environments prefer coordinating WinRM via Windows PowerShell 5.1.
    # This is opt-in and only applies to WinRM-only runs (no SSH targets) and only when not using -UseParallel.
    # Enable via: $env:FSK_PREFER_WINPS_FOR_WINRM = '1'
    if (-not $env:FSK_REEXEC -and $IsWindows -and $PSVersionTable.PSVersion.Major -ge 7 -and $env:FSK_PREFER_WINPS_FOR_WINRM -eq '1') {
        $sshLikely = $false
        $winrmLikely = $false

        if ($ComputerName -and $ComputerName.Count -gt 0) { $winrmLikely = $true }
        if ($HostName -and $HostName.Count -gt 0) { $sshLikely = $true }
        if ($UserName -or $KeyFilePath) { $sshLikely = $true }

        if ($ComputerListCsv) {
            try {
                $head = Get-Content -Path $ComputerListCsv -TotalCount 1 -ErrorAction Stop
                if ($head -match '(?i)\bHostName\b') { $sshLikely = $true }
                if ($head -match '(?i)\bComputerName\b') { $winrmLikely = $true }

                if (-not $sshLikely -or -not $winrmLikely) {
                    $sample = Import-Csv -Path $ComputerListCsv | Select-Object -First 25
                    foreach ($row in $sample) {
                        if ($row.HostName) { $sshLikely = $true }
                        if ($row.ComputerName) { $winrmLikely = $true }

                        if ($row.Transport -and ([string]$row.Transport -match '^(?i)ssh$')) { $sshLikely = $true }
                        if ($row.Transport -and ([string]$row.Transport -match '^(?i)winrm$')) { $winrmLikely = $true }

                        if ($row.OS -and ([string]$row.OS -match '^(?i)linux|mac(os)?$')) { $sshLikely = $true }
                        if ($row.OS -and ([string]$row.OS -match '^(?i)windows$')) { $winrmLikely = $true }

                        if ($sshLikely -and $winrmLikely) { break }
                    }
                }
            } catch {
                # If we can't inspect the CSV, don't force re-exec here; downstream remoting will handle it.
            }
        }

        if ($winrmLikely -and -not $sshLikely -and -not $UseParallel) {
            $winPsPath = (Get-Command powershell.exe -ErrorAction SilentlyContinue).Source
            if (-not $winPsPath) {
                throw "FSK_PREFER_WINPS_FOR_WINRM=1 was set, but powershell.exe was not found on PATH."
            }

            $env:FSK_REEXEC = '1'

            $credentialPath = $null
            $bound = @{} + $PSBoundParameters
            try {
                if ($bound.ContainsKey('Credential') -and $bound.Credential) {
                    $credentialPath = Join-Path $env:TEMP ("fsk_cred_" + [guid]::NewGuid().ToString() + '.clixml')
                    $bound.Credential | Export-Clixml -Path $credentialPath -Force
                    $bound.Remove('Credential')
                    $bound.__FSKCredentialPath = $credentialPath
                }

                $moduleManifest = (Resolve-Path (Join-Path $PSScriptRoot '..\Forensikit.psd1')).Path
                $moduleManifestEscaped = $moduleManifest.Replace("'","''")
                $payload = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes(($bound | ConvertTo-Json -Depth 8 -Compress)))

                $cmd = @"
`$json = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('$payload'))
`$obj = `$json | ConvertFrom-Json
`$params = @{}
foreach (`$p in `$obj.PSObject.Properties) { `$params[`$p.Name] = `$p.Value }
if (`$params.ContainsKey('__FSKCredentialPath')) {
    `$params.Credential = Import-Clixml -Path `$params.__FSKCredentialPath
    `$params.Remove('__FSKCredentialPath')
}
Import-Module '$moduleManifestEscaped' -Force
Invoke-ForensicCollector @params
"@

                return & $winPsPath -NoProfile -NonInteractive -ExecutionPolicy Bypass -Command $cmd
            } finally {
                if ($credentialPath) {
                    Remove-Item -Path $credentialPath -Force -ErrorAction SilentlyContinue
                }
            }
        }
    }

    # If SSH targets are present and we're running under Windows PowerShell 5.1, automatically
    # re-execute the command under PowerShell 7+ (pwsh). This allows a single entrypoint to
    # “pick the right host” based on remoting transport.
    if (-not $env:FSK_REEXEC -and $PSVersionTable.PSVersion.Major -lt 7) {
        $sshLikely = $false

        if ($HostName -and $HostName.Count -gt 0) { $sshLikely = $true }
        elseif ($UserName -or $KeyFilePath) { $sshLikely = $true }
        elseif ($ComputerListCsv) {
            try {
                $head = Get-Content -Path $ComputerListCsv -TotalCount 1 -ErrorAction Stop
                if ($head -match '(?i)\bHostName\b') { $sshLikely = $true }
                else {
                    $sample = Import-Csv -Path $ComputerListCsv | Select-Object -First 25
                    foreach ($row in $sample) {
                        if ($row.Transport -and ([string]$row.Transport -match '^(?i)ssh$')) { $sshLikely = $true; break }
                        if ($row.OS -and ([string]$row.OS -match '^(?i)linux|mac(os)?$')) { $sshLikely = $true; break }
                        if ($row.HostName) { $sshLikely = $true; break }
                    }
                }
            } catch {
                # If we can't inspect the CSV, don't force re-exec here; downstream validation will handle it.
            }
        }

        if ($sshLikely) {
            $pwshPath = (Get-Command pwsh -ErrorAction SilentlyContinue).Source
            if (-not $pwshPath) {
                throw 'SSH remoting requires PowerShell 7+ (pwsh). Install PowerShell 7 and ensure pwsh is on PATH.'
            }

            $env:FSK_REEXEC = '1'

            $credentialPath = $null
            $bound = @{} + $PSBoundParameters
            try {
                if ($bound.ContainsKey('Credential') -and $bound.Credential) {
                    $credentialPath = Join-Path $env:TEMP ("fsk_cred_" + [guid]::NewGuid().ToString() + '.clixml')
                    $bound.Credential | Export-Clixml -Path $credentialPath -Force
                    $bound.Remove('Credential')
                    $bound.__FSKCredentialPath = $credentialPath
                }

                $moduleManifest = (Resolve-Path (Join-Path $PSScriptRoot '..\Forensikit.psd1')).Path
                $moduleManifestEscaped = $moduleManifest.Replace("'","''")
                $payload = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes(($bound | ConvertTo-Json -Depth 8 -Compress)))

                $cmd = @"
`$json = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('$payload'))
`$obj = `$json | ConvertFrom-Json
`$params = @{}
foreach (`$p in `$obj.PSObject.Properties) { `$params[`$p.Name] = `$p.Value }
if (`$params.ContainsKey('__FSKCredentialPath')) {
    `$params.Credential = Import-Clixml -Path `$params.__FSKCredentialPath
    `$params.Remove('__FSKCredentialPath')
}
Import-Module '$moduleManifestEscaped' -Force
Invoke-ForensicCollector @params
"@

                return & $pwshPath -NoProfile -NonInteractive -ExecutionPolicy Bypass -Command $cmd
            } finally {
                if ($credentialPath) {
                    Remove-Item -Path $credentialPath -Force -ErrorAction SilentlyContinue
                }
            }
        }
    }

    # Note: -HostName targets may also come from CSV parsing.
    # We validate SSH prerequisites later in Invoke-FSKRemoteFanout so WinRM targets can still run
    # even if SSH prerequisites are missing.

    $winrmTargets = New-Object System.Collections.Generic.List[string]
    $sshTargets = New-Object System.Collections.Generic.List[string]
    $sshTargetOptions = @{}

    if ($ComputerListCsv) {
        $csv = Import-Csv -Path $ComputerListCsv
        foreach ($row in $csv) {
            # Supported columns (case-insensitive in PowerShell):
            # - ComputerName (WinRM target) or HostName (SSH target)
            # - OS: Windows | Linux | macOS | Auto (optional)
            # - Transport: WinRM | SSH | Auto (optional)
            $name = $null
            $transport = 'Auto'

            if ($row.Transport) { $transport = ([string]$row.Transport).Trim() }
            $os = if ($row.OS) { ([string]$row.OS).Trim() } else { 'Auto' }

            if ($row.HostName) {
                $name = ([string]$row.HostName).Trim()
                if ($transport -eq 'Auto' -and $os -eq 'Auto') { $transport = 'SSH' }
            } elseif ($row.ComputerName) {
                $name = ([string]$row.ComputerName).Trim()
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

                # Optional per-target SSH overrides:
                # - UserName / KeyFilePath (preferred)
                # - SshUserName / SshKeyFilePath (also accepted)
                $rowUser = $null
                $rowKey = $null

                $pUser = $row.PSObject.Properties['UserName']
                $pSshUser = $row.PSObject.Properties['SshUserName']
                $pKey = $row.PSObject.Properties['KeyFilePath']
                $pSshKey = $row.PSObject.Properties['SshKeyFilePath']

                if ($pUser) { $rowUser = [string]$pUser.Value }
                elseif ($pSshUser) { $rowUser = [string]$pSshUser.Value }

                if ($pKey) { $rowKey = [string]$pKey.Value }
                elseif ($pSshKey) { $rowKey = [string]$pSshKey.Value }

                if ($rowUser) { $rowUser = $rowUser.Trim() }
                if ($rowKey) { $rowKey = $rowKey.Trim().Trim('"').Trim("'") }

                if (($rowUser -and $rowUser.Trim()) -or ($rowKey -and $rowKey.Trim())) {
                    $sshTargetOptions[$name.Trim()] = @{ UserName = $rowUser; KeyFilePath = $rowKey }
                }
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

            $results = Invoke-FSKRemoteFanout -Targets $targets -CollectorConfig $fskConfig -OutputPath $OutputPath -CaseId $CaseId -RunId $runId -Credential $Credential -ThrottleLimit $ThrottleLimit -UseParallel:$UseParallel -HostNameTargets @($sshTargets.ToArray()) -SshUserName $UserName -SshKeyFilePath $KeyFilePath -SshTargetOptions $sshTargetOptions -SiemFormat $SiemFormat

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

    $localComputer = if ($env:COMPUTERNAME -and $env:COMPUTERNAME.Trim()) { $env:COMPUTERNAME.Trim() } else { [System.Environment]::MachineName }
    if ($PSCmdlet.ShouldProcess($localComputer, "Collect forensic evidence (local)")) {
        Invoke-FSKLocalCollection -CollectorConfig $fskConfig -OutputPath $OutputPath -CaseId $CaseId -SiemFormat $SiemFormat
    }
}
