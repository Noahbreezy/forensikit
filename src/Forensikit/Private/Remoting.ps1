function Invoke-FSKLocalCollection {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$CollectorConfig,
        [Parameter(Mandatory)][string]$OutputPath,
        [Parameter()][string]$CaseId,
        [Parameter()][string]$RunId,
        [Parameter()][ValidateSet('None','Ndjson')][string]$SiemFormat = 'None'
    )

    $computer = if ($env:COMPUTERNAME -and $env:COMPUTERNAME.Trim()) { $env:COMPUTERNAME.Trim() } else { [System.Environment]::MachineName }
    $user = if ($env:USERNAME -and $env:USERNAME.Trim()) { $env:USERNAME.Trim() } elseif ($env:USER -and $env:USER.Trim()) { $env:USER.Trim() } else { [System.Environment]::UserName }

    $run = New-FSKRunFolder -OutputPath $OutputPath -ComputerName $computer -CaseId $CaseId -RunId $RunId
    $logger = New-FSKLogger -LogPath (Join-Path $run.Logs 'collector.log')

    $meta = [ordered]@{
        Tool        = 'Forensikit'
        Version     = '0.1.0'
        Computer    = $computer
        User        = $user
        Mode        = $CollectorConfig.Mode
        StartedUtc  = (Get-Date).ToUniversalTime().ToString('o')
        Collectors  = @($CollectorConfig.Collectors)
    }

    Write-FSKLog -Logger $logger -Level INFO -Message "Run started (Mode=$($CollectorConfig.Mode))"

    foreach ($collector in $CollectorConfig.Collectors) {
        switch ($collector) {
            'Processes' { Invoke-FSKCollectProcesses -Run $run -Logger $logger }
            'Network'   { Invoke-FSKCollectNetwork -Run $run -Logger $logger }
            'Users'     { Invoke-FSKCollectUsers -Run $run -Logger $logger }
            'EventLogs' { Invoke-FSKCollectEventLogs -Run $run -Logger $logger -CollectorConfig $CollectorConfig }
            'Services'  { Invoke-FSKCollectServices -Run $run -Logger $logger }
            'ScheduledTasks' { Invoke-FSKCollectScheduledTasks -Run $run -Logger $logger }
            'Registry'  { Invoke-FSKCollectRegistry -Run $run -Logger $logger }
            'InstalledSoftware' { Invoke-FSKCollectInstalledSoftware -Run $run -Logger $logger }
            'DnsFirewall' { Invoke-FSKCollectDnsFirewall -Run $run -Logger $logger }
            default     { Write-FSKLog -Logger $logger -Level WARN -Message "Unknown collector '$collector'" }
        }
    }

    $meta.EndedUtc = (Get-Date).ToUniversalTime().ToString('o')
    $metaPath = Join-Path $run.Root 'run.json'
    ($meta | ConvertTo-Json -Depth 6) | Out-File -FilePath $metaPath -Encoding UTF8

    $siemPath = $null
    if ($SiemFormat -eq 'Ndjson') {
        $siemPath = Export-FSKSiemNdjson -Run $run -Config $CollectorConfig -Logger $logger -NdjsonPath (Join-Path $run.Root 'siem\\events.ndjson')
    }

    $zipPath = Join-Path (Split-Path $run.Root -Parent) ("$computer`_$($run.RunId).zip")
    New-FSKZip -SourceFolder $run.Root -ZipPath $zipPath

    Write-FSKLog -Logger $logger -Level INFO -Message "Run finished; ZIP: $zipPath"

    $integrityPath = Join-Path $run.Root 'integrity.csv'
    New-FSKIntegrityLog -RootPath $run.Root -IntegrityCsvPath $integrityPath

    return [pscustomobject]@{
        RunId = $run.RunId
        Root  = $run.Root
        Zip   = $zipPath
        Log   = $logger.Path
        SiemNdjson = $siemPath
    }
}

function Invoke-FSKRemoteSingle {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Target,
        [Parameter()][ValidateSet('WinRM','SSH')][string]$Transport = 'WinRM',
        [Parameter(Mandatory)]$CollectorConfig,
        [Parameter(Mandatory)][string]$OutputPath,
        [Parameter()][string]$CaseId,
        [Parameter()][string]$RunId,
        [Parameter()][System.Management.Automation.PSCredential]$Credential,
        [Parameter()][string]$SshUserName,
        [Parameter()][string]$SshKeyFilePath,
        [Parameter()][ValidateSet('None','Ndjson')][string]$SiemFormat = 'None'
    )

    $session = $null
    $remoteBase = $null

    try {
        if ($Transport -eq 'SSH') {
            if ($PSVersionTable.PSVersion.Major -lt 7) {
                throw "SSH remoting requires PowerShell 7+"
            }
            if (-not $SshUserName) { throw "SshUserName is required for SSH remoting" }
            if (-not $SshKeyFilePath) { throw "SshKeyFilePath is required for SSH remoting" }

            try {
                $session = New-PSSession -HostName $Target -UserName $SshUserName -KeyFilePath $SshKeyFilePath -ErrorAction Stop
            } catch {
                $msg = $_.Exception.Message
                if ($msg -match '(?i)subsystem request failed|SSH client session has ended') {
                    $hint = @(
                        "PowerShell SSH remoting requires the 'powershell' SSH Subsystem to be configured on the target.",
                        "On Ubuntu, add a line like:",
                        "  Subsystem powershell /usr/bin/pwsh -sshs -NoLogo -NoProfile",
                        "then restart SSH: sudo systemctl restart ssh",
                        "(Keep the existing 'Subsystem sftp ...' line.)"
                    ) -join ' '
                    throw "$msg $hint"
                }
                throw
            }
        } else {
            $session = if ($Credential) {
                New-PSSession -ComputerName $Target -Credential $Credential -ErrorAction Stop
            } else {
                New-PSSession -ComputerName $Target -ErrorAction Stop
            }
        }

        # Remote preflight: check platform and PowerShell version to surface clearer errors
        try {
            $pre = Invoke-Command -Session $session -ScriptBlock {
                [pscustomobject]@{
                    PSVersion = $PSVersionTable.PSVersion.ToString()
                    PSEdition = $PSVersionTable.PSEdition
                    Platform  = if ($PSVersionTable.PSVersion.Major -lt 6) { 'Windows' } elseif ($IsWindows) { 'Windows' } elseif ($IsLinux) { 'Linux' } elseif ($IsMacOS) { 'macOS' } else { 'Unknown' }
                }
            }

            # SSH remoting implies PowerShell 6+ on target; still keep guardrails
            if ($Transport -eq 'SSH' -and ([version]$pre.PSVersion).Major -lt 6) {
                throw "Target PowerShell version is too old for SSH remoting: $($pre.PSVersion)"
            }
        } catch {
            throw
        }

        $remoteBase = Invoke-Command -Session $session -ScriptBlock {
            $base = [System.IO.Path]::GetTempPath()
            $p = Join-Path $base ("Forensikit" + [System.IO.Path]::DirectorySeparatorChar + [guid]::NewGuid().ToString())
            New-Item -Path $p -ItemType Directory -Force | Out-Null
            return $p
        }

        $localModule = Join-Path $PSScriptRoot '..\..\Forensikit'
        $localModuleContents = Join-Path $localModule '*'
        # IMPORTANT: when remoting over SSH to Linux/macOS, the remote path is POSIX.
        # Do not use Join-Path here (it will emit Windows-style backslashes and break Copy-Item -ToSession).
        $remoteModule = if ($Transport -eq 'SSH') {
            ($remoteBase.TrimEnd('/')) + '/Forensikit'
        } else {
            Join-Path $remoteBase 'Forensikit'
        }

        Invoke-Command -Session $session -ArgumentList @($remoteModule) -ScriptBlock {
            param($remoteModule)
            New-Item -Path $remoteModule -ItemType Directory -Force | Out-Null
        }

        Copy-Item -Path $localModuleContents -Destination $remoteModule -ToSession $session -Recurse -Force

        $remoteResult = Invoke-Command -Session $session -ArgumentList @($remoteModule, $CollectorConfig, $remoteBase, $CaseId, $RunId, $SiemFormat, $Transport) -ScriptBlock {
            param($remoteModule, $collectorConfig, $remoteBase, $caseId, $runId, $siemFormat, $transport)

            $mod = Import-Module (Join-Path $remoteModule 'Forensikit.psd1') -Force -PassThru
            if (-not $mod) { throw 'Failed to import Forensikit module on target.' }

            $out = Join-Path $remoteBase 'Output'

            # On Linux/macOS targets over SSH: try to elevate via non-interactive sudo first.
            # If sudo requires a password or is unavailable, continue as the SSH user.
            # If we do run as root, ensure artifacts are chowned back so the SSH session can copy them out.
            $trySudo = ($transport -eq 'SSH') -and ($IsLinux -or $IsMacOS)
            $sudoOk = $false
            if ($trySudo) {
                $sudo = Get-Command sudo -ErrorAction SilentlyContinue
                if ($sudo) {
                    & sudo -n true 2>$null
                    if ($LASTEXITCODE -eq 0) { $sudoOk = $true }
                }
            }

            if ($sudoOk) {
                $pwshPath = (Get-Command pwsh -ErrorAction SilentlyContinue).Source
                if (-not $pwshPath) { $pwshPath = 'pwsh' }

                $payloadObj = [ordered]@{
                    RemoteModule = $remoteModule
                    RemoteBase   = $remoteBase
                    Out          = $out
                    CaseId       = $caseId
                    RunId        = $runId
                    SiemFormat   = $siemFormat
                    CollectorConfig = $collectorConfig
                }

                $payload = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes(($payloadObj | ConvertTo-Json -Depth 10 -Compress)))

                $cmd = @"
`$json = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('$payload'))
`$p = `$json | ConvertFrom-Json
`$mod = Import-Module (Join-Path `$p.RemoteModule 'Forensikit.psd1') -Force -PassThru
if (-not `$mod) { throw 'Failed to import Forensikit module on target (sudo context).' }
`$r = & `$mod {
    param(`$collectorConfig, `$out, `$caseId, `$runId, `$siemFormat)
    Invoke-FSKLocalCollection -CollectorConfig `$collectorConfig -OutputPath `$out -CaseId `$caseId -RunId `$runId -SiemFormat `$siemFormat
} `$p.CollectorConfig `$p.Out `$p.CaseId `$p.RunId `$p.SiemFormat
try {
    if (`$env:SUDO_USER) {
        & chown -R "`$env:SUDO_USER`:`$env:SUDO_USER" `$p.RemoteBase 2>`$null
    }
    & chmod -R u+rwX `$p.RemoteBase 2>`$null
} catch {}
`$r | ConvertTo-Json -Depth 10 -Compress
"@

                $raw = & sudo -n $pwshPath -NoLogo -NoProfile -NonInteractive -Command $cmd
                return ($raw | ConvertFrom-Json)
            }

            & $mod {
                param($collectorConfig, $out, $caseId, $runId, $siemFormat)
                Invoke-FSKLocalCollection -CollectorConfig $collectorConfig -OutputPath $out -CaseId $caseId -RunId $runId -SiemFormat $siemFormat
            } $collectorConfig $out $caseId $runId $siemFormat
        }

        $localRunFolder = Join-Path $OutputPath $remoteResult.RunId
        if (-not (Test-Path $localRunFolder)) { New-Item -Path $localRunFolder -ItemType Directory -Force | Out-Null }

        $destZip = Join-Path $localRunFolder (Split-Path $remoteResult.Zip -Leaf)
        Copy-Item -FromSession $session -Path $remoteResult.Zip -Destination $destZip -Force

        $destSiem = $null
        if ($remoteResult.SiemNdjson) {
            $destSiemDir = Join-Path (Join-Path $localRunFolder $Target) 'siem'
            if (-not (Test-Path $destSiemDir)) { New-Item -Path $destSiemDir -ItemType Directory -Force | Out-Null }
            $destSiem = Join-Path $destSiemDir 'events.ndjson'
            Copy-Item -FromSession $session -Path $remoteResult.SiemNdjson -Destination $destSiem -Force
        }

        return [pscustomobject]@{
            Computer = $Target
            Zip      = $destZip
            RunId    = $remoteResult.RunId
            SiemNdjson = $destSiem
        }
    } catch {
        throw
    } finally {
        if ($session -and $remoteBase) {
            try {
                Invoke-Command -Session $session -ArgumentList @($remoteBase) -ScriptBlock { param($p) Remove-Item -Path $p -Recurse -Force -ErrorAction SilentlyContinue }
            } catch { }
        }
        if ($session) { Remove-PSSession -Session $session -ErrorAction SilentlyContinue }
    }
}

function Invoke-FSKRemoteFanout {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string[]]$Targets,
        [Parameter(Mandatory)]$CollectorConfig,
        [Parameter(Mandatory)][string]$OutputPath,
        [Parameter()][string]$CaseId,
        [Parameter()][string]$RunId,
        [Parameter()][System.Management.Automation.PSCredential]$Credential,
        [Parameter()][int]$ThrottleLimit = 16,
        [Parameter()][switch]$UseParallel,
        [Parameter()][string[]]$HostNameTargets,
        [Parameter()][string]$SshUserName,
        [Parameter()][string]$SshKeyFilePath,
        [Parameter()][ValidateSet('None','Ndjson')][string]$SiemFormat = 'None'
    )

    $results = New-Object System.Collections.Generic.List[object]

    $canParallel = $UseParallel.IsPresent -and ($PSVersionTable.PSVersion.Major -ge 7)

    # Preflight: If SSH targets are requested but prerequisites are missing locally, return per-host errors
    if ($HostNameTargets -and $HostNameTargets.Count -gt 0) {
        if ($SshKeyFilePath) { $SshKeyFilePath = $SshKeyFilePath.Trim().Trim('"').Trim("'") }

        if ($PSVersionTable.PSVersion.Major -lt 7) {
            foreach ($h in $HostNameTargets) {
                $results.Add([pscustomobject]@{ Computer = $h; Error = 'SSH remoting requires PowerShell 7+ on the coordinator host' })
            }
            # Remove SSH targets from execution set
            $Targets = @($Targets | Where-Object { $HostNameTargets -notcontains $_ })
        } elseif (-not $SshUserName -or -not $SshKeyFilePath) {
            foreach ($h in $HostNameTargets) {
                $results.Add([pscustomobject]@{ Computer = $h; Error = 'SSH remoting requires -UserName and -KeyFilePath' })
            }
            $Targets = @($Targets | Where-Object { $HostNameTargets -notcontains $_ })
        } elseif (-not (Test-Path -LiteralPath $SshKeyFilePath)) {
            foreach ($h in $HostNameTargets) {
                $results.Add([pscustomobject]@{ Computer = $h; Error = "SSH key file not found: $SshKeyFilePath" })
            }
            $Targets = @($Targets | Where-Object { $HostNameTargets -notcontains $_ })
        }
    }

    if (-not $Targets -or $Targets.Count -eq 0) {
        return $results
    }

    if ($canParallel) {
        $parallelResults = $Targets | ForEach-Object -Parallel {
            try {
                Import-Module (Join-Path $using:PSScriptRoot '..\Forensikit.psd1') -Force
                $transport = if ($using:HostNameTargets -and ($using:HostNameTargets -contains $_)) { 'SSH' } else { 'WinRM' }
                Invoke-FSKRemoteSingle -Target $_ -Transport $transport -CollectorConfig $using:CollectorConfig -OutputPath $using:OutputPath -CaseId $using:CaseId -RunId $using:RunId -Credential $using:Credential -SshUserName $using:SshUserName -SshKeyFilePath $using:SshKeyFilePath -SiemFormat $using:SiemFormat
            } catch {
                [pscustomobject]@{ Computer = $_; Error = $_.Exception.Message }
            }
        } -ThrottleLimit $ThrottleLimit

        # Preserve any preflight error objects (e.g. SSH prerequisites) alongside parallel results.
        return @($results.ToArray()) + @($parallelResults)
    } else {
        foreach ($t in $Targets) {
            try {
                $transport = if ($HostNameTargets -and ($HostNameTargets -contains $t)) { 'SSH' } else { 'WinRM' }
                $results.Add((Invoke-FSKRemoteSingle -Target $t -Transport $transport -CollectorConfig $CollectorConfig -OutputPath $OutputPath -CaseId $CaseId -RunId $RunId -Credential $Credential -SshUserName $SshUserName -SshKeyFilePath $SshKeyFilePath -SiemFormat $SiemFormat))
            } catch {
                $results.Add([pscustomobject]@{ Computer = $t; Error = $_.Exception.Message })
            }
        }
        $results
    }
}
