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
        Platform    = (Get-FSKPlatform)
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

    $integrityPath = Join-Path $run.Root 'integrity.csv'
    New-FSKIntegrityLog -RootPath $run.Root -IntegrityCsvPath $integrityPath

    $zipPath = Join-Path (Split-Path $run.Root -Parent) ("$computer`_$($run.RunId).zip")
    New-FSKZip -SourceFolder $run.Root -ZipPath $zipPath

    Write-FSKLog -Logger $logger -Level INFO -Message "Run finished; ZIP: $zipPath"

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
        [Parameter()][string]$TargetSshUserName,
        [Parameter()][string]$TargetSshKeyFilePath,
        [Parameter()][ValidateSet('None','Ndjson')][string]$SiemFormat = 'None'
    )

    $session = $null
    $remoteBase = $null

    try {
        if ($Transport -eq 'SSH') {
            if ($PSVersionTable.PSVersion.Major -lt 7) {
                throw "SSH remoting requires PowerShell 7+"
            }

            if ($SshKeyFilePath) { $SshKeyFilePath = $SshKeyFilePath.Trim().Trim('"').Trim("'") }
            if ($TargetSshKeyFilePath) { $TargetSshKeyFilePath = $TargetSshKeyFilePath.Trim().Trim('"').Trim("'") }

            $primaryUser = if ($TargetSshUserName -and $TargetSshUserName.Trim()) { $TargetSshUserName.Trim() } else { $SshUserName }
            $primaryKey = if ($TargetSshKeyFilePath -and $TargetSshKeyFilePath.Trim()) { $TargetSshKeyFilePath } else { $SshKeyFilePath }
            $fallbackUser = if ($SshUserName -and $SshUserName.Trim()) { $SshUserName.Trim() } else { $null }
            $fallbackKey = if ($SshKeyFilePath -and $SshKeyFilePath.Trim()) { $SshKeyFilePath } else { $null }

            if (-not $primaryUser) { throw "SshUserName is required for SSH remoting (provide -UserName or CSV UserName)" }
            if (-not $primaryKey) { throw "SshKeyFilePath is required for SSH remoting (provide -KeyFilePath or CSV KeyFilePath)" }

            $hasOverride = ($TargetSshUserName -and $TargetSshUserName.Trim()) -or ($TargetSshKeyFilePath -and $TargetSshKeyFilePath.Trim())
            $canFallback = $hasOverride -and $fallbackUser -and $fallbackKey -and (($primaryUser -ne $fallbackUser) -or ($primaryKey -ne $fallbackKey))

            $attempts = New-Object System.Collections.Generic.List[object]
            $attempts.Add([pscustomobject]@{ User = $primaryUser; Key = $primaryKey; Label = 'primary' })
            if ($canFallback) {
                $attempts.Add([pscustomobject]@{ User = $fallbackUser; Key = $fallbackKey; Label = 'fallback' })
            }

            $lastError = $null
            $subsystemHint = $null

            foreach ($a in $attempts) {
                if (-not (Test-Path -LiteralPath $a.Key)) {
                    $lastError = "SSH key file not found: $($a.Key)"
                    continue
                }

                # Preflight to avoid ssh.exe prompting (e.g., unknown host key) which can hang a non-interactive run.
                # This uses OpenSSH in BatchMode to fail fast with a clear error instead of prompting.
                $sshExe = Get-Command ssh -ErrorAction SilentlyContinue
                if ($sshExe) {
                    $strict = if ($env:FSK_SSH_ACCEPT_NEW_HOSTKEY -eq '1') { 'accept-new' } else { 'yes' }
                    $args = @(
                        '-o', 'BatchMode=yes',
                        '-o', ('StrictHostKeyChecking=' + $strict),
                        '-o', 'ConnectTimeout=10',
                        '-i', $a.Key,
                        ($a.User + '@' + $Target),
                        'exit'
                    )

                    & $sshExe @args 2>$null | Out-Null
                    if ($LASTEXITCODE -ne 0) {
                        $extra = if ($strict -eq 'yes') {
                            "If this is the first time connecting, accept the SSH host key (e.g. run: ssh $($a.User)@$Target) or set FSK_SSH_ACCEPT_NEW_HOSTKEY=1 to auto-accept new host keys."
                        } else {
                            'SSH connectivity check failed. Verify DNS/firewall, key permissions, and that SSH is reachable.'
                        }
                        $lastError = "SSH preflight failed for $Target ($($a.Label) attempt). $extra"
                        continue
                    }
                }

                try {
                    $session = New-PSSession -HostName $Target -UserName $a.User -KeyFilePath $a.Key -ErrorAction Stop
                    $lastError = $null
                    break
                } catch {
                    $msg = $_.Exception.Message
                    $lastError = $msg
                    if ($msg -match '(?i)subsystem request failed|SSH client session has ended') {
                        $subsystemHint = @(
                            "PowerShell SSH remoting requires the 'powershell' SSH Subsystem to be configured on the target.",
                            'On Ubuntu, add a line like:',
                            '  Subsystem powershell /usr/bin/pwsh -sshs -NoLogo -NoProfile',
                            'then restart SSH: sudo systemctl restart ssh',
                            "(Keep the existing 'Subsystem sftp ...' line.)"
                        ) -join ' '
                    }
                }
            }

            if (-not $session) {
                if ($subsystemHint) {
                    throw "$lastError $subsystemHint"
                }
                throw $lastError
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
            } -ErrorAction Stop

            # SSH remoting implies PowerShell 6+ on target; still keep guardrails
            if ($Transport -eq 'SSH' -and ([version]$pre.PSVersion).Major -lt 6) {
                throw "Target PowerShell version is too old for SSH remoting: $($pre.PSVersion)"
            }
        } catch {
            throw
        }

        $remoteBase = Invoke-Command -Session $session -ErrorAction Stop -ScriptBlock {
            # Prefer a disk-backed temp directory on Linux/macOS.
            # Many Linux distros mount /tmp as tmpfs; writing the collection output there can consume RAM
            # and trigger the OOM killer on small hosts.
            $base = [System.IO.Path]::GetTempPath()

            if (($IsLinux -or $IsMacOS) -and (Test-Path -LiteralPath '/var/tmp')) {
                try {
                    $probe = Join-Path '/var/tmp' ("fsk_probe_" + [guid]::NewGuid().ToString())
                    New-Item -Path $probe -ItemType Directory -Force -ErrorAction Stop | Out-Null
                    Remove-Item -Path $probe -Recurse -Force -ErrorAction SilentlyContinue
                    $base = '/var/tmp'
                } catch {
                    # If /var/tmp isn't usable, fall back to default temp.
                }
            }

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
        } -ErrorAction Stop

        Copy-Item -Path $localModuleContents -Destination $remoteModule -ToSession $session -Recurse -Force -ErrorAction Stop

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
        } -ErrorAction Stop

        # Be defensive: remoting can occasionally return arrays (multiple pipeline objects) or unexpected shapes.
        # Avoid strict-mode property access on missing members.
        $remoteItems = @($remoteResult)
        $picked = $null
        foreach ($it in $remoteItems) {
            if (-not $it) { continue }
            $hasRunId = ($it.PSObject.Properties.Name -contains 'RunId')
            $hasZip = ($it.PSObject.Properties.Name -contains 'Zip')
            if ($hasRunId -and $hasZip) { $picked = $it; break }
        }

        if (-not $picked) {
            $types = @(
                foreach ($it in $remoteItems) {
                    if ($it) { $it.GetType().FullName } else { '<null>' }
                }
            ) | Select-Object -Unique

            $count = $remoteItems.Count
            $first = @($remoteItems | Where-Object { $_ } | Select-Object -First 1)
            $firstType = if ($first.Count -gt 0 -and $first[0]) { $first[0].GetType().FullName } else { '<none>' }
            $preview = $null
            try {
                $preview = (@($remoteItems | Select-Object -First 3) | ConvertTo-Json -Depth 6 -Compress)
            } catch {
                $preview = '<unserializable>'
            }

            throw "Remote collection returned an unexpected result (missing RunId/Zip). Count=$count; Types=$($types -join ', '); FirstType=$firstType; Preview=$preview"
        }

        $remoteRunId = [string]$picked.RunId
        $remoteZip = [string]$picked.Zip
        $remoteSiem = $null
        if ($picked.PSObject.Properties.Name -contains 'SiemNdjson') { $remoteSiem = $picked.SiemNdjson }

        $localRunFolder = Join-Path $OutputPath $remoteRunId
        if (-not (Test-Path $localRunFolder)) { New-Item -Path $localRunFolder -ItemType Directory -Force | Out-Null }

        $destZip = Join-Path $localRunFolder (Split-Path $remoteZip -Leaf)
        Copy-Item -FromSession $session -Path $remoteZip -Destination $destZip -Force -ErrorAction Stop

        $destSiem = $null
        if ($remoteSiem) {
            $destSiemDir = Join-Path (Join-Path $localRunFolder $Target) 'siem'
            if (-not (Test-Path $destSiemDir)) { New-Item -Path $destSiemDir -ItemType Directory -Force | Out-Null }
            $destSiem = Join-Path $destSiemDir 'events.ndjson'
            Copy-Item -FromSession $session -Path $remoteSiem -Destination $destSiem -Force -ErrorAction Stop
        }

        # Remote runs pull back a ZIP; extract it so the local output layout matches local runs:
        #   <OutputPath>\<RunId>\<Computer>\run.json ...
        $hostFolder = Join-Path $localRunFolder $Target
        if (-not (Test-Path $hostFolder)) { New-Item -Path $hostFolder -ItemType Directory -Force | Out-Null }

        $extracted = $false
        $extractError = $null
        try {
            Expand-Archive -Path $destZip -DestinationPath $hostFolder -Force
            $extracted = $true
        } catch {
            $extractError = $_.Exception.Message
            Write-Warning "Failed to extract remote ZIP for $Target into $hostFolder. You can extract manually from: $destZip. Error: $extractError"
        }

        return [pscustomobject]@{
            Computer = $Target
            Zip      = $destZip
            RunId    = $remoteRunId
            SiemNdjson = $destSiem
            RunRoot  = $localRunFolder
            Root     = $hostFolder
            Extracted = $extracted
            ExtractError = $extractError
        }
    } catch [System.Management.Automation.Remoting.PSRemotingTransportException] {
        $msg = $_.Exception.Message
        if ($Transport -eq 'SSH' -and $msg -match '(?i)SSH transport process has abruptly terminated') {
            $msg += ' Hint: this commonly happens when the target is out of memory and the Linux OOM killer terminates pwsh. Check dmesg/journalctl for "Out of memory: Killed process" and consider adding swap (or increasing RAM) on the target.'
        }
        throw $msg
    } catch {
        throw
    } finally {
        if ($session -and $remoteBase) {
            try {
                Invoke-Command -Session $session -ArgumentList @($remoteBase) -ScriptBlock { param($p) Remove-Item -Path $p -Recurse -Force -ErrorAction SilentlyContinue } -ErrorAction Stop
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
        [Parameter()][hashtable]$SshTargetOptions,
        [Parameter()][ValidateSet('None','Ndjson')][string]$SiemFormat = 'None'
    )

    $results = New-Object System.Collections.Generic.List[object]

    $canParallel = $UseParallel.IsPresent -and ($PSVersionTable.PSVersion.Major -ge 7)

    # Normalize SSH options (avoid mutating caller hashtable and ensure clean strings for -Parallel serialization).
    $sshOptMap = @{}
    if ($SshTargetOptions) {
        foreach ($k in $SshTargetOptions.Keys) {
            $v = $SshTargetOptions[$k]
            $u = $null
            $p = $null

            if ($v -is [hashtable]) {
                if ($v.ContainsKey('UserName')) { $u = [string]$v['UserName'] }
                if ($v.ContainsKey('KeyFilePath')) { $p = [string]$v['KeyFilePath'] }
            } else {
                if ($v.PSObject.Properties.Name -contains 'UserName') { $u = [string]$v.UserName }
                if ($v.PSObject.Properties.Name -contains 'KeyFilePath') { $p = [string]$v.KeyFilePath }
            }

            if ($u) { $u = $u.Trim() }
            if ($p) { $p = $p.Trim().Trim('"').Trim("'") }

            if (($u -and $u.Trim()) -or ($p -and $p.Trim())) {
                $sshOptMap[[string]$k] = @{ UserName = $u; KeyFilePath = $p }
            }
        }
    }

    # Preflight: validate SSH prerequisites per-host (so CSV per-target creds can override command-level defaults).
    if ($HostNameTargets -and $HostNameTargets.Count -gt 0) {
        if ($SshKeyFilePath) { $SshKeyFilePath = $SshKeyFilePath.Trim().Trim('"').Trim("'") }

        if ($PSVersionTable.PSVersion.Major -lt 7) {
            foreach ($h in $HostNameTargets) {
                $results.Add([pscustomobject]@{
                        Computer = $h
                        Zip = $null
                        RunId = $RunId
                        SiemNdjson = $null
                        RunRoot = $null
                        Root = $null
                        Extracted = $false
                        ExtractError = $null
                        Error = 'SSH remoting requires PowerShell 7+ on the coordinator host'
                    })
            }
            $Targets = @($Targets | Where-Object { $HostNameTargets -notcontains $_ })
        } else {
            foreach ($h in $HostNameTargets) {
                $opt = if ($sshOptMap.ContainsKey($h)) { $sshOptMap[$h] } else { $null }

                $user = if ($opt -and $opt['UserName'] -and $opt['UserName'].Trim()) { $opt['UserName'].Trim() } else { $SshUserName }
                $key = if ($opt -and $opt['KeyFilePath'] -and $opt['KeyFilePath'].Trim()) { $opt['KeyFilePath'] } else { $SshKeyFilePath }

                # If the CSV provides an override key but it doesn't exist locally, fall back to command-level key if available.
                if ($opt -and $opt['KeyFilePath'] -and $opt['KeyFilePath'].Trim() -and (-not (Test-Path -LiteralPath $opt['KeyFilePath']))) {
                    if ($SshKeyFilePath -and (Test-Path -LiteralPath $SshKeyFilePath)) {
                        $sshOptMap[$h]['KeyFilePath'] = $null
                        $key = $SshKeyFilePath
                    }
                }

                if (-not $user -or -not $user.Trim()) {
                    $results.Add([pscustomobject]@{
                            Computer = $h
                            Zip = $null
                            RunId = $RunId
                            SiemNdjson = $null
                            RunRoot = $null
                            Root = $null
                            Extracted = $false
                            ExtractError = $null
                            Error = 'SSH remoting requires a username (provide -UserName or CSV UserName)'
                        })
                    $Targets = @($Targets | Where-Object { $_ -ne $h })
                    continue
                }

                if (-not $key -or -not $key.Trim()) {
                    $results.Add([pscustomobject]@{
                            Computer = $h
                            Zip = $null
                            RunId = $RunId
                            SiemNdjson = $null
                            RunRoot = $null
                            Root = $null
                            Extracted = $false
                            ExtractError = $null
                            Error = 'SSH remoting requires a key file path (provide -KeyFilePath or CSV KeyFilePath)'
                        })
                    $Targets = @($Targets | Where-Object { $_ -ne $h })
                    continue
                }

                if (-not (Test-Path -LiteralPath $key)) {
                    $results.Add([pscustomobject]@{
                            Computer = $h
                            Zip = $null
                            RunId = $RunId
                            SiemNdjson = $null
                            RunRoot = $null
                            Root = $null
                            Extracted = $false
                            ExtractError = $null
                            Error = "SSH key file not found: $key"
                        })
                    $Targets = @($Targets | Where-Object { $_ -ne $h })
                    continue
                }
            }
        }
    }

    if (-not $Targets -or $Targets.Count -eq 0) {
        return $results
    }

    if ($canParallel) {
        $parallelResults = $Targets | ForEach-Object -Parallel {
            $target = $_
            try {
                $mod = Import-Module (Join-Path $using:PSScriptRoot '..\Forensikit.psd1') -Force -PassThru
                $transport = if ($using:HostNameTargets -and ($using:HostNameTargets -contains $target)) { 'SSH' } else { 'WinRM' }

                $targetUser = $null
                $targetKey = $null
                $map = $using:sshOptMap
                if ($transport -eq 'SSH' -and $map -and $map.ContainsKey($target)) {
                    $o = $map[$target]
                    if ($o -and $o.ContainsKey('UserName')) { $targetUser = [string]$o['UserName'] }
                    if ($o -and $o.ContainsKey('KeyFilePath')) { $targetKey = [string]$o['KeyFilePath'] }
                }

                & $mod {
                    param(
                        $Target,
                        $Transport,
                        $CollectorConfig,
                        $OutputPath,
                        $CaseId,
                        $RunId,
                        [pscredential]$Credential,
                        $SshUserName,
                        $SshKeyFilePath,
                        $TargetSshUserName,
                        $TargetSshKeyFilePath,
                        $SiemFormat
                    )
                    Invoke-FSKRemoteSingle -Target $Target -Transport $Transport -CollectorConfig $CollectorConfig -OutputPath $OutputPath -CaseId $CaseId -RunId $RunId -Credential $Credential -SshUserName $SshUserName -SshKeyFilePath $SshKeyFilePath -TargetSshUserName $TargetSshUserName -TargetSshKeyFilePath $TargetSshKeyFilePath -SiemFormat $SiemFormat
                } $target $transport $using:CollectorConfig $using:OutputPath $using:CaseId $using:RunId $using:Credential $using:SshUserName $using:SshKeyFilePath $targetUser $targetKey $using:SiemFormat
            } catch {
                [pscustomobject]@{
                    Computer = $target
                    Zip = $null
                    RunId = $using:RunId
                    SiemNdjson = $null
                    RunRoot = $null
                    Root = $null
                    Extracted = $false
                    ExtractError = $null
                    Error = $_.Exception.Message
                }
            }
        } -ThrottleLimit $ThrottleLimit

        # Preserve any preflight error objects (e.g. SSH prerequisites) alongside parallel results.
        return @($results.ToArray()) + @($parallelResults)
    } else {
        foreach ($t in $Targets) {
            try {
                $transport = if ($HostNameTargets -and ($HostNameTargets -contains $t)) { 'SSH' } else { 'WinRM' }

                $targetUser = $null
                $targetKey = $null
                if ($transport -eq 'SSH' -and $sshOptMap -and $sshOptMap.ContainsKey($t)) {
                    $o = $sshOptMap[$t]
                    if ($o -and $o.ContainsKey('UserName')) { $targetUser = [string]$o['UserName'] }
                    if ($o -and $o.ContainsKey('KeyFilePath')) { $targetKey = [string]$o['KeyFilePath'] }
                }

                $results.Add((Invoke-FSKRemoteSingle -Target $t -Transport $transport -CollectorConfig $CollectorConfig -OutputPath $OutputPath -CaseId $CaseId -RunId $RunId -Credential $Credential -SshUserName $SshUserName -SshKeyFilePath $SshKeyFilePath -TargetSshUserName $targetUser -TargetSshKeyFilePath $targetKey -SiemFormat $SiemFormat))
            } catch {
                $results.Add([pscustomobject]@{
                        Computer = $t
                        Zip = $null
                        RunId = $RunId
                        SiemNdjson = $null
                        RunRoot = $null
                        Root = $null
                        Extracted = $false
                        ExtractError = $null
                        Error = $_.Exception.Message
                    })
            }
        }
        $results
    }
}
