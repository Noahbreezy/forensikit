function Invoke-FSKLocalCollection {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Profile,
        [Parameter(Mandatory)][string]$OutputPath,
        [Parameter()][string]$CaseId,
        [Parameter()][string]$RunId,
        [Parameter()][ValidateSet('None','Ndjson')][string]$SiemFormat = 'None'
    )

    $run = New-FSKRunFolder -OutputPath $OutputPath -ComputerName $env:COMPUTERNAME -CaseId $CaseId -RunId $RunId
    $logger = New-FSKLogger -LogPath (Join-Path $run.Logs 'collector.log')

    $meta = [ordered]@{
        Tool        = 'Forensikit'
        Version     = '0.1.0'
        Computer    = $env:COMPUTERNAME
        User        = $env:USERNAME
        Mode        = $Profile.Mode
        StartedUtc  = (Get-Date).ToUniversalTime().ToString('o')
        Collectors  = @($Profile.Collectors)
    }

    Write-FSKLog -Logger $logger -Level INFO -Message "Run started (Mode=$($Profile.Mode))"

    foreach ($collector in $Profile.Collectors) {
        switch ($collector) {
            'Processes' { Invoke-FSKCollectProcesses -Run $run -Logger $logger }
            'Network'   { Invoke-FSKCollectNetwork -Run $run -Logger $logger }
            'Users'     { Invoke-FSKCollectUsers -Run $run -Logger $logger }
            'EventLogs' { Invoke-FSKCollectEventLogs -Run $run -Logger $logger -Profile $Profile }
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

    $integrityPath = Join-Path $run.Root 'integrity.csv'
    New-FSKIntegrityLog -RootPath $run.Root -IntegrityCsvPath $integrityPath

    $siemPath = $null
    if ($SiemFormat -eq 'Ndjson') {
        $siemPath = Export-FSKSiemNdjson -Run $run -Config $Profile -Logger $logger -NdjsonPath (Join-Path $run.Root 'siem\\events.ndjson')
    }

    $zipPath = Join-Path (Split-Path $run.Root -Parent) ("$($env:COMPUTERNAME)_$($run.RunId).zip")
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
        [Parameter(Mandatory)]$Profile,
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

            $session = New-PSSession -HostName $Target -UserName $SshUserName -KeyFilePath $SshKeyFilePath -ErrorAction Stop
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
        $remoteModule = Join-Path $remoteBase 'Forensikit'
        Copy-Item -Path $localModule -Destination $remoteModule -ToSession $session -Recurse -Force

        $remoteResult = Invoke-Command -Session $session -ArgumentList @($remoteModule, $Profile, $remoteBase, $CaseId, $RunId, $SiemFormat) -ScriptBlock {
            param($remoteModule, $profile, $remoteBase, $caseId, $runId, $siemFormat)

            Import-Module (Join-Path $remoteModule 'Forensikit.psd1') -Force

            $out = Join-Path $remoteBase 'Output'
            Invoke-FSKLocalCollection -Profile $profile -OutputPath $out -CaseId $caseId -RunId $runId -SiemFormat $siemFormat
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
        [Parameter(Mandatory)]$Profile,
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
        } elseif (-not (Test-Path $SshKeyFilePath)) {
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
        $Targets | ForEach-Object -Parallel {
            try {
                Import-Module $using:PSScriptRoot\..\..\Forensikit.psd1 -Force
                $transport = if ($using:HostNameTargets -and ($using:HostNameTargets -contains $_)) { 'SSH' } else { 'WinRM' }
                Invoke-FSKRemoteSingle -Target $_ -Transport $transport -Profile $using:Profile -OutputPath $using:OutputPath -CaseId $using:CaseId -RunId $using:RunId -Credential $using:Credential -SshUserName $using:SshUserName -SshKeyFilePath $using:SshKeyFilePath -SiemFormat $using:SiemFormat
            } catch {
                [pscustomobject]@{ Computer = $_; Error = $_.Exception.Message }
            }
        } -ThrottleLimit $ThrottleLimit
    } else {
        foreach ($t in $Targets) {
            try {
                $transport = if ($HostNameTargets -and ($HostNameTargets -contains $t)) { 'SSH' } else { 'WinRM' }
                $results.Add((Invoke-FSKRemoteSingle -Target $t -Transport $transport -Profile $Profile -OutputPath $OutputPath -CaseId $CaseId -RunId $RunId -Credential $Credential -SshUserName $SshUserName -SshKeyFilePath $SshKeyFilePath -SiemFormat $SiemFormat))
            } catch {
                $results.Add([pscustomobject]@{ Computer = $t; Error = $_.Exception.Message })
            }
        }
        $results
    }
}
