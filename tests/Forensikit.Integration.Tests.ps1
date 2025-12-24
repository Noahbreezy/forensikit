Set-StrictMode -Version Latest

# Integration tests: run real collectors on real systems.
# Disabled by default. Enable with:
#   $env:FSK_RUN_INTEGRATION='1'; Invoke-Pester -Path .\tests -Tag Integration
#
# Optional remote targets (comma-separated hostnames):
#   $env:FSK_INTEGRATION_TARGETS='PC01,PC02'
#   $env:FSK_INTEGRATION_TRANSPORT='WinRM'   # WinRM|SSH
#   $env:FSK_INTEGRATION_SSH_USER='ir'
#   $env:FSK_INTEGRATION_SSH_KEY='C:\\Users\\you\\.ssh\\id_ed25519'
#
# Notes:
# - These tests may require admin rights (e.g. Security event log, firewall).
# - They are best-effort: assertions focus on “outputs exist” rather than exact contents.

Describe 'Forensikit Integration' -Tag 'Integration' {
    BeforeAll {
        $script:RunIntegration = ($env:FSK_RUN_INTEGRATION -eq '1')

        function Get-FSKIntegrationModes {
            param(
                [Parameter(Mandatory)][string]$EnvVarName,
                [Parameter(Mandatory)][string[]]$Default
            )

            $raw = [Environment]::GetEnvironmentVariable($EnvVarName)
            if (-not $raw -or -not $raw.Trim()) {
                return @($Default)
            }

            $modes = @($raw -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ })
            return @($modes)
        }

        function Get-FSKIntegrationReportFormats {
            param(
                [Parameter(Mandatory)][string]$EnvVarName,
                [Parameter(Mandatory)][string]$Default
            )

            $raw = [Environment]::GetEnvironmentVariable($EnvVarName)
            if (-not $raw -or -not $raw.Trim()) { $raw = $Default }

            switch -Regex ($raw.Trim()) {
                '^(?i)both$' { return @('Markdown','Html') }
                '^(?i)markdown$' { return @('Markdown') }
                '^(?i)html$' { return @('Html') }
                default { return @('Markdown') }
            }
        }

        if ($script:RunIntegration) {
            Import-Module "$PSScriptRoot\..\src\Forensikit\Forensikit.psd1" -Force

            # Keep all real-run artifacts under the repo Output folder.
            # Structure: Output\integration\<timestamp>_<guid>\
            $repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
            $outRoot = Join-Path $repoRoot 'Output'
            if (-not (Test-Path $outRoot)) { New-Item -Path $outRoot -ItemType Directory -Force | Out-Null }

            $stamp = (Get-Date).ToUniversalTime().ToString('yyyyMMdd_HHmmssZ')
            $testRoot = Join-Path $outRoot (Join-Path 'integration' ("${stamp}_" + [guid]::NewGuid().ToString()))
            New-Item -Path $testRoot -ItemType Directory -Force | Out-Null
            $global:FSK_IntRoot = $testRoot

            # Default to keeping integration output (override by setting FSK_KEEP_INTEGRATION_OUTPUT=0)
            if (-not $env:FSK_KEEP_INTEGRATION_OUTPUT) { $env:FSK_KEEP_INTEGRATION_OUTPUT = '1' }

            # Mode selection
            # - Local defaults to Quick + Deep for broader coverage.
            # - Remote defaults to Quick (Deep can be enabled via FSK_INTEGRATION_REMOTE_MODES).
            $script:LocalModes = Get-FSKIntegrationModes -EnvVarName 'FSK_INTEGRATION_LOCAL_MODES' -Default @('Quick','Deep')
            $script:RemoteModes = Get-FSKIntegrationModes -EnvVarName 'FSK_INTEGRATION_REMOTE_MODES' -Default @('Quick')

            # Report format selection
            # Default: Markdown (HTML requires ConvertFrom-Markdown, usually PowerShell 7+)
            $script:ReportFormats = Get-FSKIntegrationReportFormats -EnvVarName 'FSK_INTEGRATION_REPORT_FORMAT' -Default 'Markdown'
        }
    }

    AfterAll {
        if ($global:FSK_IntRoot) {
            if ($script:RunIntegration) {
                foreach ($fmt in @($script:ReportFormats)) {
                    try {
                        $rootReport = Export-ForensikitReport -Path $global:FSK_IntRoot -Format $fmt
                        if ($rootReport) { Write-Host "Generated integration root report ($fmt): $rootReport" }
                    } catch {
                        if ($fmt -eq 'Html') {
                            Write-Warning 'Skipping HTML integration root report generation (ConvertFrom-Markdown not available in this session)'
                        } else {
                            throw
                        }
                    }
                }
            }

            if ($env:FSK_KEEP_INTEGRATION_OUTPUT -ne '0') {
                Write-Host "Keeping integration output at: $global:FSK_IntRoot"
            } else {
                Remove-Item -Path $global:FSK_IntRoot -Recurse -Force -ErrorAction SilentlyContinue
                Remove-Variable -Name FSK_IntRoot -Scope Global -ErrorAction SilentlyContinue
            }
        }
    }

    It 'Runs local collection(s) and produces zip + integrity' {
        if (-not $script:RunIntegration) {
            Set-ItResult -Skipped -Because 'Set $env:FSK_RUN_INTEGRATION=1 to enable integration tests.'
            return
        }

        foreach ($mode in @($script:LocalModes)) {
            $res = Invoke-ForensicCollector -Mode $mode -OutputPath $global:FSK_IntRoot -Confirm:$false -SiemFormat None
            $res | Should -Not -BeNullOrEmpty
            Test-Path $res.Root | Should -BeTrue
            Test-Path $res.Zip | Should -BeTrue
            Test-Path (Join-Path $res.Root 'integrity.csv') | Should -BeTrue
            Test-Path (Join-Path $res.Root 'logs\collector.log') | Should -BeTrue

            foreach ($fmt in @($script:ReportFormats)) {
                # Per-host human-readable report
                try {
                    $hostReport = Export-ForensikitReport -Path $res.Root -Format $fmt
                    Test-Path $hostReport | Should -BeTrue
                } catch {
                    if ($fmt -eq 'Html') {
                        Write-Warning 'Skipping HTML report generation (ConvertFrom-Markdown not available in this session)'
                    } else {
                        throw
                    }
                }

                # Run-level report (under the RunId folder)
                $runFolder = Join-Path $global:FSK_IntRoot $res.RunId
                try {
                    $runReport = Export-ForensikitReport -Path $runFolder -Format $fmt
                    Test-Path $runReport | Should -BeTrue
                } catch {
                    if ($fmt -eq 'Html') {
                        Write-Warning 'Skipping HTML run report generation (ConvertFrom-Markdown not available in this session)'
                    } else {
                        throw
                    }
                }
            }
        }
    }

    It 'Optionally runs remote fan-out against configured real targets' {
        if (-not $script:RunIntegration) {
            Set-ItResult -Skipped -Because 'Set $env:FSK_RUN_INTEGRATION=1 to enable integration tests.'
            return
        }

        if (-not $env:FSK_INTEGRATION_TARGETS) {
            Set-ItResult -Skipped -Because 'No remote targets configured (set $env:FSK_INTEGRATION_TARGETS)'
            return
        }

        $targets = @($env:FSK_INTEGRATION_TARGETS -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ })
        if ($targets.Count -lt 1) {
            Set-ItResult -Skipped -Because 'Empty remote targets list'
            return
        }

        $transport = if ($env:FSK_INTEGRATION_TRANSPORT) { $env:FSK_INTEGRATION_TRANSPORT } else { 'WinRM' }

        foreach ($mode in @($script:RemoteModes)) {
            $params = @{
                Mode = $mode
                OutputPath = $global:FSK_IntRoot
                ThrottleLimit = 8
                Confirm = $false
                SiemFormat = 'None'
            }

            if ($transport -match '^(?i)ssh$') {
                if ($PSVersionTable.PSVersion.Major -lt 7) {
                    $pwsh = Get-Command pwsh -ErrorAction SilentlyContinue
                    if (-not $pwsh) {
                        Set-ItResult -Skipped -Because 'SSH integration requires PowerShell 7+ (pwsh not found on PATH)'
                        return
                    }
                }
                $sshUser = $env:FSK_INTEGRATION_SSH_USER
                $sshKey = $env:FSK_INTEGRATION_SSH_KEY
                if ($sshKey) { $sshKey = $sshKey.Trim().Trim('"').Trim("'") }

                if (-not $sshUser -or -not $sshKey) {
                    Set-ItResult -Skipped -Because 'Set FSK_INTEGRATION_SSH_USER and FSK_INTEGRATION_SSH_KEY'
                    return
                }
                if (-not (Test-Path -LiteralPath $sshKey)) {
                    Set-ItResult -Skipped -Because 'SSH key file not found'
                    return
                }
                $params.HostName = $targets
                $params.UserName = $sshUser
                $params.KeyFilePath = $sshKey
            } else {
                $params.ComputerName = $targets
            }

            $results = Invoke-ForensicCollector @params
            $results | Should -Not -BeNullOrEmpty

            foreach ($r in @($results)) {
                if ($r.Error) { throw "Remote collection failed for $($r.Computer): $($r.Error)" }
                Test-Path $r.Zip | Should -BeTrue

                # Human-readable report: for remote runs we only have a ZIP, so extract it into
                # <OutputPath>\<RunId>\<Computer>\ and then generate report.md in that folder.
                $hostFolder = Join-Path (Join-Path $global:FSK_IntRoot $r.RunId) $r.Computer
                if (-not (Test-Path $hostFolder)) { New-Item -Path $hostFolder -ItemType Directory -Force | Out-Null }

                try {
                    Expand-Archive -Path $r.Zip -DestinationPath $hostFolder -Force
                } catch {
                    throw "Failed to expand ZIP for $($r.Computer): $($r.Zip)"
                }

                foreach ($fmt in @($script:ReportFormats)) {
                    try {
                        $hostReport = Export-ForensikitReport -Path $hostFolder -Format $fmt
                        Test-Path $hostReport | Should -BeTrue
                    } catch {
                        if ($fmt -eq 'Html') {
                            Write-Warning 'Skipping HTML host report generation (ConvertFrom-Markdown not available in this session)'
                        } else {
                            throw
                        }
                    }
                }
            }

            # Run-level report (under the RunId folder)
            $runFolder = Join-Path $global:FSK_IntRoot $results[0].RunId
            foreach ($fmt in @($script:ReportFormats)) {
                try {
                    $runReport = Export-ForensikitReport -Path $runFolder -Format $fmt
                    Test-Path $runReport | Should -BeTrue
                } catch {
                    if ($fmt -eq 'Html') {
                        Write-Warning 'Skipping HTML run report generation (ConvertFrom-Markdown not available in this session)'
                    } else {
                        throw
                    }
                }
            }
        }
    }
}
