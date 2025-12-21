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

        if ($script:RunIntegration) {
            Import-Module "$PSScriptRoot\..\src\Forensikit\Forensikit.psd1" -Force

            $testRoot = Join-Path $env:TEMP ("ForensikitIntegration_" + [guid]::NewGuid().ToString())
            New-Item -Path $testRoot -ItemType Directory -Force | Out-Null
            $global:FSK_IntRoot = $testRoot
        }
    }

    AfterAll {
        if ($global:FSK_IntRoot) {
            Remove-Item -Path $global:FSK_IntRoot -Recurse -Force -ErrorAction SilentlyContinue
            Remove-Variable -Name FSK_IntRoot -Scope Global -ErrorAction SilentlyContinue
        }
    }

    It 'Runs a local Quick collection and produces zip + integrity' {
        if (-not $script:RunIntegration) {
            Set-ItResult -Skipped -Because 'Set $env:FSK_RUN_INTEGRATION=1 to enable integration tests.'
            return
        }

        $res = Invoke-ForensicCollector -Mode Quick -OutputPath $global:FSK_IntRoot -Confirm:$false -SiemFormat None
        $res | Should -Not -BeNullOrEmpty
        Test-Path $res.Root | Should -BeTrue
        Test-Path $res.Zip | Should -BeTrue
        Test-Path (Join-Path $res.Root 'integrity.csv') | Should -BeTrue
        Test-Path (Join-Path $res.Root 'logs\collector.log') | Should -BeTrue
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

        $params = @{
            Mode = 'Quick'
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
            if (-not $env:FSK_INTEGRATION_SSH_USER -or -not $env:FSK_INTEGRATION_SSH_KEY) {
                Set-ItResult -Skipped -Because 'Set FSK_INTEGRATION_SSH_USER and FSK_INTEGRATION_SSH_KEY'
                return
            }
            if (-not (Test-Path $env:FSK_INTEGRATION_SSH_KEY)) {
                Set-ItResult -Skipped -Because 'SSH key file not found'
                return
            }
            $params.HostName = $targets
            $params.UserName = $env:FSK_INTEGRATION_SSH_USER
            $params.KeyFilePath = $env:FSK_INTEGRATION_SSH_KEY
        } else {
            $params.ComputerName = $targets
        }

        $results = Invoke-ForensicCollector @params
        $results | Should -Not -BeNullOrEmpty

        foreach ($r in @($results)) {
            if ($r.Error) { throw "Remote collection failed for $($r.Computer): $($r.Error)" }
            Test-Path $r.Zip | Should -BeTrue
        }
    }
}
