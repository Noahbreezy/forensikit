Set-StrictMode -Version Latest

Describe 'Forensikit MVP' {
    BeforeAll {
        Import-Module "$PSScriptRoot\..\src\Forensikit\Forensikit.psd1" -Force
        $testRoot = Join-Path $env:TEMP ("ForensikitTests_" + [guid]::NewGuid().ToString())
        New-Item -Path $testRoot -ItemType Directory -Force | Out-Null
        $global:FSK_TestRoot = $testRoot
    }

    AfterAll {
        Remove-Item -Path $global:FSK_TestRoot -Recurse -Force -ErrorAction SilentlyContinue
        Remove-Variable -Name FSK_TestRoot -Scope Global -ErrorAction SilentlyContinue
    }

    It 'Creates a run folder structure' {
        InModuleScope Forensikit {
            $run = New-FSKRunFolder -OutputPath $global:FSK_TestRoot -ComputerName 'TESTHOST' -CaseId 'CASE1'
            Test-Path (Join-Path (Join-Path $run.Root 'volatile') 'processes') | Should -BeTrue
            Test-Path (Join-Path (Join-Path $run.Root 'persistent') 'eventlogs') | Should -BeTrue
            Test-Path (Join-Path (Join-Path $run.Root 'persistent') 'services') | Should -BeTrue
            Test-Path (Join-Path (Join-Path $run.Root 'persistent') 'registry') | Should -BeTrue
            Test-Path (Join-Path $run.Root 'siem') | Should -BeTrue
        }
    }

    It 'Deep profile contains extended collectors' {
        InModuleScope Forensikit {
            $fskConfig = Get-FSKConfig -Mode 'Deep'
            $fskConfig.Collectors | Should -Contain 'Services'
            $fskConfig.Collectors | Should -Contain 'ScheduledTasks'
            $fskConfig.Collectors | Should -Contain 'Registry'
            $fskConfig.Collectors | Should -Contain 'InstalledSoftware'
            $fskConfig.Collectors | Should -Contain 'DnsFirewall'
        }
    }

    It 'Services collector writes output' {
        InModuleScope Forensikit {
            $run = New-FSKRunFolder -OutputPath $global:FSK_TestRoot -ComputerName 'TESTSERV'
            $logger = New-FSKLogger -LogPath (Join-Path $run.Logs 'test.log')
            Invoke-FSKCollectServices -Run $run -Logger $logger
            Test-Path (Join-Path $run.Persistent 'services\services.csv') | Should -BeTrue
        }
    }

    It 'Writes integrity.csv with SHA256 hashes' {
        InModuleScope Forensikit {
            $run = New-FSKRunFolder -OutputPath $global:FSK_TestRoot -ComputerName 'TESTHOST2'
            $p = Join-Path (Join-Path (Join-Path $run.Root 'volatile') 'processes') 'x.txt'
            'abc' | Out-File -FilePath $p -Encoding utf8
            $integrity = Join-Path $run.Root 'integrity.csv'
            New-FSKIntegrityLog -RootPath $run.Root -IntegrityCsvPath $integrity
            (Test-Path $integrity) | Should -BeTrue
            @((Import-Csv $integrity)).Count | Should -BeGreaterThan 0
        }
    }

    It 'Creates a ZIP archive from a folder' {
        InModuleScope Forensikit {
            $run = New-FSKRunFolder -OutputPath $global:FSK_TestRoot -ComputerName 'TESTHOST3'
            $p = Join-Path (Join-Path (Join-Path $run.Root 'volatile') 'processes') 'x.txt'
            'abc' | Out-File -FilePath $p -Encoding utf8
            $zip = Join-Path $global:FSK_TestRoot 'out.zip'
            New-FSKZip -SourceFolder $run.Root -ZipPath $zip
            Test-Path $zip | Should -BeTrue
        }
    }

    It 'Scheduled tasks collector writes an error marker when Get-ScheduledTask is unavailable' {
        InModuleScope Forensikit {
            $run = New-FSKRunFolder -OutputPath $global:FSK_TestRoot -ComputerName 'TESTTASKS'
            $logger = New-FSKLogger -LogPath (Join-Path $run.Logs 'test.log')

            Mock -CommandName Get-FSKPlatform -MockWith { 'Windows' }
            Mock -CommandName Get-ScheduledTask -MockWith { throw "no access" }

            Invoke-FSKCollectScheduledTasks -Run $run -Logger $logger

            Test-Path (Join-Path (Join-Path $run.Persistent 'tasks') 'scheduled_tasks_error.txt') | Should -BeTrue
        }
    }

    It 'CSV fan-out routes Windows to WinRM and Linux/macOS to SSH' {
        InModuleScope Forensikit {
            $csvPath = Join-Path $global:FSK_TestRoot 'targets.csv'
            @(
                'ComputerName,HostName,OS,Transport',
                'PC01,,Windows,Auto',
                ',ubuntu01,Linux,Auto',
                ',macmini01,macOS,SSH'
            ) | Set-Content -Path $csvPath -Encoding UTF8

            $captured = $null
            Mock -CommandName Invoke-FSKRemoteFanout -MockWith {
                param(
                    $Targets,
                    $CollectorConfig,
                    $OutputPath,
                    $CaseId,
                    $RunId,
                    [pscredential]$RemoteCredential,
                    $ThrottleLimit,
                    $UseParallel,
                    $HostNameTargets,
                    $SshUserName,
                    $SshKeyFilePath,
                    $SiemFormat
                )
                $script:captured = [pscustomobject]@{
                    Targets = @($Targets)
                    HostNameTargets = @($HostNameTargets)
                    SshUserName = $SshUserName
                    SshKeyFilePath = $SshKeyFilePath
                    RunId = $RunId
                    SiemFormat = $SiemFormat
                }
                return @()
            }

            Invoke-ForensicCollector -Mode Quick -ComputerListCsv $csvPath -OutputPath $global:FSK_TestRoot -Confirm:$false -UserName 'ir' -KeyFilePath $csvPath

            $script:captured | Should -Not -BeNullOrEmpty
            $script:captured.Targets | Should -Contain 'PC01'
            $script:captured.Targets | Should -Contain 'ubuntu01'
            $script:captured.Targets | Should -Contain 'macmini01'
            $script:captured.HostNameTargets | Should -Contain 'ubuntu01'
            $script:captured.HostNameTargets | Should -Contain 'macmini01'
            $script:captured.HostNameTargets | Should -Not -Contain 'PC01'
        }
    }

    It 'Exports per-host SIEM NDJSON from collected CSVs' {
        InModuleScope Forensikit {
            $run = New-FSKRunFolder -OutputPath $global:FSK_TestRoot -ComputerName 'TESTSIEM'
            $logger = New-FSKLogger -LogPath (Join-Path $run.Logs 'test.log')
            $fskConfig = Get-FSKConfig -Mode 'Quick'

            # Create a small CSV to simulate collector output
            $csvPath = Join-Path (Join-Path $run.Volatile 'processes') 'tiny.csv'
            @(
                [pscustomobject]@{ A = '1'; B = 'x' },
                [pscustomobject]@{ A = '2'; B = 'y' }
            ) | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8

            $ndjsonPath = Export-FSKSiemNdjson -Run $run -Config $fskConfig -Logger $logger
            (Test-Path $ndjsonPath) | Should -BeTrue

            $lines = Get-Content -Path $ndjsonPath
            $lines.Count | Should -BeGreaterThan 1
            ($lines[0] | ConvertFrom-Json).eventType | Should -Be 'run_meta'
        }
    }

    It 'Merges per-host NDJSON files into a single merged NDJSON' {
        InModuleScope Forensikit {
            $stamp = (Get-Date).ToUniversalTime().ToString('yyyyMMdd_HHmmssZ')
            $runId = "MERGE_$stamp"

            $run1 = New-FSKRunFolder -OutputPath $global:FSK_TestRoot -ComputerName 'HOSTA' -RunId $runId
            $run2 = New-FSKRunFolder -OutputPath $global:FSK_TestRoot -ComputerName 'HOSTB' -RunId $runId

            $nd1 = Join-Path $run1.Root 'siem\events.ndjson'
            $nd2 = Join-Path $run2.Root 'siem\events.ndjson'

            '{"schema":"forensikit.siem.v1","eventType":"x","host":"HOSTA"}' | Set-Content -Path $nd1 -Encoding UTF8
            @(
                '{"schema":"forensikit.siem.v1","eventType":"y","host":"HOSTB"}',
                '{"schema":"forensikit.siem.v1","eventType":"z","host":"HOSTB"}'
            ) | Set-Content -Path $nd2 -Encoding UTF8

            $runFolder = Join-Path $global:FSK_TestRoot $runId
            $merged = Join-Path $runFolder 'siem\merged.ndjson'
            Merge-FSKSiemNdjson -RunFolder $runFolder -MergedNdjsonPath $merged | Out-Null

            (Test-Path $merged) | Should -BeTrue
            (Get-Content -Path $merged).Count | Should -Be 3
        }
    }
}
