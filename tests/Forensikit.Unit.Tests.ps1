Set-StrictMode -Version Latest

# Unit tests: deterministic, mock-heavy, safe to run anywhere.
# Run: Invoke-Pester -Path .\tests -Tag Unit

Describe 'Forensikit Unit' -Tag 'Unit' {
    BeforeAll {
        Import-Module "$PSScriptRoot\..\src\Forensikit\Forensikit.psd1" -Force
        $testRoot = Join-Path $env:TEMP ("ForensikitUnit_" + [guid]::NewGuid().ToString())
        New-Item -Path $testRoot -ItemType Directory -Force | Out-Null
        $global:FSK_UnitRoot = $testRoot
    }

    AfterAll {
        Remove-Item -Path $global:FSK_UnitRoot -Recurse -Force -ErrorAction SilentlyContinue
        Remove-Variable -Name FSK_UnitRoot -Scope Global -ErrorAction SilentlyContinue
    }

    Context 'Collectors (Windows paths) produce expected outputs' {
        BeforeEach {
            InModuleScope Forensikit {
                Mock -CommandName Write-Warning -MockWith { }
            }
        }

        It 'Processes collector writes processes.csv and WMI JSON (Windows)' {
            InModuleScope Forensikit {
                $run = New-FSKRunFolder -OutputPath $global:FSK_UnitRoot -ComputerName 'UNITPROC'
                $logger = New-FSKLogger -LogPath (Join-Path $run.Logs 'collector.log')

                Mock -CommandName Get-FSKPlatform -ModuleName Forensikit -MockWith { 'Windows' }
                Mock -CommandName Get-Process -ModuleName Forensikit -MockWith {
                    @([pscustomobject]@{ ProcessName='a'; Id=1 }, [pscustomobject]@{ ProcessName='b'; Id=2 })
                }
                Mock -CommandName Get-CimInstance -ModuleName Forensikit -MockWith {
                    @([pscustomobject]@{ ProcessId=1; Name='a'; ExecutablePath='x'; CommandLine='x'; CreationDate=''; ParentProcessId=0 })
                }

                Invoke-FSKCollectProcesses -Run $run -Logger $logger

                Should -Invoke -CommandName Get-Process -ModuleName Forensikit -Times 1
                Should -Invoke -CommandName Get-CimInstance -ModuleName Forensikit -Times 1

                Test-Path (Join-Path $run.Volatile 'processes\processes.csv') | Should -BeTrue
                Test-Path (Join-Path $run.Volatile 'processes\processes_wmi.json') | Should -BeTrue
            }
        }

        It 'Processes collector logs WARN if CIM fails but still writes CSV' {
            InModuleScope Forensikit {
                $run = New-FSKRunFolder -OutputPath $global:FSK_UnitRoot -ComputerName 'UNITPROCWARN'
                $logger = New-FSKLogger -LogPath (Join-Path $run.Logs 'collector.log')

                Mock -CommandName Get-FSKPlatform -ModuleName Forensikit -MockWith { 'Windows' }
                Mock -CommandName Get-Process -ModuleName Forensikit -MockWith { @([pscustomobject]@{ ProcessName='a'; Id=1 }) }
                Mock -CommandName Get-CimInstance -ModuleName Forensikit -MockWith { throw 'cim failed' }

                Invoke-FSKCollectProcesses -Run $run -Logger $logger

                Should -Invoke -CommandName Get-Process -ModuleName Forensikit -Times 1
                Should -Invoke -CommandName Get-CimInstance -ModuleName Forensikit -Times 1

                Test-Path (Join-Path $run.Volatile 'processes\processes.csv') | Should -BeTrue
                (Get-Content -Path $logger.Path -Raw -ErrorAction Stop) | Should -Match 'CIM Win32_Process collection failed'
            }
        }

        It 'Network collector writes baseline Windows command outputs' {
            InModuleScope Forensikit {
                $run = New-FSKRunFolder -OutputPath $global:FSK_UnitRoot -ComputerName 'UNITNET'
                $logger = New-FSKLogger -LogPath (Join-Path $run.Logs 'collector.log')

                Mock -CommandName Get-FSKPlatform -ModuleName Forensikit -MockWith { 'Windows' }
                Mock -CommandName Get-Command -ModuleName Forensikit -MockWith {
                    param($Name)
                    # Force fallback to netstat for TCP, but allow UDP cmdlet to exist
                    if ($Name -eq 'Get-NetTCPConnection') { return $null }
                    if ($Name -eq 'Get-NetUDPEndpoint') { return [pscustomobject]@{ Name='Get-NetUDPEndpoint' } }
                    return $null
                }
                Mock -CommandName Get-NetUDPEndpoint -ModuleName Forensikit -MockWith { @([pscustomobject]@{ LocalPort=53; OwningProcess=1 }) }

                Invoke-FSKCollectNetwork -Run $run -Logger $logger

                Test-Path (Join-Path $run.Volatile 'network\netstat_ano.txt') | Should -BeTrue
                Test-Path (Join-Path $run.Volatile 'network\net_udp_endpoints.csv') | Should -BeTrue
                Test-Path (Join-Path $run.Volatile 'network\ipconfig_all.txt') | Should -BeTrue
                Test-Path (Join-Path $run.Volatile 'network\route_print.txt') | Should -BeTrue
                Test-Path (Join-Path $run.Volatile 'network\arp_a.txt') | Should -BeTrue
                Test-Path (Join-Path $run.Volatile 'network\netstat_abno.txt') | Should -BeTrue
            }
        }

        It 'Users collector writes whoami_all and falls back to net user' {
            InModuleScope Forensikit {
                $run = New-FSKRunFolder -OutputPath $global:FSK_UnitRoot -ComputerName 'UNITUSERS'
                $logger = New-FSKLogger -LogPath (Join-Path $run.Logs 'collector.log')

                Mock -CommandName Get-FSKPlatform -ModuleName Forensikit -MockWith { 'Windows' }
                Mock -CommandName Get-Command -ModuleName Forensikit -MockWith {
                    param($Name)
                    # Simulate absence of LocalAccounts cmdlets
                    if ($Name -in @('Get-LocalUser','Get-LocalGroup','Get-LocalGroupMember')) { return $null }
                    return $null
                }

                Invoke-FSKCollectUsers -Run $run -Logger $logger

                Test-Path (Join-Path $run.Persistent 'users\whoami_all.txt') | Should -BeTrue
                Test-Path (Join-Path $run.Persistent 'users\net_user.txt') | Should -BeTrue
            }
        }

        It 'EventLogs collector writes CSV+JSON per log when Get-WinEvent works' {
            InModuleScope Forensikit {
                $run = New-FSKRunFolder -OutputPath $global:FSK_UnitRoot -ComputerName 'UNITEVT'
                $logger = New-FSKLogger -LogPath (Join-Path $run.Logs 'collector.log')
                $cfg = [pscustomobject]@{ Mode='Quick'; Collectors=@('EventLogs'); EventLogHours=1 }

                Mock -CommandName Get-FSKPlatform -ModuleName Forensikit -MockWith { 'Windows' }
                Mock -CommandName Test-FSKIsElevated -ModuleName Forensikit -MockWith { $true }
                Mock -CommandName Get-WinEvent -ModuleName Forensikit -MockWith {
                    @(
                        [pscustomobject]@{ TimeCreated=(Get-Date); Id=1; LevelDisplayName='Information'; ProviderName='X'; MachineName='M'; Message='Hi' }
                    )
                }

                Invoke-FSKCollectEventLogs -Run $run -Logger $logger -CollectorConfig $cfg

                foreach ($name in @('System','Security','Application')) {
                    Test-Path (Join-Path $run.Persistent ("eventlogs\\${name}_events.csv")) | Should -BeTrue
                    Test-Path (Join-Path $run.Persistent ("eventlogs\\${name}_events.json")) | Should -BeTrue
                }
            }
        }

        It 'EventLogs collector continues when a log fails (e.g. Security access denied)' {
            InModuleScope Forensikit {
                $run = New-FSKRunFolder -OutputPath $global:FSK_UnitRoot -ComputerName 'UNITEVTWARN'
                $logger = New-FSKLogger -LogPath (Join-Path $run.Logs 'collector.log')
                $cfg = [pscustomobject]@{ Mode='Quick'; Collectors=@('EventLogs'); EventLogHours=1 }

                Mock -CommandName Get-FSKPlatform -ModuleName Forensikit -MockWith { 'Windows' }

                Mock -CommandName Test-FSKIsElevated -ModuleName Forensikit -MockWith { $true }
                Mock -CommandName Get-WinEvent -ModuleName Forensikit -MockWith {
                    param($FilterHashtable)
                    if ($FilterHashtable.LogName -eq 'Security') { throw 'denied' }
                    @([pscustomobject]@{ TimeCreated=(Get-Date); Id=1; LevelDisplayName='Information'; ProviderName='X'; MachineName='M'; Message='Hi' })
                }

                Invoke-FSKCollectEventLogs -Run $run -Logger $logger -CollectorConfig $cfg

                # System & Application should exist
                Test-Path (Join-Path $run.Persistent 'eventlogs\System_events.csv') | Should -BeTrue
                Test-Path (Join-Path $run.Persistent 'eventlogs\Application_events.csv') | Should -BeTrue
                # Security may not exist
                (Get-Content -Path $logger.Path -Raw) | Should -Match 'Failed to collect event log: Security'
            }
        }

        It 'Services collector writes services.csv and attempts drivers.csv' {
            InModuleScope Forensikit {
                $run = New-FSKRunFolder -OutputPath $global:FSK_UnitRoot -ComputerName 'UNITSVC'
                $logger = New-FSKLogger -LogPath (Join-Path $run.Logs 'collector.log')

                Mock -CommandName Get-FSKPlatform -ModuleName Forensikit -MockWith { 'Windows' }
                Mock -CommandName Get-Service -ModuleName Forensikit -MockWith { @([pscustomobject]@{ Name='S'; DisplayName='S'; Status='Running'; StartType='Auto' }) }
                Mock -CommandName Get-CimInstance -ModuleName Forensikit -MockWith { @([pscustomobject]@{ Name='D'; DisplayName='D'; State='Running'; Status='OK'; StartMode='Auto'; PathName='x' }) }

                Invoke-FSKCollectServices -Run $run -Logger $logger

                Test-Path (Join-Path $run.Persistent 'services\services.csv') | Should -BeTrue
                Test-Path (Join-Path $run.Persistent 'services\drivers.csv') | Should -BeTrue
            }
        }

        It 'ScheduledTasks collector writes error marker if Get-ScheduledTask fails' {
            InModuleScope Forensikit {
                $run = New-FSKRunFolder -OutputPath $global:FSK_UnitRoot -ComputerName 'UNITTASKERR'
                $logger = New-FSKLogger -LogPath (Join-Path $run.Logs 'collector.log')

                Mock -CommandName Get-FSKPlatform -ModuleName Forensikit -MockWith { 'Windows' }
                Mock -CommandName Get-ScheduledTask -ModuleName Forensikit -MockWith { throw 'no access' }

                Invoke-FSKCollectScheduledTasks -Run $run -Logger $logger

                Test-Path (Join-Path $run.Persistent 'tasks\scheduled_tasks_error.txt') | Should -BeTrue
            }
        }

        It 'ScheduledTasks collector writes CSV+JSON when Get-ScheduledTask works' {
            InModuleScope Forensikit {
                $run = New-FSKRunFolder -OutputPath $global:FSK_UnitRoot -ComputerName 'UNITTASKOK'
                $logger = New-FSKLogger -LogPath (Join-Path $run.Logs 'collector.log')

                Mock -CommandName Get-FSKPlatform -ModuleName Forensikit -MockWith { 'Windows' }
                Mock -CommandName Get-ScheduledTask -ModuleName Forensikit -MockWith {
                    @(
                        [pscustomobject]@{
                            TaskName='T'; TaskPath='\\'; State='Ready'; Enabled=$true; Author='A'; Description='D';
                            Actions=@([pscustomobject]@{ Execute='cmd.exe'; Arguments='/c echo hi' });
                            Triggers=@('Daily')
                        }
                    )
                }

                Invoke-FSKCollectScheduledTasks -Run $run -Logger $logger

                Test-Path (Join-Path $run.Persistent 'tasks\scheduled_tasks.csv') | Should -BeTrue
                Test-Path (Join-Path $run.Persistent 'tasks\scheduled_tasks.json') | Should -BeTrue
            }
        }

        It 'Registry collector writes autoruns.csv (Windows)' {
            InModuleScope Forensikit {
                $run = New-FSKRunFolder -OutputPath $global:FSK_UnitRoot -ComputerName 'UNITREG'
                $logger = New-FSKLogger -LogPath (Join-Path $run.Logs 'collector.log')

                Mock -CommandName Get-FSKPlatform -ModuleName Forensikit -MockWith { 'Windows' }
                Mock -CommandName Test-Path -ModuleName Forensikit -MockWith { $true }
                Mock -CommandName Get-ItemProperty -ModuleName Forensikit -MockWith {
                    $o = [pscustomobject]@{ }
                    Add-Member -InputObject $o -NotePropertyName 'Good' -NotePropertyValue 'C:\\x.exe' -Force
                    $o
                }

                Invoke-FSKCollectRegistry -Run $run -Logger $logger

                Microsoft.PowerShell.Management\Test-Path (Join-Path $run.Persistent 'registry\\autoruns.csv') | Should -BeTrue
            }
        }

        It 'InstalledSoftware collector writes installed_software.csv (Windows)' {
            InModuleScope Forensikit {
                $run = New-FSKRunFolder -OutputPath $global:FSK_UnitRoot -ComputerName 'UNITSW'
                $logger = New-FSKLogger -LogPath (Join-Path $run.Logs 'collector.log')

                Mock -CommandName Get-FSKPlatform -ModuleName Forensikit -MockWith { 'Windows' }
                # Make registry walks return a couple of items
                Mock -CommandName Test-Path -ModuleName Forensikit -MockWith { $true }
                Mock -CommandName Get-ChildItem -ModuleName Forensikit -MockWith { @([pscustomobject]@{ PSPath='HKLM:\\x' }, [pscustomobject]@{ PSPath='HKLM:\\y' }) }
                Mock -CommandName Get-ItemProperty -ModuleName Forensikit -MockWith {
                    [pscustomobject]@{ DisplayName='App'; DisplayVersion='1'; Publisher='P'; InstallDate=''; UninstallString='u' }
                }

                Invoke-FSKCollectInstalledSoftware -Run $run -Logger $logger

                Microsoft.PowerShell.Management\Test-Path (Join-Path $run.Persistent 'software\\installed_software.csv') | Should -BeTrue
            }
        }

        It 'DnsFirewall collector writes dns_cache and firewall_rules (Windows)' {
            InModuleScope Forensikit {
                $run = New-FSKRunFolder -OutputPath $global:FSK_UnitRoot -ComputerName 'UNITDNSFW'
                $logger = New-FSKLogger -LogPath (Join-Path $run.Logs 'collector.log')

                Mock -CommandName Get-FSKPlatform -ModuleName Forensikit -MockWith { 'Windows' }
                Mock -CommandName Get-Command -ModuleName Forensikit -MockWith {
                    param($Name)
                    if ($Name -eq 'Get-NetFirewallRule') { return [pscustomobject]@{ Name='Get-NetFirewallRule' } }
                    return $null
                }
                Mock -CommandName Get-NetFirewallRule -ModuleName Forensikit -MockWith { @([pscustomobject]@{ Name='R'; DisplayName='R'; DisplayGroup='G'; Enabled=$true; Direction='In'; Action='Allow'; Profile='Any'; InterfaceType='Any'; Program=''; Service='' }) }

                Invoke-FSKCollectDnsFirewall -Run $run -Logger $logger

                Test-Path (Join-Path $run.Persistent 'network\dns_cache.txt') | Should -BeTrue
                Test-Path (Join-Path $run.Persistent 'network\firewall_rules.csv') | Should -BeTrue
            }
        }
    }

    Context 'Core utilities' {
        It 'Integrity log includes SHA256 and timestamps' {
            InModuleScope Forensikit {
                $run = New-FSKRunFolder -OutputPath $global:FSK_UnitRoot -ComputerName 'UNITINTEGRITY'
                $p = Join-Path (Join-Path $run.Volatile 'processes') 'x.txt'
                'abc' | Out-File -FilePath $p -Encoding utf8

                $integrity = Join-Path $run.Root 'integrity.csv'
                New-FSKIntegrityLog -RootPath $run.Root -IntegrityCsvPath $integrity

                $rows = @(Import-Csv -Path $integrity)
                $rows.Count | Should -BeGreaterThan 0
                $rows[0].Sha256 | Should -Match '^[0-9A-Fa-f]{64}$'
                    $rows[0].CollectedUtc | Should -Match '^\d{4}-\d{2}-\d{2}T'
            }
        }

        It 'ZIP creation produces a file' {
            InModuleScope Forensikit {
                $run = New-FSKRunFolder -OutputPath $global:FSK_UnitRoot -ComputerName 'UNITZIP'
                'abc' | Out-File -FilePath (Join-Path (Join-Path $run.Volatile 'processes') 'x.txt') -Encoding utf8
                $zip = Join-Path $global:FSK_UnitRoot 'unit_out.zip'
                New-FSKZip -SourceFolder $run.Root -ZipPath $zip
                Test-Path $zip | Should -BeTrue
            }
        }
    }

    Context 'Remote fan-out result shape' {
        It 'SSH preflight error objects include RunId' {
            InModuleScope Forensikit {
                $cfg = Get-FSKConfig -Mode 'Quick'

                $res = @(Invoke-FSKRemoteFanout -Targets @('ubuntu01') -CollectorConfig $cfg -OutputPath $global:FSK_UnitRoot -RunId 'UNIT_RUN_1' -HostNameTargets @('ubuntu01') -SshUserName '' -SshKeyFilePath '' -UseParallel:$false)

                $res.Count | Should -Be 1
                $res[0].Computer | Should -Be 'ubuntu01'
                $res[0].RunId | Should -Be 'UNIT_RUN_1'
                $res[0].Error | Should -Match 'username'
            }
        }

        It 'Sequential fan-out catch objects include RunId' {
            InModuleScope Forensikit {
                $cfg = Get-FSKConfig -Mode 'Quick'

                Mock -CommandName Invoke-FSKRemoteSingle -ModuleName Forensikit -MockWith {
                    param(
                        [string]$Target,
                        [string]$Transport,
                        $CollectorConfig,
                        [string]$OutputPath,
                        [string]$CaseId,
                        [string]$RunId,
                        [pscredential]$Credential,
                        [string]$SshUserName,
                        [string]$SshKeyFilePath,
                        [string]$TargetSshUserName,
                        [string]$TargetSshKeyFilePath,
                        [string]$SiemFormat
                    )

                    if ($Target -eq 'badhost') { throw 'boom' }

                    [pscustomobject]@{
                        Computer = $Target
                        Zip = 'z.zip'
                        RunId = $RunId
                        SiemNdjson = $null
                        RunRoot = 'rr'
                        Root = 'r'
                        Extracted = $true
                        ExtractError = $null
                    }
                }

                $res = @(Invoke-FSKRemoteFanout -Targets @('badhost','goodhost') -CollectorConfig $cfg -OutputPath $global:FSK_UnitRoot -RunId 'UNIT_RUN_2' -UseParallel:$false)
                $res.Count | Should -Be 2

                ($res | Where-Object { $_.Computer -eq 'badhost' }).RunId | Should -Be 'UNIT_RUN_2'
                ($res | Where-Object { $_.Computer -eq 'badhost' }).Error | Should -Match 'boom'

                $good = ($res | Where-Object { $_.Computer -eq 'goodhost' })
                $good.RunId | Should -Be 'UNIT_RUN_2'
                # Success objects do not have an Error property; avoid strict-mode property access.
                ($good.PSObject.Properties.Name -contains 'Error') | Should -BeFalse
            }
        }
    }
}
