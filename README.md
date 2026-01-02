# Forensikit (MVP)

PowerShell-based evidence collection for incident response.

## Requirements
- Windows, Linux, or macOS.
- PowerShell 7+ recommended. Windows PowerShell 5.1 is supported on Windows only.
- For WinRM remoting (Windows targets): WinRM/PowerShell Remoting enabled and reachable from the coordinator host.
- For SSH remoting (Linux/macOS targets, PowerShell 7+): SSH reachable and key-based auth configured.
- To read Security Event Log on Windows, run elevated or with an account that has log read rights.

Coordinator host note:
- Forensikit works best when run from PowerShell 7+ (pwsh), including for WinRM.
- If your environment requires coordinating WinRM from Windows PowerShell 5.1, you can opt in by setting:
	- `$env:FSK_PREFER_WINPS_FOR_WINRM = '1'`
	- This only applies to WinRM-only runs (no SSH targets) and is ignored for mixed SSH+WinRM.
	- This does not enable PowerShell 7+ features like `-UseParallel`.

## Built-in help
```powershell
Get-Help Invoke-ForensicCollector -Full
Get-Help about_Forensikit
```

## Quick start (dev from repo)

```powershell
# From repo root
Import-Module .\src\Forensikit\Forensikit.psd1 -Force
Invoke-ForensicCollector -Mode Quick -OutputPath .\Output -Verbose
```

## Quick start (from release ZIP)

The project deliverable is a single PowerShell module folder packaged as a ZIP.
After extracting `Forensikit.zip`, you should have a `Forensikit\` folder containing `Forensikit.psd1` and `Forensikit.psm1`.

Option A: import directly from the extracted folder (no install required):

```powershell
# From the folder where you extracted the ZIP
Import-Module .\Forensikit\Forensikit.psd1 -Force
Invoke-ForensicCollector -Mode Quick -OutputPath .\Output -Verbose
```

Option B: install for the current user (adds it to your module path):

```powershell
$moduleName = 'Forensikit'

if ($IsWindows) {
	$destRoot = Join-Path $HOME 'Documents\PowerShell\Modules'
} else {
	$destRoot = Join-Path $HOME '.local/share/powershell/Modules'
}

$dest = Join-Path $destRoot $moduleName
New-Item -ItemType Directory -Force -Path $destRoot | Out-Null

# Assuming the extracted folder contains .\Forensikit\...
Copy-Item -Recurse -Force .\Forensikit $dest

Import-Module Forensikit -Force
Invoke-ForensicCollector -Mode Quick -OutputPath .\Output -Verbose
```

## Release (ZIP for submission)

Build a clean module-only ZIP under `release\`:

```powershell
pwsh -NoProfile -ExecutionPolicy Bypass -File .\Build-Release.ps1
```

This produces:
- `release\Forensikit.zip` (submission artifact)
- `release\Forensikit\` (expanded module folder used to create the ZIP)

## Modes
- Quick: processes, network, users, event logs (last 24h).
- Full: processes, network, users, event logs (last 7 days).
- Deep: Quick/Full plus services, drivers, scheduled tasks, autoruns, installed software, DNS cache, firewall rules (event logs last 14 days).
- Custom: provide your own JSON profile.

## Remote collection (PowerShell Remoting)

```powershell
Import-Module .\src\Forensikit\Forensikit.psd1 -Force
Invoke-ForensicCollector -Mode Quick -ComputerName PC01,PC02 -OutputPath .\Output -Verbose
```

## Network-wide (CSV)

CSV can contain mixed OS targets. Supported columns:
- `ComputerName` (WinRM target; typically Windows)
- `HostName` (SSH target; typically Linux/macOS)
- `OS` (Windows | Linux | macOS | Auto)
- `Transport` (WinRM | SSH | Auto)

Optional SSH per-target overrides:
- `UserName` (SSH username override; empty string means no override)
- `KeyFilePath` (SSH private key path override; empty string means no override)

SSH credential precedence and fallback:
1) If a CSV row specifies `UserName` and/or `KeyFilePath`, Forensikit attempts those first.
2) If that attempt fails and you also provided `-UserName` and `-KeyFilePath` on the command, it retries once using the command-level values.
3) If the CSV override fields are empty/missing, Forensikit uses the command-level `-UserName`/`-KeyFilePath` (existing behavior).

Example file: [examples/targets.csv](examples/targets.csv)

```powershell
Import-Module .\src\Forensikit\Forensikit.psd1 -Force
Invoke-ForensicCollector -Mode Quick -ComputerListCsv .\computers.csv -OutputPath .\Output -ThrottleLimit 16 -Verbose
```

Mixed OS fan-out example (PowerShell 7+ required if the CSV includes SSH targets):

```powershell
Import-Module .\src\Forensikit\Forensikit.psd1 -Force
Invoke-ForensicCollector -Mode Deep -ComputerListCsv .\examples\targets.csv -OutputPath .\Output -ThrottleLimit 16 -UserName ir -KeyFilePath $HOME\.ssh\id_ed25519 -Verbose
```

## Remote collection over SSH (PowerShell 7+)

Use this for Linux/macOS (or any host reachable via SSH with PowerShell installed).

```powershell
Import-Module .\src\Forensikit\Forensikit.psd1 -Force
Invoke-ForensicCollector -Mode Deep -HostName ubuntu01 -UserName ir -KeyFilePath $HOME\.ssh\id_ed25519 -OutputPath .\Output -Verbose
```

Notes:
- The `FSK_INTEGRATION_*` environment variables are used by the Pester **integration tests**. For real collections, call `Invoke-ForensicCollector` directly (as shown above).
- For remote runs, Forensikit always downloads a ZIP per target. The module also extracts that ZIP into `Output\<RunId>\<Host>\...` so `Export-ForensikitReport` can be run against the extracted folder.

## Custom profile
Example file: [examples/custom_profile.json](examples/custom_profile.json)

```json
{
	"Collectors": ["Processes", "Network", "Users", "EventLogs"],
	"EventLogHours": 48
}
```

Run with:
```powershell
Invoke-ForensicCollector -Mode Custom -CustomProfilePath .\examples\custom_profile.json -OutputPath .\Output
```

## Scheduling / periodic runs

Forensikit can be run periodically using a schedule that points at a **custom profile JSON**.
This keeps scheduling explicit and avoids ambiguity about "defaults" changing over time.

### 1) Create a custom profile from a built-in mode

If you want "default" Quick/Full/Deep settings but also want scheduling, generate a custom profile file:

```powershell
Import-Module .\src\Forensikit\Forensikit.psd1 -Force

# Create a custom profile equivalent to -Mode Deep
New-ForensikitCustomProfile -Mode Deep -Path .\deep_profile.json
```

You can edit the JSON afterward (e.g., change collector list or event log window).

### 2) Register the periodic schedule

Register a schedule that runs the profile on an interval:

```powershell
Import-Module .\src\Forensikit\Forensikit.psd1 -Force

$params = @{
	Name = 'deepEvery6h'
	CustomProfilePath = '.\deep_profile.json'
	Every = (New-TimeSpan -Hours 6)
	OutputPath = '.\Output'
	CopyProfile = $true
	SiemFormat = 'None'
}
Register-ForensikitSchedule @params
```

Weekly example (every Sunday at 23:59):

```powershell
$params = @{
	Name = 'weeklySunday'
	CustomProfilePath = '.\deep_profile.json'
	DaysOfWeek = 'Sunday'
	At = (New-TimeSpan -Hours 23 -Minutes 59)
	OutputPath = '.\Output'
	CopyProfile = $true
}
Register-ForensikitSchedule @params
```

Monthly example (every 15th day at 12:00):

```powershell
$params = @{
	Name = 'monthly15th'
	CustomProfilePath = '.\deep_profile.json'
	DaysOfMonth = 15
	AtMonthly = (New-TimeSpan -Hours 12)
	OutputPath = '.\Output'
	CopyProfile = $true
}
Register-ForensikitSchedule @params
```

Notes:
- `-CopyProfile` makes the schedule self-contained by copying the profile into the schedule folder.
- On Windows, you can add `-RunElevated` if required for artifacts like Security Event Log.
- The schedule uses a generated `run.ps1` wrapper (stored under a per-schedule folder) that imports Forensikit and calls `Invoke-ForensicCollector -Mode Custom`.

### Platform behavior

- Windows: registers a Scheduled Task named `Forensikit-<Name>`.
- Linux: writes a systemd **user** `.service` + `.timer` under `~/.config/systemd/user/`.
	- Optionally add `-Install` to attempt `systemctl --user enable --now ...`.
- macOS: writes a LaunchAgent plist under `~/Library/LaunchAgents/`.
	- Optionally add `-Install` to attempt `launchctl load -w ...`.

### Unregister

```powershell
Unregister-ForensikitSchedule -Name deepEvery6h
```

## Output

Each run creates:
- `integrity.csv` (SHA256 per file)
- optional SIEM output: `siem\events.ndjson` per host and `siem\merged.ndjson` per run
- a ZIP archive of the collected folder

Example layout:
```
Output\20251215_224654Z\MERCURY\
	volatile\processes\processes.csv, processes_wmi.json
	volatile\network\net_tcp_connections.csv, net_udp_endpoints.csv, ipconfig_all.txt, route_print.txt, arp_a.txt, netstat_abno.txt
	persistent\users\whoami_all.txt, local_users.csv, local_groups.csv, local_group_members.csv
	persistent\eventlogs\System_events.csv/json, Application_events.csv/json, Security_events.csv/json (if permitted)
	persistent\services\services.csv, drivers.csv
	persistent\tasks\scheduled_tasks.csv/json
	persistent\registry\autoruns.csv
	persistent\software\installed_software.csv
	persistent\network\dns_cache.txt, firewall_rules.csv
	logs\collector.log
	run.json
	integrity.csv
	siem\events.ndjson
Output\20251215_224654Z\MERCURY_20251215_224654Z.zip

```

Pester test runs can emit an NUnit-style XML report for CI consumption. To keep these artifacts untracked, write them under `artifacts\test-results\`:

`pwsh -NoProfile -ExecutionPolicy Bypass -Command "Import-Module Pester -RequiredVersion 5.7.1 -Force; New-Item -ItemType Directory -Force -Path .\artifacts\test-results | Out-Null; $config = New-PesterConfiguration; $config.Run.Path = '.\tests'; $config.Output.Verbosity = 'Detailed'; $config.TestResult.Enabled = $true; $config.TestResult.OutputFormat = 'NUnitXml'; $config.TestResult.OutputPath = '.\artifacts\test-results\testResults.xml'; Invoke-Pester -Configuration $config"`

If SIEM output is enabled for a multi-host run, a merged file is also produced:
```
Output\20251215_224654Z\siem\merged.ndjson
```

## Human-readable report

Forensikit can generate a Markdown (or HTML) report from existing output folders.

Markdown (works on all supported PowerShell versions):

```powershell
Import-Module .\src\Forensikit\Forensikit.psd1 -Force

# Run folder (contains one or more host folders)
Export-ForensikitReport -Path .\Output\20251215_224654Z

# Or per-host folder
Export-ForensikitReport -Path .\Output\20251215_224654Z\MERCURY
```

HTML (PowerShell 7+ recommended):

```powershell
Export-ForensikitReport -Path .\Output\20251215_224654Z -Format Html
```

Remote run note:
- If you ran a remote collection, point `Export-ForensikitReport` at the extracted host folder (e.g. `Output\<RunId>\<Host>`). If you only have the ZIP, extract it into a host folder first.

Integration root summary (multiple runs):

If you point `Export-ForensikitReport` at an integration test root folder (e.g. `Output\integration\<timestamp>_<guid>`), it produces a **summary-only** report across all run folders and hosts under that root:

```powershell
Export-ForensikitReport -Path .\Output\integration\20251224_174424Z_05fcec0a-feef-4737-b9ec-785da53c3249
Export-ForensikitReport -Path .\Output\integration\20251224_174424Z_05fcec0a-feef-4737-b9ec-785da53c3249 -Format Html
```

## Parameters (high level)
- `-Mode`: Quick | Full | Deep | Custom
- `-OutputPath`: base output directory (run subfolders are created under this)
- `-CaseId`: optional prefix to tag run/zip names
- `-ComputerName`: WinRM remoting targets
- `-HostName`: SSH remoting targets (PowerShell 7+)
- `-UserName`: SSH user name (PowerShell 7+)
- `-KeyFilePath`: SSH private key path (PowerShell 7+)
- `-ComputerListCsv`: CSV with `ComputerName` (WinRM) and/or `HostName` (SSH); optional per-target SSH `UserName`/`KeyFilePath` overrides
- `-Credential`: credentials for remoting
- `-ThrottleLimit`: max concurrency (applies to remote fan-out)
- `-CustomProfilePath`: JSON profile for Custom mode
- `-UseParallel`: enable PowerShell 7+ parallel fan-out
- `-SiemFormat`: None | Ndjson (writes NDJSON/JSONL under each host folder)
- `-MergeSiem`: when using `-SiemFormat Ndjson` on **multi-target** runs, also writes `siem\merged.ndjson` under the run folder (default: enabled; disable with `-MergeSiem:$false`)

## SIEM output (NDJSON/JSONL)

Enable NDJSON/JSONL output for ingestion pipelines:

```powershell
Invoke-ForensicCollector -Mode Quick -ComputerListCsv .\examples\targets.csv -OutputPath .\Output -UseParallel -ThrottleLimit 16 -SiemFormat Ndjson
```

What gets written:
- Per host: `siem\events.ndjson` (JSON Lines / NDJSON)
	- `run_meta` event (run metadata)
	- `record` events for each row in collected `*.csv` files
	- `artifact` events from `integrity.csv` (SHA256 inventory)
- Per run (multi-target): `siem\merged.ndjson` (concatenation of all per-host `events.ndjson`)

## Cross-platform notes

- The output folder structure is consistent across OSes, but some collectors are platform-specific.
	- Windows: `EventLogs` uses Windows Event Logs; `Registry` collects autoruns from HKLM/HKCU.
	- Linux: `EventLogs` uses `journalctl` when available and/or common files in `/var/log`; `Registry` collects common persistence locations (systemd units, shell startup, etc.).
	- macOS: `EventLogs` uses `log show` when available; `Services` uses `launchctl`.
- Some artifacts require elevated rights on all OSes; failures are logged and the run continues.

## Collector support matrix (Windows vs Linux)

Forensikit aims for broad cross-platform coverage, but some collectors are inherently OS-specific.
On Linux, several collectors provide a best-effort *equivalent* rather than a 1:1 match to Windows artifacts.

| Collector | Windows output (high level) | Linux output (high level) | Notes / parity |
|---|---|---|---|
| Processes | `Get-Process` + extra detail via `Win32_Process` (CIM) | `Get-Process` + best-effort `ps` listing | Parity is good; Linux process details depend on permissions/tools. |
| Network | `Get-NetTCPConnection` / `Get-NetUDPEndpoint` + `ipconfig/route/arp/netstat` | `ss` or `netstat` + `ip addr/route/neigh` (or `ifconfig`) | Socket ownership/process mapping may be partial on Linux without root/caps. |
| Users | `whoami /all`, local users/groups, group membership | `whoami`, `id`, `/etc/passwd`, `/etc/group`, `getent` | Different data sources; generally comparable coverage. |
| EventLogs | Windows Event Logs via `Get-WinEvent` (System/Security/Application) | `journalctl` when available + common `/var/log/*` files | Not 1:1. Linux access often depends on `adm`/root and distro logging. |
| Services | `Get-Service` + drivers via `Win32_SystemDriver` | `systemctl` listings + `lsmod` (when available) | “Drivers” on Linux are kernel modules; not a direct match. |
| ScheduledTasks | `Get-ScheduledTask` (flattened CSV/JSON) | `crontab`, `/etc/cron.*`, and `systemctl list-timers` | Equivalent concepts; not 1:1. Some system locations require root. |
| Registry | Autoruns from HKLM/HKCU Run/RunOnce keys | Common persistence locations (systemd units, shell startup files, etc.) | Equivalent *persistence* view; there is no registry on Linux. |
| InstalledSoftware | Uninstall registry keys (HKLM/HKCU) | `dpkg-query` and/or `rpm`, plus `snap`/`flatpak` when present | Different package managers; coverage varies by distro. |
| DnsFirewall | DNS cache via `ipconfig /displaydns` + firewall rules via `Get-NetFirewallRule` | `/etc/resolv.conf` + `/etc/hosts` + firewall via `ufw`/`firewalld`/`nft`/`iptables` | Linux DNS cache is not standardized; this is a config snapshot, not a cache equivalent. |

## Authentication & secrets

### WinRM (Windows targets: `-ComputerName` / CSV `ComputerName`)

- Uses `New-PSSession -ComputerName` under the hood.
- Authentication is handled by WinRM/PowerShell Remoting (commonly Kerberos in a domain, or NTLM depending on environment).
- You can:
	- omit `-Credential` to use your current logon token, or
	- pass a `PSCredential` (prompted or retrieved from a secure store).

Recommended ways to supply credentials:
- Interactive: `-Credential (Get-Credential)`
- Automation: use a secret store (PowerShell SecretManagement, Windows Credential Manager, or your CI/CD secret store).

Avoid:
- storing passwords in CSV files or in the repository
- hardcoding passwords in scripts

### SSH (Linux/macOS targets: `-HostName` / CSV `HostName`, PowerShell 7+)

- Uses PowerShell SSH remoting: `New-PSSession -HostName -UserName -KeyFilePath`.
- Authentication is SSH key-based.

CSV override note:
- For network-wide runs via `-ComputerListCsv`, you may optionally include per-target `UserName` and/or `KeyFilePath` columns.
- If present, Forensikit tries per-target values first, then falls back to the command-level `-UserName/-KeyFilePath` if provided.

Recommended key handling:
- Store private keys in your user profile (e.g. `~/.ssh/`) and keep them out of the repo.
- Prefer passphrase-protected keys.
- Use an agent where available:
	- Windows: OpenSSH Authentication Agent (or equivalent)
	- Linux/macOS: `ssh-agent`

Avoid:
- placing private keys in `examples/` or committing them to git
- world-readable key files (ensure file permissions restrict access to your user)

## Permissions matrix

This matrix is a practical guide; exact requirements vary by org policy, OS hardening, and EDR controls. The tool will continue on access failures and record warnings in `collector.log`.

| Feature / Collector | Windows (local) | Linux (local) | macOS (local) | Remote prerequisites |
|---|---|---|---|---|
| Run + write output | Write access to `-OutputPath` | Write access to `-OutputPath` | Write access to `-OutputPath` | Same, plus remoting connectivity |
| Processes | Usually works as standard user; full details may need admin | `ps` works as user; some details may need root | `ps` works as user; some details may need sudo | Same permissions on target account |
| Network | Basic network info works as user; socket ownership/details may need admin | `ss -p` / process ownership may need root/caps; otherwise partial | Similar to Linux; some details may need sudo | Same permissions on target account |
| Users / groups | Standard user sees own token; local account/group enumeration may require admin depending on policy | `/etc/passwd`/`getent` usually readable; directory/privileged sources may differ | Similar to Linux | Same permissions on target account |
| Event logs / system logs | System/Application often OK; Security log typically needs admin or Event Log Readers rights | `journalctl`/`/var/log/*` may require `adm` group or root | `log show` may require sudo for some subsystems | Same permissions on target account |
| Services / drivers | `Get-Service` usually OK; driver/CIM queries may need admin depending on WMI perms | `systemctl` listing often OK; deeper details may need root; `lsmod` may need root | `launchctl` visibility may be limited without sudo | Same permissions on target account |
| Scheduled tasks / cron | `Get-ScheduledTask` can be restricted; some tasks require admin to enumerate fully | `crontab -l` reads current user; system cron dirs/timers may need root | Similar; launchd visibility can be limited | Same permissions on target account |
| Persistence / autoruns | HKCU run keys: user; HKLM run keys: may require admin in hardened setups | Reading `/etc/*` and system unit dirs may require root | Similar (system locations may require sudo) | Same permissions on target account |
| Installed software | Uninstall registry keys often readable; may be restricted by policy | `dpkg-query`/`rpm -qa` usually OK as user | `/Applications` list usually OK; `brew` is per-user | Same permissions on target account |
| DNS + firewall | DNS cache/firewall rules may require admin depending on cmdlets/policy | firewall rules (`iptables`/`nft`) often requires root; resolv.conf/hosts usually readable | similar; may require sudo | Same permissions on target account |
| WinRM remoting | Local: rights to create WinRM session; Target: WinRM enabled, firewall allows, user allowed for remoting | N/A | N/A | Kerberos/NTLM via WinRM; optional `-Credential` |
| SSH remoting | N/A | Local: PowerShell 7+; Target: SSH reachable and `pwsh` installed; user can SSH | Same as Linux | Key-based auth via `-UserName/-KeyFilePath` |

## Remoting notes
- Ensure WinRM is enabled: `Enable-PSRemoting -Force` (run as admin on targets).
- Test connectivity: `Test-WSMan <ComputerName>`.
- Module is copied to remote temp, run executed there, ZIP pulled back.
- If Security log fails, collection continues and a warning is logged.

SSH remoting notes (PowerShell 7+):
- Ensure SSH is reachable and PowerShell is installed on the target (`pwsh`).
- First-time SSH connections may require accepting the target's host key. If the host key isn't trusted yet, a non-interactive run can fail until you accept it.
	- One-time setup: `ssh <user>@<host>` and accept the prompt.
	- Optional (less strict): set `FSK_SSH_ACCEPT_NEW_HOSTKEY=1` to auto-accept new host keys (uses `StrictHostKeyChecking=accept-new` when available).
- PowerShell remoting over SSH uses the PowerShell **SSH subsystem**. Ensure the target SSH server is configured with a `powershell` subsystem entry (OpenSSH `Subsystem` directive).
	- On Ubuntu, add (or verify) a line like the following in **`/etc/ssh/sshd_config`** *or* a higher-precedence drop-in under **`/etc/ssh/sshd_config.d/*.conf`**:
		- `Subsystem powershell /usr/bin/pwsh -sshs -NoLogo -NoProfile`
	- Example `sshd_config` excerpt (Ubuntu) showing the PowerShell subsystem alongside common defaults:

		```text
		Include /etc/ssh/sshd_config.d/*.conf

		KbdInteractiveAuthentication no
		UsePAM yes

		X11Forwarding yes
		PrintMotd no

		AcceptEnv LANG LC_* COLORTERM NO_COLOR

		# Allow client to pass locale and color environment variables
		# override default of no subsystems
		Subsystem       sftp    /usr/lib/openssh/sftp-server
		Subsystem powershell /usr/bin/pwsh -sshs -NoLogo -NoProfile
		```

	- Notes:
		- `KbdInteractiveAuthentication no` is fine if you do not rely on keyboard-interactive auth (for example some MFA/2FA setups use it).
		- Consider setting `X11Forwarding no` unless you explicitly need X11 forwarding.
		- The path to `pwsh` must be correct for your system (`command -v pwsh`).
		- Only one effective `Subsystem powershell ...` should be active (drop-in snippets can override the main file).
	- Validate and restart:
		- `sudo sshd -t` (syntax check)
		- `sudo systemctl restart ssh` (or `sudo systemctl restart sshd` depending on the distro)

- Privilege behavior (Linux/macOS over SSH): Forensikit will try `sudo -n` (non-interactive) to run the collection as root when possible to maximize artifact coverage.
  If `sudo -n` is not permitted (not in sudoers, or password required), it automatically falls back to running as the SSH user.

## Testing

The test suite is split into:
- **Unit** tests (mock-heavy, safe by default)
- **Integration** tests (opt-in; may touch the real system and/or real remote hosts)

```powershell
# Requires Pester 5+
Install-Module Pester -Scope CurrentUser -Force -SkipPublisherCheck

# Run everything (integration tests are skipped unless enabled)
Invoke-Pester -Path .\tests -Output Detailed

# Run only unit tests
Invoke-Pester -Path .\tests -Tag Unit -Output Detailed

# Run integration tests (opt-in)
$env:FSK_RUN_INTEGRATION = '1'
Invoke-Pester -Path .\tests -Tag Integration -Output Detailed
```

Optional remote integration (fan-out) environment variables:
- `FSK_INTEGRATION_TARGETS` (comma-separated list, e.g. `host1,host2`)
- `FSK_INTEGRATION_TRANSPORT` (`WinRM` or `SSH`)
- `FSK_INTEGRATION_SSH_USER` (for SSH)
- `FSK_INTEGRATION_SSH_KEY` (for SSH; path to private key file)

Additional integration toggles:
- `FSK_INTEGRATION_LOCAL_MODES` (comma-separated list; defaults to `Quick,Deep`)
- `FSK_INTEGRATION_REMOTE_MODES` (comma-separated list; defaults to `Quick`)
- `FSK_INTEGRATION_REPORT_FORMAT` (`Markdown`, `Html`, or `Both`; defaults to `Markdown`)
- `FSK_KEEP_INTEGRATION_OUTPUT` (`1` keep, `0` delete; defaults to `1`)

Integration artifacts are written under `Output\integration\<timestamp>_<guid>\`.

When `FSK_INTEGRATION_REPORT_FORMAT` includes Markdown and/or HTML, integration tests also generate an integration-root summary report:
- `Output\integration\<timestamp>_<guid>\report.md`
- `Output\integration\<timestamp>_<guid>\report.html`

## Rubric justification (project notes)

### Analyse (SWOT)

- Strengths: Automates tedious forensic work. Reduces errors. Open-source and modifiable.
- Weaknesses: PowerShell is limited in cross-platform support for advanced operations.
- Opportunities: Growing demand for lightweight IR tooling. Design allows for commercial expansion.
- Threats: Possibly too complex to properly expand. Restrictive policies may render the tool less effective.

### Design

Uses PowerShell core commands + optional external tools (Sysinternals, 7-Zip, AWS CLI) orchestrated from a single interface. Architecture is modular: Collection, Compression, Logging, Upload (future).

### Kennisverwerving

Demonstrates understanding of PowerShell scripting, WMI/CIM, file hashing, REST APIs, and cloud storage integration concepts.

### Usability

Simple syntax (`Invoke-ForensicCollector`) with parameters for mode and output path. Structured output plus a `collector.log` and `run.json` summary.

### Robust

Parameter validation, try/catch error handling, and a log file. Integrity verification via SHA256 hashes in `integrity.csv`.

### Uitbreidbaarheid

Collectors live in `src/Forensikit/Private/Collectors/` and are invoked by name; adding a new collector is isolated to a new file + profile inclusion.

### Best Practices / Structuur

Verb-Noun naming, module layout (Public/Private), comment-based help, and structured output folders.

### Testing

Pester tests validate key behaviors (folder creation, integrity log, compression).

## References

This project was primarily built using personal knowledge and AI tools, and verified against official documentation.

### Microsoft Learn / PowerShell

- PowerShell Remoting overview (WinRM): https://learn.microsoft.com/powershell/scripting/learn/remoting/overview?view=powershell-7.4
- PowerShell Remoting over SSH (SSH subsystem): https://learn.microsoft.com/powershell/scripting/learn/remoting/ssh-remoting-in-powershell?view=powershell-7.4
- about_Remote (remoting fundamentals): https://learn.microsoft.com/powershell/module/microsoft.powershell.core/about/about_remote?view=powershell-7.4
- New-PSSession (WinRM/SSH session creation): https://learn.microsoft.com/powershell/module/microsoft.powershell.core/new-pssession?view=powershell-7.4
- Enable-PSRemoting: https://learn.microsoft.com/powershell/module/microsoft.powershell.core/enable-psremoting?view=powershell-5.1
- Get-WinEvent: https://learn.microsoft.com/powershell/module/microsoft.powershell.diagnostics/get-winevent?view=powershell-7.4

### Microsoft Learn / Pester

- Pester module docs: https://learn.microsoft.com/powershell/module/pester/?view=pester-5.7

### Scheduling references (per OS)

- Windows Scheduled Tasks (Register-ScheduledTask): https://learn.microsoft.com/powershell/module/scheduledtasks/register-scheduledtask
- systemd unit files (.service): https://www.freedesktop.org/software/systemd/man/systemd.service.html
- systemd timers (.timer): https://www.freedesktop.org/software/systemd/man/systemd.timer.html
- launchd (LaunchAgents) property list format: https://www.manpagez.com/man/5/launchd.plist/
- OpenSSH sshd_config (Subsystem directive): https://man.openbsd.org/sshd_config
