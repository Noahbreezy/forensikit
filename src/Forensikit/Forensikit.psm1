Set-StrictMode -Version Latest

$script:ModuleRoot = $PSScriptRoot

. "$script:ModuleRoot\Private\Logging.ps1"
. "$script:ModuleRoot\Private\Platform.ps1"
. "$script:ModuleRoot\Private\Profiles.ps1"
. "$script:ModuleRoot\Private\Filesystem.ps1"
. "$script:ModuleRoot\Private\Integrity.ps1"
. "$script:ModuleRoot\Private\Compression.ps1"
. "$script:ModuleRoot\Private\SIEM.ps1"
. "$script:ModuleRoot\Private\Remoting.ps1"
. "$script:ModuleRoot\Private\Schedules.ps1"

. "$script:ModuleRoot\Private\Collectors\Processes.ps1"
. "$script:ModuleRoot\Private\Collectors\Network.ps1"
. "$script:ModuleRoot\Private\Collectors\Users.ps1"
. "$script:ModuleRoot\Private\Collectors\EventLogs.ps1"
. "$script:ModuleRoot\Private\Collectors\Services.ps1"
. "$script:ModuleRoot\Private\Collectors\Tasks.ps1"
. "$script:ModuleRoot\Private\Collectors\Registry.ps1"
. "$script:ModuleRoot\Private\Collectors\InstalledSoftware.ps1"
. "$script:ModuleRoot\Private\Collectors\DnsFirewall.ps1"

. "$script:ModuleRoot\Public\Invoke-ForensicCollector.ps1"
. "$script:ModuleRoot\Public\New-ForensikitCustomProfile.ps1"
. "$script:ModuleRoot\Public\Register-ForensikitSchedule.ps1"
. "$script:ModuleRoot\Public\Unregister-ForensikitSchedule.ps1"
