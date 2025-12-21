Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

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
	[bool]$MergeSiem = $true
)

# Host selection policy:
# - SSH remoting requires PowerShell 7+.
# - WinRM works on both, but if invoked from pwsh and ComputerName is used, prefer Windows PowerShell 5.1.

$isPs7Plus = ($PSVersionTable.PSVersion.Major -ge 7)
$usingSsh = ($HostName -and $HostName.Count -gt 0) -or $KeyFilePath -or $UserName
$usingWinRm = ($ComputerName -and $ComputerName.Count -gt 0)

if (-not $env:FSK_REEXEC) {
	if ($usingSsh -and -not $isPs7Plus) {
		$pwsh = (Get-Command pwsh -ErrorAction SilentlyContinue).Source
		if (-not $pwsh) {
			throw 'SSH remoting requires PowerShell 7+ (pwsh). Install PowerShell 7 and ensure pwsh is on PATH.'
		}
		$env:FSK_REEXEC = '1'
		& $pwsh -NoProfile -ExecutionPolicy Bypass -File $PSCommandPath @PSBoundParameters
		exit $LASTEXITCODE
	}

	if ($usingWinRm -and $isPs7Plus -and $IsWindows) {
		$winPs = (Get-Command powershell.exe -ErrorAction SilentlyContinue).Source
		if ($winPs) {
			$env:FSK_REEXEC = '1'
			& $winPs -NoProfile -ExecutionPolicy Bypass -File $PSCommandPath @PSBoundParameters
			exit $LASTEXITCODE
		}
	}
}

Import-Module "$PSScriptRoot\src\Forensikit\Forensikit.psd1" -Force
Invoke-ForensicCollector @PSBoundParameters
