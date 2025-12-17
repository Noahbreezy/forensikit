Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

Import-Module "$PSScriptRoot\src\Forensikit\Forensikit.psd1" -Force

# Pass-through wrapper for convenience
Invoke-ForensicCollector @PSBoundParameters
