[CmdletBinding()]
param(
	[Parameter()]
	[ValidateNotNullOrEmpty()]
	[string]$SourceModulePath = (Join-Path -Path $PSScriptRoot -ChildPath 'src\Forensikit'),

	[Parameter()]
	[ValidateNotNullOrEmpty()]
	[string]$OutDir = (Join-Path -Path $PSScriptRoot -ChildPath 'release'),

	[Parameter()]
	[ValidateNotNullOrEmpty()]
	[string]$ModuleName = 'Forensikit',

	[Parameter()]
	[switch]$Force
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$sourceManifest = Join-Path $SourceModulePath "$ModuleName.psd1"
if (-not (Test-Path -Path $sourceManifest)) {
	throw "Module manifest not found: $sourceManifest"
}

$stageRoot = Join-Path $OutDir '_stage'
$stageModuleDir = Join-Path $stageRoot $ModuleName
$zipPath = Join-Path $OutDir "$ModuleName.zip"

New-Item -ItemType Directory -Force -Path $OutDir | Out-Null

if (Test-Path -Path $stageRoot) {
	Remove-Item -Recurse -Force -Path $stageRoot
}

if ((Test-Path -Path $zipPath) -and $Force) {
	Remove-Item -Force -Path $zipPath
}

New-Item -ItemType Directory -Force -Path $stageModuleDir | Out-Null

Copy-Item -Recurse -Force -Path (Join-Path $SourceModulePath '*') -Destination $stageModuleDir

# Validate manifest from staged copy (ensures the ZIP is self-contained).
Test-ModuleManifest -Path (Join-Path $stageModuleDir "$ModuleName.psd1") | Out-Null

# Recreate zip (even if it exists) so the artifact matches the staged module.
if (Test-Path -Path $zipPath) {
	Remove-Item -Force -Path $zipPath
}

Compress-Archive -Path (Join-Path $stageRoot $ModuleName) -DestinationPath $zipPath -Force

# Also leave an expanded copy next to the zip for easy inspection.
$expandedModuleDir = Join-Path $OutDir $ModuleName
if (Test-Path -Path $expandedModuleDir) {
	Remove-Item -Recurse -Force -Path $expandedModuleDir
}

Copy-Item -Recurse -Force -Path $stageModuleDir -Destination $expandedModuleDir
Remove-Item -Recurse -Force -Path $stageRoot

Write-Host "Created $zipPath"