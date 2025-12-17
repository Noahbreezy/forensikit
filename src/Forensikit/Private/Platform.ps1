function Get-FSKPlatform {
    [CmdletBinding()]
    param()

    # Windows PowerShell 5.1 is Windows-only.
    if ($PSVersionTable.PSVersion.Major -lt 6) {
        return 'Windows'
    }

    if ($IsWindows) { return 'Windows' }
    if ($IsLinux) { return 'Linux' }
    if ($IsMacOS) { return 'macOS' }

    return 'Unknown'
}
