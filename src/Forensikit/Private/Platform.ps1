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

function Test-FSKIsElevated {
    [CmdletBinding()]
    param()

    if ((Get-FSKPlatform) -ne 'Windows') { return $false }

    try {
        $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
        $principal = [Security.Principal.WindowsPrincipal]::new($identity)
        return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    } catch {
        return $false
    }
}
