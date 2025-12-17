@{
    RootModule        = 'Forensikit.psm1'
    ModuleVersion     = '0.1.0'
    GUID              = 'f5d2e232-9b0b-4cf7-a9d2-78e9b0b33b6a'
    Author            = 'Forensikit'
    CompanyName       = 'Forensikit'
    Copyright         = ''
    Description       = 'PowerShell-based evidence collection for incident response (Windows/Linux/macOS).'
    PowerShellVersion = '5.1'

    FunctionsToExport = @(
        'Invoke-ForensicCollector'
    )
    CmdletsToExport   = @()
    VariablesToExport = '*'
    AliasesToExport   = @()

    PrivateData = @{
        PSData = @{
            Tags       = @('forensics','incident-response','windows','linux','macos','evidence-collection')
            ProjectUri = ''
        }
    }
}
