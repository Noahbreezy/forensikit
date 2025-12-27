function New-FSKZip {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$SourceFolder,

        [Parameter(Mandatory)]
        [string]$ZipPath
    )

    $zipDir = Split-Path -Path $ZipPath -Parent
    if (-not (Test-Path $zipDir)) { New-Item -Path $zipDir -ItemType Directory -Force | Out-Null }

    if (Test-Path $ZipPath) { Remove-Item -Path $ZipPath -Force }

    # Compress-Archive can be memory-heavy on Linux/macOS (and especially on low-RAM hosts).
    # Prefer a streaming implementation via python3 when available.
    if ($PSVersionTable.PSVersion.Major -ge 6 -and (-not $IsWindows)) {
        $py = Get-Command python3 -ErrorAction SilentlyContinue
        if ($py) {
            $src = (Resolve-Path -Path $SourceFolder).Path
            $dst = (Resolve-Path -Path (Split-Path -Path $ZipPath -Parent)).Path
            $zipAbs = Join-Path $dst (Split-Path -Path $ZipPath -Leaf)

            $code = @'
import os, sys, zipfile

src = sys.argv[1]
zip_path = sys.argv[2]

os.makedirs(os.path.dirname(zip_path), exist_ok=True)

# Use low compression level to reduce CPU/memory on small hosts.
try:
    zf = zipfile.ZipFile(zip_path, 'w', compression=zipfile.ZIP_DEFLATED, compresslevel=1)
except TypeError:
    # Older zipfile w/o compresslevel
    zf = zipfile.ZipFile(zip_path, 'w', compression=zipfile.ZIP_DEFLATED)

with zf:
    for root, dirs, files in os.walk(src):
        for name in files:
            full = os.path.join(root, name)
            rel = os.path.relpath(full, src)
            zf.write(full, rel)
'@

            & $py.Source -c $code $src $zipAbs
            return
        }
    }

    Compress-Archive -Path (Join-Path $SourceFolder '*') -DestinationPath $ZipPath -CompressionLevel Optimal
}
