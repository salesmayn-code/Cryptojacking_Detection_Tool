param(
    [string]$PythonExe = "python",
    [string]$OutName = "fake-pool"
)

$ErrorActionPreference = "Stop"

Write-Host "Building fake pool exe with $PythonExe ..."

& $PythonExe -m pip show pyinstaller *> $null
if ($LASTEXITCODE -ne 0) {
    Write-Host "PyInstaller not found. Installing in current environment..."
    & $PythonExe -m pip install pyinstaller
}

& $PythonExe -m PyInstaller --onefile --name $OutName --clean --noconfirm .\fake_pool_server.py

if ($LASTEXITCODE -ne 0) {
    throw "Build failed."
}

Write-Host "Build complete: $(Resolve-Path .\dist\$OutName.exe)"
