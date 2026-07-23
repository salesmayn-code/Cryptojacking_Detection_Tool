param(
    [string]$PythonExe = "python",
    [string]$OutName = "xmrig"
)

$ErrorActionPreference = "Stop"

Write-Host "Building simulator exe with $PythonExe ..."

& $PythonExe -m pip show pyinstaller *> $null
if ($LASTEXITCODE -ne 0) {
    Write-Host "PyInstaller not found. Installing in current environment..."
    & $PythonExe -m pip install pyinstaller
}

& $PythonExe -m PyInstaller --onefile --name $OutName --clean --noconfirm .\miner_behavior_simulator.py

if ($LASTEXITCODE -ne 0) {
    throw "Build failed."
}

Write-Host "Build complete: $(Resolve-Path .\dist\$OutName.exe)"
