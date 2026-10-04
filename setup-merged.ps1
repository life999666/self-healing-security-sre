$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $MyInvocation.MyCommand.Path

Write-Host "[1/2] Setting up Sentinel environment..."
Set-Location "$Root\sentinel_service"
if (-not (Test-Path "venv")) { python -m venv venv }
& ".\venv\Scripts\python.exe" -m pip install --upgrade pip
& ".\venv\Scripts\python.exe" -m pip install -r requirements.txt

Write-Host "[2/2] Setting up SRE environment..."
Set-Location "$Root\sre_service"
if (-not (Test-Path "venv")) { python -m venv venv }
& ".\venv\Scripts\python.exe" -m pip install --upgrade pip
& ".\venv\Scripts\python.exe" -m pip install -r requirements.txt

Write-Host "Setup complete. Configure both .env files before starting."
