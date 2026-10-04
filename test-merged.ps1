$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $MyInvocation.MyCommand.Path

Write-Host "Testing Sentinel..."
Set-Location "$Root\sentinel_service"
& ".\venv\Scripts\python.exe" -m pytest -q

Write-Host "Testing SRE..."
Set-Location "$Root\sre_service"
& ".\venv\Scripts\python.exe" -m pytest -q

Write-Host "Testing merged SQL source validator..."
& ".\venv\Scripts\python.exe" -c "from pathlib import Path; from security_tools import find_unsafe_sql; p=Path('../sentinel_service/kali_lab/unsafe_demo.py'); print(find_unsafe_sql(p.read_text(encoding='utf-8')))"
