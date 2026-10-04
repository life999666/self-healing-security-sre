$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $MyInvocation.MyCommand.Path

if (-not (Test-Path "$Root\sentinel_service\.env")) { throw "Missing sentinel_service\.env" }
if (-not (Test-Path "$Root\sre_service\.env")) { throw "Missing sre_service\.env" }

Start-Process powershell -ArgumentList '-NoExit','-Command', "Set-Location '$Root\sre_service'; .\venv\Scripts\Activate.ps1; python security_service.py"
Start-Sleep -Seconds 2
Start-Process powershell -ArgumentList '-NoExit','-Command', "Set-Location '$Root\sentinel_service'; .\venv\Scripts\Activate.ps1; python start.py"

Write-Host "Started SRE remediation API and Sentinel in separate terminals."
Write-Host "Dashboard: http://127.0.0.1:8000"
Write-Host "Gateway:   http://127.0.0.1:8080"
Write-Host "SRE API:   http://127.0.0.1:8101/health"
