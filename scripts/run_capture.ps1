# Start only the capture daemon on Windows (run this PowerShell as Administrator).
# Requires Npcap (https://npcap.com). The API/dashboard can run in a normal shell: python run.py
param([Parameter(Mandatory = $true)][string]$Interface)
$Root = Split-Path -Parent $PSScriptRoot
$Python = Join-Path $Root ".venv\Scripts\python.exe"
if (-not (Test-Path $Python)) { $Python = "python" }
Set-Location $Root
& $Python run.py capture --interface $Interface
