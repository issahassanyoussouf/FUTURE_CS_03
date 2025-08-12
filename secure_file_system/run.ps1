# run.ps1 - lance le serveur via waitress
$venv = Join-Path $PSScriptRoot "venv\Scripts\Activate.ps1"

if (Test-Path $venv) {
    . $venv
} else {
    Write-Host "Activate script not found. Activate venv manually."
    exit 1
}

# Lancer waitress (écoute sur port 8080)
waitress-serve --listen=*:8080 app:app