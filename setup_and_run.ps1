# ═══════════════════════════════════════════════════════════════════════════
# 3GPP Log Analyzer — Setup and Run Script (Windows PowerShell)
# ═══════════════════════════════════════════════════════════════════════════

Write-Host "`n=== 3GPP Log Analyzer Setup ===" -ForegroundColor Cyan

# Step 1: Check Python
try {
    $pyVersion = python --version 2>&1
    Write-Host "✓ Python: $pyVersion" -ForegroundColor Green
} catch {
    Write-Host "✗ Python not found. Install Python 3.10+ from https://python.org" -ForegroundColor Red
    exit 1
}

# Step 2: Create virtualenv if not exists
if (-not (Test-Path "venv")) {
    Write-Host "`nCreating virtual environment..." -ForegroundColor Yellow
    python -m venv venv
    Write-Host "✓ Virtual environment created" -ForegroundColor Green
}

# Step 3: Activate venv
Write-Host "`nActivating virtual environment..." -ForegroundColor Yellow
& ".\venv\Scripts\Activate.ps1"

# Step 4: Install dependencies
Write-Host "`nInstalling dependencies..." -ForegroundColor Yellow
pip install -r requirements.txt --quiet
Write-Host "✓ Dependencies installed" -ForegroundColor Green

# Step 5: Check/Create .env
if (-not (Test-Path ".env")) {
    Write-Host "`n⚠  .env not found — creating from template" -ForegroundColor Yellow
    Copy-Item ".env.example" ".env"
    Write-Host "✓ .env created. Please edit it and set GROQ_API_KEY" -ForegroundColor Yellow
    Write-Host "  Get your free API key at: https://console.groq.com" -ForegroundColor Cyan
    Write-Host ""
    $key = Read-Host "Enter your Groq API key now (or press Enter to skip)"
    if ($key) {
        (Get-Content .env) -replace "your_groq_api_key_here", $key | Set-Content .env
        Write-Host "✓ API key saved to .env" -ForegroundColor Green
    }
} else {
    Write-Host "✓ .env found" -ForegroundColor Green
}

# Step 6: Start app
Write-Host "`n=== Starting 3GPP Log Analyzer ===" -ForegroundColor Cyan
Write-Host "  URL: http://localhost:8000" -ForegroundColor White
Write-Host "  API: http://localhost:8000/docs" -ForegroundColor White
Write-Host "  Press Ctrl+C to stop`n" -ForegroundColor White

python run.py
