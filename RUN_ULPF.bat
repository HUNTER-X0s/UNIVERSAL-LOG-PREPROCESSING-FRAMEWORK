@echo off
setlocal enabledelayedexpansion

title ULPF — Universal Log Pre-processing Framework Launcher

echo ===============================================================================
echo       UNIVERSAL LOG PRE-PROCESSING FRAMEWORK (ULPF) - SOVEREIGN SUITE
echo          National Security Telemetry Normalization ^& Intelligence
echo ===============================================================================
echo.

:: Ensure we are in the root project directory regardless of how script was invoked
cd /d "%~dp0"

echo [*] Working Directory: %CD%

:: Check for virtual environment
if not exist ".venv\Scripts\python.exe" (
    echo [ERROR] Virtual environment not found at .venv\Scripts\python.exe!
    echo Please make sure the Python virtual environment is installed.
    pause
    exit /b 1
)

:: Check for Node.js / npm
where npm >nul 2>nul
if %errorlevel% neq 0 (
    echo [ERROR] Node.js / npm was not found in PATH!
    echo Please install Node.js to run the web interface.
    pause
    exit /b 1
)

:: Define PYTHONPATH with all core packages and engines
set "ULPF_PYTHONPATH=apps/api;apps/worker;packages/contracts;packages/domain;packages/ingestion;packages/normalization;packages/parser-runtime;packages/platform;packages/semantic;packages/mapping;packages/onboarding;packages/ai;packages/runtime;packages/streaming;packages/storage;packages/search;packages/delivery;packages/observability;packages/security;packages/intelligence;packages/advanced_intelligence;packages/mission;packages/blockchain"

echo.
echo [1/3] Launching ULPF FastAPI Backend Engine (Port 8000)...
start "ULPF Backend Server [Port 8000]" cmd /k "title ULPF Backend Server [Port 8000] && cd /d "%~dp0" && set "PYTHONPATH=%ULPF_PYTHONPATH%" && .venv\Scripts\python.exe -m uvicorn ulpf_api.app:create_app --factory --host 0.0.0.0 --port 8000"

:: Wait 3 seconds for backend initialization
timeout /t 3 /nobreak >nul

echo [2/3] Launching ULPF Web Console Frontend (Port 5173)...
start "ULPF Frontend Web [Port 5173]" cmd /k "title ULPF Frontend Web [Port 5173] && cd /d "%~dp0apps\web" && npm run dev -- --port 5173"

:: Wait 3 seconds for Vite server to bind
timeout /t 3 /nobreak >nul

echo [3/3] Opening Web Operations Console in your default browser...
start http://localhost:5173

echo.
echo ===============================================================================
echo   SUCCESS: All ULPF Services are running!
echo ===============================================================================
echo   - Web Console:        http://localhost:5173
echo   - REST API Engine:    http://localhost:8000
echo   - API Documentation:  http://localhost:8000/api/v1/docs
echo   - Health Endpoint:    http://localhost:8000/api/v1/health
echo ===============================================================================
echo   To shut down both servers, you can close their respective windows
echo   or simply double-click STOP_ULPF.bat.
echo ===============================================================================
echo.
pause
