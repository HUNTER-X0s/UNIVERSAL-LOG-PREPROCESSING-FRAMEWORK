@echo off
setlocal enabledelayedexpansion

title ULPF — Stop Services

echo ===============================================================================
echo       STOPPING UNIVERSAL LOG PRE-PROCESSING FRAMEWORK (ULPF) SERVICES
echo ===============================================================================
echo.

:: Stop processes listening on port 8000 (Backend)
echo [*] Checking for ULPF Backend on port 8000...
for /f "tokens=5" %%a in ('netstat -aon ^| findstr ":8000" ^| findstr "LISTENING"') do (
    echo [*] Terminating Backend process PID %%a...
    taskkill /F /PID %%a >nul 2>nul
)

:: Stop processes listening on port 5173 (Frontend)
echo [*] Checking for ULPF Frontend on port 5173...
for /f "tokens=5" %%a in ('netstat -aon ^| findstr ":5173" ^| findstr "LISTENING"') do (
    echo [*] Terminating Frontend process PID %%a...
    taskkill /F /PID %%a >nul 2>nul
)

:: Stop processes listening on port 8080 (Alternative Vite port if active)
for /f "tokens=5" %%a in ('netstat -aon ^| findstr ":8080" ^| findstr "LISTENING"') do (
    echo [*] Terminating process on port 8080 PID %%a...
    taskkill /F /PID %%a >nul 2>nul
)

echo.
echo ===============================================================================
echo   All ULPF background servers have been stopped.
echo ===============================================================================
echo.
timeout /t 2 /nobreak >nul
exit /b 0
