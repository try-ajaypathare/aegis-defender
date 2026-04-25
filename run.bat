@echo off
REM Aegis quick launcher for Windows
cd /d "%~dp0"

echo ============================================
echo  Aegis - Self-Healing Infrastructure Defender
echo ============================================
echo.

REM Optional venv. Skip silently if not present (system Python works fine).
if exist "venv\Scripts\activate.bat" (
    call venv\Scripts\activate.bat
)

echo Starting Aegis on:
echo   Defender Dashboard : http://127.0.0.1:8000
echo   Attack Console     : http://127.0.0.1:8001
echo.
echo Press Ctrl+C to stop.
echo.

python main.py

pause
