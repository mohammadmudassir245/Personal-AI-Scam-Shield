@echo off
title Personal AI Scam Shield
echo.
echo  ================================================
echo   PERSONAL AI SCAM SHIELD — Dev Launcher
echo  ================================================
echo.

:: ── Start Backend ──────────────────────────────────────────────
echo  [1/2] Starting FastAPI backend on http://localhost:8000 ...
start "Scam Shield — Backend" cmd /k "cd /d "%~dp0backend" && .venv\Scripts\python.exe -m uvicorn app.main:app --reload --port 8000"

:: Small delay so backend binds first
timeout /t 3 /nobreak >nul

:: ── Start Frontend ─────────────────────────────────────────────
echo  [2/2] Starting React frontend on http://localhost:5173 ...
start "Scam Shield — Frontend" cmd /k "cd /d "%~dp0frontend" && npm run dev"

echo.
echo  Both servers are starting. Open http://localhost:5173 in your browser.
echo  Close the two terminal windows to stop the servers.
echo.
pause
