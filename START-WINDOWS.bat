@echo off
cd /d "%~dp0"
where node >nul 2>nul
if errorlevel 1 (
  echo Install Node.js LTS from https://nodejs.org then run this file again.
  pause
  exit /b 1
)
echo Starting Sentinel. Open http://localhost:3000 in your browser.
echo Keep this window open while using the dashboard.
node server.mjs
pause
