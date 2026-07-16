@echo off
rem ============================================================
rem  ark - save everything that matters before you delete it
rem  Double-click this file to open the salvage control room.
rem ============================================================
cd /d "%~dp0"
title ark  -  salvage control  (port 8777)

rem --- find a Python interpreter -----------------------------
set "PY="
where python >nul 2>nul && set "PY=python"
if not defined PY where py >nul 2>nul && set "PY=py"
if not defined PY (
  echo.
  echo   Python 3 was not found on your PATH.
  echo   Install it from https://www.python.org/downloads/
  echo   and tick "Add python.exe to PATH" during setup.
  echo.
  pause
  exit /b 1
)

echo.
echo   ^&^   ark  -  before the flood
echo   ------------------------------------------
echo   Opening   http://127.0.0.1:8777
echo   Close this window to stop the server.
echo.

%PY% web.py
if errorlevel 1 (
  echo.
  echo   The server stopped. If it never started, port 8777
  echo   may already be in use ^(another ark window open?^).
  echo.
  pause
)
