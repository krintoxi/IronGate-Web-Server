@echo off
rem Starts IronGate with its live dashboard. Port 80 if Windows allows it, otherwise 8080.
rem For a plain request log instead of the dashboard:  IronGate.exe --headless
cd /d "%~dp0"
title IronGate
IronGate.exe %*
if errorlevel 1 pause
