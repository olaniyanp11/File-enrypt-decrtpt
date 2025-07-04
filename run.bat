@echo off
echo Starting server...
start cmd /k "npm start"
timeout /t 3 > nul
start http://localhost:3000