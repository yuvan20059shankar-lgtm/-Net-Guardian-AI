@echo off
echo ========================================================
echo  NetGuardian AI - System Startup
echo  Detect. Defend. Recover. Automatically.
echo ========================================================

echo [1/2] Starting Flask Backend on http://127.0.0.1:5000 ...
cd backend
start "NetGuardian AI - Flask Backend" powershell -NoExit -Command ".\venv\Scripts\python.exe app.py"
cd ..

echo [2/2] Starting Frontend HTTP Server on http://localhost:3000 ...
start "NetGuardian AI - Frontend SOC" cmd /k "node serve.js"

echo ========================================================
echo  Both services launched!
echo  SOC Dashboard: http://localhost:3000
echo  REST API:      http://127.0.0.1:5000/api/health
echo ========================================================
