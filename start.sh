#!/bin/bash
echo "========================================================"
echo " NetGuardian AI - System Startup"
echo " Detect. Defend. Recover. Automatically."
echo "========================================================"

echo "[1/2] Starting Flask Backend on http://127.0.0.1:5000 ..."
cd backend
if [ -d "venv" ]; then
    source venv/bin/activate
fi
python app.py &
BACKEND_PID=$!
cd ..

echo "[2/2] Starting Frontend HTTP Server on http://localhost:3000 ..."
node serve.js &
FRONTEND_PID=$!

echo "========================================================"
echo " Both services launched!"
echo " SOC Dashboard: http://localhost:3000"
echo " REST API:      http://127.0.0.1:5000/api/health"
echo " Press CTRL+C to stop both processes."
echo "========================================================"

trap "kill $BACKEND_PID $FRONTEND_PID" EXIT
wait
