#!/usr/bin/env bash
set -e

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
mkdir -p "$DIR/logs"

# Stop existing instance if running
if [ -f "$DIR/logs/sentinel.pid" ]; then
  OLD_PID=$(cat "$DIR/logs/sentinel.pid")
  kill -9 "$OLD_PID" 2>/dev/null || true
  rm -f "$DIR/logs/sentinel.pid"
fi
pkill -9 -f "backend/server.py" 2>/dev/null || true
sleep 1

# Start server in background with nohup
nohup python3 "$DIR/backend/server.py" > "$DIR/logs/sentinel.log" 2>&1 &
SERVER_PID=$!
echo "$SERVER_PID" > "$DIR/logs/sentinel.pid"

echo "=================================================="
echo "✅ Sentinel server running via nohup (PID: $SERVER_PID)"
echo "   Local URL:  http://127.0.0.1:8000"
echo "   Public URL: http://52.207.250.243/"
echo "   Log File:   $DIR/logs/sentinel.log"
echo "=================================================="
