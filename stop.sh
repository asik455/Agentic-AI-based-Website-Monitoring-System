#!/usr/bin/env bash
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

if [ -f "$DIR/logs/sentinel.pid" ]; then
  PID=$(cat "$DIR/logs/sentinel.pid")
  kill -9 "$PID" 2>/dev/null || true
  rm -f "$DIR/logs/sentinel.pid"
fi

pkill -9 -f "backend/server.py" 2>/dev/null || true

echo "🛑 Sentinel server stopped."
