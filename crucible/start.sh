#!/bin/bash
# Render: runs uvicorn internally on 8000, streamlit publicly on $PORT
# Local: not used — run uvicorn and streamlit separately as before

set -e

# Refresh malware signatures when the deployment permits network access.
# Failure is non-fatal here: the malware stage will fail closed and the UI will
# report SCAN_FAILED rather than claiming the application is clean.
if command -v freshclam >/dev/null 2>&1; then
  timeout 60 freshclam --quiet || echo "[Startup] ClamAV signature refresh unavailable"
fi

# Probe scanner binaries before Streamlit starts accepting browser sessions.
python scanner_preload.py

# Both processes are critical. Exit the container when either one stops.
uvicorn main:app --host 0.0.0.0 --port 8000 &
api_pid=$!
streamlit run dashboard.py \
  --server.port "${PORT:-8501}" \
  --server.address 0.0.0.0 \
  --server.maxUploadSize "${STREAMLIT_SERVER_MAX_UPLOAD_SIZE:-200}" \
  --server.headless true &
dashboard_pid=$!

shutdown() {
  trap - EXIT INT TERM
  kill "$api_pid" "$dashboard_pid" 2>/dev/null || true
  wait "$api_pid" "$dashboard_pid" 2>/dev/null || true
}
trap shutdown EXIT INT TERM

wait -n "$api_pid" "$dashboard_pid"
