#!/usr/bin/env bash
# One-time setup for Mac/Linux. Run with:  bash setup.sh
set -e
cd "$(dirname "$0")"
echo "[1/4] Checking Python..."
if ! command -v python3 >/dev/null 2>&1; then
  echo "Python 3 not found. Install it from https://www.python.org/downloads/ then re-run this script."; exit 1
fi
python3 --version
echo "[2/4] Creating private environment (.venv)..."
python3 -m venv .venv
echo "[3/4] Installing dependencies..."
.venv/bin/python -m pip install --quiet --upgrade pip
.venv/bin/python -m pip install --quiet -r requirements.txt
echo "[4/4] Running self-check..."
.venv/bin/python test_rating.py | tail -1
echo
echo "Setup complete. To run a report:"
echo "    bash run.sh example.com"
