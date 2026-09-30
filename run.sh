#!/usr/bin/env bash
# Run the tool without activating anything:  bash run.sh example.com [options]
set -e
set -o pipefail
cd "$(dirname "$0")"
if [ ! -x .venv/bin/python ]; then echo "Run 'bash setup.sh' first."; exit 1; fi
exec .venv/bin/python pivot.py "$@"
