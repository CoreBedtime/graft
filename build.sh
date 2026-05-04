#!/bin/bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

if [ ! -f "compile_commands.json" ]; then
    echo "[bear] compile_commands.json not found → generating"
    bear -- make -B "$@"
else
    echo "[bear] compile_commands.json exists → skipping bear"
    make -j8 "$@"
fi
