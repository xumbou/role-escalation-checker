#!/usr/bin/env bash
# Installe bacscan sur Kali Linux / Debian (et derives).
# Strategie : pipx si dispo (isole, recommande sur Kali), sinon venv local.
set -euo pipefail
cd "$(dirname "$0")"

echo "[bacscan] installation..."

if command -v pipx >/dev/null 2>&1; then
    pipx install --force .
    echo "[bacscan] installe via pipx. Lance :  bacscan --help"
    exit 0
fi

echo "[bacscan] pipx absent. Conseil Kali : sudo apt install -y pipx  (puis relance ce script)."
echo "[bacscan] repli sur un environnement virtuel local (.venv)..."
python3 -m venv .venv
# shellcheck source=/dev/null
. .venv/bin/activate
pip install -U pip >/dev/null
pip install .
echo "[bacscan] installe dans .venv."
echo "[bacscan] Lance :  . .venv/bin/activate && bacscan --help"
