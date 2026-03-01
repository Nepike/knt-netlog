#!/usr/bin/bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

cd "$script_dir"

VENV_DIR="../virtualenv"


git reset --hard
git pull origin main

source $VENV_DIR/bin/activate
pip install -r requirements.txt
