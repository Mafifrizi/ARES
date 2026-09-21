#!/usr/bin/env bash
set -e

echo "=== ARES Setup ==="

# Check Python 3.10-3.12. The tested release path is Python 3.12.x.
python3 -c "import sys; assert (3,10) <= sys.version_info[:2] < (3,13), 'Python 3.10-3.12 required'" 2>/dev/null \
    || { echo "ERROR: Python 3.10-3.12 required"; exit 1; }
echo "[OK] Python $(python3 --version)"
python3 - <<'PY'
import sys

if sys.version_info[:2] != (3, 12):
    print("[!] Package metadata permits Python 3.10-3.12, but the tested")
    print("    release path for the dashboard and Windows AD/Impacket modules")
    print("    is Python 3.12.x")
else:
    print("[OK] Python 3.12.x detected for the tested release path")
PY

# Create virtual environment kalau belum ada
if [ ! -d ".venv" ]; then
    echo "[*] Creating virtual environment..."
    python3 -m venv .venv
fi

# Aktifkan venv
source .venv/bin/activate

# Upgrade pip
pip install --upgrade pip -q

# Install ARES + dev deps and PDF backend extras
echo "[*] Installing dependencies..."
pip install -e ".[dev,pdf]" -q

# Generate .env kalau belum ada
if [ ! -f ".env" ]; then
    echo "[*] Generating .env from .env.example..."
    cp .env.example .env
fi

if grep -q "CHANGE_ME" .env 2>/dev/null; then
    echo "[*] Replacing CHANGE_ME placeholders in .env with secure keys..."
    SECRET=$(python3 -c "import secrets; print(secrets.token_hex(32))")
    ENC=$(python3 -c "import secrets; print(secrets.token_urlsafe(32))")
    ARES_GENERATED_SECRET="$SECRET" ARES_GENERATED_ENC="$ENC" python3 - <<'PY'
import os
from pathlib import Path

updates = {
    "ARES_SECRET_KEY=": f"ARES_SECRET_KEY={os.environ['ARES_GENERATED_SECRET']}",
    "ARES_ENCRYPTION_KEY=": f"ARES_ENCRYPTION_KEY={os.environ['ARES_GENERATED_ENC']}",
}
env_path = Path(".env")
lines = env_path.read_text(encoding="utf-8").splitlines()
for index, line in enumerate(lines):
    if line.strip().startswith("ARES_BROWSER_ORIGIN=") and "example.invalid" in line:
        lines[index] = "ARES_BROWSER_ORIGIN="
    for prefix, value in updates.items():
        if line.strip().startswith(prefix) and ("CHANGE_ME" in line or line.strip() == prefix):
            lines[index] = value
            break
env_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
PY
    echo "[OK] Secure keys generated in .env"
fi

echo ""
echo "=== Setup complete ==="
echo ""
echo "Next steps:"
echo "  1. source .venv/bin/activate"
echo "  2. Edit .env and set ARES_DEFAULT_ADMIN_PASSWORD"
echo "  3. Run API:   ares-api"
echo "  4. Run tests: pytest tests/unit/ -v"
