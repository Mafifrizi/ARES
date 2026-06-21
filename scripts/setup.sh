#!/usr/bin/env bash
set -e

echo "=== ARES Setup ==="

# Cek Python 3.10+
python3 -c "import sys; assert sys.version_info >= (3,10), 'Python 3.10+ required'" 2>/dev/null \
    || { echo "ERROR: Python 3.10+ required"; exit 1; }
echo "[OK] Python $(python3 --version)"

# Buat venv kalau belum ada
if [ ! -d ".venv" ]; then
    echo "[*] Creating virtual environment..."
    python3 -m venv .venv
fi

# Aktifkan venv
source .venv/bin/activate

# Upgrade pip
pip install --upgrade pip -q

# Install ARES + dev deps
echo "[*] Installing dependencies..."
pip install -e ".[dev]" -q

# Generate .env kalau belum ada
if [ ! -f ".env" ]; then
    echo "[*] Generating .env from .env.example..."
    cp .env.example .env
    SECRET=$(python3 -c "import secrets; print(secrets.token_hex(32))")
    ENC=$(python3 -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())")
    sed -i "s|ARES_SECRET_KEY=CHANGE_ME.*|ARES_SECRET_KEY=$SECRET|" .env
    sed -i "s|ARES_ENCRYPTION_KEY=CHANGE_ME.*|ARES_ENCRYPTION_KEY=$ENC|" .env
    echo "[!] .env created — set ARES_DEFAULT_ADMIN_PASSWORD before starting"
fi

echo ""
echo "=== Setup complete ==="
echo ""
echo "Next steps:"
echo "  1. source .venv/bin/activate"
echo "  2. Edit .env and set ARES_DEFAULT_ADMIN_PASSWORD"
echo "  3. Run API:   ares-api"
echo "  4. Run tests: pytest tests/unit/ -v"
