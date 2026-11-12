"""AUDIT run-1 H11: `ares setup` must not print the generated admin password and
must write the secret-bearing .env with owner-only permissions."""

import os
import re
import stat
from pathlib import Path

import pytest

from ares.cli import typer_main


def _extract(env_text: str, key: str) -> str:
    m = re.search(rf"^{re.escape(key)}=(.*)$", env_text, flags=re.MULTILINE)
    return m.group(1).strip() if m else ""


def test_setup_does_not_print_password_and_restricts_env(tmp_path, capsys):
    typer_main._run_python_setup(root=tmp_path)

    env_path = tmp_path / ".env"
    assert env_path.exists()
    env_text = env_path.read_text(encoding="utf-8")

    admin_pw = _extract(env_text, "ARES_DEFAULT_ADMIN_PASSWORD")
    assert admin_pw, "a password should have been generated into .env"

    # The generated password must never reach stdout.
    out = capsys.readouterr().out
    # Sanity: console output IS captured (otherwise the assertions below are
    # vacuously true). The setup prints a banner and an .env confirmation.
    assert "ARES Setup" in out
    assert ".env" in out
    assert admin_pw not in out
    assert "Admin password:" not in out  # old literal-print banner is gone

    # Secret keys must also be absent from stdout.
    assert _extract(env_text, "ARES_SECRET_KEY") not in out
    assert _extract(env_text, "ARES_ENCRYPTION_KEY") not in out


@pytest.mark.skipif(os.name == "nt", reason="POSIX file mode bits")
def test_setup_env_is_owner_only_on_posix(tmp_path):
    typer_main._run_python_setup(root=tmp_path)
    env_path = tmp_path / ".env"
    mode = stat.S_IMODE(Path(env_path).stat().st_mode)
    # No group/other permission bits.
    assert mode & 0o077 == 0, oct(mode)
