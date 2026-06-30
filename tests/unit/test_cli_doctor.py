from __future__ import annotations

import importlib.metadata
import sys
import types


def test_doctor_uses_distribution_metadata_for_impacket(monkeypatch, tmp_path, capsys):
    from ares.cli.typer_main import doctor

    fake_impacket = types.ModuleType("impacket")
    fake_paramiko = types.ModuleType("paramiko")
    fake_paramiko.__version__ = "3.4.0"

    def fake_version(package_name: str) -> str:
        if package_name == "impacket":
            return "0.13.1"
        raise importlib.metadata.PackageNotFoundError(package_name)

    monkeypatch.chdir(tmp_path)
    (tmp_path / ".env").write_text("ARES_SECRET_KEY=test\n", encoding="utf-8")
    monkeypatch.setattr(importlib.metadata, "version", fake_version)
    monkeypatch.setitem(sys.modules, "impacket", fake_impacket)
    monkeypatch.setitem(sys.modules, "paramiko", fake_paramiko)
    monkeypatch.setitem(sys.modules, "ldap3", None)

    doctor()

    output = capsys.readouterr().out
    assert "impacket 0.13.1" in output
    assert "too old (0.0.0)" not in output
    assert "ares-redteam[ad]" in output
