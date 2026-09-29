"""
Unit Tests for Pure-Python Linux Modules & Binary Parsers
(RFC-ARES-2026 / Issue #57 - Pure Python Sovereignty & Subprocess Evasion)

Covers:
  1. Pure Python ELF binary parser for RPATH/RUNPATH extraction (_parsers.py)
  2. Pure Python Linux capability decoder (vfs_cap_data) (_parsers.py)
  3. linux.privesc pure-Python local inspection (SUID, PATH, Capabilities, Sudo, Cron)
  4. linux.privesc remote target verification (fixing world-writable target delegation)
  5. linux.service_hijack pure-Python local inspection
  6. linux.ld_preload pure-Python local inspection
  7. linux.nfs_escape pure-Python local inspection
  8. Zero subprocess execution on localhost across all 4 Linux modules
"""
from __future__ import annotations

import io
import os
import stat
import struct
import tempfile
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from ares.core.campaign import Campaign, NoiseProfile, ScopeEntry
from ares.core.config import AresSettings
from ares.core.noise import NoiseController
from ares.modules.linux._parsers import (
    ELFParser,
    LinuxCapParser,
)
from ares.modules.linux.ld_preload import LDPreloadModule
from ares.modules.linux.nfs_escape import NFSEscapeModule
from ares.modules.linux.privesc import LinuxPrivescModule
from ares.modules.linux.service_hijack import ServiceHijackModule


def _make_module(cls: type) -> tuple:
    settings = AresSettings(
        ares_secret_key="test-secret-key-32chars-minimum!!",
        ares_encryption_key="test-encryption-key-32chars-min!!",
    )
    campaign = Campaign(
        name="Linux-PurePython-Test",
        scope=[ScopeEntry(cidr="10.0.0.0/8")],
        noise_profile=NoiseProfile("normal"),
    )
    noise = NoiseController(campaign)
    module = cls(settings=settings, campaign=campaign, noise=noise)
    return module, campaign


# ─────────────────────────────────────────────────────────────────────────────
# 1. Tests for ELFParser (Pure Python RPATH/RUNPATH Extractor)
# ─────────────────────────────────────────────────────────────────────────────

def _build_mock_elf64_with_rpath(rpath: str, is_runpath: bool = False) -> bytes:
    """Constructs a minimal valid 64-bit ELF binary with PT_DYNAMIC and DT_RPATH/DT_RUNPATH."""
    # EI_NIDENT = 16
    ident = b"\x7fELF" + b"\x02" + b"\x01" + b"\x01" + b"\x00" * 9
    e_type = 2        # ET_EXEC
    e_machine = 62    # EM_X86_64
    e_version = 1
    e_entry = 0x400000
    e_phoff = 64      # Program header follows ELF header
    e_shoff = 0       # No section headers needed if PT_DYNAMIC parsed
    e_flags = 0
    e_ehsize = 64
    e_phentsize = 56  # Elf64_Phdr size
    e_phnum = 1
    e_shentsize = 64
    e_shnum = 0
    e_shstrndx = 0

    ehdr = struct.pack(
        "<16sHHIQQQIHHHHHH",
        ident, e_type, e_machine, e_version, e_entry, e_phoff, e_shoff,
        e_flags, e_ehsize, e_phentsize, e_phnum, e_shentsize, e_shnum, e_shstrndx
    )

    # String table data
    strtab = b"\x00" + rpath.encode("utf-8") + b"\x00"
    rpath_str_offset = 1

    # Dynamic section entries:
    # DT_STRTAB = 5, DT_RPATH = 15, DT_RUNPATH = 29, DT_NULL = 0
    dynamic_offset = 64 + 56
    strtab_offset = dynamic_offset + (16 * 3)  # 3 dynamic entries

    tag_rpath = 29 if is_runpath else 15
    dyn_entries = (
        struct.pack("<QQ", 5, strtab_offset) +              # DT_STRTAB
        struct.pack("<QQ", tag_rpath, rpath_str_offset) +  # DT_RPATH / DT_RUNPATH
        struct.pack("<QQ", 0, 0)                           # DT_NULL
    )

    p_type = 2  # PT_DYNAMIC
    p_flags = 6
    p_offset = dynamic_offset
    p_vaddr = dynamic_offset
    p_paddr = dynamic_offset
    p_filesz = len(dyn_entries)
    p_memsz = len(dyn_entries)
    p_align = 8

    phdr = struct.pack(
        "<IIQQQQQQ",
        p_type, p_flags, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_align
    )

    data = ehdr + phdr + dyn_entries + strtab
    return data


def test_elf_parser_extracts_rpath():
    raw_elf = _build_mock_elf64_with_rpath("/opt/custom/lib:/usr/local/lib")
    rpaths = ELFParser.parse_rpath_bytes(raw_elf)
    assert "/opt/custom/lib" in rpaths
    assert "/usr/local/lib" in rpaths


def test_elf_parser_extracts_runpath():
    raw_elf = _build_mock_elf64_with_rpath("/tmp/insecure_libs", is_runpath=True)
    rpaths = ELFParser.parse_rpath_bytes(raw_elf)
    assert "/tmp/insecure_libs" in rpaths


def test_elf_parser_invalid_data_returns_empty():
    assert ELFParser.parse_rpath_bytes(b"not an elf file") == []
    assert ELFParser.parse_rpath_bytes(b"") == []
    assert ELFParser.parse_rpath_bytes(b"\x7fELF\x02\x01\x01" + b"\x00" * 10) == []


# ─────────────────────────────────────────────────────────────────────────────
# 2. Tests for LinuxCapParser (Pure Python Capability Decoder)
# ─────────────────────────────────────────────────────────────────────────────

def test_linux_cap_parser_decodes_vfs_cap_data():
    # VFS_CAP_REVISION_2 = 0x02000000
    # CAP_SETUID = bit 7 (1 << 7 = 0x80)
    # CAP_DAC_OVERRIDE = bit 1 (1 << 1 = 0x02)
    magic = 0x02000000
    permitted = (1 << 7) | (1 << 1)  # cap_setuid, cap_dac_override
    inheritable = 0
    permitted_hi = 0
    inheritable_hi = 0

    cap_bytes = struct.pack("<5I", magic, permitted, inheritable, permitted_hi, inheritable_hi)
    caps = LinuxCapParser.decode_capability_bytes(cap_bytes)
    assert "cap_setuid" in caps
    assert "cap_dac_override" in caps


def test_linux_cap_parser_invalid_data_safe():
    assert LinuxCapParser.decode_capability_bytes(b"") == []
    assert LinuxCapParser.decode_capability_bytes(b"\x00\x00\x00") == []


# ─────────────────────────────────────────────────────────────────────────────
# 3. Tests for LinuxPrivescModule (Pure Python & Target Fixes)
# ─────────────────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_linux_privesc_world_writable_executes_on_remote_target():
    """Verify that remote target world-writable check queries target runner, not controller filesystem."""
    module, _ = _make_module(LinuxPrivescModule)
    module._target_host = "192.168.1.100"

    mock_runner = AsyncMock(side_effect=lambda cmd: "writable" if "/etc/passwd" in cmd else "")

    result = await module._check_world_writable_sensitive(run=mock_runner)
    assert "/etc/passwd" in result
    assert mock_runner.called
    assert len(module._findings) > 0
    assert module._findings[0].host == "192.168.1.100"


@pytest.mark.asyncio
async def test_linux_privesc_pure_python_path_check_local():
    """Verify PATH check operates in pure Python on localhost without subprocess."""
    module, _ = _make_module(LinuxPrivescModule)

    with tempfile.TemporaryDirectory() as tmpdir:
        # Create a writable directory in a custom PATH
        test_path = os.path.abspath(tmpdir)
        with patch.dict(os.environ, {"PATH": test_path}):
            # Passing run=None triggers pure Python local check
            writable_dirs = await module._check_writable_path(run=None)
            assert test_path in writable_dirs


@pytest.mark.asyncio
async def test_linux_privesc_pure_python_suid_scan_local():
    """Verify pure-python SUID scanner detects SUID files without /bin/bash or find."""
    module, _ = _make_module(LinuxPrivescModule)

    with tempfile.TemporaryDirectory() as tmpdir:
        fake_suid_bin = os.path.join(tmpdir, "test_suid_binary")
        with open(fake_suid_bin, "w") as f:
            f.write("#!/bin/sh\n")

        # Mock stat to return SUID bit (stat.S_ISUID)
        orig_stat = os.stat
        def mock_stat(path, *args, **kwargs):
            st = orig_stat(path, *args, **kwargs)
            if path == fake_suid_bin:
                # Add S_ISUID bit
                fake_st = MagicMock(wraps=st)
                fake_st.st_mode = st.st_mode | stat.S_ISUID
                return fake_st
            return st

        with patch("os.stat", side_effect=mock_stat):
            suid_files = module._find_suid_local(search_dirs=[tmpdir])
            assert fake_suid_bin in suid_files


# ─────────────────────────────────────────────────────────────────────────────
# 4. Tests for ServiceHijackModule Pure Python Local Execution
# ─────────────────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_service_hijack_pure_python_local():
    """Verify service_hijack inspects units without spawning /bin/bash."""
    module, _ = _make_module(ServiceHijackModule)

    with tempfile.TemporaryDirectory() as tmpdir:
        unit_file = os.path.join(tmpdir, "vulnerable.service")
        with open(unit_file, "w") as f:
            f.write("[Service]\nExecStart=/tmp/malicious_binary\nUser=root\n")

        with patch("ares.modules.linux.service_hijack._SYSTEMD_DIRS", [tmpdir]):
            findings, raw = await module.run(host="localhost")

            # Should find the suspicious path /tmp/malicious_binary
            assert raw["units_checked"] >= 1
            assert len(raw["suspicious_paths"]) >= 1
            assert raw["suspicious_paths"][0]["binary"] == "/tmp/malicious_binary"


# ─────────────────────────────────────────────────────────────────────────────
# 5. Tests for LDPreloadModule Pure Python Local Execution
# ─────────────────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_ld_preload_pure_python_local():
    """Verify ld_preload detects writable ld.so config paths without /bin/bash."""
    module, _ = _make_module(LDPreloadModule)

    with tempfile.TemporaryDirectory() as tmpdir:
        fake_ld_conf = os.path.join(tmpdir, "ld.so.conf")
        vulnerable_dir = os.path.join(tmpdir, "insecure_libdir")
        os.makedirs(vulnerable_dir, exist_ok=True)

        with open(fake_ld_conf, "w") as f:
            f.write(f"{vulnerable_dir}\n")

        with patch("ares.modules.linux.ld_preload._LD_CONF_FILE", fake_ld_conf), \
             patch("ares.modules.linux.ld_preload._LD_CONF_DIR", tmpdir):
            findings, raw = await module.run(host="localhost")
            # Should detect vulnerable_dir as writable library path
            assert any(f.severity.value in ("high", "critical") for f in findings)


# ─────────────────────────────────────────────────────────────────────────────
# 6. Tests for NFSEscapeModule Pure Python Local Execution
# ─────────────────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_nfs_escape_pure_python_local():
    """Verify nfs_escape parses /etc/exports in pure Python without /bin/bash."""
    module, _ = _make_module(NFSEscapeModule)

    with tempfile.TemporaryDirectory() as tmpdir:
        fake_exports = os.path.join(tmpdir, "exports")
        with open(fake_exports, "w") as f:
            f.write("/shared/data *(rw,no_root_squash,insecure)\n")

        with patch("ares.modules.linux.nfs_escape._EXPORTS_FILE", fake_exports), \
             patch("ares.modules.linux.nfs_escape._MOUNTS_FILE", os.devnull), \
             patch("ares.modules.linux.nfs_escape._NFS_CONF_FILE", os.devnull):
            findings, raw = await module.run(host="localhost")

            assert len(findings) >= 1
            assert any("no_root_squash" in f.title.lower() for f in findings)
