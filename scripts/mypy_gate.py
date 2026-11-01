#!/usr/bin/env python3
"""mypy baseline gate.

Runs mypy and fails only on NEW errors relative to a committed baseline, so the
whole codebase is type-checked strict for *new* code while the existing legacy
findings (mostly false positives on dynamic/defensive code — see AUDIT_FINDINGS.md
C3) are grandfathered. This is the standard way to adopt a type checker on a large
pre-typing codebase.

Error signatures drop the line number (so unrelated edits don't churn the
baseline) and normalise path separators (so a Windows-generated baseline matches
Linux CI, which produces a subset — platform-only stub errors such as the Unix
`resource`/`fcntl` modules simply don't appear there).

Usage:
    python scripts/mypy_gate.py                 # gate: exit 1 on any new error
    python scripts/mypy_gate.py --update        # regenerate the baseline
"""
from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
BASELINE = ROOT / "mypy-baseline.txt"
MYPY_TARGET = "ares"

_LINECOL = re.compile(r"^(?P<file>[^:]+(?::[^:]+)??):\d+:(?:\d+:)? (?P<rest>.*)$")


def _signature(line: str) -> str | None:
    """Normalise a mypy error line into a line-number-independent signature."""
    line = line.rstrip()
    m = _LINECOL.match(line)
    if not m or " error: " not in f" {m.group('rest')} ":
        # keep only real "error:" lines (skip notes / summary)
        if ": error:" not in line:
            return None
    # strip "<file>:<line>:<col>:" -> "<file>|<message>"
    m2 = re.match(r"^(?P<file>.+?):\d+:(?:\d+:)?\s*(?P<msg>error:.*)$", line)
    if not m2:
        return None
    file = m2.group("file").replace("\\", "/")
    return f"{file}|{m2.group('msg').strip()}"


def _run_mypy() -> list[str]:
    proc = subprocess.run(
        [sys.executable, "-m", "mypy", MYPY_TARGET],
        cwd=ROOT, capture_output=True, text=True,
    )
    return [s for ln in proc.stdout.splitlines() if (s := _signature(ln))]


def main() -> int:
    update = "--update" in sys.argv
    current = _run_mypy()
    current_set = set(current)

    if update:
        BASELINE.write_text("\n".join(sorted(current_set)) + "\n", encoding="utf-8")
        print(f"mypy baseline updated: {len(current_set)} known signatures -> {BASELINE.name}")
        return 0

    if not BASELINE.exists():
        print("ERROR: mypy-baseline.txt missing. Run: python scripts/mypy_gate.py --update")
        return 2

    baseline = {ln for ln in BASELINE.read_text(encoding="utf-8").splitlines() if ln.strip()}
    new = sorted(current_set - baseline)
    if new:
        print(f"mypy gate FAILED: {len(new)} NEW error(s) not in baseline:\n")
        for sig in new:
            f, msg = sig.split("|", 1)
            print(f"  {f}: {msg}")
        print("\nFix the new type error(s), or (if intentional) run "
              "`python scripts/mypy_gate.py --update` to accept them.")
        return 1

    resolved = len(baseline) - len(current_set & baseline)
    print(f"mypy gate OK: 0 new errors "
          f"({len(current_set)} known, {resolved} baseline entries resolved).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
