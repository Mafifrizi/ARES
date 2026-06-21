"""
ARES Credential Cracking Integration
Automated cracking pipeline: hash discovered → cracked → vault updated.

Flow:
  Module discovers hash (kerberoast/asreproast/NTLM)
    └─► CrackingQueue.submit(hash_artifact)
          └─► CrackingWorker.run()
                ├─ hashcat (GPU, fastest)     priority=1
                └─ john    (CPU, fallback)    priority=2
                      └─ on success: vault.mark_cracked(cred_id, plaintext)
                                     ArtifactIntelEngine.process(updated_store)

Supported hash types (hashcat modes):
  13100  Kerberoast (RC4 / type 23)
  19700  Kerberoast AES128 (type 17)
  19600  Kerberoast AES256 (type 18)
  18200  ASREPRoast
  1000   NTLM (pass-the-hash)
  3000   LM
  5600   NetNTLMv2
  1800   sha512crypt (Linux /etc/shadow)
  500    md5crypt

Wordlist priority:
  1. rockyou.txt (common)
  2. kaonashi.txt (enterprise passwords)
  3. rules/OneRuleToRuleThemAll (hybrid)
  4. Custom client wordlist

Security note:
  Cracking always happens locally — no hashes sent externally.
  All cracked plaintext is encrypted in vault before any logging.
"""
from __future__ import annotations

import asyncio
import shutil
import subprocess
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any

from ares.core.logger import audit, get_logger

logger = get_logger("ares.credential.cracker")

WORDLIST_PATHS = [
    "/usr/share/wordlists/rockyou.txt",
    "/opt/wordlists/rockyou.txt",
    "/usr/share/wordlists/kaonashi.txt",
    "/opt/wordlists/kaonashi.txt",
]

RULES_PATHS = [
    "/usr/share/hashcat/rules/OneRuleToRuleThemAll.rule",
    "/opt/hashcat/rules/OneRuleToRuleThemAll.rule",
    "/usr/share/hashcat/rules/best64.rule",
]


class CrackStatus(str, Enum):
    PENDING  = "pending"
    RUNNING  = "running"
    CRACKED  = "cracked"
    FAILED   = "failed"
    SKIPPED  = "skipped"   # tool not available


@dataclass
class CrackJob:
    """A single hash cracking job."""
    job_id:       str = field(default_factory=lambda: str(uuid.uuid4())[:8])
    cred_id:      str = ""         # vault credential ID to update on success
    hash_value:   str = ""         # raw hash string
    hash_type:    str = ""         # "krb5tgs", "asrep", "ntlm", etc.
    hashcat_mode: int = 0          # hashcat -m value
    username:     str = ""
    domain:       str = ""
    status:       CrackStatus = CrackStatus.PENDING
    plaintext:    str = ""
    tool_used:    str = ""
    elapsed_s:    float = 0.0
    attempts:     int = 0
    wordlist:     str = ""
    queued_at:    float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, Any]:
        return {
            "job_id":    self.job_id,
            "cred_id":   self.cred_id,
            "username":  self.username,
            "domain":    self.domain,
            "hash_type": self.hash_type,
            "status":    self.status.value,
            "plaintext": "***" if self.plaintext else "",   # never log plaintext
            "tool":      self.tool_used,
            "elapsed_s": round(self.elapsed_s, 2),
        }


class CrackingWorker:
    """
    Runs hashcat or john on submitted jobs.
    Auto-detects available tools.
    Updates CredentialVault on success.
    """

    def __init__(
        self,
        vault:        Any,           # CredentialVault
        tmpdir:       str = "/tmp/ares-crack",
        timeout_s:    int = 3600,    # 1 hour max per job
        use_gpu:      bool = True,
    ) -> None:
        self.vault     = vault
        self.tmpdir    = Path(tmpdir)
        self.tmpdir.mkdir(parents=True, exist_ok=True, mode=0o700)  # owner-only: hash files may contain sensitive data
        self.timeout_s = timeout_s
        self.use_gpu   = use_gpu

        self._hashcat   = shutil.which("hashcat")
        self._john      = shutil.which("john") or shutil.which("john-the-ripper")
        self._wordlist  = self._find_wordlist()
        self._rules     = self._find_rules()

        if not self._hashcat and not self._john:
            logger.warning("no_cracking_tool_found",
                           msg="Install hashcat or john for automatic cracking")

    async def crack(self, job: CrackJob) -> CrackJob:
        """
        Attempt to crack a single hash.
        Tries hashcat first (GPU), falls back to john (CPU).
        Updates vault on success.
        """
        if not self._hashcat and not self._john:
            job.status = CrackStatus.SKIPPED
            return job

        t0 = time.monotonic()
        job.status = CrackStatus.RUNNING

        audit("crack_job_start", actor="cracker",
              job_id=job.job_id, hash_type=job.hash_type, username=job.username)

        # Hashcat (preferred — GPU accelerated)
        if self._hashcat and job.hashcat_mode:
            result = await self._run_hashcat(job)
        else:
            result = await self._run_john(job)

        job.elapsed_s = round(time.monotonic() - t0, 2)

        if result:
            job.status    = CrackStatus.CRACKED
            job.plaintext = result
            # IMPORTANT: update vault BEFORE any logging
            if job.cred_id:
                self.vault.mark_cracked(job.cred_id, result)
            audit("crack_success", actor="cracker",
                  job_id=job.job_id, username=job.username,
                  elapsed_s=job.elapsed_s, tool=job.tool_used)
            logger.info("hash_cracked", job_id=job.job_id,
                        username=job.username, elapsed_s=job.elapsed_s)
        else:
            job.status = CrackStatus.FAILED
            logger.info("crack_failed", job_id=job.job_id,
                        username=job.username, elapsed_s=job.elapsed_s)

        return job

    async def crack_batch(self, jobs: list[CrackJob]) -> list[CrackJob]:
        """Run multiple jobs in sequence (GPU processes one at a time for best perf)."""
        results = []
        for job in jobs:
            results.append(await self.crack(job))
        return results

    # ── Hashcat ────────────────────────────────────────────────────────────

    async def _run_hashcat(self, job: CrackJob) -> str | None:
        """
        Run hashcat on a single hash.
        Returns plaintext on success, None on failure.
        """
        hash_file  = self.tmpdir / f"{job.job_id}.hash"
        potfile    = self.tmpdir / f"{job.job_id}.pot"
        hash_file.write_text(job.hash_value)

        cmd = [
            self._hashcat,
            "-m", str(job.hashcat_mode),
            "-a", "0",                  # dictionary attack
            "--potfile-path", str(potfile),
            "--quiet",
            "--status",
            "--status-timer=10",
        ]

        # GPU or CPU
        if not self.use_gpu:
            cmd += ["-D", "1"]          # force CPU device

        # Add wordlist
        if self._wordlist:
            cmd.append(str(self._wordlist))
            job.wordlist = str(self._wordlist)

        # Add rules
        if self._rules:
            cmd += ["-r", str(self._rules)]

        cmd.append(str(hash_file))

        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout_b, _ = await asyncio.wait_for(
                proc.communicate(), timeout=self.timeout_s
            )
            job.tool_used = "hashcat"

            # Read cracked plaintext from potfile
            if potfile.exists():
                content = potfile.read_text().strip()
                if content:
                    # Potfile format: hash:plaintext
                    parts = content.split(":", 1)
                    if len(parts) == 2:
                        return parts[1]
                    # For Kerberos hashes: $krb5tgs$...:plaintext
                    last_colon = content.rfind(":")
                    if last_colon > 0:
                        return content[last_colon + 1:]

            # Also check stdout (show command)
            return await self._hashcat_show(job, hash_file, str(job.hashcat_mode))

        except asyncio.TimeoutError:
            logger.warning("hashcat_timeout", job_id=job.job_id)
            return None
        except Exception as exc:
            logger.warning("hashcat_error", job_id=job.job_id, error=str(exc)[:100])
            return None
        finally:
            hash_file.unlink(missing_ok=True)
            potfile.unlink(missing_ok=True)

    async def _hashcat_show(self, job: CrackJob, hash_file: Path, mode: str) -> str | None:
        """Run hashcat --show to retrieve already-cracked passwords."""
        try:
            result = subprocess.run(
                [self._hashcat, "-m", mode, "--show", str(hash_file)],
                capture_output=True, text=True, timeout=10,
            )
            if result.stdout.strip():
                last_colon = result.stdout.strip().rfind(":")
                if last_colon > 0:
                    return result.stdout.strip()[last_colon + 1:]
        except (IndexError, ValueError, AttributeError):
            pass
        return None

    # ── John the Ripper ────────────────────────────────────────────────────

    async def _run_john(self, job: CrackJob) -> str | None:
        """
        Run john the ripper on the hash.
        Auto-detects format from hash_type.
        """
        john_format = self._john_format(job.hash_type)
        hash_file   = self.tmpdir / f"{job.job_id}_john.hash"
        # John needs username:hash format for some types
        hash_file.write_text(f"{job.username}:{job.hash_value}\n")

        cmd = [self._john]
        if john_format:
            cmd += [f"--format={john_format}"]
        if self._wordlist:
            cmd += [f"--wordlist={self._wordlist}"]
            job.wordlist = str(self._wordlist)
        cmd.append(str(hash_file))

        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            await asyncio.wait_for(proc.communicate(), timeout=self.timeout_s)
            job.tool_used = "john"

            # Retrieve cracked password
            show_result = subprocess.run(
                [self._john, "--show", str(hash_file)],
                capture_output=True, text=True, timeout=10,
            )
            for line in show_result.stdout.splitlines():
                if ":" in line:
                    parts = line.split(":", 2)
                    if len(parts) >= 2 and parts[1]:
                        return parts[1]
        except asyncio.TimeoutError:
            logger.warning("john_timeout", job_id=job.job_id)
        except Exception as exc:
            logger.warning("john_error", job_id=job.job_id, error=str(exc)[:100])
        finally:
            hash_file.unlink(missing_ok=True)
        return None

    @staticmethod
    def _john_format(hash_type: str) -> str:
        mapping = {
            "krb5tgs":  "krb5tgs",
            "krb5asrep": "krb5asrep",
            "ntlm":     "nt",
            "ntlmv2":   "netntlmv2",
            "lm":       "lm",
            "sha512":   "sha512crypt",
            "md5":      "md5crypt",
        }
        return mapping.get(hash_type.lower(), "")

    def _find_wordlist(self) -> Path | None:
        for p in WORDLIST_PATHS:
            path = Path(p)
            if path.exists():
                return path
        return None

    def _find_rules(self) -> Path | None:
        for p in RULES_PATHS:
            path = Path(p)
            if path.exists():
                return path
        return None

    def tool_status(self) -> dict[str, Any]:
        return {
            "hashcat":  {"available": bool(self._hashcat), "path": self._hashcat},
            "john":     {"available": bool(self._john),    "path": self._john},
            "wordlist": {"path": str(self._wordlist) if self._wordlist else None,
                         "available": bool(self._wordlist)},
            "rules":    {"path": str(self._rules) if self._rules else None,
                         "available": bool(self._rules)},
        }


class CrackingQueue:
    """
    Async queue of cracking jobs consumed by CrackingWorker.
    Supports priority ordering (NTLM < Kerberoast by default).
    """

    def __init__(self, worker: CrackingWorker) -> None:
        self._queue:  asyncio.PriorityQueue[tuple[int, CrackJob]] = asyncio.PriorityQueue()
        self._worker  = worker
        self._results: dict[str, CrackJob] = {}
        self._running = False

    def submit(self, job: CrackJob, priority: int = 5) -> None:
        self._queue.put_nowait((priority, job))
        logger.debug("crack_job_submitted",
                     job_id=job.job_id, hash_type=job.hash_type, priority=priority)

    async def run_until_empty(self) -> list[CrackJob]:
        """Process all queued jobs. Returns results."""
        results: list[CrackJob] = []
        while not self._queue.empty():
            _, job = await self._queue.get()
            done = await self._worker.crack(job)
            self._results[done.job_id] = done
            results.append(done)
        return results

    def cracked_count(self) -> int:
        return sum(1 for j in self._results.values() if j.status == CrackStatus.CRACKED)

    def pending_count(self) -> int:
        return self._queue.qsize()
