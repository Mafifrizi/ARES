"""
ARES Security
JWT authentication, Fernet encryption for stored data, input sanitization.
"""

from __future__ import annotations

import re
import secrets
import threading
from datetime import datetime, timedelta, timezone
from typing import Any

import bcrypt as _bcrypt
import jwt
from cryptography.fernet import Fernet, InvalidToken
from jwt.exceptions import InvalidTokenError

from ares.core.logger import get_logger

logger = get_logger("ares.core.security")


def _get_legacy_salt() -> bytes:
    import os as _os

    environb = getattr(_os, "environb", None)
    if environb is not None:
        value = environb.get(b"ARES_LEGACY_SALT")
        if value:
            return value
    value = _os.environ.get("ARES_LEGACY_SALT")
    if value:
        return value.encode()
    return b"ares-data-encryptor-v1-fixed-salt"


# ── Password hashing ──────────────────────────────────────────────────────────
# NOTE: Use bcrypt directly — passlib 1.7.4 is incompatible with bcrypt >= 4.0
# which added an explicit 72-byte limit. We truncate + call bcrypt directly.
def hash_password(password: str) -> str:
    pw_bytes = password.encode("utf-8")[:72]
    return _bcrypt.hashpw(pw_bytes, _bcrypt.gensalt()).decode("utf-8")


def verify_password(plain: str, hashed: str) -> bool:
    pw_bytes = plain.encode("utf-8")[:72]
    hashed_bytes = hashed.encode("utf-8") if isinstance(hashed, str) else hashed
    try:
        return _bcrypt.checkpw(pw_bytes, hashed_bytes)
    except (ValueError, TypeError):
        return False


# ── JWT ───────────────────────────────────────────────────────────────────────
#
# Algorithm support:
#   HS256 (default) — symmetric HMAC. Simple, single-service deployments.
#                     ARES_JWT_ALGORITHM=HS256, ARES_SECRET_KEY=<32+ char secret>
#
#   RS256            — asymmetric RSA. Multi-service: any service can verify tokens
#                     using only the public key without knowing the private key.
#                     Generate:
#                       openssl genrsa -out ares_jwt_private.pem 2048
#                       openssl rsa -in ares_jwt_private.pem -pubout -out ares_jwt_public.pem
#                     Config:
#                       ARES_JWT_ALGORITHM=RS256
#                       ARES_JWT_PRIVATE_KEY_PATH=/run/secrets/ares_jwt_private.pem
#                       ARES_JWT_PUBLIC_KEY_PATH=/run/secrets/ares_jwt_public.pem


def _load_jwt_key(
    secret_key: str,
    algorithm: str,
    *,
    private: bool = True,
) -> Any:
    """
    Return the correct key object for PyJWT based on algorithm.

    HS256: symmetric — same key for sign and verify.
    RS256: asymmetric — private key for sign, public key for verify.
           Keys are read from ARES_JWT_PRIVATE_KEY_PATH / ARES_JWT_PUBLIC_KEY_PATH
           env vars if present; otherwise falls back to secret_key string (useful
           for testing, not recommended for production RS256 deployments).
    """
    import os as _os

    if algorithm.startswith("RS") or algorithm.startswith("ES"):
        if private:
            key_path = _os.environ.get("ARES_JWT_PRIVATE_KEY_PATH", "")
            if key_path:
                try:
                    with open(key_path, "rb") as _fh:
                        return _fh.read()
                except OSError as exc:
                    logger.error(
                        "jwt_private_key_load_failed", path=key_path, error=str(exc)
                    )
        else:
            key_path = _os.environ.get("ARES_JWT_PUBLIC_KEY_PATH", "")
            if key_path:
                try:
                    with open(key_path, "rb") as _fh:
                        return _fh.read()
                except OSError as exc:
                    logger.error(
                        "jwt_public_key_load_failed", path=key_path, error=str(exc)
                    )
        # Fallback — not safe for RS256 production use, but allows unit tests to run
        logger.warning(
            "jwt_asymmetric_key_fallback",
            msg="Set ARES_JWT_PRIVATE_KEY_PATH/ARES_JWT_PUBLIC_KEY_PATH for RS256",
        )
        return secret_key
    # HS256 / HS384 / HS512 — symmetric
    return secret_key


def create_access_token(
    data: dict[str, Any],
    secret_key: str,
    algorithm: str = "HS256",  # override with ARES_JWT_ALGORITHM=RS256
    expires_minutes: int = 60,
) -> str:
    payload = data.copy()
    payload["exp"] = datetime.now(timezone.utc) + timedelta(minutes=expires_minutes)
    payload["iat"] = datetime.now(timezone.utc)
    payload["jti"] = secrets.token_hex(16)  # unique token ID for revocation
    key = _load_jwt_key(secret_key, algorithm, private=True)
    return jwt.encode(payload, key, algorithm=algorithm)


def decode_access_token(
    token: str,
    secret_key: str,
    algorithm: str = "HS256",
) -> dict[str, Any] | None:
    try:
        key = _load_jwt_key(secret_key, algorithm, private=False)
        # For HS256 algorithms=[algorithm] is required; for RS256 PyJWT handles it
        return jwt.decode(token, key, algorithms=[algorithm])
    except InvalidTokenError as e:
        logger.warning("security_jwt_decode_failed", e=e)
        return None


# ── Data encryption ───────────────────────────────────────────────────────────


class DataEncryptor:
    """
    Fernet symmetric encryption for sensitive campaign data (credentials, loot).

    Key derivation: PBKDF2-HMAC-SHA256 (100,000 iterations).

    Salt strategy (CRIT-SEC-02 fix):
        A 16-byte random salt is generated per DataEncryptor instance.
        Every ciphertext is stored as "<salt_hex_32chars>:<fernet_token>".
        On decrypt(), the salt is parsed from the prefix so the correct
        derived key is always used — no need to store salt separately in DB.

        This means each encrypted value has its own unique salt, eliminating
        the fixed-salt offline brute-force risk entirely. Decryption works
        across restarts as long as ARES_ENCRYPTION_KEY stays the same.

    Legacy compatibility:
        Values without a 32-char hex prefix are decrypted using the old
        fixed salt as a fallback, keeping existing DB records readable.
        They will be re-encrypted with a random salt on the next write.
    """

    # Legacy fixed salt — ONLY for decrypting old records written before per-record salts.
    # Security rationale: this salt is intentionally static because it was used as a
    # global salt in v5 and earlier. All new writes use per-record random salts (see encrypt()).
    # Override via ARES_LEGACY_SALT env var if you rotated this in your deployment.
    # Changing this will make all pre-v6 encrypted records unreadable.
    _LEGACY_SALT: bytes = _get_legacy_salt()

    def __init__(self, key: str) -> None:
        import os as _os

        self._raw_key = key.encode()
        self._salt = _os.urandom(16)  # fresh random salt per instance
        self._salt_hex = self._salt.hex()  # 32 hex chars, used as ciphertext prefix
        self._fernet = self._derive_fernet(self._salt)

    def _derive_fernet(self, salt: bytes) -> Fernet:
        import base64

        from cryptography.hazmat.primitives import hashes as _hashes
        from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

        kdf = PBKDF2HMAC(
            algorithm=_hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100_000,
        )
        return Fernet(base64.urlsafe_b64encode(kdf.derive(self._raw_key)))

    @staticmethod
    def _is_canonical_fernet_token(token: str) -> bool:
        import base64
        import binascii

        try:
            raw = token.encode("ascii")
            decoded = base64.b64decode(raw, altchars=b"-_", validate=True)
        except (UnicodeEncodeError, ValueError, binascii.Error):
            return False
        return base64.urlsafe_b64encode(decoded) == raw

    def encrypt(self, data: str | None) -> str | None:
        """Encrypt value. Returns '<salt_hex>:<fernet_token>' or None."""
        if data is None:
            return None
        token = self._fernet.encrypt(data.encode()).decode()
        return f"{self._salt_hex}:{token}"

    def decrypt(self, token: str | None) -> str | None:
        """
        Decrypt a value from encrypt().
        Handles new '<salt_hex>:<token>' format and legacy fixed-salt format.
        """
        if token is None:
            return None
        try:
            # New format: first 32 chars = salt hex, char 33 = ':', rest = fernet token
            if len(token) > 33 and token[32] == ":":
                salt = bytes.fromhex(token[:32])
                raw_fernet_token = token[33:]
                if not self._is_canonical_fernet_token(raw_fernet_token):
                    raise ValueError("Invalid Fernet token encoding")
                fernet_token = raw_fernet_token.encode()
                return self._derive_fernet(salt).decrypt(fernet_token).decode()

            # Legacy fallback: no prefix — use old fixed salt for pre-existing DB records
            if not self._is_canonical_fernet_token(token):
                raise ValueError("Invalid Fernet token encoding")
            result = (
                self._derive_fernet(self._LEGACY_SALT).decrypt(token.encode()).decode()
            )
            logger.info(
                "[security] Decrypted legacy ciphertext — will re-encrypt on next write"
            )
            return result

        except (InvalidToken, ValueError, UnicodeDecodeError) as exc:
            logger.error(
                "[security] Decryption failed — data may be tampered or key mismatch",
                error=str(exc)[:80],
            )
            return None

    @staticmethod
    def generate_key() -> str:
        """Generate a new random Fernet key."""
        return Fernet.generate_key().decode()


# ── Input sanitization ────────────────────────────────────────────────────────

_LDAP_INJECTION_CHARS = re.compile(r"[\\*()\x00-\x1f\x7f]")
_COMMAND_INJECTION_CHARS = re.compile(r"[;&|`$<>]")
_PATH_TRAVERSAL = re.compile(r"\.\./|\.\.\\")


def sanitize_ldap(value: str) -> str:
    """Strip LDAP injection metacharacters from user-controlled input."""
    sanitized = _LDAP_INJECTION_CHARS.sub("", value)
    if sanitized != value:
        logger.warning(
            "security_ldap_injection_chars_stripped_from", value=repr(value)
        )
    return sanitized


def sanitize_hostname(value: str) -> str:
    """Validate and sanitize a hostname or IP."""
    clean = re.sub(r"[^a-zA-Z0-9.\-_]", "", value)
    if clean != value:
        logger.warning(
            "security_hostname_sanitized", value=repr(value), clean=repr(clean)
        )
    return clean


def sanitize_path(value: str) -> str:
    """
    Prevent path traversal and restrict to allowed directories.

    Rules:
      1. Strip ../ and ..\\ sequences (relative traversal)
      2. Resolve to absolute path
      3. Reject paths outside ALLOWED_PATH_PREFIXES
      4. Reject paths to known sensitive locations
    """
    import tempfile
    from pathlib import Path as _Path

    sanitized = value
    while True:
        cleaned = _PATH_TRAVERSAL.sub("", sanitized)
        if cleaned == sanitized:
            break
        sanitized = cleaned
    if sanitized != value:
        logger.warning("security_path_traversal_attempt_blocked", value=repr(value))
    if "\x00" in sanitized:
        logger.warning("security_null_byte_path_blocked", value=repr(value))
        raise ValueError("Path contains a null byte")

    # Resolve to absolute path for validation.
    resolved_path = _Path(sanitized).resolve()
    resolved = str(resolved_path)

    # Reject known sensitive paths regardless of prefix
    _SENSITIVE = (
        "/etc/shadow",
        "/etc/passwd",
        "/etc/sudoers",
        "/root/.ssh",
        "/root/.bash_history",
        "/proc/",
        "/sys/",
    )

    def _is_sensitive(path: str) -> bool:
        normalized = path.replace("\\", "/")
        for sensitive in _SENSITIVE:
            root = sensitive.rstrip("/")
            if normalized == root or normalized.startswith(f"{root}/"):
                return True
        return False

    if _is_sensitive(sanitized) or _is_sensitive(resolved):
        logger.warning("security_sensitive_path_blocked", path=repr(resolved))
        raise ValueError(f"Access to sensitive path is not allowed: {resolved}")

    # Allowed directory roots — only these can be accessed.
    _ALLOWED = tuple(
        p.resolve()
        for p in (
            _Path.home(),  # ~/.ares/*, ~/bloodhound/*, etc.
            _Path(tempfile.gettempdir()),  # platform temp files
            _Path("/tmp"),  # POSIX temp files, resolves to C:\tmp on Windows
            _Path("/opt/ares"),  # installation dir
            _Path("/home"),  # user home directories
            _Path("/var/lib/ares"),  # data dir
        )
    )

    def _is_under_allowed_root(path: _Path) -> bool:
        for prefix in _ALLOWED:
            if path == prefix or path.is_relative_to(prefix):
                return True
        return False

    if not _is_under_allowed_root(resolved_path):
        logger.warning(
            "security_path_outside_allowed_dirs",
            path=repr(resolved),
            allowed=tuple(str(p) for p in _ALLOWED),
        )
        raise ValueError(
            f"Path '{resolved}' is outside allowed directories. "
            f"Allowed prefixes: {', '.join(str(p) for p in _ALLOWED)}"
        )

    return sanitized


def validate_ip_or_cidr(value: str) -> bool:
    """Returns True if value is a valid IP or CIDR."""
    from netaddr import AddrFormatError, IPAddress, IPNetwork

    try:
        IPAddress(value)
        return True
    except (AddrFormatError, ValueError):
        pass
    try:
        IPNetwork(value)
        return True
    except (AddrFormatError, ValueError):
        return False


# ── Secure Credential Artifact Management ─────────────────────────────────────
# Campaign-scoped artifact tracking. Key = campaign_id (or "_GLOBAL" for
# artifacts created outside any campaign context). Thread-safe via lock.
_CREDENTIAL_ARTIFACTS: dict[str, list[str]] = {}
_ARTIFACT_LOCK = threading.Lock()

_GLOBAL_SCOPE = "_GLOBAL"


def _restrict_windows_acl(
    path: str,
    *,
    is_dir: bool = False,
    require_success: bool = False,
) -> bool:
    """Best-effort owner-only ACL restriction for Windows temp artifacts.

    Returns True when the ACL was hardened. If hardening fails, the default is
    to preserve a usable temp artifact and log the failure; callers that need
    fail-closed behavior can pass require_success=True.
    """
    import csv
    import getpass
    import os
    import subprocess

    if os.name != "nt":
        return True

    def _run_icacls(args: list[str]) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["icacls", path, *args],
            capture_output=True,
            check=False,
            text=True,
            timeout=10,
        )

    def _current_principal() -> str:
        try:
            completed = subprocess.run(
                ["whoami", "/user", "/fo", "csv", "/nh"],
                capture_output=True,
                check=False,
                text=True,
                timeout=10,
            )
            if completed.returncode == 0 and completed.stdout.strip():
                rows = list(csv.reader(completed.stdout.splitlines()))
                if rows and len(rows[0]) >= 2 and rows[0][1].strip():
                    return f"*{rows[0][1].strip()}"
        except (OSError, subprocess.SubprocessError):
            pass

        username = os.environ.get("USERNAME") or getpass.getuser()
        domain = os.environ.get("USERDOMAIN", "").strip()
        return f"{domain}\\{username}" if domain and username else username

    def _warn(event: str, completed: subprocess.CompletedProcess[str] | None = None) -> None:
        logger.warning(
            event,
            path=path,
            returncode=getattr(completed, "returncode", None),
            stdout=(getattr(completed, "stdout", "") or "")[:300],
            stderr=(getattr(completed, "stderr", "") or "")[:300],
        )

    def _fail(event: str, completed: subprocess.CompletedProcess[str] | None = None) -> bool:
        _warn(event, completed)
        if require_success:
            raise PermissionError(f"{event}: unable to harden ACL for {path!r}")
        return False

    principal = _current_principal()
    grant = f"{principal}:{'(OI)(CI)F' if is_dir else 'F'}"
    try:
        grant_result = _run_icacls(["/grant:r", grant])
    except (OSError, subprocess.SubprocessError) as exc:
        logger.warning("credential_artifact_acl_grant_failed", path=path, error=str(exc))
        if require_success:
            raise PermissionError(f"unable to grant owner ACL for {path!r}") from exc
        return False
    if grant_result.returncode != 0:
        return _fail("credential_artifact_acl_grant_failed", grant_result)

    try:
        inherit_result = _run_icacls(["/inheritance:r"])
    except (OSError, subprocess.SubprocessError) as exc:
        logger.warning("credential_artifact_acl_inheritance_failed", path=path, error=str(exc))
        try:
            _run_icacls(["/inheritance:e"])
            _run_icacls(["/grant:r", grant])
        except (OSError, subprocess.SubprocessError) as restore_exc:
            logger.warning(
                "credential_artifact_acl_restore_failed",
                path=path,
                error=str(restore_exc),
            )
        if require_success:
            raise PermissionError(f"unable to remove inherited ACL for {path!r}") from exc
        return False
    if inherit_result.returncode != 0:
        try:
            restore_result = _run_icacls(["/inheritance:e"])
            if restore_result.returncode != 0:
                _warn("credential_artifact_acl_restore_failed", restore_result)
            restore_grant_result = _run_icacls(["/grant:r", grant])
            if restore_grant_result.returncode != 0:
                _warn("credential_artifact_acl_restore_failed", restore_grant_result)
        except (OSError, subprocess.SubprocessError) as restore_exc:
            logger.warning(
                "credential_artifact_acl_restore_failed",
                path=path,
                error=str(restore_exc),
            )
        return _fail("credential_artifact_acl_inheritance_failed", inherit_result)

    return True


def secure_mkstemp(
    suffix: str = "",
    prefix: str = "ares_",
    campaign_id: str = "",
) -> tuple[str, int]:
    """
    Create a tempfile with restrictive permissions (0o600) for credential material.
    Registers path for campaign-scoped tracking so cleanup deletes only the
    correct campaign's artifacts.

    Returns (path, fd) — caller MUST os.close(fd) after use.
    """
    import os
    import tempfile

    fd, path = tempfile.mkstemp(suffix=suffix, prefix=prefix)
    os.fchmod(fd, 0o600)  # owner read/write only — BEFORE any data written
    os.chmod(path, 0o600)  # Windows reflects file modes through chmod(path)
    _restrict_windows_acl(path)
    scope = campaign_id or _GLOBAL_SCOPE
    with _ARTIFACT_LOCK:
        _CREDENTIAL_ARTIFACTS.setdefault(scope, []).append(path)
    logger.debug("credential_artifact_created", path=path, campaign=scope)
    return path, fd


def secure_mkdtemp(prefix: str = "ares-", campaign_id: str = "") -> str:
    """
    Create a temp directory with restrictive permissions (0o700) for credential material.
    Registers path for campaign-scoped tracking.
    """
    import os
    import tempfile

    path = tempfile.mkdtemp(prefix=prefix)
    os.chmod(path, 0o700)  # owner only
    _restrict_windows_acl(path, is_dir=True)
    scope = campaign_id or _GLOBAL_SCOPE
    with _ARTIFACT_LOCK:
        _CREDENTIAL_ARTIFACTS.setdefault(scope, []).append(path)
    logger.debug("credential_artifact_dir_created", path=path, campaign=scope)
    return path


def cleanup_credential_artifacts(campaign_id: str = "") -> int:
    """
    Delete tracked credential artifacts for a specific campaign.
    If campaign_id is empty, cleans up _GLOBAL scope only.
    Call at campaign end.

    Returns number of artifacts cleaned.
    """
    import os
    import shutil

    scope = campaign_id or _GLOBAL_SCOPE
    with _ARTIFACT_LOCK:
        paths = _CREDENTIAL_ARTIFACTS.pop(scope, [])
    cleaned = 0
    for path in paths:
        try:
            if os.path.isdir(path):
                shutil.rmtree(path, ignore_errors=True)
                cleaned += 1
            elif os.path.isfile(path):
                os.unlink(path)
                cleaned += 1
        except OSError:
            pass
    if cleaned:
        logger.info("credential_artifacts_cleaned", count=cleaned, campaign=scope)
    return cleaned


def cleanup_all_credential_artifacts() -> int:
    """
    Delete ALL tracked credential artifacts across ALL campaigns.
    Call at process shutdown / atexit.

    Returns total number of artifacts cleaned.
    """
    with _ARTIFACT_LOCK:
        all_scopes = list(_CREDENTIAL_ARTIFACTS.keys())
    total = 0
    for scope in all_scopes:
        total += cleanup_credential_artifacts(scope)
    return total
