"""
ARES Configuration
Typed settings loaded from environment / .env file.
No hardcoded secrets — ever.
"""
from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Literal

from pydantic import Field, SecretStr, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class NoiseSettings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="ARES_")

    default_noise_profile: Literal["stealth", "normal", "aggressive"] = "stealth"
    default_jitter_min_ms: int = Field(500, ge=0)
    default_jitter_max_ms: int = Field(3000, ge=0)

    @field_validator("default_jitter_max_ms")
    @classmethod
    def max_must_exceed_min(cls, v: int, info: object) -> int:
        # pydantic v2 info.data
        data = getattr(info, "data", {})
        if v <= data.get("default_jitter_min_ms", 0):
            raise ValueError("jitter_max must be greater than jitter_min")
        return v


class APISettings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="ARES_")

    api_host: str = "127.0.0.1"
    api_port: int = Field(8080, ge=1024, le=65535)
    secret_key: SecretStr = Field(..., min_length=32)
    jwt_algorithm: str = "HS256"
    jwt_expire_minutes: int = Field(60, ge=5)
    rate_limit_rpm: int = Field(60, ge=1)
    debug: bool = False


class DatabaseSettings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="ARES_")

    database_url: str = "sqlite+aiosqlite:///./ares.db"


class SecuritySettings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="ARES_")

    encryption_key: SecretStr = Field(..., min_length=32)


class LogSettings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="ARES_")

    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR"] = "INFO"
    log_file: str = "logs/ares.log"


class AresSettings(BaseSettings):
    """Master settings — loads from .env automatically."""
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # API
    ares_api_host: str = "127.0.0.1"
    ares_api_port: int = Field(8080, ge=1024, le=65535)
    ares_secret_key: SecretStr = Field(..., min_length=32, description="Generate: openssl rand -hex 32")
    ares_jwt_algorithm: str = "HS256"   # HS256 (default) or RS256 (asymmetric)
    # RS256 key paths (ignored when ares_jwt_algorithm=HS256)
    ares_jwt_private_key_path: str = ""  # path to PEM private key for signing
    ares_jwt_public_key_path:  str = ""  # path to PEM public key for verification
    ares_jwt_expire_minutes: int = Field(60, ge=5)
    ares_rate_limit_rpm: int = Field(60, ge=1)
    ares_debug: bool = False

    # Database
    ares_database_url: str = "sqlite+aiosqlite:///./ares.db"

    # Encryption
    ares_encryption_key: SecretStr = Field(..., min_length=32, description="Generate: python -c 'from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())'")

    # Logging
    ares_log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR"] = "INFO"
    ares_log_file: str = "logs/ares.log"

    # Noise
    ares_default_noise_profile: Literal["stealth", "normal", "aggressive"] = "stealth"
    ares_default_jitter_min_ms: int = Field(500, ge=0)
    ares_default_jitter_max_ms: int = Field(3000, ge=0)

    # Redis (optional — enables multi-pod rate limiting)
    # Set to empty string or omit to use in-process fallback
    ares_redis_url: str = Field(
        default="",
        description="Redis URL for multi-pod rate limiting. Empty = in-process fallback.",
    )

    # Webhook notifications (optional)
    ares_webhook_url:           str   = Field(default="", description="Slack/Teams/generic webhook URL")
    ares_webhook_on_severity:   str   = Field(default="critical,high", description="Comma-sep severity thresholds")
    ares_webhook_timeout:       float = Field(default=5.0, description="HTTP timeout seconds")
    ares_webhook_retry:         int   = Field(default=2, ge=0, le=5, description="Max retries on failure")

    # OpenTelemetry (optional — distributed tracing)
    ares_otel_endpoint:    str   = Field(default="", description="OTLP gRPC endpoint e.g. http://jaeger:4317")
    ares_otel_service:     str   = Field(default="ares-api", description="Service name in traces")
    ares_otel_sample_rate: float = Field(default=1.0, ge=0.0, le=1.0, description="Trace sampling rate")

    # ── Network security ──────────────────────────────────────────────────────
    ares_cors_origins: str = Field(
        default="http://localhost:3000,http://localhost:8080",
        description="Comma-separated allowed CORS origins. Example: https://ares.corp.local",
    )
    ares_trusted_hosts: str = Field(
        default="localhost,127.0.0.1",
        description="Comma-separated trusted hostnames. Example: ares.corp.local,10.0.0.5",
    )

    @property
    def cors_origins_list(self) -> list[str]:
        return [o.strip() for o in self.ares_cors_origins.split(",") if o.strip()]

    @property
    def trusted_hosts_list(self) -> list[str]:
        return [h.strip() for h in self.ares_trusted_hosts.split(",") if h.strip()]

    # Bootstrap — initial admin password, must be set via ARES_DEFAULT_ADMIN_PASSWORD env var.
    # No default is provided; ARES will refuse to start if this is unset.
    # Rotate immediately after first login via POST /auth/change-password.
    ares_default_admin_password: str = Field(
        ...,
        min_length=12,
        description=(
            "Initial admin password. Set via ARES_DEFAULT_ADMIN_PASSWORD. "
            "Must be at least 12 characters. Rotate immediately after first login."
        ),
    )

    @property
    def is_production(self) -> bool:
        return not self.ares_debug

    @property
    def secret_key_value(self) -> str:
        return self.ares_secret_key.get_secret_value()

    @property
    def jwt_signing_key(self) -> str:
        """
        Return the correct signing key for the configured JWT algorithm.
        RS256: returns private key PEM path.
        HS256: returns the HMAC secret.
        """
        if self.ares_jwt_algorithm == "RS256":
            if not self.ares_jwt_private_key_path:
                raise ValueError(
                    "ARES_JWT_ALGORITHM=RS256 requires ARES_JWT_PRIVATE_KEY_PATH. "
                    "Generate: openssl genrsa -out jwt_private.pem 2048"
                )
            return self.ares_jwt_private_key_path   # path — security.py loads the file
        return self.secret_key_value

    @property
    def jwt_verify_key(self) -> str:
        """
        Return the correct verification key for the configured JWT algorithm.
        RS256: returns public key PEM path.
        HS256: returns the HMAC secret.
        """
        if self.ares_jwt_algorithm == "RS256":
            if not self.ares_jwt_public_key_path:
                raise ValueError(
                    "ARES_JWT_ALGORITHM=RS256 requires ARES_JWT_PUBLIC_KEY_PATH. "
                    "Generate: openssl rsa -in jwt_private.pem -pubout -out jwt_public.pem"
                )
            return self.ares_jwt_public_key_path   # path — security.py loads the file
        return self.secret_key_value

    @property
    def encryption_key_value(self) -> str:
        return self.ares_encryption_key.get_secret_value()

    @property
    def db_path(self) -> str:
        """Strip SQLAlchemy prefix for aiosqlite direct use."""
        url = self.ares_database_url
        for prefix in ("sqlite+aiosqlite:///", "sqlite:///"):
            if url.startswith(prefix):
                return url[len(prefix):]
        return url


@lru_cache(maxsize=1)
def get_settings() -> AresSettings:
    """
    Cached settings instance — call this everywhere.
    Raises a clean, actionable error if required env vars are missing.
    """
    try:
        return AresSettings()
    except Exception as exc:
        msg = str(exc)
        if "ares_secret_key" in msg or "ares_encryption_key" in msg or "ares_default_admin_password" in msg:
            raise SystemExit(
                "\n\033[1m\033[31m❌ ARES not configured.\033[0m\n"
                "\n"
                "   Required environment variables are missing:\n"
                "     ARES_SECRET_KEY              — generate: openssl rand -hex 32\n"
                "     ARES_ENCRYPTION_KEY          — generate: python -c "
                "'from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())'\n"
                "     ARES_DEFAULT_ADMIN_PASSWORD  — min 12 chars, rotate after first login\n"
                "\n"
                "   \033[1mQuickest fix:\033[0m\n"
                "     bash scripts/setup.sh\n"
                "\n"
                "   Or copy .env.example to .env and fill in the required values.\n"
            ) from None
        raise

def clear_settings_cache() -> None:
    """Clear the lru_cache on get_settings().

    Call this in tests before changing env vars:
        monkeypatch.setenv("ARES_SECRET_KEY", "x")
        clear_settings_cache()
    """
    get_settings.cache_clear()

