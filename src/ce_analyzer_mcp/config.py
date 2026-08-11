from __future__ import annotations

import ipaddress
import os
import re
from collections.abc import Mapping
from typing import Any, Final
from urllib.parse import urlsplit, urlunsplit

from pydantic import BaseModel, ConfigDict, Field, SecretStr, field_validator, model_validator

from ce_analyzer_mcp.errors import ConfigurationError

_AUTH_HEADER_RE: Final = re.compile(r"^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$")
_CONTROL_RE: Final = re.compile(r"[\x00-\x1f\x7f-\x9f]")


def _env_bool(name: str, value: str) -> bool:
    normalized = value.strip().lower()
    if normalized in {"1", "true", "yes", "on"}:
        return True
    if normalized in {"0", "false", "no", "off"}:
        return False
    raise ConfigurationError(f"{name} must be true or false")


def _env_int(name: str, value: str) -> int:
    try:
        return int(value)
    except ValueError as exc:
        raise ConfigurationError(f"{name} must be an integer") from exc


def _env_float(name: str, value: str) -> float:
    try:
        return float(value)
    except ValueError as exc:
        raise ConfigurationError(f"{name} must be a number") from exc


def _is_loopback(host: str) -> bool:
    if host.lower() == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


class Settings(BaseModel):
    """Immutable process-wide configuration loaded before stdio starts."""

    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        hide_input_in_errors=True,
        strict=True,
        validate_default=True,
    )

    base_url: str = "https://godbolt.org/"
    auth_token: SecretStr | None = None
    auth_header: str = "Authorization"
    auth_scheme: str = "Bearer"
    verify_tls: bool = True
    allow_insecure_http: bool = False
    connect_timeout_seconds: float = Field(default=5.0, gt=0, le=120)
    read_timeout_seconds: float = Field(default=60.0, gt=0, le=600)
    max_concurrency: int = Field(default=4, ge=1, le=32)
    metadata_ttl_seconds: int = Field(default=300, ge=0, le=86_400)

    @field_validator("base_url")
    @classmethod
    def validate_base_url(cls, value: str) -> str:
        if _CONTROL_RE.search(value) or any(character.isspace() for character in value):
            raise ValueError("base URL contains whitespace or control characters")
        try:
            parsed = urlsplit(value)
            _ = parsed.port
        except ValueError as exc:
            raise ValueError("base URL is malformed") from exc
        if parsed.scheme.lower() not in {"http", "https"}:
            raise ValueError("base URL must use http or https")
        if not parsed.hostname:
            raise ValueError("base URL must include a host")
        if parsed.username is not None or parsed.password is not None:
            raise ValueError("base URL must not contain credentials")
        if parsed.query or parsed.fragment:
            raise ValueError("base URL must not contain a query or fragment")
        path = parsed.path.rstrip("/") + "/"
        return urlunsplit((parsed.scheme.lower(), parsed.netloc, path, "", ""))

    @field_validator("auth_header")
    @classmethod
    def validate_auth_header(cls, value: str) -> str:
        if not _AUTH_HEADER_RE.fullmatch(value):
            raise ValueError("auth header is not a valid HTTP field name")
        return value

    @field_validator("auth_token")
    @classmethod
    def validate_auth_token(cls, value: SecretStr | None) -> SecretStr | None:
        if value is None:
            return None
        token = value.get_secret_value()
        if not token or len(token) > 8192 or _CONTROL_RE.search(token):
            raise ValueError("auth token is empty, oversized, or contains control characters")
        return value

    @field_validator("auth_scheme")
    @classmethod
    def validate_auth_scheme(cls, value: str) -> str:
        if len(value) > 64 or (value and not _AUTH_HEADER_RE.fullmatch(value)):
            raise ValueError("auth scheme is malformed")
        return value

    @model_validator(mode="after")
    def validate_transport_policy(self) -> Settings:
        parsed = urlsplit(self.base_url)
        if (
            parsed.scheme == "http"
            and not _is_loopback(parsed.hostname or "")
            and not self.allow_insecure_http
        ):
            raise ValueError(
                "plain HTTP is allowed only for loopback unless CE_API_ALLOW_INSECURE_HTTP is true"
            )
        return self

    @classmethod
    def from_env(cls, environ: Mapping[str, str] | None = None) -> Settings:
        env = os.environ if environ is None else environ
        values: dict[str, Any] = {}
        string_fields = {
            "CE_API_BASE_URL": "base_url",
            "CE_API_AUTH_HEADER": "auth_header",
            "CE_API_AUTH_SCHEME": "auth_scheme",
        }
        for env_name, field_name in string_fields.items():
            if env_name in env:
                values[field_name] = env[env_name]
        if token := env.get("CE_API_AUTH_TOKEN"):
            values["auth_token"] = SecretStr(token)
        bool_fields = {
            "CE_API_VERIFY_TLS": "verify_tls",
            "CE_API_ALLOW_INSECURE_HTTP": "allow_insecure_http",
        }
        for env_name, field_name in bool_fields.items():
            if env_name in env:
                values[field_name] = _env_bool(env_name, env[env_name])
        float_fields = {
            "CE_API_CONNECT_TIMEOUT_SECONDS": "connect_timeout_seconds",
            "CE_API_READ_TIMEOUT_SECONDS": "read_timeout_seconds",
        }
        for env_name, field_name in float_fields.items():
            if env_name in env:
                values[field_name] = _env_float(env_name, env[env_name])
        int_fields = {
            "CE_API_MAX_CONCURRENCY": "max_concurrency",
            "CE_API_METADATA_TTL_SECONDS": "metadata_ttl_seconds",
        }
        for env_name, field_name in int_fields.items():
            if env_name in env:
                values[field_name] = _env_int(env_name, env[env_name])
        try:
            return cls.model_validate(values)
        except ValueError as exc:
            raise ConfigurationError(str(exc)) from None

    def authentication_headers(self) -> dict[str, str]:
        if self.auth_token is None:
            return {}
        token = self.auth_token.get_secret_value()
        value = f"{self.auth_scheme} {token}" if self.auth_scheme else token
        return {self.auth_header: value}
