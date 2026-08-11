from __future__ import annotations

from collections.abc import Mapping

import pytest
from pydantic import ValidationError

from ce_analyzer_mcp.config import Settings
from ce_analyzer_mcp.errors import ConfigurationError


def test_defaults_are_secure_and_documented() -> None:
    settings = Settings.from_env({})

    assert settings.base_url == "https://godbolt.org/"
    assert settings.auth_token is None
    assert settings.auth_header == "Authorization"
    assert settings.auth_scheme == "Bearer"
    assert settings.verify_tls is True
    assert settings.allow_insecure_http is False
    assert settings.connect_timeout_seconds == 5.0
    assert settings.read_timeout_seconds == 60.0
    assert settings.max_concurrency == 4
    assert settings.metadata_ttl_seconds == 300
    assert settings.authentication_headers() == {}


def test_from_env_parses_every_supported_setting() -> None:
    settings = Settings.from_env(
        {
            "CE_API_BASE_URL": "https://ce.example.test/root",
            "CE_API_AUTH_TOKEN": "top-secret",
            "CE_API_AUTH_HEADER": "X-Compiler-Key",
            "CE_API_AUTH_SCHEME": "Token",
            "CE_API_VERIFY_TLS": "off",
            "CE_API_ALLOW_INSECURE_HTTP": "yes",
            "CE_API_CONNECT_TIMEOUT_SECONDS": "1.25",
            "CE_API_READ_TIMEOUT_SECONDS": "42",
            "CE_API_MAX_CONCURRENCY": "9",
            "CE_API_METADATA_TTL_SECONDS": "0",
            "UNRELATED": "ignored",
        }
    )

    assert settings.base_url == "https://ce.example.test/root/"
    assert settings.verify_tls is False
    assert settings.allow_insecure_http is True
    assert settings.connect_timeout_seconds == 1.25
    assert settings.read_timeout_seconds == 42.0
    assert settings.max_concurrency == 9
    assert settings.metadata_ttl_seconds == 0
    assert settings.authentication_headers() == {"X-Compiler-Key": "Token top-secret"}


@pytest.mark.parametrize("true_value", ["1", "true", "TRUE", " yes ", "On"])
@pytest.mark.parametrize("false_value", ["0", "false", "FALSE", " no ", "Off"])
def test_boolean_environment_spellings(true_value: str, false_value: str) -> None:
    settings = Settings.from_env(
        {
            "CE_API_VERIFY_TLS": true_value,
            "CE_API_ALLOW_INSECURE_HTTP": false_value,
        }
    )

    assert settings.verify_tls is True
    assert settings.allow_insecure_http is False


@pytest.mark.parametrize(
    ("name", "value", "message"),
    [
        ("CE_API_VERIFY_TLS", "truthy", "must be true or false"),
        ("CE_API_ALLOW_INSECURE_HTTP", "", "must be true or false"),
        ("CE_API_MAX_CONCURRENCY", "4.0", "must be an integer"),
        ("CE_API_METADATA_TTL_SECONDS", "forever", "must be an integer"),
        ("CE_API_CONNECT_TIMEOUT_SECONDS", "quickly", "must be a number"),
        ("CE_API_READ_TIMEOUT_SECONDS", "", "must be a number"),
    ],
)
def test_invalid_environment_scalars_raise_configuration_error(
    name: str, value: str, message: str
) -> None:
    with pytest.raises(ConfigurationError, match=message):
        Settings.from_env({name: value})


@pytest.mark.parametrize(
    ("name", "value"),
    [
        ("CE_API_CONNECT_TIMEOUT_SECONDS", "0"),
        ("CE_API_CONNECT_TIMEOUT_SECONDS", "121"),
        ("CE_API_CONNECT_TIMEOUT_SECONDS", "nan"),
        ("CE_API_READ_TIMEOUT_SECONDS", "-1"),
        ("CE_API_READ_TIMEOUT_SECONDS", "601"),
        ("CE_API_READ_TIMEOUT_SECONDS", "inf"),
        ("CE_API_MAX_CONCURRENCY", "0"),
        ("CE_API_MAX_CONCURRENCY", "33"),
        ("CE_API_METADATA_TTL_SECONDS", "-1"),
        ("CE_API_METADATA_TTL_SECONDS", "86401"),
    ],
)
def test_environment_numeric_bounds(name: str, value: str) -> None:
    with pytest.raises(ConfigurationError):
        Settings.from_env({name: value})


@pytest.mark.parametrize(
    ("raw", "normalized"),
    [
        ("https://example.test", "https://example.test/"),
        ("HTTPS://Example.Test/api///", "https://Example.Test/api/"),
        ("https://example.test:8443/root", "https://example.test:8443/root/"),
        ("http://localhost:10240/api", "http://localhost:10240/api/"),
        ("http://127.0.0.1", "http://127.0.0.1/"),
        ("http://127.42.0.9/path", "http://127.42.0.9/path/"),
        ("http://[::1]:8080", "http://[::1]:8080/"),
    ],
)
def test_base_url_normalization_and_loopback_policy(raw: str, normalized: str) -> None:
    assert Settings(base_url=raw).base_url == normalized


@pytest.mark.parametrize(
    "url",
    [
        "",
        "example.test",
        "/api",
        "ftp://example.test",
        "https:///missing-host",
        "https://example.test:invalid",
        "https://[not-ipv6]/",
        "https://example.test/api?token=secret",
        "https://example.test/api#fragment",
        "https://example.test/\nother",
        "https://bad host.example/",
    ],
)
def test_malformed_base_urls_are_rejected_without_echoing_input(url: str) -> None:
    with pytest.raises(ConfigurationError) as raised:
        Settings.from_env({"CE_API_BASE_URL": url})

    if url:
        assert url not in str(raised.value)


@pytest.mark.parametrize(
    "url",
    [
        "https://user@example.test",
        "https://user:password@example.test/api",
        "https://:password@example.test",
    ],
)
def test_embedded_url_credentials_are_rejected_and_redacted(url: str) -> None:
    with pytest.raises(ConfigurationError) as raised:
        Settings.from_env({"CE_API_BASE_URL": url})

    message = str(raised.value)
    assert "credentials" in message
    assert "password" not in message
    assert "user@example" not in message


@pytest.mark.parametrize(
    "url",
    [
        "http://example.test",
        "http://192.0.2.1/api",
        "http://localhost.example.test",
        "http://0.0.0.0",
        "http://[::]",
    ],
)
def test_non_loopback_plain_http_requires_explicit_override(url: str) -> None:
    with pytest.raises(ConfigurationError, match="plain HTTP"):
        Settings.from_env({"CE_API_BASE_URL": url})

    settings = Settings.from_env(
        {
            "CE_API_BASE_URL": url,
            "CE_API_ALLOW_INSECURE_HTTP": "true",
        }
    )
    assert settings.base_url.startswith("http://")


@pytest.mark.parametrize(
    "header",
    [
        "",
        "Authorization: Bearer",
        "X API Key",
        "X-Key\r\nInjected",
        "X-Key\x7f",
        "Äuthorization",
    ],
)
def test_malformed_auth_header_names_are_rejected(header: str) -> None:
    with pytest.raises(ConfigurationError, match="valid HTTP field name"):
        Settings.from_env({"CE_API_AUTH_HEADER": header})


@pytest.mark.parametrize("header", ["Authorization", "X-Api-Key", "x_custom.key", "X~Key"])
def test_valid_auth_header_names_are_preserved(header: str) -> None:
    settings = Settings.from_env({"CE_API_AUTH_TOKEN": "secret", "CE_API_AUTH_HEADER": header})
    assert settings.authentication_headers() == {header: "Bearer secret"}


def test_empty_auth_scheme_builds_api_key_header_without_whitespace() -> None:
    settings = Settings.from_env(
        {
            "CE_API_AUTH_TOKEN": "api-key-value",
            "CE_API_AUTH_HEADER": "X-Api-Key",
            "CE_API_AUTH_SCHEME": "",
        }
    )

    assert settings.authentication_headers() == {"X-Api-Key": "api-key-value"}


@pytest.mark.parametrize(
    "scheme",
    [" Bearer", "Bearer ", "Basic Auth", "Bearer\nInjected", "x" * 65],
)
def test_malformed_auth_schemes_are_rejected(scheme: str) -> None:
    with pytest.raises(ConfigurationError, match="auth scheme is malformed"):
        Settings.from_env({"CE_API_AUTH_SCHEME": scheme})


def test_empty_auth_token_is_treated_as_unconfigured() -> None:
    settings = Settings.from_env(
        {
            "CE_API_AUTH_TOKEN": "",
            "CE_API_AUTH_HEADER": "X-Api-Key",
            "CE_API_AUTH_SCHEME": "",
        }
    )
    assert settings.auth_token is None
    assert settings.authentication_headers() == {}


def test_auth_token_is_redacted_from_repr_and_unrelated_validation_errors() -> None:
    token = "never-print-this-token"
    settings = Settings.from_env({"CE_API_AUTH_TOKEN": token})

    assert token not in repr(settings)
    assert token not in str(settings)
    assert "**********" in repr(settings)

    with pytest.raises(ConfigurationError) as raised:
        Settings.from_env(
            {
                "CE_API_AUTH_TOKEN": token,
                "CE_API_BASE_URL": "http://not-loopback.example",
            }
        )
    assert token not in str(raised.value)


@pytest.mark.parametrize("token", ["line\nbreak", "nul\x00byte", "x" * 8193])
def test_auth_token_rejects_unsafe_header_values_without_echoing_them(token: str) -> None:
    with pytest.raises(ConfigurationError) as raised:
        Settings.from_env({"CE_API_AUTH_TOKEN": token})

    assert token not in str(raised.value)


def test_settings_are_frozen_strict_and_forbid_unknown_fields() -> None:
    settings = Settings()
    with pytest.raises(ValidationError, match="frozen"):
        settings.max_concurrency = 8  # type: ignore[misc]
    with pytest.raises(ValidationError):
        Settings.model_validate({"verify_tls": "true"})
    with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
        Settings.model_validate({"unknown": 1})


def test_from_env_accepts_an_arbitrary_read_only_mapping() -> None:
    class ReadOnlyEnvironment(Mapping[str, str]):
        def __getitem__(self, key: str) -> str:
            return {"CE_API_MAX_CONCURRENCY": "2"}[key]

        def __iter__(self):  # type: ignore[no-untyped-def]
            return iter(("CE_API_MAX_CONCURRENCY",))

        def __len__(self) -> int:
            return 1

    assert Settings.from_env(ReadOnlyEnvironment()).max_concurrency == 2
