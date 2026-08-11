from __future__ import annotations

import re
from typing import Final

_CONTROL_RE: Final = re.compile(r"[\x00-\x1f\x7f-\x9f]")
_MAX_COMPONENT_LENGTH: Final = 240


def _safe_component(value: str) -> str:
    clean = _CONTROL_RE.sub("", value)
    if len(clean) > _MAX_COMPONENT_LENGTH:
        return f"{clean[:_MAX_COMPONENT_LENGTH]}..."
    return clean


class CEAnalyzerError(Exception):
    """Base class for failures safe to return through MCP."""

    code = "ce_analyzer_error"

    def __init__(self, message: str) -> None:
        self.public_message = _safe_component(message)
        super().__init__(self.public_message)


class ConfigurationError(CEAnalyzerError):
    code = "configuration_error"


class InputPolicyError(CEAnalyzerError):
    code = "invalid_input"


class SelectionError(CEAnalyzerError):
    code = "invalid_selection"


class ShortlinkValidationFailure(CEAnalyzerError):
    code = "shortlink_validation_failed"

    def __init__(self, compiler_id: str, status: str, exit_code: int) -> None:
        super().__init__(
            f"Shortlink compilation validation failed for compiler {compiler_id!r} "
            f"with status {status!r} and exit code {exit_code}"
        )


def _request_context(endpoint: str, fingerprint: str | None) -> str:
    context = f"endpoint {_safe_component(endpoint)!r}"
    if fingerprint:
        context += f", request fingerprint {_safe_component(fingerprint)!r}"
    return context


class TransportFailure(CEAnalyzerError):
    code = "transport_failure"

    def __init__(self, endpoint: str, fingerprint: str | None = None) -> None:
        super().__init__(
            f"Compiler Explorer transport failure at {_request_context(endpoint, fingerprint)}"
        )


class AuthenticationFailure(CEAnalyzerError):
    code = "authentication_failure"

    def __init__(
        self,
        endpoint: str,
        status: int,
        fingerprint: str | None = None,
    ) -> None:
        super().__init__(
            "Compiler Explorer authentication failed "
            f"with status {status} at {_request_context(endpoint, fingerprint)}"
        )


class BackendFailure(CEAnalyzerError):
    code = "backend_failure"

    def __init__(
        self,
        endpoint: str,
        status: int,
        fingerprint: str | None = None,
    ) -> None:
        super().__init__(
            f"Compiler Explorer returned status {status} at "
            f"{_request_context(endpoint, fingerprint)}"
        )


class IncompatibleBackend(CEAnalyzerError):
    code = "incompatible_backend"

    def __init__(
        self,
        endpoint: str,
        fingerprint: str | None = None,
        detail: str = "an incompatible response",
    ) -> None:
        super().__init__(
            f"Compiler Explorer returned {_safe_component(detail)} at "
            f"{_request_context(endpoint, fingerprint)}"
        )


class ResponseTooLarge(CEAnalyzerError):
    code = "response_too_large"

    def __init__(
        self,
        endpoint: str,
        fingerprint: str | None = None,
    ) -> None:
        super().__init__(
            f"Compiler Explorer response exceeded the configured safety limit at "
            f"{_request_context(endpoint, fingerprint)}"
        )


class NotFound(CEAnalyzerError):
    code = "not_found"

    def __init__(self, resource: str) -> None:
        super().__init__(f"Compiler Explorer has no result for {_safe_component(resource)}")
