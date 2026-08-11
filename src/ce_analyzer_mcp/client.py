from __future__ import annotations

import asyncio
import copy
import hashlib
import json
import math
import time
from collections.abc import Awaitable, Callable, Mapping, Sequence
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from typing import Any, Final, TypeVar, cast
from urllib.parse import quote, urljoin

import httpx

from ce_analyzer_mcp.__about__ import __version__
from ce_analyzer_mcp.config import Settings
from ce_analyzer_mcp.errors import (
    AuthenticationFailure,
    BackendFailure,
    IncompatibleBackend,
    NotFound,
    ResponseTooLarge,
    TransportFailure,
)
from ce_analyzer_mcp.models import (
    AnalyzerSelection,
    AssemblyFilters,
    LibrarySelection,
    ShortlinkCompilerConfiguration,
    SourceBundle,
    serialize_argument_tokens,
)

MAX_UPSTREAM_RESPONSE_BYTES: Final = 8 * 1024 * 1024
_TRANSIENT_STATUSES: Final = frozenset({429, 502, 503, 504})
_MAX_RETRY_AFTER_SECONDS: Final = 2.0
_COMPILER_FIELDS: Final = ",".join(
    (
        "id",
        "name",
        "lang",
        "compilerType",
        "compilerCategories",
        "semver",
        "releaseTrack",
        "instructionSet",
        "group",
        "groupName",
        "isSemVer",
        "isNightly",
        "emulated",
        "interpreted",
        "hidden",
        "supportsBinary",
        "supportsExecute",
        "supportsOptOutput",
        "supportsAsmDocs",
        "tools",
        "libsArr",
    )
)
_LIBRARY_FIELDS: Final = ",".join(
    (
        "id",
        "name",
        "description",
        "url",
        "versions.id",
        "versions.version",
        "versions.name",
        "versions.alias",
        "versions.hidden",
    )
)

Sleep = Callable[[float], Awaitable[None]]
Clock = Callable[[], float]
T = TypeVar("T")


class _ResponseStartedTransportFailure(TransportFailure):
    pass


def build_compile_payload(
    *,
    source: SourceBundle,
    compiler_arguments: Sequence[str],
    libraries: Sequence[LibrarySelection],
    filters: AssemblyFilters,
    analyzers: Sequence[AnalyzerSelection] = (),
    produce_optimization_output: bool = False,
    skip_assembly: bool = False,
) -> dict[str, Any]:
    """Build an allowlisted compile-only request without merging caller JSON."""

    return {
        "source": source.source,
        "options": {
            "userArguments": serialize_argument_tokens(compiler_arguments),
            "compilerOptions": {
                "skipAsm": skip_assembly,
                "skipPopArgs": True,
                "executorRequest": False,
                "overrides": [],
                "produceOptInfo": produce_optimization_output,
            },
            "filters": _display_filters(filters),
            "tools": [
                {
                    "id": analyzer.id,
                    "args": serialize_argument_tokens(analyzer.arguments),
                    "stdin": "",
                }
                for analyzer in analyzers
            ],
            "libraries": [{"id": library.id, "version": library.version} for library in libraries],
            "executeParameters": {"args": [], "stdin": "", "runtimeTools": []},
        },
        "lang": "c++",
        "allowStoreCodeDebug": False,
        "files": [
            {"filename": virtual_file.path, "contents": virtual_file.content}
            for virtual_file in source.files
        ],
    }


def _display_filters(filters: AssemblyFilters) -> dict[str, bool]:
    return {
        "binary": False,
        "binaryObject": False,
        "commentOnly": filters.comment_only,
        "demangle": filters.demangle,
        "directives": filters.directives,
        "execute": False,
        "intel": filters.intel,
        "labels": filters.labels,
        "libraryCode": filters.library_code,
        "trim": filters.trim,
        "debugCalls": filters.debug_calls,
    }


def build_shortlink_payload(
    source: SourceBundle,
    compilers: Sequence[ShortlinkCompilerConfiguration],
) -> dict[str, Any]:
    """Build one allowlisted Compiler Explorer ClientState for permanent storage."""

    return {
        "sessions": [
            {
                "id": 1,
                "language": "c++",
                "source": source.source,
                "compilers": [
                    {
                        "id": compiler.compiler,
                        "options": serialize_argument_tokens(compiler.compiler_arguments),
                        "libs": [
                            {"name": library.id, "ver": library.version}
                            for library in compiler.libraries
                        ],
                        "filters": _display_filters(compiler.filters),
                    }
                    for compiler in compilers
                ],
            }
        ]
    }


def canonical_request_fingerprint(compiler_id: str, payload: Mapping[str, Any]) -> str:
    canonical = json.dumps(
        {"compiler": compiler_id, "payload": payload},
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
        allow_nan=False,
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _reject_json_constant(value: str) -> None:
    raise ValueError(f"invalid JSON constant {value}")


def _parse_json(content: bytes, endpoint: str, fingerprint: str | None) -> Any:
    try:
        return json.loads(content, parse_constant=_reject_json_constant)
    except (UnicodeDecodeError, ValueError, RecursionError):
        raise IncompatibleBackend(endpoint, fingerprint, "malformed JSON") from None


def _retry_after(headers: Mapping[str, str], now: Callable[[], datetime]) -> float | None:
    value = headers.get("retry-after")
    if value is None:
        return None
    try:
        seconds = float(value)
    except ValueError:
        try:
            target = parsedate_to_datetime(value)
            if target.tzinfo is None:
                target = target.replace(tzinfo=timezone.utc)
            seconds = (target - now()).total_seconds()
        except (TypeError, ValueError, OverflowError):
            return None
    if not math.isfinite(seconds):
        return None
    return min(max(seconds, 0.0), _MAX_RETRY_AFTER_SECONDS)


class CompilerExplorerClient:
    """Bounded asynchronous transport for the supported Compiler Explorer API subset."""

    def __init__(
        self,
        settings: Settings,
        *,
        transport: httpx.AsyncBaseTransport | None = None,
        sleep: Sleep = asyncio.sleep,
        clock: Clock = time.monotonic,
        utcnow: Callable[[], datetime] | None = None,
        max_response_bytes: int = MAX_UPSTREAM_RESPONSE_BYTES,
    ) -> None:
        self.settings = settings
        self._transport = transport
        self._sleep = sleep
        self._clock = clock
        self._utcnow = utcnow or (lambda: datetime.now(timezone.utc))
        self._max_response_bytes = max_response_bytes
        self._semaphore = asyncio.Semaphore(settings.max_concurrency)
        self._cache_lock = asyncio.Lock()
        self._cache: dict[str, tuple[float, Any]] = {}
        self._http: httpx.AsyncClient | None = None

    async def __aenter__(self) -> CompilerExplorerClient:
        if self._http is not None:
            raise RuntimeError("CompilerExplorerClient cannot be entered twice")
        headers = {
            "Accept": "application/json",
            "User-Agent": f"ce-analyzer-mcp/{__version__}",
            **self.settings.authentication_headers(),
        }
        timeout = httpx.Timeout(
            connect=self.settings.connect_timeout_seconds,
            read=self.settings.read_timeout_seconds,
            write=self.settings.read_timeout_seconds,
            pool=self.settings.connect_timeout_seconds,
        )
        limits = httpx.Limits(
            max_connections=self.settings.max_concurrency,
            max_keepalive_connections=self.settings.max_concurrency,
        )
        self._http = httpx.AsyncClient(
            base_url=self.settings.base_url,
            headers=headers,
            timeout=timeout,
            limits=limits,
            verify=self.settings.verify_tls,
            follow_redirects=False,
            transport=self._transport,
        )
        return self

    async def __aexit__(self, *_: object) -> None:
        await self.close()

    async def close(self) -> None:
        if self._http is not None:
            client, self._http = self._http, None
            await client.aclose()

    def _active_client(self) -> httpx.AsyncClient:
        if self._http is None:
            raise RuntimeError("CompilerExplorerClient must be used as an async context manager")
        return self._http

    async def _request_once(
        self,
        method: str,
        endpoint: str,
        *,
        params: Mapping[str, str] | None,
        json_body: Mapping[str, Any] | None,
        fingerprint: str | None,
    ) -> tuple[int, dict[str, str], bytes]:
        client = self._active_client()
        request_headers = {"Content-Type": "application/json"} if json_body is not None else None
        response_started = False
        try:
            async with (
                self._semaphore,
                client.stream(
                    method,
                    endpoint,
                    params=params,
                    json=json_body,
                    headers=request_headers,
                ) as response,
            ):
                response_started = True
                headers = {name.lower(): value for name, value in response.headers.items()}
                if response.status_code in _TRANSIENT_STATUSES:
                    return response.status_code, headers, b""
                content_length = response.headers.get("content-length")
                if content_length is not None:
                    try:
                        if int(content_length) > self._max_response_bytes:
                            raise ResponseTooLarge(endpoint, fingerprint)
                    except ValueError:
                        pass
                chunks: list[bytes] = []
                size = 0
                async for chunk in response.aiter_bytes():
                    size += len(chunk)
                    if size > self._max_response_bytes:
                        raise ResponseTooLarge(endpoint, fingerprint)
                    chunks.append(chunk)
                return response.status_code, headers, b"".join(chunks)
        except ResponseTooLarge:
            raise
        except httpx.TransportError:
            if response_started:
                raise _ResponseStartedTransportFailure(endpoint, fingerprint) from None
            raise TransportFailure(endpoint, fingerprint) from None

    async def _request(
        self,
        method: str,
        endpoint: str,
        *,
        params: Mapping[str, str] | None = None,
        json_body: Mapping[str, Any] | None = None,
        fingerprint: str | None = None,
        attempts: int,
    ) -> bytes:
        for attempt in range(attempts):
            try:
                status, headers, content = await self._request_once(
                    method,
                    endpoint,
                    params=params,
                    json_body=json_body,
                    fingerprint=fingerprint,
                )
            except _ResponseStartedTransportFailure:
                if method != "GET" or attempt + 1 == attempts:
                    raise
                await self._sleep(min(0.2 * (2**attempt), _MAX_RETRY_AFTER_SECONDS))
                continue
            except TransportFailure:
                if attempt + 1 == attempts:
                    raise
                await self._sleep(min(0.2 * (2**attempt), _MAX_RETRY_AFTER_SECONDS))
                continue
            if status in _TRANSIENT_STATUSES and attempt + 1 < attempts:
                delay = _retry_after(headers, self._utcnow)
                await self._sleep(
                    delay
                    if delay is not None
                    else min(0.2 * (2**attempt), _MAX_RETRY_AFTER_SECONDS)
                )
                continue
            if status in {401, 403}:
                raise AuthenticationFailure(endpoint, status, fingerprint)
            if status == 404:
                raise NotFound(endpoint)
            if status < 200 or status >= 300:
                raise BackendFailure(endpoint, status, fingerprint)
            return content
        raise AssertionError("request retry loop exhausted")

    async def _cached(self, key: str, loader: Callable[[], Awaitable[T]]) -> T:
        ttl = self.settings.metadata_ttl_seconds
        now = self._clock()
        if ttl:
            cached = self._cache.get(key)
            if cached is not None and now - cached[0] < ttl:
                return cast(T, copy.deepcopy(cached[1]))
        async with self._cache_lock:
            now = self._clock()
            if ttl:
                cached = self._cache.get(key)
                if cached is not None and now - cached[0] < ttl:
                    return cast(T, copy.deepcopy(cached[1]))
            value = await loader()
            if ttl:
                self._cache[key] = (self._clock(), copy.deepcopy(value))
            return value

    async def _metadata_text(self, endpoint: str) -> str:
        async def load() -> str:
            content = await self._request("GET", endpoint, attempts=3)
            try:
                value = content.decode("utf-8").strip()
            except UnicodeDecodeError:
                raise IncompatibleBackend(endpoint, detail="non-UTF-8 metadata") from None
            if len(value) > 512:
                raise IncompatibleBackend(endpoint, detail="oversized scalar metadata")
            return value

        return await self._cached(endpoint, load)

    async def get_version(self) -> str:
        return await self._metadata_text("api/version")

    async def get_release_build(self) -> str:
        return await self._metadata_text("api/releaseBuild")

    async def _metadata_list(
        self,
        endpoint: str,
        *,
        params: Mapping[str, str] | None = None,
    ) -> list[dict[str, Any]]:
        key = endpoint if not params else f"{endpoint}?{json.dumps(dict(params), sort_keys=True)}"

        async def load() -> list[dict[str, Any]]:
            content = await self._request("GET", endpoint, params=params, attempts=3)
            value = _parse_json(content, endpoint, None)
            if not isinstance(value, list) or not all(isinstance(item, dict) for item in value):
                raise IncompatibleBackend(endpoint, detail="non-list metadata")
            return value

        return await self._cached(key, load)

    async def get_compilers(self) -> list[dict[str, Any]]:
        language = quote("c++", safe="")
        return await self._metadata_list(
            f"api/compilers/{language}",
            params={"fields": _COMPILER_FIELDS},
        )

    async def get_libraries(self) -> list[dict[str, Any]]:
        language = quote("c++", safe="")
        return await self._metadata_list(
            f"api/libraries/{language}",
            params={"fields": _LIBRARY_FIELDS},
        )

    async def get_tools(self) -> list[dict[str, Any]]:
        language = quote("c++", safe="")
        return await self._metadata_list(f"api/tools/{language}")

    async def compile(
        self,
        compiler_id: str,
        payload: Mapping[str, Any],
        fingerprint: str,
    ) -> dict[str, Any]:
        endpoint = f"api/compiler/{quote(compiler_id, safe='')}/compile"
        content = await self._request(
            "POST",
            endpoint,
            json_body=payload,
            fingerprint=fingerprint,
            attempts=2,
        )
        value = _parse_json(content, endpoint, fingerprint)
        if not isinstance(value, dict):
            raise IncompatibleBackend(endpoint, fingerprint, "a non-object compile response")
        if value.get("didExecute") is True or "execResult" in value:
            raise IncompatibleBackend(
                endpoint,
                fingerprint,
                "an unexpected program-execution result",
            )
        return value

    async def create_shortlink(self, payload: Mapping[str, Any]) -> dict[str, Any]:
        endpoint = "api/shortener"
        content = await self._request(
            "POST",
            endpoint,
            json_body=payload,
            attempts=1,
        )
        value = _parse_json(content, endpoint, None)
        if not isinstance(value, dict):
            raise IncompatibleBackend(endpoint, detail="a non-object shortener response")
        return value

    async def get_shortlink(self, shortlink_id: str) -> dict[str, Any]:
        endpoint = f"api/shortlinkinfo/{quote(shortlink_id, safe='')}"
        content = await self._request("GET", endpoint, attempts=3)
        value = _parse_json(content, endpoint, None)
        if not isinstance(value, dict):
            raise IncompatibleBackend(endpoint, detail="a non-object shortlink response")
        return value

    def shortlink_url(self, shortlink_id: str) -> str:
        return urljoin(self.settings.base_url, f"z/{quote(shortlink_id, safe='')}")

    async def get_opcode_documentation(
        self,
        instruction_set: str,
        opcode: str,
    ) -> dict[str, Any]:
        endpoint = f"api/asm/{quote(instruction_set, safe='')}/{quote(opcode, safe='')}"
        content = await self._request("GET", endpoint, attempts=3)
        value = _parse_json(content, endpoint, None)
        if not isinstance(value, dict):
            raise IncompatibleBackend(endpoint, detail="non-object opcode documentation")
        if isinstance(value.get("error"), str):
            raise NotFound(f"opcode {instruction_set}/{opcode}")
        return value
