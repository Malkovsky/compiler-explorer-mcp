from __future__ import annotations

import json
from collections.abc import AsyncIterator
from datetime import datetime, timedelta, timezone
from typing import Any

import anyio
import httpx
import pytest

import ce_analyzer_mcp.client as client_module
from ce_analyzer_mcp.__about__ import __version__
from ce_analyzer_mcp.client import (
    CompilerExplorerClient,
    _retry_after,
    build_compile_payload,
    build_shortlink_payload,
    canonical_request_fingerprint,
    serialize_argument_tokens,
)
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
    VirtualFile,
)


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


def _settings(**updates: Any) -> Settings:
    return Settings.model_validate(
        {
            "base_url": "https://ce.example.test/",
            "metadata_ttl_seconds": 0,
            **updates,
        }
    )


class ChunkStream(httpx.AsyncByteStream):
    def __init__(self, chunks: list[bytes], error: Exception | None = None) -> None:
        self._chunks = chunks
        self._error = error
        self.closed = False

    async def __aiter__(self) -> AsyncIterator[bytes]:
        for chunk in self._chunks:
            yield chunk
        if self._error is not None:
            raise self._error

    async def aclose(self) -> None:
        self.closed = True


def test_argument_token_serialization_is_shell_safe_and_deterministic() -> None:
    assert serialize_argument_tokens([]) == ""
    assert serialize_argument_tokens(["-O2", "-Wall"]) == "-O2 -Wall"
    assert serialize_argument_tokens(["-DNAME=hello world", "", "a'b"]) == (
        "'-DNAME=hello world' '' 'a'\"'\"'b'"
    )
    assert serialize_argument_tokens(["é", "$HOME", "*.cpp"]) == "'é' '$HOME' '*.cpp'"


def test_compile_payload_exact_camel_case_snapshot() -> None:
    payload = build_compile_payload(
        source=SourceBundle(
            source='#include "include/value.hpp"\nint main() { return value; }',
            files=[VirtualFile(path="include/value.hpp", content="constexpr int value = 7;")],
        ),
        compiler_arguments=["-std=c++23", "-DNAME=hello world"],
        libraries=[LibrarySelection(id="fmt", version="10.2.1")],
        filters=AssemblyFilters(
            comment_only=False,
            demangle=False,
            directives=False,
            intel=False,
            labels=False,
            library_code=True,
            trim=True,
            debug_calls=True,
        ),
        analyzers=[AnalyzerSelection(id="clangtidy", arguments=["--checks=*", "--fix=false"])],
        produce_optimization_output=True,
    )

    assert payload == {
        "source": '#include "include/value.hpp"\nint main() { return value; }',
        "options": {
            "userArguments": "-std=c++23 '-DNAME=hello world'",
            "compilerOptions": {
                "skipAsm": False,
                "skipPopArgs": True,
                "executorRequest": False,
                "overrides": [],
                "produceOptInfo": True,
            },
            "filters": {
                "binary": False,
                "binaryObject": False,
                "commentOnly": False,
                "demangle": False,
                "directives": False,
                "execute": False,
                "intel": False,
                "labels": False,
                "libraryCode": True,
                "trim": True,
                "debugCalls": True,
            },
            "tools": [{"id": "clangtidy", "args": "'--checks=*' --fix=false", "stdin": ""}],
            "libraries": [{"id": "fmt", "version": "10.2.1"}],
            "executeParameters": {"args": [], "stdin": "", "runtimeTools": []},
        },
        "lang": "c++",
        "allowStoreCodeDebug": False,
        "files": [{"filename": "include/value.hpp", "contents": "constexpr int value = 7;"}],
    }


def test_compile_payload_defaults_force_execution_binary_overrides_and_storage_off() -> None:
    payload = build_compile_payload(
        source=SourceBundle(source="int main() {}"),
        compiler_arguments=[],
        libraries=[],
        filters=AssemblyFilters(),
    )

    assert payload["lang"] == "c++"
    assert payload["allowStoreCodeDebug"] is False
    assert payload["files"] == []
    assert payload["options"]["tools"] == []
    assert payload["options"]["libraries"] == []
    assert payload["options"]["compilerOptions"] == {
        "skipAsm": False,
        "skipPopArgs": True,
        "executorRequest": False,
        "overrides": [],
        "produceOptInfo": False,
    }
    assert payload["options"]["filters"]["execute"] is False
    assert payload["options"]["filters"]["binary"] is False
    assert payload["options"]["filters"]["binaryObject"] is False
    assert payload["options"]["executeParameters"] == {
        "args": [],
        "stdin": "",
        "runtimeTools": [],
    }


def test_compile_payload_returns_fresh_nested_collections() -> None:
    kwargs = {
        "source": SourceBundle(source=""),
        "compiler_arguments": [],
        "libraries": [],
        "filters": AssemblyFilters(),
    }
    first = build_compile_payload(**kwargs)
    second = build_compile_payload(**kwargs)
    first["options"]["compilerOptions"]["overrides"].append({"dangerous": True})
    first["options"]["filters"]["execute"] = True

    assert second["options"]["compilerOptions"]["overrides"] == []
    assert second["options"]["filters"]["execute"] is False


def test_shortlink_payload_exact_client_state_snapshot() -> None:
    payload = build_shortlink_payload(
        SourceBundle(source="int answer() { return 42; }"),
        [
            ShortlinkCompilerConfiguration(
                compiler="g141",
                compiler_arguments=["-O2", "-DNAME=two words"],
                libraries=[LibrarySelection(id="fmt", version="110")],
                filters=AssemblyFilters(intel=False, trim=True),
            )
        ],
    )

    assert payload == {
        "sessions": [
            {
                "id": 1,
                "language": "c++",
                "source": "int answer() { return 42; }",
                "compilers": [
                    {
                        "id": "g141",
                        "options": "-O2 '-DNAME=two words'",
                        "libs": [{"name": "fmt", "ver": "110"}],
                        "filters": {
                            "binary": False,
                            "binaryObject": False,
                            "commentOnly": True,
                            "demangle": True,
                            "directives": True,
                            "execute": False,
                            "intel": False,
                            "labels": True,
                            "libraryCode": False,
                            "trim": True,
                            "debugCalls": False,
                        },
                    }
                ],
            }
        ]
    }


def test_canonical_fingerprint_has_a_stable_snapshot() -> None:
    payload = {
        "lang": "c++",
        "options": {"userArguments": "-O2"},
        "source": "int main() {}",
    }
    assert canonical_request_fingerprint("gcc-14", payload) == (
        "9804b848d894e190b4039c719921d7237f7c9e8e63b98d2186cc7a537bd7f16f"
    )


def test_canonical_fingerprint_ignores_mapping_order_but_not_semantic_inputs() -> None:
    first = {"é": {"b": 2, "a": 1}, "items": [1, 2]}
    reordered = {"items": [1, 2], "é": {"a": 1, "b": 2}}
    fingerprint = canonical_request_fingerprint("compiler", first)

    assert canonical_request_fingerprint("compiler", reordered) == fingerprint
    assert canonical_request_fingerprint("other-compiler", reordered) != fingerprint
    assert canonical_request_fingerprint("compiler", {**reordered, "items": [2, 1]}) != fingerprint
    assert len(fingerprint) == 64
    assert fingerprint == fingerprint.lower()


def test_canonical_fingerprint_rejects_non_json_finite_values() -> None:
    with pytest.raises(ValueError):
        canonical_request_fingerprint("gcc", {"invalid": float("nan")})


@pytest.mark.anyio
async def test_client_requires_context_and_context_lifecycle_is_single_use_at_a_time() -> None:
    client = CompilerExplorerClient(_settings(), transport=httpx.MockTransport(lambda _: None))
    with pytest.raises(RuntimeError, match="async context manager"):
        await client.get_version()

    await client.__aenter__()
    with pytest.raises(RuntimeError, match="entered twice"):
        await client.__aenter__()
    await client.close()
    await client.close()
    with pytest.raises(RuntimeError, match="async context manager"):
        await client.get_version()


@pytest.mark.anyio
async def test_http_client_construction_uses_tls_timeouts_limits_auth_and_no_redirects(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict[str, Any] = {}

    class FakeAsyncClient:
        def __init__(self, **kwargs: Any) -> None:
            captured.update(kwargs)

        async def aclose(self) -> None:
            captured["closed"] = True

    monkeypatch.setattr(client_module.httpx, "AsyncClient", FakeAsyncClient)
    settings = _settings(
        auth_token="secret",
        auth_header="X-Key",
        auth_scheme="",
        verify_tls=False,
        connect_timeout_seconds=1.5,
        read_timeout_seconds=7.25,
        max_concurrency=3,
    )
    client = CompilerExplorerClient(settings)

    async with client:
        assert captured["base_url"] == "https://ce.example.test/"
        assert captured["headers"] == {
            "Accept": "application/json",
            "User-Agent": f"ce-analyzer-mcp/{__version__}",
            "X-Key": "secret",
        }
        assert captured["verify"] is False
        assert captured["follow_redirects"] is False
        assert captured["timeout"].connect == 1.5
        assert captured["timeout"].pool == 1.5
        assert captured["timeout"].read == 7.25
        assert captured["timeout"].write == 7.25
        assert captured["limits"].max_connections == 3
        assert captured["limits"].max_keepalive_connections == 3
    assert captured["closed"] is True


@pytest.mark.anyio
async def test_get_paths_headers_query_fields_and_scalar_metadata() -> None:
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        path = request.url.path
        if path.endswith("/api/version"):
            return httpx.Response(200, content=b"  1.2.3\n")
        if path.endswith("/api/releaseBuild"):
            return httpx.Response(200, content=b"release-42")
        return httpx.Response(200, json=[])

    settings = _settings(
        base_url="https://ce.example.test/root/",
        auth_token="token-value",
        auth_header="X-Auth",
        auth_scheme="Token",
        connect_timeout_seconds=2.0,
        read_timeout_seconds=9.0,
    )
    async with CompilerExplorerClient(settings, transport=httpx.MockTransport(handler)) as client:
        assert await client.get_version() == "1.2.3"
        assert await client.get_release_build() == "release-42"
        assert await client.get_compilers() == []
        assert await client.get_libraries() == []
        assert await client.get_tools() == []

    assert [request.url.path for request in requests] == [
        "/root/api/version",
        "/root/api/releaseBuild",
        "/root/api/compilers/c++",
        "/root/api/libraries/c++",
        "/root/api/tools/c++",
    ]
    for request in requests:
        assert request.method == "GET"
        assert request.headers["accept"] == "application/json"
        assert request.headers["user-agent"] == f"ce-analyzer-mcp/{__version__}"
        assert request.headers["x-auth"] == "Token token-value"
        assert "content-type" not in request.headers
        assert request.extensions["timeout"] == {
            "connect": 2.0,
            "read": 9.0,
            "write": 9.0,
            "pool": 2.0,
        }
    assert "fields" in requests[2].url.params
    assert "compilerCategories" in requests[2].url.params["fields"]
    assert "libsArr" in requests[2].url.params["fields"]
    assert "fields" in requests[3].url.params
    assert "versions.hidden" in requests[3].url.params["fields"]
    assert not requests[4].url.params
    assert b"c%2B%2B" in requests[2].url.raw_path
    assert b"c%2B%2B" in requests[3].url.raw_path
    assert b"c%2B%2B" in requests[4].url.raw_path


@pytest.mark.anyio
async def test_compile_path_json_headers_body_and_encoded_compiler_id() -> None:
    seen: list[httpx.Request] = []
    payload = {"source": "private source", "lang": "c++"}

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(200, json={"code": 0, "didExecute": False})

    async with CompilerExplorerClient(
        _settings(), transport=httpx.MockTransport(handler)
    ) as client:
        result = await client.compile("gcc/14+custom", payload, "f" * 64)

    assert result == {"code": 0, "didExecute": False}
    assert len(seen) == 1
    request = seen[0]
    assert request.method == "POST"
    assert request.url.path == "/api/compiler/gcc/14+custom/compile"
    assert request.url.raw_path == b"/api/compiler/gcc%2F14%2Bcustom/compile"
    assert request.headers["accept"] == "application/json"
    assert request.headers["content-type"] == "application/json"
    assert json.loads(request.content) == payload


@pytest.mark.anyio
async def test_shortlink_create_get_paths_bodies_and_prefixed_public_url() -> None:
    requests: list[httpx.Request] = []
    state = {"sessions": [{"id": 1, "language": "c++", "source": "int f();"}]}

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        if request.method == "POST":
            return httpx.Response(200, json={"url": "https://ce.example.test/root/z/abc_123"})
        return httpx.Response(200, json=state)

    async with CompilerExplorerClient(
        _settings(base_url="https://ce.example.test/root/"),
        transport=httpx.MockTransport(handler),
    ) as client:
        assert await client.create_shortlink(state) == {
            "url": "https://ce.example.test/root/z/abc_123"
        }
        assert await client.get_shortlink("abc_123") == state
        assert client.shortlink_url("abc_123") == "https://ce.example.test/root/z/abc_123"

    assert [request.method for request in requests] == ["POST", "GET"]
    assert [request.url.path for request in requests] == [
        "/root/api/shortener",
        "/root/api/shortlinkinfo/abc_123",
    ]
    assert json.loads(requests[0].content) == state
    assert requests[1].content == b""


@pytest.mark.anyio
@pytest.mark.parametrize("value", [[], "text", 0, None])
async def test_shortlink_endpoints_require_json_objects(value: Any) -> None:
    def handler(_: httpx.Request) -> httpx.Response:
        return (
            httpx.Response(200, content=b"null")
            if value is None
            else httpx.Response(200, json=value)
        )

    async with CompilerExplorerClient(
        _settings(), transport=httpx.MockTransport(handler)
    ) as client:
        with pytest.raises(IncompatibleBackend, match="non-object shortener response"):
            await client.create_shortlink({"sessions": []})
        with pytest.raises(IncompatibleBackend, match="non-object shortlink response"):
            await client.get_shortlink("abc")


@pytest.mark.anyio
async def test_shortlink_creation_post_is_never_retried() -> None:
    calls = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        raise httpx.ConnectError("indeterminate storage", request=request)

    async with CompilerExplorerClient(
        _settings(), transport=httpx.MockTransport(handler)
    ) as client:
        with pytest.raises(TransportFailure):
            await client.create_shortlink({"sessions": []})

    assert calls == 1


@pytest.mark.anyio
async def test_shortlink_creation_transient_status_is_not_retried() -> None:
    calls = 0

    def handler(_: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(503)

    async with CompilerExplorerClient(
        _settings(), transport=httpx.MockTransport(handler)
    ) as client:
        with pytest.raises(BackendFailure, match="status 503"):
            await client.create_shortlink({"sessions": []})

    assert calls == 1


@pytest.mark.anyio
async def test_opcode_path_segments_are_encoded_and_error_payload_maps_to_not_found() -> None:
    paths: list[bytes] = []

    def handler(request: httpx.Request) -> httpx.Response:
        paths.append(request.url.raw_path)
        if len(paths) == 1:
            return httpx.Response(200, json={"tooltip": "move", "html": "<p>move</p>"})
        return httpx.Response(200, json={"error": "unknown internal detail"})

    async with CompilerExplorerClient(
        _settings(), transport=httpx.MockTransport(handler)
    ) as client:
        assert (await client.get_opcode_documentation("x86/64", "add+r0"))["tooltip"] == ("move")
        with pytest.raises(NotFound, match=r"opcode x86/64/add\+r0"):
            await client.get_opcode_documentation("x86/64", "add+r0")

    assert paths == [
        b"/api/asm/x86%2F64/add%2Br0",
        b"/api/asm/x86%2F64/add%2Br0",
    ]


@pytest.mark.anyio
@pytest.mark.parametrize("method", ["get_version", "get_release_build"])
async def test_scalar_metadata_rejects_non_utf8_and_oversized_values(method: str) -> None:
    responses = iter(
        [
            httpx.Response(200, content=b"\xff"),
            httpx.Response(200, content=b"x" * 513),
        ]
    )
    transport = httpx.MockTransport(lambda _: next(responses))
    async with CompilerExplorerClient(_settings(), transport=transport) as client:
        with pytest.raises(IncompatibleBackend, match="non-UTF-8 metadata"):
            await getattr(client, method)()
        with pytest.raises(IncompatibleBackend, match="oversized scalar metadata"):
            await getattr(client, method)()


@pytest.mark.anyio
@pytest.mark.parametrize(
    "body",
    [b"not-json", b'{"x": NaN}', b"\xff", b"[1, 2"],
)
async def test_metadata_rejects_malformed_or_nonstandard_json(body: bytes) -> None:
    async with CompilerExplorerClient(
        _settings(), transport=httpx.MockTransport(lambda _: httpx.Response(200, content=body))
    ) as client:
        with pytest.raises(IncompatibleBackend, match="malformed JSON"):
            await client.get_tools()


@pytest.mark.anyio
@pytest.mark.parametrize("value", [{}, [1], [None], ["item"], [{"valid": True}, 1]])
async def test_metadata_requires_a_list_of_objects(value: Any) -> None:
    async with CompilerExplorerClient(
        _settings(), transport=httpx.MockTransport(lambda _: httpx.Response(200, json=value))
    ) as client:
        with pytest.raises(IncompatibleBackend, match="non-list metadata"):
            await client.get_tools()


@pytest.mark.anyio
async def test_metadata_accepts_unknown_object_fields_without_mutating_json() -> None:
    value = [{"id": "gcc", "unknown": {"nested": [1, 2, 3]}}]
    async with CompilerExplorerClient(
        _settings(), transport=httpx.MockTransport(lambda _: httpx.Response(200, json=value))
    ) as client:
        assert await client.get_compilers() == value


@pytest.mark.anyio
@pytest.mark.parametrize("value", [[], "object", 42, None])
async def test_compile_requires_json_object(value: Any) -> None:
    def handler(_: httpx.Request) -> httpx.Response:
        if value is None:
            return httpx.Response(200, content=b"null")
        return httpx.Response(200, json=value)

    async with CompilerExplorerClient(
        _settings(), transport=httpx.MockTransport(handler)
    ) as client:
        with pytest.raises(IncompatibleBackend, match="non-object compile response"):
            await client.compile("gcc", {}, "abc123")


@pytest.mark.anyio
@pytest.mark.parametrize(
    "value",
    [
        {"didExecute": True},
        {"execResult": {}},
        {"didExecute": False, "execResult": None},
    ],
)
async def test_compile_refuses_any_execution_result(value: dict[str, Any]) -> None:
    async with CompilerExplorerClient(
        _settings(), transport=httpx.MockTransport(lambda _: httpx.Response(200, json=value))
    ) as client:
        with pytest.raises(IncompatibleBackend, match="unexpected program-execution result"):
            await client.compile("gcc", {}, "abc123")


@pytest.mark.anyio
@pytest.mark.parametrize("value", [[], "text", 0, None])
async def test_opcode_documentation_requires_json_object(value: Any) -> None:
    def handler(_: httpx.Request) -> httpx.Response:
        if value is None:
            return httpx.Response(200, content=b"null")
        return httpx.Response(200, json=value)

    async with CompilerExplorerClient(
        _settings(), transport=httpx.MockTransport(handler)
    ) as client:
        with pytest.raises(IncompatibleBackend, match="non-object opcode documentation"):
            await client.get_opcode_documentation("x86-64", "mov")


@pytest.mark.anyio
async def test_declared_content_length_is_rejected_before_stream_read() -> None:
    stream = ChunkStream([b"should-not-be-read"])

    def handler(_: httpx.Request) -> httpx.Response:
        return httpx.Response(200, headers={"Content-Length": "11"}, stream=stream)

    async with CompilerExplorerClient(
        _settings(), transport=httpx.MockTransport(handler), max_response_bytes=10
    ) as client:
        with pytest.raises(ResponseTooLarge):
            await client.get_tools()
    assert stream.closed is True


@pytest.mark.anyio
async def test_streamed_body_is_bounded_even_without_valid_content_length() -> None:
    streams: list[ChunkStream] = []

    def handler(_: httpx.Request) -> httpx.Response:
        stream = ChunkStream([b"12345", b"67890", b"X"])
        streams.append(stream)
        return httpx.Response(200, headers={"Content-Length": "invalid"}, stream=stream)

    async with CompilerExplorerClient(
        _settings(), transport=httpx.MockTransport(handler), max_response_bytes=10
    ) as client:
        with pytest.raises(ResponseTooLarge):
            await client.get_tools()
    assert len(streams) == 1
    assert streams[0].closed is True


@pytest.mark.anyio
@pytest.mark.parametrize(
    ("status", "error_type"),
    [
        (401, AuthenticationFailure),
        (403, AuthenticationFailure),
        (404, NotFound),
        (400, BackendFailure),
        (418, BackendFailure),
        (500, BackendFailure),
    ],
)
async def test_http_status_mapping_does_not_expose_response_body_or_headers(
    status: int, error_type: type[Exception]
) -> None:
    source = "private-source-marker"
    token = "private-token-marker"

    def handler(_: httpx.Request) -> httpx.Response:
        return httpx.Response(
            status,
            headers={"X-Backend-Secret": token},
            content=f"backend echoed {source} and {token}".encode(),
        )

    async with CompilerExplorerClient(
        _settings(auth_token=token), transport=httpx.MockTransport(handler)
    ) as client:
        with pytest.raises(error_type) as raised:
            await client.compile("gcc", {"source": source}, "deadbeef")

    message = str(raised.value)
    assert source not in message
    assert token not in message
    if status != 404:
        assert "deadbeef" in message
        assert str(status) in message


@pytest.mark.anyio
@pytest.mark.parametrize("status", [301, 302, 307, 308])
async def test_redirects_are_never_followed_including_to_another_origin(status: int) -> None:
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(status, headers={"Location": "https://attacker.example/steal"})

    async with CompilerExplorerClient(
        _settings(auth_token="do-not-forward"), transport=httpx.MockTransport(handler)
    ) as client:
        with pytest.raises(BackendFailure, match=f"status {status}"):
            await client.get_version()

    assert len(requests) == 1
    assert requests[0].url.host == "ce.example.test"


@pytest.mark.anyio
async def test_metadata_transport_retries_use_bounded_exponential_backoff() -> None:
    calls = 0
    sleeps: list[float] = []

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        if calls < 3:
            raise httpx.ConnectError("connection failed", request=request)
        return httpx.Response(200, json=[])

    async def sleep(delay: float) -> None:
        sleeps.append(delay)

    async with CompilerExplorerClient(
        _settings(), transport=httpx.MockTransport(handler), sleep=sleep
    ) as client:
        assert await client.get_tools() == []

    assert calls == 3
    assert sleeps == [0.2, 0.4]


@pytest.mark.anyio
@pytest.mark.parametrize("status", [429, 502, 503, 504])
async def test_metadata_retries_each_explicit_transient_status(status: int) -> None:
    calls = 0
    sleeps: list[float] = []

    def handler(_: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(status if calls == 1 else 200, json=[])

    async with CompilerExplorerClient(
        _settings(),
        transport=httpx.MockTransport(handler),
        sleep=lambda delay: _record_sleep(sleeps, delay),
    ) as client:
        assert await client.get_compilers() == []

    assert calls == 2
    assert sleeps == [0.2]


async def _record_sleep(delays: list[float], delay: float) -> None:
    delays.append(delay)


@pytest.mark.parametrize(
    ("header", "expected"),
    [
        ("0", 0.0),
        ("-5", 0.0),
        ("0.75", 0.75),
        ("120", 2.0),
        ("inf", None),
        ("NaN", None),
        ("invalid", None),
    ],
)
def test_retry_after_numeric_values_are_normalized_and_capped(
    header: str, expected: float | None
) -> None:
    now = datetime(2026, 8, 10, tzinfo=timezone.utc)
    assert _retry_after({"retry-after": header}, lambda: now) == expected


def test_retry_after_http_dates_are_normalized_and_capped() -> None:
    now = datetime(2026, 8, 10, 0, 0, 0, tzinfo=timezone.utc)
    assert _retry_after({"retry-after": "Mon, 10 Aug 2026 00:00:01 GMT"}, lambda: now) == 1.0
    assert _retry_after({"retry-after": "Mon, 10 Aug 2026 00:10:00 GMT"}, lambda: now) == 2.0
    assert _retry_after({"retry-after": "Sun, 09 Aug 2026 23:59:00 GMT"}, lambda: now) == 0.0
    assert _retry_after({}, lambda: now) is None


@pytest.mark.anyio
async def test_retry_after_header_controls_actual_delay_and_is_capped() -> None:
    calls = 0
    sleeps: list[float] = []

    def handler(_: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        if calls == 1:
            return httpx.Response(429, headers={"Retry-After": "999"})
        return httpx.Response(200, json=[])

    async with CompilerExplorerClient(
        _settings(),
        transport=httpx.MockTransport(handler),
        sleep=lambda delay: _record_sleep(sleeps, delay),
    ) as client:
        await client.get_libraries()

    assert sleeps == [2.0]


@pytest.mark.anyio
async def test_final_transient_status_is_not_retried_forever() -> None:
    calls = 0
    sleeps: list[float] = []

    def handler(_: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(503)

    async with CompilerExplorerClient(
        _settings(),
        transport=httpx.MockTransport(handler),
        sleep=lambda delay: _record_sleep(sleeps, delay),
    ) as client:
        with pytest.raises(BackendFailure, match="status 503"):
            await client.get_tools()

    assert calls == 3
    assert sleeps == [0.2, 0.4]


@pytest.mark.anyio
@pytest.mark.parametrize("failure", ["transport", 429, 502, 503, 504])
async def test_compile_retries_once_for_pre_response_or_explicit_transient_failure(
    failure: str | int,
) -> None:
    calls = 0
    sleeps: list[float] = []

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        if calls == 1:
            if failure == "transport":
                raise httpx.ConnectError("not connected", request=request)
            return httpx.Response(failure)
        return httpx.Response(200, json={"code": 0})

    async with CompilerExplorerClient(
        _settings(),
        transport=httpx.MockTransport(handler),
        sleep=lambda delay: _record_sleep(sleeps, delay),
    ) as client:
        assert await client.compile("gcc", {}, "fingerprint") == {"code": 0}

    assert calls == 2
    assert sleeps == [0.2]


@pytest.mark.anyio
async def test_compile_does_not_retry_non_transient_response() -> None:
    calls = 0

    def handler(_: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(500, content=b"source and token")

    async with CompilerExplorerClient(
        _settings(), transport=httpx.MockTransport(handler)
    ) as client:
        with pytest.raises(BackendFailure):
            await client.compile("gcc", {"source": "private"}, "fingerprint")
    assert calls == 1


@pytest.mark.anyio
async def test_compile_does_not_retry_transport_failure_after_response_started() -> None:
    calls = 0

    def handler(_: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(
            200,
            stream=ChunkStream(
                [b'{"partial":'],
                httpx.ReadTimeout("timed out while reading response"),
            ),
        )

    async with CompilerExplorerClient(
        _settings(), transport=httpx.MockTransport(handler), sleep=lambda _: _no_sleep()
    ) as client:
        with pytest.raises(TransportFailure):
            await client.compile("gcc", {"source": "private"}, "fingerprint")

    assert calls == 1


async def _no_sleep() -> None:
    return None


@pytest.mark.anyio
async def test_authentication_and_response_size_failures_are_not_retried() -> None:
    auth_calls = 0
    size_calls = 0

    def auth_handler(_: httpx.Request) -> httpx.Response:
        nonlocal auth_calls
        auth_calls += 1
        return httpx.Response(401)

    def size_handler(_: httpx.Request) -> httpx.Response:
        nonlocal size_calls
        size_calls += 1
        return httpx.Response(200, content=b"123456")

    async with CompilerExplorerClient(
        _settings(), transport=httpx.MockTransport(auth_handler)
    ) as client:
        with pytest.raises(AuthenticationFailure):
            await client.get_tools()
    async with CompilerExplorerClient(
        _settings(), transport=httpx.MockTransport(size_handler), max_response_bytes=5
    ) as client:
        with pytest.raises(ResponseTooLarge):
            await client.get_tools()

    assert auth_calls == 1
    assert size_calls == 1


@pytest.mark.anyio
async def test_transport_error_is_sanitized_and_preserves_only_endpoint_and_fingerprint() -> None:
    token = "transport-secret-token"
    source = "transport-secret-source"

    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError(
            f"could not send {token} or {source}",
            request=request,
        )

    async with CompilerExplorerClient(
        _settings(auth_token=token),
        transport=httpx.MockTransport(handler),
        sleep=lambda _: _no_sleep(),
    ) as client:
        with pytest.raises(TransportFailure) as raised:
            await client.compile("gcc", {"source": source}, "safe-fingerprint")

    message = str(raised.value)
    assert "api/compiler/gcc/compile" in message
    assert "safe-fingerprint" in message
    assert source not in message
    assert token not in message


@pytest.mark.anyio
async def test_metadata_cache_ttl_deep_copies_hits_and_refreshes_at_expiry() -> None:
    calls = 0
    now = [100.0]

    def handler(_: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(200, json=[{"id": f"tool-{calls}"}])

    async with CompilerExplorerClient(
        _settings(metadata_ttl_seconds=10),
        transport=httpx.MockTransport(handler),
        clock=lambda: now[0],
    ) as client:
        first = await client.get_tools()
        first[0]["id"] = "mutated"
        first.append({"id": "injected"})

        now[0] = 109.999
        second = await client.get_tools()
        assert second == [{"id": "tool-1"}]
        assert second is not first

        now[0] = 110.0
        third = await client.get_tools()
        assert third == [{"id": "tool-2"}]

    assert calls == 2


@pytest.mark.anyio
async def test_zero_metadata_ttl_disables_cache() -> None:
    calls = 0

    def handler(_: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(200, json=[])

    async with CompilerExplorerClient(
        _settings(metadata_ttl_seconds=0), transport=httpx.MockTransport(handler)
    ) as client:
        await client.get_version()
        await client.get_version()
        await client.get_compilers()
        await client.get_compilers()

    assert calls == 4


@pytest.mark.anyio
async def test_cache_key_includes_metadata_query_parameters_and_endpoint() -> None:
    calls: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(str(request.url))
        return httpx.Response(200, json=[])

    async with CompilerExplorerClient(
        _settings(metadata_ttl_seconds=60), transport=httpx.MockTransport(handler)
    ) as client:
        await client._metadata_list("api/custom", params={"b": "2", "a": "1"})
        await client._metadata_list("api/custom", params={"a": "1", "b": "2"})
        await client._metadata_list("api/other", params={"a": "1", "b": "2"})

    assert len(calls) == 2


@pytest.mark.anyio
async def test_cache_lock_coalesces_concurrent_metadata_loads() -> None:
    calls = 0

    async def handler(_: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        await anyio.sleep(0.01)
        return httpx.Response(200, json=[{"id": "one"}])

    results: list[list[dict[str, Any]]] = []
    async with (
        CompilerExplorerClient(
            _settings(metadata_ttl_seconds=60), transport=httpx.MockTransport(handler)
        ) as client,
        anyio.create_task_group() as task_group,
    ):
        for _ in range(8):
            task_group.start_soon(_append_tools, client, results)

    assert calls == 1
    assert results == [[{"id": "one"}]] * 8
    assert len({id(result) for result in results}) == 8


async def _append_tools(
    client: CompilerExplorerClient, results: list[list[dict[str, Any]]]
) -> None:
    results.append(await client.get_tools())


@pytest.mark.anyio
async def test_global_semaphore_caps_concurrent_compile_requests() -> None:
    active = 0
    maximum_active = 0

    async def handler(_: httpx.Request) -> httpx.Response:
        nonlocal active, maximum_active
        active += 1
        maximum_active = max(maximum_active, active)
        await anyio.sleep(0.01)
        active -= 1
        return httpx.Response(200, json={"code": 0})

    async with (
        CompilerExplorerClient(
            _settings(max_concurrency=2), transport=httpx.MockTransport(handler)
        ) as client,
        anyio.create_task_group() as task_group,
    ):
        for index in range(8):
            task_group.start_soon(
                client.compile,
                f"compiler-{index}",
                {},
                f"fingerprint-{index}",
            )

    assert maximum_active == 2


def test_retry_after_naive_http_date_uses_utc(monkeypatch: pytest.MonkeyPatch) -> None:
    now = datetime(2026, 8, 10, tzinfo=timezone.utc)
    monkeypatch.setattr(
        client_module,
        "parsedate_to_datetime",
        lambda _: (now + timedelta(seconds=1)).replace(tzinfo=None),
    )
    assert _retry_after({"retry-after": "date"}, lambda: now) == 1.0
