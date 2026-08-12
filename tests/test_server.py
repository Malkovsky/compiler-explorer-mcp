from __future__ import annotations

import asyncio
import json
from collections.abc import AsyncIterator, Coroutine
from contextlib import asynccontextmanager
from typing import Any, TypeVar

from mcp import Client
from mcp.server import MCPServer

from ce_analyzer_mcp.config import Settings
from ce_analyzer_mcp.errors import SelectionError
from ce_analyzer_mcp.models import (
    AliasResolution,
    AnalyzeCppRequest,
    AnalyzeResult,
    AnalyzerInfo,
    AnalyzerRunResult,
    AnalyzerSearchResult,
    AssemblyComparison,
    AssemblyLine,
    CompareCaseResult,
    CompareCppRequest,
    CompareResult,
    CompileCppRequest,
    CompileResult,
    CompilerIdentity,
    CompilerInfo,
    CompilerSearchResult,
    CreateShortlinkRequest,
    CreateShortlinkResult,
    DiagnosticLine,
    GetShortlinkRequest,
    GetShortlinkResult,
    LibraryInfo,
    LibrarySearchResult,
    OpcodeDocumentation,
    OpcodeDocumentationRequest,
    OptimizationRecord,
    Page,
    PageInfo,
    SearchAnalyzersRequest,
    SearchCompilersRequest,
    SearchLibrariesRequest,
    ShortlinkCompilerValidation,
    ShortlinkSessionInfo,
    WarningItem,
)
from ce_analyzer_mcp.server import (
    AppState,
    _structured_text_fallback,
    create_server,
    mcp,
    server,
)

T = TypeVar("T")


def test_structured_text_fallback_mirrors_small_results_and_bounds_large_ones() -> None:
    small = {"value": "visible"}
    assert json.loads(_structured_text_fallback(small)) == small

    summary = json.loads(_structured_text_fallback({"value": "x" * 128_000}))
    assert summary["structuredContentAvailable"] is True
    assert summary["textOmitted"] is True
    assert summary["serializedBytes"] > 128_000


TOOL_NAMES = [
    "search_compilers",
    "search_libraries",
    "search_analyzers",
    "compile_cpp",
    "compare_cpp",
    "analyze_cpp",
    "create_shortlink",
    "get_shortlink",
    "get_opcode_documentation",
]


def _run(coroutine: Coroutine[Any, Any, T]) -> T:
    return asyncio.run(coroutine)


def _page(items: list[T], *, offset: int = 0, limit: int = 20) -> Page[T]:
    return Page[T](
        items=items,
        page=PageInfo(
            offset=offset,
            limit=limit,
            total=len(items),
            returned=len(items),
            truncated_before=False,
            truncated_after=False,
        ),
    )


def _identity(requested: str = "gcc-latest", resolved: str = "g++-15") -> CompilerIdentity:
    return CompilerIdentity(
        requested_selector=requested,
        resolved_id=resolved,
        name="Offline GCC 15",
        version="15.1.0",
    )


class FakeWorkflows:
    def __init__(self) -> None:
        self.calls: list[tuple[str, object]] = []

    async def search_compilers(self, request: SearchCompilersRequest) -> CompilerSearchResult:
        self.calls.append(("search_compilers", request))
        if request.query == "domain-error":
            raise SelectionError("offline compiler selection failed safely")
        return CompilerSearchResult(
            compilers=_page(
                [
                    CompilerInfo(
                        id="g++-15",
                        name="Offline GCC 15",
                        family="gcc",
                        version="15.1.0",
                        instruction_set="x86-64",
                        aliases=["gcc-latest"],
                    )
                ],
                offset=request.offset,
                limit=request.limit,
            ),
            aliases=[
                AliasResolution(
                    alias="gcc-latest",
                    status="resolved",
                    resolved_id="g++-15",
                    resolved_name="Offline GCC 15",
                )
            ],
        )

    async def search_libraries(self, request: SearchLibrariesRequest) -> LibrarySearchResult:
        self.calls.append(("search_libraries", request))
        return LibrarySearchResult(
            libraries=_page(
                [
                    LibraryInfo(
                        id="fmt",
                        name="fmt",
                        version_id="110",
                        version="11.0.0",
                    )
                ],
                offset=request.offset,
                limit=request.limit,
            )
        )

    async def search_analyzers(self, request: SearchAnalyzersRequest) -> AnalyzerSearchResult:
        self.calls.append(("search_analyzers", request))
        compiler = _identity(request.compiler, "clang-20") if request.compiler else None
        return AnalyzerSearchResult(
            analyzers=_page(
                [
                    AnalyzerInfo(
                        id="clangtidy",
                        name="clang-tidy",
                        aliases=["clang-tidy"],
                        compiler_compatible=True if request.compiler else None,
                    )
                ],
                offset=request.offset,
                limit=request.limit,
            ),
            aliases=[
                AliasResolution(
                    alias="clang-tidy",
                    status="resolved",
                    resolved_id="clangtidy",
                    resolved_name="clang-tidy",
                )
            ],
            compiler=compiler,
        )

    async def compile_cpp(self, request: CompileCppRequest) -> CompileResult:
        self.calls.append(("compile_cpp", request))
        diagnostics = (
            _page(
                [DiagnosticLine(stream="stderr", text="offline warning")],
                offset=request.window.offset,
                limit=request.window.limit,
            )
            if request.include_diagnostics
            else None
        )
        assembly = (
            _page(
                (
                    [AssemblyLine(text="mov eax, 7"), AssemblyLine(text="ret")]
                    if request.assembly_format == "detailed"
                    else ["mov eax, 7", "ret"]
                ),
                offset=request.window.offset,
                limit=request.window.limit,
            )
            if request.include_assembly
            else None
        )
        optimization = (
            _page(
                [OptimizationRecord(display="offline optimization")],
                offset=request.window.offset,
                limit=request.window.limit,
            )
            if request.include_optimization
            else None
        )
        return CompileResult(
            fingerprint="c" * 64,
            compiler=_identity(request.compiler),
            status="success",
            exit_code=0,
            timed_out=False,
            diagnostics=diagnostics,
            assembly=assembly,
            optimization=optimization,
            assembly_line_count=2,
            assembly_sha256="a" * 64,
        )

    async def compare_cpp(self, request: CompareCppRequest) -> CompareResult:
        self.calls.append(("compare_cpp", request))
        cases = [
            CompareCaseResult(
                label=case.label,
                fingerprint=(str(index) * 64)[:64],
                compiler=_identity(case.compiler, f"compiler-{index}"),
                status="success",
                exit_code=0,
                timed_out=False,
                diagnostics=_page(
                    [],
                    offset=request.window.offset,
                    limit=request.window.limit,
                ),
                assembly_line_count=1,
                assembly_sha256=(chr(97 + index) * 64),
            )
            for index, case in enumerate(request.cases)
        ]
        baseline = request.cases[0]
        comparisons = [
            AssemblyComparison(
                baseline_label=baseline.label,
                candidate_label=case.label,
                baseline_sha256="a" * 64,
                candidate_sha256=(chr(97 + index) * 64),
                identical=index == 0,
                diff=_page(
                    [] if index == 0 else ["--- baseline", "+++ candidate"],
                    offset=request.window.offset,
                    limit=request.window.limit,
                ),
                baseline_input_line_count=1,
                candidate_input_line_count=1,
            )
            for index, case in enumerate(request.cases[1:], start=1)
        ]
        return CompareResult(
            cases=cases,
            comparisons=comparisons,
            benchmark_warning=WarningItem(
                code="not_a_benchmark",
                message="Assembly differences are not performance measurements.",
            ),
        )

    async def analyze_cpp(self, request: AnalyzeCppRequest) -> AnalyzeResult:
        self.calls.append(("analyze_cpp", request))
        return AnalyzeResult(
            fingerprint="d" * 64,
            compiler=_identity(request.compiler, "clang-20"),
            status="success",
            exit_code=0,
            timed_out=False,
            diagnostics=_page(
                [],
                offset=request.window.offset,
                limit=request.window.limit,
            ),
            analyzers=[
                AnalyzerRunResult(
                    requested_selector=selection.id,
                    resolved_id=f"exact-{index}",
                    name=f"Offline analyzer {index}",
                    status="success",
                    exit_code=0,
                    output=_page(
                        [DiagnosticLine(stream="stdout", text=f"analyzer {index} ok")],
                        offset=request.window.offset,
                        limit=request.window.limit,
                    ),
                )
                for index, selection in enumerate(request.analyzers)
            ],
        )

    async def get_opcode_documentation(
        self,
        request: OpcodeDocumentationRequest,
    ) -> OpcodeDocumentation:
        self.calls.append(("get_opcode_documentation", request))
        return OpcodeDocumentation(
            instruction_set=request.instruction_set,
            opcode=request.opcode,
            tooltip="offline move instruction",
            html="<p>offline move instruction</p>",
            source_url="https://example.test/opcodes/mov",
        )

    async def create_shortlink(self, request: CreateShortlinkRequest) -> CreateShortlinkResult:
        self.calls.append(("create_shortlink", request))
        return CreateShortlinkResult(
            shortlink_id="offline123",
            url="https://example.test/z/offline123",
            compilers=[
                ShortlinkCompilerValidation(
                    compiler=_identity(configuration.compiler),
                    fingerprint="e" * 64 if request.validate_compilation else None,
                    status="success" if request.validate_compilation else "not_run",
                    exit_code=0 if request.validate_compilation else None,
                )
                for configuration in request.compilers
            ],
            compilation_validated=request.validate_compilation,
        )

    async def get_shortlink(self, request: GetShortlinkRequest) -> GetShortlinkResult:
        self.calls.append(("get_shortlink", request))
        return GetShortlinkResult(
            shortlink_id=request.shortlink_id,
            url=f"https://example.test/z/{request.shortlink_id}",
            sessions=[
                ShortlinkSessionInfo(
                    session_id=1,
                    source="int restored_from_shortlink();\n",
                )
            ],
        )


def _offline_server() -> tuple[MCPServer[Any], FakeWorkflows]:
    workflows = FakeWorkflows()

    @asynccontextmanager
    async def lifespan(_: MCPServer[Any]) -> AsyncIterator[AppState]:
        yield AppState(
            settings=Settings(),
            client=object(),  # type: ignore[arg-type]
            catalog=object(),  # type: ignore[arg-type]
            workflows=workflows,  # type: ignore[arg-type]
        )

    return create_server(lifespan), workflows


def _error_text(result: Any) -> str:
    return "\n".join(block.text for block in result.content if hasattr(block, "text"))


def test_module_level_server_identity_and_alias() -> None:
    assert isinstance(mcp, MCPServer)
    assert server is mcp
    assert mcp.name == "ce-analyzer-mcp"
    assert mcp.title == "Compiler Explorer C++ Analyzer"
    assert mcp.version == "0.1.0"
    assert "transmit supplied source" in (mcp.instructions or "")


def test_in_memory_client_lists_exactly_nine_strict_structured_tools() -> None:
    offline_server, _ = _offline_server()

    async def exercise() -> None:
        async with Client(offline_server) as client:
            listing = await client.list_tools(cache_mode="bypass")

        assert [tool.name for tool in listing.tools] == TOOL_NAMES
        required = {
            "search_compilers": set(),
            "search_libraries": set(),
            "search_analyzers": set(),
            "compile_cpp": {"source"},
            "compare_cpp": {"source", "cases"},
            "analyze_cpp": {"source", "analyzers"},
            "create_shortlink": {"source"},
            "get_shortlink": {"shortlink_id"},
            "get_opcode_documentation": {"instruction_set", "opcode"},
        }
        for tool in listing.tools:
            assert tool.description is not None
            assert tool.annotations is not None
            assert tool.annotations.read_only_hint is (tool.name != "create_shortlink")
            assert tool.annotations.destructive_hint is False
            assert tool.annotations.idempotent_hint is (tool.name != "create_shortlink")
            assert tool.annotations.open_world_hint is True
            assert tool.input_schema["type"] == "object"
            assert tool.input_schema.get("additionalProperties") is False
            assert set(tool.input_schema.get("required", [])) == required[tool.name]
            assert tool.output_schema is not None
            assert tool.output_schema["type"] == "object"
            assert tool.output_schema["additionalProperties"] is False
            assert tool.output_schema["title"].endswith("Result") or tool.name == (
                "get_opcode_documentation"
            )

    _run(exercise())


def test_representative_calls_for_all_tools_return_typed_structured_output() -> None:
    offline_server, workflows = _offline_server()
    source_marker = "MCP_SOURCE_MUST_NOT_ECHO_50ec"

    async def exercise() -> dict[str, Any]:
        async with Client(offline_server) as client:
            return {
                "search_compilers": await client.call_tool(
                    "search_compilers", {"query": "gcc", "offset": 0, "limit": 5}
                ),
                "search_libraries": await client.call_tool(
                    "search_libraries", {"query": "fmt", "limit": 5}
                ),
                "search_analyzers": await client.call_tool(
                    "search_analyzers",
                    {"query": "tidy", "compiler": "clang-latest", "limit": 5},
                ),
                "compile_cpp": await client.call_tool(
                    "compile_cpp",
                    {
                        "source": f"int {source_marker}() {{ return 7; }}",
                        "compiler": "gcc-latest",
                        "files": [{"path": "include/value.hpp", "content": "#define V 7"}],
                        "compiler_arguments": ["-O2", "-Wall"],
                        "libraries": [{"id": "fmt", "version": "110"}],
                        "filters": {"intel": False, "trim": True},
                        "assembly_format": "text",
                        "include_optimization": True,
                        "window": {"offset": 0, "limit": 3},
                    },
                ),
                "compare_cpp": await client.call_tool(
                    "compare_cpp",
                    {
                        "source": f"int {source_marker}_compare() {{ return 7; }}",
                        "cases": [
                            {"label": "baseline", "compiler": "gcc-latest"},
                            {
                                "label": "candidate",
                                "compiler": "clang-latest",
                                "compiler_arguments": ["-O3"],
                            },
                        ],
                        "window": {"limit": 10},
                    },
                ),
                "analyze_cpp": await client.call_tool(
                    "analyze_cpp",
                    {
                        "source": f"int {source_marker}_analyze() {{ return 7; }}",
                        "compiler": "clang-latest",
                        "analyzers": [
                            {"id": "clang-tidy", "arguments": ["--checks=* "]},
                            {"id": "iwyu", "arguments": []},
                        ],
                        "window": {"limit": 2},
                    },
                ),
                "create_shortlink": await client.call_tool(
                    "create_shortlink",
                    {
                        "source": f"int {source_marker}_share() {{ return 7; }}",
                        "compilers": [
                            {"compiler": "gcc-latest", "compiler_arguments": ["-O2"]},
                            {"compiler": "clang-latest", "compiler_arguments": ["-O3"]},
                        ],
                    },
                ),
                "get_shortlink": await client.call_tool(
                    "get_shortlink",
                    {"shortlink_id": "offline123"},
                ),
                "get_opcode_documentation": await client.call_tool(
                    "get_opcode_documentation",
                    {"instruction_set": "x86-64", "opcode": "mov"},
                ),
            }

    results = _run(exercise())

    expected_top_level = {
        "search_compilers": "compilers",
        "search_libraries": "libraries",
        "search_analyzers": "analyzers",
        "compile_cpp": "fingerprint",
        "compare_cpp": "comparisons",
        "analyze_cpp": "fingerprint",
        "create_shortlink": "shortlink_id",
        "get_shortlink": "sessions",
        "get_opcode_documentation": "tooltip",
    }
    for name, result in results.items():
        assert result.is_error is False, _error_text(result)
        assert isinstance(result.structured_content, dict)
        assert expected_top_level[name] in result.structured_content
        assert result.content
        assert json.loads(_error_text(result)) == result.structured_content
        assert source_marker not in json.dumps(result.structured_content, sort_keys=True)

    assert [name for name, _ in workflows.calls] == TOOL_NAMES
    requests = {name: request for name, request in workflows.calls}
    assert isinstance(requests["search_compilers"], SearchCompilersRequest)
    assert isinstance(requests["search_libraries"], SearchLibrariesRequest)
    assert isinstance(requests["search_analyzers"], SearchAnalyzersRequest)
    compile_request = requests["compile_cpp"]
    assert isinstance(compile_request, CompileCppRequest)
    assert compile_request.source.files[0].path == "include/value.hpp"
    assert compile_request.filters.intel is False
    assert compile_request.filters.trim is True
    assert compile_request.assembly_format == "text"
    assert compile_request.include_optimization is True
    compare_request = requests["compare_cpp"]
    assert isinstance(compare_request, CompareCppRequest)
    assert [case.label for case in compare_request.cases] == ["baseline", "candidate"]
    analyze_request = requests["analyze_cpp"]
    assert isinstance(analyze_request, AnalyzeCppRequest)
    assert [selection.id for selection in analyze_request.analyzers] == ["clang-tidy", "iwyu"]
    create_request = requests["create_shortlink"]
    assert isinstance(create_request, CreateShortlinkRequest)
    assert [configuration.compiler for configuration in create_request.compilers] == [
        "gcc-latest",
        "clang-latest",
    ]
    get_request = requests["get_shortlink"]
    assert isinstance(get_request, GetShortlinkRequest)
    assert get_request.shortlink_id == "offline123"
    opcode_request = requests["get_opcode_documentation"]
    assert isinstance(opcode_request, OpcodeDocumentationRequest)
    assert opcode_request.instruction_set == "x86-64"


def test_mcp_validation_failures_are_bounded_tool_errors() -> None:
    offline_server, workflows = _offline_server()

    invalid_calls: list[tuple[str, dict[str, Any], str]] = [
        ("search_compilers", {"limit": 51}, "less than or equal to 50"),
        ("compile_cpp", {}, "source"),
        ("compile_cpp", {"source": "bad\x00source"}, "must not contain NUL"),
        (
            "compile_cpp",
            {"source": "int x;", "files": [{"path": "../secret", "content": "x"}]},
            "parent segments",
        ),
        (
            "compare_cpp",
            {"source": "int x;", "cases": [{"label": "only", "compiler": "gcc-latest"}]},
            "at least 2",
        ),
        ("analyze_cpp", {"source": "int x;", "analyzers": []}, "at least 1"),
        ("create_shortlink", {"source": "int x;", "compilers": []}, "at least 1"),
        ("get_shortlink", {"shortlink_id": "https://evil.test/z/x"}, "malformed"),
        (
            "get_opcode_documentation",
            {"instruction_set": "x86/64", "opcode": "mov"},
            "malformed",
        ),
    ]

    async def exercise() -> list[tuple[Any, str]]:
        observed: list[tuple[Any, str]] = []
        async with Client(offline_server) as client:
            for name, arguments, expected in invalid_calls:
                observed.append((await client.call_tool(name, arguments), expected))
        return observed

    for result, expected in _run(exercise()):
        assert result.is_error is True
        text = _error_text(result)
        assert expected in text
        assert len(text) < 2_000
    assert workflows.calls == []


def test_mcp_rejects_unknown_outer_arguments_instead_of_silently_ignoring_them() -> None:
    offline_server, workflows = _offline_server()

    async def exercise() -> Any:
        async with Client(offline_server) as client:
            return await client.call_tool(
                "compile_cpp",
                {"source": "int main(){}", "execute": True, "backend_url": "https://evil.test"},
            )

    result = _run(exercise())

    assert result.is_error is True
    assert "extra" in _error_text(result).casefold()
    assert workflows.calls == []


def test_domain_errors_are_converted_to_concise_mcp_tool_errors() -> None:
    offline_server, workflows = _offline_server()

    async def exercise() -> Any:
        async with Client(offline_server) as client:
            return await client.call_tool("search_compilers", {"query": "domain-error"})

    result = _run(exercise())

    assert result.is_error is True
    assert _error_text(result).endswith("offline compiler selection failed safely")
    assert [name for name, _ in workflows.calls] == ["search_compilers"]
