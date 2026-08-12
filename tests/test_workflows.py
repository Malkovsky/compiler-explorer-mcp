from __future__ import annotations

import asyncio
import copy
import shlex
from collections.abc import Coroutine, Sequence
from typing import Any, TypeVar

import pytest
from packaging.version import Version

from ce_analyzer_mcp.catalog import CatalogCompiler, ResolvedAnalyzer
from ce_analyzer_mcp.client import canonical_request_fingerprint
from ce_analyzer_mcp.errors import SelectionError, ShortlinkValidationFailure, TransportFailure
from ce_analyzer_mcp.models import (
    AliasResolution,
    AnalyzeCppRequest,
    AnalyzerInfo,
    AnalyzerSearchResult,
    AnalyzerSelection,
    AssemblyFilters,
    CompareCppRequest,
    ComparisonCase,
    CompileCppRequest,
    CompilerIdentity,
    CompilerInfo,
    CompilerSearchResult,
    CreateShortlinkRequest,
    GetShortlinkRequest,
    LibraryInfo,
    LibrarySearchResult,
    LibrarySelection,
    OpcodeDocumentationRequest,
    OutputWindow,
    Page,
    PageInfo,
    SearchAnalyzersRequest,
    SearchCompilersRequest,
    SearchLibrariesRequest,
    ShortlinkCompilerConfiguration,
    SourceBundle,
    VirtualFile,
)
from ce_analyzer_mcp.workflows import Workflows

T = TypeVar("T")


def _run(coroutine: Coroutine[Any, Any, T]) -> T:
    return asyncio.run(coroutine)


def _page(items: list[T], limit: int = 20) -> Page[T]:
    return Page[T](
        items=items,
        page=PageInfo(
            offset=0,
            limit=limit,
            total=len(items),
            returned=len(items),
            truncated_before=False,
            truncated_after=False,
        ),
    )


def _compiler(
    compiler_id: str,
    *,
    family: str = "gcc",
    optimization: bool | None = True,
    tools: Sequence[str] = (),
) -> CatalogCompiler:
    version = "15.1.0" if family == "gcc" else "20.0.0"
    return CatalogCompiler(
        info=CompilerInfo(
            id=compiler_id,
            name=f"{family.upper()} {version}",
            family=family,  # type: ignore[arg-type]
            version=version,
            instruction_set="x86-64",
            release_track="stable",
            supports_optimization_output=optimization,
        ),
        group="gcc86" if family == "gcc" else "clang",
        group_name=f"{family} x86-64",
        compiler_type=family,
        categories=frozenset({family}),
        language="c++",
        stable_version=Version(version),
        release_track="stable",
        is_semver=True,
        is_nightly=False,
        hidden=False,
        emulated=False,
        interpreted=False,
        tools=frozenset(tools),
        library_allowlist=None,
    )


class FakeCatalog:
    def __init__(
        self,
        *,
        compilers: dict[str, CatalogCompiler] | None = None,
        analyzers: Sequence[ResolvedAnalyzer] = (),
        fail_selector: str | None = None,
    ) -> None:
        self.compilers = compilers or {
            "gcc-latest": _compiler("g++-15"),
            "clang-latest": _compiler(
                "clang-20",
                family="clang",
                tools=("clangtidy", "iwyu"),
            ),
        }
        self.analyzers = list(analyzers)
        self.fail_selector = fail_selector
        self.events: list[tuple[str, object]] = []

    async def resolve_compiler(self, selector: str) -> CatalogCompiler:
        self.events.append(("compiler", selector))
        if selector == self.fail_selector or selector not in self.compilers:
            raise SelectionError(f"unknown compiler {selector!r}")
        return self.compilers[selector]

    async def resolve_libraries(
        self,
        selections: Sequence[LibrarySelection],
        compiler: CatalogCompiler,
    ) -> list[LibrarySelection]:
        self.events.append(
            (
                "libraries",
                (compiler.info.id, [(item.id, item.version) for item in selections]),
            )
        )
        return list(selections)

    async def resolve_analyzers(
        self,
        selections: Sequence[AnalyzerSelection],
        compiler: CatalogCompiler,
    ) -> list[ResolvedAnalyzer]:
        self.events.append(
            (
                "analyzers",
                (compiler.info.id, [item.id for item in selections]),
            )
        )
        return list(self.analyzers)

    @staticmethod
    def compiler_identity(requested: str, compiler: CatalogCompiler) -> CompilerIdentity:
        return CompilerIdentity(
            requested_selector=requested,
            resolved_id=compiler.info.id,
            name=compiler.info.name,
            version=compiler.info.version,
        )

    async def search_compilers(self, request: SearchCompilersRequest) -> CompilerSearchResult:
        self.events.append(("search_compilers", request))
        info = next(iter(self.compilers.values())).info
        return CompilerSearchResult(
            compilers=_page([info], request.limit),
            aliases=[
                AliasResolution(
                    alias="gcc-latest",
                    status="resolved",
                    resolved_id=info.id,
                    resolved_name=info.name,
                )
            ],
        )

    async def search_libraries(self, request: SearchLibrariesRequest) -> LibrarySearchResult:
        self.events.append(("search_libraries", request))
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
                request.limit,
            )
        )

    async def search_analyzers(self, request: SearchAnalyzersRequest) -> AnalyzerSearchResult:
        self.events.append(("search_analyzers", request))
        return AnalyzerSearchResult(
            analyzers=_page(
                [AnalyzerInfo(id="clangtidy", name="clang-tidy", aliases=["clang-tidy"])],
                request.limit,
            ),
            aliases=[
                AliasResolution(
                    alias="clang-tidy",
                    status="resolved",
                    resolved_id="clangtidy",
                    resolved_name="clang-tidy",
                )
            ],
        )


class FakeClient:
    def __init__(
        self,
        responses: dict[str, dict[str, Any]] | None = None,
        *,
        delays: dict[str, float] | None = None,
        max_concurrency: int = 4,
        opcode_response: dict[str, Any] | None = None,
        shortlink_create_response: dict[str, Any] | None = None,
        shortlink_get_response: dict[str, Any] | None = None,
    ) -> None:
        self.responses = responses or {}
        self.delays = delays or {}
        self.calls: list[tuple[str, dict[str, Any], str]] = []
        self.launched: list[str] = []
        self.completed: list[str] = []
        self.active = 0
        self.max_active = 0
        self._semaphore = asyncio.Semaphore(max_concurrency)
        self.opcode_response = opcode_response or {
            "tooltip": "move data",
            "html": "<p>move data</p>",
            "url": "https://godbolt.org/x86-64/mov",
        }
        self.opcode_calls: list[tuple[str, str]] = []
        self.shortlink_create_response = shortlink_create_response or {
            "url": "https://ce.example.test/z/offline123"
        }
        self.shortlink_get_response = shortlink_get_response or {"sessions": []}
        self.shortlink_create_calls: list[dict[str, Any]] = []
        self.shortlink_get_calls: list[str] = []

    async def compile(
        self,
        compiler_id: str,
        payload: dict[str, Any],
        fingerprint: str,
    ) -> dict[str, Any]:
        self.calls.append((compiler_id, copy.deepcopy(payload), fingerprint))
        self.launched.append(compiler_id)
        async with self._semaphore:
            self.active += 1
            self.max_active = max(self.max_active, self.active)
            try:
                await asyncio.sleep(self.delays.get(compiler_id, 0))
                response = self.responses.get(
                    compiler_id,
                    {"code": 0, "timedOut": False, "stdout": [], "stderr": [], "asm": []},
                )
                return copy.deepcopy(response)
            finally:
                self.active -= 1
                self.completed.append(compiler_id)

    async def get_opcode_documentation(
        self,
        instruction_set: str,
        opcode: str,
    ) -> dict[str, Any]:
        self.opcode_calls.append((instruction_set, opcode))
        return copy.deepcopy(self.opcode_response)

    async def create_shortlink(self, payload: dict[str, Any]) -> dict[str, Any]:
        self.shortlink_create_calls.append(copy.deepcopy(payload))
        return copy.deepcopy(self.shortlink_create_response)

    async def get_shortlink(self, shortlink_id: str) -> dict[str, Any]:
        self.shortlink_get_calls.append(shortlink_id)
        return copy.deepcopy(self.shortlink_get_response)

    @staticmethod
    def shortlink_url(shortlink_id: str) -> str:
        return f"https://ce.example.test/z/{shortlink_id}"


def _assert_compile_only_payload(
    payload: dict[str, Any],
    *,
    skip_assembly: bool = False,
) -> None:
    assert set(payload) == {"source", "options", "lang", "allowStoreCodeDebug", "files"}
    assert payload["lang"] == "c++"
    assert payload["allowStoreCodeDebug"] is False
    options = payload["options"]
    assert set(options) == {
        "userArguments",
        "compilerOptions",
        "filters",
        "tools",
        "libraries",
        "executeParameters",
    }
    assert options["compilerOptions"] == {
        "skipAsm": skip_assembly,
        "skipPopArgs": True,
        "executorRequest": False,
        "overrides": [],
        "produceOptInfo": options["compilerOptions"]["produceOptInfo"],
    }
    assert options["filters"]["binary"] is False
    assert options["filters"]["binaryObject"] is False
    assert options["filters"]["execute"] is False
    assert options["executeParameters"] == {"args": [], "stdin": "", "runtimeTools": []}
    for tool in options["tools"]:
        assert set(tool) == {"id", "args", "stdin"}
        assert tool["stdin"] == ""
    for library in options["libraries"]:
        assert set(library) == {"id", "version"}


def test_compile_workflow_payload_normalization_windows_hash_and_no_source_echo() -> None:
    source_marker = "SOURCE_MUST_NOT_BE_ECHOED_7c53"
    client = FakeClient(
        {
            "g++-15": {
                "code": 0,
                "timedOut": False,
                "stdout": [{"text": "first diagnostic"}, {"text": "second diagnostic"}],
                "stderr": [],
                "asm": [{"text": "mov eax, 1"}, {"text": "ret"}],
                "optOutput": ["first optimization", "second optimization"],
                "truncated": True,
                "okToCache": True,
                "retrievedFromCache": False,
            }
        }
    )
    catalog = FakeCatalog()
    workflows = Workflows(client, catalog)  # type: ignore[arg-type]
    filters = AssemblyFilters(
        comment_only=False,
        demangle=False,
        directives=False,
        intel=False,
        labels=False,
        library_code=True,
        trim=True,
        debug_calls=True,
    )
    request = CompileCppRequest(
        source=SourceBundle(
            source=f"int {source_marker}() {{ return 1; }}",
            files=[VirtualFile(path="include/value.hpp", content="#define VALUE 1")],
        ),
        compiler="gcc-latest",
        compiler_arguments=["-O2", "-DNAME=two words", "-Wall"],
        libraries=[LibrarySelection(id="fmt", version="110")],
        filters=filters,
        include_optimization=True,
        window=OutputWindow(offset=1, limit=1),
    )

    result = _run(workflows.compile_cpp(request))

    assert len(client.calls) == 1
    compiler_id, payload, fingerprint = client.calls[0]
    _assert_compile_only_payload(payload)
    assert compiler_id == "g++-15"
    assert payload["source"] == request.source.source
    assert payload["files"] == [{"filename": "include/value.hpp", "contents": "#define VALUE 1"}]
    assert payload["options"]["userArguments"] == shlex.join(request.compiler_arguments)
    assert payload["options"]["libraries"] == [{"id": "fmt", "version": "110"}]
    assert payload["options"]["tools"] == []
    assert payload["options"]["compilerOptions"]["produceOptInfo"] is True
    assert payload["options"]["filters"] == {
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
    }
    assert fingerprint == canonical_request_fingerprint("g++-15", payload)
    assert result.fingerprint == fingerprint
    assert result.compiler.model_dump() == {
        "requested_selector": "gcc-latest",
        "resolved_id": "g++-15",
        "name": "GCC 15.1.0",
        "version": "15.1.0",
    }
    assert result.status == "success"
    assert result.backend_truncated is True
    assert result.cache_eligible is True
    assert result.cache_hit is False
    assert result.diagnostics is not None
    assert [item.text for item in result.diagnostics.items] == ["second diagnostic"]
    assert result.assembly is not None
    assert [item.text for item in result.assembly.items] == ["ret"]
    assert result.optimization is not None
    assert [item.display for item in result.optimization.items] == ["second optimization"]
    assert result.assembly_line_count == 2
    assert result.assembly_sha256 is not None and len(result.assembly_sha256) == 64
    assert "backend_output_truncated" in {warning.code for warning in result.warnings}
    assert source_marker not in result.model_dump_json()


def test_compile_text_assembly_format_returns_sanitized_strings_with_full_metadata() -> None:
    client = FakeClient(
        {
            "g++-15": {
                "code": 0,
                "timedOut": False,
                "asm": [
                    {
                        "text": "\u001b[31mmov eax, 7\u001b[0m",
                        "opcodes": ["b807000000"],
                        "address": 16,
                    },
                    {"text": "ret", "source": {"line": 1, "column": 2}},
                ],
            }
        }
    )
    workflows = Workflows(client, FakeCatalog())  # type: ignore[arg-type]

    result = _run(
        workflows.compile_cpp(
            CompileCppRequest(
                source=SourceBundle(source="int f();"),
                assembly_format="text",
                window=OutputWindow(offset=0, limit=1),
            )
        )
    )

    assert result.assembly is not None
    assert result.assembly.items == ["mov eax, 7"]
    assert result.assembly.page.total == 2
    assert result.assembly.page.next_offset == 1
    assert result.assembly_line_count == 2
    assert result.assembly_sha256 is not None and len(result.assembly_sha256) == 64


def test_compile_omits_unrequested_sections_and_skips_assembly() -> None:
    client = FakeClient(
        {
            "g++-15": {
                "code": 1,
                "timedOut": False,
                "stderr": ["compile failed"],
                "asm": ["partial asm"],
                "optOutput": ["not requested"],
            }
        }
    )
    workflows = Workflows(client, FakeCatalog())  # type: ignore[arg-type]
    request = CompileCppRequest(
        source=SourceBundle(source="invalid cpp"),
        include_diagnostics=False,
        include_assembly=False,
        include_optimization=False,
    )

    result = _run(workflows.compile_cpp(request))

    _assert_compile_only_payload(client.calls[0][1], skip_assembly=True)
    assert result.status == "failed"
    assert result.exit_code == 1
    assert result.diagnostics is None
    assert result.assembly is None
    assert result.optimization is None
    assert result.assembly_line_count == 0
    assert result.assembly_sha256 is None


def test_compile_rejects_unadvertised_optimization_before_backend_call() -> None:
    catalog = FakeCatalog(compilers={"no-opt": _compiler("no-opt", optimization=False)})
    client = FakeClient()
    workflows = Workflows(client, catalog)  # type: ignore[arg-type]

    with pytest.raises(SelectionError, match="does not advertise optimization"):
        _run(
            workflows.compile_cpp(
                CompileCppRequest(
                    source=SourceBundle(source="int x;"),
                    compiler="no-opt",
                    include_optimization=True,
                )
            )
        )

    assert client.calls == []


def test_compare_preflights_every_selection_before_launching_any_compile() -> None:
    catalog = FakeCatalog(
        compilers={"valid": _compiler("valid")},
        fail_selector="missing",
    )
    client = FakeClient()
    workflows = Workflows(client, catalog)  # type: ignore[arg-type]
    request = CompareCppRequest(
        source=SourceBundle(source="int f(){return 1;}"),
        cases=[
            ComparisonCase(label="valid case", compiler="valid"),
            ComparisonCase(label="invalid case", compiler="missing"),
        ],
    )

    with pytest.raises(SelectionError, match="unknown compiler 'missing'"):
        _run(workflows.compare_cpp(request))

    assert client.calls == []
    assert catalog.events[:3] == [
        ("compiler", "valid"),
        ("libraries", ("valid", [])),
        ("compiler", "missing"),
    ]


def test_compare_is_concurrent_ordered_partial_failure_and_baseline_relative() -> None:
    source_marker = "COMPARE_SOURCE_NOT_ECHOED_8041"
    selectors = ["base", "same", "changed", "broken"]
    catalog = FakeCatalog(compilers={name: _compiler(name) for name in selectors})
    client = FakeClient(
        {
            "base": {
                "code": 0,
                "timedOut": False,
                "stdout": ["base diagnostic"],
                "asm": ["mov eax, 1", "ret"],
            },
            "same": {
                "code": 0,
                "timedOut": False,
                "asm": ["  mov   eax, 1", " ret "],
            },
            "changed": {
                "code": 0,
                "timedOut": False,
                "asm": ["mov eax, 2", "ret"],
            },
            "broken": {
                "code": 2,
                "timedOut": False,
                "stderr": ["candidate failed"],
                "asm": [],
            },
        },
        delays={"base": 0.04, "same": 0.03, "changed": 0.01, "broken": 0},
        max_concurrency=2,
    )
    workflows = Workflows(client, catalog)  # type: ignore[arg-type]
    request = CompareCppRequest(
        source=SourceBundle(source=f"int {source_marker}() {{ return 1; }}"),
        cases=[
            ComparisonCase(label="baseline", compiler="base", compiler_arguments=["-O1"]),
            ComparisonCase(label="same asm", compiler="same", compiler_arguments=["-O2"]),
            ComparisonCase(label="changed asm", compiler="changed", compiler_arguments=["-O3"]),
            ComparisonCase(label="does not compile", compiler="broken"),
        ],
        window=OutputWindow(offset=1, limit=3),
    )

    result = _run(workflows.compare_cpp(request))

    assert client.launched == selectors
    assert client.max_active == 2
    assert client.completed != selectors
    assert [case.label for case in result.cases] == [case.label for case in request.cases]
    assert [case.status for case in result.cases] == ["success", "success", "success", "failed"]
    assert result.cases[-1].exit_code == 2
    assert [comparison.baseline_label for comparison in result.comparisons] == [
        "baseline",
        "baseline",
        "baseline",
    ]
    same, changed, broken = result.comparisons
    assert same.candidate_label == "same asm"
    assert same.identical is True
    assert same.diff is not None and same.diff.items == []
    assert same.omission_code is None
    assert same.omission_reason is None
    assert changed.candidate_label == "changed asm"
    assert changed.identical is False
    assert changed.diff is not None
    assert changed.diff.page.limit == 3
    assert changed.diff.page.returned == 3
    assert changed.diff.page.truncated_before is True
    assert changed.diff.page.truncated_after is True
    assert changed.diff.items[0] == "+++ changed asm"
    assert broken.identical is None
    assert broken.diff is None
    assert broken.omission_code == "candidate_failed"
    assert broken.omission_reason == "candidate compilation did not succeed"
    assert result.benchmark_warning.code == "not_a_benchmark"
    assert "not performance measurements" in result.benchmark_warning.message
    assert "semantic equivalence" in result.benchmark_warning.message
    assert source_marker not in result.model_dump_json()
    for compiler_id, payload, fingerprint in client.calls:
        _assert_compile_only_payload(payload)
        assert payload["options"]["compilerOptions"]["produceOptInfo"] is False
        assert payload["options"]["tools"] == []
        assert fingerprint == canonical_request_fingerprint(compiler_id, payload)


def test_compare_omits_diff_when_safe_input_limit_is_exceeded() -> None:
    lines = [f"line {index}" for index in range(5_001)]
    catalog = FakeCatalog(
        compilers={"base": _compiler("base"), "candidate": _compiler("candidate")}
    )
    client = FakeClient(
        {
            "base": {"code": 0, "timedOut": False, "asm": lines},
            "candidate": {"code": 0, "timedOut": False, "asm": [*lines[:-1], "changed"]},
        }
    )
    workflows = Workflows(client, catalog)  # type: ignore[arg-type]
    request = CompareCppRequest(
        source=SourceBundle(source="int f();"),
        cases=[
            ComparisonCase(label="base", compiler="base"),
            ComparisonCase(label="candidate", compiler="candidate"),
        ],
    )

    result = _run(workflows.compare_cpp(request))

    comparison = result.comparisons[0]
    assert comparison.identical is False
    assert comparison.diff is None
    assert comparison.omission_code == "diff_input_limit_exceeded"
    assert comparison.omission_reason == "assembly exceeds the safe diff input limit"
    assert comparison.diff_input_limit == 5_000
    assert comparison.baseline_input_line_count == 5_001
    assert comparison.candidate_input_line_count == 5_001


def test_compare_omits_all_diffs_when_baseline_compilation_fails() -> None:
    catalog = FakeCatalog(
        compilers={"base": _compiler("base"), "candidate": _compiler("candidate")}
    )
    client = FakeClient(
        {
            "base": {"code": 1, "timedOut": False, "stderr": ["bad baseline"], "asm": []},
            "candidate": {"code": 0, "timedOut": False, "asm": ["ret"]},
        }
    )
    workflows = Workflows(client, catalog)  # type: ignore[arg-type]

    result = _run(
        workflows.compare_cpp(
            CompareCppRequest(
                source=SourceBundle(source="bad source"),
                cases=[
                    ComparisonCase(label="base", compiler="base"),
                    ComparisonCase(label="candidate", compiler="candidate"),
                ],
            )
        )
    )

    assert result.comparisons[0].omission_reason == "baseline compilation did not succeed"
    assert result.comparisons[0].omission_code == "baseline_failed"
    assert result.comparisons[0].identical is None


def test_compare_preserves_successful_cases_when_one_transport_request_fails() -> None:
    class PartiallyFailingClient(FakeClient):
        async def compile(
            self,
            compiler_id: str,
            payload: dict[str, Any],
            fingerprint: str,
        ) -> dict[str, Any]:
            if compiler_id == "transport-error":
                raise TransportFailure("api/compiler/transport-error/compile", fingerprint)
            return await super().compile(compiler_id, payload, fingerprint)

    catalog = FakeCatalog(
        compilers={
            "base": _compiler("base"),
            "transport-error": _compiler("transport-error"),
            "good": _compiler("good"),
        }
    )
    client = PartiallyFailingClient(
        {
            "base": {"code": 0, "timedOut": False, "asm": ["ret"]},
            "good": {"code": 0, "timedOut": False, "asm": ["xor eax, eax", "ret"]},
        }
    )
    workflows = Workflows(client, catalog)  # type: ignore[arg-type]

    result = _run(
        workflows.compare_cpp(
            CompareCppRequest(
                source=SourceBundle(source="int f();"),
                cases=[
                    ComparisonCase(label="base", compiler="base"),
                    ComparisonCase(label="network failure", compiler="transport-error"),
                    ComparisonCase(label="good", compiler="good"),
                ],
            )
        )
    )

    assert [case.status for case in result.cases] == ["success", "error", "success"]
    assert result.cases[1].exit_code is None
    assert result.cases[1].warnings[0].code == "transport_failure"
    failed, good = result.comparisons
    assert failed.omission_code == "candidate_failed"
    assert good.identical is False
    assert good.diff is not None
    assert "partial_compare_failure" in {warning.code for warning in result.warnings}


def test_analyze_runs_selected_tools_once_and_normalizes_every_status() -> None:
    source_marker = "ANALYZE_SOURCE_NOT_ECHOED_52a9"
    resolved = [
        ResolvedAnalyzer("clang-tidy", "clangtidy", "clang-tidy", ("--checks=*",)),
        ResolvedAnalyzer("iwyu", "iwyu", "Include What You Use", ("-Xiwyu", "--verbose=1")),
        ResolvedAnalyzer("osaca", "osaca", "OSACA", ()),
        ResolvedAnalyzer("pvs-studio", "pvs", "PVS-Studio", ("--lic-file", "token path")),
    ]
    catalog = FakeCatalog(
        compilers={
            "clang-latest": _compiler(
                "clang-20",
                family="clang",
                tools=[item.id for item in resolved],
            )
        },
        analyzers=resolved,
    )
    client = FakeClient(
        {
            "clang-20": {
                "code": 0,
                "timedOut": False,
                "stderr": ["compiler warning"],
                "tools": [
                    {
                        "id": "clangtidy",
                        "name": "clang-tidy",
                        "code": 0,
                        "stdout": ["tidy first", "tidy second"],
                    },
                    {"id": "iwyu", "name": "IWYU", "code": 3, "stderr": ["remove vector"]},
                    {"id": "pvs", "name": "PVS", "stdout": ["missing status"]},
                    {"id": "unrequested", "name": "Unexpected", "code": 0, "stdout": ["ignored"]},
                ],
            }
        }
    )
    workflows = Workflows(client, catalog)  # type: ignore[arg-type]
    request = AnalyzeCppRequest(
        source=SourceBundle(source=f"int {source_marker}() {{ return 0; }}"),
        analyzers=[AnalyzerSelection(id=item.requested_selector) for item in resolved],
        compiler_arguments=["-std=c++23", "-DVALUE=two words"],
        libraries=[LibrarySelection(id="fmt", version="110")],
        window=OutputWindow(limit=1),
    )

    result = _run(workflows.analyze_cpp(request))

    assert len(client.calls) == 1
    compiler_id, payload, fingerprint = client.calls[0]
    _assert_compile_only_payload(payload, skip_assembly=True)
    assert compiler_id == "clang-20"
    assert payload["options"]["userArguments"] == shlex.join(request.compiler_arguments)
    assert payload["options"]["libraries"] == [{"id": "fmt", "version": "110"}]
    assert payload["options"]["tools"] == [
        {"id": "clangtidy", "args": "'--checks=*'", "stdin": ""},
        {"id": "iwyu", "args": "-Xiwyu --verbose=1", "stdin": ""},
        {"id": "osaca", "args": "", "stdin": ""},
        {"id": "pvs", "args": "--lic-file 'token path'", "stdin": ""},
    ]
    assert payload["options"]["compilerOptions"]["produceOptInfo"] is False
    assert result.fingerprint == fingerprint
    assert [analyzer.resolved_id for analyzer in result.analyzers] == [
        "clangtidy",
        "iwyu",
        "osaca",
        "pvs",
    ]
    assert [analyzer.status for analyzer in result.analyzers] == [
        "success",
        "failed",
        "missing",
        "malformed",
    ]
    assert result.status == "failed"
    assert result.exit_code == 0
    assert [analyzer.exit_code for analyzer in result.analyzers] == [0, 3, None, None]
    assert [line.text for line in result.analyzers[0].output.items] == ["tidy first"]
    assert result.analyzers[0].output.page.truncated_after is True
    assert [line.text for line in result.analyzers[1].output.items] == ["remove vector"]
    assert result.analyzers[2].output.items == []
    assert "missing_analyzer_output" in {warning.code for warning in result.analyzers[2].warnings}
    assert "malformed_analyzer_status" in {warning.code for warning in result.analyzers[3].warnings}
    assert {
        "missing_analyzer_output",
        "unrequested_analyzer_output_ignored",
    }.issubset({warning.code for warning in result.warnings})
    assert source_marker not in result.model_dump_json()
    assert '"text":"ignored"' not in result.model_dump_json()


def test_analyze_warns_for_malformed_whole_tool_section_and_missing_result() -> None:
    resolved = [ResolvedAnalyzer("clang-tidy", "clangtidy", "clang-tidy", ())]
    catalog = FakeCatalog(analyzers=resolved)
    client = FakeClient(
        {
            "g++-15": {
                "code": 0,
                "timedOut": False,
                "tools": {"id": "clangtidy", "code": 0},
            }
        }
    )
    workflows = Workflows(client, catalog)  # type: ignore[arg-type]

    result = _run(
        workflows.analyze_cpp(
            AnalyzeCppRequest(
                source=SourceBundle(source="int f();"),
                compiler="gcc-latest",
                analyzers=[AnalyzerSelection(id="clang-tidy")],
            )
        )
    )

    assert result.analyzers[0].status == "missing"
    assert {"malformed_tools", "missing_analyzer_output"}.issubset(
        {warning.code for warning in result.warnings}
    )


@pytest.mark.parametrize(
    ("compile_status", "tool_code", "expected_status"),
    [
        ((0, False), 0, "success"),
        ((1, False), 0, "failed"),
        ((124, True), 1, "timed_out"),
    ],
)
def test_analyze_aggregate_status_includes_compiler_and_analyzer_results(
    compile_status: tuple[int, bool],
    tool_code: int,
    expected_status: str,
) -> None:
    resolved = [ResolvedAnalyzer("llvm-mca", "llvm-mca", "LLVM MCA", ())]
    catalog = FakeCatalog(analyzers=resolved)
    code, timed_out = compile_status
    client = FakeClient(
        {
            "g++-15": {
                "code": code,
                "timedOut": timed_out,
                "tools": [
                    {
                        "id": "llvm-mca",
                        "name": "LLVM MCA",
                        "code": tool_code,
                        "stdout": ["modeled output"],
                    }
                ],
            }
        }
    )
    workflows = Workflows(client, catalog)  # type: ignore[arg-type]

    result = _run(
        workflows.analyze_cpp(
            AnalyzeCppRequest(
                source=SourceBundle(source="int f();"),
                compiler="gcc-latest",
                analyzers=[AnalyzerSelection(id="llvm-mca")],
            )
        )
    )

    assert result.status == expected_status
    assert result.exit_code == code


def test_create_shortlink_preflights_validates_and_stores_resolved_configurations() -> None:
    source_marker = "SHORTLINK_SOURCE_NOT_ECHOED_42bd"
    catalog = FakeCatalog()
    client = FakeClient(
        {
            "g++-15": {"code": 0, "timedOut": False, "asm": ["ignored"]},
            "clang-20": {"code": 0, "timedOut": False, "asm": ["ignored"]},
        }
    )
    workflows = Workflows(client, catalog)  # type: ignore[arg-type]
    request = CreateShortlinkRequest(
        source=SourceBundle(source=f"int {source_marker}() {{ return 42; }}"),
        compilers=[
            ShortlinkCompilerConfiguration(
                compiler="gcc-latest",
                compiler_arguments=["-O2"],
                libraries=[LibrarySelection(id="fmt", version="110")],
            ),
            ShortlinkCompilerConfiguration(
                compiler="clang-latest",
                compiler_arguments=["-O3"],
                filters=AssemblyFilters(intel=False),
            ),
        ],
    )

    result = _run(workflows.create_shortlink(request))

    assert result.shortlink_id == "offline123"
    assert result.url == "https://ce.example.test/z/offline123"
    assert result.compilation_validated is True
    assert [item.status for item in result.compilers] == ["success", "success"]
    assert [item.compiler.resolved_id for item in result.compilers] == ["g++-15", "clang-20"]
    assert all(item.fingerprint for item in result.compilers)
    assert len(client.calls) == 2
    assert all(call[1]["options"]["compilerOptions"]["skipAsm"] is True for call in client.calls)
    assert len(client.shortlink_create_calls) == 1
    stored = client.shortlink_create_calls[0]
    assert stored["sessions"][0]["source"] == request.source.source
    assert [item["id"] for item in stored["sessions"][0]["compilers"]] == [
        "g++-15",
        "clang-20",
    ]
    assert stored["sessions"][0]["compilers"][0]["libs"] == [{"name": "fmt", "ver": "110"}]
    assert source_marker not in result.model_dump_json()


def test_create_shortlink_can_skip_compile_but_still_preflights_catalog() -> None:
    catalog = FakeCatalog()
    client = FakeClient()
    workflows = Workflows(client, catalog)  # type: ignore[arg-type]

    result = _run(
        workflows.create_shortlink(
            CreateShortlinkRequest(
                source=SourceBundle(source="int f();"),
                compilers=[ShortlinkCompilerConfiguration(compiler="gcc-latest")],
                validate_compilation=False,
            )
        )
    )

    assert client.calls == []
    assert len(client.shortlink_create_calls) == 1
    assert result.compilation_validated is False
    assert result.compilers[0].status == "not_run"
    assert result.compilers[0].fingerprint is None
    assert catalog.events[:2] == [
        ("compiler", "gcc-latest"),
        ("libraries", ("g++-15", [])),
    ]


def test_create_shortlink_validation_failure_prevents_permanent_storage() -> None:
    client = FakeClient({"g++-15": {"code": 1, "timedOut": False, "stderr": ["bad"]}})
    workflows = Workflows(client, FakeCatalog())  # type: ignore[arg-type]

    with pytest.raises(ShortlinkValidationFailure, match=r"g\+\+-15"):
        _run(
            workflows.create_shortlink(
                CreateShortlinkRequest(
                    source=SourceBundle(source="invalid"),
                    compilers=[ShortlinkCompilerConfiguration()],
                )
            )
        )

    assert client.shortlink_create_calls == []


def test_get_shortlink_normalizes_without_catalog_resolution_or_compilation() -> None:
    catalog = FakeCatalog()
    source = "int shared() { return 1; }\n"
    client = FakeClient(
        shortlink_get_response={
            "sessions": [
                {
                    "id": 1,
                    "language": "c++",
                    "source": source,
                    "compilers": [
                        {
                            "id": "retired-compiler",
                            "options": "-O2",
                            "libs": [{"name": "fmt", "ver": "110"}],
                        }
                    ],
                }
            ]
        }
    )
    workflows = Workflows(client, catalog)  # type: ignore[arg-type]

    result = _run(workflows.get_shortlink(GetShortlinkRequest(shortlink_id="saved_123")))

    assert client.shortlink_get_calls == ["saved_123"]
    assert client.calls == []
    assert catalog.events == []
    assert result.url == "https://ce.example.test/z/saved_123"
    assert result.sessions[0].source == source
    assert result.sessions[0].compilers[0].compiler_id == "retired-compiler"


def test_opcode_workflow_calls_explicit_ids_and_returns_sanitized_documentation() -> None:
    client = FakeClient(
        opcode_response={
            "tooltip": "\x1b[32mmove\x1b[0m",
            "html": '<p onclick="bad">move</p><script>secret</script>',
            "url": "https://godbolt.org/aarch64/add",
        }
    )
    workflows = Workflows(client, FakeCatalog())  # type: ignore[arg-type]

    result = _run(
        workflows.get_opcode_documentation(
            OpcodeDocumentationRequest(instruction_set="aarch64", opcode="add")
        )
    )

    assert client.opcode_calls == [("aarch64", "add")]
    assert result.tooltip == "move"
    assert result.html == "<p>move</p>"
    assert result.instruction_set == "aarch64"
    assert result.opcode == "add"


def test_search_workflows_delegate_typed_requests() -> None:
    catalog = FakeCatalog()
    workflows = Workflows(FakeClient(), catalog)  # type: ignore[arg-type]
    compiler_request = SearchCompilersRequest(query="gcc", limit=3)
    library_request = SearchLibrariesRequest(query="fmt", limit=4)
    analyzer_request = SearchAnalyzersRequest(query="tidy", compiler="clang-latest", limit=5)

    compiler_result = _run(workflows.search_compilers(compiler_request))
    library_result = _run(workflows.search_libraries(library_request))
    analyzer_result = _run(workflows.search_analyzers(analyzer_request))

    assert compiler_result.compilers.items[0].id == "g++-15"
    assert library_result.libraries.items[0].version_id == "110"
    assert analyzer_result.analyzers.items[0].id == "clangtidy"
    assert ("search_compilers", compiler_request) in catalog.events
    assert ("search_libraries", library_request) in catalog.events
    assert ("search_analyzers", analyzer_request) in catalog.events


def test_compile_final_budget_truncates_real_response_pages() -> None:
    lines = [{"text": f"{index:04d}: " + ("x" * 4_000)} for index in range(1_000)]
    client = FakeClient({"g++-15": {"code": 0, "timedOut": False, "stdout": [], "asm": lines}})
    workflows = Workflows(client, FakeCatalog())  # type: ignore[arg-type]

    result = _run(
        workflows.compile_cpp(
            CompileCppRequest(
                source=SourceBundle(source="int f(){return 0;}"),
                window=OutputWindow(limit=1_000),
            )
        )
    )

    assert result.response_truncated is True
    assert result.assembly is not None
    assert len(result.assembly.items) < 1_000
    assert "response_budget_truncated" in {warning.code for warning in result.warnings}
