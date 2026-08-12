from __future__ import annotations

import asyncio
import difflib
from dataclasses import dataclass
from typing import Any, Final, Literal, TypeAlias

from ce_analyzer_mcp.catalog import Catalog, CatalogCompiler
from ce_analyzer_mcp.client import (
    CompilerExplorerClient,
    build_compile_payload,
    build_shortlink_payload,
    canonical_request_fingerprint,
)
from ce_analyzer_mcp.errors import CEAnalyzerError, SelectionError, ShortlinkValidationFailure
from ce_analyzer_mcp.models import (
    AnalyzeCppRequest,
    AnalyzeResult,
    AnalyzerRunResult,
    AnalyzerSearchResult,
    AssemblyComparison,
    AssemblyLine,
    CompareCaseResult,
    CompareCppRequest,
    CompareResult,
    CompileCppRequest,
    CompileResult,
    CompilerSearchResult,
    CreateShortlinkRequest,
    CreateShortlinkResult,
    DiagnosticLine,
    GetShortlinkRequest,
    GetShortlinkResult,
    LibrarySearchResult,
    OpcodeDocumentation,
    OpcodeDocumentationRequest,
    Page,
    SearchAnalyzersRequest,
    SearchCompilersRequest,
    SearchLibrariesRequest,
    ShortlinkCompilerConfiguration,
    ShortlinkCompilerValidation,
    WarningItem,
)
from ce_analyzer_mcp.results import (
    NormalizedCompile,
    assembly_fingerprint,
    enforce_response_budget,
    enforce_shortlink_response_budget,
    merge_warnings,
    normalize_compile_response,
    normalize_opcode_documentation,
    normalize_shortlink_creation,
    normalize_shortlink_info,
    truncate_text,
    window_page,
)

_MAX_DIFF_INPUT_LINES: Final = 5_000
_NO_BENCHMARK_WARNING: Final = (
    "Assembly differences are not performance measurements and do not establish semantic "
    "equivalence or relative speed."
)
LiteralAnalyzerStatus: TypeAlias = Literal["success", "failed", "missing", "malformed"]


@dataclass(frozen=True)
class _PreparedCompile:
    label: str
    requested_selector: str
    compiler: CatalogCompiler
    payload: dict[str, Any]
    fingerprint: str


@dataclass(frozen=True)
class _PreparedShortlink:
    requested_selector: str
    compiler: CatalogCompiler
    configuration: ShortlinkCompilerConfiguration
    compile_payload: dict[str, Any]
    fingerprint: str


def _warning(code: str, message: str) -> WarningItem:
    return WarningItem(code=code, message=message)


def _compile_warnings(normalized: NormalizedCompile) -> list[WarningItem]:
    warnings = list(normalized.warnings)
    if normalized.backend_truncated is True:
        warnings.append(
            _warning(
                "backend_output_truncated",
                "Compiler Explorer reported that backend output was truncated.",
            )
        )
    return merge_warnings(warnings)


class Workflows:
    def __init__(self, client: CompilerExplorerClient, catalog: Catalog) -> None:
        self._client = client
        self._catalog = catalog

    async def search_compilers(self, request: SearchCompilersRequest) -> CompilerSearchResult:
        response = await self._catalog.search_compilers(request)
        enforce_response_budget(response, [response.compilers])
        return response

    async def search_libraries(self, request: SearchLibrariesRequest) -> LibrarySearchResult:
        response = await self._catalog.search_libraries(request)
        enforce_response_budget(response, [response.libraries])
        return response

    async def search_analyzers(self, request: SearchAnalyzersRequest) -> AnalyzerSearchResult:
        response = await self._catalog.search_analyzers(request)
        enforce_response_budget(response, [response.analyzers])
        return response

    async def compile_cpp(self, request: CompileCppRequest) -> CompileResult:
        compiler = await self._catalog.resolve_compiler(request.compiler)
        libraries = await self._catalog.resolve_libraries(request.libraries, compiler)
        if request.include_optimization and compiler.info.supports_optimization_output is False:
            raise SelectionError(
                f"compiler {compiler.info.id!r} does not advertise optimization output support"
            )
        payload = build_compile_payload(
            source=request.source,
            compiler_arguments=request.compiler_arguments,
            libraries=libraries,
            filters=request.filters,
            produce_optimization_output=request.include_optimization,
            skip_assembly=not request.include_assembly,
        )
        fingerprint = canonical_request_fingerprint(compiler.info.id, payload)
        normalized = normalize_compile_response(
            await self._client.compile(compiler.info.id, payload, fingerprint)
        )
        diagnostics = (
            window_page(normalized.diagnostics, request.window)
            if request.include_diagnostics
            else None
        )
        assembly: Page[AssemblyLine] | Page[str] | None = None
        if request.include_assembly:
            assembly = (
                window_page(normalized.assembly, request.window)
                if request.assembly_format == "detailed"
                else window_page([line.text for line in normalized.assembly], request.window)
            )
        optimization = (
            window_page(normalized.optimization, request.window)
            if request.include_optimization
            else None
        )
        response = CompileResult(
            fingerprint=fingerprint,
            compiler=self._catalog.compiler_identity(request.compiler, compiler),
            status=normalized.status,
            exit_code=normalized.exit_code,
            timed_out=normalized.timed_out,
            backend_truncated=normalized.backend_truncated,
            cache_eligible=normalized.cache_eligible,
            cache_hit=normalized.cache_hit,
            diagnostics=diagnostics,
            assembly=assembly,
            optimization=optimization,
            assembly_line_count=len(normalized.assembly) if request.include_assembly else 0,
            assembly_sha256=(
                assembly_fingerprint(normalized.assembly) if request.include_assembly else None
            ),
            warnings=_compile_warnings(normalized),
        )
        pages: list[Page[Any]] = [
            page
            for page in (response.diagnostics, response.assembly, response.optimization)
            if page is not None
        ]
        enforce_response_budget(response, pages)
        return response

    async def _prepare_comparison(self, request: CompareCppRequest) -> list[_PreparedCompile]:
        prepared: list[_PreparedCompile] = []
        for case in request.cases:
            compiler = await self._catalog.resolve_compiler(case.compiler)
            libraries = await self._catalog.resolve_libraries(case.libraries, compiler)
            payload = build_compile_payload(
                source=request.source,
                compiler_arguments=case.compiler_arguments,
                libraries=libraries,
                filters=case.filters,
            )
            prepared.append(
                _PreparedCompile(
                    label=case.label,
                    requested_selector=case.compiler,
                    compiler=compiler,
                    payload=payload,
                    fingerprint=canonical_request_fingerprint(compiler.info.id, payload),
                )
            )
        return prepared

    async def compare_cpp(self, request: CompareCppRequest) -> CompareResult:
        prepared = await self._prepare_comparison(request)
        raw_results = await asyncio.gather(
            *(
                self._client.compile(
                    item.compiler.info.id,
                    item.payload,
                    item.fingerprint,
                )
                for item in prepared
            ),
            return_exceptions=True,
        )
        outcomes: list[NormalizedCompile | CEAnalyzerError] = []
        for raw in raw_results:
            if isinstance(raw, CEAnalyzerError):
                outcomes.append(raw)
            elif isinstance(raw, BaseException):
                raise raw
            else:
                outcomes.append(normalize_compile_response(raw))
        case_results: list[CompareCaseResult] = []
        pages: list[Page[Any]] = []
        for item, outcome in zip(prepared, outcomes, strict=True):
            if isinstance(outcome, CEAnalyzerError):
                diagnostics: Page[DiagnosticLine] = window_page([], request.window)
                pages.append(diagnostics)
                case_results.append(
                    CompareCaseResult(
                        label=item.label,
                        fingerprint=item.fingerprint,
                        compiler=self._catalog.compiler_identity(
                            item.requested_selector,
                            item.compiler,
                        ),
                        status="error",
                        exit_code=None,
                        timed_out=False,
                        diagnostics=diagnostics,
                        assembly_line_count=0,
                        warnings=[_warning(outcome.code, outcome.public_message)],
                    )
                )
                continue
            normalized = outcome
            diagnostics = window_page(normalized.diagnostics, request.window)
            pages.append(diagnostics)
            case_results.append(
                CompareCaseResult(
                    label=item.label,
                    fingerprint=item.fingerprint,
                    compiler=self._catalog.compiler_identity(
                        item.requested_selector,
                        item.compiler,
                    ),
                    status=normalized.status,
                    exit_code=normalized.exit_code,
                    timed_out=normalized.timed_out,
                    backend_truncated=normalized.backend_truncated,
                    cache_eligible=normalized.cache_eligible,
                    cache_hit=normalized.cache_hit,
                    diagnostics=diagnostics,
                    assembly_line_count=len(normalized.assembly),
                    assembly_sha256=assembly_fingerprint(normalized.assembly),
                    warnings=_compile_warnings(normalized),
                )
            )
        comparisons: list[AssemblyComparison] = []
        top_warnings: list[WarningItem] = []
        if any(isinstance(outcome, CEAnalyzerError) for outcome in outcomes):
            top_warnings.append(
                _warning(
                    "partial_compare_failure",
                    "One or more comparison cases failed before a compile result was available.",
                )
            )
        baseline_item = prepared[0]
        baseline = outcomes[0]
        baseline_hash = (
            None
            if isinstance(baseline, CEAnalyzerError)
            else assembly_fingerprint(baseline.assembly)
        )
        baseline_line_count = 0 if isinstance(baseline, CEAnalyzerError) else len(baseline.assembly)
        for candidate_item, candidate in zip(prepared[1:], outcomes[1:], strict=True):
            candidate_hash = (
                None
                if isinstance(candidate, CEAnalyzerError)
                else assembly_fingerprint(candidate.assembly)
            )
            candidate_line_count = (
                0 if isinstance(candidate, CEAnalyzerError) else len(candidate.assembly)
            )
            omission_code: str | None = None
            omission_reason: str | None = None
            diff: Page[str] | None = None
            identical: bool | None = None
            if isinstance(baseline, CEAnalyzerError) or baseline.status != "success":
                omission_code = "baseline_failed"
                omission_reason = "baseline compilation did not succeed"
            elif isinstance(candidate, CEAnalyzerError) or candidate.status != "success":
                omission_code = "candidate_failed"
                omission_reason = "candidate compilation did not succeed"
            elif baseline_hash is None or candidate_hash is None:
                omission_code = "assembly_unavailable"
                omission_reason = "assembly output is unavailable"
            else:
                identical = baseline_hash == candidate_hash
                if identical:
                    diff = window_page([], request.window)
                elif (
                    baseline_line_count > _MAX_DIFF_INPUT_LINES
                    or candidate_line_count > _MAX_DIFF_INPUT_LINES
                ):
                    omission_code = "diff_input_limit_exceeded"
                    omission_reason = "assembly exceeds the safe diff input limit"
                else:
                    raw_diff = difflib.unified_diff(
                        [line.text for line in baseline.assembly],
                        [line.text for line in candidate.assembly],
                        fromfile=baseline_item.label,
                        tofile=candidate_item.label,
                        lineterm="",
                    )
                    diff_lines: list[str] = []
                    diff_truncated = False
                    for line in raw_diff:
                        text, truncated = truncate_text(line)
                        diff_lines.append(text)
                        diff_truncated = diff_truncated or truncated
                    if diff_truncated:
                        top_warnings.append(
                            _warning(
                                "diff_line_truncated",
                                "One or more unified-diff lines exceeded the line limit.",
                            )
                        )
                    diff = window_page(diff_lines, request.window)
            if diff is not None:
                pages.append(diff)
            comparisons.append(
                AssemblyComparison(
                    baseline_label=baseline_item.label,
                    candidate_label=candidate_item.label,
                    baseline_sha256=baseline_hash,
                    candidate_sha256=candidate_hash,
                    identical=identical,
                    diff=diff,
                    omission_code=omission_code,  # type: ignore[arg-type]
                    omission_reason=omission_reason,
                    diff_input_limit=(
                        _MAX_DIFF_INPUT_LINES
                        if omission_code == "diff_input_limit_exceeded"
                        else None
                    ),
                    baseline_input_line_count=baseline_line_count,
                    candidate_input_line_count=candidate_line_count,
                )
            )
        response = CompareResult(
            cases=case_results,
            comparisons=comparisons,
            benchmark_warning=_warning("not_a_benchmark", _NO_BENCHMARK_WARNING),
            warnings=merge_warnings(top_warnings),
        )
        pages = [case.diagnostics for case in response.cases]
        pages.extend(
            comparison.diff for comparison in response.comparisons if comparison.diff is not None
        )
        enforce_response_budget(response, pages)
        return response

    async def analyze_cpp(self, request: AnalyzeCppRequest) -> AnalyzeResult:
        compiler = await self._catalog.resolve_compiler(request.compiler)
        libraries = await self._catalog.resolve_libraries(request.libraries, compiler)
        analyzers = await self._catalog.resolve_analyzers(request.analyzers, compiler)
        payload = build_compile_payload(
            source=request.source,
            compiler_arguments=request.compiler_arguments,
            libraries=libraries,
            filters=request.filters,
            analyzers=[analyzer.as_selection() for analyzer in analyzers],
            skip_assembly=True,
        )
        fingerprint = canonical_request_fingerprint(compiler.info.id, payload)
        normalized = normalize_compile_response(
            await self._client.compile(compiler.info.id, payload, fingerprint)
        )
        diagnostics = window_page(normalized.diagnostics, request.window)
        pages: list[Page[Any]] = [diagnostics]
        by_id = {tool.id: tool for tool in normalized.tools}
        analyzer_results: list[AnalyzerRunResult] = []
        top_warnings = _compile_warnings(normalized)
        for analyzer in analyzers:
            result = by_id.get(analyzer.id)
            if result is None:
                output: Page[DiagnosticLine] = window_page([], request.window)
                warnings = [
                    _warning(
                        "missing_analyzer_output",
                        f"Compiler Explorer returned no output for analyzer {analyzer.id!r}.",
                    )
                ]
                status: LiteralAnalyzerStatus = "missing"
                exit_code = None
                top_warnings.extend(warnings)
            else:
                output = window_page(result.output, request.window)
                warnings = list(result.warnings)
                exit_code = result.code
                if result.malformed:
                    status = "malformed"
                elif result.code == 0:
                    status = "success"
                else:
                    status = "failed"
            pages.append(output)
            analyzer_results.append(
                AnalyzerRunResult(
                    requested_selector=analyzer.requested_selector,
                    resolved_id=analyzer.id,
                    name=analyzer.name,
                    status=status,
                    exit_code=exit_code,
                    output=output,
                    warnings=merge_warnings(warnings),
                )
            )
        unrequested = sorted(set(by_id) - {analyzer.id for analyzer in analyzers})
        if unrequested:
            top_warnings.append(
                _warning(
                    "unrequested_analyzer_output_ignored",
                    "Ignored unrequested analyzer result IDs: " + ", ".join(unrequested[:10]),
                )
            )
        if normalized.status == "timed_out":
            aggregate_status: Literal["success", "failed", "timed_out"] = "timed_out"
        elif normalized.status == "failed" or any(
            analyzer.status != "success" for analyzer in analyzer_results
        ):
            aggregate_status = "failed"
        else:
            aggregate_status = "success"
        response = AnalyzeResult(
            fingerprint=fingerprint,
            compiler=self._catalog.compiler_identity(request.compiler, compiler),
            status=aggregate_status,
            exit_code=normalized.exit_code,
            timed_out=normalized.timed_out,
            backend_truncated=normalized.backend_truncated,
            cache_eligible=normalized.cache_eligible,
            cache_hit=normalized.cache_hit,
            diagnostics=diagnostics,
            analyzers=analyzer_results,
            warnings=merge_warnings(top_warnings),
        )
        pages = [response.diagnostics]
        pages.extend(analyzer.output for analyzer in response.analyzers)
        enforce_response_budget(response, pages)
        return response

    async def _prepare_shortlink(
        self,
        request: CreateShortlinkRequest,
    ) -> list[_PreparedShortlink]:
        prepared: list[_PreparedShortlink] = []
        for configuration in request.compilers:
            compiler = await self._catalog.resolve_compiler(configuration.compiler)
            libraries = await self._catalog.resolve_libraries(
                configuration.libraries,
                compiler,
            )
            resolved = ShortlinkCompilerConfiguration(
                compiler=compiler.info.id,
                compiler_arguments=configuration.compiler_arguments,
                libraries=libraries,
                filters=configuration.filters,
            )
            compile_payload = build_compile_payload(
                source=request.source,
                compiler_arguments=resolved.compiler_arguments,
                libraries=resolved.libraries,
                filters=resolved.filters,
                skip_assembly=True,
            )
            prepared.append(
                _PreparedShortlink(
                    requested_selector=configuration.compiler,
                    compiler=compiler,
                    configuration=resolved,
                    compile_payload=compile_payload,
                    fingerprint=canonical_request_fingerprint(
                        compiler.info.id,
                        compile_payload,
                    ),
                )
            )
        return prepared

    async def create_shortlink(
        self,
        request: CreateShortlinkRequest,
    ) -> CreateShortlinkResult:
        prepared = await self._prepare_shortlink(request)
        validations: list[ShortlinkCompilerValidation] = []
        if request.validate_compilation:
            raw_results = await asyncio.gather(
                *(
                    self._client.compile(
                        item.compiler.info.id,
                        item.compile_payload,
                        item.fingerprint,
                    )
                    for item in prepared
                )
            )
            normalized_results = [normalize_compile_response(raw) for raw in raw_results]
            for item, normalized in zip(prepared, normalized_results, strict=True):
                if normalized.status != "success":
                    raise ShortlinkValidationFailure(
                        item.compiler.info.id,
                        normalized.status,
                        normalized.exit_code,
                    )
                validations.append(
                    ShortlinkCompilerValidation(
                        compiler=self._catalog.compiler_identity(
                            item.requested_selector,
                            item.compiler,
                        ),
                        fingerprint=item.fingerprint,
                        status="success",
                        exit_code=normalized.exit_code,
                    )
                )
        else:
            validations = [
                ShortlinkCompilerValidation(
                    compiler=self._catalog.compiler_identity(
                        item.requested_selector,
                        item.compiler,
                    ),
                    status="not_run",
                )
                for item in prepared
            ]
        payload = build_shortlink_payload(
            request.source,
            [item.configuration for item in prepared],
        )
        shortlink_id, _ = normalize_shortlink_creation(
            await self._client.create_shortlink(payload),
            self._client.shortlink_url("origin-check"),
        )
        response = CreateShortlinkResult(
            shortlink_id=shortlink_id,
            url=self._client.shortlink_url(shortlink_id),
            compilers=validations,
            compilation_validated=request.validate_compilation,
        )
        enforce_response_budget(response, [])
        return response

    async def get_shortlink(self, request: GetShortlinkRequest) -> GetShortlinkResult:
        response = normalize_shortlink_info(
            await self._client.get_shortlink(request.shortlink_id),
            request.shortlink_id,
            self._client.shortlink_url(request.shortlink_id),
        )
        enforce_shortlink_response_budget(response)
        enforce_response_budget(response, [])
        return response

    async def get_opcode_documentation(
        self,
        request: OpcodeDocumentationRequest,
    ) -> OpcodeDocumentation:
        raw = await self._client.get_opcode_documentation(
            request.instruction_set,
            request.opcode,
        )
        response = normalize_opcode_documentation(
            raw,
            request.instruction_set,
            request.opcode,
        )
        enforce_response_budget(response, [])
        return response
