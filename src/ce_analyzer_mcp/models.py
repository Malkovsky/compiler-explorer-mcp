from __future__ import annotations

import re
import shlex
from collections.abc import Sequence
from pathlib import PurePosixPath
from typing import Generic, Literal, TypeVar

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

MAX_TEXT_BYTES = 128 * 1024
MAX_AGGREGATE_SOURCE_BYTES = 256 * 1024
MAX_VIRTUAL_FILES = 32
MAX_COMPILER_ARGUMENTS = 128
MAX_COMPILER_ARGUMENT_BYTES = 8 * 1024
MAX_ANALYZERS = 4
MAX_ANALYZER_ARGUMENTS = 64
MAX_ANALYZER_ARGUMENT_BYTES = 4 * 1024
MAX_LIBRARIES = 8
MAX_SHORTLINK_COMPILERS = 6
MAX_SHORTLINK_SESSIONS = 8
MAX_SHORTLINK_SESSION_COMPILERS = 8
MAX_PAGE_SIZE = 50
MAX_WINDOW_SIZE = 1000
DEFAULT_WINDOW_SIZE = 200
MAX_LINE_BYTES = 4096
MAX_SERIALIZED_RESPONSE_BYTES = 1_000_000

_SELECTION_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+:/-]{0,127}$")
_OPCODE_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+-]{0,63}$")
_SHORTLINK_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$")
_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f-\x9f]")


class StrictModel(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        hide_input_in_errors=True,
        strict=True,
        validate_default=True,
    )


def _utf8_size(value: str, field: str) -> int:
    try:
        return len(value.encode("utf-8"))
    except UnicodeEncodeError as exc:
        raise ValueError(f"{field} must contain valid UTF-8 text") from exc


def _validate_text(value: str, field: str, maximum: int = MAX_TEXT_BYTES) -> str:
    if "\x00" in value:
        raise ValueError(f"{field} must not contain NUL")
    if _utf8_size(value, field) > maximum:
        raise ValueError(f"{field} exceeds {maximum} UTF-8 bytes")
    return value


def serialize_argument_tokens(tokens: Sequence[str]) -> str:
    """Serialize argument tokens in the exact form sent to Compiler Explorer."""

    return shlex.join(tokens)


def validate_tokens(
    values: list[str],
    *,
    field: str,
    maximum_count: int,
    maximum_bytes: int,
) -> list[str]:
    if len(values) > maximum_count:
        raise ValueError(f"{field} accepts at most {maximum_count} tokens")
    for token in values:
        if not token:
            raise ValueError(f"{field} tokens must not be empty")
        if "\x00" in token or "\n" in token or "\r" in token:
            raise ValueError(f"{field} tokens must not contain NUL or newlines")
        _utf8_size(token, field)
    serialized = serialize_argument_tokens(values)
    if _utf8_size(serialized, field) > maximum_bytes:
        raise ValueError(f"{field} exceeds {maximum_bytes} shell-serialized UTF-8 bytes")
    return values


def _validate_selector(value: str, field: str) -> str:
    if not _SELECTION_RE.fullmatch(value):
        raise ValueError(f"{field} is malformed")
    return value


def _validate_query(value: str) -> str:
    if len(value) > 200 or _CONTROL_RE.search(value):
        raise ValueError("query is malformed")
    return value


class VirtualFile(StrictModel):
    path: str
    content: str

    @field_validator("path")
    @classmethod
    def validate_path(cls, value: str) -> str:
        if not value or len(value) > 255:
            raise ValueError("virtual file path must contain 1 to 255 characters")
        if "\x00" in value or "\\" in value or _CONTROL_RE.search(value):
            raise ValueError("virtual file path must be a control-free POSIX path")
        path = PurePosixPath(value)
        if path.is_absolute() or value.endswith("/"):
            raise ValueError("virtual file path must be relative and name a file")
        if re.match(r"^[A-Za-z]:", value):
            raise ValueError("virtual file path must not contain a Windows drive prefix")
        if any(part in {"", ".", ".."} for part in value.split("/")):
            raise ValueError("virtual file path must not contain empty, dot, or parent segments")
        if value == "example.cpp":
            raise ValueError("virtual file path collides with the backend main source filename")
        if str(path) != value:
            raise ValueError("virtual file path must be normalized")
        return value

    @field_validator("content")
    @classmethod
    def validate_content(cls, value: str) -> str:
        return _validate_text(value, "virtual file content")


class SourceBundle(StrictModel):
    source: str
    files: list[VirtualFile] = Field(default_factory=list, max_length=MAX_VIRTUAL_FILES)

    @field_validator("source")
    @classmethod
    def validate_source(cls, value: str) -> str:
        return _validate_text(value, "source")

    @model_validator(mode="after")
    def validate_bundle(self) -> SourceBundle:
        paths = [file.path for file in self.files]
        if len(paths) != len(set(paths)):
            raise ValueError("virtual file paths must be unique")
        total = _utf8_size(self.source, "source")
        total += sum(_utf8_size(file.content, "virtual file content") for file in self.files)
        if total > MAX_AGGREGATE_SOURCE_BYTES:
            raise ValueError(
                f"aggregate source input exceeds {MAX_AGGREGATE_SOURCE_BYTES} UTF-8 bytes"
            )
        return self


class LibrarySelection(StrictModel):
    id: str
    version: str

    @field_validator("id")
    @classmethod
    def validate_id(cls, value: str) -> str:
        return _validate_selector(value, "library ID")

    @field_validator("version")
    @classmethod
    def validate_version(cls, value: str) -> str:
        return _validate_selector(value, "library version ID")


class AnalyzerSelection(StrictModel):
    id: str
    arguments: list[str] = Field(default_factory=list, max_length=MAX_ANALYZER_ARGUMENTS)

    @field_validator("id")
    @classmethod
    def validate_id(cls, value: str) -> str:
        return _validate_selector(value, "analyzer ID or alias")

    @field_validator("arguments")
    @classmethod
    def validate_arguments(cls, value: list[str]) -> list[str]:
        return validate_tokens(
            value,
            field="analyzer arguments",
            maximum_count=MAX_ANALYZER_ARGUMENTS,
            maximum_bytes=MAX_ANALYZER_ARGUMENT_BYTES,
        )


class AssemblyFilters(StrictModel):
    comment_only: bool = True
    demangle: bool = True
    directives: bool = True
    intel: bool = True
    labels: bool = True
    library_code: bool = False
    trim: bool = False
    debug_calls: bool = False


class OutputWindow(StrictModel):
    offset: int = Field(default=0, ge=0)
    limit: int = Field(default=DEFAULT_WINDOW_SIZE, ge=1, le=MAX_WINDOW_SIZE)


class SearchRequest(StrictModel):
    query: str = ""
    offset: int = Field(default=0, ge=0)
    limit: int = Field(default=20, ge=1, le=MAX_PAGE_SIZE)

    @field_validator("query")
    @classmethod
    def validate_query(cls, value: str) -> str:
        return _validate_query(value)


class SearchCompilersRequest(SearchRequest):
    pass


class SearchLibrariesRequest(SearchRequest):
    pass


class SearchAnalyzersRequest(SearchRequest):
    compiler: str | None = None

    @field_validator("compiler")
    @classmethod
    def validate_compiler(cls, value: str | None) -> str | None:
        if value is None:
            return None
        return _validate_selector(value, "compiler selector")


class CompileCppRequest(StrictModel):
    source: SourceBundle
    compiler: str = "gcc-latest"
    compiler_arguments: list[str] = Field(default_factory=list, max_length=MAX_COMPILER_ARGUMENTS)
    libraries: list[LibrarySelection] = Field(default_factory=list, max_length=MAX_LIBRARIES)
    filters: AssemblyFilters = Field(default_factory=AssemblyFilters)
    include_diagnostics: bool = True
    include_assembly: bool = True
    include_optimization: bool = False
    window: OutputWindow = Field(default_factory=OutputWindow)

    @field_validator("compiler")
    @classmethod
    def validate_compiler(cls, value: str) -> str:
        return _validate_selector(value, "compiler selector")

    @field_validator("compiler_arguments")
    @classmethod
    def validate_compiler_arguments(cls, value: list[str]) -> list[str]:
        return validate_tokens(
            value,
            field="compiler arguments",
            maximum_count=MAX_COMPILER_ARGUMENTS,
            maximum_bytes=MAX_COMPILER_ARGUMENT_BYTES,
        )


class ComparisonCase(StrictModel):
    label: str = Field(min_length=1, max_length=64)
    compiler: str
    compiler_arguments: list[str] = Field(default_factory=list, max_length=MAX_COMPILER_ARGUMENTS)
    libraries: list[LibrarySelection] = Field(default_factory=list, max_length=MAX_LIBRARIES)
    filters: AssemblyFilters = Field(default_factory=AssemblyFilters)

    @field_validator("label")
    @classmethod
    def validate_label(cls, value: str) -> str:
        if _CONTROL_RE.search(value):
            raise ValueError("comparison label must not contain control characters")
        return value

    @field_validator("compiler")
    @classmethod
    def validate_compiler(cls, value: str) -> str:
        return _validate_selector(value, "compiler selector")

    @field_validator("compiler_arguments")
    @classmethod
    def validate_compiler_arguments(cls, value: list[str]) -> list[str]:
        return validate_tokens(
            value,
            field="compiler arguments",
            maximum_count=MAX_COMPILER_ARGUMENTS,
            maximum_bytes=MAX_COMPILER_ARGUMENT_BYTES,
        )


class CompareCppRequest(StrictModel):
    source: SourceBundle
    cases: list[ComparisonCase] = Field(min_length=2, max_length=6)
    window: OutputWindow = Field(default_factory=OutputWindow)

    @model_validator(mode="after")
    def validate_labels(self) -> CompareCppRequest:
        labels = [case.label.casefold() for case in self.cases]
        if len(labels) != len(set(labels)):
            raise ValueError("comparison case labels must be unique")
        return self


class AnalyzeCppRequest(StrictModel):
    source: SourceBundle
    compiler: str = "clang-latest"
    compiler_arguments: list[str] = Field(default_factory=list, max_length=MAX_COMPILER_ARGUMENTS)
    libraries: list[LibrarySelection] = Field(default_factory=list, max_length=MAX_LIBRARIES)
    analyzers: list[AnalyzerSelection] = Field(min_length=1, max_length=MAX_ANALYZERS)
    filters: AssemblyFilters = Field(default_factory=AssemblyFilters)
    window: OutputWindow = Field(default_factory=OutputWindow)

    @field_validator("compiler")
    @classmethod
    def validate_compiler(cls, value: str) -> str:
        return _validate_selector(value, "compiler selector")

    @field_validator("compiler_arguments")
    @classmethod
    def validate_compiler_arguments(cls, value: list[str]) -> list[str]:
        return validate_tokens(
            value,
            field="compiler arguments",
            maximum_count=MAX_COMPILER_ARGUMENTS,
            maximum_bytes=MAX_COMPILER_ARGUMENT_BYTES,
        )

    @model_validator(mode="after")
    def validate_analyzers(self) -> AnalyzeCppRequest:
        analyzer_ids = [analyzer.id for analyzer in self.analyzers]
        if len(analyzer_ids) != len(set(analyzer_ids)):
            raise ValueError("analyzer selections must be unique")
        total_bytes = sum(
            _utf8_size(
                serialize_argument_tokens(analyzer.arguments),
                "analyzer arguments",
            )
            for analyzer in self.analyzers
        )
        if total_bytes > MAX_ANALYZER_ARGUMENT_BYTES:
            raise ValueError(
                "analyzer arguments exceed "
                f"{MAX_ANALYZER_ARGUMENT_BYTES} aggregate shell-serialized UTF-8 bytes"
            )
        return self


class ShortlinkCompilerConfiguration(StrictModel):
    compiler: str = "gcc-latest"
    compiler_arguments: list[str] = Field(default_factory=list, max_length=MAX_COMPILER_ARGUMENTS)
    libraries: list[LibrarySelection] = Field(default_factory=list, max_length=MAX_LIBRARIES)
    filters: AssemblyFilters = Field(default_factory=AssemblyFilters)

    @field_validator("compiler")
    @classmethod
    def validate_compiler(cls, value: str) -> str:
        return _validate_selector(value, "compiler selector")

    @field_validator("compiler_arguments")
    @classmethod
    def validate_compiler_arguments(cls, value: list[str]) -> list[str]:
        validated = validate_tokens(
            value,
            field="compiler arguments",
            maximum_count=MAX_COMPILER_ARGUMENTS,
            maximum_bytes=MAX_COMPILER_ARGUMENT_BYTES,
        )
        if any(_CONTROL_RE.search(token) for token in validated):
            raise ValueError("shortlink compiler arguments must not contain control characters")
        return validated


class CreateShortlinkRequest(StrictModel):
    source: SourceBundle
    compilers: list[ShortlinkCompilerConfiguration] = Field(
        min_length=1,
        max_length=MAX_SHORTLINK_COMPILERS,
    )
    validate_compilation: bool = True

    @model_validator(mode="after")
    def reject_virtual_files(self) -> CreateShortlinkRequest:
        if self.source.files:
            raise ValueError("shortlinks do not support virtual files")
        return self


class GetShortlinkRequest(StrictModel):
    shortlink_id: str

    @field_validator("shortlink_id")
    @classmethod
    def validate_shortlink_id(cls, value: str) -> str:
        if not _SHORTLINK_ID_RE.fullmatch(value):
            raise ValueError("shortlink ID is malformed")
        return value


class OpcodeDocumentationRequest(StrictModel):
    instruction_set: str
    opcode: str

    @field_validator("instruction_set")
    @classmethod
    def validate_instruction_set(cls, value: str) -> str:
        if not _OPCODE_ID_RE.fullmatch(value):
            raise ValueError("instruction set ID is malformed")
        return value

    @field_validator("opcode")
    @classmethod
    def validate_opcode(cls, value: str) -> str:
        if not _OPCODE_ID_RE.fullmatch(value):
            raise ValueError("opcode ID is malformed")
        return value


class WarningItem(StrictModel):
    code: str
    message: str


class PageInfo(StrictModel):
    offset: int
    limit: int
    total: int
    returned: int
    truncated_before: bool
    truncated_after: bool
    next_offset: int | None = None


T = TypeVar("T")


class Page(StrictModel, Generic[T]):
    items: list[T]
    page: PageInfo


class AliasResolution(StrictModel):
    alias: str
    status: Literal["resolved", "ambiguous", "unavailable"]
    resolved_id: str | None = None
    resolved_name: str | None = None
    candidates: list[str] = Field(default_factory=list)


class CompilerInfo(StrictModel):
    id: str
    name: str
    family: Literal["gcc", "clang", "msvc", "other"]
    version: str
    instruction_set: str | None = None
    release_track: str | None = None
    supports_optimization_output: bool | None = None
    aliases: list[str] = Field(default_factory=list)


class CompilerSearchResult(StrictModel):
    compilers: Page[CompilerInfo]
    aliases: list[AliasResolution]
    warnings: list[WarningItem] = Field(default_factory=list)
    response_truncated: bool = False


class LibraryInfo(StrictModel):
    id: str
    name: str
    version_id: str
    version: str
    version_name: str | None = None
    description: str | None = None
    url: str | None = None


class LibrarySearchResult(StrictModel):
    libraries: Page[LibraryInfo]
    warnings: list[WarningItem] = Field(default_factory=list)
    response_truncated: bool = False


class AnalyzerInfo(StrictModel):
    id: str
    name: str
    kind: str | None = None
    aliases: list[str] = Field(default_factory=list)
    compiler_compatible: bool | None = None


class AnalyzerSearchResult(StrictModel):
    analyzers: Page[AnalyzerInfo]
    aliases: list[AliasResolution]
    compiler: CompilerIdentity | None = None
    warnings: list[WarningItem] = Field(default_factory=list)
    response_truncated: bool = False


class CompilerIdentity(StrictModel):
    requested_selector: str
    resolved_id: str
    name: str
    version: str


class ShortlinkCompilerValidation(StrictModel):
    compiler: CompilerIdentity
    fingerprint: str | None = None
    status: Literal["success", "not_run"]
    exit_code: int | None = None


class CreateShortlinkResult(StrictModel):
    shortlink_id: str
    url: str
    compilers: list[ShortlinkCompilerValidation]
    compilation_validated: bool
    warnings: list[WarningItem] = Field(default_factory=list)
    response_truncated: bool = False


class ShortlinkCompilerInfo(StrictModel):
    compiler_id: str
    options: str
    libraries: list[LibrarySelection] = Field(default_factory=list, max_length=MAX_LIBRARIES)
    filters: AssemblyFilters = Field(default_factory=AssemblyFilters)

    @field_validator("compiler_id")
    @classmethod
    def validate_compiler_id(cls, value: str) -> str:
        return _validate_selector(value, "compiler ID")

    @field_validator("options")
    @classmethod
    def validate_options(cls, value: str) -> str:
        if _CONTROL_RE.search(value):
            raise ValueError("compiler options must not contain control characters")
        return _validate_text(value, "compiler options", MAX_COMPILER_ARGUMENT_BYTES)


class ShortlinkSessionInfo(StrictModel):
    session_id: int | str | None = None
    language: Literal["c++"] = "c++"
    source: str
    compilers: list[ShortlinkCompilerInfo] = Field(
        default_factory=list,
        max_length=MAX_SHORTLINK_SESSION_COMPILERS,
    )

    @field_validator("session_id")
    @classmethod
    def validate_session_id(cls, value: int | str | None) -> int | str | None:
        if isinstance(value, str) and (not value or len(value) > 128 or _CONTROL_RE.search(value)):
            raise ValueError("shortlink session ID is malformed")
        return value

    @field_validator("source")
    @classmethod
    def validate_source(cls, value: str) -> str:
        return _validate_text(value, "shortlink source")


class GetShortlinkResult(StrictModel):
    shortlink_id: str
    url: str
    sessions: list[ShortlinkSessionInfo] = Field(max_length=MAX_SHORTLINK_SESSIONS)
    has_trees: bool = False
    warnings: list[WarningItem] = Field(default_factory=list)
    response_truncated: bool = False

    @model_validator(mode="after")
    def validate_aggregate_source(self) -> GetShortlinkResult:
        total = sum(_utf8_size(session.source, "shortlink source") for session in self.sessions)
        if total > MAX_AGGREGATE_SOURCE_BYTES:
            raise ValueError(
                f"aggregate shortlink source exceeds {MAX_AGGREGATE_SOURCE_BYTES} UTF-8 bytes"
            )
        return self


class DiagnosticLink(StrictModel):
    text: str
    url: str


class DiagnosticFlowStep(StrictModel):
    text: str
    file: str | None = None
    line: int | None = None
    column: int | None = None


class DiagnosticTag(StrictModel):
    text: str
    severity: int | None = None
    file: str | None = None
    line: int | None = None
    column: int | None = None
    end_line: int | None = None
    end_column: int | None = None
    link: DiagnosticLink | None = None
    flow: list[DiagnosticFlowStep] = Field(default_factory=list)


class DiagnosticLine(StrictModel):
    stream: Literal["stdout", "stderr"]
    text: str
    text_truncated: bool = False
    tag: DiagnosticTag | None = None


class SourceLocation(StrictModel):
    file: str | None = None
    line: int | None = None
    column: int | None = None
    main_source: bool | None = None


class AssemblyLabel(StrictModel):
    name: str
    target: str | None = None
    start_column: int | None = None
    end_column: int | None = None


class AssemblyLine(StrictModel):
    text: str
    text_truncated: bool = False
    source: SourceLocation | None = None
    opcodes: list[str] = Field(default_factory=list)
    address: int | None = None
    labels: list[AssemblyLabel] = Field(default_factory=list)


class OptimizationRecord(StrictModel):
    pass_name: str | None = None
    name: str | None = None
    optimization_type: str | None = None
    function: str | None = None
    display: str
    text_truncated: bool = False
    source: SourceLocation | None = None


class CompileResult(StrictModel):
    fingerprint: str
    compiler: CompilerIdentity
    status: Literal["success", "failed", "timed_out"]
    exit_code: int
    timed_out: bool
    backend_truncated: bool | None = None
    cache_eligible: bool | None = None
    cache_hit: bool | None = None
    diagnostics: Page[DiagnosticLine] | None = None
    assembly: Page[AssemblyLine] | None = None
    optimization: Page[OptimizationRecord] | None = None
    assembly_line_count: int
    assembly_sha256: str | None = None
    warnings: list[WarningItem] = Field(default_factory=list)
    response_truncated: bool = False


class CompareCaseResult(StrictModel):
    label: str
    fingerprint: str
    compiler: CompilerIdentity
    status: Literal["success", "failed", "timed_out", "error"]
    exit_code: int | None
    timed_out: bool
    backend_truncated: bool | None = None
    cache_eligible: bool | None = None
    cache_hit: bool | None = None
    diagnostics: Page[DiagnosticLine]
    assembly_line_count: int
    assembly_sha256: str | None = None
    warnings: list[WarningItem] = Field(default_factory=list)


class AssemblyComparison(StrictModel):
    baseline_label: str
    candidate_label: str
    baseline_sha256: str | None = None
    candidate_sha256: str | None = None
    identical: bool | None = None
    diff: Page[str] | None = None
    omission_code: (
        Literal[
            "baseline_failed",
            "candidate_failed",
            "assembly_unavailable",
            "diff_input_limit_exceeded",
        ]
        | None
    ) = None
    omission_reason: str | None = None
    diff_input_limit: int | None = None
    baseline_input_line_count: int
    candidate_input_line_count: int


class CompareResult(StrictModel):
    cases: list[CompareCaseResult]
    comparisons: list[AssemblyComparison]
    benchmark_warning: WarningItem
    warnings: list[WarningItem] = Field(default_factory=list)
    response_truncated: bool = False


class AnalyzerRunResult(StrictModel):
    requested_selector: str
    resolved_id: str
    name: str
    status: Literal["success", "failed", "missing", "malformed"]
    exit_code: int | None = None
    output: Page[DiagnosticLine]
    warnings: list[WarningItem] = Field(default_factory=list)


class AnalyzeResult(StrictModel):
    fingerprint: str
    compiler: CompilerIdentity
    status: Literal["success", "failed", "timed_out"]
    exit_code: int
    timed_out: bool
    backend_truncated: bool | None = None
    cache_eligible: bool | None = None
    cache_hit: bool | None = None
    diagnostics: Page[DiagnosticLine]
    analyzers: list[AnalyzerRunResult]
    warnings: list[WarningItem] = Field(default_factory=list)
    response_truncated: bool = False


class OpcodeDocumentation(StrictModel):
    instruction_set: str
    opcode: str
    tooltip: str
    html: str
    source_url: str
    tooltip_truncated: bool = False
    html_truncated: bool = False
    warnings: list[WarningItem] = Field(default_factory=list)
    response_truncated: bool = False
