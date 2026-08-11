from __future__ import annotations

from collections.abc import Callable

import pytest
from pydantic import ValidationError

from ce_analyzer_mcp.models import (
    DEFAULT_WINDOW_SIZE,
    MAX_AGGREGATE_SOURCE_BYTES,
    MAX_ANALYZER_ARGUMENT_BYTES,
    MAX_ANALYZER_ARGUMENTS,
    MAX_ANALYZERS,
    MAX_COMPILER_ARGUMENT_BYTES,
    MAX_COMPILER_ARGUMENTS,
    MAX_LIBRARIES,
    MAX_PAGE_SIZE,
    MAX_SHORTLINK_COMPILERS,
    MAX_TEXT_BYTES,
    MAX_VIRTUAL_FILES,
    MAX_WINDOW_SIZE,
    AnalyzeCppRequest,
    AnalyzerSelection,
    AssemblyFilters,
    CompareCppRequest,
    ComparisonCase,
    CompileCppRequest,
    CreateShortlinkRequest,
    GetShortlinkRequest,
    LibrarySelection,
    OpcodeDocumentationRequest,
    OutputWindow,
    SearchAnalyzersRequest,
    SearchCompilersRequest,
    SearchLibrariesRequest,
    ShortlinkCompilerConfiguration,
    SourceBundle,
    VirtualFile,
    validate_tokens,
)


def _validation_message(factory: Callable[[], object]) -> str:
    with pytest.raises(ValidationError) as raised:
        factory()
    return str(raised.value)


def _library(index: int) -> LibrarySelection:
    return LibrarySelection(id=f"library-{index}", version=f"version-{index}")


def _analyzer(index: int, arguments: list[str] | None = None) -> AnalyzerSelection:
    return AnalyzerSelection(id=f"analyzer-{index}", arguments=arguments or [])


def _case(index: int, *, label: str | None = None) -> ComparisonCase:
    return ComparisonCase(label=label or f"case-{index}", compiler=f"compiler-{index}")


def test_virtual_file_accepts_normalized_relative_posix_paths() -> None:
    for path in ["header.h", "include/header.hpp", "a/b/c++_header-1.inc", "é.hpp"]:
        assert VirtualFile(path=path, content="// content").path == path


@pytest.mark.parametrize(
    "path",
    [
        "",
        "/etc/passwd",
        "C:\\Windows\\system.ini",
        "C:/Windows/system.ini",
        "../secret.hpp",
        "include/../secret.hpp",
        "./header.hpp",
        "include/./header.hpp",
        "include//header.hpp",
        "include/",
        "header.hpp\x00suffix",
        "header.hpp\nother",
        "header.hpp\x7f",
        "example.cpp",
        "a" * 256,
    ],
)
def test_virtual_file_rejects_hostile_or_non_normalized_paths(path: str) -> None:
    assert "virtual file path" in _validation_message(lambda: VirtualFile(path=path, content=""))


def test_virtual_file_path_length_boundary() -> None:
    assert len(VirtualFile(path="a" * 255, content="").path) == 255
    with pytest.raises(ValidationError):
        VirtualFile(path="a" * 256, content="")


@pytest.mark.parametrize("field", ["source", "virtual file"])
def test_each_text_field_enforces_utf8_byte_limit_and_nul(field: str) -> None:
    exact = "é" * (MAX_TEXT_BYTES // 2)
    too_large = exact + "a"
    if field == "source":
        assert SourceBundle(source=exact).source == exact
        with pytest.raises(ValidationError, match="UTF-8 bytes"):
            SourceBundle(source=too_large)
        with pytest.raises(ValidationError, match="NUL"):
            SourceBundle(source="x\x00y")
    else:
        assert VirtualFile(path="x.hpp", content=exact).content == exact
        with pytest.raises(ValidationError, match="UTF-8 bytes"):
            VirtualFile(path="x.hpp", content=too_large)
        with pytest.raises(ValidationError, match="NUL"):
            VirtualFile(path="x.hpp", content="x\x00y")


def test_text_rejects_unpaired_surrogates_as_invalid_utf8() -> None:
    with pytest.raises(ValidationError, match="valid UTF-8"):
        SourceBundle(source="\ud800")
    with pytest.raises(ValidationError, match="valid UTF-8"):
        VirtualFile(path="x.hpp", content="\udfff")


def test_source_bundle_virtual_file_count_boundaries() -> None:
    files = [
        VirtualFile(path=f"file-{index}.hpp", content="") for index in range(MAX_VIRTUAL_FILES)
    ]
    assert len(SourceBundle(source="", files=files).files) == MAX_VIRTUAL_FILES

    files.append(VirtualFile(path="one-too-many.hpp", content=""))
    with pytest.raises(ValidationError):
        SourceBundle(source="", files=files)


def test_source_bundle_rejects_duplicate_paths_but_keeps_posix_case_distinct() -> None:
    duplicate = VirtualFile(path="include/a.hpp", content="one")
    with pytest.raises(ValidationError, match="paths must be unique"):
        SourceBundle(source="", files=[duplicate, duplicate.model_copy(update={"content": "two"})])

    bundle = SourceBundle(
        source="",
        files=[
            VirtualFile(path="include/A.hpp", content=""),
            VirtualFile(path="include/a.hpp", content=""),
        ],
    )
    assert len(bundle.files) == 2


def test_aggregate_source_size_uses_utf8_bytes_and_exact_boundary() -> None:
    bundle = SourceBundle(
        source="a" * MAX_TEXT_BYTES,
        files=[VirtualFile(path="extra.hpp", content="é" * (MAX_TEXT_BYTES // 2))],
    )
    assert len(bundle.source.encode()) + len(bundle.files[0].content.encode()) == (
        MAX_AGGREGATE_SOURCE_BYTES
    )

    with pytest.raises(ValidationError, match="aggregate source input"):
        SourceBundle(
            source="a" * MAX_TEXT_BYTES,
            files=[
                VirtualFile(path="extra.hpp", content="é" * (MAX_TEXT_BYTES // 2)),
                VirtualFile(path="overflow.hpp", content="x"),
            ],
        )


@pytest.mark.parametrize(
    "tokens",
    [
        [""],
        ["-DNAME=x\x00y"],
        ["-DNAME=x\ny"],
        ["-DNAME=x\ry"],
        ["\ud800"],
    ],
)
def test_token_validation_rejects_empty_control_and_non_utf8_tokens(tokens: list[str]) -> None:
    with pytest.raises(ValueError):
        validate_tokens(tokens, field="arguments", maximum_count=2, maximum_bytes=20)


def test_token_validation_counts_shell_serialized_utf8_bytes() -> None:
    assert validate_tokens(["é", "x"], field="arguments", maximum_count=2, maximum_bytes=6) == [
        "é",
        "x",
    ]
    with pytest.raises(ValueError, match="exceeds 5 shell-serialized UTF-8 bytes"):
        validate_tokens(["é", "x"], field="arguments", maximum_count=2, maximum_bytes=5)


def test_token_validation_rejects_shell_quote_expansion_beyond_budget() -> None:
    with pytest.raises(ValueError, match="shell-serialized UTF-8 bytes"):
        validate_tokens(["'" * 100], field="arguments", maximum_count=1, maximum_bytes=128)


def test_compiler_argument_count_and_byte_boundaries() -> None:
    maximum_count = ["x"] * MAX_COMPILER_ARGUMENTS
    assert len(
        CompileCppRequest(
            source={"source": ""}, compiler_arguments=maximum_count
        ).compiler_arguments
    ) == (MAX_COMPILER_ARGUMENTS)
    with pytest.raises(ValidationError):
        CompileCppRequest(source={"source": ""}, compiler_arguments=[*maximum_count, "x"])

    exact_bytes = "x" * MAX_COMPILER_ARGUMENT_BYTES
    assert CompileCppRequest(source={"source": ""}, compiler_arguments=[exact_bytes])
    with pytest.raises(ValidationError, match="compiler arguments exceeds"):
        CompileCppRequest(source={"source": ""}, compiler_arguments=[exact_bytes + "x"])


def test_analyzer_argument_count_and_byte_boundaries() -> None:
    maximum_count = ["x"] * MAX_ANALYZER_ARGUMENTS
    assert len(AnalyzerSelection(id="tool", arguments=maximum_count).arguments) == (
        MAX_ANALYZER_ARGUMENTS
    )
    with pytest.raises(ValidationError):
        AnalyzerSelection(id="tool", arguments=[*maximum_count, "x"])

    exact_bytes = "é" * ((MAX_ANALYZER_ARGUMENT_BYTES - 2) // 2)
    assert AnalyzerSelection(id="tool", arguments=[exact_bytes])
    with pytest.raises(ValidationError, match="analyzer arguments exceeds"):
        AnalyzerSelection(id="tool", arguments=[exact_bytes + "é"])


def test_analyze_request_enforces_total_analyzer_argument_budget() -> None:
    half_budget = "x" * (MAX_ANALYZER_ARGUMENT_BYTES // 2 + 1)
    with pytest.raises(ValidationError, match="analyzer arguments"):
        AnalyzeCppRequest(
            source={"source": ""},
            analyzers=[
                {"id": "clang-tidy", "arguments": [half_budget]},
                {"id": "iwyu", "arguments": [half_budget]},
            ],
        )


def test_analyze_request_counts_serialized_quote_expansion_in_aggregate_budget() -> None:
    quote_heavy = "'" * 410
    with pytest.raises(ValidationError, match="aggregate shell-serialized UTF-8 bytes"):
        AnalyzeCppRequest(
            source={"source": ""},
            analyzers=[
                {"id": "clang-tidy", "arguments": [quote_heavy]},
                {"id": "iwyu", "arguments": [quote_heavy]},
            ],
        )


@pytest.mark.parametrize(
    "value",
    ["", " bad", "bad value", "bad\nvalue", "bad?value", "bad#value", "a" * 129],
)
def test_selection_ids_are_strict(value: str) -> None:
    for factory in (
        lambda: LibrarySelection(id=value, version="v1"),
        lambda: LibrarySelection(id="lib", version=value),
        lambda: AnalyzerSelection(id=value),
        lambda: CompileCppRequest(source={"source": ""}, compiler=value),
        lambda: SearchAnalyzersRequest(compiler=value),
    ):
        with pytest.raises(ValidationError):
            factory()


def test_selection_ids_accept_backend_pathlike_punctuation() -> None:
    selection = LibrarySelection(id="boost.system+headers", version="1.85.0/x64")
    analyzer = AnalyzerSelection(id="tool:id_v2")
    assert selection.model_dump() == {"id": "boost.system+headers", "version": "1.85.0/x64"}
    assert analyzer.id == "tool:id_v2"


def test_compile_request_defaults_are_compile_only_shaped_and_independent() -> None:
    first = CompileCppRequest(source={"source": "int main() {}"})
    second = CompileCppRequest(source={"source": ""})

    assert first.compiler == "gcc-latest"
    assert first.compiler_arguments == []
    assert first.libraries == []
    assert first.filters == AssemblyFilters()
    assert first.include_diagnostics is True
    assert first.include_assembly is True
    assert first.include_optimization is False
    assert first.window == OutputWindow(offset=0, limit=DEFAULT_WINDOW_SIZE)
    first.compiler_arguments.append("-O2")
    assert second.compiler_arguments == []


def test_assembly_filter_defaults_and_strict_types() -> None:
    filters = AssemblyFilters()
    assert filters.model_dump() == {
        "comment_only": True,
        "demangle": True,
        "directives": True,
        "intel": True,
        "labels": True,
        "library_code": False,
        "trim": False,
        "debug_calls": False,
    }
    with pytest.raises(ValidationError):
        AssemblyFilters(intel=1)


def test_library_count_boundary() -> None:
    libraries = [_library(index) for index in range(MAX_LIBRARIES)]
    assert len(CompileCppRequest(source={"source": ""}, libraries=libraries).libraries) == (
        MAX_LIBRARIES
    )
    with pytest.raises(ValidationError):
        CompileCppRequest(source={"source": ""}, libraries=[*libraries, _library(99)])


def test_analyzer_count_duplicate_and_default_compiler_rules() -> None:
    analyzers = [_analyzer(index) for index in range(MAX_ANALYZERS)]
    request = AnalyzeCppRequest(source={"source": ""}, analyzers=analyzers)
    assert request.compiler == "clang-latest"
    assert len(request.analyzers) == MAX_ANALYZERS

    with pytest.raises(ValidationError):
        AnalyzeCppRequest(source={"source": ""}, analyzers=[])
    with pytest.raises(ValidationError):
        AnalyzeCppRequest(source={"source": ""}, analyzers=[*analyzers, _analyzer(MAX_ANALYZERS)])
    with pytest.raises(ValidationError, match="analyzer selections must be unique"):
        AnalyzeCppRequest(
            source={"source": ""},
            analyzers=[AnalyzerSelection(id="tool"), AnalyzerSelection(id="tool")],
        )


def test_comparison_case_count_and_case_insensitive_unique_labels() -> None:
    minimum = CompareCppRequest(source={"source": ""}, cases=[_case(0), _case(1)])
    assert len(minimum.cases) == 2
    maximum = CompareCppRequest(source={"source": ""}, cases=[_case(index) for index in range(6)])
    assert len(maximum.cases) == 6

    with pytest.raises(ValidationError):
        CompareCppRequest(source={"source": ""}, cases=[_case(0)])
    with pytest.raises(ValidationError):
        CompareCppRequest(source={"source": ""}, cases=[_case(index) for index in range(7)])
    with pytest.raises(ValidationError, match="labels must be unique"):
        CompareCppRequest(
            source={"source": ""},
            cases=[_case(0, label="Baseline"), _case(1, label="baseline")],
        )


def test_shortlink_creation_defaults_limits_and_virtual_file_policy() -> None:
    configuration = ShortlinkCompilerConfiguration()
    assert configuration.compiler == "gcc-latest"
    assert configuration.compiler_arguments == []
    assert configuration.libraries == []
    assert configuration.filters == AssemblyFilters()

    compilers = [
        ShortlinkCompilerConfiguration(compiler=f"compiler-{index}")
        for index in range(MAX_SHORTLINK_COMPILERS)
    ]
    request = CreateShortlinkRequest(source={"source": "int f();"}, compilers=compilers)
    assert request.validate_compilation is True
    assert len(request.compilers) == MAX_SHORTLINK_COMPILERS
    with pytest.raises(ValidationError):
        CreateShortlinkRequest(source={"source": ""}, compilers=[])
    with pytest.raises(ValidationError):
        CreateShortlinkRequest(
            source={"source": ""},
            compilers=[*compilers, ShortlinkCompilerConfiguration(compiler="extra")],
        )

    with pytest.raises(ValidationError, match="control characters"):
        ShortlinkCompilerConfiguration(compiler_arguments=["-DVALUE=bad\tvalue"])
    with pytest.raises(ValidationError, match="do not support virtual files"):
        CreateShortlinkRequest(
            source={"source": "", "files": [{"path": "x.hpp", "content": ""}]},
            compilers=[configuration],
        )


@pytest.mark.parametrize(
    "shortlink_id",
    ["", "bad/id", "https://godbolt.org/z/abc", "bad?id", "bad#id", "bad id", "x" * 129],
)
def test_shortlink_id_policy_rejects_urls_paths_and_malformed_ids(shortlink_id: str) -> None:
    with pytest.raises(ValidationError, match="shortlink ID is malformed"):
        GetShortlinkRequest(shortlink_id=shortlink_id)


def test_shortlink_id_policy_accepts_builtin_url_safe_ids() -> None:
    assert GetShortlinkRequest(shortlink_id="Km_340-test").shortlink_id == "Km_340-test"


@pytest.mark.parametrize("label", ["", "x" * 65, "line\nbreak", "nul\x00byte", "delete\x7f"])
def test_comparison_label_limits(label: str) -> None:
    with pytest.raises(ValidationError):
        ComparisonCase(label=label, compiler="gcc")


@pytest.mark.parametrize(
    "request_type", [SearchCompilersRequest, SearchLibrariesRequest, SearchAnalyzersRequest]
)
def test_search_defaults_limits_and_query_policy(request_type: type) -> None:
    request = request_type()
    expected = {"query": "", "offset": 0, "limit": 20}
    if request_type is SearchAnalyzersRequest:
        expected["compiler"] = None
    assert request.model_dump() == expected
    assert request_type(offset=5, limit=MAX_PAGE_SIZE).limit == MAX_PAGE_SIZE

    for values in (
        {"offset": -1},
        {"limit": 0},
        {"limit": MAX_PAGE_SIZE + 1},
        {"query": "x" * 201},
        {"query": "x\n"},
    ):
        with pytest.raises(ValidationError):
            request_type(**values)


def test_output_window_boundaries() -> None:
    assert OutputWindow() == OutputWindow(offset=0, limit=DEFAULT_WINDOW_SIZE)
    assert OutputWindow(offset=2**63, limit=MAX_WINDOW_SIZE).offset == 2**63
    for values in ({"offset": -1}, {"limit": 0}, {"limit": MAX_WINDOW_SIZE + 1}):
        with pytest.raises(ValidationError):
            OutputWindow(**values)


@pytest.mark.parametrize(
    "values",
    [
        {"instruction_set": "", "opcode": "mov"},
        {"instruction_set": "x86/64", "opcode": "mov"},
        {"instruction_set": "x86-64", "opcode": "mov eax,ebx"},
        {"instruction_set": "x86-64", "opcode": "x" * 65},
        {"instruction_set": "x86-64", "opcode": "mov\n"},
    ],
)
def test_opcode_identifier_policy(values: dict[str, str]) -> None:
    with pytest.raises(ValidationError):
        OpcodeDocumentationRequest(**values)


def test_opcode_identifier_valid_punctuation() -> None:
    request = OpcodeDocumentationRequest(instruction_set="x86-64_v2", opcode="vadd.ps+mask")
    assert request.model_dump() == {"instruction_set": "x86-64_v2", "opcode": "vadd.ps+mask"}


@pytest.mark.parametrize(
    ("model", "values"),
    [
        (VirtualFile, {"path": "x.hpp", "content": "", "extra": True}),
        (SourceBundle, {"source": "", "path": "/tmp/source.cpp"}),
        (CompileCppRequest, {"source": {"source": ""}, "execute": True}),
        (
            CreateShortlinkRequest,
            {
                "source": {"source": ""},
                "compilers": [{"compiler": "gcc"}],
                "backend_url": "https://evil.test",
            },
        ),
        (GetShortlinkRequest, {"shortlink_id": "abc", "url": "https://evil.test"}),
        (AnalyzeCppRequest, {"source": {"source": ""}, "analyzers": [{"id": "x"}], "stdin": "x"}),
        (
            CompareCppRequest,
            {
                "source": {"source": ""},
                "cases": [{"label": "a", "compiler": "a"}, {"label": "b", "compiler": "b"}],
                "backend_url": "https://evil.test",
            },
        ),
    ],
)
def test_request_models_forbid_extra_policy_escape_fields(
    model: type, values: dict[str, object]
) -> None:
    with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
        model.model_validate(values)


def test_request_models_are_strict_about_container_and_scalar_types() -> None:
    with pytest.raises(ValidationError):
        SourceBundle.model_validate({"source": 123})
    with pytest.raises(ValidationError):
        CompileCppRequest.model_validate({"source": {"source": ""}, "compiler_arguments": "-O2"})
    with pytest.raises(ValidationError):
        SearchCompilersRequest.model_validate({"offset": "0"})
    with pytest.raises(ValidationError):
        AnalyzeCppRequest.model_validate(
            {"source": {"source": ""}, "analyzers": [{"id": "x"}], "filters": {"intel": 1}}
        )
