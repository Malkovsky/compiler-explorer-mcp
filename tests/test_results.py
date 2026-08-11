from __future__ import annotations

import hashlib
import json
from typing import Any

import pytest

from ce_analyzer_mcp.client import canonical_request_fingerprint
from ce_analyzer_mcp.errors import IncompatibleBackend
from ce_analyzer_mcp.models import (
    MAX_LINE_BYTES,
    MAX_TEXT_BYTES,
    AssemblyLine,
    CompileResult,
    CompilerIdentity,
    OutputWindow,
    WarningItem,
)
from ce_analyzer_mcp.results import (
    assembly_fingerprint,
    enforce_response_budget,
    enforce_shortlink_response_budget,
    merge_warnings,
    normalize_compile_response,
    normalize_opcode_documentation,
    normalize_shortlink_creation,
    normalize_shortlink_info,
    sanitize_html,
    sanitize_text,
    truncate_text,
    window_page,
)


def _warning_codes(value: Any) -> set[str]:
    return {warning.code for warning in value.warnings}


def test_normalizes_builtin_shortlink_creation_url() -> None:
    assert normalize_shortlink_creation({"url": "https://godbolt.org/compiler/z/Km_340-test"}) == (
        "Km_340-test",
        "https://godbolt.org/compiler/z/Km_340-test",
    )


@pytest.mark.parametrize(
    "url",
    [
        "https://godbolt.org/x/abc",
        "https://godbolt.org/z/bad/id",
        "https://user:secret@godbolt.org/z/abc",
        "https://godbolt.org/z/abc?tracking=1",
        "https://godbolt.org/z/abc#fragment",
        "javascript:alert(1)",
        "https://godbolt.org/z/bad%20id",
    ],
)
def test_rejects_malformed_or_non_builtin_shortlink_creation_urls(url: str) -> None:
    with pytest.raises(IncompatibleBackend):
        normalize_shortlink_creation({"url": url})


def test_rejects_shortlink_creation_url_from_foreign_origin_or_path_prefix() -> None:
    for url in ("https://evil.test/z/abc", "https://godbolt.org/other/z/abc"):
        with pytest.raises(IncompatibleBackend, match="foreign-origin"):
            normalize_shortlink_creation(
                {"url": url},
                "https://godbolt.org/compiler/z/origin-check",
            )


def test_shortlink_origin_comparison_normalizes_default_ports() -> None:
    assert (
        normalize_shortlink_creation(
            {"url": "https://godbolt.org/z/abc"},
            "https://godbolt.org:443/z/origin-check",
        )[0]
        == "abc"
    )


def test_normalizes_shortlink_state_and_warns_for_unsafe_or_unsupported_fields() -> None:
    source = "#include <numeric>\nint sum();\n"
    result = normalize_shortlink_info(
        {
            "sessions": [
                {
                    "id": 1,
                    "language": "c++",
                    "source": source,
                    "compilers": [
                        {
                            "id": "g162",
                            "options": "-std=c++23 -O3",
                            "libs": [
                                {"name": "fmt", "ver": "110"},
                                {"id": "boost", "version": "188"},
                            ],
                            "filters": {
                                "commentOnly": False,
                                "intel": True,
                                "trim": True,
                                "execute": True,
                            },
                            "tools": [{"id": "clangtidy"}],
                        }
                    ],
                    "executors": [{"compiler": {"id": "g162"}}],
                },
                {"id": 2, "language": "rust", "source": "fn main() {}"},
            ],
            "trees": [{"id": 7, "files": [{"content": "untrusted"}]}],
            "unknown": {"secret": "must not be copied"},
        },
        "abc123",
        "https://godbolt.org/z/abc123",
    )

    assert result.shortlink_id == "abc123"
    assert result.url == "https://godbolt.org/z/abc123"
    assert result.has_trees is True
    assert len(result.sessions) == 1
    assert result.sessions[0].source == source
    compiler = result.sessions[0].compilers[0]
    assert compiler.compiler_id == "g162"
    assert compiler.options == "-std=c++23 -O3"
    assert [(item.id, item.version) for item in compiler.libraries] == [
        ("fmt", "110"),
        ("boost", "188"),
    ]
    assert compiler.filters.comment_only is False
    assert compiler.filters.intel is True
    assert compiler.filters.trim is True
    assert {
        "shortlink_state_omitted",
        "shortlink_execution_state_omitted",
    }.issubset(_warning_codes(result))
    serialized = result.model_dump_json()
    assert "must not be copied" not in serialized
    assert "clangtidy" not in serialized
    assert "fn main" not in serialized


def test_shortlink_state_rejects_missing_sessions_and_oversized_source() -> None:
    with pytest.raises(IncompatibleBackend, match="session list"):
        normalize_shortlink_info({}, "abc", "https://godbolt.org/z/abc")
    with pytest.raises(IncompatibleBackend, match="shortlink source"):
        normalize_shortlink_info(
            {
                "sessions": [
                    {
                        "id": 1,
                        "language": "c++",
                        "source": "x" * (MAX_TEXT_BYTES + 1),
                        "compilers": [],
                    }
                ]
            },
            "abc",
            "https://godbolt.org/z/abc",
        )


def test_shortlink_cplusplus_quota_is_applied_after_language_filtering() -> None:
    sessions = [{"id": index, "language": "rust", "source": "fn main() {}"} for index in range(8)]
    sessions.append(
        {
            "id": 9,
            "language": "c++",
            "source": "int included();",
            "compilers": [],
        }
    )

    result = normalize_shortlink_info(
        {"sessions": sessions},
        "abc",
        "https://godbolt.org/z/abc",
    )

    assert [session.source for session in result.sessions] == ["int included();"]
    assert "shortlink_state_omitted" in _warning_codes(result)


def test_unknown_and_object_conformance_state_are_explicitly_omitted() -> None:
    result = normalize_shortlink_info(
        {
            "sessions": [
                {
                    "id": 1,
                    "language": "c++",
                    "source": "int f();",
                    "compilers": [],
                    "conformanceview": {"editorid": 1},
                    "future": {"nested": "ignored"},
                }
            ]
        },
        "abc",
        "https://godbolt.org/z/abc",
    )

    assert "shortlink_state_omitted" in _warning_codes(result)
    assert "nested" not in result.model_dump_json()


def test_malformed_nested_library_and_execution_fields_are_warned() -> None:
    result = normalize_shortlink_info(
        {
            "sessions": [
                {
                    "id": 1,
                    "language": "c++",
                    "source": "int f();",
                    "compilers": [
                        {
                            "id": "gcc",
                            "options": "-O2",
                            "libs": [{"name": "fmt", "ver": "110", "future": True}],
                            "filters": {"execute": "yes"},
                        }
                    ],
                }
            ]
        },
        "abc",
        "https://godbolt.org/z/abc",
    )

    assert "malformed_shortlink_state" in _warning_codes(result)


def test_shortlink_response_budget_drops_panes_and_sessions_explicitly() -> None:
    raw_sessions = [
        {
            "id": session,
            "language": "c++",
            "source": "\x01" * (32 * 1024),
            "compilers": [
                {
                    "id": f"compiler-{compiler}",
                    "options": "\\" * (8 * 1024),
                }
                for compiler in range(8)
            ],
        }
        for session in range(8)
    ]
    result = normalize_shortlink_info(
        {"sessions": raw_sessions},
        "abc",
        "https://godbolt.org/z/abc",
    )

    enforce_shortlink_response_budget(result)

    assert result.response_truncated is True
    assert "shortlink_response_truncated" in _warning_codes(result)
    assert len(result.model_dump_json().encode("utf-8")) <= 1_000_000
    assert sum(len(session.compilers) for session in result.sessions) < 64


@pytest.mark.parametrize(
    ("raw", "status", "exit_code", "timed_out", "diagnostic"),
    [
        pytest.param(
            {
                "code": 0,
                "timedOut": False,
                "stdout": [{"text": "Using built-in specs."}],
                "stderr": [],
                "asm": [{"text": "main:", "source": {"line": 1, "mainsource": True}}],
                "truncated": False,
                "okToCache": True,
                "retreivedFromCache": True,
                "futureBackendField": {"ignored": True},
            },
            "success",
            0,
            False,
            "Using built-in specs.",
            id="gcc-success-and-legacy-cache-spelling",
        ),
        pytest.param(
            {
                "code": 1,
                "timedOut": False,
                "stdout": [],
                "stderr": [{"text": "<source>:1:1: error: expected expression"}],
                "asm": [],
                "retrievedFromCache": False,
            },
            "failed",
            1,
            False,
            "<source>:1:1: error: expected expression",
            id="clang-failure-and-corrected-cache-spelling",
        ),
        pytest.param(
            {
                "code": 124,
                "timedOut": True,
                "stderr": ["compilation terminated"],
                "asm": "",
            },
            "timed_out",
            124,
            True,
            "compilation terminated",
            id="timeout-takes-precedence-over-exit-code",
        ),
    ],
)
def test_normalizes_tolerant_gcc_and_clang_results(
    raw: dict[str, object],
    status: str,
    exit_code: int,
    timed_out: bool,
    diagnostic: str,
) -> None:
    result = normalize_compile_response(raw)

    assert result.status == status
    assert result.exit_code == exit_code
    assert result.timed_out is timed_out
    assert [line.text for line in result.diagnostics] == [diagnostic]
    if "okToCache" in raw:
        assert result.cache_eligible is True
        assert result.cache_hit is True
        assert result.backend_truncated is False
    elif "retrievedFromCache" in raw:
        assert result.cache_hit is False


def test_preserves_tagged_multiline_diagnostics_and_strips_terminal_controls() -> None:
    result = normalize_compile_response(
        {
            "code": 0,
            "timedOut": False,
            "stdout": [
                {
                    "text": "\x1b[33mwarning:\x1b[0m\tfirst\x00\ncontinuation\x07",
                    "tag": {
                        "text": "\x1b[1m-Wconversion\x1b[0m",
                        "severity": 2,
                        "file": "src/ma\x00in.cpp",
                        "line": 7,
                        "column": 3,
                        "endline": 7,
                        "endcolumn": 9,
                        "link": {
                            "text": "documentation\x07",
                            "url": "https://clang.llvm.org/docs/DiagnosticsReference.html",
                        },
                        "flow": [
                            {
                                "text": "\x1b[36mvalue originates here\x1b[0m",
                                "file": "include/x.hpp",
                                "line": 2,
                                "column": 5,
                            }
                        ],
                    },
                }
            ],
            "stderr": [{"text": "\x1b]0;hostile title\x07plain"}],
        }
    )

    assert [line.text for line in result.diagnostics] == [
        "warning:    first",
        "continuation",
        "plain",
    ]
    first, continuation, _ = result.diagnostics
    assert continuation.tag is None
    assert first.tag is not None
    assert first.tag.model_dump() == {
        "text": "-Wconversion",
        "severity": 2,
        "file": "src/main.cpp",
        "line": 7,
        "column": 3,
        "end_line": 7,
        "end_column": 9,
        "link": {
            "text": "documentation",
            "url": "https://clang.llvm.org/docs/DiagnosticsReference.html",
        },
        "flow": [
            {
                "text": "value originates here",
                "file": "include/x.hpp",
                "line": 2,
                "column": 5,
            }
        ],
    }
    assert not result.warnings


def test_preserves_source_mapped_assembly_opcodes_addresses_and_labels() -> None:
    result = normalize_compile_response(
        {
            "code": 0,
            "timedOut": False,
            "asm": [
                {
                    "text": "\x1b[32m  mov eax, DWORD PTR [rbp-4]\x1b[0m",
                    "source": {
                        "file": "main.cpp",
                        "line": 4,
                        "column": 9,
                        "mainsource": True,
                    },
                    "opcodes": ["8b", "45", "fc", 17],
                    "address": 4096,
                    "labels": [
                        {
                            "name": ".Ltmp\x00",
                            "target": "main\x1b[0m",
                            "range": {"startCol": 2, "endCol": 7},
                        },
                        {"notName": "ignored"},
                    ],
                },
                {"disassembly": "ret", "source": {"unknown": True}, "labels": "bad"},
                42,
            ],
        }
    )

    assert len(result.assembly) == 2
    first, second = result.assembly
    assert first.text == "  mov eax, DWORD PTR [rbp-4]"
    assert first.source is not None
    assert first.source.model_dump() == {
        "file": "main.cpp",
        "line": 4,
        "column": 9,
        "main_source": True,
    }
    assert first.opcodes == ["8b", "45", "fc"]
    assert first.address == 4096
    assert [label.model_dump() for label in first.labels] == [
        {
            "name": ".Ltmp",
            "target": "main",
            "start_column": 2,
            "end_column": 7,
        }
    ]
    assert second.text == "ret"
    assert second.source is None
    assert "malformed_assembly" in _warning_codes(result)


def test_normalizes_optimization_record_variants() -> None:
    result = normalize_compile_response(
        {
            "code": 0,
            "timedOut": False,
            "optOutput": [
                {
                    "Pass": "inline",
                    "Name": "Inlined",
                    "optType": "Passed",
                    "Function": "int square(int)",
                    "displayString": "inlined call",
                    "DebugLoc": {"File": "main.cpp", "Line": 3, "Column": 11},
                },
                {
                    "Pass": "loop-vectorize",
                    "Name": "Vectorized",
                    "optType": "Passed",
                    "Function": "sum",
                    "DebugLoc": {"file": "sum.cpp", "line": 8, "column": 2},
                },
                "backend free-form optimization note",
                None,
            ],
        }
    )

    assert [record.display for record in result.optimization] == [
        "inlined call",
        "Passed: loop-vectorize: Vectorized: sum",
        "backend free-form optimization note",
    ]
    first, second, _ = result.optimization
    assert first.pass_name == "inline"
    assert first.source is not None and first.source.line == 3
    assert second.source is not None and second.source.file == "sum.cpp"
    assert "malformed_optimization_output" in _warning_codes(result)


def test_normalizes_heterogeneous_tool_results_without_source_echo() -> None:
    secret_replacement = "DO_NOT_RETURN_THIS_REPLACEMENT_SOURCE"
    result = normalize_compile_response(
        {
            "code": 0,
            "timedOut": False,
            "tools": [
                {
                    "id": "clangtidy",
                    "name": "clang-tidy",
                    "code": 0,
                    "stdout": [{"text": "\x1b[32mtidy ok\x1b[0m"}],
                    "artifact": {"content": "artifact line 1\nartifact line 2"},
                    "sourcechanged": True,
                    "newsource": secret_replacement,
                },
                {
                    "id": "iwyu",
                    "name": "Include What You Use",
                    "code": 2,
                    "stderr": ["\x1b[31mremove <vector>\x1b[0m"],
                },
                {"id": "broken", "name": "Broken", "code": "zero", "artifact": []},
                {"id": "iwyu", "name": "duplicate", "code": 0},
                {"name": "missing ID", "code": 0},
            ],
        }
    )

    assert [tool.id for tool in result.tools] == ["clangtidy", "iwyu", "broken"]
    tidy, iwyu, broken = result.tools
    assert [line.text for line in tidy.output] == [
        "tidy ok",
        "artifact line 1",
        "artifact line 2",
    ]
    assert tidy.code == 0 and tidy.malformed is False
    assert "analyzer_source_change_omitted" in _warning_codes(tidy)
    assert [line.text for line in iwyu.output] == ["remove <vector>"]
    assert iwyu.code == 2 and iwyu.malformed is False
    assert broken.code is None and broken.malformed is True
    assert {
        "malformed_analyzer_artifact",
        "malformed_analyzer_status",
    }.issubset(_warning_codes(broken))
    assert {"duplicate_tool_result", "malformed_tools"}.issubset(_warning_codes(result))
    assert secret_replacement not in repr(result)


def test_analyzer_specific_noise_and_modeling_limitations_are_explicit() -> None:
    result = normalize_compile_response(
        {
            "code": 0,
            "timedOut": False,
            "tools": [
                {
                    "id": "clangtidytrunk",
                    "name": "clang-tidy",
                    "code": 0,
                    "stdout": [
                        "52 warnings generated.",
                        "example.cpp:1:1: warning: retained [performance-test]",
                        "Suppressed 42 warnings (42 in non-user code).",
                    ],
                },
                {
                    "id": "llvm-mcatrunk",
                    "name": "LLVM MCA",
                    "code": 0,
                    "stdout": ["Block RThroughput: 5.5"],
                },
                {
                    "id": "osacatrunk",
                    "name": "OSACA",
                    "code": 1,
                    "stderr": [
                        "Traceback (most recent call last):",
                        "SyntaxError: Could not parse instruction lea esi, [4*rdx]",
                    ],
                },
            ],
        }
    )

    tidy, llvm_mca, osaca = result.tools
    assert [line.text for line in tidy.output] == [
        "example.cpp:1:1: warning: retained [performance-test]"
    ]
    assert "clang_tidy_summary_omitted" in _warning_codes(tidy)
    assert "llvm_mca_control_flow_not_modeled" in _warning_codes(llvm_mca)
    assert "osaca_parser_failure" in _warning_codes(osaca)
    assert "Could not parse instruction" in osaca.output[-1].text


def test_malformed_compile_sections_are_ignored_with_explicit_warnings() -> None:
    result = normalize_compile_response(
        {
            "code": True,
            "timedOut": "false",
            "stdout": {"text": "not a list"},
            "stderr": [None, {"text": "kept", "tag": "bad-tag"}, {"text": 12}],
            "asm": {"text": "not a list"},
            "optOutput": {"displayString": "not a list"},
            "tools": {"id": "not a list"},
            "unknown": "tolerated",
        }
    )

    assert result.exit_code == -1
    assert result.status == "failed"
    assert result.timed_out is False
    assert [line.text for line in result.diagnostics] == ["kept"]
    assert not result.assembly
    assert not result.optimization
    assert not result.tools
    assert {
        "malformed_compile_status",
        "missing_timeout_status",
        "malformed_diagnostics",
        "malformed_assembly",
        "malformed_optimization_output",
        "malformed_tools",
    }.issubset(_warning_codes(result))


def test_line_truncation_is_utf8_safe_and_reported_per_section() -> None:
    oversized = "prefix-" + ("\N{SNOWMAN}" * MAX_LINE_BYTES)
    result = normalize_compile_response(
        {
            "code": 0,
            "timedOut": False,
            "stdout": [oversized],
            "asm": [{"text": oversized}],
            "optOutput": [oversized],
            "tools": [{"id": "tool", "name": "Tool", "code": 0, "stderr": [oversized]}],
        }
    )

    diagnostic = result.diagnostics[0]
    assembly = result.assembly[0]
    optimization = result.optimization[0]
    tool_line = result.tools[0].output[0]
    for line in (diagnostic, assembly, tool_line):
        assert line.text_truncated is True
        assert line.text.endswith("...")
        assert len(line.text.encode("utf-8")) <= MAX_LINE_BYTES
    assert optimization.text_truncated is True
    assert optimization.display.endswith("...")
    assert len(optimization.display.encode("utf-8")) <= MAX_LINE_BYTES
    assert {
        "diagnostic_text_truncated",
        "assembly_text_truncated",
        "optimization_output_truncated",
    }.issubset(_warning_codes(result))
    assert "diagnostic_text_truncated" in _warning_codes(result.tools[0])

    shortened, truncated = truncate_text("\N{SNOWMAN}" * 5, maximum_bytes=8)
    assert truncated is True
    assert shortened.endswith("...")
    assert len(shortened.encode("utf-8")) <= 8


def test_analyzer_artifact_section_cap_is_reported() -> None:
    result = normalize_compile_response(
        {
            "code": 0,
            "timedOut": False,
            "tools": [
                {
                    "id": "artifact-tool",
                    "name": "Artifact Tool",
                    "code": 0,
                    "artifact": {"content": "\n".join("line" for _ in range(20_001))},
                }
            ],
        }
    )

    assert len(result.tools[0].output) == 20_000
    assert "analyzer_output_truncated" in _warning_codes(result.tools[0])


def test_combined_diagnostic_section_cap_and_malformed_tool_output_are_reported() -> None:
    result = normalize_compile_response(
        {
            "code": 0,
            "timedOut": False,
            "stdout": ["out"] * 10_001,
            "stderr": ["err"] * 10_001,
            "tools": [{"id": "tool", "name": "Tool", "code": 0, "stdout": {}}],
        }
    )

    assert len(result.diagnostics) == 20_000
    assert "diagnostic_text_truncated" in _warning_codes(result)
    assert result.tools[0].malformed is True
    assert "malformed_diagnostics" in _warning_codes(result.tools[0])


@pytest.mark.parametrize(
    ("offset", "limit", "items", "expected"),
    [
        (0, 2, ["a", "b"], (False, True, 2)),
        (1, 2, ["b", "c"], (True, False, None)),
        (8, 2, [], (True, False, None)),
    ],
)
def test_window_page_metadata(
    offset: int,
    limit: int,
    items: list[str],
    expected: tuple[bool, bool, int | None],
) -> None:
    page = window_page(["a", "b", "c"], OutputWindow(offset=offset, limit=limit))

    assert page.items == items
    assert page.page.model_dump() == {
        "offset": offset,
        "limit": limit,
        "total": 3,
        "returned": len(items),
        "truncated_before": expected[0],
        "truncated_after": expected[1],
        "next_offset": expected[2],
    }


def test_final_response_budget_reduces_pages_and_preserves_totals() -> None:
    lines = [AssemblyLine(text=f"{index:03d}: " + ("x" * 180)) for index in range(200)]
    assembly = window_page(lines, OutputWindow(limit=1000))
    response = CompileResult(
        fingerprint="f" * 64,
        compiler=CompilerIdentity(
            requested_selector="gcc-latest",
            resolved_id="g++-15",
            name="GCC 15",
            version="15.1.0",
        ),
        status="success",
        exit_code=0,
        timed_out=False,
        assembly=assembly,
        assembly_line_count=len(lines),
    )
    assert len(response.model_dump_json().encode("utf-8")) > 6_000

    assert response.assembly is not None
    enforce_response_budget(response, [response.assembly], maximum_bytes=6_000)

    assert len(response.model_dump_json().encode("utf-8")) <= 6_000
    assert response.response_truncated is True
    assert "response_budget_truncated" in _warning_codes(response)
    assert 0 < len(response.assembly.items) < len(lines)
    assert response.assembly.page.total == len(lines)
    assert response.assembly.page.returned == len(response.assembly.items)
    assert response.assembly.page.truncated_after is True
    assert response.assembly.page.next_offset == len(response.assembly.items)


def test_assembly_fingerprint_normalizes_only_whitespace() -> None:
    first = [AssemblyLine(text="  mov\teax,   1  "), AssemblyLine(text="ret")]
    same = [AssemblyLine(text="mov eax, 1"), AssemblyLine(text="  ret  ")]
    changed = [AssemblyLine(text="mov eax, 2"), AssemblyLine(text="ret")]
    expected = hashlib.sha256(b"mov eax, 1\nret").hexdigest()

    assert assembly_fingerprint(first) == expected
    assert assembly_fingerprint(same) == expected
    assert assembly_fingerprint(changed) != expected
    assert assembly_fingerprint([]) is None


def test_canonical_request_fingerprint_is_stable_and_content_sensitive() -> None:
    payload_a = {"lang": "c++", "options": {"execute": False, "flags": ["-O2", "-Wall"]}}
    payload_b = {"options": {"flags": ["-O2", "-Wall"], "execute": False}, "lang": "c++"}
    canonical = json.dumps(
        {"compiler": "g++-15", "payload": payload_a},
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
        allow_nan=False,
    )

    fingerprint = canonical_request_fingerprint("g++-15", payload_a)
    assert fingerprint == hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    assert fingerprint == canonical_request_fingerprint("g++-15", payload_b)
    assert fingerprint != canonical_request_fingerprint("clang-20", payload_b)
    assert fingerprint != canonical_request_fingerprint(
        "g++-15", {**payload_b, "source": "int main(){}"}
    )
    assert len(fingerprint) == 64


def test_sanitize_text_removes_ansi_osc_and_controls_but_expands_tabs() -> None:
    value = "\x1b[31mred\x1b[0m\ttext\x00\x08\x0b\x1f\x7f\x9f\x1b]2;title\x07end"
    assert sanitize_text(value) == "red    textend"


def test_html_sanitizer_keeps_only_allowlisted_markup_and_no_attributes() -> None:
    hostile = (
        '<div>outside<p onclick="steal()">safe &amp; <strong class="x">bold</strong>'
        '<img src=x onerror="steal()"><a href="javascript:steal()">link</a></p>'
        "<script>alert('source')</script><style>body{display:none}</style>"
        "<pre>\x1b[31mcode\x1b[0m</pre></div>"
    )

    cleaned = sanitize_html(hostile)

    assert cleaned == "outside<p>safe &amp; <strong>bold</strong>link</p><pre>code</pre>"
    for forbidden in ("script", "style", "onclick", "onerror", "href", "img", "javascript"):
        assert forbidden not in cleaned.casefold()


def test_opcode_documentation_is_sanitized_bounded_and_warned() -> None:
    result = normalize_opcode_documentation(
        {
            "tooltip": "\x1b[32m" + ("\N{SNOWMAN}" * 5_000) + "\x1b[0m",
            "html": '<p onclick="x">' + ("content" * 6_000) + "</p><script>secret</script>",
            "url": "https://godbolt.org/x86-64/mov",
            "unrestricted": {"ignored": True},
        },
        "x86-64",
        "mov",
    )

    assert result.instruction_set == "x86-64"
    assert result.opcode == "mov"
    assert len(result.tooltip.encode("utf-8")) <= 8 * 1024
    assert len(result.html.encode("utf-8")) <= 32 * 1024
    assert result.tooltip_truncated is True
    assert result.html_truncated is True
    assert result.source_url == "https://godbolt.org/x86-64/mov"
    assert "onclick" not in result.html
    assert "secret" not in result.html
    assert {"opcode_tooltip_truncated", "opcode_html_truncated"} == _warning_codes(result)


@pytest.mark.parametrize(
    "raw",
    [
        {},
        {"tooltip": "mov", "html": "<p>move</p>"},
        {"tooltip": "mov", "html": "<p>move</p>", "url": "javascript:alert(1)"},
        {"tooltip": "mov", "html": "<p>move</p>", "url": "https://user:pass@example.com"},
    ],
)
def test_incomplete_or_unsafe_opcode_documentation_is_rejected(raw: dict[str, str]) -> None:
    with pytest.raises(IncompatibleBackend, match="incomplete opcode documentation") as error:
        normalize_opcode_documentation(raw, "x86-64", "mov")

    assert "api/asm/x86-64/mov" in error.value.public_message


def test_warning_merge_is_stable_and_deduplicates_exact_pairs() -> None:
    one = WarningItem(code="one", message="first")
    same = WarningItem(code="one", message="first")
    other_message = WarningItem(code="one", message="second")
    two = WarningItem(code="two", message="second")

    assert merge_warnings([one, same], [other_message, two, one]) == [
        one,
        other_message,
        two,
    ]
