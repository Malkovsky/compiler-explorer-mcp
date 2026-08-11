from __future__ import annotations

import hashlib
import html
import math
import re
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from html.parser import HTMLParser
from typing import Any, Final, Literal, TypeVar
from urllib.parse import urlsplit

from pydantic import ValidationError

from ce_analyzer_mcp.errors import IncompatibleBackend
from ce_analyzer_mcp.models import (
    MAX_LIBRARIES,
    MAX_LINE_BYTES,
    MAX_SERIALIZED_RESPONSE_BYTES,
    MAX_SHORTLINK_SESSION_COMPILERS,
    MAX_SHORTLINK_SESSIONS,
    AssemblyFilters,
    AssemblyLabel,
    AssemblyLine,
    DiagnosticFlowStep,
    DiagnosticLine,
    DiagnosticLink,
    DiagnosticTag,
    GetShortlinkRequest,
    GetShortlinkResult,
    LibrarySelection,
    OpcodeDocumentation,
    OptimizationRecord,
    OutputWindow,
    Page,
    PageInfo,
    ShortlinkCompilerInfo,
    ShortlinkSessionInfo,
    SourceLocation,
    StrictModel,
    WarningItem,
)

_ANSI_RE: Final = re.compile(
    r"\x1b(?:"
    r"\][^\x07]*(?:\x07|\x1b\\)|"
    r"P.*?\x1b\\|"
    r"\[[0-?]*[ -/]*[@-~]|"
    r"[@-_]"
    r")",
    re.DOTALL,
)
_CONTROL_RE: Final = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f]")
_WHITESPACE_RE: Final = re.compile(r"\s+")
_NON_ALNUM_RE: Final = re.compile(r"[^a-z0-9]+")
_CLANG_TIDY_SUMMARY_RE: Final = re.compile(
    r"^(?:\d+ warnings? generated\.|Suppressed \d+ warnings? \(\d+ in non-user code\)\.)$"
)
_MAX_NORMALIZED_ITEMS: Final = 20_000
_MAX_TAG_FLOW: Final = 32
_MAX_LABELS: Final = 32
_MAX_OPCODES: Final = 32
_MAX_TOOLTIP_BYTES: Final = 8 * 1024
_MAX_HTML_BYTES: Final = 32 * 1024
_MAX_SHORTLINK_RAW_SESSIONS: Final = 64
_ALLOWED_HTML_TAGS: Final = frozenset(
    {"p", "br", "strong", "em", "b", "i", "code", "pre", "ul", "ol", "li"}
)
_VOID_HTML_TAGS: Final = frozenset({"br"})

V = TypeVar("V")


@dataclass(frozen=True)
class NormalizedTool:
    id: str
    name: str
    code: int | None
    output: tuple[DiagnosticLine, ...]
    malformed: bool
    warnings: tuple[WarningItem, ...]


@dataclass(frozen=True)
class NormalizedCompile:
    exit_code: int
    timed_out: bool
    backend_truncated: bool | None
    cache_eligible: bool | None
    cache_hit: bool | None
    diagnostics: tuple[DiagnosticLine, ...]
    assembly: tuple[AssemblyLine, ...]
    optimization: tuple[OptimizationRecord, ...]
    tools: tuple[NormalizedTool, ...]
    warnings: tuple[WarningItem, ...]

    @property
    def status(self) -> Literal["success", "failed", "timed_out"]:
        if self.timed_out:
            return "timed_out"
        return "success" if self.exit_code == 0 else "failed"


def sanitize_text(value: str) -> str:
    without_ansi = _ANSI_RE.sub("", value)
    without_ansi = without_ansi.replace("\t", "    ").replace("\n", " ")
    return _CONTROL_RE.sub("", without_ansi)


def truncate_text(value: str, maximum_bytes: int = MAX_LINE_BYTES) -> tuple[str, bool]:
    sanitized = sanitize_text(value)
    encoded = sanitized.encode("utf-8", errors="replace")
    if len(encoded) <= maximum_bytes:
        return encoded.decode("utf-8"), False
    marker = b"..."
    shortened = encoded[: maximum_bytes - len(marker)]
    while shortened:
        try:
            text = shortened.decode("utf-8")
            return f"{text}...", True
        except UnicodeDecodeError as exc:
            shortened = shortened[: exc.start]
    return "...", True


def _warning(code: str, message: str) -> WarningItem:
    return WarningItem(code=code, message=message)


def merge_warnings(*groups: Iterable[WarningItem]) -> list[WarningItem]:
    merged: list[WarningItem] = []
    seen: set[tuple[str, str]] = set()
    for group in groups:
        for warning in group:
            key = (warning.code, warning.message)
            if key not in seen:
                seen.add(key)
                merged.append(warning)
    return merged


def _integer(value: Any) -> int | None:
    return value if isinstance(value, int) and not isinstance(value, bool) else None


def _boolean(value: Any) -> bool | None:
    return value if isinstance(value, bool) else None


def _safe_url(value: Any) -> str | None:
    if not isinstance(value, str) or len(value) > 2048:
        return None
    cleaned = sanitize_text(value)
    parsed = urlsplit(cleaned)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        return None
    if parsed.username is not None or parsed.password is not None:
        return None
    return cleaned


def _source_location(value: Any) -> SourceLocation | None:
    if not isinstance(value, dict):
        return None
    file_value = value.get("file")
    file_name = sanitize_text(file_value)[:255] if isinstance(file_value, str) else None
    line = _integer(value.get("line"))
    column = _integer(value.get("column"))
    main_source = _boolean(value.get("mainsource"))
    if line is None and column is None and file_name is None and main_source is None:
        return None
    return SourceLocation(
        file=file_name,
        line=line,
        column=column,
        main_source=main_source,
    )


def _diagnostic_tag(value: Any) -> tuple[DiagnosticTag | None, bool]:
    if not isinstance(value, dict):
        return None, value is not None
    raw_text = value.get("text")
    if not isinstance(raw_text, str):
        return None, True
    text, _ = truncate_text(raw_text)
    raw_link = value.get("link")
    link: DiagnosticLink | None = None
    malformed = False
    if isinstance(raw_link, dict):
        link_text = raw_link.get("text")
        link_url = _safe_url(raw_link.get("url"))
        if isinstance(link_text, str) and link_url is not None:
            clean_link_text, _ = truncate_text(link_text, 512)
            link = DiagnosticLink(text=clean_link_text, url=link_url)
        else:
            malformed = True
    elif raw_link is not None:
        malformed = True
    flow: list[DiagnosticFlowStep] = []
    raw_flow = value.get("flow")
    if isinstance(raw_flow, list):
        malformed = malformed or len(raw_flow) > _MAX_TAG_FLOW
        for step in raw_flow[:_MAX_TAG_FLOW]:
            if not isinstance(step, dict) or not isinstance(step.get("text"), str):
                malformed = True
                continue
            step_text, _ = truncate_text(step["text"], 1024)
            step_file = step.get("file")
            flow.append(
                DiagnosticFlowStep(
                    text=step_text,
                    file=sanitize_text(step_file)[:255] if isinstance(step_file, str) else None,
                    line=_integer(step.get("line")),
                    column=_integer(step.get("column")),
                )
            )
    elif raw_flow is not None:
        malformed = True
    file_value = value.get("file")
    return (
        DiagnosticTag(
            text=text,
            severity=_integer(value.get("severity")),
            file=sanitize_text(file_value)[:255] if isinstance(file_value, str) else None,
            line=_integer(value.get("line")),
            column=_integer(value.get("column")),
            end_line=_integer(value.get("endline")),
            end_column=_integer(value.get("endcolumn")),
            link=link,
            flow=flow,
        ),
        malformed,
    )


def _diagnostic_stream(
    value: Any,
    stream: Literal["stdout", "stderr"],
) -> tuple[list[DiagnosticLine], bool, bool]:
    if value is None:
        return [], False, False
    if not isinstance(value, list):
        return [], True, False
    lines: list[DiagnosticLine] = []
    malformed = False
    text_truncated = False
    for raw_line in value:
        if len(lines) >= _MAX_NORMALIZED_ITEMS:
            break
        if isinstance(raw_line, str):
            raw_text = raw_line
            tag = None
        elif isinstance(raw_line, dict) and isinstance(raw_line.get("text"), str):
            raw_text = raw_line["text"]
            tag, bad_tag = _diagnostic_tag(raw_line.get("tag"))
            malformed = malformed or bad_tag
        else:
            malformed = True
            continue
        pieces = raw_text.splitlines() or [""]
        for index, piece in enumerate(pieces):
            if len(lines) >= _MAX_NORMALIZED_ITEMS:
                break
            text, truncated = truncate_text(piece)
            text_truncated = text_truncated or truncated
            lines.append(
                DiagnosticLine(
                    stream=stream,
                    text=text,
                    text_truncated=truncated,
                    tag=tag if index == 0 else None,
                )
            )
    capped = len(lines) >= _MAX_NORMALIZED_ITEMS and len(value) > 0
    return lines, malformed, text_truncated or capped


def _normalize_diagnostics(
    stdout: Any,
    stderr: Any,
) -> tuple[list[DiagnosticLine], list[WarningItem]]:
    out, malformed_out, truncated_out = _diagnostic_stream(stdout, "stdout")
    err, malformed_err, truncated_err = _diagnostic_stream(stderr, "stderr")
    combined = out + err
    combined_capped = len(combined) > _MAX_NORMALIZED_ITEMS
    warnings: list[WarningItem] = []
    if malformed_out or malformed_err:
        warnings.append(
            _warning(
                "malformed_diagnostics",
                "Ignored malformed fields in Compiler Explorer diagnostics.",
            )
        )
    if truncated_out or truncated_err or combined_capped:
        warnings.append(
            _warning(
                "diagnostic_text_truncated",
                "One or more diagnostic lines or the diagnostic section exceeded safety limits.",
            )
        )
    return combined[:_MAX_NORMALIZED_ITEMS], warnings


def _assembly_labels(value: Any) -> tuple[list[AssemblyLabel], bool]:
    if value is None:
        return [], False
    if not isinstance(value, list):
        return [], True
    labels: list[AssemblyLabel] = []
    malformed = len(value) > _MAX_LABELS
    for item in value[:_MAX_LABELS]:
        if not isinstance(item, dict) or not isinstance(item.get("name"), str):
            malformed = True
            continue
        label_range = item.get("range")
        if not isinstance(label_range, dict):
            label_range = {}
        name, _ = truncate_text(item["name"], 256)
        target = item.get("target")
        labels.append(
            AssemblyLabel(
                name=name,
                target=sanitize_text(target)[:256] if isinstance(target, str) else None,
                start_column=_integer(label_range.get("startCol")),
                end_column=_integer(label_range.get("endCol")),
            )
        )
    return labels, malformed


def _normalize_assembly(value: Any) -> tuple[list[AssemblyLine], list[WarningItem]]:
    if value is None:
        return [], []
    raw_lines: list[Any]
    if isinstance(value, str):
        raw_lines = value.splitlines()
    elif isinstance(value, list):
        raw_lines = value
    else:
        return [], [
            _warning("malformed_assembly", "Compiler Explorer returned malformed assembly.")
        ]
    lines: list[AssemblyLine] = []
    malformed = False
    truncated_any = False
    capped = len(raw_lines) > _MAX_NORMALIZED_ITEMS
    for raw_line in raw_lines[:_MAX_NORMALIZED_ITEMS]:
        if isinstance(raw_line, str):
            raw_text = raw_line
            source = None
            opcodes: list[str] = []
            address = None
            labels: list[AssemblyLabel] = []
        elif isinstance(raw_line, dict):
            candidate = raw_line.get("text")
            if not isinstance(candidate, str):
                candidate = raw_line.get("disassembly")
            if not isinstance(candidate, str):
                malformed = True
                continue
            raw_text = candidate
            source = _source_location(raw_line.get("source"))
            raw_opcodes = raw_line.get("opcodes")
            opcodes = []
            if isinstance(raw_opcodes, list):
                malformed = malformed or len(raw_opcodes) > _MAX_OPCODES
                for opcode in raw_opcodes[:_MAX_OPCODES]:
                    if isinstance(opcode, str):
                        clean_opcode, _ = truncate_text(opcode, 128)
                        opcodes.append(clean_opcode)
                    else:
                        malformed = True
            elif raw_opcodes is not None:
                malformed = True
            address = _integer(raw_line.get("address"))
            labels, bad_labels = _assembly_labels(raw_line.get("labels"))
            malformed = malformed or bad_labels
        else:
            malformed = True
            continue
        text, truncated = truncate_text(raw_text)
        truncated_any = truncated_any or truncated
        lines.append(
            AssemblyLine(
                text=text,
                text_truncated=truncated,
                source=source,
                opcodes=opcodes,
                address=address,
                labels=labels,
            )
        )
    warnings: list[WarningItem] = []
    if malformed:
        warnings.append(
            _warning(
                "malformed_assembly",
                "Ignored malformed fields in Compiler Explorer assembly.",
            )
        )
    if truncated_any or capped:
        warnings.append(
            _warning(
                "assembly_text_truncated",
                "One or more assembly lines or the assembly section exceeded safety limits.",
            )
        )
    return lines, warnings


def _optimization_source(value: Any) -> SourceLocation | None:
    if not isinstance(value, dict):
        return None
    file_value = value.get("File", value.get("file"))
    file_name = sanitize_text(file_value)[:255] if isinstance(file_value, str) else None
    line = _integer(value.get("Line", value.get("line")))
    column = _integer(value.get("Column", value.get("column")))
    if file_name is None and line is None and column is None:
        return None
    return SourceLocation(file=file_name, line=line, column=column)


def _optional_clean(value: Any, maximum: int = 512) -> str | None:
    if not isinstance(value, str):
        return None
    clean, _ = truncate_text(value, maximum)
    return clean


def _normalize_optimization(value: Any) -> tuple[list[OptimizationRecord], list[WarningItem]]:
    if value is None:
        return [], []
    if not isinstance(value, list):
        return [], [
            _warning(
                "malformed_optimization_output",
                "Compiler Explorer returned malformed optimization output.",
            )
        ]
    records: list[OptimizationRecord] = []
    malformed = False
    truncated_any = False
    for item in value[:_MAX_NORMALIZED_ITEMS]:
        if isinstance(item, str):
            display, truncated = truncate_text(item)
            records.append(OptimizationRecord(display=display, text_truncated=truncated))
            truncated_any = truncated_any or truncated
            continue
        if not isinstance(item, dict):
            malformed = True
            continue
        raw_display = item.get("displayString")
        if not isinstance(raw_display, str):
            known = [
                part
                for key in ("optType", "Pass", "Name", "Function")
                if isinstance((part := item.get(key)), str)
            ]
            raw_display = ": ".join(known)
        display, truncated = truncate_text(raw_display)
        truncated_any = truncated_any or truncated
        records.append(
            OptimizationRecord(
                pass_name=_optional_clean(item.get("Pass")),
                name=_optional_clean(item.get("Name")),
                optimization_type=_optional_clean(item.get("optType")),
                function=_optional_clean(item.get("Function"), 1024),
                display=display,
                text_truncated=truncated,
                source=_optimization_source(item.get("DebugLoc")),
            )
        )
    capped = len(value) > _MAX_NORMALIZED_ITEMS
    warnings: list[WarningItem] = []
    if malformed:
        warnings.append(
            _warning(
                "malformed_optimization_output",
                "Ignored malformed optimization records.",
            )
        )
    if truncated_any or capped:
        warnings.append(
            _warning(
                "optimization_output_truncated",
                "Optimization records exceeded line or section safety limits.",
            )
        )
    return records, warnings


def _normalize_tools(value: Any) -> tuple[list[NormalizedTool], list[WarningItem]]:
    if value is None:
        return [], []
    if not isinstance(value, list):
        return [], [
            _warning("malformed_tools", "Compiler Explorer returned malformed tool output.")
        ]
    tools: list[NormalizedTool] = []
    warnings: list[WarningItem] = []
    seen: set[str] = set()
    for item in value[:_MAX_NORMALIZED_ITEMS]:
        if not isinstance(item, dict) or not isinstance(item.get("id"), str):
            warnings.append(_warning("malformed_tools", "Ignored a malformed tool result."))
            continue
        tool_id, id_truncated = truncate_text(item["id"], 128)
        if tool_id in seen:
            warnings.append(
                _warning("duplicate_tool_result", f"Ignored duplicate tool result {tool_id!r}.")
            )
            continue
        seen.add(tool_id)
        name_value = item.get("name")
        name, name_truncated = truncate_text(
            name_value if isinstance(name_value, str) else tool_id,
            300,
        )
        output, output_warnings = _normalize_diagnostics(item.get("stdout"), item.get("stderr"))
        tool_warnings = list(output_warnings)
        normalized_identity = _NON_ALNUM_RE.sub("", f"{tool_id} {name}".casefold())
        if "clangtidy" in normalized_identity:
            filtered_output = [
                line for line in output if not _CLANG_TIDY_SUMMARY_RE.fullmatch(line.text)
            ]
            if len(filtered_output) != len(output):
                output = filtered_output
                tool_warnings.append(
                    _warning(
                        "clang_tidy_summary_omitted",
                        "Omitted clang-tidy aggregate warning-count boilerplate; findings remain.",
                    )
                )
        artifact = item.get("artifact")
        artifact_text_truncated = False
        if isinstance(artifact, dict) and isinstance(artifact.get("content"), str):
            artifact_lines = artifact["content"].splitlines()
            remaining = max(0, _MAX_NORMALIZED_ITEMS - len(output))
            for artifact_line in artifact_lines[:remaining]:
                text, truncated = truncate_text(artifact_line)
                artifact_text_truncated = artifact_text_truncated or truncated
                output.append(
                    DiagnosticLine(
                        stream="stdout",
                        text=text,
                        text_truncated=truncated,
                    )
                )
            if len(artifact_lines) > remaining:
                tool_warnings.append(
                    _warning("analyzer_output_truncated", "Analyzer output exceeded safety limits.")
                )
        elif artifact is not None:
            tool_warnings.append(
                _warning("malformed_analyzer_artifact", "Ignored a malformed analyzer artifact.")
            )
        if item.get("sourcechanged") is True or "newsource" in item:
            tool_warnings.append(
                _warning(
                    "analyzer_source_change_omitted",
                    "Analyzer-proposed source changes are intentionally not returned.",
                )
            )
        if artifact_text_truncated:
            tool_warnings.append(
                _warning(
                    "analyzer_output_truncated",
                    "One or more analyzer artifact lines exceeded the line limit.",
                )
            )
        code = _integer(item.get("code"))
        malformed = (
            code is None
            or id_truncated
            or name_truncated
            or any(warning.code.startswith("malformed_") for warning in tool_warnings)
        )
        if code is None:
            tool_warnings.append(
                _warning("malformed_analyzer_status", "Analyzer result has no valid exit code.")
            )
        if "llvmmca" in normalized_identity:
            tool_warnings.append(
                _warning(
                    "llvm_mca_control_flow_not_modeled",
                    "llvm-mca models a linear instruction region; branch probabilities and "
                    "mutually exclusive paths are not whole-function runtime predictions.",
                )
            )
        if "osaca" in normalized_identity and code not in {None, 0}:
            parser_signatures = ("could not parse instruction", "syntaxerror", "traceback")
            if any(
                signature in line.text.casefold()
                for line in output
                for signature in parser_signatures
            ):
                tool_warnings.append(
                    _warning(
                        "osaca_parser_failure",
                        "The upstream OSACA analyzer rejected compiler-generated assembly.",
                    )
                )
        tools.append(
            NormalizedTool(
                id=tool_id,
                name=name,
                code=code,
                output=tuple(output),
                malformed=malformed,
                warnings=tuple(merge_warnings(tool_warnings)),
            )
        )
    if len(value) > _MAX_NORMALIZED_ITEMS:
        warnings.append(_warning("tool_results_truncated", "Tool results exceeded safety limits."))
    return tools, merge_warnings(warnings)


def normalize_compile_response(value: dict[str, Any]) -> NormalizedCompile:
    warnings: list[WarningItem] = []
    exit_code = _integer(value.get("code"))
    if exit_code is None:
        exit_code = -1
        warnings.append(
            _warning("malformed_compile_status", "Compile response has no valid exit code.")
        )
    timed_out = _boolean(value.get("timedOut"))
    if timed_out is None:
        timed_out = False
        warnings.append(
            _warning("missing_timeout_status", "Compile response omitted its timeout status.")
        )
    diagnostics, diagnostic_warnings = _normalize_diagnostics(
        value.get("stdout"), value.get("stderr")
    )
    assembly, assembly_warnings = _normalize_assembly(value.get("asm"))
    optimization, optimization_warnings = _normalize_optimization(value.get("optOutput"))
    tools, tool_warnings = _normalize_tools(value.get("tools"))
    return NormalizedCompile(
        exit_code=exit_code,
        timed_out=timed_out,
        backend_truncated=_boolean(value.get("truncated")),
        cache_eligible=_boolean(value.get("okToCache")),
        cache_hit=_boolean(value.get("retreivedFromCache", value.get("retrievedFromCache"))),
        diagnostics=tuple(diagnostics),
        assembly=tuple(assembly),
        optimization=tuple(optimization),
        tools=tuple(tools),
        warnings=tuple(
            merge_warnings(
                warnings,
                diagnostic_warnings,
                assembly_warnings,
                optimization_warnings,
                tool_warnings,
            )
        ),
    )


def normalize_shortlink_creation(
    value: dict[str, Any],
    expected_url: str | None = None,
) -> tuple[str, str]:
    endpoint = "api/shortener"
    url = value.get("url")
    if (
        not isinstance(url, str)
        or len(url) > 2048
        or _CONTROL_RE.search(url)
        or any(character.isspace() for character in url)
    ):
        raise IncompatibleBackend(endpoint, detail="an invalid shortlink URL")
    try:
        parsed = urlsplit(url)
        _ = parsed.port
    except ValueError:
        raise IncompatibleBackend(endpoint, detail="an invalid shortlink URL") from None
    if (
        parsed.scheme not in {"http", "https"}
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
    ):
        raise IncompatibleBackend(endpoint, detail="an invalid shortlink URL")
    segments = [segment for segment in parsed.path.split("/") if segment]
    if len(segments) < 2 or segments[-2] != "z":
        raise IncompatibleBackend(endpoint, detail="a non-built-in shortlink URL")
    shortlink_id = segments[-1]
    try:
        GetShortlinkRequest(shortlink_id=shortlink_id)
    except ValidationError:
        raise IncompatibleBackend(endpoint, detail="an invalid shortlink ID") from None
    if expected_url is not None:
        expected = urlsplit(expected_url)
        expected_segments = [segment for segment in expected.path.split("/") if segment]
        returned_origin = (
            parsed.scheme,
            parsed.hostname,
            parsed.port or (443 if parsed.scheme == "https" else 80),
        )
        expected_origin = (
            expected.scheme,
            expected.hostname,
            expected.port or (443 if expected.scheme == "https" else 80),
        )
        if (
            returned_origin != expected_origin
            or len(expected_segments) < 2
            or expected_segments[-2] != "z"
            or segments[:-2] != expected_segments[:-2]
        ):
            raise IncompatibleBackend(endpoint, detail="a foreign-origin shortlink URL")
    return shortlink_id, url


def _shortlink_libraries(value: Any) -> tuple[list[LibrarySelection], bool]:
    if value is None:
        return [], False
    if not isinstance(value, list):
        return [], True
    libraries: list[LibrarySelection] = []
    malformed = len(value) > MAX_LIBRARIES
    seen: set[str] = set()
    for item in value[:MAX_LIBRARIES]:
        if not isinstance(item, dict):
            malformed = True
            continue
        library_id = item.get("name", item.get("id"))
        version = item.get("ver", item.get("version"))
        if set(item) - {"name", "id", "ver", "version"}:
            malformed = True
        if not isinstance(library_id, str) or not isinstance(version, str) or library_id in seen:
            malformed = True
            continue
        try:
            library = LibrarySelection(id=library_id, version=version)
        except ValidationError:
            malformed = True
            continue
        seen.add(library_id)
        libraries.append(library)
    return libraries, malformed


def _shortlink_filters(value: Any) -> tuple[AssemblyFilters, bool, bool, bool]:
    if value is None:
        return AssemblyFilters(), False, False, False
    if not isinstance(value, dict):
        return AssemblyFilters(), True, False, False
    mapping = {
        "commentOnly": "comment_only",
        "demangle": "demangle",
        "directives": "directives",
        "intel": "intel",
        "labels": "labels",
        "libraryCode": "library_code",
        "trim": "trim",
        "debugCalls": "debug_calls",
    }
    updates: dict[str, bool] = {}
    malformed = False
    for wire_name, model_name in mapping.items():
        candidate = value.get(wire_name)
        if candidate is None:
            continue
        if isinstance(candidate, bool):
            updates[model_name] = candidate
        else:
            malformed = True
    unsafe = False
    for name in ("execute", "binary", "binaryObject"):
        candidate = value.get(name)
        if candidate is True:
            unsafe = True
        elif candidate is not None and not isinstance(candidate, bool):
            malformed = True
    known = {*mapping, "execute", "binary", "binaryObject"}
    omitted = bool(set(value) - known)
    return AssemblyFilters.model_validate(updates), malformed, unsafe, omitted


def normalize_shortlink_info(
    value: dict[str, Any],
    shortlink_id: str,
    url: str,
) -> GetShortlinkResult:
    endpoint = f"api/shortlinkinfo/{shortlink_id}"
    raw_sessions = value.get("sessions")
    if not isinstance(raw_sessions, list):
        raise IncompatibleBackend(endpoint, detail="a malformed shortlink session list")
    warnings: list[WarningItem] = []
    sessions: list[ShortlinkSessionInfo] = []
    malformed = False
    omitted = bool(set(value) - {"sessions", "trees", "nonce"})
    unsafe = False
    sessions_truncated = len(raw_sessions) > _MAX_SHORTLINK_RAW_SESSIONS
    for raw_session in raw_sessions[:_MAX_SHORTLINK_RAW_SESSIONS]:
        if not isinstance(raw_session, dict):
            malformed = True
            continue
        language = raw_session.get("language")
        if language != "c++":
            omitted = True
            continue
        if len(sessions) >= MAX_SHORTLINK_SESSIONS:
            sessions_truncated = True
            continue
        source = raw_session.get("source")
        raw_compilers = raw_session.get("compilers", [])
        if not isinstance(source, str) or not isinstance(raw_compilers, list):
            malformed = True
            continue
        if len(raw_compilers) > MAX_SHORTLINK_SESSION_COMPILERS:
            warnings.append(
                _warning(
                    "shortlink_compilers_truncated",
                    "A shortlink session contained more compiler panes than the output limit.",
                )
            )
        compilers: list[ShortlinkCompilerInfo] = []
        for raw_compiler in raw_compilers[:MAX_SHORTLINK_SESSION_COMPILERS]:
            if not isinstance(raw_compiler, dict):
                malformed = True
                continue
            compiler_id = raw_compiler.get("id")
            options = raw_compiler.get("options", "")
            if not isinstance(compiler_id, str) or not isinstance(options, str):
                malformed = True
                continue
            libraries, malformed_libraries = _shortlink_libraries(raw_compiler.get("libs"))
            filters, malformed_filters, unsafe_filters, omitted_filters = _shortlink_filters(
                raw_compiler.get("filters")
            )
            malformed = malformed or malformed_libraries or malformed_filters
            unsafe = unsafe or unsafe_filters
            omitted = omitted or omitted_filters
            known_compiler_fields = {
                "_internalid",
                "id",
                "options",
                "libs",
                "filters",
                "tools",
                "overrides",
                "specialoutputs",
            }
            if set(raw_compiler) - known_compiler_fields or any(
                raw_compiler.get(name) for name in ("tools", "overrides", "specialoutputs")
            ):
                omitted = True
            try:
                compilers.append(
                    ShortlinkCompilerInfo(
                        compiler_id=compiler_id,
                        options=options,
                        libraries=libraries,
                        filters=filters,
                    )
                )
            except ValidationError:
                malformed = True
        session_id = raw_session.get("id")
        if isinstance(session_id, bool) or not isinstance(session_id, (int, str, type(None))):
            session_id = None
            malformed = True
        if raw_session.get("executors"):
            unsafe = True
        known_session_fields = {
            "id",
            "language",
            "source",
            "filename",
            "compilers",
            "executors",
            "conformanceview",
        }
        if set(raw_session) - known_session_fields or raw_session.get("conformanceview"):
            omitted = True
        try:
            sessions.append(
                ShortlinkSessionInfo(
                    session_id=session_id,
                    source=source,
                    compilers=compilers,
                )
            )
        except ValidationError:
            raise IncompatibleBackend(
                endpoint,
                detail="invalid or oversized shortlink source",
            ) from None
    raw_trees = value.get("trees")
    has_trees = isinstance(raw_trees, list) and bool(raw_trees)
    if raw_trees is not None and not isinstance(raw_trees, list):
        malformed = True
    if has_trees:
        omitted = True
    if sessions_truncated:
        warnings.append(
            _warning(
                "shortlink_sessions_truncated",
                f"Only the first {MAX_SHORTLINK_SESSIONS} bounded C++ sessions were returned.",
            )
        )
    if malformed:
        warnings.append(
            _warning(
                "malformed_shortlink_state",
                "Ignored malformed fields in Compiler Explorer shortlink state.",
            )
        )
    if omitted:
        warnings.append(
            _warning(
                "shortlink_state_omitted",
                "Omitted unsupported non-C++ sessions, project trees, or pane-specific state.",
            )
        )
    if unsafe:
        warnings.append(
            _warning(
                "shortlink_execution_state_omitted",
                "Omitted executor, analyzer, binary-output, or execution-oriented shortlink state.",
            )
        )
    try:
        return GetShortlinkResult(
            shortlink_id=shortlink_id,
            url=url,
            sessions=sessions,
            has_trees=has_trees,
            warnings=merge_warnings(warnings),
        )
    except ValidationError:
        raise IncompatibleBackend(endpoint, detail="oversized normalized shortlink state") from None


def enforce_shortlink_response_budget(
    response: GetShortlinkResult,
    maximum_bytes: int = MAX_SERIALIZED_RESPONSE_BYTES,
) -> None:
    if _serialized_size(response) <= maximum_bytes:
        return
    response.response_truncated = True
    response.warnings.append(
        _warning(
            "shortlink_response_truncated",
            f"Shortlink state was reduced to the {maximum_bytes}-byte response safety budget.",
        )
    )
    while _serialized_size(response) > maximum_bytes:
        session = next(
            (candidate for candidate in reversed(response.sessions) if candidate.compilers),
            None,
        )
        if session is None:
            break
        session.compilers.pop()
    while _serialized_size(response) > maximum_bytes and len(response.sessions) > 1:
        response.sessions.pop()
    if _serialized_size(response) > maximum_bytes:
        raise IncompatibleBackend(
            f"api/shortlinkinfo/{response.shortlink_id}",
            detail="shortlink source exceeds the serialized response budget",
        )


def assembly_fingerprint(lines: Sequence[AssemblyLine]) -> str | None:
    if not lines:
        return None
    normalized = "\n".join(_WHITESPACE_RE.sub(" ", line.text.strip()) for line in lines)
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()


def window_page(items: Sequence[V], window: OutputWindow) -> Page[V]:
    total = len(items)
    selected = list(items[window.offset : window.offset + window.limit])
    returned = len(selected)
    return Page[V](
        items=selected,
        page=PageInfo(
            offset=window.offset,
            limit=window.limit,
            total=total,
            returned=returned,
            truncated_before=window.offset > 0 and total > 0,
            truncated_after=window.offset + returned < total,
            next_offset=window.offset + returned if window.offset + returned < total else None,
        ),
    )


class _SafeHTMLParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.parts: list[str] = []
        self._suppressed_depth = 0

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        del attrs
        lowered = tag.casefold()
        if lowered in {"script", "style"}:
            self._suppressed_depth += 1
        elif self._suppressed_depth == 0 and lowered in _ALLOWED_HTML_TAGS:
            self.parts.append(f"<{lowered}>")

    def handle_startendtag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        del attrs
        lowered = tag.casefold()
        if self._suppressed_depth == 0 and lowered in _VOID_HTML_TAGS:
            self.parts.append(f"<{lowered}>")

    def handle_endtag(self, tag: str) -> None:
        lowered = tag.casefold()
        if lowered in {"script", "style"} and self._suppressed_depth:
            self._suppressed_depth -= 1
        elif (
            self._suppressed_depth == 0
            and lowered in _ALLOWED_HTML_TAGS
            and lowered not in _VOID_HTML_TAGS
        ):
            self.parts.append(f"</{lowered}>")

    def handle_data(self, data: str) -> None:
        if self._suppressed_depth == 0:
            self.parts.append(html.escape(sanitize_text(data), quote=False))


def sanitize_html(value: str) -> str:
    parser = _SafeHTMLParser()
    try:
        parser.feed(value)
        parser.close()
    except (ValueError, RecursionError):
        return html.escape(sanitize_text(value), quote=False)
    return "".join(parser.parts)


def normalize_opcode_documentation(
    value: dict[str, Any],
    instruction_set: str,
    opcode: str,
) -> OpcodeDocumentation:
    tooltip_value = value.get("tooltip")
    html_value = value.get("html")
    source_url = _safe_url(value.get("url"))
    if not isinstance(tooltip_value, str) or not isinstance(html_value, str) or source_url is None:
        endpoint = f"api/asm/{instruction_set}/{opcode}"
        raise IncompatibleBackend(endpoint, detail="incomplete opcode documentation")
    tooltip, tooltip_truncated = truncate_text(tooltip_value, _MAX_TOOLTIP_BYTES)
    sanitized_html = sanitize_html(html_value)
    html_output, html_truncated = truncate_text(sanitized_html, _MAX_HTML_BYTES)
    warnings: list[WarningItem] = []
    if tooltip_truncated:
        warnings.append(
            _warning("opcode_tooltip_truncated", "Opcode tooltip exceeded the output limit.")
        )
    if html_truncated:
        warnings.append(_warning("opcode_html_truncated", "Opcode HTML exceeded the output limit."))
    return OpcodeDocumentation(
        instruction_set=instruction_set,
        opcode=opcode,
        tooltip=tooltip,
        html=html_output,
        source_url=source_url,
        tooltip_truncated=tooltip_truncated,
        html_truncated=html_truncated,
        warnings=warnings,
    )


def _serialized_size(value: StrictModel) -> int:
    return len(value.model_dump_json().encode("utf-8"))


def enforce_response_budget(
    response: StrictModel,
    pages: Sequence[Page[Any]],
    maximum_bytes: int = MAX_SERIALIZED_RESPONSE_BYTES,
) -> None:
    size = _serialized_size(response)
    if size <= maximum_bytes:
        return
    response_truncated = getattr(response, "response_truncated", None)
    if isinstance(response_truncated, bool):
        response.response_truncated = True  # type: ignore[attr-defined]
    warnings = getattr(response, "warnings", None)
    if isinstance(warnings, list):
        warnings.append(
            _warning(
                "response_budget_truncated",
                f"Serialized response was reduced to the {maximum_bytes}-byte safety budget.",
            )
        )
    mutable_pages = [page for page in pages if page.items]
    for _ in range(64):
        size = _serialized_size(response)
        if size <= maximum_bytes or not mutable_pages:
            break
        page = max(mutable_pages, key=lambda candidate: len(candidate.items))
        excess_ratio = max((size - maximum_bytes) / size, 0.05)
        remove_count = max(1, math.ceil(len(page.items) * excess_ratio))
        del page.items[-remove_count:]
        page.page.returned = len(page.items)
        page.page.truncated_after = True
        page.page.next_offset = page.page.offset + page.page.returned
        mutable_pages = [candidate for candidate in mutable_pages if candidate.items]
    if _serialized_size(response) > maximum_bytes:
        raise ValueError("fixed response metadata exceeds serialized response budget")
