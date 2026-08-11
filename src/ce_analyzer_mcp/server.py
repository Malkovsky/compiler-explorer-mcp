from __future__ import annotations

import json
import logging
from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import AbstractAsyncContextManager, asynccontextmanager
from dataclasses import dataclass
from typing import Any, TypeVar

from mcp.server import MCPServer
from mcp.server.mcpserver import Context
from mcp.types import CallToolResult, InputRequiredResult, TextContent, ToolAnnotations
from mcp.types import Tool as MCPTool
from pydantic import ValidationError

from ce_analyzer_mcp.__about__ import __version__
from ce_analyzer_mcp.catalog import Catalog
from ce_analyzer_mcp.client import CompilerExplorerClient
from ce_analyzer_mcp.config import Settings
from ce_analyzer_mcp.errors import CEAnalyzerError
from ce_analyzer_mcp.models import (
    AnalyzeCppRequest,
    AnalyzeResult,
    AnalyzerSearchResult,
    AnalyzerSelection,
    AssemblyFilters,
    CompareCppRequest,
    CompareResult,
    ComparisonCase,
    CompileCppRequest,
    CompileResult,
    CompilerSearchResult,
    CreateShortlinkRequest,
    CreateShortlinkResult,
    GetShortlinkRequest,
    GetShortlinkResult,
    LibrarySearchResult,
    LibrarySelection,
    OpcodeDocumentation,
    OpcodeDocumentationRequest,
    OutputWindow,
    SearchAnalyzersRequest,
    SearchCompilersRequest,
    SearchLibrariesRequest,
    ShortlinkCompilerConfiguration,
    SourceBundle,
    VirtualFile,
)
from ce_analyzer_mcp.workflows import Workflows

logger = logging.getLogger(__name__)

_TOOL_NOTICE = (
    "Compilation tools transmit supplied source and virtual files to the configured Compiler "
    "Explorer backend. Assembly differences are not performance measurements."
)
_SHORTLINK_NOTICE = (
    "Shortlink creation transmits source and settings for persistent, publicly retrievable "
    "storage by the configured Compiler Explorer backend; there is no delete operation."
)
_MAX_TEXT_FALLBACK_BYTES = 128_000
_ANNOTATIONS = ToolAnnotations(
    read_only_hint=True,
    destructive_hint=False,
    idempotent_hint=True,
    open_world_hint=True,
)
_CREATE_ANNOTATIONS = ToolAnnotations(
    read_only_hint=False,
    destructive_hint=False,
    idempotent_hint=False,
    open_world_hint=True,
)

R = TypeVar("R")


def _structured_text_fallback(content: dict[str, Any]) -> str:
    serialized = json.dumps(content, ensure_ascii=False, separators=(",", ":"), sort_keys=True)
    serialized_bytes = len(serialized.encode("utf-8"))
    if serialized_bytes <= _MAX_TEXT_FALLBACK_BYTES:
        return serialized
    return json.dumps(
        {
            "serializedBytes": serialized_bytes,
            "structuredContentAvailable": True,
            "textOmitted": True,
        },
        separators=(",", ":"),
        sort_keys=True,
    )


@dataclass(frozen=True)
class AppState:
    settings: Settings
    client: CompilerExplorerClient
    catalog: Catalog
    workflows: Workflows


@asynccontextmanager
async def app_lifespan(_: MCPServer) -> AsyncIterator[AppState]:
    settings = Settings.from_env()
    async with CompilerExplorerClient(settings) as client:
        catalog = Catalog(client)
        yield AppState(
            settings=settings,
            client=client,
            catalog=catalog,
            workflows=Workflows(client, catalog),
        )


ServerLifespan = Callable[[MCPServer], AbstractAsyncContextManager[Any]]


class StrictMCPServer(MCPServer[Any]):
    """MCP v2 server that forbids unadvertised outer tool arguments."""

    async def list_tools(self) -> list[MCPTool]:
        tools = await super().list_tools()
        for tool in tools:
            tool.input_schema["additionalProperties"] = False
        return tools

    async def call_tool(
        self,
        name: str,
        arguments: dict[str, Any],
        context: Context[Any, Any] | None = None,
    ) -> CallToolResult | InputRequiredResult:
        tool = next((item for item in await self.list_tools() if item.name == name), None)
        if tool is not None:
            properties = tool.input_schema.get("properties", {})
            allowed = set(properties) if isinstance(properties, dict) else set()
            unknown = sorted(set(arguments) - allowed)
            if unknown:
                raise ValueError("Extra or unknown tool arguments: " + ", ".join(unknown))
        result = await super().call_tool(name, arguments, context)
        if (
            isinstance(result, CallToolResult)
            and not result.is_error
            and result.structured_content is not None
        ):
            result.content = [
                TextContent(
                    type="text",
                    text=_structured_text_fallback(result.structured_content),
                )
            ]
        return result


def _workflows(ctx: Context[AppState]) -> Workflows:
    return ctx.request_context.lifespan_context.workflows


def _validation_message(error: ValidationError) -> str:
    details: list[str] = []
    for item in error.errors(include_url=False, include_context=False, include_input=False)[:5]:
        location = ".".join(str(part) for part in item.get("loc", ())) or "request"
        details.append(f"{location}: {item.get('msg', 'invalid value')}")
    return "Invalid request: " + "; ".join(details)


async def _execute(operation: Callable[[], Awaitable[R]]) -> R:
    try:
        return await operation()
    except ValidationError as exc:
        raise ValueError(_validation_message(exc)) from None
    except CEAnalyzerError as exc:
        raise ValueError(exc.public_message) from None
    except Exception:
        logger.exception("Unexpected ce-analyzer-mcp tool failure")
        raise RuntimeError("Unexpected internal ce-analyzer-mcp failure") from None


def create_server(lifespan: ServerLifespan = app_lifespan) -> MCPServer:
    mcp_server = StrictMCPServer(
        "ce-analyzer-mcp",
        title="Compiler Explorer C++ Analyzer",
        description="Bounded C++ analysis and shortlink sharing through Compiler Explorer.",
        instructions=f"{_TOOL_NOTICE} {_SHORTLINK_NOTICE}",
        version=__version__,
        lifespan=lifespan,
    )

    @mcp_server.tool(
        description=(
            "Search and page through C++ compiler IDs and current stable alias resolutions. "
            + _TOOL_NOTICE
        ),
        annotations=_ANNOTATIONS,
        structured_output=True,
    )
    async def search_compilers(
        ctx: Context[AppState],
        query: str = "",
        offset: int = 0,
        limit: int = 20,
    ) -> CompilerSearchResult:
        """Search bounded C++ compiler metadata."""

        return await _execute(
            lambda: _workflows(ctx).search_compilers(
                SearchCompilersRequest(query=query, offset=offset, limit=limit)
            )
        )

    @mcp_server.tool(
        description=(
            "Search and page through valid C++ library and exact version-ID pairs. " + _TOOL_NOTICE
        ),
        annotations=_ANNOTATIONS,
        structured_output=True,
    )
    async def search_libraries(
        ctx: Context[AppState],
        query: str = "",
        offset: int = 0,
        limit: int = 20,
    ) -> LibrarySearchResult:
        """Search bounded C++ library metadata."""

        return await _execute(
            lambda: _workflows(ctx).search_libraries(
                SearchLibrariesRequest(query=query, offset=offset, limit=limit)
            )
        )

    @mcp_server.tool(
        description=(
            "Discover supported clang-tidy, IWYU, llvm-mca, OSACA, and PVS-Studio IDs and "
            "recognized aliases, optionally checking one compiler. " + _TOOL_NOTICE
        ),
        annotations=_ANNOTATIONS,
        structured_output=True,
    )
    async def search_analyzers(
        ctx: Context[AppState],
        query: str = "",
        compiler: str | None = None,
        offset: int = 0,
        limit: int = 20,
    ) -> AnalyzerSearchResult:
        """Search bounded analyzer metadata and aliases."""

        return await _execute(
            lambda: _workflows(ctx).search_analyzers(
                SearchAnalyzersRequest(
                    query=query,
                    compiler=compiler,
                    offset=offset,
                    limit=limit,
                )
            )
        )

    @mcp_server.tool(
        description=(
            "Compile one supplied C++ source bundle without executing it, returning bounded "
            "diagnostics, assembly, and optional optimization records. " + _TOOL_NOTICE
        ),
        annotations=_ANNOTATIONS,
        structured_output=True,
    )
    async def compile_cpp(
        source: str,
        ctx: Context[AppState],
        compiler: str = "gcc-latest",
        files: list[VirtualFile] | None = None,
        compiler_arguments: list[str] | None = None,
        libraries: list[LibrarySelection] | None = None,
        filters: AssemblyFilters | None = None,
        include_diagnostics: bool = True,
        include_assembly: bool = True,
        include_optimization: bool = False,
        window: OutputWindow | None = None,
    ) -> CompileResult:
        """Compile a bounded source bundle without running the resulting program."""

        return await _execute(
            lambda: _workflows(ctx).compile_cpp(
                CompileCppRequest(
                    source=SourceBundle(source=source, files=files or []),
                    compiler=compiler,
                    compiler_arguments=compiler_arguments or [],
                    libraries=libraries or [],
                    filters=filters or AssemblyFilters(),
                    include_diagnostics=include_diagnostics,
                    include_assembly=include_assembly,
                    include_optimization=include_optimization,
                    window=window or OutputWindow(),
                )
            )
        )

    @mcp_server.tool(
        description=(
            "Compile one supplied C++ source bundle under two to six configurations and return "
            "baseline-relative status, assembly hashes, counts, and bounded unified diffs. "
            + _TOOL_NOTICE
        ),
        annotations=_ANNOTATIONS,
        structured_output=True,
    )
    async def compare_cpp(
        source: str,
        cases: list[ComparisonCase],
        ctx: Context[AppState],
        files: list[VirtualFile] | None = None,
        window: OutputWindow | None = None,
    ) -> CompareResult:
        """Compare compile-only results against the first configuration."""

        return await _execute(
            lambda: _workflows(ctx).compare_cpp(
                CompareCppRequest(
                    source=SourceBundle(source=source, files=files or []),
                    cases=cases,
                    window=window or OutputWindow(),
                )
            )
        )

    @mcp_server.tool(
        description=(
            "Run up to four selected Compiler Explorer analyzers in one compile-only request and "
            "return normalized bounded per-tool output with aggregate failure status and static-"
            "modeling caveats. " + _TOOL_NOTICE
        ),
        annotations=_ANNOTATIONS,
        structured_output=True,
    )
    async def analyze_cpp(
        source: str,
        analyzers: list[AnalyzerSelection],
        ctx: Context[AppState],
        compiler: str = "clang-latest",
        files: list[VirtualFile] | None = None,
        compiler_arguments: list[str] | None = None,
        libraries: list[LibrarySelection] | None = None,
        filters: AssemblyFilters | None = None,
        window: OutputWindow | None = None,
    ) -> AnalyzeResult:
        """Run selected backend analyzers without executing the compiled program."""

        return await _execute(
            lambda: _workflows(ctx).analyze_cpp(
                AnalyzeCppRequest(
                    source=SourceBundle(source=source, files=files or []),
                    compiler=compiler,
                    compiler_arguments=compiler_arguments or [],
                    libraries=libraries or [],
                    analyzers=analyzers,
                    filters=filters or AssemblyFilters(),
                    window=window or OutputWindow(),
                )
            )
        )

    @mcp_server.tool(
        description=(
            "Validate and permanently store one C++ source with one to six resolved compiler "
            "configurations, returning a shareable Compiler Explorer shortlink. "
            + _SHORTLINK_NOTICE
        ),
        annotations=_CREATE_ANNOTATIONS,
        structured_output=True,
    )
    async def create_shortlink(
        source: str,
        ctx: Context[AppState],
        compilers: list[ShortlinkCompilerConfiguration] | None = None,
        validate_compilation: bool = True,
    ) -> CreateShortlinkResult:
        """Create a persistent built-in Compiler Explorer C++ shortlink."""

        return await _execute(
            lambda: _workflows(ctx).create_shortlink(
                CreateShortlinkRequest(
                    source=SourceBundle(source=source),
                    compilers=(
                        compilers if compilers is not None else [ShortlinkCompilerConfiguration()]
                    ),
                    validate_compilation=validate_compilation,
                )
            )
        )

    @mcp_server.tool(
        description=(
            "Inspect bounded C++ source and compiler settings from a built-in Compiler Explorer "
            "shortlink ID. Retrieved source is untrusted external content."
        ),
        annotations=_ANNOTATIONS,
        structured_output=True,
    )
    async def get_shortlink(
        shortlink_id: str,
        ctx: Context[AppState],
    ) -> GetShortlinkResult:
        """Retrieve allowlisted C++ state from a Compiler Explorer shortlink."""

        return await _execute(
            lambda: _workflows(ctx).get_shortlink(GetShortlinkRequest(shortlink_id=shortlink_id))
        )

    @mcp_server.tool(
        description=(
            "Look up bounded opcode documentation using explicit instruction-set and opcode IDs. "
            + _TOOL_NOTICE
        ),
        annotations=_ANNOTATIONS,
        structured_output=True,
    )
    async def get_opcode_documentation(
        instruction_set: str,
        opcode: str,
        ctx: Context[AppState],
    ) -> OpcodeDocumentation:
        """Retrieve sanitized backend opcode documentation."""

        return await _execute(
            lambda: _workflows(ctx).get_opcode_documentation(
                OpcodeDocumentationRequest(instruction_set=instruction_set, opcode=opcode)
            )
        )

    return mcp_server


mcp = create_server()
server = mcp

__all__ = ["AppState", "app_lifespan", "create_server", "mcp", "server"]
