from __future__ import annotations

import asyncio
import os

import pytest

from ce_analyzer_mcp.catalog import Catalog
from ce_analyzer_mcp.client import CompilerExplorerClient
from ce_analyzer_mcp.config import Settings
from ce_analyzer_mcp.models import (
    CompileCppRequest,
    CompileResult,
    CreateShortlinkRequest,
    CreateShortlinkResult,
    GetShortlinkRequest,
    GetShortlinkResult,
    OutputWindow,
    ShortlinkCompilerConfiguration,
    SourceBundle,
)
from ce_analyzer_mcp.workflows import Workflows


@pytest.mark.live
@pytest.mark.skipif(
    os.environ.get("CE_LIVE_TEST") != "1",
    reason="set CE_LIVE_TEST=1 to contact the configured Compiler Explorer backend",
)
def test_tiny_live_compile_is_bounded_compile_only_and_does_not_echo_source() -> None:
    source = "int square(int value) { return value * value; }"

    async def exercise() -> CompileResult:
        settings = Settings.from_env()
        async with CompilerExplorerClient(settings) as client:
            workflows = Workflows(client, Catalog(client))
            return await workflows.compile_cpp(
                CompileCppRequest(
                    source=SourceBundle(source=source),
                    compiler="gcc-latest",
                    compiler_arguments=["-O1"],
                    include_diagnostics=True,
                    include_assembly=True,
                    include_optimization=False,
                    window=OutputWindow(limit=5),
                )
            )

    result = asyncio.run(exercise())

    assert result.status == "success"
    assert result.exit_code == 0
    assert result.timed_out is False
    assert result.compiler.resolved_id
    assert len(result.fingerprint) == 64
    assert result.assembly_line_count > 0
    assert source not in result.model_dump_json()


@pytest.mark.live
@pytest.mark.skipif(
    os.environ.get("CE_LIVE_SHORTLINK_TEST") != "1",
    reason="set CE_LIVE_SHORTLINK_TEST=1 to permanently create a public shortlink",
)
def test_tiny_live_shortlink_is_validated_created_and_retrievable() -> None:
    source = 'extern "C" int shared_answer() { return 42; }\n'

    async def exercise() -> tuple[CreateShortlinkResult, GetShortlinkResult]:
        settings = Settings.from_env()
        async with CompilerExplorerClient(settings) as client:
            workflows = Workflows(client, Catalog(client))
            created = await workflows.create_shortlink(
                CreateShortlinkRequest(
                    source=SourceBundle(source=source),
                    compilers=[
                        ShortlinkCompilerConfiguration(
                            compiler="gcc-latest",
                            compiler_arguments=["-O1"],
                        )
                    ],
                )
            )
            retrieved = await workflows.get_shortlink(
                GetShortlinkRequest(shortlink_id=created.shortlink_id)
            )
            return created, retrieved

    created, retrieved = asyncio.run(exercise())

    assert created.compilation_validated is True
    assert created.compilers[0].status == "success"
    assert source not in created.model_dump_json()
    assert retrieved.shortlink_id == created.shortlink_id
    assert retrieved.sessions[0].source == source
