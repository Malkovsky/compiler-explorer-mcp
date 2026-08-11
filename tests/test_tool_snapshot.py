from __future__ import annotations

import asyncio
import json
from pathlib import Path

import pytest
from mcp.types import ListToolsResult, Tool, ToolExecution

from ce_analyzer_mcp.tool_snapshot import (
    SERVER_NAME,
    SNAPSHOT_FORMAT,
    SNAPSHOT_FORMAT_VERSION,
    build_tools_snapshot,
    collect_tool_pages,
    main,
    normalize_tool,
    serialize_tools_snapshot,
)

PROJECT_ROOT = Path(__file__).resolve().parents[1]
SNAPSHOT_PATH = PROJECT_ROOT / "mcp-tools.json"


def test_committed_tools_snapshot_is_complete_sanitized_and_current() -> None:
    committed = json.loads(SNAPSHOT_PATH.read_text(encoding="utf-8"))
    generated = asyncio.run(build_tools_snapshot())

    assert committed == generated
    assert committed["format"] == SNAPSHOT_FORMAT
    assert committed["formatVersion"] == SNAPSHOT_FORMAT_VERSION
    assert committed["server"]["name"] == SERVER_NAME
    assert len(committed["tools"]) == 9
    assert len({tool["name"] for tool in committed["tools"]}) == 9

    allowed_fields = {
        "name",
        "title",
        "description",
        "inputSchema",
        "outputSchema",
        "annotations",
        "icons",
        "execution",
    }
    for tool in committed["tools"]:
        assert set(tool) <= allowed_fields
        assert isinstance(tool["name"], str) and tool["name"]
        assert isinstance(tool["inputSchema"], dict)
        assert "_meta" not in tool


def test_tool_normalization_omits_protocol_meta_but_preserves_schema_and_execution() -> None:
    tool = Tool(
        name="probe",
        inputSchema={
            "type": "object",
            "properties": {"_meta": {"type": "string"}},
        },
        execution=ToolExecution(taskSupport="optional"),
        _meta={"credential": "must-not-appear"},
    )

    normalized = normalize_tool(tool)
    assert "_meta" not in normalized
    assert normalized["inputSchema"]["properties"]["_meta"] == {"type": "string"}
    assert normalized["execution"] == {"taskSupport": "optional"}


def test_tool_page_collection_combines_pages_and_rejects_repeated_cursors() -> None:
    pages = {
        None: ListToolsResult(
            tools=[Tool(name="first", inputSchema={"type": "object"})],
            nextCursor="second-page",
        ),
        "second-page": ListToolsResult(tools=[Tool(name="second", inputSchema={"type": "object"})]),
    }

    async def list_page(cursor: str | None) -> ListToolsResult:
        return pages[cursor]

    tools = asyncio.run(collect_tool_pages(list_page))
    assert [tool.name for tool in tools] == ["first", "second"]

    async def repeated_cursor(_: str | None) -> ListToolsResult:
        return ListToolsResult(tools=[], nextCursor="same")

    with pytest.raises(RuntimeError, match="repeated pagination cursor"):
        asyncio.run(collect_tool_pages(repeated_cursor))


def test_snapshot_check_detects_stale_content(tmp_path: Path) -> None:
    path = tmp_path / "mcp-tools.json"
    path.write_text("{}\n", encoding="utf-8")
    assert main(["--check", str(path)]) == 1

    path.write_text(
        serialize_tools_snapshot(asyncio.run(build_tools_snapshot())),
        encoding="utf-8",
    )
    assert main(["--check", str(path)]) == 0
