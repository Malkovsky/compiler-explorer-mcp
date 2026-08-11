from __future__ import annotations

import argparse
import asyncio
import json
import sys
from collections.abc import Awaitable, Callable, Sequence
from pathlib import Path
from typing import Any

from mcp import Client
from mcp.types import ListToolsResult, Tool

from ce_analyzer_mcp.__about__ import __version__
from ce_analyzer_mcp.server import create_server

SNAPSHOT_FORMAT = "mcp-tools-snapshot"
SNAPSHOT_FORMAT_VERSION = 1
SERVER_NAME = "ce-analyzer-mcp"


def _sanitize_json(value: Any) -> Any:
    if isinstance(value, dict):
        return {key: _sanitize_json(item) for key, item in sorted(value.items())}
    if isinstance(value, list):
        return [_sanitize_json(item) for item in value]
    if value is None or isinstance(value, str | int | float | bool):
        return value
    raise TypeError(f"Unsupported snapshot value type: {type(value).__name__}")


def normalize_tool(tool: Tool) -> dict[str, Any]:
    if not isinstance(tool.input_schema, dict):
        raise TypeError(f"Tool {tool.name!r} has a non-object input schema")

    normalized: dict[str, Any] = {"name": tool.name}
    if tool.title is not None:
        normalized["title"] = tool.title
    if tool.description is not None:
        normalized["description"] = tool.description
    normalized["inputSchema"] = _sanitize_json(tool.input_schema)
    if tool.output_schema is not None:
        if not isinstance(tool.output_schema, dict):
            raise TypeError(f"Tool {tool.name!r} has a non-object output schema")
        normalized["outputSchema"] = _sanitize_json(tool.output_schema)
    if tool.annotations is not None:
        normalized["annotations"] = _sanitize_json(
            tool.annotations.model_dump(mode="json", by_alias=True, exclude_none=True)
        )
    if tool.icons is not None:
        normalized["icons"] = _sanitize_json(
            [icon.model_dump(mode="json", by_alias=True, exclude_none=True) for icon in tool.icons]
        )
    if tool.execution is not None:
        normalized["execution"] = _sanitize_json(
            tool.execution.model_dump(mode="json", by_alias=True, exclude_none=True)
        )
    return normalized


async def collect_tool_pages(
    list_page: Callable[[str | None], Awaitable[ListToolsResult]],
) -> list[Tool]:
    tools: list[Tool] = []
    seen_cursors: set[str] = set()
    cursor: str | None = None

    while True:
        page = await list_page(cursor)
        tools.extend(page.tools)
        cursor = page.next_cursor
        if cursor is None:
            return tools
        if cursor in seen_cursors:
            raise RuntimeError("tools/list returned a repeated pagination cursor")
        seen_cursors.add(cursor)


async def build_tools_snapshot() -> dict[str, Any]:
    async with Client(create_server()) as client:

        async def list_page(cursor: str | None) -> ListToolsResult:
            return await client.list_tools(cursor=cursor, cache_mode="bypass")

        tools = await collect_tool_pages(list_page)

    names = [tool.name for tool in tools]
    if len(names) != len(set(names)):
        raise RuntimeError("tools/list returned duplicate tool names")

    return {
        "format": SNAPSHOT_FORMAT,
        "formatVersion": SNAPSHOT_FORMAT_VERSION,
        "server": {"name": SERVER_NAME, "version": __version__},
        "tools": [normalize_tool(tool) for tool in tools],
    }


def serialize_tools_snapshot(snapshot: dict[str, Any]) -> str:
    return json.dumps(snapshot, ensure_ascii=False, indent=2) + "\n"


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Generate the sanitized MCP tools snapshot")
    parser.add_argument("path", nargs="?", default="mcp-tools.json", type=Path)
    parser.add_argument(
        "--check", action="store_true", help="fail if the snapshot is absent or stale"
    )
    args = parser.parse_args(argv)

    expected = serialize_tools_snapshot(asyncio.run(build_tools_snapshot()))
    if args.check:
        if not args.path.is_file() or args.path.read_text(encoding="utf-8") != expected:
            print(f"{args.path} is missing or stale", file=sys.stderr)
            return 1
        return 0

    args.path.write_text(expected, encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
