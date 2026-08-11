from __future__ import annotations

import argparse
from collections.abc import Sequence

from ce_analyzer_mcp.__about__ import __version__


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ce-analyzer-mcp",
        description="Run the Compiler Explorer analysis and sharing MCP server over stdio.",
    )
    parser.add_argument("--version", action="version", version=__version__)
    return parser


def main(argv: Sequence[str] | None = None) -> None:
    build_parser().parse_args(argv)
    from ce_analyzer_mcp.server import mcp

    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
