from __future__ import annotations

import email.parser
import os
import subprocess
import sys
import tarfile
import types
import zipfile
from pathlib import Path

import pytest

from ce_analyzer_mcp import __version__
from ce_analyzer_mcp.cli import build_parser, main

PROJECT_ROOT = Path(__file__).resolve().parents[1]
SOURCE_ROOT = PROJECT_ROOT / "src"


def _source_environment() -> dict[str, str]:
    environment = os.environ.copy()
    current = environment.get("PYTHONPATH")
    environment["PYTHONPATH"] = (
        str(SOURCE_ROOT) if not current else os.pathsep.join((str(SOURCE_ROOT), current))
    )
    return environment


def _run_python(*arguments: str, pythonpath: str | None = None) -> subprocess.CompletedProcess[str]:
    environment = os.environ.copy()
    environment["PYTHONPATH"] = pythonpath if pythonpath is not None else str(SOURCE_ROOT)
    return subprocess.run(
        [sys.executable, *arguments],
        cwd=PROJECT_ROOT,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
        timeout=120,
    )


def test_parser_metadata_and_direct_version_form(capsys: pytest.CaptureFixture[str]) -> None:
    parser = build_parser()
    assert parser.prog == "ce-analyzer-mcp"
    assert "Compiler Explorer analysis and sharing MCP server" in parser.description

    with pytest.raises(SystemExit) as exit_info:
        main(["--version"])

    captured = capsys.readouterr()
    assert exit_info.value.code == 0
    assert captured.out == f"{__version__}\n"
    assert captured.err == ""


def test_direct_help_form_has_no_startup_banner(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as exit_info:
        main(["--help"])

    captured = capsys.readouterr()
    assert exit_info.value.code == 0
    assert captured.out.startswith("usage: ce-analyzer-mcp")
    assert "--version" in captured.out
    assert "stdio" in captured.out
    assert captured.err == ""
    assert "starting" not in captured.out.casefold()


def test_main_starts_only_stdio_transport(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[dict[str, str]] = []

    class FakeMCP:
        def run(self, **kwargs: str) -> None:
            calls.append(kwargs)

    fake_server = types.ModuleType("ce_analyzer_mcp.server")
    fake_server.mcp = FakeMCP()  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "ce_analyzer_mcp.server", fake_server)

    main([])

    assert calls == [{"transport": "stdio"}]


@pytest.mark.parametrize(
    ("arguments", "expected"),
    [
        (("-m", "ce_analyzer_mcp", "--version"), "0.1.0\n"),
        (("-m", "ce_analyzer_mcp.cli", "--version"), "0.1.0\n"),
    ],
)
def test_module_version_forms(arguments: tuple[str, ...], expected: str) -> None:
    completed = _run_python(*arguments)

    assert completed.returncode == 0, completed.stderr
    assert completed.stdout == expected
    assert completed.stderr == ""


@pytest.mark.parametrize("module", ["ce_analyzer_mcp", "ce_analyzer_mcp.cli"])
def test_module_help_forms(module: str) -> None:
    completed = _run_python("-m", module, "--help")

    assert completed.returncode == 0, completed.stderr
    assert completed.stdout.startswith("usage: ce-analyzer-mcp")
    assert "--version" in completed.stdout
    assert completed.stderr == ""


def test_declared_project_metadata_and_entry_point_are_consistent() -> None:
    pyproject = (PROJECT_ROOT / "pyproject.toml").read_text(encoding="utf-8")
    about = (SOURCE_ROOT / "ce_analyzer_mcp" / "__about__.py").read_text(encoding="utf-8")

    assert 'name = "ce-analyzer-mcp"' in pyproject
    assert f'version = "{__version__}"' in pyproject
    assert f'__version__ = "{__version__}"' in about
    assert 'requires-python = ">=3.10"' in pyproject
    assert 'ce-analyzer-mcp = "ce_analyzer_mcp.cli:main"' in pyproject
    assert 'readme = "README.md"' in pyproject
    assert 'license = "MIT"' in pyproject
    assert '"mcp>=2,<3"' in pyproject
    assert '"httpx>=0.27,<1"' in pyproject
    assert '"pydantic>=2,<3"' in pyproject
    assert '"packaging>=24,<27"' in pyproject
    assert 'packages = ["src/ce_analyzer_mcp"]' in pyproject
    assert (SOURCE_ROOT / "ce_analyzer_mcp" / "py.typed").is_file()


def test_all_declared_packaging_inputs_exist() -> None:
    required = [
        PROJECT_ROOT / "README.md",
        PROJECT_ROOT / "LICENSE",
        PROJECT_ROOT / "pyproject.toml",
        PROJECT_ROOT / "uv.lock",
        SOURCE_ROOT / "ce_analyzer_mcp" / "__init__.py",
        SOURCE_ROOT / "ce_analyzer_mcp" / "__main__.py",
        SOURCE_ROOT / "ce_analyzer_mcp" / "py.typed",
    ]

    missing = [path.relative_to(PROJECT_ROOT).as_posix() for path in required if not path.is_file()]
    assert missing == [], f"declared packaging inputs are missing: {missing}"


@pytest.mark.skipif(
    not (PROJECT_ROOT / "README.md").is_file(),
    reason="artifact smoke depends on the separately asserted declared README.md input",
)
def test_build_wheel_sdist_metadata_contents_and_import_smoke(tmp_path: Path) -> None:
    output = tmp_path / "artifacts"
    output.mkdir()
    build = subprocess.run(
        [
            sys.executable,
            "-m",
            "build",
            "--outdir",
            str(output),
            str(PROJECT_ROOT),
        ],
        cwd=PROJECT_ROOT,
        env=_source_environment(),
        check=False,
        capture_output=True,
        text=True,
        timeout=240,
    )
    assert build.returncode == 0, f"{build.stdout}\n{build.stderr}"

    wheels = list(output.glob("ce_analyzer_mcp-*.whl"))
    sdists = list(output.glob("ce_analyzer_mcp-*.tar.gz"))
    assert len(wheels) == 1
    assert len(sdists) == 1
    wheel = wheels[0]
    sdist = sdists[0]

    with zipfile.ZipFile(wheel) as archive:
        names = set(archive.namelist())
        assert "ce_analyzer_mcp/__init__.py" in names
        assert "ce_analyzer_mcp/__main__.py" in names
        assert "ce_analyzer_mcp/server.py" in names
        assert "ce_analyzer_mcp/py.typed" in names
        assert not any(name.startswith("tests/") for name in names)
        metadata_name = next(name for name in names if name.endswith(".dist-info/METADATA"))
        entry_points_name = next(
            name for name in names if name.endswith(".dist-info/entry_points.txt")
        )
        metadata_text = archive.read(metadata_name).decode("utf-8")
        entry_points = archive.read(entry_points_name).decode("utf-8")

    metadata = email.parser.Parser().parsestr(metadata_text)
    assert metadata["Name"] == "ce-analyzer-mcp"
    assert metadata["Version"] == __version__
    assert metadata["Requires-Python"] == ">=3.10"
    requirements = metadata.get_all("Requires-Dist") or []
    assert any(requirement.startswith("mcp<3,>=2") for requirement in requirements)
    assert any(requirement.startswith("httpx<1,>=0.27") for requirement in requirements)
    assert any(requirement.startswith("pydantic<3,>=2") for requirement in requirements)
    assert "[console_scripts]" in entry_points
    assert "ce-analyzer-mcp = ce_analyzer_mcp.cli:main" in entry_points

    with tarfile.open(sdist, mode="r:gz") as archive:
        members = archive.getmembers()
        names = {member.name for member in members}
        assert all(not Path(member.name).is_absolute() for member in members)
        assert all(".." not in Path(member.name).parts for member in members)
        prefix = next(name.split("/", 1)[0] for name in names if name.endswith("/pyproject.toml"))
        expected = {
            f"{prefix}/README.md",
            f"{prefix}/LICENSE",
            f"{prefix}/pyproject.toml",
            f"{prefix}/uv.lock",
            f"{prefix}/src/ce_analyzer_mcp/server.py",
            f"{prefix}/tests/test_results.py",
            f"{prefix}/tests/test_workflows.py",
            f"{prefix}/tests/test_server.py",
            f"{prefix}/tests/test_cli_packaging.py",
            f"{prefix}/tests/test_live.py",
        }
        assert expected.issubset(names)

    twine = subprocess.run(
        [sys.executable, "-m", "twine", "check", str(wheel), str(sdist)],
        cwd=PROJECT_ROOT,
        check=False,
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert twine.returncode == 0, f"{twine.stdout}\n{twine.stderr}"

    smoke = _run_python(
        "-c",
        (
            "import asyncio, ce_analyzer_mcp; "
            "from ce_analyzer_mcp.server import create_server; "
            "tools=asyncio.run(create_server().list_tools()); "
            "print(ce_analyzer_mcp.__version__, len(tools), ','.join(t.name for t in tools))"
        ),
        pythonpath=str(wheel),
    )
    assert smoke.returncode == 0, smoke.stderr
    assert (
        smoke.stdout
        == f"{__version__} 9 "
        + ",".join(
            [
                "search_compilers",
                "search_libraries",
                "search_analyzers",
                "compile_cpp",
                "compare_cpp",
                "analyze_cpp",
                "create_shortlink",
                "get_shortlink",
                "get_opcode_documentation",
            ]
        )
        + "\n"
    )

    wheel_cli = _run_python(
        "-c",
        "from ce_analyzer_mcp.cli import main; main(['--version'])",
        pythonpath=str(wheel),
    )
    assert wheel_cli.returncode == 0, wheel_cli.stderr
    assert wheel_cli.stdout == f"{__version__}\n"
