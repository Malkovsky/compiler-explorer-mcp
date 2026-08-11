from __future__ import annotations

import copy
from typing import Any

import pytest

from ce_analyzer_mcp.catalog import (
    ANALYZER_ALIASES,
    COMPILER_ALIASES,
    Catalog,
    _normalize_analyzers,
    _normalize_compilers,
    _normalize_libraries,
)
from ce_analyzer_mcp.errors import SelectionError
from ce_analyzer_mcp.models import (
    AnalyzerSelection,
    LibrarySelection,
    SearchAnalyzersRequest,
    SearchCompilersRequest,
    SearchLibrariesRequest,
)


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


_MISSING = object()


class FakeClient:
    def __init__(
        self,
        *,
        compilers: list[dict[str, Any]] | None = None,
        libraries: list[dict[str, Any]] | None = None,
        tools: list[dict[str, Any]] | None = None,
    ) -> None:
        self.compilers = compilers or []
        self.libraries = libraries or []
        self.tools = tools or []
        self.compiler_calls = 0
        self.library_calls = 0
        self.tool_calls = 0

    async def get_compilers(self) -> list[dict[str, Any]]:
        self.compiler_calls += 1
        return copy.deepcopy(self.compilers)

    async def get_libraries(self) -> list[dict[str, Any]]:
        self.library_calls += 1
        return copy.deepcopy(self.libraries)

    async def get_tools(self) -> list[dict[str, Any]]:
        self.tool_calls += 1
        return copy.deepcopy(self.tools)


def _compiler(
    compiler_id: str,
    version: str,
    *,
    family: str = "gcc",
    name: str | None = None,
    instruction_set: str = "amd64",
    group: str | None = None,
    group_name: str | None = None,
    compiler_type: str | None = None,
    categories: list[str] | None = None,
    language: str = "c++",
    release_track: str | None = "stable",
    is_semver: bool | None = True,
    is_nightly: bool | None = False,
    hidden: bool | None = False,
    emulated: bool | None = False,
    interpreted: bool | None = False,
    tools: list[Any] | dict[str, Any] | None = None,
    libraries: object = _MISSING,
    supports_opt: bool | None = True,
) -> dict[str, Any]:
    default_groups = {"gcc": "gcc86", "clang": "clang", "msvc": "vcpp_x64"}
    family_names = {"gcc": "GCC", "clang": "Clang", "msvc": "MSVC"}
    item: dict[str, Any] = {
        "id": compiler_id,
        "name": name or f"x86-64 {family_names.get(family, family)} {version}",
        "lang": language,
        "compilerType": compiler_type if compiler_type is not None else family,
        "compilerCategories": categories if categories is not None else [family],
        "semver": version,
        "releaseTrack": release_track,
        "instructionSet": instruction_set,
        "group": group if group is not None else default_groups.get(family, "other"),
        "groupName": group_name or f"{family} x86-64",
        "isSemVer": is_semver,
        "isNightly": is_nightly,
        "hidden": hidden,
        "emulated": emulated,
        "interpreted": interpreted,
        "supportsOptOutput": supports_opt,
        "tools": tools or [],
    }
    if libraries is not _MISSING:
        item["libsArr"] = libraries
    return item


def _library(
    library_id: str,
    name: str,
    versions: list[dict[str, Any]],
    *,
    description: Any = None,
    url: Any = None,
) -> dict[str, Any]:
    return {
        "id": library_id,
        "name": name,
        "description": description,
        "url": url,
        "versions": versions,
    }


def _version(
    version_id: Any,
    version: Any,
    *,
    name: Any = None,
    hidden: bool = False,
) -> dict[str, Any]:
    return {"id": version_id, "version": version, "name": name, "hidden": hidden}


def _tool(
    tool_id: Any,
    name: Any,
    *,
    language: Any = "c++",
    kind: Any = "independent",
) -> dict[str, Any]:
    return {"id": tool_id, "name": name, "languageId": language, "type": kind}


def test_compiler_metadata_normalization_is_tolerant_bounded_and_typed() -> None:
    raw = [
        {
            **_compiler(
                "gcc-14",
                "14.2.0",
                name=" GCC\x00 14.2 ",
                categories=["GCC"],
                instruction_set="x86-64",
                tools=["clangtidy", {"id": "llvm-mca"}, {"bad": "ignored"}, 42],
                libraries=["fmt", {"id": "boost"}, "bad id"],
            ),
            "supportsOptOutput": True,
        },
        _compiler("wrong-language", "1.0", language="rust"),
        {"id": "bad id", "name": "Bad", "lang": "c++"},
        {"id": "missing-name", "lang": "c++"},
        {"id": 123, "name": "Wrong type", "lang": "c++"},
    ]

    compilers, ignored = _normalize_compilers(raw)

    assert ignored == 4
    assert len(compilers) == 1
    compiler = compilers[0]
    assert compiler.info.model_dump() == {
        "id": "gcc-14",
        "name": "GCC 14.2",
        "family": "gcc",
        "version": "14.2.0",
        "instruction_set": "x86-64",
        "release_track": "stable",
        "supports_optimization_output": True,
        "aliases": [],
    }
    assert compiler.tools == frozenset({"clangtidy", "llvm-mca"})
    assert compiler.library_allowlist == frozenset({"fmt", "boost"})
    assert str(compiler.stable_version) == "14.2.0"


@pytest.mark.parametrize(
    ("item", "expected_family"),
    [
        (_compiler("g", "1", family="other", categories=["GCC"]), "gcc"),
        (_compiler("c", "1", family="other", categories=["Clang"]), "clang"),
        (_compiler("m", "1", family="other", categories=["MSVC"]), "msvc"),
        (
            _compiler(
                "fallback-gcc",
                "1",
                family="other",
                categories=[],
                compiler_type="gcc",
            ),
            "gcc",
        ),
        (
            _compiler(
                "fallback-clang",
                "1",
                family="other",
                categories=[],
                compiler_type="clang",
            ),
            "clang",
        ),
        (
            _compiler(
                "fallback-msvc",
                "1",
                family="other",
                categories=[],
                compiler_type="win32-vc",
            ),
            "msvc",
        ),
        (_compiler("other", "1", family="other", categories=[]), "other"),
    ],
)
def test_compiler_family_normalization(item: dict[str, Any], expected_family: str) -> None:
    compilers, ignored = _normalize_compilers([item])
    assert ignored == 0
    assert compilers[0].info.family == expected_family


def test_compiler_normalization_defaults_optional_metadata_without_guessing_booleans() -> None:
    item = {"id": "exact", "name": "Exact Compiler"}
    compilers, ignored = _normalize_compilers([item])

    assert ignored == 0
    compiler = compilers[0]
    assert compiler.info.family == "other"
    assert compiler.info.version == ""
    assert compiler.info.instruction_set is None
    assert compiler.info.supports_optimization_output is None
    assert compiler.stable_version is None
    assert compiler.hidden is None
    assert compiler.library_allowlist is None


@pytest.mark.anyio
async def test_exact_compiler_id_precedes_alias_even_when_exact_entry_is_not_alias_eligible() -> (
    None
):
    exact_alias_id = _compiler(
        "gcc-latest",
        "development",
        name="Exact backend ID",
        instruction_set="aarch64",
        release_track="nightly",
    )
    client = FakeClient(compilers=[_compiler("gcc-14", "14.2.0"), exact_alias_id])

    resolved = await Catalog(client).resolve_compiler("gcc-latest")  # type: ignore[arg-type]

    assert resolved.info.id == "gcc-latest"
    assert resolved.info.name == "Exact backend ID"


@pytest.mark.anyio
async def test_duplicate_exact_compiler_ids_are_rejected_as_ambiguous() -> None:
    client = FakeClient(compilers=[_compiler("duplicate", "1.0"), _compiler("duplicate", "2.0")])

    with pytest.raises(SelectionError, match="compiler ID 'duplicate' is ambiguous"):
        await Catalog(client).resolve_compiler("duplicate")  # type: ignore[arg-type]


@pytest.mark.anyio
@pytest.mark.parametrize(
    ("alias", "family", "older_id", "newer_id"),
    [
        ("gcc-latest", "gcc", "gcc-13", "gcc-14"),
        ("clang-latest", "clang", "clang-18", "clang-19"),
        ("msvc-latest", "msvc", "msvc-19.43", "msvc-19.44"),
    ],
)
async def test_each_compiler_alias_selects_newest_stable_native_candidate(
    alias: str, family: str, older_id: str, newer_id: str
) -> None:
    old_version, new_version = {
        "gcc": ("13.4.0", "14.2.0"),
        "clang": ("18.1.8", "19.1.7"),
        "msvc": ("19.43.34810", "19.44.35207"),
    }[family]
    client = FakeClient(
        compilers=[
            _compiler(newer_id, new_version, family=family),
            _compiler(older_id, old_version, family=family),
        ]
    )

    resolved = await Catalog(client).resolve_compiler(alias)  # type: ignore[arg-type]

    assert resolved.info.id == newer_id
    assert resolved.info.version == new_version


@pytest.mark.anyio
@pytest.mark.parametrize(
    ("excluded_id", "updates"),
    [
        ("gcc-99-trunk", {}),
        ("gcc-99-nightly-name", {}),
        ("gcc-99-snapshot", {}),
        ("gcc-99-experimental", {}),
        ("gcc-99-assertions", {}),
        ("gcc-99-feature-branch", {}),
        ("gcc-99-cross", {}),
        ("gcc-99", {"instruction_set": "aarch64", "name": "ARM GCC 99"}),
        ("gcc-99", {"is_nightly": True}),
        ("gcc-99", {"hidden": True}),
        ("gcc-99", {"emulated": True}),
        ("gcc-99", {"interpreted": True}),
        ("gcc-99", {"is_semver": False}),
        ("gcc-99", {"release_track": "beta"}),
        ("gcc-99", {"version": "99.0.0rc1"}),
        ("gcc-99", {"version": "not-a-version"}),
    ],
)
async def test_gcc_alias_excludes_nonstable_cross_and_malformed_candidates(
    excluded_id: str, updates: dict[str, Any]
) -> None:
    version = updates.pop("version", "99.0.0")
    client = FakeClient(
        compilers=[
            _compiler("gcc-14-stable", "14.2.0"),
            _compiler(excluded_id, version, **updates),
        ]
    )

    resolved = await Catalog(client).resolve_compiler("gcc-latest")  # type: ignore[arg-type]

    assert resolved.info.id == "gcc-14-stable"


@pytest.mark.anyio
@pytest.mark.parametrize("family", ["gcc", "clang", "msvc"])
async def test_aliases_exclude_cross_trunk_nightly_assertion_experimental_for_each_family(
    family: str,
) -> None:
    stable_versions = {"gcc": "14.2.0", "clang": "19.1.7", "msvc": "19.44.35207"}
    version = stable_versions[family]
    compilers = [
        _compiler(f"{family}-stable", version, family=family),
        _compiler(f"{family}-trunk", "99.0", family=family),
        _compiler(f"{family}-nightly", "98.0", family=family, is_nightly=True),
        _compiler(f"{family}-assertions", "97.0", family=family),
        _compiler(f"{family}-experimental", "96.0", family=family),
        _compiler(
            f"{family}-cross",
            "95.0",
            family=family,
            instruction_set="aarch64",
            name=f"AArch64 {family} cross compiler",
        ),
    ]

    resolved = await Catalog(FakeClient(compilers=compilers)).resolve_compiler(  # type: ignore[arg-type]
        f"{family}-latest"
    )

    assert resolved.info.id == f"{family}-stable"


@pytest.mark.anyio
async def test_alias_excludes_vendor_forks_even_if_they_claim_canonical_metadata() -> None:
    client = FakeClient(
        compilers=[
            _compiler("gcc-14", "14.2.0"),
            _compiler(
                "acme-gcc-99",
                "99.0.0",
                name="x86-64 Acme GCC vendor fork 99",
                categories=["gcc"],
                group="gcc86",
            ),
        ]
    )

    resolved = await Catalog(client).resolve_compiler("gcc-latest")  # type: ignore[arg-type]

    assert resolved.info.id == "gcc-14"


@pytest.mark.anyio
@pytest.mark.parametrize("family", ["gcc", "clang", "msvc"])
async def test_alias_version_ties_use_deterministic_lexical_id_tiebreak(family: str) -> None:
    version = {"gcc": "14.2.0", "clang": "19.1.7", "msvc": "19.44.35207"}[family]
    client = FakeClient(
        compilers=[
            _compiler(f"{family}-z", version, family=family),
            _compiler(f"{family}-a", version, family=family),
            _compiler(f"{family}-m", version, family=family),
        ]
    )

    resolved = await Catalog(client).resolve_compiler(f"{family}-latest")  # type: ignore[arg-type]

    assert resolved.info.id == f"{family}-a"


@pytest.mark.anyio
async def test_alias_can_use_explicit_native_name_when_group_is_noncanonical() -> None:
    candidate = _compiler(
        "gcc-native",
        "15.1.0",
        name="x86-64 GCC 15.1",
        group="custom-native-group",
    )
    resolved = await Catalog(FakeClient(compilers=[candidate])).resolve_compiler(  # type: ignore[arg-type]
        "gcc-latest"
    )
    assert resolved.info.id == "gcc-native"


@pytest.mark.anyio
async def test_unavailable_alias_error_has_sorted_bounded_family_candidates() -> None:
    compilers = [
        _compiler(
            f"gcc-cross-{index:02}",
            f"{index}.0",
            instruction_set="aarch64",
            name=f"AArch64 GCC {index}",
        )
        for index in range(14, 0, -1)
    ]

    with pytest.raises(SelectionError) as raised:
        await Catalog(FakeClient(compilers=compilers)).resolve_compiler(  # type: ignore[arg-type]
            "gcc-latest"
        )

    message = str(raised.value)
    assert "no stable native x86-64 match" in message
    assert "gcc-cross-01" in message
    assert "gcc-cross-10" in message
    assert "gcc-cross-11" not in message


@pytest.mark.anyio
async def test_unknown_compiler_requires_exact_id_or_curated_alias_with_bounded_candidates() -> (
    None
):
    compilers = [_compiler(f"gcc-14-{letter}", "14.2.0") for letter in "lkjihgfedcba"]
    catalog = Catalog(FakeClient(compilers=compilers))  # type: ignore[arg-type]

    with pytest.raises(SelectionError) as raised:
        await catalog.resolve_compiler("14")

    message = str(raised.value)
    assert "unknown exact compiler ID or alias '14'" in message
    assert "gcc-14-a" in message
    assert "gcc-14-j" in message
    assert "gcc-14-k" not in message


@pytest.mark.anyio
async def test_compiler_search_is_case_insensitive_tokenized_sorted_and_paginated() -> None:
    client = FakeClient(
        compilers=[
            _compiler("z-gcc", "12.1", name="x86-64 GCC Old", group_name="Linux Native"),
            _compiler("B-gcc", "14.2", name="x86-64 GCC New", group_name="Linux Native"),
            _compiler("a-gcc", "13.3", name="x86-64 GCC Middle", group_name="Linux Native"),
            _compiler("clang", "19.1", family="clang"),
            {"id": "bad id", "name": "malformed"},
        ]
    )
    result = await Catalog(client).search_compilers(  # type: ignore[arg-type]
        SearchCompilersRequest(query="GCC linux", offset=1, limit=1)
    )

    assert [item.id for item in result.compilers.items] == ["B-gcc"]
    assert result.compilers.page.model_dump() == {
        "offset": 1,
        "limit": 1,
        "total": 3,
        "returned": 1,
        "truncated_before": True,
        "truncated_after": True,
        "next_offset": 2,
    }
    assert result.warnings[0].code == "metadata_items_ignored"
    assert "Ignored 1" in result.warnings[0].message
    assert [alias.alias for alias in result.aliases] == list(COMPILER_ALIASES)


@pytest.mark.anyio
async def test_compiler_search_normalizes_separators_but_resolution_stays_exact() -> None:
    client = FakeClient(
        compilers=[
            _compiler("clang_trunk", "22.0", family="clang"),
            _compiler(
                "armv8-clang-trunk",
                "22.0",
                family="clang",
                instruction_set="aarch64",
            ),
        ]
    )
    catalog = Catalog(client)  # type: ignore[arg-type]

    result = await catalog.search_compilers(SearchCompilersRequest(query="clang-trunk"))
    assert [compiler.id for compiler in result.compilers.items] == [
        "armv8-clang-trunk",
        "clang_trunk",
    ]

    with pytest.raises(SelectionError) as raised:
        await catalog.resolve_compiler("clang-trunk")
    assert "Did you mean exact backend ID 'clang_trunk'?" in str(raised.value)

    assert (await catalog.resolve_compiler("clang_trunk")).info.id == "clang_trunk"


@pytest.mark.anyio
async def test_compiler_search_attaches_only_current_alias_to_resolved_item() -> None:
    client = FakeClient(
        compilers=[
            _compiler("gcc-13", "13.4.0"),
            _compiler("gcc-14", "14.2.0"),
            _compiler("clang-19", "19.1.7", family="clang"),
            _compiler("msvc-19", "19.44.35207", family="msvc"),
        ]
    )
    result = await Catalog(client).search_compilers(SearchCompilersRequest(limit=50))  # type: ignore[arg-type]
    by_id = {compiler.id: compiler for compiler in result.compilers.items}

    assert by_id["gcc-14"].aliases == ["gcc-latest"]
    assert by_id["gcc-13"].aliases == []
    assert by_id["clang-19"].aliases == ["clang-latest"]
    assert by_id["msvc-19"].aliases == ["msvc-latest"]
    assert all(alias.status == "resolved" for alias in result.aliases)


@pytest.mark.anyio
async def test_search_page_beyond_end_is_deterministic_and_explicit() -> None:
    result = await Catalog(
        FakeClient(compilers=[_compiler("gcc", "1.0")])  # type: ignore[arg-type]
    ).search_compilers(SearchCompilersRequest(offset=100, limit=7))

    assert result.compilers.items == []
    assert result.compilers.page.offset == 100
    assert result.compilers.page.limit == 7
    assert result.compilers.page.total == 1
    assert result.compilers.page.returned == 0
    assert result.compilers.page.truncated_before is True
    assert result.compilers.page.truncated_after is False
    assert result.compilers.page.next_offset is None


def test_library_metadata_normalization_flattens_versions_and_sanitizes_fields() -> None:
    raw = [
        _library(
            "fmt",
            " fmt\x00 library ",
            [
                _version("v9", "9.1.0", name="old"),
                _version("v11", "11.0.2", name="new"),
                _version("hidden", "99.0", hidden=True),
                _version("bad id", "10.0"),
                _version("missing-version", None),
                "not-an-object",  # type: ignore[list-item]
            ],
            description=" formatting\x7f library ",
            url="https://fmt.dev/docs",
        ),
        _library("bad id", "Bad", [_version("v1", "1")]),
        {"id": "noversions", "name": "No Versions", "versions": {}},
    ]

    libraries, ignored = _normalize_libraries(raw)

    assert ignored == 6
    assert [(item.info.id, item.info.version_id) for item in libraries] == [
        ("fmt", "v11"),
        ("fmt", "v9"),
    ]
    newest = libraries[0].info
    assert newest.name == "fmt library"
    assert newest.version == "11.0.2"
    assert newest.version_name == "new"
    assert newest.description == "formatting library"
    assert newest.url == "https://fmt.dev/docs"


@pytest.mark.parametrize(
    "url",
    [
        "javascript:alert(1)",
        "ftp://example.test/lib",
        "https://user:password@example.test/lib",
        "//example.test/lib",
        "not a URL",
        123,
    ],
)
def test_library_metadata_drops_unsafe_urls(url: Any) -> None:
    libraries, ignored = _normalize_libraries(
        [_library("lib", "Library", [_version("v1", "1.0")], url=url)]
    )
    assert ignored == 0
    assert libraries[0].info.url is None


@pytest.mark.anyio
async def test_library_search_is_tokenized_version_sorted_and_paginated() -> None:
    client = FakeClient(
        libraries=[
            _library(
                "fmt",
                "Formatting Library",
                [
                    _version("v9", "9.1.0", name="Legacy"),
                    _version("v10", "10.2.1", name="Current"),
                ],
                description="Fast formatting",
            ),
            _library("boost", "Boost", [_version("185", "1.85.0")]),
        ]
    )
    result = await Catalog(client).search_libraries(  # type: ignore[arg-type]
        SearchLibrariesRequest(query="FORMAT library", offset=0, limit=1)
    )

    assert [(item.id, item.version_id) for item in result.libraries.items] == [("fmt", "v10")]
    assert result.libraries.page.total == 2
    assert result.libraries.page.returned == 1
    assert result.libraries.page.truncated_after is True
    assert result.libraries.page.next_offset == 1


@pytest.mark.anyio
async def test_library_resolution_requires_exact_case_sensitive_id_and_version_pair() -> None:
    client = FakeClient(
        compilers=[_compiler("gcc", "14.2")],
        libraries=[_library("fmt", "fmt", [_version("v10", "10.2.1")])],
    )
    catalog = Catalog(client)  # type: ignore[arg-type]
    compiler = await catalog.resolve_compiler("gcc")

    exact = LibrarySelection(id="fmt", version="v10")
    assert await catalog.resolve_libraries([exact], compiler) == [exact]
    for selection in (
        LibrarySelection(id="FMT", version="v10"),
        LibrarySelection(id="fmt", version="10.2.1"),
        LibrarySelection(id="fmt", version="V10"),
    ):
        with pytest.raises(SelectionError, match="unknown exact library/version pair"):
            await catalog.resolve_libraries([selection], compiler)


@pytest.mark.anyio
async def test_library_resolution_rejects_duplicate_library_ids_even_with_different_versions() -> (
    None
):
    client = FakeClient(
        compilers=[_compiler("gcc", "14.2")],
        libraries=[
            _library(
                "fmt",
                "fmt",
                [_version("v9", "9.1"), _version("v10", "10.2")],
            )
        ],
    )
    catalog = Catalog(client)  # type: ignore[arg-type]
    compiler = await catalog.resolve_compiler("gcc")

    with pytest.raises(SelectionError, match="each library ID may be selected only once"):
        await catalog.resolve_libraries(
            [
                LibrarySelection(id="fmt", version="v9"),
                LibrarySelection(id="fmt", version="v10"),
            ],
            compiler,
        )


@pytest.mark.anyio
@pytest.mark.parametrize(
    ("allowlist", "selection", "allowed"),
    [
        (["fmt"], LibrarySelection(id="fmt", version="v10"), True),
        (["fmt.v10"], LibrarySelection(id="fmt", version="v10"), True),
        (["fmt.v9"], LibrarySelection(id="fmt", version="v10"), False),
        (["boost"], LibrarySelection(id="fmt", version="v10"), False),
    ],
)
async def test_compiler_library_allowlist_validates_id_or_exact_id_version_entry(
    allowlist: list[str], selection: LibrarySelection, allowed: bool
) -> None:
    client = FakeClient(
        compilers=[_compiler("gcc", "14.2", libraries=allowlist)],
        libraries=[_library("fmt", "fmt", [_version("v10", "10.2")])],
    )
    catalog = Catalog(client)  # type: ignore[arg-type]
    compiler = await catalog.resolve_compiler("gcc")

    if allowed:
        assert await catalog.resolve_libraries([selection], compiler) == [selection]
    else:
        with pytest.raises(SelectionError, match="is not available for compiler"):
            await catalog.resolve_libraries([selection], compiler)


@pytest.mark.anyio
async def test_explicit_empty_compiler_library_allowlist_means_all_libraries() -> None:
    client = FakeClient(
        compilers=[_compiler("gcc", "14.2", libraries=[])],
        libraries=[_library("fmt", "fmt", [_version("v10", "10.2")])],
    )
    catalog = Catalog(client)  # type: ignore[arg-type]
    compiler = await catalog.resolve_compiler("gcc")

    selection = LibrarySelection(id="fmt", version="v10")
    assert await catalog.resolve_libraries([selection], compiler) == [selection]


@pytest.mark.anyio
async def test_absent_compiler_library_allowlist_does_not_invent_restrictions() -> None:
    client = FakeClient(
        compilers=[_compiler("gcc", "14.2")],
        libraries=[_library("fmt", "fmt", [_version("v10", "10.2")])],
    )
    catalog = Catalog(client)  # type: ignore[arg-type]
    compiler = await catalog.resolve_compiler("gcc")
    selection = LibrarySelection(id="fmt", version="v10")
    assert await catalog.resolve_libraries([selection], compiler) == [selection]


def test_analyzer_metadata_recognizes_only_curated_analyzer_kinds() -> None:
    raw = [
        _tool("clangtidy", "Clang-Tidy"),
        _tool("iwyu-main", "Include What You Use"),
        _tool("llvm-mca-19", "LLVM MCA"),
        _tool("osaca", "OSACA analysis"),
        _tool("pvs", "PVS-Studio"),
        _tool("readelf", "Read ELF"),
        _tool("rust-clangtidy", "Clang Tidy", language="rust"),
        _tool("bad id", "Clang Tidy"),
        _tool("missing-name", None),
    ]

    analyzers, ignored = _normalize_analyzers(raw)

    assert ignored == 3
    assert [(item.info.id, item.info.aliases) for item in analyzers] == [
        ("clangtidy", ["clang-tidy"]),
        ("iwyu-main", ["iwyu"]),
        ("llvm-mca-19", ["llvm-mca"]),
        ("osaca", ["osaca"]),
        ("pvs", ["pvs-studio"]),
    ]
    assert [item.info.kind for item in analyzers] == ["independent"] * 5


@pytest.mark.anyio
async def test_analyzer_search_without_compiler_reports_all_aliases_and_unknown_compatibility() -> (
    None
):
    tools = [
        _tool("clangtidy", "Clang Tidy"),
        _tool("iwyu", "Include What You Use"),
        _tool("llvm-mca", "LLVM MCA"),
        _tool("osaca", "OSACA"),
        _tool("pvs", "PVS Studio"),
    ]
    result = await Catalog(FakeClient(tools=tools)).search_analyzers(  # type: ignore[arg-type]
        SearchAnalyzersRequest(limit=50)
    )

    assert [item.id for item in result.analyzers.items] == [
        "clangtidy",
        "iwyu",
        "llvm-mca",
        "osaca",
        "pvs",
    ]
    assert all(item.compiler_compatible is None for item in result.analyzers.items)
    assert result.compiler is None
    assert [alias.alias for alias in result.aliases] == list(ANALYZER_ALIASES)
    assert all(alias.status == "resolved" for alias in result.aliases)


@pytest.mark.anyio
async def test_analyzer_search_with_compiler_filters_alias_resolution_and_marks_compatibility() -> (
    None
):
    client = FakeClient(
        compilers=[
            _compiler(
                "clang-19",
                "19.1.7",
                family="clang",
                tools=["clangtidy", {"id": "llvm-mca"}],
            )
        ],
        tools=[
            _tool("clangtidy", "Clang Tidy"),
            _tool("iwyu", "Include What You Use"),
            _tool("llvm-mca", "LLVM MCA"),
        ],
    )
    result = await Catalog(client).search_analyzers(  # type: ignore[arg-type]
        SearchAnalyzersRequest(compiler="clang-latest", query="l", limit=50)
    )

    compatibility = {item.id: item.compiler_compatible for item in result.analyzers.items}
    assert compatibility == {"clangtidy": True, "iwyu": False, "llvm-mca": True}
    assert result.compiler is not None
    assert result.compiler.model_dump() == {
        "requested_selector": "clang-latest",
        "resolved_id": "clang-19",
        "name": "x86-64 Clang 19.1.7",
        "version": "19.1.7",
    }
    aliases = {alias.alias: alias for alias in result.aliases}
    assert aliases["clang-tidy"].resolved_id == "clangtidy"
    assert aliases["llvm-mca"].resolved_id == "llvm-mca"
    assert aliases["iwyu"].status == "unavailable"


@pytest.mark.anyio
async def test_analyzer_search_is_tokenized_sorted_paginated_and_warns_on_malformed_metadata() -> (
    None
):
    client = FakeClient(
        tools=[
            _tool("z-tidy", "Clang Tidy Zebra"),
            _tool("a-tidy", "Clang Tidy Alpha"),
            _tool("m-tidy", "Clang Tidy Middle"),
            _tool("bad id", "Clang Tidy Bad"),
        ]
    )
    result = await Catalog(client).search_analyzers(  # type: ignore[arg-type]
        SearchAnalyzersRequest(query="CLANG tidy", offset=1, limit=1)
    )

    assert [item.id for item in result.analyzers.items] == ["m-tidy"]
    assert result.analyzers.page.total == 3
    assert result.analyzers.page.truncated_before is True
    assert result.analyzers.page.truncated_after is True
    assert result.analyzers.page.next_offset == 2
    assert result.warnings[0].code == "metadata_items_ignored"


@pytest.mark.anyio
async def test_exact_analyzer_id_precedes_alias_resolution() -> None:
    client = FakeClient(
        compilers=[_compiler("clang", "19.1", family="clang", tools=["clang-tidy", "other-tidy"])],
        tools=[
            _tool("clang-tidy", "Clang Tidy Exact ID"),
            _tool("other-tidy", "Clang Tidy Other"),
        ],
    )
    catalog = Catalog(client)  # type: ignore[arg-type]
    compiler = await catalog.resolve_compiler("clang")

    resolved = await catalog.resolve_analyzers(
        [AnalyzerSelection(id="clang-tidy", arguments=["--checks=bugprone-*"])], compiler
    )

    assert len(resolved) == 1
    assert resolved[0].requested_selector == "clang-tidy"
    assert resolved[0].id == "clang-tidy"
    assert resolved[0].name == "Clang Tidy Exact ID"
    assert resolved[0].arguments == ("--checks=bugprone-*",)
    assert resolved[0].as_selection() == AnalyzerSelection(
        id="clang-tidy", arguments=["--checks=bugprone-*"]
    )


@pytest.mark.anyio
async def test_analyzer_alias_reporting_matches_exact_id_precedence() -> None:
    client = FakeClient(
        compilers=[_compiler("clang", "19.1", family="clang", tools=["iwyu", "iwyu022"])],
        tools=[
            _tool("iwyu", "Include What You Use 0.12"),
            _tool("iwyu022", "Include What You Use 0.22"),
        ],
    )
    catalog = Catalog(client)  # type: ignore[arg-type]

    result = await catalog.search_analyzers(SearchAnalyzersRequest(compiler="clang"))
    iwyu = next(alias for alias in result.aliases if alias.alias == "iwyu")
    assert iwyu.status == "resolved"
    assert iwyu.resolved_id == "iwyu"

    compiler = await catalog.resolve_compiler("clang")
    resolved = await catalog.resolve_analyzers([AnalyzerSelection(id="iwyu")], compiler)
    assert resolved[0].id == "iwyu"


@pytest.mark.anyio
@pytest.mark.parametrize(
    ("alias", "tool_id", "name"),
    [
        ("clang-tidy", "clangtidy", "Clang Tidy"),
        ("iwyu", "iwyu", "Include What You Use"),
        ("llvm-mca", "llvm-mca", "LLVM MCA"),
        ("osaca", "osaca", "OSACA"),
        ("pvs-studio", "pvs", "PVS-Studio"),
    ],
)
async def test_each_curated_analyzer_alias_resolves_to_exact_compatible_backend_id(
    alias: str, tool_id: str, name: str
) -> None:
    client = FakeClient(
        compilers=[_compiler("gcc", "14.2", tools=[tool_id])],
        tools=[_tool(tool_id, name)],
    )
    catalog = Catalog(client)  # type: ignore[arg-type]
    compiler = await catalog.resolve_compiler("gcc")

    resolved = await catalog.resolve_analyzers([AnalyzerSelection(id=alias)], compiler)

    assert [(item.requested_selector, item.id, item.name) for item in resolved] == [
        (alias, tool_id, name)
    ]


@pytest.mark.anyio
async def test_analyzer_alias_ambiguity_is_deterministic_actionable_and_compiler_scoped() -> None:
    tools = [
        _tool("z-tidy", "Clang Tidy Z"),
        _tool("a-tidy", "Clang Tidy A"),
        _tool("incompatible-tidy", "Clang Tidy Incompatible"),
    ]
    client = FakeClient(
        compilers=[_compiler("clang", "19.1", family="clang", tools=["z-tidy", "a-tidy"])],
        tools=tools,
    )
    catalog = Catalog(client)  # type: ignore[arg-type]
    compiler = await catalog.resolve_compiler("clang")

    search = await catalog.search_analyzers(
        SearchAnalyzersRequest(compiler="clang", query="clang-tidy", limit=50)
    )
    clang_tidy = next(alias for alias in search.aliases if alias.alias == "clang-tidy")
    assert clang_tidy.status == "ambiguous"
    assert clang_tidy.candidates == ["a-tidy", "z-tidy"]

    with pytest.raises(SelectionError) as raised:
        await catalog.resolve_analyzers([AnalyzerSelection(id="clang-tidy")], compiler)
    message = str(raised.value)
    assert "ambiguous for compiler 'clang'" in message
    assert "a-tidy, z-tidy" in message
    assert "incompatible-tidy" not in message


@pytest.mark.anyio
async def test_exact_analyzer_must_be_available_for_selected_compiler() -> None:
    client = FakeClient(
        compilers=[_compiler("gcc", "14.2", tools=[])],
        tools=[_tool("clangtidy", "Clang Tidy")],
    )
    catalog = Catalog(client)  # type: ignore[arg-type]
    compiler = await catalog.resolve_compiler("gcc")

    with pytest.raises(SelectionError, match="is not available for compiler 'gcc'"):
        await catalog.resolve_analyzers([AnalyzerSelection(id="clangtidy")], compiler)


@pytest.mark.anyio
async def test_unavailable_analyzer_alias_is_distinct_from_unknown_selector() -> None:
    client = FakeClient(
        compilers=[_compiler("gcc", "14.2", tools=[])],
        tools=[_tool("clangtidy", "Clang Tidy")],
    )
    catalog = Catalog(client)  # type: ignore[arg-type]
    compiler = await catalog.resolve_compiler("gcc")

    with pytest.raises(SelectionError, match="alias 'clang-tidy' is unavailable"):
        await catalog.resolve_analyzers([AnalyzerSelection(id="clang-tidy")], compiler)
    with pytest.raises(SelectionError, match="unknown exact analyzer ID or alias 'unknown'"):
        await catalog.resolve_analyzers([AnalyzerSelection(id="unknown")], compiler)


@pytest.mark.anyio
async def test_duplicate_exact_analyzer_metadata_is_rejected_as_ambiguous() -> None:
    client = FakeClient(
        compilers=[_compiler("gcc", "14.2", tools=["tidy"])],
        tools=[_tool("tidy", "Clang Tidy One"), _tool("tidy", "Clang Tidy Two")],
    )
    catalog = Catalog(client)  # type: ignore[arg-type]
    compiler = await catalog.resolve_compiler("gcc")

    with pytest.raises(SelectionError, match="analyzer ID 'tidy' is ambiguous"):
        await catalog.resolve_analyzers([AnalyzerSelection(id="tidy")], compiler)


@pytest.mark.anyio
async def test_selections_that_resolve_to_same_backend_analyzer_are_rejected() -> None:
    client = FakeClient(
        compilers=[_compiler("gcc", "14.2", tools=["tidy"])],
        tools=[_tool("tidy", "Clang Tidy")],
    )
    catalog = Catalog(client)  # type: ignore[arg-type]
    compiler = await catalog.resolve_compiler("gcc")

    with pytest.raises(SelectionError, match="duplicate backend tool IDs"):
        await catalog.resolve_analyzers(
            [AnalyzerSelection(id="tidy"), AnalyzerSelection(id="clang-tidy")], compiler
        )


@pytest.mark.anyio
async def test_compiler_identity_preserves_requested_selector_and_exact_metadata() -> None:
    client = FakeClient(compilers=[_compiler("gcc-14", "14.2.0", name="GNU GCC 14")])
    catalog = Catalog(client)  # type: ignore[arg-type]
    compiler = await catalog.resolve_compiler("gcc-latest")

    identity = catalog.compiler_identity("gcc-latest", compiler)

    assert identity.model_dump() == {
        "requested_selector": "gcc-latest",
        "resolved_id": "gcc-14",
        "name": "GNU GCC 14",
        "version": "14.2.0",
    }
