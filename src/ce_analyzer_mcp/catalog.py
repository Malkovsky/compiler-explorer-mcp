from __future__ import annotations

import re
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from typing import Any, Final, TypeVar
from urllib.parse import urlsplit

from packaging.version import InvalidVersion, Version

from ce_analyzer_mcp.client import CompilerExplorerClient
from ce_analyzer_mcp.errors import SelectionError
from ce_analyzer_mcp.models import (
    AliasResolution,
    AnalyzerInfo,
    AnalyzerSearchResult,
    AnalyzerSelection,
    CompilerIdentity,
    CompilerInfo,
    CompilerSearchResult,
    LibraryInfo,
    LibrarySearchResult,
    LibrarySelection,
    Page,
    PageInfo,
    SearchAnalyzersRequest,
    SearchCompilersRequest,
    SearchLibrariesRequest,
    WarningItem,
)

COMPILER_ALIASES: Final = ("gcc-latest", "clang-latest", "msvc-latest")
ANALYZER_ALIASES: Final = (
    "clang-tidy",
    "iwyu",
    "llvm-mca",
    "osaca",
    "pvs-studio",
)

_IDENTIFIER_RE: Final = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+:/-]{0,127}$")
_CONTROL_RE: Final = re.compile(r"[\x00-\x1f\x7f-\x9f]")
_NON_ALNUM_RE: Final = re.compile(r"[^a-z0-9]+")
_EXCLUDED_ALIAS_TERMS: Final = (
    "trunk",
    "nightly",
    "snapshot",
    "experimental",
    "assertion",
    "assertions",
    "feature branch",
    "feature-branch",
    "prerelease",
    "vendor",
    " fork",
    "cross",
    "aarch",
    "arm64",
    "armv",
    "riscv",
    "powerpc",
    "ppc",
    "wasm",
    "mingw",
    "nvptx",
    "amdgpu",
)
_X86_64_INSTRUCTION_SETS: Final = frozenset({"amd64", "x86-64", "x86_64"})
_CANONICAL_GROUPS: Final = {
    "gcc": frozenset({"gcc86", "gcc_x86_64"}),
    "clang": frozenset({"clang", "clang_x86_64"}),
    "msvc": frozenset({"vcpp_x64", "msvc_x64"}),
}

U = TypeVar("U")


@dataclass(frozen=True)
class CatalogCompiler:
    info: CompilerInfo
    group: str
    group_name: str
    compiler_type: str
    categories: frozenset[str]
    language: str
    stable_version: Version | None
    release_track: str | None
    is_semver: bool | None
    is_nightly: bool | None
    hidden: bool | None
    emulated: bool | None
    interpreted: bool | None
    tools: frozenset[str]
    library_allowlist: frozenset[str] | None


@dataclass(frozen=True)
class CatalogLibrary:
    info: LibraryInfo


@dataclass(frozen=True)
class CatalogAnalyzer:
    info: AnalyzerInfo


@dataclass(frozen=True)
class ResolvedAnalyzer:
    requested_selector: str
    id: str
    name: str
    arguments: tuple[str, ...]

    def as_selection(self) -> AnalyzerSelection:
        return AnalyzerSelection(id=self.id, arguments=list(self.arguments))


def _string(value: Any, *, maximum: int = 300) -> str | None:
    if not isinstance(value, str):
        return None
    clean = _CONTROL_RE.sub("", value).strip()
    if not clean:
        return None
    return clean[:maximum]


def _identifier(value: Any) -> str | None:
    text = _string(value, maximum=128)
    if text is None or not _IDENTIFIER_RE.fullmatch(text):
        return None
    return text


def _optional_bool(value: Any) -> bool | None:
    return value if isinstance(value, bool) else None


def _string_set(value: Any) -> frozenset[str]:
    if isinstance(value, list):
        values: set[str] = set()
        for item in value:
            candidate = item.get("id") if isinstance(item, dict) else item
            if (text := _identifier(candidate)) is not None:
                values.add(text)
        return frozenset(values)
    if isinstance(value, dict):
        return frozenset(text for item in value if (text := _identifier(item)) is not None)
    return frozenset()


def _family(
    categories: frozenset[str],
    compiler_type: str,
    group: str,
    name: str,
) -> str:
    lowered_categories = {category.casefold() for category in categories}
    if "msvc" in lowered_categories:
        return "msvc"
    if "clang" in lowered_categories:
        return "clang"
    if "gcc" in lowered_categories:
        return "gcc"
    combined = f"{compiler_type} {group} {name}".casefold()
    if "win32-vc" in combined or "msvc" in combined or group.casefold().startswith("vcpp"):
        return "msvc"
    if "clang" in combined:
        return "clang"
    if re.search(r"(?:^|[^a-z])gcc(?:[^a-z]|$)", combined) or group.casefold().startswith("gcc"):
        return "gcc"
    return "other"


def _version(value: str) -> Version | None:
    try:
        parsed = Version(value)
    except InvalidVersion:
        return None
    if parsed.is_prerelease or parsed.is_devrelease or parsed.local is not None:
        return None
    return parsed


def _safe_url(value: Any) -> str | None:
    text = _string(value, maximum=2048)
    if text is None:
        return None
    parsed = urlsplit(text)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        return None
    if parsed.username is not None or parsed.password is not None:
        return None
    return text


def _normalize_compilers(raw: Sequence[dict[str, Any]]) -> tuple[list[CatalogCompiler], int]:
    compilers: list[CatalogCompiler] = []
    ignored = 0
    for item in raw:
        compiler_id = _identifier(item.get("id"))
        name = _string(item.get("name"))
        if compiler_id is None or name is None:
            ignored += 1
            continue
        language = _string(item.get("lang")) or "c++"
        if language.casefold() not in {"c++", "cpp"}:
            ignored += 1
            continue
        compiler_type = _string(item.get("compilerType")) or ""
        group = _string(item.get("group")) or ""
        group_name = _string(item.get("groupName")) or ""
        categories = _string_set(item.get("compilerCategories"))
        family = _family(categories, compiler_type, group, name)
        version_text = _string(item.get("semver"), maximum=100) or ""
        tools = _string_set(item.get("tools"))
        raw_libraries = item.get("libsArr")
        if isinstance(raw_libraries, list) and raw_libraries:
            library_allowlist: frozenset[str] | None = _string_set(raw_libraries)
        else:
            library_allowlist = None
        release_track = _string(item.get("releaseTrack"), maximum=80)
        instruction_set = _string(item.get("instructionSet"), maximum=80)
        info = CompilerInfo(
            id=compiler_id,
            name=name,
            family=family,  # type: ignore[arg-type]
            version=version_text,
            instruction_set=instruction_set,
            release_track=release_track,
            supports_optimization_output=_optional_bool(item.get("supportsOptOutput")),
        )
        compilers.append(
            CatalogCompiler(
                info=info,
                group=group,
                group_name=group_name,
                compiler_type=compiler_type,
                categories=categories,
                language=language,
                stable_version=_version(version_text),
                release_track=release_track,
                is_semver=_optional_bool(item.get("isSemVer")),
                is_nightly=_optional_bool(item.get("isNightly")),
                hidden=_optional_bool(item.get("hidden")),
                emulated=_optional_bool(item.get("emulated")),
                interpreted=_optional_bool(item.get("interpreted")),
                tools=tools,
                library_allowlist=library_allowlist,
            )
        )
    return compilers, ignored


def _is_native_stable(compiler: CatalogCompiler, family: str) -> bool:
    if compiler.info.family != family or compiler.stable_version is None:
        return False
    if compiler.hidden is True or compiler.is_nightly is True:
        return False
    if compiler.emulated is True or compiler.interpreted is True:
        return False
    if compiler.is_semver is False:
        return False
    if compiler.release_track is not None and compiler.release_track.casefold() != "stable":
        return False
    instruction_set = (compiler.info.instruction_set or "").casefold()
    if instruction_set not in _X86_64_INSTRUCTION_SETS:
        return False
    combined = " ".join(
        (
            compiler.info.id,
            compiler.info.name,
            compiler.group,
            compiler.group_name,
            compiler.compiler_type,
        )
    ).casefold()
    if any(term in combined for term in _EXCLUDED_ALIAS_TERMS):
        return False
    group = compiler.group.casefold()
    name = compiler.info.name.casefold()
    if family == "msvc":
        canonical_name = name.startswith(("x64 msvc ", "x86-64 msvc "))
    else:
        canonical_name = name.startswith(f"x86-64 {family} ")
    return group in _CANONICAL_GROUPS[family] or canonical_name


def _resolve_compiler_alias(
    alias: str,
    compilers: Sequence[CatalogCompiler],
) -> CatalogCompiler | None:
    family = alias.removesuffix("-latest")
    candidates = [compiler for compiler in compilers if _is_native_stable(compiler, family)]
    candidates.sort(key=lambda compiler: compiler.info.id.casefold())
    candidates.sort(key=lambda compiler: compiler.stable_version or Version("0"), reverse=True)
    return candidates[0] if candidates else None


def _compiler_aliases(compilers: Sequence[CatalogCompiler]) -> list[AliasResolution]:
    resolutions: list[AliasResolution] = []
    for alias in COMPILER_ALIASES:
        resolved = _resolve_compiler_alias(alias, compilers)
        if resolved is None:
            family = alias.removesuffix("-latest")
            candidates = sorted(
                (compiler.info.id for compiler in compilers if compiler.info.family == family),
                key=str.casefold,
            )[:10]
            resolutions.append(
                AliasResolution(alias=alias, status="unavailable", candidates=candidates)
            )
        else:
            resolutions.append(
                AliasResolution(
                    alias=alias,
                    status="resolved",
                    resolved_id=resolved.info.id,
                    resolved_name=resolved.info.name,
                )
            )
    return resolutions


def _normalize_libraries(raw: Sequence[dict[str, Any]]) -> tuple[list[CatalogLibrary], int]:
    libraries: list[CatalogLibrary] = []
    ignored = 0
    for item in raw:
        library_id = _identifier(item.get("id"))
        if library_id is None:
            ignored += 1
            continue
        name = _string(item.get("name")) or library_id
        description = _string(item.get("description"), maximum=1000)
        url = _safe_url(item.get("url"))
        versions = item.get("versions")
        if not isinstance(versions, list):
            ignored += 1
            continue
        normalized_versions: list[tuple[Version | None, CatalogLibrary]] = []
        for version_item in versions:
            if not isinstance(version_item, dict) or version_item.get("hidden") is True:
                ignored += 1
                continue
            version_id = _identifier(version_item.get("id"))
            version_text = _string(version_item.get("version"), maximum=100)
            if version_id is None or version_text is None:
                ignored += 1
                continue
            info = LibraryInfo(
                id=library_id,
                name=name,
                version_id=version_id,
                version=version_text,
                version_name=_string(version_item.get("name")),
                description=description,
                url=url,
            )
            normalized_versions.append((_version(version_text), CatalogLibrary(info=info)))
        normalized_versions.sort(
            key=lambda pair: (
                pair[0] is not None,
                pair[0] or Version("0"),
                pair[1].info.version_id,
            ),
            reverse=True,
        )
        libraries.extend(library for _, library in normalized_versions)
    libraries.sort(key=lambda library: (library.info.id.casefold(), library.info.name.casefold()))
    return libraries, ignored


def _tool_aliases(tool_id: str, name: str) -> tuple[str, ...]:
    normalized_id = _NON_ALNUM_RE.sub("", tool_id.casefold())
    normalized_name = _NON_ALNUM_RE.sub("", name.casefold())
    combined = f"{normalized_id} {normalized_name}"
    aliases: list[str] = []
    if "clangtidy" in combined:
        aliases.append("clang-tidy")
    if normalized_id.startswith("iwyu") or "includewhatyouuse" in combined:
        aliases.append("iwyu")
    if "llvmmca" in combined:
        aliases.append("llvm-mca")
    if "osaca" in combined:
        aliases.append("osaca")
    if "pvsstudio" in combined:
        aliases.append("pvs-studio")
    return tuple(aliases)


def _normalize_analyzers(raw: Sequence[dict[str, Any]]) -> tuple[list[CatalogAnalyzer], int]:
    analyzers: list[CatalogAnalyzer] = []
    ignored = 0
    for item in raw:
        analyzer_id = _identifier(item.get("id"))
        name = _string(item.get("name"))
        language = _string(item.get("languageId"), maximum=40)
        if analyzer_id is None or name is None or (language and language.casefold() != "c++"):
            ignored += 1
            continue
        aliases = _tool_aliases(analyzer_id, name)
        if not aliases:
            continue
        analyzers.append(
            CatalogAnalyzer(
                info=AnalyzerInfo(
                    id=analyzer_id,
                    name=name,
                    kind=_string(item.get("type"), maximum=80),
                    aliases=list(aliases),
                )
            )
        )
    analyzers.sort(
        key=lambda analyzer: (analyzer.info.id.casefold(), analyzer.info.name.casefold())
    )
    return analyzers, ignored


def _matches(query: str, fields: Iterable[str | None]) -> bool:
    tokens = _NON_ALNUM_RE.sub(" ", query.casefold()).split()
    if not tokens:
        return True
    haystack = _NON_ALNUM_RE.sub(
        " ",
        " ".join(field for field in fields if field).casefold(),
    )
    return all(token in haystack for token in tokens)


def _normalized_identifier(value: str) -> str:
    return _NON_ALNUM_RE.sub("", value.casefold())


def _page(items: Sequence[U], offset: int, limit: int) -> Page[U]:
    total = len(items)
    selected = list(items[offset : offset + limit])
    returned = len(selected)
    return Page[U](
        items=selected,
        page=PageInfo(
            offset=offset,
            limit=limit,
            total=total,
            returned=returned,
            truncated_before=offset > 0 and total > 0,
            truncated_after=offset + returned < total,
            next_offset=offset + returned if offset + returned < total else None,
        ),
    )


def _metadata_warning(ignored: int) -> list[WarningItem]:
    if not ignored:
        return []
    return [
        WarningItem(
            code="metadata_items_ignored",
            message=f"Ignored {ignored} malformed or unsupported metadata entries.",
        )
    ]


def _identity(requested: str, compiler: CatalogCompiler) -> CompilerIdentity:
    return CompilerIdentity(
        requested_selector=requested,
        resolved_id=compiler.info.id,
        name=compiler.info.name,
        version=compiler.info.version,
    )


class Catalog:
    def __init__(self, client: CompilerExplorerClient) -> None:
        self._client = client

    async def _compilers(self) -> tuple[list[CatalogCompiler], int]:
        return _normalize_compilers(await self._client.get_compilers())

    async def search_compilers(self, request: SearchCompilersRequest) -> CompilerSearchResult:
        compilers, ignored = await self._compilers()
        aliases = _compiler_aliases(compilers)
        aliases_by_id: dict[str, list[str]] = {}
        for resolution in aliases:
            if resolution.resolved_id is not None:
                aliases_by_id.setdefault(resolution.resolved_id, []).append(resolution.alias)
        matching = [
            compiler.info.model_copy(
                update={"aliases": sorted(aliases_by_id.get(compiler.info.id, []))}
            )
            for compiler in compilers
            if _matches(
                request.query,
                (
                    compiler.info.id,
                    compiler.info.name,
                    compiler.info.family,
                    compiler.info.version,
                    compiler.info.instruction_set,
                    compiler.group_name,
                ),
            )
        ]
        matching.sort(key=lambda compiler: (compiler.id.casefold(), compiler.name.casefold()))
        return CompilerSearchResult(
            compilers=_page(matching, request.offset, request.limit),
            aliases=aliases,
            warnings=_metadata_warning(ignored),
        )

    async def resolve_compiler(self, selector: str) -> CatalogCompiler:
        compilers, _ = await self._compilers()
        exact = [compiler for compiler in compilers if compiler.info.id == selector]
        if len(exact) == 1:
            return exact[0]
        if len(exact) > 1:
            raise SelectionError(f"compiler ID {selector!r} is ambiguous in backend metadata")
        if selector in COMPILER_ALIASES:
            resolved = _resolve_compiler_alias(selector, compilers)
            if resolved is not None:
                return resolved
            family = selector.removesuffix("-latest")
            candidates = sorted(
                (compiler.info.id for compiler in compilers if compiler.info.family == family),
                key=str.casefold,
            )[:10]
            suffix = f" Candidates: {', '.join(candidates)}." if candidates else ""
            raise SelectionError(
                f"compiler alias {selector!r} has no stable native x86-64 match.{suffix}"
            )
        normalized_selector = _normalized_identifier(selector)
        candidates = [
            compiler.info.id
            for compiler in compilers
            if _matches(selector, (compiler.info.id, compiler.info.name))
        ]
        candidates.sort(
            key=lambda compiler_id: (
                _normalized_identifier(compiler_id) != normalized_selector,
                compiler_id.casefold(),
            )
        )
        candidates = candidates[:10]
        normalized_exact = [
            compiler_id
            for compiler_id in candidates
            if _normalized_identifier(compiler_id) == normalized_selector
        ]
        suggestion = (
            f" Did you mean exact backend ID {normalized_exact[0]!r}?"
            if len(normalized_exact) == 1
            else ""
        )
        suffix = f" Candidates: {', '.join(candidates)}." if candidates else ""
        raise SelectionError(
            f"unknown exact compiler ID or alias {selector!r}.{suggestion}{suffix}"
        )

    async def search_libraries(self, request: SearchLibrariesRequest) -> LibrarySearchResult:
        libraries, ignored = _normalize_libraries(await self._client.get_libraries())
        matching = [
            library.info
            for library in libraries
            if _matches(
                request.query,
                (
                    library.info.id,
                    library.info.name,
                    library.info.version_id,
                    library.info.version,
                    library.info.version_name,
                    library.info.description,
                ),
            )
        ]
        return LibrarySearchResult(
            libraries=_page(matching, request.offset, request.limit),
            warnings=_metadata_warning(ignored),
        )

    async def resolve_libraries(
        self,
        selections: Sequence[LibrarySelection],
        compiler: CatalogCompiler,
    ) -> list[LibrarySelection]:
        if len({selection.id for selection in selections}) != len(selections):
            raise SelectionError("each library ID may be selected only once")
        libraries, _ = _normalize_libraries(await self._client.get_libraries())
        known = {(library.info.id, library.info.version_id) for library in libraries}
        resolved: list[LibrarySelection] = []
        for selection in selections:
            pair = (selection.id, selection.version)
            if pair not in known:
                raise SelectionError(
                    f"unknown exact library/version pair {selection.id!r}/{selection.version!r}"
                )
            allowlist = compiler.library_allowlist
            if allowlist is not None and not (
                selection.id in allowlist or f"{selection.id}.{selection.version}" in allowlist
            ):
                raise SelectionError(
                    f"library {selection.id!r}/{selection.version!r} is not available for "
                    f"compiler {compiler.info.id!r}"
                )
            resolved.append(selection)
        return resolved

    async def _analyzers(self) -> tuple[list[CatalogAnalyzer], int]:
        return _normalize_analyzers(await self._client.get_tools())

    @staticmethod
    def _analyzer_alias_resolutions(
        analyzers: Sequence[CatalogAnalyzer],
        compatible_ids: frozenset[str] | None = None,
    ) -> list[AliasResolution]:
        resolutions: list[AliasResolution] = []
        for alias in ANALYZER_ALIASES:
            exact = [
                analyzer
                for analyzer in analyzers
                if analyzer.info.id == alias
                and (compatible_ids is None or analyzer.info.id in compatible_ids)
            ]
            known_exact = any(analyzer.info.id == alias for analyzer in analyzers)
            if len(exact) == 1:
                resolutions.append(
                    AliasResolution(
                        alias=alias,
                        status="resolved",
                        resolved_id=exact[0].info.id,
                        resolved_name=exact[0].info.name,
                    )
                )
                continue
            if len(exact) > 1:
                resolutions.append(
                    AliasResolution(
                        alias=alias,
                        status="ambiguous",
                        candidates=[candidate.info.id for candidate in exact[:10]],
                    )
                )
                continue
            if known_exact:
                resolutions.append(AliasResolution(alias=alias, status="unavailable"))
                continue
            candidates = [
                analyzer
                for analyzer in analyzers
                if alias in analyzer.info.aliases
                and (compatible_ids is None or analyzer.info.id in compatible_ids)
            ]
            if len(candidates) == 1:
                resolutions.append(
                    AliasResolution(
                        alias=alias,
                        status="resolved",
                        resolved_id=candidates[0].info.id,
                        resolved_name=candidates[0].info.name,
                    )
                )
            elif candidates:
                resolutions.append(
                    AliasResolution(
                        alias=alias,
                        status="ambiguous",
                        candidates=[candidate.info.id for candidate in candidates[:10]],
                    )
                )
            else:
                resolutions.append(AliasResolution(alias=alias, status="unavailable"))
        return resolutions

    async def search_analyzers(self, request: SearchAnalyzersRequest) -> AnalyzerSearchResult:
        analyzers, ignored = await self._analyzers()
        compiler: CatalogCompiler | None = None
        compatible_ids: frozenset[str] | None = None
        if request.compiler is not None:
            compiler = await self.resolve_compiler(request.compiler)
            compatible_ids = compiler.tools
        matching: list[AnalyzerInfo] = []
        for analyzer in analyzers:
            if not _matches(
                request.query,
                (analyzer.info.id, analyzer.info.name, *analyzer.info.aliases),
            ):
                continue
            compatible = None if compatible_ids is None else analyzer.info.id in compatible_ids
            matching.append(analyzer.info.model_copy(update={"compiler_compatible": compatible}))
        return AnalyzerSearchResult(
            analyzers=_page(matching, request.offset, request.limit),
            aliases=self._analyzer_alias_resolutions(analyzers, compatible_ids),
            compiler=_identity(request.compiler, compiler)
            if request.compiler is not None and compiler is not None
            else None,
            warnings=_metadata_warning(ignored),
        )

    async def resolve_analyzers(
        self,
        selections: Sequence[AnalyzerSelection],
        compiler: CatalogCompiler,
    ) -> list[ResolvedAnalyzer]:
        analyzers, _ = await self._analyzers()
        resolved: list[ResolvedAnalyzer] = []
        for selection in selections:
            exact = [analyzer for analyzer in analyzers if analyzer.info.id == selection.id]
            if len(exact) == 1:
                analyzer = exact[0]
            elif len(exact) > 1:
                raise SelectionError(
                    f"analyzer ID {selection.id!r} is ambiguous in backend metadata"
                )
            elif selection.id in ANALYZER_ALIASES:
                candidates = [
                    candidate
                    for candidate in analyzers
                    if selection.id in candidate.info.aliases
                    and candidate.info.id in compiler.tools
                ]
                if len(candidates) != 1:
                    candidate_ids = [candidate.info.id for candidate in candidates[:10]]
                    detail = f" Candidates: {', '.join(candidate_ids)}." if candidate_ids else ""
                    state = "ambiguous" if candidates else "unavailable"
                    raise SelectionError(
                        f"analyzer alias {selection.id!r} is {state} for compiler "
                        f"{compiler.info.id!r}.{detail}"
                    )
                analyzer = candidates[0]
            else:
                raise SelectionError(f"unknown exact analyzer ID or alias {selection.id!r}")
            if analyzer.info.id not in compiler.tools:
                raise SelectionError(
                    f"analyzer {analyzer.info.id!r} is not available for compiler "
                    f"{compiler.info.id!r}"
                )
            resolved.append(
                ResolvedAnalyzer(
                    requested_selector=selection.id,
                    id=analyzer.info.id,
                    name=analyzer.info.name,
                    arguments=tuple(selection.arguments),
                )
            )
        ids = [analyzer.id for analyzer in resolved]
        if len(ids) != len(set(ids)):
            raise SelectionError("analyzer selections resolve to duplicate backend tool IDs")
        return resolved

    @staticmethod
    def compiler_identity(requested: str, compiler: CatalogCompiler) -> CompilerIdentity:
        return _identity(requested, compiler)
