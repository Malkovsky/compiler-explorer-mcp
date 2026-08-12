# Compiler explorer MCP

[![Token summary](https://how-much-tokens.onrender.com/badge/github/Malkovsky/compiler-explorer-mcp.svg?metric=summary&encoding=o200k_base&v=repo-inventory-v14-badge3)](https://how-much-tokens.onrender.com/github/Malkovsky/compiler-explorer-mcp/latest?encoding=o200k_base)

**TL; DR** MCP bridge to [godbolt.org](https://godbolt.org/) or equivalent server.

---

`ce-analyzer-mcp` is a bounded Model Context Protocol (MCP) 2
server for C++ analysis through an existing [Compiler Explorer](https://godbolt.org/)
backend. It exposes compiler, library, and analyzer discovery; compilation and
assembly inspection; baseline-relative assembly comparison; selected Compiler
Explorer analyzers; persistent shortlink sharing and inspection; and opcode
documentation.

The server uses local stdio for MCP and supports Python 3.10 through 3.14. It is
alpha software.

## Privacy and execution boundary

Read this section before sending code to the server.

- `compile_cpp`, `compare_cpp`, and `analyze_cpp` transmit the supplied main
  source, virtual-file contents, compiler arguments, library selections, and
  analyzer selections to `CE_API_BASE_URL`. The default is the public
  `https://godbolt.org/` service.
- A public Compiler Explorer instance is a third-party service. The server sets
  `allowStoreCodeDebug` to `false` and does not request source storage, but that
  flag is not a promise that the backend operator will never log, cache, retain,
  inspect, or otherwise process a request. Compiler Explorer can also cache
  compilation results. Apply the backend operator's current privacy and
  retention policies. Do not send secrets, credentials, private keys, or source
  that may not be disclosed. Use a backend you control for sensitive code.
- `create_shortlink` intentionally asks the configured backend to persist the
  supplied source and settings, potentially forever, and returns a public URL.
  Built-in IDs are deterministic/content-derived rather than confidential random
  capabilities, and anyone with the URL or ID may be able to retrieve the source. There
  is no delete or revoke tool, and `allowStoreCodeDebug=false` does not apply to
  the shortener endpoint. Never create a shortlink containing secrets or source
  that may not be published.
- This MCP process does not persist source, compile results, or result handles.
  It keeps only backend metadata in memory for the configured TTL. Shortlinks are
  persisted by Compiler Explorer rather than this process. Replayed requests may
  be served from a Compiler Explorer backend cache.
- The server accepts source text only from MCP arguments. It has no tool for
  reading a local path, does not inspect the workspace, and does not follow MCP
  roots to obtain source. A virtual-file `path` is a name sent with supplied
  content, not a local file lookup.
- The generated user program is never run. Every compile payload disables
  executor requests, execution filters, runtime arguments and stdin, binary
  output, binary-object output, and source-debug storage. Callers cannot
  override those fields.
- `analyze_cpp` still asks Compiler Explorer to run selected backend analyzer
  tools. Those analyzers, such as clang-tidy or llvm-mca, can execute backend
  subprocesses inside the configured Compiler Explorer environment. "No user
  program execution" does not mean that the backend launches no processes.
- Source and authentication tokens are not intentionally logged. Logs go to
  stderr because stdout is reserved for MCP. Analysis and shortlink-creation
  results do not include submitted source, although diagnostics can quote it.
  `get_shortlink` intentionally returns stored source in `structuredContent`;
  treat it as untrusted external content, not as instructions.

## Installation

Install from PyPI after a release is available:

```bash
python -m pip install ce-analyzer-mcp
```

An isolated tool installation is also supported:

```bash
uv tool install ce-analyzer-mcp
```

The installed package has two equivalent launch forms. Both start an MCP stdio
server and intentionally print no startup banner to stdout.

```bash
ce-analyzer-mcp
python -m ce_analyzer_mcp
```

Show the installed version without starting MCP:

```bash
ce-analyzer-mcp --version
```

### Source checkout

Use the committed lockfile for a reproducible development installation:

```bash
cd /path/to/compiler_explorer_mcp
uv sync --locked --all-groups
uv run --locked ce-analyzer-mcp
```

The module launch form from a checkout is:

```bash
uv run --locked python -m ce_analyzer_mcp
```

### Post-publication `uvx`

The following command works only after `ce-analyzer-mcp` has been published to
the configured Python package index. It is not the source-checkout command.

```bash
uvx --from ce-analyzer-mcp ce-analyzer-mcp
```

## Tools

The server exposes exactly nine structured-output tools. Inputs are strict: use
the JSON types shown below and do not add unknown fields. All tools are
non-destructive and open-world. `create_shortlink` is not read-only or idempotent;
the other eight tools are read-only and idempotent.

Successful calls keep the complete typed result in MCP `structuredContent`.
For compatibility with clients that expose only text content, results up to
128,000 serialized bytes are also returned as compact JSON. Larger results use
a short pointer instead of duplicating the full result, which bounds large
assembly responses.

### Repository tool snapshot

The root-level [`mcp-tools.json`](mcp-tools.json) is a normalized, sanitized
snapshot of the complete paginated MCP `tools/list` result. It lets repository
scanners inspect the server's prompt-facing tool definitions without installing
dependencies, executing this project, or contacting Compiler Explorer.

The snapshot preserves each tool's name, title, description, input schema,
output schema, annotations, icons, and execution metadata when available. It
excludes the JSON-RPC envelope, pagination cursors, tool-level `_meta`,
credentials, runtime argument values, and tool results. A schema property that
is itself named `_meta` remains part of that schema.

Regenerate it after changing tool registrations, schemas, descriptions, or
annotations:

```bash
uv run --locked python -m ce_analyzer_mcp.tool_snapshot
```

Verify that the committed snapshot is current without rewriting it:

```bash
uv run --locked python -m ce_analyzer_mcp.tool_snapshot --check
```

CI performs this freshness check and compares the installed wheel's complete
tool list against the snapshot.

### Shared input objects

Compilation tools accept the main source as the top-level string `source`, not
as a nested source-bundle object. Optional virtual files have this shape:

```json
{
  "path": "include/widget.hpp",
  "content": "#pragma once\nint widget();\n"
}
```

A library selection uses the exact `id` and exact version ID returned as
`version_id` by `search_libraries`. The request field is named `version`:

```json
{
  "id": "exact-library-id",
  "version": "exact-version-id"
}
```

An analyzer selection uses an exact backend tool ID or a recognized alias and a
token array, not a shell command string:

```json
{
  "id": "clang-tidy",
  "arguments": ["--checks=performance-*"]
}
```

The assembly display-filter object and its defaults are:

```json
{
  "comment_only": true,
  "demangle": true,
  "directives": true,
  "intel": true,
  "labels": true,
  "library_code": false,
  "trim": false,
  "debug_calls": false
}
```

Every output window has the following shape. `offset` defaults to `0` and must
be non-negative; `limit` defaults to `200` and must be from `1` through `1000`.

```json
{
  "offset": 0,
  "limit": 200
}
```

At the MCP boundary, optional `files`, `compiler_arguments`, `libraries`,
`filters`, and `window` parameters may be omitted or set to `null`; either form
selects the documented default. `search_analyzers.compiler` is also nullable.
Required arrays such as `cases` and `analyzers` are not nullable.

### `search_compilers`

Searches normalized C++ compiler metadata and reports exact backend IDs plus the
current status of all compiler aliases.

```json
{
  "query": "gcc 14",
  "offset": 0,
  "limit": 20
}
```

`query` is optional, case-insensitive, and token-based. All query tokens must
match normalized metadata. `offset` and `limit` are optional; offset must be
non-negative and limit must be from 1 through 50. The result contains a page of
compilers and separate alias resolutions.

Discovery treats identifier separators such as `-`, `_`, `.`, `/`, and `:` as
equivalent, so a search for `clang-trunk` can find backend ID `clang_trunk`.
Compilation still requires the exact ID or a documented alias; an unknown
selector reports an exact-ID suggestion but is never corrected automatically.

### `search_libraries`

Searches valid C++ library/version pairs. Use both returned exact identifiers in
later compile requests.

```json
{
  "query": "fmt",
  "offset": 0,
  "limit": 20
}
```

The fields and defaults are the same as `search_compilers`.

Library results are the versions advertised by the configured Compiler Explorer
backend, not a package-registry freshness claim. A newer upstream release cannot
be selected until that backend advertises its exact version ID.

### `search_analyzers`

Discovers supported analyzer IDs and alias resolutions. Supplying `compiler`
resolves that compiler and adds compatibility information for it.

```json
{
  "query": "clang tidy",
  "compiler": "clang-latest",
  "offset": 0,
  "limit": 20
}
```

All fields are optional. `compiler` must be an exact compiler ID or compiler
alias when present.

### `compile_cpp`

Performs one compile-only request and returns selected bounded diagnostics,
assembly, and optimization records.

```json
{
  "source": "#include <widget.hpp>\nint main() { return widget(); }\n",
  "compiler": "gcc-latest",
  "files": [
    {
      "path": "include/widget.hpp",
      "content": "#pragma once\nint widget();\n"
    },
    {
      "path": "src/widget.cpp",
      "content": "int widget() { return 0; }\n"
    }
  ],
  "compiler_arguments": ["-std=c++23", "-O2", "-Iinclude"],
  "libraries": [],
  "filters": {
    "comment_only": true,
    "demangle": true,
    "directives": true,
    "intel": true,
    "labels": true,
    "library_code": false,
    "trim": false,
    "debug_calls": false
  },
  "include_diagnostics": true,
  "include_assembly": true,
  "assembly_format": "text",
  "include_optimization": false,
  "window": {
    "offset": 0,
    "limit": 200
  }
}
```

Only `source` is required. `compiler` defaults to `gcc-latest`; arrays default to
empty; the filter, include, and window values default to those shown. Asking for
optimization output fails before compilation when metadata explicitly says that
the selected compiler does not support it.

The response identifies the requested selector and resolved compiler, reports
status, exit code, timeout and backend cache/truncation fields when available,
and includes a canonical SHA-256 request fingerprint. Compiler failure or timeout
is a structured result rather than an MCP transport error.

When `include_assembly` is `false`, the request sets Compiler Explorer's
`skipAsm` option. Assembly output, line count, and hash are then intentionally
unavailable instead of downloading assembly only to discard it.

`assembly_format` controls the returned assembly item shape:

- `"detailed"` is the backward-compatible default and returns objects with text,
  source mappings, opcodes, addresses, and labels.
- `"text"` returns sanitized assembly strings and is recommended when only the
  generated instructions are needed. Paging, total line count, and the full
  normalized assembly hash remain available.

Text mode usually uses substantially fewer response tokens because it omits
empty per-line metadata. The input selection determines whether `assembly.items`
contains detailed objects or strings; the default detailed response payload is
unchanged for backward compatibility.

### `compare_cpp`

Compiles one source bundle under two to six configurations. The first case is
the baseline; every later case is compared with that baseline.

```json
{
  "source": "int square(int x) { return x * x; }\n",
  "files": [],
  "cases": [
    {
      "label": "gcc-O2",
      "compiler": "gcc-latest",
      "compiler_arguments": ["-O2"],
      "libraries": [],
      "filters": {
        "comment_only": true,
        "demangle": true,
        "directives": true,
        "intel": true,
        "labels": true,
        "library_code": false,
        "trim": false,
        "debug_calls": false
      }
    },
    {
      "label": "clang-O2",
      "compiler": "clang-latest",
      "compiler_arguments": ["-O2"],
      "libraries": [],
      "filters": {
        "comment_only": true,
        "demangle": true,
        "directives": true,
        "intel": true,
        "labels": true,
        "library_code": false,
        "trim": false,
        "debug_calls": false
      }
    }
  ],
  "window": {
    "offset": 0,
    "limit": 200
  }
}
```

`source` and `cases` are required. In each case, `label` and `compiler` are
required; arguments and libraries default to empty and filters use the shared
defaults. Labels are unique without regard to case. All selectors are resolved
before any case starts, then cases compile concurrently under the process-wide
concurrency limit.

The result preserves each compile status and diagnostics, then returns assembly
line counts, normalized assembly hashes, and a bounded unified diff when both
baseline and candidate succeeded. It provides an omission reason otherwise.

Transport, authentication, incompatible-backend, and response-size failures are
reported as an `error` status on the affected case without discarding successful
cases. Every comparison includes input line counts. Omitted diffs also include a
machine-readable `omission_code`; an oversized input reports
`diff_input_limit_exceeded` and the active `diff_input_limit`.

Assembly hashes and diffs are observations about filtered textual assembly.
Different assembly is not a benchmark or a performance measurement. Matching or
different assembly does not establish semantic equivalence, correctness, or
relative speed.

### `analyze_cpp`

Runs one to four selected Compiler Explorer analyzers in a single compile-only
request and normalizes each tool's output.

```json
{
  "source": "#include <vector>\nint main() { std::vector<int> v; }\n",
  "analyzers": [
    {
      "id": "clang-tidy",
      "arguments": ["--checks=performance-*"]
    }
  ],
  "compiler": "clang-latest",
  "files": [],
  "compiler_arguments": ["-std=c++20"],
  "libraries": [],
  "filters": {
    "comment_only": true,
    "demangle": true,
    "directives": true,
    "intel": true,
    "labels": true,
    "library_code": false,
    "trim": false,
    "debug_calls": false
  },
  "window": {
    "offset": 0,
    "limit": 200
  }
}
```

`source` and `analyzers` are required. `compiler` defaults to `clang-latest`;
the remaining optional fields use the shared defaults. Analyzer selections must
be unique and must resolve to distinct tools supported by the selected compiler.
The result includes compiler diagnostics and a status, exit code, bounded output,
and warnings for every requested analyzer, including missing or malformed backend
tool results. Analyzer requests ask Compiler Explorer to omit assembly parsing and
assembly output after the selected tools run; the compiler may still generate the
assembly required by post-compilation analyzers.

Top-level `status` is aggregate: it is `failed` when compilation fails or any
requested analyzer fails, is missing, or is malformed. `exit_code` remains the
compiler exit code; each analyzer carries its own exit code. Known limitations
are explicit per-tool warnings: llvm-mca models a linear instruction region and
not branch probabilities, and an OSACA assembly-parser rejection is identified
without hiding its original output. Exact clang-tidy warning-count boilerplate is
omitted while actual findings remain.

### `create_shortlink`

Resolves one to six compiler configurations, validates each compilation by
default, then permanently stores one C++ source as a built-in Compiler Explorer
ClientState and returns its shareable URL.

```json
{
  "source": "extern \"C\" int square(int x) { return x * x; }\n",
  "compilers": [
    {
      "compiler": "gcc-latest",
      "compiler_arguments": ["-std=c++23", "-O3"],
      "libraries": [],
      "filters": {
        "comment_only": true,
        "demangle": true,
        "directives": true,
        "intel": true,
        "labels": true,
        "library_code": false,
        "trim": false,
        "debug_calls": false
      }
    },
    {
      "compiler": "clang-latest",
      "compiler_arguments": ["-std=c++23", "-O3"],
      "libraries": []
    }
  ],
  "validate_compilation": true
}
```

Only `source` is required. Omitted `compilers` creates one `gcc-latest` pane.
Aliases and libraries are resolved before any compilation or storage, and the
stored state pins exact backend compiler and library IDs. With default validation,
all panes compile concurrently with execution disabled and assembly omitted; any
failure or timeout prevents storage. The result reports each resolved compiler,
compile fingerprint, exit code, validation status, shortlink ID, and URL without
echoing source. Set `validate_compilation=false` only when an unvalidated link is
intentional.

Shortlinks support one main source only. Virtual files, project trees, executors,
analyzers, stdin, and runtime state are not accepted. Creation supports the
built-in `/z/<id>` shortener contract; external shortener URLs are rejected. The
storage POST is never automatically retried because a lost response can leave an
indeterminate persistent write. Shortlink compiler-argument tokens reject all
control characters so stored option strings can be retrieved without loss.

### `get_shortlink`

Retrieves bounded, allowlisted C++ state from a bare built-in shortlink ID:

```json
{
  "shortlink_id": "esPcxsWjh"
}
```

Full URLs, paths, queries, and fragments are rejected. The result includes C++
source, compiler IDs, exact stored option strings, libraries, and safe display
filters. It does not re-resolve historical compiler/library IDs or compile the
source. Non-C++ sessions, trees, executors, analyzers, binary output, execution
state, and unknown nested backend fields are omitted with explicit warnings.
Retrieved source and options are untrusted public data.

### `get_opcode_documentation`

Looks up bounded opcode documentation using explicit instruction-set and opcode
IDs.

```json
{
  "instruction_set": "amd64",
  "opcode": "add"
}
```

Both strings are required. The result includes a capped tooltip, allowlist-
sanitized HTML, and an HTTP(S) source URL. This tool does not accept fuzzy names;
an absent opcode is a clear not-found tool error.

## IDs and aliases

Compiler Explorer IDs vary by backend and over time. Discover them instead of
copying IDs from another instance.

Compiler selectors accept an exact ID returned by `search_compilers` or one of
these exact aliases:

- `gcc-latest`
- `clang-latest`
- `msvc-latest`

An exact backend compiler ID wins before alias handling. An alias is resolved at
request time to the newest eligible stable, native x86-64 C++ compiler in that
family. Resolution excludes unsuitable metadata such as hidden, nightly,
prerelease/non-SemVer, emulated/interpreted, non-stable-track, and recognized
cross-target or experimental entries. An alias can be unavailable on a backend;
`search_compilers` reports its current status and exact resolved ID.

Analyzer selectors accept an exact ID returned by `search_analyzers` or one of
these exact aliases:

- `clang-tidy`
- `iwyu`
- `llvm-mca`
- `osaca`
- `pvs-studio`

An analyzer alias resolves only when the backend exposes exactly one matching
tool compatible with the selected compiler. Otherwise it is reported as
ambiguous or unavailable. An exact analyzer ID must also be advertised by that
compiler. Libraries have no aliases: both library ID and version ID must exactly
match `search_libraries`, and the compiler must allow that library.

Exact IDs take precedence when an analyzer ID is also spelled like a curated
alias. For example, if the backend advertises both `iwyu` and `iwyu022`, selector
`iwyu` means the exact `iwyu` tool; choose `iwyu022` explicitly for that version.

Compiler, library, and analyzer selectors are 1 to 128 characters, start with an
ASCII alphanumeric character, and otherwise allow ASCII letters, digits, `.`,
`_`, `+`, `:`, `/`, and `-`. Instruction-set and opcode IDs are 1 to 64
characters and allow ASCII letters, digits, `.`, `_`, `+`, and `-` after the
initial alphanumeric character.

## Virtual files

`files` is an array of at most 32 supplied `{path, content}` objects. Paths are
case-sensitive for duplicate detection and must satisfy all of these rules:

- Relative, normalized POSIX paths only, using `/` rather than `\`.
- Between 1 and 255 characters and must name a file, not end in `/`.
- No absolute path, NUL/control character, empty segment, `.` segment, or `..`
  segment.
- No duplicate path within one source bundle.

The main source and every virtual-file content field is capped separately at 128
KiB of UTF-8. The main source plus all virtual-file contents is capped at 256 KiB
of UTF-8. A path is never opened locally; `content` is the only content sent for
that virtual file. `example.cpp` is reserved for the backend's main source, and
Windows drive-prefixed paths are rejected. Additional `.cpp` virtual files are
not automatically compiled as separate translation units; version 1 exposes no
project or CMake build workflow.

## Pagination, replay, and state

Discovery tools use stable `offset`/`limit` pagination. The default discovery
page is 20 items and the maximum is 50. Every page reports:

- `offset`
- `limit`
- `total`
- `returned`
- `truncated_before`
- `truncated_after`
- `next_offset`

Compile-derived line output uses `window` with default `{offset: 0, limit: 200}`
and maximum `limit: 1000`. The same window is applied independently to each
requested diagnostics, assembly, optimization, analyzer-output, and diff section.
Use each section's own `next_offset`; sections can have different totals.

The server is stateless with respect to compile results and exposes no result
handle. Requesting another window replays the complete tool request and can cause
another backend compile. The canonical fingerprint remains stable for the same
resolved compiler and payload, and Compiler Explorer may satisfy the replay from
its cache. Backend `cache_eligible` and `cache_hit` fields are returned when the
backend provides them. There is no cache-bypass input.

Shortlinks are an explicit exception to backend-stateless analysis: creation asks
Compiler Explorer to persist one deterministic ClientState. Retrieval is by bare
ID and does not create a local result handle or local source cache.

Compiler, library, and analyzer metadata is cached only in memory for
`CE_API_METADATA_TTL_SECONDS`. Restarting the process clears it; setting the TTL
to `0` disables metadata caching.

## Limits

The principal request and response safety limits are:

| Item | Limit |
| --- | ---: |
| Main source | 128 KiB UTF-8 |
| Each virtual-file content | 128 KiB UTF-8 |
| Aggregate source and virtual-file content | 256 KiB UTF-8 |
| Virtual files | 32 |
| Compiler arguments | 128 non-empty tokens, 8 KiB shell-serialized UTF-8 |
| Libraries | 8, with each library ID selected once |
| Analyzers | 1 to 4 |
| Analyzer arguments | 64 non-empty tokens per analyzer, 4 KiB shell-serialized UTF-8 across all analyzers |
| Comparison cases | 2 to 6 |
| Comparison label | 1 to 64 control-free characters, case-insensitively unique |
| Shortlink compiler panes | 1 to 6 |
| Retrieved shortlink sessions | 8 C++ sessions |
| Raw shortlink sessions examined | First 64 entries |
| Retrieved compiler panes per session | 8 |
| Shortlink ID | 1 to 128 ASCII letters, digits, `_`, or `-`; first character alphanumeric |
| Search query | 200 control-free characters |
| Discovery page | 1 to 50 items, default 20 |
| Output window | 1 to 1000 lines per section, default 200 |
| Normalized backend section | 20,000 items before windowing |
| Individual output line | 4,096 UTF-8 bytes including truncation marker |
| Serialized MCP result | 1,000,000 UTF-8 bytes |
| Upstream HTTP response | 8 MiB |
| Assembly accepted for each side of a diff | 5,000 lines |
| Opcode tooltip | 8 KiB UTF-8 |
| Sanitized opcode HTML | 32 KiB UTF-8 |

Compiler and analyzer argument tokens must not be empty and must not contain NUL,
carriage return, or newline. They are shell-quoted into the backend's argument
string in one controlled serializer. These shape limits do not make arbitrary
compiler flags safe; the configured Compiler Explorer sandbox remains the
compiler-policy boundary.

ANSI and unsafe control sequences are removed from diagnostic, analyzer, and
assembly text. Truncation is explicit through page metadata, `text_truncated`,
section warnings, backend truncation fields, and/or `response_truncated`. If a
comparison input exceeds 5,000 assembly lines on either side, its diff is omitted
instead of processing an unbounded diff.

## Configuration

Configuration is read once from the server process environment at startup and is
immutable for that process. MCP tool callers cannot change the backend URL,
credentials, TLS policy, timeouts, concurrency, or metadata cache policy.

| Environment variable | Default | Validation and behavior |
| --- | --- | --- |
| `CE_API_BASE_URL` | `https://godbolt.org/` | Absolute HTTP(S) URL with a host; credentials, query, fragment, malformed ports, and control characters are rejected. A path prefix is allowed and normalized with a trailing `/`. |
| `CE_API_AUTH_TOKEN` | Unset | Optional secret. Empty is treated as unset. Never put a token in an MCP tool argument. |
| `CE_API_AUTH_HEADER` | `Authorization` | Must be a valid HTTP field name. |
| `CE_API_AUTH_SCHEME` | `Bearer` | Empty or an HTTP token of at most 64 characters. Set to an empty string for a raw API-key header value. |
| `CE_API_VERIFY_TLS` | `true` | Verifies HTTPS certificates. Setting it to `false` disables verification and is insecure. |
| `CE_API_ALLOW_INSECURE_HTTP` | `false` | Plain HTTP is accepted automatically only for `localhost` or another loopback address. Set to `true` to permit non-loopback HTTP, which exposes source and credentials in transit. |
| `CE_API_CONNECT_TIMEOUT_SECONDS` | `5` | Number greater than 0 and at most 120; also used for the connection-pool timeout. |
| `CE_API_READ_TIMEOUT_SECONDS` | `60` | Number greater than 0 and at most 600; also used for write timeout. |
| `CE_API_MAX_CONCURRENCY` | `4` | Integer from 1 through 32; controls the global request semaphore and HTTP connection limits. |
| `CE_API_METADATA_TTL_SECONDS` | `300` | Integer from 0 through 86,400; `0` disables the in-memory metadata cache. |

Boolean values accept `1`, `true`, `yes`, or `on`, and `0`, `false`, `no`, or
`off`, case-insensitively. Authentication is sent as
`<CE_API_AUTH_SCHEME> <CE_API_AUTH_TOKEN>` when the scheme is non-empty, or as
the raw token when it is empty. HTTP redirects are not followed.

For an authenticated backend, place the token in the environment that launches
the MCP client. This Bash example avoids putting the token value in a JSON file
or command-line argument:

```bash
read -r -s -p "Compiler Explorer token: " CE_API_AUTH_TOKEN
export CE_API_AUTH_TOKEN
ce-analyzer-mcp
```

## MCP client configuration

All examples below use the installed console script and stdio transport. Ensure
`ce-analyzer-mcp` is on the GUI application's `PATH`, or replace it with an
absolute executable path. To use the other installed launch form, set the
command to the absolute path of the intended Python interpreter and set arguments
to `-m`, `ce_analyzer_mcp`.

The snippets never contain a token value. If authentication is required, define
`CE_API_AUTH_TOKEN` in the parent application's OS environment before it starts.
Remove an environment-reference block when no token is needed. Do not paste a
secret directly into a checked-in MCP configuration.

### Kilo

Add this to project `kilo.json`/`kilo.jsonc`, `.kilo/kilo.json`/`kilo.jsonc`, or
the global `~/.config/kilo/kilo.json`/`kilo.jsonc`:

```json
{
  "$schema": "https://app.kilo.ai/config.json",
  "mcp": {
    "ce-analyzer": {
      "type": "local",
      "command": ["ce-analyzer-mcp"],
      "environment": {
        "CE_API_AUTH_TOKEN": "{env:CE_API_AUTH_TOKEN}"
      },
      "enabled": true,
      "timeout": 120000
    }
  }
}
```

For Kilo's module launch form, use
`"command": ["/absolute/path/to/python", "-m", "ce_analyzer_mcp"]`.

### Claude Desktop

Open the Desktop developer configuration. Its file is
`~/Library/Application Support/Claude/claude_desktop_config.json` on macOS and
`%APPDATA%\Claude\claude_desktop_config.json` on Windows:

```json
{
  "mcpServers": {
    "ce-analyzer": {
      "command": "ce-analyzer-mcp",
      "args": []
    }
  }
}
```

Claude Desktop does not provide portable shell-style interpolation in this file.
Set `CE_API_AUTH_TOKEN` in the Desktop process environment rather than storing it
under `env`, then fully restart the application.

### Claude Code

For a shared project configuration, add this to `.mcp.json`:

```json
{
  "mcpServers": {
    "ce-analyzer": {
      "type": "stdio",
      "command": "ce-analyzer-mcp",
      "args": [],
      "env": {
        "CE_API_AUTH_TOKEN": "${CE_API_AUTH_TOKEN}"
      }
    }
  }
}
```

Alternatively, add the installed command to Claude Code's user scope without
embedding a credential:

```bash
claude mcp add --transport stdio --scope user ce-analyzer -- ce-analyzer-mcp
```

### Cursor

Add this to project `.cursor/mcp.json` or global `~/.cursor/mcp.json`:

```json
{
  "mcpServers": {
    "ce-analyzer": {
      "type": "stdio",
      "command": "ce-analyzer-mcp",
      "args": [],
      "env": {
        "CE_API_AUTH_TOKEN": "${env:CE_API_AUTH_TOKEN}"
      }
    }
  }
}
```

### VS Code

Add this to workspace `.vscode/mcp.json` or use **MCP: Open User
Configuration** for a profile-wide server:

```json
{
  "servers": {
    "ceAnalyzer": {
      "type": "stdio",
      "command": "ce-analyzer-mcp",
      "args": [],
      "env": {
        "CE_API_AUTH_TOKEN": "${env:CE_API_AUTH_TOKEN}"
      }
    }
  }
}
```

This project exposes stdio MCP only. The HTTP(S) URL in `CE_API_BASE_URL` is the
outbound Compiler Explorer REST backend, not an MCP HTTP endpoint.

## Errors and retries

Invalid strict input, unknown or incompatible selections, transport failures,
authentication failures, non-transient backend HTTP failures, oversized or
incompatible backend responses, and missing opcode documentation are returned as
concise MCP tool errors. Validation errors report at most five field locations
and hide input values. Expected errors include only bounded, sanitized context
such as endpoint, HTTP status, and request fingerprint; they omit source, request
headers, and credentials. Unexpected exceptions are logged to stderr and become
a generic internal tool error.

A compiler's nonzero exit code and a backend-reported compile timeout remain
normal structured compile results so clients can inspect diagnostics. Missing or
malformed analyzer output is also represented in the analyzer result with
warnings. In a comparison, expected per-case Compiler Explorer request failures
are likewise structured so other completed cases remain available; unexpected
internal exceptions still fail the whole tool call.

Metadata GET requests use up to three attempts for transport failures and HTTP
429, 502, 503, or 504. A compile POST uses up to two attempts for a pre-response
transport failure or one of those explicit transient statuses. Retry-After is
capped, and redirects are disabled so credentials are not forwarded to another
origin. A shortlink-storage POST uses exactly one attempt and is never retried;
shortlink-info GET requests use the normal metadata GET policy.

## Releasing

Releases are built from `v<version>` tags by
[`release.yml`](.github/workflows/release.yml). The workflow requires the tag to
exactly match `[project].version` in `pyproject.toml`, reruns the offline quality
and coverage checks, validates the repository tool snapshot, builds and
smoke-tests the wheel and source distribution, publishes them to PyPI through
OIDC trusted publishing, and then creates a GitHub Release containing those same
artifacts.

The `publish-pypi` job uses a protected GitHub environment named `pypi`. Configure
that environment with required reviewer approval and restrict deployment to tags
matching `v*`. Do not add a PyPI API token or password as a repository secret.

Configure the PyPI trusted publisher with these exact values:

- PyPI project: `ce-analyzer-mcp`
- GitHub owner: `Malkovsky`
- Repository: `compiler-explorer-mcp`
- Workflow filename: `release.yml`
- Environment: `pypi`

For the first publication, create a pending trusted publisher from the PyPI
account publishing settings before pushing the tag. For later releases, update
the version in both `pyproject.toml` and
`src/ce_analyzer_mcp/__about__.py`, then regenerate all version-bearing metadata
before committing:

```bash
uv lock
uv run --locked python -m ce_analyzer_mcp.tool_snapshot
uv run --locked pytest -m "not live"
```

After the release commit is on `main` and CI is green, create and push an
annotated tag. Approve the `pypi` environment deployment only after confirming
the tag's CI run is green:

```bash
git tag -a v0.2.1 -m "Release 0.2.1"
git push origin v0.2.1
```

PyPI filenames and released versions are immutable. If a release has already
been published, fix forward with a new version rather than moving or recreating
its tag.

## License

MIT
