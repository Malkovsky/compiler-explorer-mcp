# Maintainer Notes

- MCP 2.0's generated outer argument model ignores unknown keys and omits `additionalProperties: false`. Keep `StrictMCPServer.list_tools` and `call_tool` enforcing both the advertised schema and runtime rejection.
- Pydantic may copy nested `Page` models while constructing an output model. Response-budget trimming must receive pages taken from the final response, not pre-construction local page objects.
- Compiler Explorer `libsArr` is unrestricted when absent or empty; only a nonempty list restricts valid library IDs or `id.version` pairs.
- A compile POST may retry only before response headers or on an explicit transient status. Preserve the `response_started` distinction; post-response stream failures are retryable only for GET metadata.
- CE version endpoints return scalar text, cache-hit fields may use the misspelling `retreivedFromCache`, and extra virtual `.cpp` files are not automatically compiled as translation units.
- MCP 2 duplicates structured tool results into pretty-printed text by default, while some clients expose only text content. Mirror small results as bounded compact JSON, use a pointer for large results, and always preserve complete `structuredContent`.
- Analyzer aggregate status includes every requested tool; the top-level exit code remains the compiler exit code. Compiler/analyzer discovery may normalize separators, but execution resolution stays exact and exact analyzer IDs precede aliases.
- Built-in shortlinks store a direct deterministic `sessions` ClientState indefinitely; emit libraries as `libs[].name`/`ver`, pin resolved exact IDs, and never retry the storage POST after an ambiguous failure.
- Shortlink retrieval is untrusted backend content. Normalize only bounded C++ sessions and safe compiler display state; omit trees, executors, tools, execution/binary flags, and unknown nested JSON with explicit warnings.
- `mcp-tools.json` is the sanitized repository snapshot of all paginated `tools/list` pages. Regenerate it with `python -m ce_analyzer_mcp.tool_snapshot`; CI checks freshness and uses it to verify the installed wheel's tool list.
