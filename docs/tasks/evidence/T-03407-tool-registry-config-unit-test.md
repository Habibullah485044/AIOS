# T-03407 Evidence: Tool Registry & Taxonomy — configuration Unit Test

- Date: 2026-11-06
- New `code/aiosh-mcp/tests/test_tool_registry_config_unit.py` (24 tests), standalone.

## Coverage
| Area | Cases |
|---|---|
| Exact bounds | for each numeric key: `lo` and `hi` accepted without error; `lo-1` and `hi+1` clamped with `TOOLREGCONF_ERR_BOUNDS` |
| File size | a file of exactly 64 KiB is read |
| Hostile files (never raise) | invalid UTF-8, empty, `null`, a 1e309 float, a 1e400 number, a 5000-digit integer, 100 000-deep nesting, duplicate keys |
| Mode | duplicate `mode` keys cannot launder strict when the env says strict; blank values (`""`, spaces, ideographic space) are no opinion; fullwidth `ＳＴＲＩＣＴ`, `strict\n`, `Strict` and unknowns (`off`, `0`, `none`) are strict |
| Never raises | an internal failure falls back to defaults with `TOOLREGCONF_ERR_IO`, and the fallback **still honours an env strict** (fail closed) |
| Caching | 16 threads calling `process_config()` resolve exactly once and get the same object |
| Bounded errors | a 5 000-char unknown key gives errors ≤ `MAX_ERROR_CHARS` |

Pytest puts each test id into an environment variable, and Windows caps those at 32 767 chars. The hostile-content
parameters therefore carry short ids.

## Results
```
$ python -m pytest tests/test_tool_registry_config_unit.py -q
24 passed in 0.94s
```

## Mutations (applied one at a time, then reverted; unit + impl tests)
| Mutation | Result |
|---|---|
| M1: an unknown mode value means shadow (fail open) | 5 failed |
| M2: the first source wins instead of the strictest | 2 failed |
| M3: the internal-failure fallback ignores an env strict | 1 failed |
