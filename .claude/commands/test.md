Run tests for the monad C++ project.

## Arguments

The user may pass arguments like:
- A test filter string — passed as `-R <filter>` to ctest (e.g., `monad_trie`, `EvmcHost`)
- No arguments — run all tests

## Instructions

You are running tests for the monad C++ project located at $CWD.

### macOS / Apple Silicon — stop first

**Do not run a full test suite on macOS or Docker Desktop `linux/amd64` (Rosetta).** The project is x86-64-only; Rosetta runs produce hundreds of environmental failures (SIGILL, io_uring/hugetlbfs, hugepage ENOSPC) that are **not** merge bugs and waste large amounts of time/tokens.

On a Mac host:

1. Tell the user that full `ctest` is not meaningful here.
2. Prefer **no** full suite: assume CI / a real Linux x86-64 runner is the gate unless they insist.
3. If they still want a local check, only build/run a **narrow** filter for files you changed (e.g. `-R Event|ExecuteBlock`), and stop after that — never escalate to full suite or multi-hour container rebuilds without explicit approval.
4. Do not "fix" Rosetta/hugepage failures by enabling host hugepages or long docker rebuild loops.

### Prerequisites

A build must exist in `build/`. If it doesn't, tell the user to run `/build` first. Native configure/build on Apple Silicon is expected to fail; do not spend the session fighting that.

### Steps (Linux x86-64 only)

1. **Run ctest:**
   ```bash
   ctest --test-dir build --output-on-failure --timeout 500 --parallel
   ```
   If the user specified a test filter, add `-R <filter>`.

2. **Run the Python test layer:**
   ```bash
   pytest-3 category/core/monad/tests/
   ```
   This runs additional tests (e.g., disassembly validation). If pytest-3 is not installed, treat it as a failure and tell the user — this is a required part of the pre-PR test gate.

### Error handling

- If tests fail, show which tests failed and their output
- If `build/` doesn't exist, tell the user to run `/build` first
- On macOS, environmental failures are not actionable merge defects — report that and stop

### Important

- Always run commands from the project root directory: $CWD
- Do NOT modify any source files
