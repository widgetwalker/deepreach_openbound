# Contributing to DeepReach

Thank you for your interest in contributing to DeepReach! 🎉  
We welcome contributions of all kinds: bug reports, new features, documentation improvements, and more.

---

## Table of Contents

- [Getting Started](#getting-started)
- [Development Setup](#development-setup)
- [Running Tests](#running-tests)
- [Submitting Changes](#submitting-changes)
- [Adding a New Ecosystem](#adding-a-new-ecosystem)
- [Code Style](#code-style)
- [Reporting Issues](#reporting-issues)

---

## Getting Started

1. **Fork** the repository on GitHub.
2. **Clone** your fork locally:
   ```bash
   git clone https://github.com/<your-username>/openbound.git
   cd openbound
   ```
3. Create a **virtual environment** and install dependencies:
   ```bash
   python -m venv .venv
   source .venv/bin/activate   # Windows: .venv\Scripts\activate
   pip install -e ".[dev]"
   ```

---

## Development Setup

The project uses:
- **`ruff`** — linting and formatting
- **`pytest`** — testing
- **`mypy`** — static type checking
- **`tree-sitter`** — AST parsing

```bash
# Run the linter
python -m ruff check src tests

# Auto-fix style issues
python -m ruff check --fix src tests && python -m ruff format src tests

# Run static type checks
python -m mypy src tests
```

---

## Running Tests

```bash
# Run all unit tests
python -m pytest

# Run with coverage report
python -m pytest --cov=deepreach --cov-report=term-missing

# Run the built-in self-test command
python -m deepreach self-test
```

All pull requests must pass the full test suite before merging.

---

## Submitting Changes

1. Create a new branch: `git checkout -b feat/my-feature`
2. Make your changes, with tests.
3. Ensure `ruff` and `pytest` both pass cleanly.
4. Commit with a clear message following [Conventional Commits](https://www.conventionalcommits.org/):
   - `feat: add Dart/Flutter lockfile parser`
   - `fix: handle UTF-16 encoded requirements.txt`
   - `docs: improve README install instructions`
5. Push your branch and open a Pull Request against `main`.

---

## Adding a New Ecosystem

DeepReach is designed to be extended. Adding a new ecosystem (e.g. Dart/Cargo/Maven) involves three steps:

### 1. Add a lockfile parser
Create `src/deepreach/lockfile_parser/<ecosystem>.py` implementing a `parse(content: str) -> List[tuple]` function.  
See [`npm.py`](src/deepreach/lockfile_parser/npm.py) or [`pip.py`](src/deepreach/lockfile_parser/pip.py) for reference.

### 2. Wire it in the CLI
Add detection for the lockfile filename in `_scan_command` inside [`cli.py`](src/deepreach/cli.py).

### 3. Add a reachability adapter (optional but powerful)
Create `src/deepreach/reachability/<language>.py` implementing a `LanguageAdapter` that uses `tree-sitter` to extract call expressions from source files.  
See [`javascript.py`](src/deepreach/reachability/javascript.py) for reference.

---

## Code Style

- **Line length**: 88 characters (enforced by `ruff`)
- **Formatting**: `ruff format` (Black-compatible)
- **Type hints**: Required on all public functions
- **Docstrings**: Required on all public classes and functions

---

## Reporting Issues

- **Bugs**: Open a [GitHub Issue](https://github.com/widgetwalker/deepreach_openbound/issues) with reproduction steps.
- **Security vulnerabilities**: See [SECURITY.md](SECURITY.md).
- **Feature requests**: Open a GitHub Discussion or Issue tagged `enhancement`.

---

We look forward to your contributions! 🚀
