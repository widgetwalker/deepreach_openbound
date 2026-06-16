# DeepReach

[![CI Status](https://github.com/widgetwalker/deepreach_openbound/actions/workflows/ci.yml/badge.svg)](https://github.com/widgetwalker/deepreach_openbound/actions)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python Version](https://img.shields.io/badge/python-3.11%20%7C%203.12%20%7C%203.13-blue)](https://www.python.org/)

**DeepReach** is a high-performance, FOSS command-line interface (CLI) tool designed to scan Node.js and Python projects for **reachable** vulnerabilities (CVEs). 

Unlike standard vulnerability scanners that flag every vulnerable dependency in your tree, DeepReach performs static Abstract Syntax Tree (AST) call graph analysis to verify if the vulnerable functions in your dependencies are actually invoked or reachable in your application source code. This eliminates alert fatigue by prioritizing true threats.

---

## 🚀 Key Features

*   **Dependency Resolution**:
    *   **Node.js**: Parses `package-lock.json` supporting modern schema formats.
    *   **Python**: Parses `requirements.txt` dependency specifications.
*   **Vulnerability Federation**:
    *   Queries public advisory databases including **OSV.dev**, **GitHub Security Advisories (GHSA)**, and **NVD**.
    *   Maintains a fast, local **SQLite-backed cache store** to avoid network overhead during rescans.
*   **Static Reachability Analysis**:
    *   Utilizes **tree-sitter** grammars to traverse and construct precise AST call-graphs.
    *   Supports analysis for **Python** (`.py`), **JavaScript** (`.js`, `.jsx`), and **TypeScript** (`.ts`, `.tsx`).
*   **Actionable Reports**:
    *   Provides high-quality stdout table outputs.
    *   Supports **JSON** and **SARIF** output targets for seamless IDE and CI/CD integration.

---

## 🛠️ Architecture Overview

The tool is modularly organized to separate concerns cleanly:

```
src/deepreach/
├── cli.py                  # Command-line interface definition & command orchestration
├── config.py               # XDG-compliant path configuration for caching
├── models.py               # Normalized type-safe models (Advisory, Finding, DefSite, etc.)
├── lockfile_parser/        # Ecosystem-specific lockfile parser implementations
├── vuln_federation/        # Database store & external vulnerability adapters
└── reachability/           # Language AST parsers & reachability call-graph builders
```

---

## 💻 Installation & Setup

### Prerequisites

*   Python `pypy` or `cpython` >= **3.11**
*   Tree-sitter language libraries (for syntax tree analysis):
    ```bash
    pip install tree-sitter tree-sitter-python tree-sitter-javascript
    ```

### Running the Tool

You can run the CLI directly from the source:

```bash
# Display help and usage
python -m deepreach --help

# Initialize or update the local vulnerability cache
python -m deepreach init

# Scan a repository for reachable vulnerabilities
python -m deepreach scan /path/to/your/project
```

---

## 🧪 Testing and Verification

DeepReach comes with a comprehensive test suite verifying lockfile parsers, reachability graph solvers, and SQLite cache store mechanics.

To run the unit tests, run:

```bash
python -m pytest
```

To run static type-checking and code quality linters:

```bash
python -m mypy src tests
python -m ruff check src tests
```

---

## 📄 License

DeepReach is licensed under the MIT License. See [LICENSE](LICENSE) and [NOTICE](NOTICE) for details.