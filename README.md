# DeepReach

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python Version](https://img.shields.io/badge/python-3.11%20%7C%203.12%20%7C%203.13-blue)](https://www.python.org/)

**DeepReach** is a FOSS command-line tool that scans Node.js and Python projects for **reachable** CVEs.

> Unlike `npm audit` or `pip-audit`, DeepReach doesn't just flag every vulnerable package in your tree — it performs **AST-level static analysis** to determine if the vulnerable code is actually *called* by your application. This eliminates false positives and alert fatigue.

---

## ✨ Quick Start

### Local installation

```bash
# Clone and install
git clone https://github.com/widgetwalker/deepreach_openbound
cd openbound
python -m venv .venv && .venv/Scripts/activate
pip install -e .

# Point it at any Node.js or Python project — recursively scans all subdirectories
python -m deepreach scan /path/to/your/project

# Get machine-readable output for CI/CD pipelines
python -m deepreach scan /path/to/project --format json
python -m deepreach scan /path/to/project --format sarif

# Fail CI if a REACHABLE high-severity CVE is found
python -m deepreach scan /path/to/project --fail-on high
```

### Run with Docker

```bash
# Build the hardened minimal Docker image
docker build -t deepreach .

# Scan a local project directory by mounting it as a volume
docker run --rm -v /path/to/your/project:/workspace deepreach scan /workspace
```


---

## 🚀 Key Features

| Feature | Details |
|---|---|
| **Recursive lockfile discovery** | Automatically finds `package-lock.json` and `requirements.txt` anywhere under the target path |
| **OSV.dev integration** | Queries the Open Source Vulnerability database in real-time with local SQLite cache |
| **AST reachability analysis** | Uses `tree-sitter` to extract call graphs from `.js`, `.jsx`, `.ts`, `.tsx`, and `.py` source files |
| **Rich colored output** | Color-coded severity badges, reachability indicators, and file traces |
| **JSON + SARIF output** | Machine-readable formats for IDE integration and CI/CD pipelines |
| **`--fail-on` severity gate** | Returns exit code `2` when a reachable CVE meets or exceeds the specified severity |
| **`deepreach explain <CVE>`** | Look up detailed advisory info from the local cache |
| **`deepreach self-test`** | Runs the full test suite from the CLI |

---

## 💡 Why Reachability Matters

Standard dependency scanners report *every* vulnerable version in your dependency tree — including transitive deps you don't even call. This leads to hundreds of false-positive alerts for vulnerabilities that are literally unreachable in your code.

**DeepReach only tells you about CVEs in code paths your application actually executes.**

```
npm audit   →  47 vulnerabilities   (how many matter? who knows)
deepreach   →   3 REACHABLE CVEs    (these are the ones to fix TODAY)
            →  44 unreachable       (scheduled for next sprint)
```

---

## 🛠️ Architecture

```
src/deepreach/
├── cli.py                  # CLI entry point — scan, explain, self-test, license
├── models.py               # Type-safe data models (Advisory, Finding, Edge, etc.)
├── config.py               # XDG-compliant cache path configuration
├── lockfile_parser/
│   ├── npm.py              # package-lock.json parser (npm v2/v3 schema)
│   └── pip.py              # requirements.txt parser
├── vuln_federation/
│   ├── osv.py              # OSV.dev API adapter
│   ├── ghsa.py             # GitHub Security Advisories adapter (stub)
│   └── store.py            # SQLite-backed advisory cache
├── reachability/
│   ├── javascript.py       # JS/TS tree-sitter call-graph extractor
│   └── python_lang.py      # Python tree-sitter call-graph extractor
└── report/
    ├── __init__.py         # Package init
    ├── table.py            # Text table report generator
    ├── json_fmt.py         # Deterministic JSON report generator
    ├── sarif.py            # Deterministic SARIF report generator
    └── explain.py          # Detailed call path explanation generator
```


---

## 🧪 Testing

```bash
# Run the full test suite
python -m pytest

# Run via the CLI self-test command
python -m deepreach self-test

# Scan the bundled vulnerable example app
python -m deepreach scan examples/vulnerable-app/nodejs
python -m deepreach scan examples/vulnerable-app/python
```

DeepReach ships with an intentionally vulnerable Node.js + Python sample app in `examples/vulnerable-app/` for demo and testing purposes.

---

## 📤 Output Formats

### Table (default)
Color-coded human-readable output with reachability traces pointing to exact file + line numbers.

### JSON (`--format json`)
```json
{
  "tool": "deepreach",
  "target": "/path/to/project",
  "summary": {
    "total_dependencies": 487,
    "vulnerable_packages": 9,
    "reachable_cves": 3,
    "total_cves": 28
  },
  "findings": [...]
}
```

### SARIF (`--format sarif`)
Standard [SARIF 2.1.0](https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html) output, compatible with GitHub Code Scanning, VS Code SARIF Viewer, and other security tooling.

---

## 🔧 Extending DeepReach

Adding a new ecosystem (e.g. Dart, Rust/Cargo, Java/Maven) requires:

1. A lockfile parser in `src/deepreach/lockfile_parser/`
2. A tree-sitter language adapter in `src/deepreach/reachability/`
3. Wire it up in `cli.py`

See [CONTRIBUTING.md](CONTRIBUTING.md) for a full guide.

---

## 📄 License

DeepReach is licensed under the **MIT License**.  
See [LICENSE](LICENSE) and [NOTICE](NOTICE) for full details.

---

## 🔒 Security

Found a vulnerability in DeepReach itself? Please read our [SECURITY.md](SECURITY.md) for responsible disclosure guidelines.