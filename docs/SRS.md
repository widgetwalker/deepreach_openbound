# DeepReach - Software Requirements Specification (SRS)

**Version:** 0.1.0-draft · **Status:** binding for v1 implementation · **License:** MIT

> This SRS is the engineering contract for the 14-day build. Every requirement is either **MUST**, **SHOULD**, or **MAY**, in RFC 2119 sense. Anything not listed here is out of scope for v1.

---

## 1. Scope

DepReach is a single-binary Python CLI distributed via PyPI and a Docker image. It performs offline static reachability analysis over JavaScript, TypeScript, and Python source code, cross-references reachable code with vulnerability advisories cached locally from OSV.dev, GitHub Security Advisories, and (optionally) NVD, and emits a deterministic report in three formats: colourised table, JSON, and SARIF 2.1.0.

The system has **no** web server, **no** database server, **no** message queue, and **no** network requirement at scan time. The only network calls happen during `depreach init` (cache population) and are skippable with `--offline`.

## 2. Normative references

- **RFC 2119** - Key words for use in RFCs.
- **OSV Schema v1.6.x** - open source vulnerability data interchange format.
- **SARIF 2.1.0** - Static Analysis Results Interchange Format.
- **PEP 440** - Python version specifiers.
- **SemVer 2.0** - semantic versioning for the public CLI.
- **SPDX License List** - third-party licence identification.
- **CycloneDX 1.5** (informative) - SBOM format, planned v1.1.

## 3. Definitions

| Term | Definition |
|------|------------|
| **Advisory** | A normalised record `{cve_id, ecosystem, package, vulnerable_version_range, vulnerable_functions, fix_version, severity}` produced by a `SourceAdapter`. |
| **DefSite** | A `(file, line, name, exported)` tuple marking a function or arrow definition. |
| **Edge** | A `(caller: DefSite, callee_ref: ImportPath, line)` tuple marking a call expression. |
| **ImportPath** | A symbolic reference `{package?, module_path, symbol}` to be resolved by `resolver.py`. |
| **Reachable set** | The set of `DefSite`s reachable by BFS from the entry points. |
| **Finding** | The conclusion: `(advisory, reachable_defsite | None, call_path: list[DefSite], confidence: high|medium|low)`. |
| **Call path** | The shortest concrete path of `DefSite`s from an entry point to the vulnerable function. |

## 4. Overall description

### 4.1 Product perspective

DepReach sits in the developer terminal, parallel to `cargo audit` (Rust ecosystem) and `pip-audit`. It does not require any background service, any web app, or any account.

### 4.2 User class and characteristics

| User | Technical level | Frequency |
|------|----------------|-----------|
| Solo dev | intermediate, comfortable in terminal | weekly |
| OSS maintainer | advanced | on Dependabot alerts |
| Eng lead | advanced, CI/CD literate | per CI run |
| Judge / reviewer | expert, skeptical | one-off demo |

### 4.3 Operating environment

- Linux x86_64, macOS aarch64/x86_64, Windows on ARM/x86_64 via WSL2.
- Python 3.11, 3.12, 3.13.
- 4 GB RAM minimum, 8 GB recommended for monorepos.
- 200 MB free disk for the cache, 1 GB recommended.

### 4.4 Design and implementation constraints

| # | Constraint |
|---|------------|
| C-1 | FOSS-only dependencies, allowlist in §13. |
| C-2 | MIT-licensed. |
| C-3 | Python 3.11+; no compatibility shims for older versions. |
| C-4 | No C extensions that require a compiler at install time. Pure-Python wheels preferred. |
| C-5 | tree-sitter language packs must be pure-Python wrappers around the compiled `.so` shipped in the wheel. |
| C-6 | `pip install` must complete on a fresh Ubuntu 24.04 container in < 60 s. |
| C-7 | No `numpy`, no `pandas`, no `torch` (prohibitive install size). |
| C-8 | `mypy --strict` clean on `src/` and `tests/`. |
| C-9 | `ruff check` clean on `src/` and `tests/`. |
| C-10 | `pytest --cov` ≥ 90 % line coverage, ≥ 85 % branch. |

### 4.5 Assumptions and dependencies

- The host machine has a lockfile (npm, pnpm, yarn, pip, poetry, or uv).
- The host machine has a reachable network **only** at `depreach init` time.
- OSV.dev and GHSA remain publicly accessible without authentication.
- The target repo is small enough that a full tree-sitter parse finishes within the performance budget.

## 5. Functional requirements

### 5.1 CLI surface

| ID | Requirement | Priority |
|----|-------------|----------|
| FR-CLI-1 | The tool MUST expose subcommands: `init`, `scan`, `explain`, `self-test`, `--version`, `--license`. | MUST |
| FR-CLI-2 | `depreach scan <PATH>` MUST accept `--entry FILE[:LINE]` repeatable. | MUST |
| FR-CLI-3 | `depreach scan <PATH>` MUST accept `--format table\|json\|sarif`. | MUST |
| FR-CLI-4 | `depreach scan <PATH>` MUST accept `--all` to show unreachable advisories. | MUST |
| FR-CLI-5 | `depreach scan <PATH>` MUST accept `--fail-on critical\|high\|medium\|low`. | MUST |
| FR-CLI-6 | `depreach scan <PATH>` MUST accept `--no-color` for non-TTY output. | MUST |
| FR-CLI-7 | `depreach init` MUST accept `--offline` to skip network. | MUST |
| FR-CLI-8 | `depreach explain <REPO> <CVE-ID>` MUST print the call-path tree. | MUST |
| FR-CLI-9 | `depreach self-test` MUST exit 0 on a healthy install and non-zero on a broken one. | MUST |
| FR-CLI-10 | Every error message MUST name the failing subsystem and the fix command. | MUST |
| FR-CLI-11 | Stack traces MUST appear only with `--debug`. | MUST |
| FR-CLI-12 | Exit codes MUST be stable: 0 = clean, 1 = reachable CVE above threshold, 2 = usage error, 3 = lockfile parse error, 4 = advisory fetch error, 5 = unsupported ecosystem. | MUST |

### 5.2 Lockfile parsing

| ID | Requirement | Priority |
|----|-------------|----------|
| FR-LF-1 | The parser MUST detect and parse npm `package-lock.json` v1, v2, v3. | MUST |
| FR-LF-2 | The parser MUST detect and parse `pnpm-lock.yaml` v5, v6, v7, v8, v9. | MUST |
| FR-LF-3 | The parser MUST detect and parse `yarn.lock` classic and berry. | MUST |
| FR-LF-4 | The parser MUST detect and parse `requirements.txt` with pinned versions. | MUST |
| FR-LF-5 | The parser MUST detect and parse `poetry.lock` v1 and v2. | MUST |
| FR-LF-6 | The parser MUST detect and parse `uv.lock` v0.4+. | MUST |
| FR-LF-7 | The parser MUST emit `(ecosystem, name, version, parent_name, dep_path)` tuples. | MUST |
| FR-LF-8 | The parser MUST raise `LockfileParseError` with a one-line fix suggestion on any malformed input. | MUST |
| FR-LF-9 | The parser MUST be exhaustively property-tested with `hypothesis`. | MUST |

### 5.3 Vulnerability federation

| ID | Requirement | Priority |
|----|-------------|----------|
| FR-VF-1 | The federation MUST cache advisories in SQLite at `~/.cache/depreach/vulns.db`. | MUST |
| FR-VF-2 | The OSV adapter MUST pull from `https://api.osv.dev/v1/query` and `https://api.osv.dev/v1/vulns/<id>`. | MUST |
| FR-VF-3 | The GHSA adapter MUST pull from `https://api.github.com/advisories` (public, unauthenticated, rate-limited). | MUST |
| FR-VF-4 | The NVD adapter MUST be off by default and enabled with `--enable-nvd`. | MUST |
| FR-VF-5 | All adapters MUST respect `If-None-Match` / `If-Modified-Since` to enable delta updates. | MUST |
| FR-VF-6 | All adapters MUST be rate-limit-aware and back off with jittered exponential delay. | MUST |
| FR-VF-7 | The schema MUST be migratable; a `schema_version` column MUST be present. | MUST |
| FR-VF-8 | Advisory normalisation MUST map every input to a single `Advisory` dataclass. | MUST |
| FR-VF-9 | Version-range matching MUST support npm semver, PEP 440, and Maven-style ranges. | MUST |

### 5.4 Reachability

| ID | Requirement | Priority |
|----|-------------|----------|
| FR-RCH-1 | Source files MUST be parsed with `tree-sitter` using `tree-sitter-javascript`, `tree-sitter-typescript`, `tree-sitter-python`. | MUST |
| FR-RF-2 | The parser MUST skip `.git/`, `node_modules/`, `.venv/`, `venv/`, `dist/`, `build/`, `__pycache__/`, `.mypy_cache/`, `target/`, `.next/`, `.turbo/`, `coverage/`. | MUST |
| FR-RF-3 | Function definitions, arrow functions, class methods, and Python `def`/`async def` MUST be extracted as `DefSite`. | MUST |
| FR-RF-4 | Call expressions, method calls, and Python attribute calls MUST be extracted as `Edge`. | MUST |
| FR-RF-5 | Imports MUST be resolved to local files, `node_modules/<pkg>`, or `site-packages/<pkg>`. | MUST |
| FR-RF-6 | `node_modules/<pkg>` resolution MUST honour `exports` and `main` fields of the package's `package.json`. | MUST |
| FR-RF-7 | `site-packages/<pkg>` resolution MUST honour the `.dist-info/RECORD` and `top_level.txt`. | MUST |
| FR-RF-8 | Entry-point auto-detect MUST find: `package.json` `bin`, `main`, `scripts.start`; Python `__main__.py`, `console_scripts` from installed dists, FastAPI/Flask route decorators under the repo. | MUST |
| FR-RF-9 | Reachability MUST be BFS, with cycle detection, and MUST terminate in ≤ 4 s on the 50 kLOC benchmark. | MUST |
| FR-RF-10 | Unresolvable imports MUST be marked `unresolved` and excluded from reachable set. | MUST |

### 5.5 Reporting

| ID | Requirement | Priority |
|----|-------------|----------|
| FR-REP-1 | Table output MUST be colourised when stdout is a TTY, plain otherwise. | MUST |
| FR-REP-2 | Table output MUST be at most 80 columns wide by default, paginated with `--page-size`. | MUST |
| FR-REP-3 | JSON output MUST use sorted keys, no trailing whitespace, and a final newline. | MUST |
| FR-REP-4 | SARIF output MUST validate against the official JSON schema (test in CI). | MUST |
| FR-REP-5 | `depreach explain` MUST print a tree of `DefSite`s from entry point to vulnerable call. | MUST |
| FR-REP-6 | The summary footer MUST include total time, peak RSS, and packages scanned. | MUST |
| FR-REP-7 | Two consecutive reports on identical input MUST have identical SHA-256 (timestamps excluded via `freezegun` in test). | MUST |

## 6. Non-functional requirements

### 6.1 Performance

| ID | Requirement |
|----|-------------|
| NFR-P-1 | Scan a 50 kLOC repo with 300 dependencies in ≤ 60 s wall, ≤ 600 MB RSS. |
| NFR-P-2 | `depreach init` to populate the OSV+GHSA cache MUST complete in ≤ 5 min on a 100 Mbps link. |
| NFR-P-3 | `depreach scan --offline` MUST NOT make any network call (asserted in test). |

### 6.2 Reliability

| ID | Requirement |
|----|-------------|
| NFR-R-1 | `depreach self-test` MUST detect a corrupt SQLite cache and rebuild it automatically. |
| NFR-R-2 | A failing CVE adapter MUST NOT block the others; partial results are reported with `--partial-ok`. |
| NFR-R-3 | A crashing tree-sitter parser MUST log the offending file and skip it, never abort the run. |

### 6.3 Security & privacy

| ID | Requirement |
|----|-------------|
| NFR-S-1 | The binary MUST NOT initiate any network call at scan time (`--offline` is the default behaviour at scan time, with the explicit `--online` flag for advisory refresh). |
| NFR-S-2 | The binary MUST NOT read environment variables outside the documented set. |
| NFR-S-3 | The binary MUST NOT write outside the project directory and `~/.cache/depreach/`. |
| NFR-S-4 | The release artefacts MUST be cosign-signed (keyless, OIDC). |
| NFR-S-5 | The `SECURITY.md` MUST document a 90-day disclosure window. |

### 6.4 Maintainability

| ID | Requirement |
|----|-------------|
| NFR-M-1 | Every public function MUST have a docstring with parameters, return, exceptions, and example. |
| NFR-M-2 | Every public function MUST have at least one `pytest` test. |
| NFR-M-3 | No function longer than 40 lines; no file longer than 400 lines. |
| NFR-M-4 | `mypy --strict` MUST pass. |
| NFR-M-5 | `ruff check` MUST pass with the project config. |

### 6.5 Portability

| ID | Requirement |
|----|-------------|
| NFR-PORT-1 | Wheels MUST be published for `cp311-cp311`, `cp312-cp312`, `cp313-cp313` × `manylinux_2_28_x86_64`, `musllinux_1_2_x86_64`, `macosx_12.0_arm64`, `macosx_12.0_x86_64`. |
| NFR-PORT-2 | The Dockerfile MUST build on `python:3.11-slim`. |
| NFR-PORT-3 | CI MUST run on `ubuntu-latest`, `macos-latest`, `windows-latest`. |

### 6.6 Localisation

| ID | Requirement |
|----|-------------|
| NFR-L-1 | All user-facing strings MUST be in en-US. i18n is a v2 concern. |

## 7. Interface requirements

### 7.1 CLI grammar (BNF-ish)

```
depreach := ( "init" init_opts
            | "scan" PATH scan_opts
            | "explain" PATH CVE_ID
            | "self-test"
            | "--version"
            | "--license" )

init_opts := { "--offline" }

scan_opts := { "--entry" FILE [":" LINE]          ; repeatable
             , "--format" ("table"|"json"|"sarif")
             , "--all"
             , "--fail-on" ("critical"|"high"|"medium"|"low")
             , "--no-color"
             , "--debug"
             , "--enable-nvd"
             , "--partial-ok" }
```

### 7.2 JSON schema (abridged)

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "https://depreach.dev/schemas/scan-result-v1.json",
  "type": "object",
  "required": ["meta", "summary", "findings"],
  "properties": {
    "meta": {
      "type": "object",
      "required": ["tool", "version", "schema_version", "repo", "scanned_at_utc"],
      "properties": {
        "tool":            { "const": "depreach" },
        "version":         { "type": "string" },
        "schema_version":  { "const": "1.0.0" },
        "repo":            { "type": "string" },
        "scanned_at_utc":  { "type": "string", "format": "date-time" }
      }
    },
    "summary": {
      "type": "object",
      "required": ["reachable", "unreachable", "by_severity", "duration_ms", "peak_rss_bytes"],
      "properties": {
        "reachable":      { "type": "integer", "minimum": 0 },
        "unreachable":    { "type": "integer", "minimum": 0 },
        "by_severity": {
          "type": "object",
          "properties": {
            "critical": { "type": "integer" },
            "high":     { "type": "integer" },
            "medium":   { "type": "integer" },
            "low":      { "type": "integer" }
          }
        },
        "duration_ms":     { "type": "integer" },
        "peak_rss_bytes":  { "type": "integer" }
      }
    },
    "findings": {
      "type": "array",
      "items": { "$ref": "#/$defs/finding" }
    }
  },
  "$defs": {
    "finding": {
      "type": "object",
      "required": ["cve_id", "package", "ecosystem", "reachable", "confidence"],
      "properties": {
        "cve_id":      { "type": "string" },
        "package":     { "type": "string" },
        "ecosystem":   { "enum": ["npm", "pypi"] },
        "reachable":   { "type": "boolean" },
        "confidence":  { "enum": ["high", "medium", "low"] },
        "call_path":   { "type": "array", "items": { "type": "string" } },
        "fix_version": { "type": ["string", "null"] }
      }
    }
  }
}
```

### 7.3 SARIF rules

- `runs[0].tool.driver.name = "depreach"`.
- One `result` per `Finding`.
- `result.level` mapped from `Finding.confidence` and severity: `critical|high` → `error`, `medium` → `warning`, `low` → `note`.
- `result.locations[0].physicalLocation.artifactLocation.uri` is the user-repo file.
- `result.properties["cve_id"]`, `"package"`, `"confidence"` propagated.

## 8. Data definitions

| Field | Type | Source | Notes |
|-------|------|--------|-------|
| `cve_id` | str | advisory | GHSA IDs accepted in place of CVE; normalised to CVE when present. |
| `vulnerable_version_range` | str | advisory | npm semver, PEP 440, or generic interval. |
| `vulnerable_functions` | list[str] \| None | advisory | OSV `affected[].functions[].name`. None = unknown. |
| `severity` | enum | advisory | Critical / High / Medium / Low, derived from CVSS v3 when present. |
| `confidence` | enum | computed | `high` if `vulnerable_functions` intersects reachable; `low` if advisory lists no functions. |

## 9. Verification & acceptance

The release is accepted when:

1. `pip install -e .` succeeds on a clean Ubuntu 24.04 container.
2. `depreach scan examples/vulnerable-app` returns the planted 2 CVEs in the documented order in < 15 s.
3. `depreach self-test` exits 0.
4. `ruff check`, `mypy --strict src tests`, `pytest --cov` all pass with coverage ≥ 90 %.
5. `pip-licenses --allow-only <allowlist>` exits 0.
6. `docker build .` produces an image ≤ 200 MB.
7. `README.md` links resolve, demo GIF plays, AI attributions are present.
8. Two consecutive `depreach scan` runs on the same repo produce byte-identical JSON.
9. `osv-scanner -L <lockfile>` on `examples/vulnerable-app` returns ≥ 30 alerts; DepReach returns 2 reachable.

## 10. Future work (v1.1+)

- CycloneDX SBOM export (`--format cyclonedx`).
- `depreach watch` for editor integration.
- Go, Rust, Ruby, Java ecosystems.
- Container image scanning (`depreach scan oci://...`).
- GitHub Action with PR comment bot.
- `depreach baseline` to track reachable CVE count over time.
- Optional LLM-generated remediation hints, **explicitly off by default** and **strictly FOSS-licensed model** (e.g. local Mistral via Ollama).

---

*This SRS is the contract. Any change to a MUST-level requirement requires an ADR in `docs/adr/`.*
