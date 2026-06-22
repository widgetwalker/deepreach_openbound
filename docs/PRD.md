# DeepReach — Product Requirements Document (PRD)

**Owner:** UNBOUND '26 Team · **Track:** Open Innovation · **License:** MIT · **Status:** v0.1.0-draft

---

## 1. Summary

DepReach is a command-line tool that scans a Node or Python repository and reports only the **CVEs that are actually reachable from the application's entry points**, instead of the hundreds of "critical" alerts that `npm audit`, `pip-audit`, and `osv-scanner` produce. Each reachable verdict cites a `file:line` in the user's own code, so the developer can fix the real exposure in minutes rather than chasing ghosts for a weekend.

## 2. Problem

Modern SCA (software composition analysis) tools answer *"is a vulnerable version of this package in my lockfile?"* and stop there. The result is a flood of "critical" findings for code paths that never run:

- A solo dev with `axios < 1.6.0` in a 12-package backend gets a `CRITICAL` CVE banner and reads the advisory. Two hours later they discover it's a CSRF bug in the browser build that their server never imports.
- A Python team gets a Pillow CVE for an image format their CLI never processes.
- An OSS maintainer of a tiny library gets a Dependabot storm on transitive deps they cannot upgrade without breaking the public API.

The cognitive cost is the same as a real vulnerability. The two are indistinguishable in a 4 000-row scan report. **DepReach's job is to make them distinguishable.**

## 3. Target user

| Persona | Description | Pain |
|---------|-------------|------|
| **Solo backend dev (Node or Python)** | 1–3 person team, 1–50 kLOC, ships weekly | Spends half a Saturday per CVE storm reading advisories. |
| **OSS maintainer of a library** | 100+ reverse-deps, low time budget | Receives panic issues on every transitive CVE; needs a clean "we don't reach that code" answer. |
| **Security-curious eng lead at a small startup** | 5–30 engineers, no dedicated AppSec hire | Needs a 1-line CI gate: "fail the build if any reachable CVE is open." |
| **Hackathon judge / conference reviewer** | Curious, skeptical, has 90 seconds | Wants a colourful TUI that *demonstrates* the win, not a wall of JSON. |

## 4. Goals (success criteria, measurable)

| # | Goal | Metric | Target |
|---|------|--------|--------|
| G1 | Reachability precision on a hand-tagged corpus of 50 real-world repos | `(reachable ∩ real) / reachable` | ≥ 0.80 |
| G2 | Reachability recall on the same corpus | `(reachable ∩ real) / real` | ≥ 0.65 |
| G3 | Wall-clock time on a 50 kLOC repo with 300 deps, cold cache | `time depreach scan <repo>` | ≤ 60 s |
| G4 | Peak RSS on the same workload | `/usr/bin/time -v` | ≤ 600 MB |
| G5 | Cold-start to first report on a 2018 laptop (4 GB RAM, no SSD) | end-to-end | ≤ 60 s |
| G6 | CLI clarity | users complete the demo in under 90 s with no docs | ≥ 8 / 10 in usability test |
| G7 | FOSS compliance | `pip-licenses --allow-only <allowlist>` | 0 violations |
| G8 | Determinism | SHA-256 of two consecutive reports | equal |

## 5. Non-goals (explicit YAGNI for v1)

1. Web UI, REST API, GraphQL, gRPC.
2. VS Code or JetBrains extension.
3. Real-time file watcher (`depreach watch`).
4. Auto-fix or PR-bot.
5. SBOM export in v1 (planned v1.1 as `--format cyclonedx`).
6. Languages other than Node (JS + TS) and Python in v1.
7. Container-image scanning, IaC scanning, secrets scanning.
8. Cloud SaaS, multi-tenant, team dashboards.
9. AI/LLM-generated remediation advice (would violate FOSS-only runtime and determinism).
10. Telemetry, crash reporting, auto-updates.

## 6. User stories

| ID | As a … | I want to … | So that … |
|----|--------|--------------|-----------|
| US-1 | solo dev | run `depreach scan ./my-app` and see only the CVEs I can actually reach | I spend 10 min triaging, not 10 hours |
| US-2 | solo dev | pass `--entry src/server.ts:42` to anchor reachability on a single handler | I can audit one route before merging |
| US-3 | solo dev | pipe JSON into `jq` to filter by severity or file | I can drop DepReach into a custom triage script |
| US-4 | OSS maintainer | cite DepReach's "no reachable CVE" verdict in a GitHub issue | I can stop the panic-thread with evidence |
| US-5 | eng lead | run DepReach in CI with `--fail-on high` | my build fails before shipping a reachable high |
| US-6 | eng lead | upload SARIF to GitHub code-scanning | security findings land in the PR review |
| US-7 | eng lead | run `depreach explain CVE-2024-1234` to see the call path | I can show the auditor exactly what fires |
| US-8 | maintainer | run `depreach self-test` to verify the tool itself | I trust the binary I ship |
| US-9 | judge | run `depreach scan examples/vulnerable-app` | I see the win in 30 seconds |
| US-10 | anyone | run `depreach --license` | I see every third-party licence in one shot |

## 7. Functional requirements (full list lives in `SRS.md`)

| ID | Requirement |
|----|-------------|
| FR-1 | Detect npm (lockfile v1/v2/v3), pnpm-lock.yaml, yarn.lock (classic + berry), pip (requirements.txt + resolved), poetry.lock, uv.lock |
| FR-2 | Pull advisories from OSV.dev (default-on), GHSA (default-on), NVD (feature-flagged) |
| FR-3 | Cache advisories locally in SQLite at `~/.cache/depreach/vulns.db` |
| FR-4 | Parse JS, TS, Python source with tree-sitter, skip `node_modules/`, `.venv/`, `dist/`, `build/` |
| FR-5 | Build a call graph of all function defs and call sites |
| FR-6 | Resolve imports to local files and `node_modules/<pkg>` or `site-packages/<pkg>` |
| FR-7 | Accept a `--entry FILE[:LINE]` flag, defaulting to auto-detected entry points |
| FR-8 | BFS the call graph from entry points to a "reachable" set |
| FR-9 | Cross-reference reachable set against advisory.vulnerable_functions |
| FR-10 | Emit a colourised table, sorted JSON, and SARIF 2.1.0 |
| FR-11 | Provide `depreach explain <CVE-ID>` showing the call path that triggered it |
| FR-12 | Provide `depreach self-test` running the golden-file suite |
| FR-13 | Map exceptions to stable exit codes 0/1/2/3/4 |
| FR-14 | Ship under MIT with a `NOTICE` listing every third-party licence |

## 8. Distribution

- **Primary**: source distribution via `pip install depreach` from PyPI.
- **Source**: `git clone` + `uv sync` + `uv run depreach`.
- **Container**: `docker run --rm -v $PWD:/scan depreach/depreach scan /scan` (image ≤ 200 MB).
- **CI snippet**: a `depreach-action` GitHub Action, in-tree at `.github/actions/depreach`.
- **No** Homebrew formula in v1, no snap, no AUR (YAGNI; 14 days is short).

## 9. Pricing

Free. MIT. No premium tier. No "team plan." No usage limits. The tool has no network dependency at runtime (only at `depreach init` time to populate the cache).

## 10. Risks & mitigations

| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|------------|
| tree-sitter language packs break across versions | Medium | High | pin `tree-sitter==0.21.x` and language `>=0.21,<0.23`; CI installs the exact pinned wheels |
| OSV.dev schema drift | Low | Medium | adapter unit tests against pinned golden JSON; fail loudly on unknown fields |
| Lockfile format churn (e.g. yarn berry PnP) | Medium | Medium | adapter smoke test on the latest 3 yarn minor versions in CI |
| Reachability false negatives cause user to ignore a real CVE | Low | **Catastrophic** | always show the *unreachable* set behind a `--all` flag; warn in the table footer; default exit code does **not** pass CI on unreachable criticals |
| Performance budget blown on a 200 kLOC monorepo | Medium | Medium | per-stage timing in `--profile json`; document the limit; defer the fix to v1.1 with sharded analysis |
| 14-day scope creep | High | High | the 14-day schedule in MASTER_PROMPT §14 is the contract; any feature past day 14 lands in v1.1 |
| License violation in a transitive dep | Low | **Disqualifying** | `pip-licenses` allowlist enforced in CI; weekly Dependabot PRs reviewed same-day |

## 11. Success metric for the hackathon itself

A 5-minute live demo that:

1. Starts on an empty terminal.
2. `pip install depreach` (cached in advance).
3. `depreach scan examples/vulnerable-app`.
4. Shows: "2 reachable CVEs, here's the call path to each, here's the line in your code, here's the fix version."
5. Asks `osv-scanner --lockfile=off` on the same app, shows the 38-alert flood.
6. End on the screen: "Same repo. 38 alerts → 2. 94% noise removed."

The "before / after" diff is the entire pitch.

## 12. Out-of-scope for the demo (defer to "what's next")

- Multi-language support (Go, Rust, Ruby).
- Container image scanning.
- Cloud-hosted SaaS.
- Editor integration.

## 13. Approval

| Role | Name | Date |
|------|------|------|
| Product | _TBD_ | _TBD_ |
| Engineering | _TBD_ | _TBD_ |
| FOSS Compliance | _TBD_ | _TBD_ |

---

*Companion documents: `SRS.md` (engineering spec), `ARCHITECTURE.md` (component design), `WINNING_STRATEGY.md` (judge narrative), `MASTER_PROMPT.md` (execution contract).*
