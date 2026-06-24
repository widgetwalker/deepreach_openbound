# DeepReach - Winning Strategy & 5-Minute Demo Script

This guide outlines the recommended narrative, demo workflow, and talking points for recording the **5-minute working prototype video** required by the jury.

---

## 🎯 The Jury Narrative (The "Alert Fatigue" Angle)

1.  **The Hook (0:00 - 1:00)**: Start with the pain. Standard SCA scanners (`npm audit`, `pip-audit`) flag *everything* that's vulnerable in the dependency tree, leading to massive alert fatigue. Explain that **90%+ of these alerts are false positives** because the application never actually executes or imports the vulnerable functions.
2.  **The Solution (1:00 - 1:45)**: Introduce **DeepReach**. It is a FOSS command-line tool that performs AST-level static analysis (using `tree-sitter`) to resolve dependency trees and trace if code paths can actually reach the vulnerability.
3.  **The Demo (1:45 - 4:00)**: Show it working live on both Node.js and Python projects. Show how it filters out unreachable alerts, leaving developers with only the active threats to fix.
4.  **Under the Hood & FOSS Values (4:00 - 4:30)**: Highlight the offline-first architecture, no proprietary APIs, no telemetry, and MIT license compliance.
5.  **Conclusion & Call to Action (4:30 - 5:00)**: Summarize how DeepReach makes security actionable for dev teams today.

---

## 🎬 5-Minute Screen Recording Script

Here is the exact step-by-step terminal walkthrough for the video recording.

### Part 1: Installation & Setup (1:00)
Show how fast and clean it is to set up:

```bash
# 1. Activate environment and install DeepReach
pip install -e .

# 2. Populate the local SQLite vulnerability cache
python -m deepreach init
```
*   **What to say**: *"DeepReach is fully offline-first. Running `deepreach init` downloads open-source vulnerability feeds from OSV.dev and indexes them into a local SQLite cache. All subsequent scans require zero network connectivity, making it secure and fast."*

### Part 2: Running a Scan (1:30)
Run the scan on the bundled example application:

```bash
# 3. Scan the vulnerable Python application
python -m deepreach scan examples/vulnerable-app/python
```
*   **What to say**: *"Let's scan our vulnerable Python sample app. Notice that DeepReach scans the requirements.txt, builds the AST call graph using tree-sitter, and generates a color-coded table. It lists the CVE, the package, and the exact reachability status. It shows that although multiple packages are vulnerable, only specific CVEs are actually reachable."*

### Part 3: Explaining the Reachability Path (1:00)
Demonstrate the explain feature to prove the reachability claim:

```bash
# 4. Query the exact reachability call-path for a CVE
python -m deepreach explain examples/vulnerable-app/python CVE-2023-30720
```
*   **What to say**: *"We don't make hand-wavy claims. By running `deepreach explain`, developers get a complete, file-and-line call-trace starting from the entry point of their codebase all the way to the vulnerable dependency's function definition."*

### Part 4: CI/CD Formats & Custom Entry Points (1:00)
Show how it integrates with automated pipelines:

```bash
# 5. Output in machine-readable formats for security tooling
python -m deepreach scan examples/vulnerable-app/python --format json
python -m deepreach scan examples/vulnerable-app/python --format sarif

# 6. Run the CLI self-test suite
python -m deepreach self-test
```
*   **What to say**: *"For automation, DeepReach outputs standard JSON and SARIF 2.1.0, making it plug-and-play with GitHub Code Scanning, IDE viewers, and CI gates. And the `self-test` command lets developers run verification tests directly in the field."*

---

## 💡 Recording Tips

*   **Resolution**: Record in 1080p. Keep your terminal font size large enough to be easily readable on mobile screens.
*   **Audio**: Use a clear microphone and minimize background noise.
*   **Keep it moving**: Avoid dead silence. Explain what is happening while the scanner runs (which takes less than 2 seconds!).
