# Sentinel

A local-first security scanner and dashboard for reviewing risk before release.

**Status:** v0.3 adds Python dependency graph import, opt-in OSV advisory lookup, OpenAPI/authentication and Docker/Compose configuration checks, and local AI evidence review. Start with [APPLICATION-REVIEW-SETUP.txt](APPLICATION-REVIEW-SETUP.txt). Original source-scanning and AI finding review remain available. All AI advice is advisory; this is a prototype, not comprehensive security validation.

## Start on your PC

Install [Node.js LTS](https://nodejs.org) (22 or newer recommended) and [Git](https://git-scm.com/downloads). Clone this repository using its **Code → HTTPS** URL, then open a terminal inside the cloned folder:

```sh
npm start
```

Open **http://localhost:3000**. Keep the terminal running; stop with Ctrl+C.

No `npm install`, Python, Docker, API key, or account is required. AI additionally requires a running local Ollama service and an installed local model. Optional web fonts fall back to system fonts offline.

**Windows:** you can also double-click `START-WINDOWS.bat`.

**macOS/Linux:** run `node server.mjs` in Terminal.

See [START-HERE.txt](START-HERE.txt) for detailed setup and troubleshooting. To download without Git, choose **Code → Download ZIP** and extract the whole archive.

## Application review (new in v0.3)

Open **Application review → Load demonstration**. To use your own environment, run `python -m pip inspect > pip-inspect.json` in that project's virtual environment and upload it with OpenAPI JSON, Dockerfile, normalized Compose JSON, and/or supported source files. Conditional requirements, missing packages, and unevaluated constraints are explicit. The graph is not runtime reachability.

The optional OSV lookup sends package names/versions to `api.osv.dev` only after consent. Findings retain advisory IDs, raw CVSS vectors, available severity labels and fixed-version entries; compatibility is not established. Failed or partial lookups remain unknown, and failed refreshes retain older results as stale evidence.

The observed-priority index is the maximum finding weight (Critical 90, High 70, Medium 40, Low 15, unknown advisory severity 35). It is a versioned triage rubric, not CVSS, EPSS, or compromise probability. Missing evidence does not become a safety claim. Application assessment/export is separate from the original source-project gate.

Ollama can review a bounded evidence bundle, cite evidence IDs, and propose relationships to investigate. Relationships remain unverified hypotheses. The model cannot change the score or gate. Run `npm run test:application:live` to check actual OSV + local model behavior with constructed sample metadata on your PC.

## Real AI review

1. Install [Ollama](https://ollama.com/download) and open it.
2. Run `ollama pull qwen2.5-coder:3b` (model download is separate from this ZIP).
3. Start Sentinel and scan `demo/unsafe-preview.js`. Old v0.1 findings require a rescan.
4. Open the finding → **AI security analyst → Check Ollama → Analyze with AI**.
5. Review cited evidence, assumptions, and the proposed replacement. **Check with scanner** runs heuristic checks on the modified excerpt only; it does not execute or syntax-check the suggestion.
6. Download the AI review JSON, review/test the real code, and rescan.

The model receives a bounded, redacted excerpt and rule metadata under a versioned system prompt. JSON output is validated; cited lines must match the input. Responses record the model/digest, prompt version, context SHA-256, timestamp, and timing. Errors are shown honestly; there is no hardcoded production fallback. Model reasoning and patches still require human review.

For a live comparison of a user-input HTML sink and a constant HTML sink, run `npm run test:ai:live`. This invokes your real local model and writes its actual outputs to `ai-evaluation-results.json`; two examples are not a general accuracy benchmark.

## What works

- Source-file upload, pasted code, and deliberately vulnerable sample repositories.
- Eight heuristic checks: SQL query construction, credential-like literals, eval, HTML assignment, TLS verification, container image/user configuration, and debug mode.
- Findings with severity, source location, explanation, and remediation guidance.
- Triage statuses, review notes, and configurable critical/high release blockers.
- SARIF 2.1.0, CycloneDX 1.5 inventory, JSON reports, and policy decisions.
- Local baselines and audit history.
- Standalone CLI and a downloadable GitHub Actions scanning template.

## Demo workflow

1. Open **New scan → Try a sample → Run scan**.
2. Open a finding to inspect its explanation and location.
3. Use **New scan → Paste source** to scan this vulnerable snippet:

```js
db.query("SELECT * FROM users WHERE id = " + req.params.id);
```

4. Open that project, choose **Rescan → Paste source**, and submit:

```js
db.query("SELECT * FROM users WHERE id = ?", [req.params.id]);
```

5. Observe the finding disappear and the project's gate pass for supported checks.
6. Export the evidence report. Remove demo projects in **Settings** before exporting real workspace data.

## CLI

Run from the repository root, quoting paths with spaces:

```sh
node dist/sentinel.mjs scan "/path/to/project"
node dist/sentinel.mjs scan "/path/to/project" --format sarif > results.sarif
node dist/sentinel.mjs scan "/path/to/project" --format sbom > sbom.json
```

Windows example:

```powershell
node dist/sentinel.mjs scan "C:\Users\you\Projects\my-app"
```

Exit codes: **0** = gate passes; **1** = gate blocked; **2** = error. CLI output does not automatically sync with the dashboard. The CLI skips symlinks, dependency/build folders, and individual files over 1 MB.

## Validation and updates

```sh
npm test
```

Thirty-one local tests pass. They cover scanner behavior, context redaction, exact citation validation, malformed/offline model responses, local HTTP boundaries, request limits, inference concurrency, unchanged release decisions, Python graphs, configuration checks, OSV response handling, and the application controller. Model-service tests use test doubles; live model quality is evaluated separately on your PC. The included GitHub Actions workflow runs syntax checks and tests on Node.js 22 and 24 under Windows, macOS, and Ubuntu. Browser verification is not complete; configured CI does not mean remote runs have passed.

To get future updates, run `git pull` inside your clone, then restart the server. Commit or stash your own edits before pulling.

## Project layout

| Path | Purpose |
| --- | --- |
| `server.mjs` | Local UI server and protected AI endpoints, bound to 127.0.0.1 |
| `lib/ai.mjs` | Ollama calls, system prompt, schema, and citation validation |
| `dist/ai-ui.js` | AI review UI, model connection, and review exports |
| `scripts/evaluate-ai.mjs` | Real-model evaluation on two illustrative cases |
| `dist/index.html` | Dashboard entry page |
| `dist/app.js` | Dashboard interactions and local state |
| `dist/style.css` | Responsive styling |
| `dist/sentinel.mjs` | Shared scanner, exporters, and CLI |
| `tests/scanner.test.mjs` | Scanner behavior tests |
| `.github/workflows/test.yml` | Cross-platform CI checks |
| `START-HERE.txt` | PC setup guide |

## Local data and limitations

Scanning runs on your device. Raw uploaded files are not persisted. Findings contain bounded, best-effort-redacted source context; AI reviews may also contain code excerpts. AI requests send that context to the local server and Ollama on this PC. Findings, review notes, policies, baselines, and the latest 300 audit events are stored in browser localStorage. Keep the same browser profile and port to retain this workspace. Clearing site data removes it. Backup export exists; backup import is not implemented.

This is a prototype, not a comprehensive security product. The original rule explanations remain clearly labeled; optional model-generated reviews are separately labeled and stored. Line-based rules can miss vulnerabilities and report false positives. Review context and test changes. A passing gate is not a security guarantee.

Not implemented: runtime dependency exploitability/reachability, live URL scanning, built-container-image scanning, SaaS toolchain connections, Docker attack execution, OpenVEX analysis, hosted team accounts, scoped API keys, runtime capture, or CLI/dashboard synchronization. OSV lookup covers known Python package advisories, not vulnerability prediction. CycloneDX output is an inventory, not a dependency vulnerability scan. The local audit history is not tamper-proof.

This repository does not depend on the original cloud workspace or its deployment identity.

API references: [Ollama chat](https://docs.ollama.com/api/chat), [local model list](https://docs.ollama.com/api/tags), [Qwen2.5 Coder model](https://ollama.com/library/qwen2.5-coder:3b).

References: [pip inspect](https://pip.pypa.io/en/stable/cli/pip_inspect/), [OSV batch API](https://google.github.io/osv.dev/post-v1-querybatch/), [OSV schema](https://ossf.github.io/osv-schema/).
