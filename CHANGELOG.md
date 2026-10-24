# Changelog

## 0.3.0 — Application evidence review

- Python pip-inspect dependency graph with explicit conditional/missing relationships.
- Consent-gated OSV version lookup, pagination, advisory detail links and partial/failure handling.
- OpenAPI declarations, JWT verification source patterns, Dockerfile and Compose JSON checks.
- Deterministic observed-priority rubric, coverage fields, and separate application decision.
- Local AI review with validated evidence IDs and explicitly unverified relationship hypotheses.
- Application JSON and dependency-graph CycloneDX export; constructed demo inputs.
- 31 passing automated checks and an optional real OSV/model evaluation script.
- Live external integration and browser QA still require verification on the target PC.

## 0.2.0 — Local AI contextual review

- Added actual Ollama chat inference for individual scanner findings.
- Added bounded source context capture and best-effort credential redaction.
- Added a versioned system prompt and structured response schema.
- Validate quoted source lines and exact replacement snippets against the input.
- Display contextual assessments, assumptions, proposed code, and developer verification steps.
- Record model identity, model digest, prompt version, context hash, and inference timing in exported reviews.
- Check proposed replacements with the existing rules on a copy of the captured excerpt; no code execution or automatic release approval.
- Added local model discovery, offline/error handling, request limits, same-origin checks, and one-inference-at-a-time behavior.
- Added 12 AI and server tests, for 16 total passing local tests.
- Added demonstration source files and a live-model evaluation script.

AI model weights are downloaded separately through Ollama. Automated model-service tests use test doubles. Live inference and browser QA must still be verified on the user's PC.

## 0.1.0 — Portable baseline

- Local dashboard and standalone CLI with eight heuristic rules.
- Finding review and triage, release policies, baselines, and local audit history.
- SARIF, CycloneDX inventory, findings JSON, and policy exports.
- Windows/macOS/Linux launchers and dependency-free local server.
- Four scanner tests and a cross-platform GitHub Actions test workflow.
