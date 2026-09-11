---
name: audit-entrypoint
description: Run a complete read-only SignalTrace audit of a public website URL and emit one evidence-backed JSON report. This is the only marketplace entrypoint; use it for end-to-end audits rather than isolated specialist interpretation.
---

# SignalTrace audit entrypoint

Start the global deadline before any DNS or HTTP work. Read [the audit contract](../../references/audit-contract.md), then run `python3 ../../scripts/signaltrace.py <URL>` from this skill directory, or resolve that script to an absolute path first. If the harness supplies an input envelope, pipe that JSON object to stdin and do not add guessed targets.

The script is the authority for robots decisions, request budgets, concurrency, timeouts, redirect handling, body limits, URL deduplication, evidence caching, scope comparison, finding deduplication, severity, and final serialization. Do not perform side-channel network requests around it.

Specialists receive cached evidence first. If delegating beyond the bundled runner, give each specialist a bounded task containing permission status, remaining request budget, remaining deadline, and a maximum additional-request count. Additional evidence must be requested through the same governor. Continue useful local parsing while independent bounded checks run.

Return the runner's single stdout JSON object unchanged. Do not wrap it in prose or emit intermediate JSON documents. A robots denial, exhausted budget, timeout, or absent independent source is coverage state, not permission to speculate.
