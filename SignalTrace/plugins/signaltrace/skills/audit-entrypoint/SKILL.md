---
name: audit-entrypoint
description: Run a complete read-only SignalTrace audit of a public website URL and emit one evidence-backed JSON report. This is the only marketplace entrypoint; use it for end-to-end audits rather than isolated specialist interpretation.
---

# SignalTrace audit entrypoint

Start the global deadline before any DNS or HTTP work. Read [the audit contract](../../references/audit-contract.md) and [bot-directive rules](../../references/bot-directives.md), then run `python3 ../../scripts/signaltrace.py <URL>` from this skill directory, or resolve that script to an absolute path first. If the harness supplies an input envelope, pipe that JSON object to stdin and do not add guessed targets.

The script is the authority for robots and bot-directive decisions, request budgets, concurrency, timeouts, redirect handling, body limits, URL deduplication, evidence caching, scope comparison, finding deduplication, severity, and final serialization. Its governor is the only component allowed to execute curl. Do not perform side-channel network requests around it.

Specialists receive cached evidence first, and the complete audit must work with no delegation facility. If host delegation is available, read the optional delegation contract in [the audit contract](../../references/audit-contract.md). Delegate only a specific evidence dependency, never a finding or unrestricted crawl. Include the task identifier, cache references, permission status, remaining global and per-origin budgets, remaining time, maximum additional requests, and cancellation deadline. Workers never fetch directly; the entrypoint performs an explicitly granted request through its governor. Continue local parsing while independent bounded analysis runs, serialize same-origin network work, and cancel or ignore late output without turning it into a finding.

Return the runner's single stdout JSON object unchanged. Do not wrap it in prose or emit intermediate JSON documents. A robots denial, exhausted budget, timeout, or absent independent source is coverage state, not permission to speculate.
