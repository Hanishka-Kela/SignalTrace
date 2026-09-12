# SignalTrace audit contract

Read this reference when coordinating specialists, constructing findings, comparing claims, or validating final output.

## Authority and boundaries

SignalTrace is read-only. Fetch only public HTTP(S) URLs named by the audit input or links actually observed in cached evidence. Do not guess paths. Do not use browser automation, credentials, alternate user-agents, hostname aliases, query mutations, or retries to evade a denial. All network access belongs to the shared request governor; specialist code must not open sockets directly.

Start the monotonic global deadline before DNS or network activity. A request consumes global and per-origin budget when it starts, whether it succeeds or fails. Check `robots.txt` before the first non-robots request to each origin. Serialize all requests to the same origin. A denied URL stays denied for the audit. Redirects are evidence and each redirect target is separately normalized, deduplicated, budgeted, and robots-checked.

## Optional delegation contract

Delegation is an optimization, never a dependency. When no subagent facility exists, run every specialist locally against the same cached evidence. If delegation exists, create a specialist only for a concrete missing evidence dependency: one selected final destination, one named external source, one linked policy page, or one alternate representation. A finding by itself is not a reason to delegate, and ordinary analysis always uses the cache.

Every delegated task must contain `task_identifier`, `cached_evidence_references`, `permission_status`, `remaining_global_request_budget`, `remaining_per_origin_budget`, `remaining_time`, `maximum_additional_requests`, and `cancellation_deadline`. Give the worker analysis data, not crawl authority. A worker may not call curl, built-in fetch, `urllib`, or another network tool. If one extra request is explicitly granted, the entrypoint executes it through its governor and returns the resulting cache reference; the worker still does not fetch directly.

Keep local work running while independent tasks execute. Never schedule two network fetches to the same origin concurrently. At the cancellation deadline, cancel or ignore unfinished work, emit no finding based on partial output, and append the task identifier to both `coverage.checks_unresolved` and its compatibility alias `coverage.unresolved_checks`. Never wait indefinitely.

## Claim scope

The single shared scope primitive normalizes these fields:

`entity`, `predicate`, `value`, `unit`, `plan`, `version`, `variant`, `region`, `date`, `operation`, `source_location`.

It returns exactly one of `compatible`, `conflicting`, `ambiguous`, or `insufficient-evidence`. A different entity or predicate is insufficient evidence, a missing qualification on either side is ambiguous, and only fully aligned scope may be called compatible or conflicting. Never collapse region, version, plan, variant, date, operation, currency, or unit.

## Severity

- **Critical:** a directly established defect blocks the complete, explicitly scoped primary task.
- **High:** a confirmed wrong destination or same-scope contradiction changes eligibility, price, compatibility, availability, or identity.
- **Medium:** a confirmed localized representation defect impairs a supported answer or search feature but leaves a usable route.
- **No finding:** proactive improvement, deliberate restriction, incomplete evidence, unresolved dynamic state, or unsupported hypothesis.

Do not emit a finding for the last category. Record it in `coverage.checks_unresolved` when useful.

## Finding contract

Every emitted finding has non-empty `id`, `title`, `severity`, `confidence`, `evidence`, `affected_url`, `evidence_type`, `responsible_party`, `impact`, `suggested_action`, `priority`, and `coverage_status`. Allowed severities are `Critical`, `High`, and `Medium`; confidence is a number from 0 through 1. Evidence should identify an exact block, property, link text, redirect hop, or extracted passage.

Deduplicate by normalized affected URL plus underlying defect and scope. When one missing qualification appears in a table, summary, and passage, merge those observations into one finding. Keep the strongest directly supported severity and combine distinct evidence.

## Final report

Emit exactly one object with `site`, RFC 3339 UTC `audited_at`, `summary`, `coverage`, `findings`, and `suggested_actions`. `suggested_actions` is a deduplicated priority-ordered projection of finding actions. Partial or denied audits still return the schema with explicit unresolved coverage.
