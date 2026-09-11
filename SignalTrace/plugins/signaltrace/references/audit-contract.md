# SignalTrace audit contract

Read this reference when coordinating specialists, constructing findings, comparing claims, or validating final output.

## Authority and boundaries

SignalTrace is read-only. Fetch only public HTTP(S) URLs named by the audit input or links actually observed in cached evidence. Do not guess paths. Do not use browser automation, credentials, alternate user-agents, hostname aliases, query mutations, or retries to evade a denial. All network access belongs to the shared request governor; specialist code must not open sockets directly.

Start the monotonic global deadline before DNS or network activity. A request consumes budget when it starts, whether it succeeds or fails. Check `robots.txt` before the first non-robots request to each origin. A denied URL stays denied for the audit. Redirects are evidence and each redirect target is separately normalized, deduplicated, budgeted, and robots-checked.

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
