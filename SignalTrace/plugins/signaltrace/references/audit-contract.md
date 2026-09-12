# SignalTrace audit contract

Read this reference when coordinating specialists, constructing findings, comparing claims, or validating final output.

## Authority and boundaries

SignalTrace is read-only. Fetch only public HTTP(S) URLs named by the audit input or links actually observed in cached evidence. Do not guess paths. Do not use browser automation, credentials, alternate user-agents, hostname aliases, query mutations, or retries to evade a denial. All network access belongs to the shared request governor, which invokes curl; specialist code must not open sockets or run curl directly.

Start the monotonic global deadline before DNS or network activity. A request, redirect hop, or retry consumes global and per-origin budget when it starts, whether it succeeds or fails. Check `robots.txt` before the first non-robots request to each origin. Serialize all requests to the same origin and permit no more than two simultaneous requests across different origins. A denied URL stays denied for the audit. A missing robots.txt means no published robots policy was found. SignalTrace continues only within its bounded, polite audit limits. It does not treat absence as unrestricted authorization. A timed-out, unreachable, 5xx, access-error, or unparseable robots response is `unavailable` and permits only the reduced conservative sample. A 403, 429, repeated 5xx, or explicit anti-bot page response stops further requests to that origin without being mislabeled as robots denial. Redirects are evidence and each redirect target is separately normalized, deduplicated, budgeted, and robots-checked before curl receives that target.

The visitor-journey sample is selected only from the cached target page. Prefer at most one navigation/category, product/service/detail, search or GET form action, contact/help/about, and policy/shipping/returns URL. Never recursively select links from sampled pages. Record selected, crawled, and skipped links under `coverage.journey`, including the reason for every skipped candidate retained by the evidence cap.

The small sample is deliberate, not an instruction to consume the available request or time ceiling. One page per role provides bounded role diversity while limiting load, repeated-template evidence, and exposure to slow origins; unused budget remains a safety margin for robots requests, redirects, explicitly supplied citations or sources, and `sameAs` verification. The default deadline in this package is 30 seconds and the enforced hard ceiling is 300 seconds. This checkout does not implement a 225-second scheduling freeze or a 280-second report target. Expanding toward either threshold would be a separate coverage-policy decision and must retain the same non-recursive selection, spacing, serialization, and governor limits.

For `sameAs` identity comparison, `og:site_name` is platform-level metadata and is excluded from destination identity candidates and verdict comparisons. It is not evidence about the account or channel owner. Entity-level signals such as `og:title`, `title`, `twitter:title`, `profile:username`, headings, and destination JSON-LD names remain eligible; a destination with no eligible signal is `insufficient-evidence`.

### Observed timings

Captured 2026-09-12 during bounded real-site audits:

- Mokobara collection page: approximately 10.7 seconds elapsed, 6 total requests, and 5 target-page requests.
- Myntra homepage deep link: approximately 15.2 seconds elapsed, 14 total requests, and 8 target requests.

Both runs completed well under the package's 30-second default deadline and 300-second hard ceiling. These observations cover only two small, bounded audits; neither exercised a large enough site or link-sampling volume to validate the ceiling, the sampling policy at scale, or worst-case timing behavior. They are timing observations, not a basis for changing timeout, deadline, request, or sampling constants.

## Optional delegation contract

Delegation is an optimization, never a dependency. When no subagent facility exists, run every specialist locally against the same cached evidence. If delegation exists, create a specialist only for a concrete missing evidence dependency: one selected final destination, one named external source, one linked policy page, or one alternate representation. A finding by itself is not a reason to delegate, and ordinary analysis always uses the cache.

Every delegated task must contain `task_identifier`, `cached_evidence_references`, `permission_status`, `remaining_global_request_budget`, `remaining_per_origin_budget`, `remaining_time`, `maximum_additional_requests`, and `cancellation_deadline`. Default `maximum_additional_requests` to zero and cap it at one for a concrete evidence dependency. Give the worker analysis data, not crawl authority, and never let it choose a URL or user-agent. A worker may not call curl, built-in fetch, `urllib`, or another network tool. The entrypoint executes any explicitly granted request through its governor and returns the resulting cache reference; the worker still does not fetch directly.

Keep local work running while independent tasks execute. Never schedule two network fetches to the same origin concurrently. At the cancellation deadline, cancel or ignore unfinished work, emit no finding based on partial output, and append the task identifier to `coverage.checks_unresolved`. Never wait indefinitely.

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

## Evidence and behavioral interpretation

Static HTML, HTTP responses, redirects, and structured representations can establish observable structural and content conditions. They cannot establish actual abandonment, confusion, bounce rate, conversion loss, visual attractiveness, whether visitors dislike a design, or whether a change will increase sales. Those outcomes require browser or user testing, analytics, or controlled experiments.

Keep the direct observation separate from interpretation. Every serialized result preserves its URL, source representation, exact observed evidence, performed check, and what was not verified. Plausible consequences belong only in cautious opportunity rationale; never present them as measured outcomes. Do not infer demographics, revenue, customer behavior, visual quality, or JavaScript-generated behavior from static source.

A malformed representation, HTTP failure, broken link, same-scope contradiction, or unrelated redirect may be a confirmed finding because the fetched evidence directly demonstrates it. An absent optional feature, label, continuation, recovery route, prominence signal, or readable media equivalent is a suggested opportunity unless a separate confirmed-defect rule directly applies.

## Finding contract

Every emitted finding has non-empty `id`, `title`, `severity`, `confidence`, `evidence`, `affected_url`, `evidence_type`, `responsible_party`, `impact`, `suggested_action`, `priority`, and `coverage_status`, plus `is_finding: true`. Allowed severities are `Critical`, `High`, and `Medium`; confidence is a number from 0 through 1. Evidence should identify an exact block, property, link text, redirect hop, or extracted passage.

Deduplicate by normalized affected URL plus underlying defect and scope. When one missing qualification appears in a table, summary, and passage, merge those observations into one finding. Keep the strongest directly supported severity and combine distinct evidence.

## Final report

Emit exactly one object with `site`, RFC 3339 UTC `audited_at`, `summary`, `coverage`, `findings`, and `suggested_actions`. Findings are directly established defects, use `is_finding: true`, and retain their own remediation field. Top-level `suggested_actions` contains only evidence-backed improvement opportunities with `is_finding: false`; it is never a projection of findings. Each opportunity uses priority `low`, `medium`, or `high`; category `positioning`, `discoverability`, `engagement`, `navigation`, `trust`, `content-clarity`, or `availability`; an evidence source of `initial HTML`, `sampled internal page`, `redirect chain`, or `robots.txt`; and confidence `certain` or `likely`. Positioning opportunities additionally carry candidate use-case and audience hypotheses plus grouped copy variants; their `evidence.observed` is an array of exact, located observations. Each serialized evidence object records `check_performed` and `not_verified`, and `coverage.behavioral_impact` states that behavioral outcomes were not measured. Consolidate the same check family and root cause across pages into one systemic opportunity with deterministically ordered per-page evidence; keep different checks or causes separate. Then sort high, medium, low, and stable rule ID. Partial or denied audits still return both arrays and explicit `checks_unresolved` coverage.
