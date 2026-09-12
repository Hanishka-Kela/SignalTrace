---
name: improvement-opportunity-audit
description: Identify evidence-backed improvements for AI discoverability and visitor engagement without treating absent optional features as defects.
license: MIT
---

# Improvement opportunity audit

Use only the cached HTML, headers, extracted elements, and permission evidence already fetched by `audit-entrypoint`. Do not crawl independently or request additional URLs. Produce deterministic recommendations for the entrypoint's `suggested_actions` array, each tied to a concrete observation and marked `is_finding: false`.

An opportunity is not proof of failure. Do not call missing optional metadata a defect unless a separate finding rule directly establishes impact. Do not infer analytics, conversion rates, revenue, inventory truth, user demographics, rankings, traffic, or demand.

Recommend conservative, domain-general improvements only when cached evidence supports the applicable rule: machine-readable entity metadata, visible equivalents for media facts, terminology alignment, earlier answer-bearing content, concrete value propositions, descriptive navigation, usable search forms, labeled controls, unavailable-state recovery, freshness and trust signals, clear detail-page continuation, or concise attribute and comparison content. Compare cached listing and detail representations only at like entity and commercial scope. Return no recommendation when the required observation is absent.

Use only the categories `discoverability`, `engagement`, `navigation`, `trust`, `content-clarity`, and `availability`. Evidence sources are `initial HTML`, `sampled internal page`, `redirect chain`, or `robots.txt`. Deduplicate by stable rule ID plus evidence URL. Never claim that a competitor performs better unless explicitly supplied competitor evidence was fetched and compared at like scope.
