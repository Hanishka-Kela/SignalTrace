---
name: improvement-opportunity-audit
description: Identify evidence-backed improvements for AI discoverability and visitor engagement without treating absent optional features as defects.
license: MIT
---

# Improvement opportunity audit

Use only the cached HTML, headers, extracted elements, and permission evidence already fetched by `audit-entrypoint`. Do not crawl independently or request additional URLs. Produce deterministic recommendations for the entrypoint's `suggested_actions` array, each tied to a concrete observation and marked `is_finding: false`.

An opportunity is not proof of failure. Do not call missing optional metadata a defect unless a separate finding rule directly establishes impact. Do not infer analytics, conversion rates, revenue, inventory truth, user demographics, rankings, traffic, or demand.

Recommend conservative, domain-general improvements only when cached evidence supports the applicable rule: machine-readable entity metadata, visible equivalents for media facts, terminology alignment, earlier answer-bearing content, unavailable-state recovery, freshness signals, clear continuation paths, or concise attribute-oriented content. Return no recommendation when the required observation is absent.
