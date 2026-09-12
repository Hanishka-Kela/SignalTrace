---
name: citation-destination-audit
description: Trace a bounded claim-to-link-to-redirect-to-destination chain and test whether the resolved page supports the scoped entity or task. Use as SignalTrace's citation specialist, never as an unrestricted crawler.
license: MIT
---

# Citation destination audit

This is SignalTrace's primary differentiating specialist. Read [destination rules](../../references/destination-rules.md) and [the shared contract](../../references/audit-contract.md). Start from cached, observed links. Preserve the attached claim, authored URL, every permitted redirect, final URL, and supported entity/task.

Use `../../scripts/scope.py` for all entity, predicate, value, unit, plan, version, variant, region, date, operation, and source-location comparisons. Distinguish a confirmed mismatch from missing evidence. Assign responsibility precisely and never blame the site for an assistant-generated URL.

Do not treat a canonical URL difference as variant loss without conflicting resolved evidence, or a documented successor as broken. Request any allowed additional destination through the shared governor; never guess or broaden the crawl.
