---
name: source-verification-audit
description: Compare scoped claims against explicitly supplied external evidence sources while preserving independence and qualifiers. Use as a bounded SignalTrace specialist; never search broadly or manufacture corroboration.
license: MIT
---

# Source verification audit

Read [destination rules](../../references/destination-rules.md) and [the shared contract](../../references/audit-contract.md). Examine only source URLs explicitly present in the audit input and fetched by the shared governor. Use `../../scripts/scope.py` for comparison.

Preserve entity, predicate, value, unit/currency, plan, version, variant, region, date, operation, and source location. Separate two-source agreement from web-wide agreement. Treat syndicated/canonical copies as one lineage. Identify ambiguous source identity, unsupported numerical claims, and restricted, placeholder, locked, or image-only evidence.

When no suitable independent source exists, return `not assessed` as coverage—not a finding. Never infer invisibility from search-result absence or create corroboration from unavailable evidence.
