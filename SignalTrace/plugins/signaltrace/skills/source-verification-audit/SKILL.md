---
name: source-verification-audit
description: Compare scoped claims against explicitly supplied external evidence sources while preserving independence and qualifiers. Use as a bounded SignalTrace specialist; never search broadly or manufacture corroboration.
license: MIT
---

# Source verification audit

## Inputs and status

This specialist is dormant on a bare URL invocation. It activates only when the caller supplies a JSON envelope containing optional `claims` and/or `sources`; it never searches broadly or invents corroboration. Without that envelope, report `not executed` coverage rather than implying that external verification was attempted.

Read [destination rules](../../references/destination-rules.md) and [the shared contract](../../references/audit-contract.md). Examine only source URLs explicitly present in the audit input and fetched by the shared governor. Use `../../scripts/scope.py` for comparison.

Preserve entity, predicate, value, unit/currency, plan, version, variant, region, date, operation, and source location. Separate two-source agreement from web-wide agreement. Treat syndicated/canonical copies as one lineage. Identify ambiguous source identity, unsupported numerical claims, and restricted, placeholder, locked, or image-only evidence.

When supplied sources cannot provide suitable independent evidence, return `not assessed` as coverage—not a finding. Never infer invisibility from search-result absence or create corroboration from unavailable evidence.
