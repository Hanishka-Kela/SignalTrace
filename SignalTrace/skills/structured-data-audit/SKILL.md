---
name: structured-data-audit
description: Inspect cached public HTML for structured-data validity, feature-minimum properties, entity identity, and like-scope agreement. Use as a bounded SignalTrace specialist, not as an independent crawler.
license: MIT
allowed-tools: [python]
---

# Structured data audit

Use cached evidence supplied by `audit-entrypoint`. Read [structured data rules](../references/structured-data-rules.md) and [the shared contract](../references/audit-contract.md). Analyze JSON-LD block-by-block, including arrays and `@graph`, plus observed Microdata and RDFa.

Use the shared `normalize_scope`/`compare_scopes` implementation in `../scripts/scope.py` for any agreement claim. Identify the exact block, node type, property, and visible evidence. Do not require optional fields, treat missing JSON-LD as automatically severe, downgrade valid Microdata/RDFa, or imply guaranteed AI citation.

Return observations only within the bounded task. Network evidence, if genuinely required, must go through the entrypoint's shared governor and explicit allowance.
