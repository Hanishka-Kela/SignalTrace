---
name: content-engagement-audit
description: Inspect cached initial HTML for answer availability and usable continuation paths after an AI referral. Use as a bounded SignalTrace specialist; do not infer analytics or runtime failures.
license: MIT
---

# Content engagement audit

Analyze only the fetched representation and read [the shared contract](../../references/audit-contract.md). Look for directly evidenced app-shell dependence, missing answer-bearing text, inaccessible media-only facts, unsupported headings, JavaScript-only continuation, unclear next actions, unresolved out-of-stock routes, mismatched generic destinations, and main answers buried by boilerplate.

Script-to-text ratio and hydration markers are diagnostics, never standalone findings. Introductory copy is not itself defective. Do not infer bounce rate, conversions, demand, inventory accuracy, sales velocity, or broken JavaScript. Do not report a missing notification path when one is present.

Return exact excerpts or element evidence and remain within the supplied bounded task. Any additional fetch must use the entrypoint's governor.
