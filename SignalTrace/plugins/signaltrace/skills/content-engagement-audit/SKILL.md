---
name: content-engagement-audit
description: Inspect cached landing and sampled internal HTML for answer availability, discoverability, and usable continuation paths after an AI referral. Use as a bounded SignalTrace specialist; do not infer analytics or runtime failures.
license: MIT
---

# Content engagement audit

Analyze only cached representations and read [the shared contract](../../references/audit-contract.md). Compare the landing page with the entrypoint-selected, non-recursive internal sample. Look for directly evidenced app-shell dependence, missing answer-bearing text, inaccessible media-only facts or controls, unsupported or contradictory identity, JavaScript-only continuation, unclear actions, unusable static search forms, unresolved out-of-stock routes, listing/detail price conflicts at like scope, mismatched generic destinations, dead ends, and useful content buried by shared boilerplate.

Script-to-text ratio and hydration markers are diagnostics, never standalone findings. Introductory copy is not itself defective. Static markup cannot prove mobile or visual-design behavior. Do not infer bounce rate, conversions, demand, inventory accuracy, sales velocity, user psychology, or broken JavaScript. Do not report a missing notification path when a waitlist, notification, alternative, or relevant recovery route is present.

Return exact excerpts or element evidence and remain within the supplied bounded task. Any additional fetch must use the entrypoint's governor.
