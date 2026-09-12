---
name: improvement-opportunity-audit
description: Identify evidence-backed improvements for AI discoverability and visitor engagement without treating absent optional features as defects.
license: MIT
allowed-tools: [python]
---

# Improvement opportunity audit

Use only the cached HTML, headers, extracted elements, and permission evidence already fetched by `audit-entrypoint`. Do not crawl independently or request additional URLs. Produce deterministic recommendations for the entrypoint's `suggested_actions` array, each tied to a concrete observation and marked `is_finding: false`.

An opportunity is not proof of failure. Do not call missing optional metadata a defect unless a separate finding rule directly establishes impact. Do not infer analytics, conversion rates, revenue, inventory truth, user demographics, rankings, traffic, or demand.

Static HTML analysis identifies only observable risks and improvement opportunities; it does not prove actual user confusion, abandonment, bounce rate, conversion loss, usability, visual-design quality, dislike, or sales impact. Describe the fetched evidence and the possible improvement, keep plausible consequences cautious, and prohibit unsupported behavioral conclusions. Preserve the performed check and explicitly state that behavioral impact was not verified. Before recommending a control label, check direct text, `aria-label`, resolvable `aria-labelledby`, associated and wrapping labels, `title`, an appropriate input placeholder, common visually hidden text, and deterministically associated fieldset or surrounding-heading context. Suppress the recommendation when any supported mechanism supplies a name.

Recommend conservative, domain-general improvements only when cached evidence supports the applicable rule: machine-readable entity metadata, visible equivalents for media facts, terminology alignment, earlier answer-bearing content, concrete value propositions, descriptive navigation, usable search forms, labeled controls, unavailable-state recovery, freshness and trust signals, clear detail-page continuation, or concise attribute and comparison content. Compare cached listing and detail representations only at like entity and commercial scope. Return no recommendation when the required observation is absent.

For product-positioning analysis, extract only facts actually present in cached title, headings, descriptions, category labels, controls, links, visible text, and structured data. Preserve the URL, source location, exact text, normalized value, and confidence for every observation used. Candidate audiences and use cases are hypotheses based on combinations of those attributes, not verified demographics or customer behavior. Generate headlines, taglines, category labels, and search phrases only from observed facts. A missing tagline alone is never a finding, and generated copy is a recommendation rather than a performance claim.

Use only the categories `positioning`, `discoverability`, `engagement`, `navigation`, `trust`, `content-clarity`, and `availability`. Evidence sources are `initial HTML`, `sampled internal page`, `redirect chain`, or `robots.txt`. Group repeated observations by stable rule ID and normalized evidence URL, preserve distinct evidence in that group, and scope colliding final IDs deterministically by page role or normalized URL. Never emit one recommendation per individual empty control. Negative controls: emit no audience hypothesis without use-case evidence; require explicit trail attributes for trail positioning and explicit work context for office-commuter positioning; suppress the gap when prominent communication already states the supported use case and attributes; never infer a price tier from a lone price. Never claim that a competitor performs better unless explicitly supplied competitor evidence was fetched and compared at like scope.
