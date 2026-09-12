# SignalTrace

SignalTrace is a read-only website audit marketplace for diagnosing AI discoverability
and visitor-engagement problems from bounded public web evidence.

It respects `robots.txt`, uses curl-only HTTP requests, applies shared request limits,
and never modifies the audited website.

## Skills

- **audit-entrypoint** — Coordinates the complete audit and emits one JSON report.
- **structured-data-audit** — Checks JSON-LD, Microdata, RDFa, entity identity, and
  structured-data consistency.
- **content-engagement-audit** — Checks readable content, navigation, controls,
  continuation paths, product facts, and static engagement risks.
- **citation-destination-audit** — Verifies supplied citation and `sameAs` destinations,
  redirects, identity matches, dead links, and parked pages.
- **source-verification-audit** — Compares explicitly supplied claims with fetched
  independent sources while preserving scope and qualifiers.
- **improvement-opportunity-audit** — Suggests evidence-grounded improvements for
  positioning, headings, audience/use-case clarity, search language, and engagement.
  Suggestions are not treated as confirmed defects.

## Composition

The evaluator invokes `audit-entrypoint`. It:

1. Parses the supplied URL or JSON input.
2. Fetches and evaluates `robots.txt`.
3. Fetches the target page using the shared request governor.
4. Selects a small, deterministic set of same-origin journey links.
5. Runs the specialist analyses over cached evidence.
6. Composes one report containing `findings` and `suggested_actions`.
7. Emits the report as JSON on standard output.

The audit intentionally analyzes the raw HTML payload returned by the server. This is
the baseline representation available to lightweight crawlers and AI retrieval systems.
It does not execute JavaScript, launch a browser, or claim to reproduce a fully rendered
browser experience. It also does not use analytics, scrape social feeds, or modify a
live website.

## Run

```bash
python3 scripts/signaltrace.py https://example.com
