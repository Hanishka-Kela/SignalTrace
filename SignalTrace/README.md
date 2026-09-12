# SignalTrace

Read-only, evidence-backed auditor for AI discoverability and on-site
engagement problems. Given a public URL, it fetches the page and a bounded,
robots-aware sample of internal links (via `curl` only — no browser
rendering, no third-party packages) and emits one JSON report of confirmed
findings plus suggested, non-destructive improvements. It never modifies the
target site.

## Skills

- **`audit-entrypoint`** *(entrypoint)* — Runs the audit end-to-end: fetches
  the target, selects a small deterministic sample of internal links, and is
  the only skill allowed to make network requests. It calls each specialist
  below against the cached evidence and assembles their output into one
  report.

- **`structured-data-audit`** — Checks JSON-LD, Microdata, and RDFa for
  validity, required fields, and consistent entity identity.

- **`content-engagement-audit`** — Checks whether a page's initial HTML
  actually answers the visitor's likely question, has readable text
  equivalents for image-only content, and offers a usable next step.

- **`citation-destination-audit`** — Follows a claim → link → redirect →
  destination chain and checks whether the page you land on actually
  supports what was claimed about it.

- **`source-verification-audit`** — Compares supplied claims against
  explicitly provided external sources. Only runs when the caller supplies a
  `claims`/`sources` input; otherwise it stays dormant and reports as much.

- **`improvement-opportunity-audit`** — Turns the other specialists' cached
  evidence into non-destructive suggestions (e.g. missing FAQ schema, an
  Organization node without `sameAs`, a Product without review signals).
  These are opportunities, never findings — they're not treated as proof of
  a defect.

## How the entrypoint composes them

`audit-entrypoint` fetches and caches the target page once, then hands that
same cached evidence to each specialist skill in turn. Every specialist
reads only from that shared cache — none of them fetch anything on their
own. `audit-entrypoint` collects each specialist's confirmed findings and
suggested opportunities, deduplicates and assigns stable IDs, and emits a
single JSON report with severity, evidence, and a `suggested_action` for
each item.

## Run it

```bash
python3 scripts/signaltrace.py <url>
```

See `references/audit-contract.md` for the full input/output contract,
including the optional stdin envelope for supplying external
`claims`/`sources`.
