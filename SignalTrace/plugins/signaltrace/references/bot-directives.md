# Bot directives and search eligibility

Read this reference from `audit-entrypoint` when evaluating search eligibility from cached evidence. This is shared logic, not a separate skill.

Use only the governor's recorded robots decision, final HTTP headers, and initial HTML. Check `X-Robots-Tag`, `<meta name="robots">`, and equivalent named bot directives when present. Preserve the exact directive and source location.

- A parsed `Disallow` or explicit `noindex` is a deliberate access or indexing restriction, not automatically a defect.
- Missing `robots.txt` means no robots policy was published at that path; it does not prove broad search eligibility.
- Unreachable, timed-out, HTTP-error, or unparseable robots evidence is unresolved and must not be treated as permission.
- Conflicting `index` and `noindex` directives in the same cached representation are a localized representation defect.
- Search-result absence is never evidence of invisibility.
- Do not claim any directive guarantees crawling, indexing, ranking, AI discovery, or citation.

Record deliberate restrictions and incomplete states under coverage. Emit a finding only for a directly observed contradictory or malformed representation that meets the shared severity rules.
