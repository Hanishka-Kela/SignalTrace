# Structured data decision rules

Read this reference only for structured-data analysis.

- Parse every `application/ld+json` block independently and identify it by its one-based source order.
- Accept a top-level object, array, and nested `@graph`; walk nested nodes without losing their block identity.
- Recognize at least Product, Offer, Article and its common subtypes, Recipe, Organization, and BreadcrumbList. Other declared types remain evidence even when no feature rule is implemented.
- Report invalid JSON with the block number and parser location. Do not infer the intended correction.
- Feature-minimum checks are contextual: Product needs a stable name and an offer or another supported product fact; Offer needs price plus priceCurrency when a price is present; Article needs headline; Recipe needs name plus recipeIngredient; Organization needs name; BreadcrumbList needs itemListElement.
- Missing optional properties and JSON-LD absence alone are not findings. Valid Microdata or RDFa is a representation, not a failure.
- Compare visible and structured values only at like scope. Price, currency, availability, version, variant, region, and dates must retain qualifiers. Dynamic or ambiguous mismatches are unresolved, not findings.
- Structured data can aid machine interpretation; never say it guarantees search treatment or AI citation.
