# Build Colony — Public Engine Core Candidate

Deterministic coordination kernel with source-bound manifests, hash-chained
execution state, runner dispatch/session checks, signed actor attestation,
pool assignment and adversarial replay tests.

The candidate uses reviewed source blobs and generic tests only. No secrets,
protected operational state, internal host bindings or source Git ancestry are
part of this staged subtree. The enclosing repository remains PRIVATE.

Local test: `python -m pip install -e '.[attestation]'` then
`python -m unittest discover -s tests -v`.

This is **not** a live public runner, a verified private/public handoff,
the complete original engine, or an approved canonical cutover.
