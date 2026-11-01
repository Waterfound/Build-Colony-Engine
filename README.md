# Build Colony Engine

Public-source engineering execution core maintained by Waterfound.

This project contains the deterministic coordination kernel, state and evidence
verification, source-bound runner dispatch, session/replay safeguards, actor
attestation and runner pool primitives. It was assembled as a clean-history
source extraction, **not** as a Git mirror of any private repository.

## Status

**Initial public engine candidate.** The public source is testable, but
production admission, private controller integration, canonical engine cutover,
and cost-accounting gates are **not yet verified**.

## Local tests

Requirements: Python 3.11+.

```bash
python -m pip install -e '.[attestation]'
python -m unittest discover -s tests -v
```

See `source_manifest.json` for immutable source-content hashes. CI also
verifies these hashes before accepting source-integrity results.

## Trust boundary

The public engine must never receive private operational records, credentials,
seeds or privileged control-plane authority. Workload submission and result
acceptance require independent, authorized source/provenance checks.

A successful CI run proves the public-core regressions, not a migration of
confidential workloads or permission to run them on public infrastructure.

## License

MIT; see `LICENSE`.
