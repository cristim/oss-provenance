# This repository's provenance policy

The project uses its own checker on staged changes. Its MIT-only policy covers the Rust implementation, Rust tests, and Python fixture generator. The scanner sends fingerprints to `https://api.osskb.org/scan/direct`. It does not send plaintext source or repository paths.

## Coverage

`.oss-provenance.toml` lists coverage exclusions explicitly:

- Documentation, license text, and notice artifacts are reviewed as documentation and attribution, rather than searched for source matches.
- Build metadata, hook configuration, the CI workflow, and formatting settings are outside this source-reuse check.
- The three recorded scanner-response and fingerprint JSON fixtures are generated test data.

No Rust or Python implementation/test file outside the bundled upstream reference is excluded. New source paths are included by default. A new tiny file with insufficient fingerprints blocks the check until its coverage is explicitly reviewed. Exclusions are part of the admitted policy and cannot be changed by an ordinary candidate commit.

The bundled upstream Python reference is kept in `LICENSE-NOTICES/` with its original MIT notice. Its exact bytes and the MIT license artifact are protected by the admitted evidence hashes. The manifest also records the local Rust adaptation. Removing these artifacts or recorded uses blocks the check even though the notice directory is excluded from source searches.

## Initial assessment

The initial full-tree assessment returned no matches for the 16 included source files and no coverage issues. This does not establish original authorship: the Rust fingerprint implementation is a known adaptation of SCANOSS's Python code. Its pinned upstream source, grant, and local uses are therefore recorded explicitly in the ledger, independent of scanner detection.

MIT is the only allowed license requirement. Every discovered match still needs reviewed source evidence; a scanner's MIT label cannot clear it. Other license requirements remain unresolved until the maintainer changes and re-admits the policy.

## Enable the hook in a clone

Install `pre-commit` and Rust through your usual tooling. Review `.oss-provenance.toml`, the recorded upstream evidence, and the coverage exclusions above. The initial reviewed policy commit is `e439647c7e9106f8ad677e5413738044b6b4b47b`. To admit that policy and install the configured hooks:

```sh
git config --local oss-provenance.policy-ref e439647c7e9106f8ad677e5413738044b6b4b47b
pre-commit install --install-hooks
pre-commit run oss-provenance --all-files
```

The last command invokes the hook even without changed files. It validates the existing notice ledger and scans staged changes; `--all-files` here does not turn the hook into a full-tree assessment. Ordinary commits run formatting, Clippy, tests, and the provenance check. A clone without explicit policy admission fails the provenance check.

For a fresh full-tree assessment, install the CLI as described in the main README and run:

```sh
oss-provenance check --all --base e439647c7e9106f8ad677e5413738044b6b4b47b --head HEAD --policy-ref e439647c7e9106f8ad677e5413738044b6b4b47b
```

## Policy maintenance

Policy admission is local Git configuration containing a full immutable commit ID. Cloning the repository does not admit a policy automatically. Evaluate the complete proposed tree before admitting a policy change, retaining the prior ledger baseline:

```sh
oss-provenance evaluate --all --base PRIOR_LEDGER_SHA --head PROPOSED_SHA --policy-ref PROPOSED_SHA --format json
```

Evaluation always exits 1. Review the report for unresolved issues and findings, inspect policy and evidence changes, then admit only the reviewed commit. Updating a notice description must keep the generated notice README consistent. Changing a recorded source snippet requires an explicit ledger update and, when replacing historical use, a reviewed retirement.

The commit hook uses a pinned published checker rather than building the candidate's checker code. Change that pin only after reviewing the replacement version. Hooks depend on the hosted service and can block commits during an outage; an outage is not a passing scan.
