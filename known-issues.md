# Known limitations

- Automatic provider execution, sandboxed candidate tests, and bounded automatic rewrite/rescan are not implemented. Both agent options produce explicit blocked handoffs. Local API-key environment variables are absent; CLI-only isolation and authenticated generation have not been verified together.
- New source evidence requires human admission. The collector fetches real immutable GitHub evidence and can inspect a supplied pinned ScanCode report, but it does not run ScanCode or automatically conclude applicability.
- GitHub is the only supported source host. Unresolvable scanner versions, modified grants, custom SPDX references, ambiguous provenance, and unsupported fuzzy source correspondence remain unresolved.
- No scan cache is implemented. Accepted matches download pinned evidence, so service outages can block commits and large changes may be slow.
- The full-tree policy admission workflow is explicit CLI evaluation and maintainer configuration, not a protected CI promotion service.
- There is no shipped dependency-vulnerability or coverage-threshold gate yet. Standard offline tests, format, clippy, and build checks are provided.
- The tool's distribution license remains undecided. Do not publish this crate yet. Preserved third-party attribution is not the tool's own license.
