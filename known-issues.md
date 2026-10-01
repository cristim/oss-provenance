# Known limitations

- Automatic provider execution, sandboxed candidate tests, and bounded automatic rewrite/rescan are not implemented in the CLI. Both agent options produce explicit blocked handoffs. A separate end-to-end demonstration used authenticated, fresh-context generation with tools disabled, sandboxed candidate tests, and the commit hook; the provider's host process was not isolated by an OS sandbox.
- New source evidence requires human admission. The collector fetches real immutable GitHub evidence and can inspect a supplied pinned ScanCode report, but it does not run ScanCode or automatically conclude applicability.
- GitHub is the only supported source host. Unresolvable scanner versions, modified grants, custom SPDX references, ambiguous provenance, and unsupported fuzzy source correspondence remain unresolved.
- Caching is opt-in. Scanner responses expire after one hour; immutable source bytes are hash-checked on reuse. Mutable cached negative results require trusted storage and may miss corpus changes within that hour. No automatic eviction or disk-size limit is implemented.
- Requests are serial per process, with bounded retries. Multiple agents do not share a rate limiter. Outages can still block commits when there is no valid cache entry. Structured runtime errors distinguish scanner failures from other operational problems, but do not decide whether or when an outer agent loop should retry.
- The full-tree policy admission workflow is explicit CLI evaluation and maintainer configuration, not a protected CI promotion service.
- There is no shipped dependency-vulnerability or coverage-threshold gate yet. Standard offline tests, format, clippy, and build checks are provided.
