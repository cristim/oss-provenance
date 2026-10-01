# GitLab LabKit evidence fixture

Repository: https://gitlab.com/gitlab-org/labkit
Revision: `f6a93079dd611ffeec26f9f599dc1f78397f41ba`
Source: `fields/fields.go`, stored here as `fields.go`.
Grant: the original root `LICENSE`, retained alongside the source.

The commit and nine recursive tree pages in `tests/fixtures/gitlab/` were recorded from GitLab's public API on 2026-10-01. Each tree fixture preserves the JSON response body and the `x-page` / `x-next-page` headers; there are 815 entries. The source has no SPDX header. Collection must retain these artifacts while leaving grant applicability pending. The Go file is unmodified test data and is neither compiled nor executed.

Source SHA-256: `f0356f426a0da955390eec27c5f546d6d72e3241bf3fcc21f39d41a422308747`
Source MD5: `da966675939febb440609aeea0bac49b`
License SHA-256: `d08172d312bc93d0d098342e1ac50d35439152e5ea17c4f668e55e868fd4d1da`

Use `cargo test --test evidence live_gitlab_collection_and_source_verification_use_pinned_bytes -- --ignored` to verify the real collection and immutable source download. Offline tests replay the recorded responses without network access.
