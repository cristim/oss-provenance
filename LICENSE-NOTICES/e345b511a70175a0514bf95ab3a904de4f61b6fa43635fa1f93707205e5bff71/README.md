# Third-party source notice

Source repository: https://github.com/scanoss/scanoss.py

Immutable revision: 0c1292bd4d53bc504804411dd42ff1ab0fa7aa76

Upstream path: src/scanoss/winnowing.py

Source SHA-256: ec606d89ddd0d2d49c193cf74147e7806ee68a573a9865cf714bf586bea9e0d5

Upstream license expression: MIT

Selected license: MIT

Review of applicability and obligations:

The pinned source embeds the MIT grant and Copyright (c) 2021, SCANOSS. The complete copyright, permission, and warranty text is retained in LICENSE-NOTICES/scanoss-winnowing/LICENSE and the unmodified upstream source. This MIT-licensed Rust CLI adapts the winnowing loop and bundles the original Python source as a development reference and test fixture; it does not execute that Python file. Preserve these artifacts in distributed source and package artifacts. The reviewed MIT grant requires retention of its copyright and permission notice; no additional source-prefix condition is imposed by this grant.

## Preserved license and notice artifacts

- LICENSE-NOTICES/scanoss-winnowing/LICENSE (SHA-256: bb42ef82d9a941c2fed842bfbfed63c0fad3e34889d49d3f7816ba968d3e16d9)
- LICENSE-NOTICES/scanoss-winnowing/winnowing.py (SHA-256: ec606d89ddd0d2d49c193cf74147e7806ee68a573a9865cf714bf586bea9e0d5)

## Uses in this project

### LICENSE-NOTICES/scanoss-winnowing/winnowing.py:454-568

Snippet SHA-256: be4ed66bf37ee7746f64a20d22efb51e5d0adfd73cdabb6d553ca6242792d554

Unmodified upstream wfp_for_contents implementation retained as a development reference and public test fixture. The entire bundled file is also protected by its evidence-artifact hash, including its original MIT header.

### src/fingerprint.rs:58-94

Snippet SHA-256: da1b750c51a1645225a692b4cf9ac3cbfd02bebda460434a9109505e20280718

Rust adaptation of the upstream winnowing loop: normalize alphanumeric bytes, maintain 30-byte grams and a 64-hash window, select minimum CRC32C values, and emit line-associated fingerprints. The recorded span covers the algorithm body independently of surrounding setup or tests.

