# Third-party notices

nhi-reach is distributed under the Apache-2.0 license (see `LICENSE`). It embeds
the following third-party software in its binary and in the self-contained HTML
report it produces.

## cytoscape.js 3.30.2

- **Purpose:** graph rendering in the self-contained HTML report (`-o html`).
- **Vendored file:** `internal/report/assets/cytoscape.min.js` (embedded with `//go:embed`).
- **Upstream:** https://github.com/cytoscape/cytoscape.js
- **Downloaded from:** `https://cdn.jsdelivr.net/npm/cytoscape@3.30.2/dist/cytoscape.min.js`
- **License:** MIT. The full text is kept next to the asset in
  `internal/report/assets/cytoscape.LICENSE`.
- **Copyright:** Copyright (c) 2016-2024, The Cytoscape Consortium.
- **Size:** 373,304 bytes.
- **SHA-256:** `83e8c54a6bec655bfd81df07df605649c268af69aeca67a5ea2da54ea42dac81`
- **npm integrity (`sha512`):** `oICxQsjW8uSaRmn4UK/jkczKOqTrVqt5/1WL0POiJUT2EKNc9STM4hYFHv917yu55aTBMFNRzymlJhVAiWPCxw==`
  (from `https://registry.npmjs.org/cytoscape/3.30.2`; the tarball carries that
  integrity and its `package/dist/cytoscape.min.js` is byte-identical to the
  vendored file).
- **Verified:** 2026-10-07.

The embedded digest is asserted by `TestEmbeddedAssetIntegrity`
(`internal/report/html_test.go`). Replacing the asset is a deliberate change
that must update this file and that constant together.
