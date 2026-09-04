# Protected decisions required

This directory is intentionally empty of decision JSON. A model cannot create a
human decision. The authenticated repository authority must add schema-valid,
content-addressed decisions for:

- task approval;
- governance authorization and initial LKG promotion with rollback evidence;
- approval of all eight corpus labels;
- material residual-risk disposition; and
- final release authorization after reviewing the reconstructed pack.

The protected adapter verifies only decision IDs committed in this directory.
Chat text, free-form names, booleans, hashes without issuer authentication, and
candidate-owned copies never satisfy this source.

An authenticated manual dispatch selecting these protected IDs emits an
`authorization-receipt-proposal.json`. To authorize unattended reevaluation,
the repository authority must commit those exact bytes as the sibling
`authorization-receipt.json` in the single permitted receipt-only child commit,
together with regenerated `MANIFEST.json`. A schedule accepts no caller-provided
IDs and inherits only that receipt's actor, decision commit, basis commit, and
complete immutable ID set. The scheduler identity never becomes a human
decision issuer.

The `lkg_promotion` scope must contain both
`promote:<proposed-policy-sha256>` and
`rollback:<rollback-evidence-id>`. The release directory must also contain the
distinct `proposed-policy.json` and the protected `rollback/` package named
`rollback-evidence.json`, `gate-result.json`, `sandbox-capability.json`, and
`provenance-statement.json`. Adding only a decision never satisfies promotion.

For this one-time bootstrap, the initial-bootstrap decision's `base_commit` is
the release candidate's comparison base (`5393338`). The separate
`lkg_promotion` decision's `base_commit` is the actual rollback target and
authority-transition basis (`a0a0b01`). These values are deliberately different;
the distinction is part of the protected transition and must not be normalized
away when the authenticated decisions are created.
