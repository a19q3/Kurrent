# P0 precondition-assertion patch (not yet applied)

This patch captures the working-tree diff for `src/lib.rs` at commit
`4730b26` (the alignment commit). Most of the diff is pre-existing
work by another author (the larger factory/lane/settlement surface
work). The piece authored in this session is the precondition
assertion and its documentation, which lives in the
`evaluate_settlement_eligibility` function.

The patch is intentionally not applied in this commit because the
`src/lib.rs` working tree contains pre-existing multi-hundred-line
changes from another author that have not been committed yet. The
session's contribution is a 1-line `debug_assert!` plus a 2-line
docstring + comment embedded inside a 348-line hunk that includes
other people's working-tree changes.

To isolate just the precondition assert from the rest of the diff:

  # 1. After `src/lib.rs` working tree is clean (i.e. after the other
  #    author has committed their changes), apply this full patch
  #    onto a fresh copy of the post-commit `src/lib.rs`.
  git apply --check tmp/p0-precondition-assert.patch
  # (expect this to fail if other authors' changes are already in
  #  HEAD, because the patch is a working-tree snapshot, not a
  #  clean delta)
  
  # 2. The targeted change this session owns is the `debug_assert!`
  #    that fires when the verifier hands a candidate list whose
  #    `accepted_order_index` is not strictly increasing. It lives
  #    inside `evaluate_settlement_eligibility`, after the
  #    `sort_by_key(|c| c.accepted_order_index)` line. The release
  #    build still relies on the `windows(2)` invariant loop further
  #    down; the assert is a debug-only precondition check that the
  #    verifier produced a strictly-ordered list before the
  #    invariant loop has to enforce it.

  # 3. If a manual application is preferred over the full patch, copy
  #    the `debug_assert!` block and the surrounding docstring /
  #    comment from the patch hunk header into a clean lib.rs.

Expected outcome after a clean application:

  - All existing 83 tests still pass.
  - `cargo test` runs the debug assertion in test builds; in
    `cargo build --release` it is compiled out.
  - No new clippy warnings; no new rustc warnings.

Out-of-band note:

  The `src/bin/kurrentctl.rs` working tree at commit `4730b26` also
  has 352+ pre-existing lines that are not this session's work. They
  are intentionally not in this commit and not captured in this
  patch; they belong to the same author as the larger
  `src/lib.rs` working-tree diff and should be committed by them.
