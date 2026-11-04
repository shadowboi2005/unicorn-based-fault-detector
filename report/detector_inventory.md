# Detector inventory: what we have, what overlaps, what actually detects

A consolidated audit of every leak/fault detector in the codebase: its role, whether it
is a special-case of another detector, its **measured track record** under the
instruction-skip model, and a keep/drop verdict. Effectiveness is grounded in the study
reports (`report/dilithium_polyvecl_add_leak.md`, `report/attack_coverage.md`,
`report/llvm_vs_arm.md`, `report/mayo_llvm_vs_arm.md`), not recollection.

> **Decision taken (branch `refactor/trim-detectors-instr-skip`).** The platform now
> keeps exactly **two** detectors for the instruction-skip scope: **`per_coord`** (the
> confirmed correction/output-leak detector) and the new **per-position `phi`** detector
> (`ucpqc/phi.py`, promoted from the LLVM-gap experiment's Arm B — the high-recall
> replacement for the retired whole-output `sifa` / `candidates._phi_counts`). The other
> nine (`two_key`, `subspace`, `structural`, `mmd`, `uniformity`, `spec_aware`,
> `r0_reject`, `differential`, `sifa`) and their supporting primitives / profile hooks
> were removed. They are **recoverable from git history** — revert this branch's PR, or
> check out the restore point `6218c34` (`llvm-arm-translation` before the trim) — if a
> data-fault / MAYO / multi-signature regime that needs them is added back.

## Where the detectors live

Three tiers; only the first two are "detectors" in the oracle sense:

- **Tier 1 — oracle registry** (`ucpqc/assess.py`, `_DETECTORS`): ten named, selectable
  detectors that produce a LEAK/ok verdict.
- **Tier 2 — φIF** (`ucpqc/candidates.py`, `_phi_counts`): the funcskip key-dependent-ineffective
  flip counter, tallied outside the registry.
- **Tier 3 — statistical primitives** (`ucpqc/detectors.py`): `tvla_t`, `two_key_accuracy`,
  `lda_accuracy`, `structural_leak`, `perm_pvalue`, `mmd_test`, `uniformity_divergence`,
  `band_count`/`band_levene`, `bh_fdr`, `holm_bonferroni`, … — building blocks the Tier-1
  scorers call, not standalone oracles.

## The master table

Effectiveness key: ✅ confirmed real leak · ⚠️ fires but confirms nothing (candidate locator) ·
❌ never fired in any report.

| # | Detector | Axis / role | Measured track record | Relationship to others | Verdict |
|---|----------|-------------|-----------------------|------------------------|---------|
| 4 | **`per_coord`** | output leak (correction) | ✅ **Only confirmed detector.** Found `polyvecl_add` — 5 LEAK sites, \|t\|=16.9 vs ~3–4.5 floor; the canonical Exploiting-Determinism leak. 1/8 LLVM-correction fns translated to ARM. | diagonal special-case of `subspace`; single-coordinate localization | **keep — earns its place** |
| 11 | `phi_IF` | fault ineffective (φIF) | ⚠️ 71 candidate sites / 4 fns (Dilithium); "locate candidate sites, do **not** establish SIFA-exploitability" — confounded by input-dependence. 1/10 LLVM-ineffective fns. | same oracle as `sifa`, per-*site* granularity | keep as locator → replace with per-position φIF |
| 10 | `sifa` | fault ineffective | ⚠️ Same axis; no **confirmed** key-dependent leak in the reports. | binary (thresholded) case of `differential`; duplicate of `phi_IF` | merge → per-position φIF |
| 9 | `differential` | fault effect magnitude | ❌ No firing recorded. | continuous generalization of `sifa` | keep only if continuous variant wanted; else dormant |
| 8 | `r0_reject` | rejection bypass | ⚠️ Attack-specific (Finding-a-Polytope); "partial" — ct0/hint "~never fire at n=24"; no confirmed key-dependent leak. | specialization of `spec_aware` to the `r0` observer | keep only if that attack stays in scope |
| 7 | `spec_aware` | spec violation | ❌ No confirmed detection recorded. | general form of `r0_reject` | dormant |
| 6 | `uniformity` | nonce bias | ❌ Loop-abort on `y` **not flagged** ("0 LEAK, φIF within control"). | orthogonal | dormant (needs y-partially-known regime) |
| 2 | `subspace` | output leak (subspace) | ❌ **Never fired.** | general linear case; subsumes `two_key` & `per_coord` | dormant |
| 1 | `two_key` | output leak (mean shift) | ❌ **Never fired** — by design *dilutes* a localized leak across all D dims (why `per_coord` caught `polyvecl_add` and this did not). | strict special-case of `subspace` | **drop / fold into `subspace`** |
| 5 | `mmd` | output leak (nonlinear) | ❌ Never fired; calibrated-only, emits no fixed-threshold verdict. | orthogonal (higher-moment) | dormant |
| 3 | **`structural`** | recoverability | ❌ **Never fired** (appears in reports only as the word "structural", never as a detection). | algebra-aware extension of `subspace` | **roadmap-dependent — see below** |

## Replacement map (who subsumes whom)

Three families. Within a family, special-cases can fold into their general form; across
families the axis is genuinely different and nothing is redundant.

**Family 1 — secret-dependence of the output.** One nested linear idea + two extensions:

```
            per_coord  (diagonal: any single coordinate separates)   ← the one that works
                 │  special case of
            two_key    (identity covariance: whole-vector mean shift) ← strict special case
                 │  special case of
            subspace   (general linear: correlated low-dim subspace)
                 │  extended by
   ┌─────────────┴─────────────┐
structural (+field/recoverability)   mmd (+nonlinear/higher-moment)
```

- `two_key` ⊂ `subspace` (identity-covariance) — **foldable**.
- `per_coord` is also formally the diagonal case of `subspace`, but it keeps a **unique
  property**: single-coordinate *localization* ("which byte leaks") and small-N robustness.
  It is the one detector with a confirmed hit. **Not foldable in practice.**
- `structural` and `mmd` each add a property `subspace` lacks (field-level recoverability;
  nonlinear differences) — orthogonal, not replacements.

**Family 2 — distribution shape of a must-be-uniform / in-spec quantity.**

- `r0_reject` ⊂ `spec_aware` (specialization to the `r0` observer) — **foldable** into
  `spec_aware` + an observer argument.
- `uniformity` is orthogonal (bias of the uniform nonce), not a replacement.

**Family 3 — key-dependence of the fault itself (φIF / SIFA).** The real duplication:

- `sifa` and `phi_IF` are the **same oracle** (key-dependent ineffectiveness) at different
  granularity/plumbing (whole-output rate vs per-site flip). Both low-recall.
- `differential` is the **continuous** sibling (effect magnitude, not a 0/1 no-op) — fires
  where the fault is partially effective; not a duplicate of the two binary ones.
- **Proposed per-position φIF subsumes `sifa` + `phi_IF`** (per-position, many-key
  existential = the high-recall version) and leaves `differential` standing.

## The two reasons a detector "never fired" — opposite implications

Silence is not one thing:

1. **Truly subsumed / redundant** — `two_key` is a strict special-case of a detector that
   *did* work (`per_coord`). Safe to drop outright.
2. **Dormant because its fault model is never exercised** — `subspace`, `structural`, `mmd`,
   `uniformity`, `differential` target leaks the **single-signature instruction-skip** sweep
   structurally cannot produce. The reports say so directly: the two-key/subspace detectors
   "do not, and are not meant to" catch leaks under single-sig skip; MAYO's recoverability
   surface "wants a **data fault**", which is out of scope for the skip sweeps. Their silence
   is "wrong fault model", not "broken detector".

The principle *"no use for a detector that doesn't detect"* applies cleanly to case 1. For
case 2 it applies only if the platform will **never** run the richer fault model those
detectors need. If it stays skip-only on released signatures, `two_key`, `subspace`,
`structural`, `mmd` are dead weight together.

## Focus question: do we need `structural`? Does it do anything `per_coord` doesn't?

**On paper — yes, a genuinely unique property.** `per_coord` is a *marginal, single-coordinate*
test: it fires only when some one output byte separates the keys by a mean shift, and is
**blind to a leak spread across many coordinates with no single byte separating** — a
joint/subspace leak. `structural` is built for exactly that: rank collapse over the scheme's
own field (GF(q) / GF(16)) detects the secret being *recoverable* from a low-dimensional
linear relation across coordinates even when every marginal byte looks clean. That is
precisely **MAYO's oil-space** shape, which `per_coord` cannot see. They are not
replacements — different failure modes (marginal vs joint).

**In practice — it has never caught anything**, because the only leak that materialized under
skip (`polyvecl_add`) is a single-coordinate correction leak `per_coord` handles, and the
recoverability leak `structural` targets arises under **data faults on MAYO**, which this
skip-only platform does not run.

So the decision reduces to one roadmap question:

- **If MAYO + data-fault recoverability analysis is on the roadmap** → **keep `structural`.**
  It is the *only* detector for that axis; `per_coord` provably cannot replace it.
- **If the platform stays single-sig instruction-skip on released signatures** → `structural`
  (with `two_key`, `subspace`, `mmd`) is dormant dead weight, and dropping it is correct by
  the "must detect" principle.

## Recommended end-state

- **Clearly earned keep:** `per_coord` (only confirmed detector).
- **Clearly droppable now:** `two_key` (strict special-case of `per_coord`/`subspace`).
- **Fold:** `r0_reject` → `spec_aware` + observer arg.
- **Consolidate the φIF cluster:** replace `sifa` + `phi_IF` with one **per-position,
  many-key φIF** (keeps the input-variation control + FDR, tuned toward recall; see
  `report/llvm_gap_experiment.md` for the Arm B evidence this is the detector that actually
  surfaces the LLVM tool's `ineffective` sites). `differential` stays — continuous sibling.
- **Roadmap-gated:** `subspace`, `structural`, `mmd`, `uniformity`, `differential`,
  `r0_reject` — keep iff the data-fault / MAYO / multi-signature regimes they target are in
  scope; otherwise they are dormant dead weight under a skip-only platform.

Net: **11 → ~8** detectors with no new false-negative hole — the drop is the strict
special-case (`two_key`), the fold is a specialization (`r0_reject`), and the φIF duplication
collapses into its high-recall replacement.

## Caveat

Candidate-locator framing preserved throughout: a φIF / `ineffective` witness **locates a
SIFA candidate; it is not a proven exploit.** "Never fired" reflects the committed study
reports; a detector dormant under the current fault model is not evidence it is broken, only
that its target regime was not exercised.
