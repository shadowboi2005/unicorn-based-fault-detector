# Detection log — what was flagged, on what inputs, and how

This collects every leak the framework has **flagged** (and the notable ones it
deliberately does *not*), and for each one states the **test inputs** and the
**detection method**. It spans the ALAFA sweep (example 09), the intra-function
skip tool (example 10), the r0-check attack (example 08), and the MAYO analysis.

We never recover a key here — every entry is a **leak / no-leak verdict**.

## The common test spine

Every flag comes from the same shape:

1. **Two secret keys** A and B (seeds `secret-key-AAAA` / `secret-key-BBBB`), each
   expanded to a real key via the stubbed, deterministic RNG.
2. **N messages** (`msg-0…msg-(N-1)`), signed under **both** keys with the same
   per-key nonce stream — so the *only* variable between the two populations is
   the key.
3. A **fault** is installed at one site (a whole-call skip in `sweep`, an
   instruction skip in `funcskip`, or a targeted value fault in example 08).
4. Each faulted output is turned into a **feature**, and a **detector** asks:
   *can the two keys be told apart (or a secret be recovered) from the faulted
   output?* A threshold gives LEAK / ok; a run that crashes/hangs is `crash`.

The feature and detector are supplied by the scheme's `AnalysisProfile`
(`ucpqc/profiles/`); the engine (`ucpqc/assess.py`) is scheme-agnostic.

## The detectors (the "how")

| detector | feature it consumes | leak rule | what it catches |
|---|---|---|---|
| `two_key` | matched filter of `c` against `z` (or raw bytes) | LOO nearest-mean accuracy ≥ 80% | whole-output **mean shift** by key |
| `per_coord` (A) | same feature | max &#124;Welch t&#124; over coords ≥ Bonferroni threshold (~5.3) | leak in **one output position** |
| `subspace` (B) | same feature | covariance-whitened (LDA) LOO accuracy ≥ 80% | leak in a **correlated subspace** |
| `structural` (B\*) | **field elements** (Z_q / GF(16)) | rank-collapse `score = collapse·separation` ≥ 0.5 | **accumulation / recoverability** (low-dim key-dependent subspace) |
| `uniformity` | raw nonce coefficients | largest histogram bin share > 10% | a **biased nonce** (loop-abort) |
| `spec_aware` | raw coefficients + `reject_bound` | count of coeffs ≥ bound > 0 | a **rejection-boundary bypass** |

`two_key` / `per_coord` / `subspace` are the same LOO classifier under identity /
diagonal / full covariance; `structural` is the same idea over the scheme's own
algebra (see `ucpqc/detectors.py`).

---

## Dilithium (ML-DSA-44)

### ✅ `z = z + y` mask removal — the headline leak
- **Site:** `bl polyvecl_add` — `0x4d5e` in the `sweep`, `0x46e4` inside `polyvecl_add` in `funcskip`.
- **Fault:** skip the masking add, so `z` stays `= c·s1` (the fresh nonce `y` is never added).
- **Inputs:** 2 keys × N signatures; **feature** = `matched_filter(c, z)` — the negacyclic correlation of the sparse challenge `c` (re-expanded from `c_tilde` via the firmware's own `poly_challenge`) against the response polyvec `z` decoded from the signature. `z`'s marginal is nonce-masked, so a plain histogram is blind; the matched filter extracts the `(c, z)` joint.
- **Detected by:** `two_key` — LOO accuracy **100%** at N=12 (chance = 50%, threshold 80%). Control (no fault) sits at chance.
- **Also flagged by** every stronger detector, on the same inputs: `per_coord` (max&#124;t&#124; ≫ threshold), `subspace` (LDA 100%), and `structural` — which deconvolves `c` from `z` over `Z_q` to a per-signature `s1` estimate; with the mask gone every signature yields the **same** `s1`, collapsing to rank 1 (score **0.917**). This is the negacyclic-ring instance of the field-aware detector.

### ⚠️ `mov r7, r0` output-pointer load — an isolated-replay artifact
- **Site:** `0x46d2` (loads the `polyvecl_add` output pointer), in `funcskip`.
- **Fault:** skip the output-pointer load → the write goes to a stale address while the aliased buffer still holds `c·s1`.
- **Detected as:** `two_key` **100% in isolated replay**, but only ~69% end-to-end (below 80%). Flagged in `funcskip` because isolated replay preserves the aliasing that a full signing would overwrite — documented as a **capture-and-replay artifact**, not a true end-to-end leak.

### ✅ r0 rejection-check bypass — an accumulation leak (example 08)
- **Fault:** force the r0 norm-check to *accept* (stuck-at-0 on the `cmp` result) → the signer releases **out-of-spec** signatures.
- **Inputs:** sign with the check forced to accept; **feature** = raw `r0` / `z` coefficients.
- **Detected by:** `spec_aware` — `band_count` = number of coefficients with `|coeff| ≥ reject_bound` (`GAMMA2 − BETA`); **0 for every accepted golden signature, > 0 once the check is bypassed**. `band_levene` is the second-order variant. This is a *many-signature* lattice/polytope recovery, not a per-signature distinguisher.

### ❌ rejection-check faults in the `sweep` — deliberately *not* flagged
- **Fault:** whole-call **skip** of `poly_chknorm` (vs. example 08's stuck-at-accept).
- **Outcome:** `crash/hang` — `r0` keeps a stale nonzero value → the loop rejects every iteration and spins to the 20M-instruction cap. Skipping a check and forcing its verdict are **opposite faults**; the sweep breaks the loop in the wrong direction, so this leak needs example 08's targeted fault. (See `examples/plots/9/09.md`.)

### ❌ loop-abort on the nonce `y` (category 4.1) — out of the whole-call model
- A whole-call skip zeroes the *entire* `y` sampler → signing crashes. The real attack aborts *part-way*, leaving a partly-known nonce — a finer fault the sweep can't express.

---

## MAYO-1

### ❌ `sweep`: 0 leaking sites (and why that's the honest result)
- **Inputs:** 2 keys × N=12; **feature** = raw released signature bytes; **detector** = `two_key`.
- **Control at chance (46%)** — MAYO is *not* golden-confounded: the fresh vinegar masks the key just as `y` does in Dilithium, so the released signature hides the key.
- Every vinegar-critical site **crashes** under a whole-call skip (`shake256`@0x7046 that expands the vinegar seed, `sample_solution`, `compute_M_and_VPV`), because zeroing the whole vinegar/seed makes the linear solve fail. The recombination `s = v + o` is **inlined**, so there is no `bl` to skip. → no site both completes *and* leaks. (Runtime: serial 566.8 s, `-j20` 37.4 s.)

### ⚠️ De-inlined `mat_add` (recombination) — localized but not yet detected
- **Setup:** rebuild MAYO with `mat_mul`/`mat_add` marked `noinline` (`firmware_ni/`), so the `s = v + Ox` recombination becomes real `bl mat_mul.constprop.0` / `bl mat_add.constprop.0` calls that `funcskip` can capture.
- **Fault:** instruction-skip the F16 add (`eor`) inside `mat_add`.
- **Detected as:** chance across **all** detectors — `two_key` 47%, `per_coord` max&#124;t&#124; 2.5, `subspace` 57%, `structural` score 0.0. Two reasons, both real: (1) the fused, word-vectorized F16 loop means the skip exposes the **vinegar** operand (shake-random, not linearly separable), not clean oil; (2) the oil leak is **GF(16)-algebraic** — real-valued detectors are blind, and even the GF(16) `structural` detector needs the oil actually exposed.
- **What would flag it:** a **data fault** (zero/fix an operand, as the real attacks glitch) on the de-inlined `mat_add` so the output is clean oil `Ox`, then the `structural` detector over `GF2m(4)` (oil lies in the ≤ k·o-dim, key-dependent oil subspace → rank collapse). The detector and localizer are in place; the missing piece is the data-fault model.

---

## One-line summary table

| scheme | site / fault | inputs | detector | metric | verdict |
|---|---|---|---|---|---|
| ML-DSA | `z=z+y` skip (`bl polyvecl_add`) | 2 keys × N, matched-filter(`c`,`z`) | `two_key` | 100% | **LEAK** |
| ML-DSA | same, field-aware | 2 keys × N, `s1` over Z_q | `structural` | 0.917 | **LEAK** |
| ML-DSA | `mov r7,r0` (out ptr) | funcskip isolated replay | `two_key` | 100% iso / 69% e2e | artifact |
| ML-DSA | r0-check forced accept | raw coeffs + bound | `spec_aware` | band_count > 0 | **LEAK** (ex.08) |
| ML-DSA | `poly_chknorm` skip | — | `two_key` | — | crash/hang |
| MAYO | any sweep site | 2 keys × N, raw bytes | `two_key` | ≤54% | none (control 46%) |
| MAYO | de-inlined `mat_add` eor-skip | funcskip, GF(16) | all | ≤57% / 0.0 | none (needs data fault) |
