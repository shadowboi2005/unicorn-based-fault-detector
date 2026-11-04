# Per-function LLVM→ARM translation table — walkthrough (Dilithium / ML-DSA-44)

A reading of the per-function table in [`llvm_vs_arm.md`](llvm_vs_arm.md): what each
column is, where its numbers come from, why `Dilithium-LLVM` flagged each reference
function, and whether the ARM-binary fault study (`pqm4` `ml-dsa-44_m4f` /
`firmware/ml-dsa-44_m4f_test.elf`) reproduced it. The headline is a **1/8 correction
translation rate** and the compiler **dropping 8 reference functions out of the signing
call graph**.

The two IR findings live on **two distinct detector axes** — keep them apart:

- **(A) correction / leak** = `per_coord`/TVLA distribution-difference: does the faulted
  *output distribution* differ by key? Flagged LEAK at FDR≤0.01 via `max|Welch t|`
  (no-leak floor ≈ 3–4.5).
- **(B) ineffective / φIF**: does *whether a skip is a no-op* differ by key? Keys A/B
  sign the **same messages + RNG** (only `sk` differs); a site is φIF if skipping is a
  no-op for one key but output-changing for the other on ≥1 message.

These are not the same signal and do not imply each other: a site can be φIF with `|t|`
at the floor, and a LEAK site can have 0 φIF flips.

## How the table is produced

`scripts/build_llvm_report.py` emits `llvm_vs_arm.md`. Each column:

- **`LLVM ineff` / `LLVM corr`** (`detected/total`) — **not computed here**. They are
  hand-transcribed from the `Dilithium-LLVM` project's summary image into the `LLVM`
  dict at the top of the script (e.g. `"poly_add":(1,4,1,4)` = ineff 1/4, corr 1/4). The
  per-function *tainted-instruction* sets that back the `total` denominators live in
  `../Dilithium-LLVM/llvm/taintResults/pqcrystals_dilithium2_ref_<fn>.json` (each key is
  a tainted IR instruction, e.g. the `add nsw i32` / `store` in `poly_add`); those JSONs
  are also what annotate the IR-tainted-count on the TVLA plots. The script does **not**
  recompute detected/total from them.
- **`ARM leak (LEAK/scored, max|t|)`** — `arm_row(fn)` runs
  `assess.assess_funcskip_from_dump(dumps/<fn>_instrskip, detector="per_coord")`. `scored`
  = skip sites with a defined metric, `LEAK` = sites at `status=="LEAK"` (FDR≤0.01),
  `max|t|` = the largest Welch t over scored sites. This is axis (A).
- **`ARM φIF sites (flips)`** — axis (B), computed in the same `arm_row`. For every skip
  site, per message index `i` (A and B share the public input now that RNG is fixed), it
  compares `effA[i] = (out != golden_A)` against `effB[i]`; a **flip** is `effA[i] != effB[i]`.
  `φIF sites` = sites with ≥1 flip; `flips` = total flips. The per-site detail
  (`pc`, disasm, flips) feeds the (B) tables.
- **`note`** — reachability, resolved per function from the profile
  (`ucpqc/profiles/dilithium_targets.py`): `KEYGEN_ONLY`, `THUNK_REDIRECT` (4-byte C
  thunks that tail-call a worker — the skip surface lives in the worker), and
  **`NOT_REACHED`**, which is read *empirically* from `captures/manifest.json`: a target
  with `A == 0` captured invocations during signing. A function with a `note` gets no
  `arm_row` (dash in both ARM columns).

## Column-by-column, row-grouped

### Thunks (no interior skip surface) — ARM columns dashed by design

`poly_caddq → polyveck_caddq`, `poly_invntt_tomont → invntt_tomont`,
`poly_ntt → ntt`, `poly_pointwise_montgomery → polyvecl_pointwise_poly_montgomery`.
These are 4-byte C thunks; their LLVM ineff/corr counts (e.g. `poly_pointwise_montgomery`
4/5 ineff) describe IR that at the binary level is exercised inside the redirect target,
so the ARM study faults the target, not the thunk.

### Keygen-only — sampled in keygen, never on the sign path

`poly_uniform_eta`, `polyvecl_uniform_eta`, `polyveck_uniform_eta`, `polyveck_shiftl`.
LLVM flagged them (all have corr/ineff hits, e.g. `poly_uniform_gamma1`-style
`uniform_eta` 1/2 both axes), but the `funcskip` capture only hooks the **signing** call,
so there is nothing to translate against. Dashed.

### Reachable, with an ARM dump — the actual translation set

These 21 functions carry real numbers in both ARM columns. Pattern:

- **Correction/leak axis is almost entirely dead under instruction-skip.** Every
  reachable function reports `0/scored` LEAK with `max|t|` at the 3–4.5 no-leak floor
  (`invntt_tomont` 0/267 |t|=4.5, `ntt` 0/382 |t|=4.2, `poly_uniform` 0/45 |t|=2.8,
  `polyvec_matrix_pointwise_montgomery` 0/15 |t|=4.4, `polyvecl_chknorm` 0/11 |t|=0.0, …)
  — **except** `polyvecl_add`: **5/10 LEAK, max|t|=16.9**. This is the response mask add
  `z = z + y` over the L=4 secret polynomials; skipping the output-pointer setup
  (`mov r7,r0 @0x46d2`), a per-poly `bl poly_add @0x46e4`, or the loop control
  (`cmp @0x46e8`/`bne @0x46ec`) drops an add, so the emitted `z` exposes the
  deterministic `c·s1` term — the canonical *Exploiting-Determinism* fault. The |t|≈16.9
  sits an order of magnitude above the floor. A whole-instruction skip is a *coarser*
  fault than an IR bit/value corruption, which is why LLVM's value-level correction hits
  mostly do not survive the translation to skip-induced key leakage.

- **φIF axis fires in 4 functions, 71 sites total**: `ntt` 63 (261 flips),
  `poly_challenge` 5 (7), `polyvecl_uniform_gamma1` 2 (38), `poly_chknorm` 1 (1). In `ntt`
  the sites are the Montgomery-butterfly `smull`/`smlal`/`add` ops: skipping one is a
  no-op exactly when that key's coefficient makes the product irrelevant, so the no-op
  pattern tracks the secret-derived NTT operands. Note the **asymmetry with LLVM**: `ntt`
  is LLVM-ineffective **0/13** yet is the heaviest ARM φIF source, and `poly_challenge` /
  `poly_chknorm` are not in the LLVM dict at all (`-`). The φIF signal is a SIFA
  *candidate* surface, not a proof: A and B feed the faulted function different inputs
  (different `c̃`, `μ`), so a flip conflates key-dependence with input-dependence — each
  site still needs the SIFA ineffective-conditioned-bias test.

## The 1/8 correction translation rate

Restricting to functions that are (i) LLVM-**correction**-flagged (`corr detected > 0`)
and (ii) reachable with an ARM dump gives **8** functions: `poly_add`, `poly_decompose`,
`poly_make_hint`, `poly_sub`, `poly_uniform_gamma1`, `polyveck_decompose`, `polyvecl_add`,
`polyvecl_uniform_gamma1`. Of these, exactly **one** — `polyvecl_add` — shows an ARM LEAK
site. **1/8.** (`polyveck_decompose`'s and `polyvecl_uniform_gamma1`'s LLVM correction hits,
for instance, produce 0 ARM LEAK: 0/10 |t|=4.0 and 0/10 |t|=4.5 respectively.)

The ineffective→φIF rate is reported alongside as **1/10**: of the 10 reachable
LLVM-**ineffective**-flagged functions (`poly_add`, `poly_make_hint`, `poly_sub`,
`poly_uniform`, `poly_uniform_gamma1`, `polyveck_caddq`, `polyveck_decompose`,
`polyveck_reduce`, `polyvecl_add`, `polyvecl_uniform_gamma1`), only
`polyvecl_uniform_gamma1` also has an ARM φIF site. The other three ARM-φIF functions
(`ntt`, `poly_challenge`, `poly_chknorm`) were **not** LLVM-ineffective-flagged, so they
do not count toward this rate — the axes genuinely disagree on which functions matter.

## The inlining effect — 8 functions dropped from the sign call graph

Eight reference functions show `—` in both ARM columns with
*"not called in m4f signing (inlined / verify-only)"*. From `captures/manifest.json`
(A==0 captured invocations during signing), the exact set is:

| function | LLVM ineff | LLVM corr | role in ref Dilithium |
|---|---|---|---|
| `polyveck_add` | 0/1 | 0/1 | `w ± …` K-vector add |
| `polyveck_sub` | 0/1 | 0/1 | `w - cs2` K-vector sub |
| `polyveck_chknorm` | — | — | `‖r0‖`, `‖cs2‖`, `‖ct0‖` norm checks |
| `polyveck_make_hint` | — | — | hint-bit generation |
| `polyveck_pointwise_poly_montgomery` | 1/1 | 0/1 | one of the `c·s` multiplies |
| `polyvecl_pointwise_poly_montgomery` | 1/1 | 0/1 | the `c·s1` multiply |
| `polyvecl_invntt_tomont` | 0/1 | 0/1 | L-vector inverse NTT |
| `polyvecl_pointwise_acc_montgomery` | 1/3 | 0/3 | matrix·vector accumulate |

**These symbols are not absent from the binary** — all eight are still global `T` symbols
in `ml-dsa-44_m4f_test.elf` (`nm`: `pqcrystals_dilithium_polyveck_add @0x4811`,
`…_polyvecl_pointwise_acc_montgomery @0x4759`, etc.). The compiler kept the definitions
(they are exported / used by verify or keygen) but the **signing path never calls them**,
which is why `funcskip` records 0 invocations and no dump is produced. Two mechanisms:

1. **Hand-written fused asm replaces the generic C.** The m4f build links
   `pqcrystals_dilithium_asm_pointwise_montgomery @0x53ad` and
   `…_asm_pointwise_acc_montgomery @0x5431`; the `c·s` multiplies and the matrix-accumulate
   run through these fused assembly routines on the sign path, so the generic
   `polyvecl/polyveck_pointwise_*montgomery` C bodies are dead there. (Likewise the sign
   path uses `polyvecl_small_ntt @0x51c1` / `polyveck_small_ntt @0x51e1` /
   `poly_small_ntt_precomp @0x5185` for the secret-vector transforms, leaving
   `polyvecl_invntt_tomont` uncalled during signing.)
2. **Inlining / verify-only use.** The K-vector `add`/`sub`, `chknorm` and `make_hint`
   wrappers are either inlined into their callers on the sign path or only reached in
   verification, so their standalone symbols never fire during a sign.

The consequence for this study: the ARM fault surface is **strictly smaller** than the IR
`Dilithium-LLVM` analysed. The `c·s` multiplies in particular — exactly the operations
SIFA/ineffective analysis cares about — are not independently faultable at these symbols
on the m4f sign path; their arithmetic has migrated into the fused-asm routines and into
the inlined NTT butterflies (where the ARM φIF signal in `ntt` actually shows up).
**Compilation itself changes what can be faulted**, so IR-level reachability over-counts
the real attack surface.
