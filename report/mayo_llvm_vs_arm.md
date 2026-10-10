# MAYO: LLVM-IR fault setup vs ARM-binary φIF — correlation

How the `QEMU-test` LLVM-IR fault analysis of **MAYO** lines up with this platform's
ARM-binary φIF sweeps (`report/mayo_phi.md` = whole-call A, `report/mayo_phi_funcskip.md`
= intra-function B).

## Important: no LLVM verdicts exist for MAYO

For Dilithium the LLVM project published a *summary* of ineffective/correction faults
(detected/total per function) — that is what `report/llvm_vs_arm.md` correlates against.
For MAYO, `QEMU-test/results/` ships only the **fault-injection setup**: per function, a
set of faulted-IR variants under `binOpFault/` (value/data faults) and
`loopOrFuncSkip/` (loop- and call-skip faults), plus `run_witness_verfication.sh` to
classify them by replaying witnesses on QEMU. **No witness.json, no verification output,
no ineffective/correction tally, and no MAYO taint results are committed.** So this is a
*coverage + fault-model* correlation, not a detected/total numeric match.

## Two things the correlation turns on

1. **Fault model.** MAYO's LLVM fault sites are overwhelmingly `binOpFault` = **value/data
   faults** on the GF(16) arithmetic (`mul_f` 64, `compute_A` 96, `compute_rhs` 56,
   `sub_f`/`add_f`/`m_vec_add` 4 each), with only a handful of `loopOrFuncSkip` on the
   matrix routines. Our ARM study injects **instruction skips** only, which aligns with
   the `loopOrFuncSkip` axis — **not** the `binOp` (data-fault) axis. The functions LLVM
   hits hardest (the GF(16) element ops) are exactly the ones a skip can't probe.
2. **Compilation.** The m4f build **inlines 11 of the 19** LLVM-analyzed functions out of
   any separable symbol, so they have no ARM fault surface at all; and it **fuses** the
   reference matrix structure into bespoke `*_asm` routines, which *relocates* where a
   skip is fault-sensitive.

## Per-function correlation

| LLVM MAYO fn | LLVM faults (binOp / loopskip) | ARM m4f status | ARM φIF (B) |
|---|---|---|---|
| `mul_f` | 64 / 0 | inlined (GF16 element op) | — |
| `compute_A` | 96 / 4 | inlined | — |
| `compute_rhs` | 56 / 1 | reached, swept | **7** |
| `sub_f` | 4 / 0 | inlined | — |
| `add_f` | 4 / 0 | inlined | — |
| `m_vec_add` | 4 / 0 | inlined | — |
| `m_vec_mul_add` | 0 / 1 | inlined | — |
| `mat_add` / `mat_mul` / `lincomb` | 0 / 1–2 | inlined | — |
| `compute_M_and_VPV` | 0 / 4 | reached, swept | **1** |
| `compute_P3` | 0 / 2 | keygen-only (P3), not in sign | — |
| `P1_times_Vt` | 0 / 1 | reached, swept | 0 |
| `P1P1t_times_O` | 0 / 2 | reached, swept | 0 |
| `P1_times_O` | 0 / 1 | keygen-only, not reached | — |
| `mul_add_mat_x_m_mat` | 0 / 1 | reached as 2 fused `*_asm` | 0 |
| `mul_add_mat_trans_x_m_mat` | 0 / 1 | fused `*_asm`, not reached | — |
| `mul_add_m_upper_triangular_mat_x_mat(_trans)` | 0 / 1 each | `m_upper` / folded, not reached | — |
| *(no ref name)* `multiply_P1_right_m4f_V_V_O` | — | m4f-fused P1·V (= ref `P1_times_Vt`/`mul_add`) | **31** |

## Takeaways

- **Fault-model mismatch is the headline.** The axis LLVM exercises most on MAYO (value
  faults on GF(16) arithmetic) is the one our skip-only platform *cannot* reach, and those
  functions are inlined on ARM anyway. This matches the standing MAYO conclusion: its
  SIFA/ineffective surface wants a **data fault**, not an instruction skip.
- **Where the models do overlap (the skip axis), compilation moved the target.** At the
  reference level the P1·V product is `P1_times_Vt` (LLVM: 1 loop/skip fault site); on ARM
  that generic routine shows **0** φIF, while the m4f-fused `multiply_P1_right_m4f_V_V_O`
  that actually does the work in signing shows **31**. The fault-sensitive surface the LLVM
  IR locates in one function lands in a *different*, compiler-generated routine on the
  binary — so LLVM-IR localization does not map 1:1 to the ARM binary.
- **Reachability pruning agrees with the scheme structure:** `P1_times_O`, `m_upper`,
  `mul_add_mat_trans_*`, `compute_P3` are keygen / public-map code and are correctly
  *not reached* during signing on ARM, consistent with their role in the reference.
- **Same exploitability caveat as Dilithium:** the ARM φIF counts locate *candidate* sites;
  the 2-key metric conflates key- with input-dependence and does not by itself prove
  SIFA-exploitability (that needs the ineffective-conditioned-bias test).
