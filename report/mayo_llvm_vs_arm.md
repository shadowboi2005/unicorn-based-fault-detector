# MAYO: LLVM analysis vs ARM-binary φIF — correlation

Correlates the `MAYO-LLVM` IR analysis of **MAYO** with this platform's ARM-binary φIF
sweeps (`report/mayo_phi.md` = whole-call A, `report/mayo_phi_funcskip.md` =
intra-function B).

## What the LLVM side actually provides for MAYO

Two sibling repos, the MAYO counterpart of the Dilithium pipeline:

- **`MAYO-LLVM/llvm-apps/mayo-propagation-analysis/taintResults/`** — per-function
  **taint** analysis: the set of secret-tainted IR instructions (seeded from `sk`),
  one JSON per function (`len` = number of secret-dependent IR instructions).
- **`MAYO-LLVM/llvm-apps/fault-prop/`** — **SMT** fault propagation: for a chosen fault
  (binop value fault, loop/func skip, …) it emits `correct.smt2` vs `faulty_*.smt2` and
  asks a solver whether any input makes the faulted output differ. **UNSAT = provably
  *ineffective*** (no input distinguishes faulty from correct); SAT (+witness) = the fault
  can change the output. These are **targeted experiments, not a full sweep**, and only
  one verdict is committed: `fault-prop/mayo_sign_add_skip/output.txt` = **UNSAT**, i.e.
  skipping that add in signing is provably ineffective.
- (`../QEMU-test/results/` holds the complementary witness-replay funcskip IR variants.)

So unlike Dilithium there is **no per-function ineffective/correction tally** for MAYO —
but there **is** a quantitative taint signal, which is what we correlate against.

## Taint (secret-dependence) vs ARM φIF

| ref function | tainted IR instrs | ARM m4f status | ARM φIF (B) |
|---|---|---|---|
| `sample_solution` | 145 | reached, swept | **8** |
| `compute_A` | 76 | inlined | — |
| `compute_rhs` | 52 | reached, swept | **7** |
| `mayo_sign_signature` | 48 | top-level sign | — |
| `m_vec_mul_add` | 22 | inlined | — |
| `mul_f` | 18 | inlined | — |
| `P1P1t_times_O` | 10 | reached, swept | 0 |
| `mayo_expand_sk` | 7 | reached (whole-call effective) | — |
| `m_vec_add` / `mat_add` | 6 | inlined | — |
| `compute_M_and_VPV` | 4 | reached, swept | **1** |
| `m_upper` | 4 | keygen, not reached | — |
| `P1_times_Vt` | 1 | reached, swept | 0 |
| `P1_times_O` | 1 | keygen, not reached | — |
| *(m4f-fused, no ref)* `multiply_P1_right_m4f_V_V_O` | — | reached, swept | **31** |

## What correlates — and what breaks

- **Taint predicts φIF on the non-vectorised sign code.** Among reached+swept functions
  the high-taint ones are exactly the φIF carriers: `sample_solution` (145→8),
  `compute_rhs` (52→7), `compute_M_and_VPV` (4→1). The reference genuinely marks these as
  the secret-heavy routines, and the ARM skip surface agrees.
- **m4f vectorisation breaks the correlation.** `P1P1t_times_O` is secret-tainted
  (taint 10) yet shows **0** ARM φIF: on m4f it is a fused/bitsliced GF(16) multiply, so a
  single-instruction skip hits many packed field elements at once — always effective or a
  crash, never *conditionally* dead by key. Taint (a reference-IR property) cannot see this;
  it is a property of the compiled vector code.
- **Compilation relocates the surface.** The biggest ARM φIF cluster,
  `multiply_P1_right_m4f_V_V_O` (**31** sites), has *no* reference function — it is the
  m4f-fused realisation of the P1·V product that the reference splits across
  `P1_times_Vt` (taint **1**) and the `mul_add_*` helpers. So the fault-sensitive surface
  the IR taint barely flags is concentrated by the compiler into a bespoke routine. **IR-level
  localisation is not 1:1 with the ARM binary.**
- **Fault-model axis.** MAYO's committed LLVM fault experiments are value/binop faults and
  targeted skips; the one solved verdict (`mayo_sign_add_skip` = UNSAT = ineffective) is a
  *provable* ineffective fault. Our platform only injects instruction skips, so it probes the
  skip axis; the value-fault axis (where MAYO's SIFA surface is expected) is out of scope —
  consistent with the standing conclusion that MAYO ineffective/SIFA wants a **data fault**.
- **Reachability agrees with scheme structure:** `P1_times_O`, `m_upper` (taint 1 and 4) are
  keygen/public-map and correctly *not reached* in signing on ARM.

## Caveat (same as the Dilithium φIF study)

The ARM φIF counts **locate candidate sites; they do not establish SIFA-exploitability.**
The 2-key metric conflates key- with input-dependence, and publicness of a driving value
does not disqualify a site. The LLVM SMT verdict (UNSAT ⇒ ineffective) is a stronger,
*provable* statement, but exists for only one targeted fault here; a full ineffective/
correction map for MAYO would require running the `fault-prop` SMT experiments across the
signing functions (the method is present; the verdicts are not pre-computed).
