# How the Dilithium-LLVM IR numbers (ineffective / correction) are derived

Companion to `report/llvm_vs_arm.md`. That report's per-function **LLVM ineff** and
**LLVM corr** columns come from the sibling repo `../Dilithium-LLVM` (the Dilithium
counterpart of `../MAYO-LLVM`). This note documents how that repo produces those verdicts,
exactly what feeds our report, and why the ARM translation rate is low by construction.

Repo located: **`/home/imnothackr/mnt/sidechannel/btp1/Dilithium-LLVM`** (found; pq-crystals
`ref/` + `avx2/` Dilithium with an added `llvm/` fault-analysis tree). Same methodology family
as `MAYO-LLVM`, different on-disk layout.

## (a) What the Dilithium-LLVM pipeline does

Three stages, operating on the whole-program IR `llvm/dilithium_IR/dilithium2.ll`
(ML-DSA-44; `dilithium3.ll`/`dilithium5.ll` also present):

1. **Taint / level-propagation analysis** — `llvm/llvm-gen/level_prop.cpp` (+ `llvm-gen.cpp`).
   An info-flow pass over a 3-level lattice `Level { Public=0, EphSecret=1, Secret=2 }`
   (`join = max`), propagated through registers, memory, and across calls. It records, per
   function, the set of **secret-tainted IR instructions** and emits one JSON per function to
   `llvm/taintResults/` (99 files, `pqcrystals_dilithium2_ref_<fn>.json`). Each entry is keyed
   by the instruction's IR line number and carries `{ "instr": <IR text>, "type": <class> }`,
   where `type ∈ {BinOp, CallInst, LoadInst, StoreInst, GetElementPtrInst, CastInst, ...}`
   and `CallInst` entries add `"callee"`. These tainted instructions are the **fault sites**;
   the total per function is the denominator in our report's `d/t` columns.

2. **Fault injection** — `llvm/fault-types/`, dispatched by `run_faults.sh`: for each site in a
   function's taint JSON it branches on `type`:
   - `type == BinOp` → `binOp_load_store_Fault` with fault models
     `{undef, zero, opA, opB}` (replace the binop result with `undef`/`0`, or forward operand
     A / operand B). Load/Store sites use a `mem` model.
   - `type == CallInst` → `loop_fn_Fault <ir> 1 <fn> <line>`: **whole-call skip** (mode 1) and
     a **loop-skip** variant (the IR-level analogue of our ARM `funcskip`).
   The injector clones the module, runs `PromotePass` + a `FaultInjectionPass(model, locator)`,
   and writes a faulted `.ll` per site/model.

3. **SMT fault-propagation** — each site produces a `correct` query (unfaulted) and a
   `faulty_*` query via `llvmbmc ... --dump-solver-query` → `.smt2`, then a z3 harness
   (`smt_parser.cpp`, per the `MAYO-LLVM` template) compares the symbolic outputs.
   `fuse_back.cpp` splices a single faulted function back into the whole-program module so the
   query is over the real downstream computation, not the function in isolation.

## (b) How "ineffective" vs "correction" verdicts are produced

The z3 harness builds `delta = out_correct XOR out_faulty` as a symbolic expression over the
symbolic inputs (confirmed in `MAYO-LLVM/.../binOpFault/smt_parser.cpp`, lines ~48-110), then
discharges a satisfiability query:

- **ineffective** (SIFA-style no-op): the fault can be *silently absorbed* — there is an input
  making `delta == 0` though the faulted instruction did fire. The MAYO template encodes the
  *key-dependent* form directly: two secret instances `b1 != b2` with
  `delta_b1 == 0 ∧ delta_b2 != 0` — SAT ⇒ the same fault is a no-op for one secret but changes
  the output for another (an ineffective-fault / SIFA candidate). UNSAT ⇒ provably no such
  split (provably ineffective / not key-splitting, depending on the asserted direction).
- **correction** (output-changing): the complementary axis — the fault *does* change the
  signature output (`delta != 0`), i.e. a fault the scheme does not absorb.

Each column in our report is `detected/total`: **total** = tainted fault sites for that
function (from the taint JSON); **detected** = sites the SMT step placed in that bucket.
`signature_internal` (15/23 ineff, 11/22 corr) is the whole-sign top level and carries the
largest site count.

## (c) Exactly what feeds our ucpqc report

Nothing from `../Dilithium-LLVM` is read at report-build time. `scripts/build_llvm_report.py`
hardcodes the LLVM numbers in a dict `LLVM = { fn: (ineff_d, ineff_t, corr_d, corr_t), ... }`
(lines 18-31), with the docstring/comment stating they were **"transcribed from the
Dilithium-LLVM summary image"**. So:

- `LLVM ineff` column = `ineff_d/ineff_t` for that function.
- `LLVM corr`  column = `corr_d/corr_t`.
- The script's own inputs are purely the ARM side: `dumps/<fn>_instrskip/` (funcskip dumps,
  via `ucpqc.assess`/`ucpqc.dump`) and `captures/manifest.json` (reachability `A==0`).

The upstream artifacts those numbers *summarize* are `llvm/taintResults/*.json` (denominators /
fault-site lists) and the per-site `llvmbmc` + z3 SAT/UNSAT runs (numerators). **Caveat:** the
Dilithium-LLVM repo does not check in the final counts — no `.smt2`, no results/summary file is
present (the `run_command`/`cp *.smt2` lines in both injectors are commented out, and the
`tests_dilithium/<fn>/` output tree is not committed). The `d/t` integers exist only in the
transcribed dict and the (uncommitted) "summary image"; they are not independently
re-derivable from what is checked in without re-running the `llvmbmc`/z3 stage.

## (d) Key caveat — why the LLVM→ARM translation rate is low

The LLVM fault model is **finer and categorically different** from our ARM one:

- **LLVM** faults *individual IR values/bits* (binop → undef/0/opA/opB, load/store `mem`) and
  decides effect by an **SMT equivalence proof** over symbolic inputs — it can prove a fault
  provably ineffective, or exhibit a key-splitting witness, for a *single IR operation*.
- **ARM** (`funcskip`) deletes a *whole machine instruction* and decides empirically (n=40
  messages/key): `correction` ≈ TVLA/`per_coord` LEAK at FDR≤0.01, `φIF` = a skip that is a
  no-op for one key but output-changing for the other.

A whole-instruction skip is a *coarser* fault than an IR value/bit corruption, and the m4f
optimising compiler **inlines ~8 reference functions out of the signing path**, shrinking the
ARM fault surface relative to the IR the LLVM tool analysed. Hence the low translation:
**1/8** LLVM-correction functions leak on ARM (`polyvecl_add`, the `z=z+y` mask add), and
**1/10** LLVM-ineffective functions show an ARM φIF site. The two studies locate related but
not identical phenomena; the table is a *translation* study, not a 1:1 correspondence.
