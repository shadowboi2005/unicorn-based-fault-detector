# Attack coverage bookkeeping — Dilithium/ML-DSA fault attacks

Which cataloged fault attacks (`../../../dilithium_fault_attacks.md`) this framework
**flags** via each fault mechanism. "Detected" = the fault is injectable **and**
the resulting leak is flagged by an appropriate detector (leak-level assessment;
we do **not** run the cryptanalytic recovery/solver — that is out of scope, only
flagging matters). Both detected and not-detected are tracked deliberately.

**Legend**
- ✅ detected & demonstrated (an example reproduces the fault and a detector flags it)
- 🟡 flaggable — fault mechanism and detector already exist, demo not yet wired
- ❌ not detectable by this mechanism (reason in cell)

| Attack paper name | detected by function-call skip | detected by intra-function instr skip |
|---|---|---|
| Espitau et al. 2016 — *Loop-Abort Faults* (§4.1, y) | ❌ whole y-sampler call skip hangs | 🟡 loop-abort inside `poly_uniform_gamma1`; uniformity/bias detector |
| Groot Bruinderink & Pessl 2018 — *Differential Fault Attacks* (§4.4) | ❌ nonce-reuse, not a skip leak | ❌ needs a nonce-collision detector, not a skip |
| Ravi et al. 2019 — *Number "Not Used" Once* (§4.4) | ❌ nonce-reuse | ❌ nonce-reuse (collision detector) |
| Ravi, Jhanwar et al. 2019 — *Exploiting Determinism* (§4.2, skip-add) | ✅ example 09 (`z=z+y`, two-key 100%) | ✅ example 10 (`bl poly_add` skip, 100%) |
| Islam et al. 2022 — *Signature Correction* (§4.6b, Rowhammer `s1`) | ❌ memory fault + verify-oracle | ❌ memory fault + verify-oracle, not a skip leak |
| ElGhamrawy et al. 2023 — *MLWE→RLWE* (§4.2) | ✅ example 09 | ✅ example 10 (per-coeff / call skip in the add) |
| Ulitzsch et al. 2023 — *Loop Aborts Strike Back* (§4.1) | ❌ whole-call skip hangs | 🟡 loop-abort inside the `y` sampler |
| Bronchain et al. 2023/24 — *Small-Norm Poly Mult* (§4.2) | ✅ the `z=y+c·s1` fault instance | ✅ example 10 |
| Krahmer et al. 2024 — *Correction Fault Attacks* (§4.5, hedged) | ❌ verify-oracle attack + needs hedged mode | ❌ verify-oracle attack + needs hedged mode |
| Jendral 2024 — *Single-Trace Fault* (§4.1/4.2, hedged) | ❌ whole-call skip hangs | 🟡 `y` loop-abort path (NTT(c)-zeroing needs a data fault, not a skip) |
| Wang et al. 2024 — *Mind the Faulty Keccak* (§4.6a, round-skip) | ❌ whole Keccak call skip breaks everything | 🟡 round-skip inside `KeccakF1600_StatePermute`; downstream uniformity/two-key |
| Azevedo-Oliveira et al. 2025 — *Finding a Polytope* (§4.3, r0 test) | ❌ whole `chknorm` call skip hangs | ✅ example 10 region replay (skip `bne @ 0x4dde`) |
| Du et al. 2025 — *Breaking the Shield* (§4.2) | ✅ example 09 | ✅ example 10 |

## Notes

- **Function-call skip** = example-09-style: step the PC past a `bl`. It hangs on
  the rejection checks (skipping the whole `chknorm` leaves a stale nonzero
  verdict → always reject) and on the samplers (skipping the whole `y` call
  aborts signing), which is why §4.1 and §4.3 read ❌ for it.
- **Intra-function instruction skip** = example-10-style: capture the function's
  I/O once, replay it in isolation, skip one instruction inside (or, for §4.3, a
  region so the caller's reject branch is in scope). This reaches the leaks the
  whole-call skip cannot.
- **§4.3 is also detected by a non-skip primitive** — example 08 forces the r0
  compare result (stuck-at-accept) and flags the released out-of-spec `r0` with
  the spec-aware band-`‖r0‖∞` detector. The table column is specifically the
  *skip* mechanism.
- The three ❌❌ rows (§4.4, §4.5, §4.6b) are **not skip-flaggable by design**:
  §4.4 is nonce reuse (needs a two-signing collision check), §4.5/§4.6b are
  verify-**oracle** correction attacks whose secret only emerges from the oracle
  loop — there is no per-signature distribution to flag, so they fall outside the
  distribution-flagging paradigm entirely (§4.5 additionally needs hedged mode,
  absent in this firmware).

## Summary

| mechanism | ✅ demonstrated | 🟡 flaggable (ready) | ❌ not applicable |
|---|---|---|---|
| function-call skip | 4 (all §4.2) | 0 | 9 |
| intra-function instr skip | 5 (§4.2 ×4, §4.3) | 4 (§4.1 ×2, §4.6a, §4.1/4.2 Jendral) | 4 (§4.4 ×2, §4.5, §4.6b) |

Intra-function skips strictly dominate call skips (every ✅ call-skip attack is
also ✅ intra) and additionally reach §4.3 and the 🟡 §4.1/§4.6a classes.

## Per-function flag rates

For functions that carry a detected intra-function attack, how many of their
instructions, when skipped (persistent), flag as a leak — see
`function_flag_rates.png`, produced by `examples/plots/plot_10_functions.py`
(ml-dsa-44, N=24/key):

| target | catalog | detector | instructions | flagged | golden 2-key |
|---|---|---|---|---|---|
| `polyvecl_add` | 4.2 `z=z+y` | two-key | 13 | **2** (15%) | 46% |
| `polyvecl_reduce` | control | two-key | 10 | **0** (0%) | 50% |
| r0 decision region | 4.3 bypass | accept-flip | 4 | **1** (25%) | n/a |

Reading it:

- **`polyvecl_add`** (the §4.2 leak): 2 of 13 instructions flag — the `bl poly_add`
  and the `mov r7,r0` that both leave `z = c·s1` (the mask never mixed in). The
  other 11 either run harmlessly (8) or crash the function (3).
- **`polyvecl_reduce`** (control): 0 of 10 flag. It operates on the *already-masked*
  `z`, so no single skip exposes the secret — **the detector does not cry wolf on
  a benign function** (selectivity, complementing the ~0% false-positive rate).
- **r0 decision region** (§4.3): 1 of 4 instructions — only the reject branch
  (`bne @ 0x4dde`) — bypasses the check and releases all out-of-spec `r0`.

**Methodology guard (why the `golden 2-key` column matters).** A two-key flag is
only meaningful if the function's *unfaulted* output is already ~chance (masked).
`polyvecl_add` (46%) and `polyvecl_reduce` (50%) qualify. A different candidate,
`poly_add`, was **excluded**: its captured invocation has a **98%** golden
baseline — its output is secret-dependent even with no fault, so a two-key "flag"
there is meaningless. Always confirm golden ≈ 50% before trusting the flag count;
for inherently-secret internal buffers (`c·s1`, `r0`) use the role-appropriate
detector (uniformity or spec-aware band) instead.
