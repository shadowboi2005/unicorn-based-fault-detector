# LLVM-IR → ARM-binary fault-leakage translation (Dilithium / ML-DSA-44)

How many of the `Dilithium-LLVM` IR-level fault findings reproduce on the **ARM binary**
via this platform's `funcskip` instruction-skip + detector repertoire.

- **LLVM** has two IR-fault tests: *ineffective* (SIFA-style no-op faults) and *correction*
  (output-changing faults). Numbers (detected/total) are transcribed from the project's summary image.
- **ARM** (n=40/key): *leak* = `per_coord`/TVLA sites flagged LEAK at FDR≤0.01 (the correction
  analog); *ineffective* = max over sites of the share of skip-replays byte-identical to the
  unfaulted output; *sifa z* = key-dependence of that rate. A function counts as ARM-ineffective-
  detected when that max fraction ≥ 0.5.
- Fault models differ (IR bit/value faults vs whole-instruction skip), and funcskip captures
  only functions **reached during signing**, so this is a *translation* study, not 1:1.

## Aggregate translation rate (reachable functions with an ARM dump)

- **Correction → ARM leak:** 1/8 of LLVM-correction-flagged functions also leak on ARM (the ARM leakers: `polyvecl_add`).
- **Ineffective faults present:** 7/10 of LLVM-ineffective-flagged functions have an ARM skip site that is a no-op ≥0.5 of the time.
- **SIFA (key-DEPENDENT ineffectiveness):** 0/17 functions show a significant `sifa z` (>3) -- i.e. the ineffective *rate itself* differs by key.

## Takeaways

- Under whole-instruction skip, the ARM binary leaks the key at essentially **one** place -- the mask add `polyvecl_add` (`z = z + y`), matching the canonical Exploiting-Determinism fault -- while every other reachable function shows **0** leaking sites. LLVM's value-level *correction* faults therefore translate **poorly** to instruction-skip key leakage: a whole-instruction skip is a much coarser fault than an IR bit/value corruption.
- *Ineffective* (no-op) faults are **common** on the skip surface (most functions have a site where skipping is a no-op), but the **SIFA signal -- key-dependent ineffectiveness -- is absent** (`sifa z ≈ 0` everywhere): the no-op rate is the same for both keys. This matches our earlier conclusion that SIFA needs a **data** fault, not a skip.
- The m4f optimising compiler **inlines 8 of the reference functions out of the signing path** (`polyveck_add/sub/chknorm/make_hint`, the `c·s` `*_pointwise_poly_montgomery` multiplies, `polyvecl_invntt_tomont`/`pointwise_acc`), so the ARM fault surface is **smaller** than the IR the LLVM tool analysed -- compilation itself changes what can be faulted.

## Per-function

| function | LLVM ineff | LLVM corr | ARM leak (LEAK/scored, max\|t\|) | ARM ineff (max frac, sifa z) | note |
|---|---|---|---|---|---|
| `invntt_tomont` | 0/18 | 0/18 | 0/267, |t|=4.5 | 1.00, z=0.0 | |
| `ntt` | 0/13 | 0/13 | 0/382, |t|=4.2 | 1.00, z=0.1 | |
| `poly_add` | 1/4 | 1/4 | 0/7, |t|=2.7 | 0.00, z=0.0 | |
| `poly_caddq` | 1/1 | 0/1 | — | — | 4B thunk -> `polyveck_caddq` |
| `poly_challenge` | - | - | 0/58, |t|=3.6 | 1.00, z=0.0 | |
| `poly_chknorm` | - | - | 0/16, |t|=1.0 | 1.00, z=0.1 | |
| `poly_decompose` | 0/1 | 1/1 | 0/7, |t|=2.7 | 1.00, z=0.0 | |
| `poly_invntt_tomont` | 0/1 | 0/1 | — | — | 4B thunk -> `invntt_tomont` |
| `poly_make_hint` | 1/5 | 1/5 | 0/10, |t|=2.6 | 1.00, z=0.0 | |
| `poly_ntt` | 1/1 | 0/1 | — | — | 4B thunk -> `ntt` |
| `poly_pointwise_montgomery` | 4/5 | 1/5 | — | — | 4B thunk -> `polyvecl_pointwise_poly_montgomery` |
| `poly_sub` | 1/4 | 1/4 | 0/7, |t|=2.7 | 0.00, z=0.0 | |
| `poly_uniform` | 2/3 | 0/3 | 0/45, |t|=2.8 | 1.00, z=0.0 | |
| `poly_uniform_eta` | 1/2 | 1/2 | — | — | keygen-only (not sign-reachable) |
| `poly_uniform_gamma1` | 2/2 | 2/2 | 0/6, |t|=4.1 | 0.00, z=0.0 | |
| `polyvec_matrix_pointwise_montgomery` | 0/1 | 0/1 | 0/15, |t|=4.4 | 0.00, z=0.0 | |
| `polyveck_add` | 0/1 | 0/1 | — | — | not called in m4f signing (inlined / verify-only) |
| `polyveck_caddq` | 1/1 | 0/1 | 0/8, |t|=3.6 | 1.00, z=0.2 | |
| `polyveck_chknorm` | - | - | — | — | not called in m4f signing (inlined / verify-only) |
| `polyveck_decompose` | 1/1 | 1/1 | 0/10, |t|=4.0 | 1.00, z=0.1 | |
| `polyveck_invntt_tomont` | 0/1 | 0/1 | 0/7, |t|=3.6 | 0.00, z=0.0 | |
| `polyveck_make_hint` | - | - | — | — | not called in m4f signing (inlined / verify-only) |
| `polyveck_ntt` | 0/1 | 0/1 | 0/8, |t|=3.8 | 1.00, z=0.0 | |
| `polyveck_pointwise_poly_montgomery` | 1/1 | 0/1 | — | — | not called in m4f signing (inlined / verify-only) |
| `polyveck_reduce` | 1/1 | 0/1 | 0/8, |t|=3.4 | 1.00, z=0.0 | |
| `polyveck_shiftl` | 1/1 | 1/1 | — | — | keygen-only (not sign-reachable) |
| `polyveck_sub` | 0/1 | 0/1 | — | — | not called in m4f signing (inlined / verify-only) |
| `polyveck_uniform_eta` | 1/1 | 1/1 | — | — | keygen-only (not sign-reachable) |
| `polyvecl_add` | 1/1 | 1/1 | 5/10, |t|=16.9 | 1.00, z=0.0 | |
| `polyvecl_chknorm` | - | - | 0/11, |t|=0.0 | 1.00, z=0.0 | |
| `polyvecl_invntt_tomont` | 0/1 | 0/1 | — | — | not called in m4f signing (inlined / verify-only) |
| `polyvecl_ntt` | 0/1 | 0/1 | 0/8, |t|=3.6 | 1.00, z=0.0 | |
| `polyvecl_pointwise_acc_montgomery` | 1/3 | 0/3 | — | — | not called in m4f signing (inlined / verify-only) |
| `polyvecl_pointwise_poly_montgomery` | 1/1 | 0/1 | — | — | not called in m4f signing (inlined / verify-only) |
| `polyvecl_reduce` | - | - | 0/8, |t|=4.5 | 1.00, z=0.7 | |
| `polyvecl_uniform_eta` | 1/1 | 1/1 | — | — | keygen-only (not sign-reachable) |
| `polyvecl_uniform_gamma1` | 1/1 | 1/1 | 0/10, |t|=4.5 | 1.00, z=0.2 | |
| `signature_internal` | 15/23 | 11/22 | — | — | whole-sign top level (see `sweep` mode) |
