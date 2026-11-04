# Dilithium m4f: the secret c·s path and operand-aware NTT targets (instruction skip)

Companion to `report/llvm_vs_arm.md`. That study swept the functions the Dilithium-LLVM
project analysed, each at its **last** call in a signing. Two consequences, verified by a
call trace of one m4f signing and by capture:

1. **m4f computes c·s1 and c·s2 on a separate mod-769 "small NTT" path** (`smallntt.h`/`smallpoly.c`: `polyvecl_small_ntt`, `polyveck_small_ntt`, `polyvecl_small_basemul_invntt`, `poly_small_basemul_invntt`, asm workers `small_ntt_asm_769`, `small_asymmetric_mul_asm_769`, `small_invntt_asm_769`). These are not in the reference function list, so they were never swept, and the reference `*_pointwise_poly_montgomery` c·s functions were not "inlined away" but replaced.
2. **The `ntt` target was NTT(c), the public challenge.** `ntt` is called for NTT(t0), NTT(y) and NTT(c); the last call is `poly_ntt(&cp)`. Its captured input is byte-identical to `ntt_c` below. Likewise `invntt_tomont` was c·t0[K-1].

Targets here pick the operand with a `caller` filter (`Target.caller`). n=40 messages/key, `per_coord` TVLA at FDR≤0.01, replay budget 500k.

**φIF control.** A/B flips (keys A, B, same message+RNG) mix key- and input-dependence. The control replays key A against key A on 40 *other* messages (A/A'): input-dependence only. A site is **key-dependent** only if its A/B flips exceed its A/A' flips (one-sided Fisher exact per site, BH-FDR q=0.05).

## Summary

| target (operand) | sites | (A) LEAK / scored | max\|t\| | unfaulted A/B max\|t\| | effective | φIF A/B sites (flips) | φIF A/A' sites (flips) | **key-dep. sites** |
|---|---|---|---|---|---|---|---|---|
| `ntt_c` — ntt (NTT(c), public) | 382 | 0/382 | 4.2 | 3.4 | 99% | 63 (261) | 56 (240) | **0** |
| `ntt_y` — ntt (NTT(y), secret nonce) | 382 | 2/382 | 8.9 | 3.0 | 99% | 0 (0) | 0 (0) | **0** |
| `ntt_t0` — ntt (NTT(t0), key) | 382 | n/a (8/382) | 5029.9 | ∞ (constant per key) | 99% | 0 (0) | 0 (0) | **0** |
| `invntt_ct0` — invntt_tomont (c*t0) | 267 | 0/267 | 4.5 | 2.9 | 98% | 0 (0) | 0 (0) | **0** |
| `invntt_w` — invntt_tomont (w = A*y) | 267 | 0/267 | 4.5 | 2.5 | 98% | 0 (0) | 0 (0) | **0** |
| `small_polyeta_unpack` — small_polyeta_unpack (s1[0]) | 55 | n/a (0/55) | 1.0 | ∞ (constant per key) | 80% | 0 (0) | 0 (0) | **0** |
| `polyvecl_small_ntt` — polyvecl_small_ntt (s1) | 8 | n/a (1/8) | 15.6 | ∞ (constant per key) | 62% | 0 (0) | 0 (0) | **0** |
| `polyveck_small_ntt` — polyveck_small_ntt (s2) | 8 | n/a (1/8) | 27.7 | ∞ (constant per key) | 62% | 0 (0) | 0 (0) | **0** |
| `poly_small_ntt_precomp` — poly_small_ntt_precomp (c, public) | 16 | 0/15 | 2.5 | 2.5 | 31% | 0 (0) | 0 (0) | **0** |
| `small_ntt_s1` — small_ntt_asm (NTT(s1)) | 408 | n/a (3/408) | 846.7 | ∞ (constant per key) | 100% | 0 (0) | 0 (0) | **0** |
| `small_ntt_s2` — small_ntt_asm (NTT(s2)) | 408 | n/a (3/408) | 406.5 | ∞ (constant per key) | 100% | 0 (0) | 0 (0) | **0** |
| `small_ntt_c` — small_ntt_asm (NTT(c), public) | 408 | 0/408 | 4.7 | 2.5 | 97% | 91 (633) | 95 (635) | **0** |
| `small_mul_cs1` — small_asymmetric_mul (c*s1) | 37 | 0/37 | 3.9 | 3.9 | 76% | 0 (0) | 0 (0) | **0** |
| `small_mul_cs2` — small_asymmetric_mul (c*s2) | 37 | 0/37 | 4.4 | 3.0 | 76% | 0 (0) | 0 (0) | **0** |
| `small_invntt_cs1` — small_invntt_asm (c*s1) | 486 | 0/486 | 4.7 | 2.9 | 100% | 21 (43) | 20 (45) | **0** |
| `small_invntt_cs2` — small_invntt_asm (c*s2) | 486 | 0/485 | 4.2 | 3.1 | 100% | 21 (40) | 19 (41) | **0** |
| `polyvecl_small_basemul_invntt` — polyvecl_small_basemul_invntt (c*s1) | 22 | n/a (8/22) | 16.9 | 16.9 | 86% | 0 (0) | 0 (0) | **0** |
| `poly_small_basemul_invntt` — poly_small_basemul_invntt (c*s2) | 16 | 0/16 | 3.1 | 3.0 | 81% | 0 (0) | 0 (0) | **0** |
| `poly_challenge` — poly_challenge | 58 | 0/58 | 3.6 | 2.8 | 57% | 5 (7) | 3 (6) | **0** |
| `polyvecl_uniform_gamma1` — polyvecl_uniform_gamma1 | 10 | 0/10 | 4.5 | 3.1 | 74% | 2 (38) | 2 (32) | **0** |
| `poly_chknorm` — poly_chknorm | 16 | 0/16 | 1.0 | 0.0 | 25% | 1 (1) | 1 (1) | **0** |

*(A) LEAK is shown as n/a when the unfaulted outputs already separate the keys (max|t| > 4.5): the function output is a secret intermediate, so a key-dependent faulted output is expected and not a fault finding. Effective = mean fraction of (site, message) replays whose output differs from the unfaulted one.*

## Key-dependent φIF sites (A/B significantly above the A/A' control)

None: at every site the A/B flip count is within what input-dependence alone produces (A/A').

## Largest raw A/B φIF sites (before the control), for reference

`ntt_c`: `0x5b2c` smull sb, fp, fp, r1 (8 vs 5), `0x5b34` smlal sb, fp, sl, r3 (8 vs 5), `0x5b38` smull sb, ip, ip, r1 (8 vs 7), `0x5b40` smlal sb, ip, sl, r3 (8 vs 7), `0x5b52` add r6, fp (8 vs 5)

`small_ntt_c`: `0x617c` smulwt r7, sl, r7 (24 vs 17), `0x6184` smlabt r7, r7, ip, r0 (24 vs 17), `0x6180` smlabt lr, lr, ip, r0 (19 vs 11), `0x63d8` smlabt lr, lr, ip, r0 (17 vs 14), `0x6160` smulwt r6, sl, r6 (16 vs 18)

`small_invntt_cs1`: `0x6c44` smulwb lr, sl, r2 (4 vs 4), `0x6c90` smlabt r5, r5, ip, r0 (4 vs 3), `0x6cb4` smulwt r7, fp, r7 (4 vs 3), `0x6ce0` smulwt sb, fp, sb (4 vs 5), `0x6c7c` smlabt r4, r4, ip, r0 (3 vs 1)

`small_invntt_cs2`: `0x6c90` smlabt r5, r5, ip, r0 (5 vs 6), `0x6c44` smulwb lr, sl, r2 (4 vs 1), `0x6c2c` smlabt lr, lr, ip, r0 (3 vs 2), `0x6c5c` smulwt r3, fp, r3 (3 vs 1), `0x6c8c` smlabt lr, lr, ip, r0 (3 vs 4)

`poly_challenge`: `0x4122` str.w r0, [r7, r4, lsl #2] (3 vs 4), `0x40a2` ldrb.w r5, [sp, #2] (1 vs 1), `0x40ae` lsls r5, r5, #0x10 (1 vs 1), `0x40be` orr.w r5, r5, r3, lsl #24 (1 vs 0), `0x4140` lsr.w r6, r6, #1 (1 vs 0)

`polyvecl_uniform_gamma1`: `0x4684` lsls r2, r2, #2 (19 vs 16), `0x468c` uxth r4, r2 (19 vs 16)

`poly_chknorm`: `0x3ea0` ldr r3, [pc, #0x28] (1 vs 1)

## Notes on the remaining (A) LEAK flags

- `ntt_y` (2 sites, `0x59a0 cmp.w r0, sl` / `0x59a4 bne.w`, |t|=8.9; same-key control 3.1): skipping the NTT's loop exit runs an extra pass that reads past the y buffer. Re-run with the **snapshot** backend (real memory layout, `dumps_snap/ntt_y_instrskip`) the same sites score |t|=3.9, not significant: the call backend relocates inputs into scratch memory, so the overflowing pass read replay-environment bytes, not the signing's real neighbours. **Artifact.** General caveat: a skip that breaks a loop bound reads/writes out of the target's buffers, and only the snapshot backend reproduces what lies there.
- Every other LEAK count on this page is n/a: the output is key-separable with no fault (key-fixed operand, or the matched filter recovering s1 from c·s1).

