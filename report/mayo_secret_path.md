# MAYO1 m4f: instruction-skip φIF over the whole secret-dependent signing path

Extends `report/mayo_phi_funcskip.md` (11 hand-picked functions, 8 msgs/key, no control) to every secret-dependent function a MAYO1 m4f signing calls (from a call trace of one signing), with a **same-key control**. Snapshot-region replay: snapshot at the function's first entry, skip one instruction, run entry→ret, compare writable RAM + r0 with golden.

- **A/B**: keys A and B, same message + RNG. A flip = the skip is a no-op for one key and effective for the other. Mixes key- and input-dependence.
- **A/A'**: key A vs key A on disjoint messages: input-dependence only.
- **key-dependent site**: A/B flips significantly above A/A' (one-sided Fisher exact per site, BH-FDR q=0.05 across all swept sites).
- Not swept: the two top-level drivers `mayo_expand_sk` and `mayo_sign_signature` (entry→ret re-runs ~7.5M / ~13.7M instructions per replay; their callees are swept individually). Multiply-called asm workers are faulted at their first call.
- There is no (A) LEAK axis here: the compared state is the whole writable RAM, not a released output, so a distribution test on it is not meaningful.

## Summary

| function | role | sites (stride) | effective | crash | φIF A/B sites (flips) | φIF A/A' sites (flips) | **key-dep. sites** |
|---|---|---|---|---|---|---|---|
| `P1P1t_times_O.isra.0` | L = (P1+P1ᵀ)O  [O secret] | 141 (1) | 94% | 25% | 0 (0) | 0 (0) | **0** |
| `multiply_P1_right_m4f_V_V_O_asm` | P1·O worker  [O] | 544 (2) | 95% | 0% | 31 (496) | 0 (0) | **31** |
| `multiply_P1t_right_m4f_V_V_O_asm` | P1ᵀ·O worker  [O] | 502 (2) | 94% | 0% | 32 (512) | 0 (0) | **32** |
| `multiply_P1_right_m4f_O_asm2` | P1·O tail worker  [O] | 422 (2) | 98% | 0% | 5 (80) | 0 (0) | **5** |
| `compute_M_and_VPV.isra.0` | M = V·L, VPV  [V secret] | 27 (1) | 94% | 36% | 1 (1) | 0 (0) | **0** |
| `P1_times_Vt.isra.0` | P1·Vᵀ  [V] | 119 (1) | 97% | 17% | 0 (0) | 0 (0) | **0** |
| `multiply_P1_right_transposed_m4f` | P1·Vᵀ driver  [V] | 25 (1) | 88% | 32% | 0 (0) | 0 (0) | **0** |
| `multiply_P1_right_m4f_V_V_K_asm` | P1·Vᵀ worker  [V] | 629 (3) | 95% | 8% | 112 (555) | 83 (83) | **30** |
| `multiply_P1_right_m4f_K_asm2_transposed` | P1·Vᵀ tail worker  [V] | 550 (3) | 99% | 0% | 86 (122) | 72 (113) | **0** |
| `mul_add_mat_x_m_mat_m4f_K_V_O_triangular_asm` | V·L accumulate  [V, L] | 263 (1) | 81% | 5% | 0 (0) | 0 (0) | **0** |
| `mul_add_mat_x_m_mat_m4f_K_V_K_triangular_asm` | V·(P1Vᵀ) accumulate  [V] | 263 (1) | 80% | 5% | 0 (0) | 0 (0) | **0** |
| `compute_rhs.isra.0` | t − VPV  [V] | 203 (1) | 91% | 9% | 7 (28) | 7 (14) | **0** |
| `sample_solution` | solve Mx = y, s = v + O·x  [V, O] | 231 (1) | 66% | 14% | 18 (38) | 13 (28) | **0** |
| `EF_m4f.constprop.0` | Gaussian elimination driver  [M] | 85 (1) | 71% | 27% | 0 (0) | 0 (0) | **0** |
| `ef_bitslice_asm` | EF bitslice  [M] | 139 (1) | 100% | 1% | 0 (0) | 0 (0) | **0** |
| `ef_inner1_asm` | EF inner 1  [M] | 97 (1) | 61% | 6% | 8 (66) | 8 (56) | **0** |
| `ef_inner2_asm` | EF inner 2  [M] | 147 (1) | 41% | 1% | 48 (365) | 48 (352) | **0** |
| `ef_inner3_asm` | EF inner 3  [M] | 64 (1) | 44% | 2% | 11 (27) | 11 (29) | **0** |
| `ef_inner4_asm` | EF inner 4  [M] | 173 (1) | 57% | 3% | 0 (0) | 0 (0) | **0** |
| `ef_unbitslice_asm` | EF unbitslice  [M] | 150 (1) | 92% | 1% | 35 (115) | 29 (98) | **0** |
| `backsub_inner_asm` | back-substitution  [M] | 459 (1) | 76% | 1% | 306 (1339) | 300 (563) | **0** |

n = 16 messages per side. *effective* = share of non-crashing replays whose state differs from golden; *crash* = replays that faulted or hit the budget.

## Key-dependent sites

**`multiply_P1_right_m4f_V_V_O_asm`**

| addr | instruction | A/B flips | A/A' flips | p |
|---|---|---|---|---|
| `0x9ddc` | `ubfx r6, r3, #0x18, #4` | 16/16 | 0/16 | 1.7e-09 |
| `0xa09c` | `ror.w sl, sl, #4` | 16/16 | 0/16 | 1.7e-09 |
| `0xa184` | `ror.w sl, sl, #4` | 16/16 | 0/16 | 1.7e-09 |
| `0xa22c` | `ubfx r6, r3, #0x10, #4` | 16/16 | 0/16 | 1.7e-09 |
| `0xa38c` | `ubfx r6, r3, #0, #4` | 16/16 | 0/16 | 1.7e-09 |
| `0xa41c` | `bfi r6, sl, #4, #4` | 16/16 | 0/16 | 1.7e-09 |
| `0xa474` | `ubfx r6, r3, #0, #4` | 16/16 | 0/16 | 1.7e-09 |
| `0xa55c` | `ubfx r6, r3, #0, #4` | 16/16 | 0/16 | 1.7e-09 |
| `0xa594` | `ubfx r6, r3, #8, #4` | 16/16 | 0/16 | 1.7e-09 |
| `0xa5cc` | `ubfx r6, r3, #0x10, #4` | 16/16 | 0/16 | 1.7e-09 |
| `0xa71c` | `eor.w r4, r4, r8` | 16/16 | 0/16 | 1.7e-09 |
| `0xa734` | `ldr.w r8, [r1, r6, lsl #2]` | 16/16 | 0/16 | 1.7e-09 |
| `0xa75c` | `lsl.w r6, r6, #4` | 16/16 | 0/16 | 1.7e-09 |
| `0xa774` | `lsl.w r6, r6, #4` | 16/16 | 0/16 | 1.7e-09 |
| `0xa77c` | `ldr.w r8, [r1, r6, lsl #2]` | 16/16 | 0/16 | 1.7e-09 |
| `0xa7bc` | `lsl.w r6, r6, #4` | 16/16 | 0/16 | 1.7e-09 |
| `0xa85c` | `eor.w r4, r4, r8` | 16/16 | 0/16 | 1.7e-09 |
| `0xa8d4` | `ldr.w r8, [r1, r6, lsl #2]` | 16/16 | 0/16 | 1.7e-09 |
| `0xa944` | `lsl.w r6, r6, #4` | 16/16 | 0/16 | 1.7e-09 |
| `0xa95c` | `lsl.w r6, r6, #4` | 16/16 | 0/16 | 1.7e-09 |

**`multiply_P1t_right_m4f_V_V_O_asm`**

| addr | instruction | A/B flips | A/A' flips | p |
|---|---|---|---|---|
| `0xcbb0` | `ubfx r6, sl, #4, #4` | 16/16 | 0/16 | 1.7e-09 |
| `0xcbb8` | `ldr.w r8, [r1, r6, lsl #2]` | 16/16 | 0/16 | 1.7e-09 |
| `0xcbc8` | `ldr.w r4, [r0]` | 16/16 | 0/16 | 1.7e-09 |
| `0xcc60` | `eor.w r4, r4, r8` | 16/16 | 0/16 | 1.7e-09 |
| `0xcca8` | `ldr.w r4, [r0]` | 16/16 | 0/16 | 1.7e-09 |
| `0xccb0` | `eor.w r4, r4, r8` | 16/16 | 0/16 | 1.7e-09 |
| `0xccf0` | `eor.w r4, r4, r8` | 16/16 | 0/16 | 1.7e-09 |
| `0xcd48` | `ubfx r6, sl, #0x14, #4` | 16/16 | 0/16 | 1.7e-09 |
| `0xcd50` | `ldr.w r8, [r1, r6, lsl #2]` | 16/16 | 0/16 | 1.7e-09 |
| `0xcdf8` | `eor.w r4, r4, r8` | 16/16 | 0/16 | 1.7e-09 |
| `0xce20` | `eor.w r4, r4, r8` | 16/16 | 0/16 | 1.7e-09 |
| `0xce30` | `ldr.w r4, [r0]` | 16/16 | 0/16 | 1.7e-09 |
| `0xce80` | `ldr.w r4, [r0]` | 16/16 | 0/16 | 1.7e-09 |
| `0xcf20` | `ubfx r6, sl, #0x10, #4` | 16/16 | 0/16 | 1.7e-09 |
| `0xcf28` | `ldr.w r8, [r1, r6, lsl #2]` | 16/16 | 0/16 | 1.7e-09 |
| `0xcf80` | `eor.w r4, r4, r8` | 16/16 | 0/16 | 1.7e-09 |
| `0xd018` | `ubfx r6, sl, #0, #4` | 16/16 | 0/16 | 1.7e-09 |
| `0xd020` | `ldr.w r8, [r1, r6, lsl #2]` | 16/16 | 0/16 | 1.7e-09 |
| `0xd058` | `ldr.w r4, [r0]` | 16/16 | 0/16 | 1.7e-09 |
| `0xd120` | `ubfx r6, sl, #0x14, #4` | 16/16 | 0/16 | 1.7e-09 |

**`multiply_P1_right_m4f_O_asm2`**

| addr | instruction | A/B flips | A/A' flips | p |
|---|---|---|---|---|
| `0xe948` | `ubfx r7, r5, #0x10, #4` | 16/16 | 0/16 | 1.7e-09 |
| `0xe970` | `ubfx r7, r6, #0x18, #4` | 16/16 | 0/16 | 1.7e-09 |
| `0xea88` | `eor.w r4, r4, r7, lsl #4` | 16/16 | 0/16 | 1.7e-09 |
| `0xea90` | `eor.w r4, r4, r7, lsl #8` | 16/16 | 0/16 | 1.7e-09 |
| `0xed28` | `eor.w r4, r4, r5, lsl #1` | 16/16 | 0/16 | 1.7e-09 |

**`multiply_P1_right_m4f_V_V_K_asm`**

| addr | instruction | A/B flips | A/A' flips | p |
|---|---|---|---|---|
| `0xb578` | `ror.w sl, sl, #4` | 16/16 | 0/16 | 1.7e-09 |
| `0xbe90` | `ldr.w r8, [r6]` | 16/16 | 0/16 | 1.7e-09 |
| `0xbed8` | `lsl.w r6, r6, #4` | 16/16 | 0/16 | 1.7e-09 |
| `0xbef0` | `eor.w r4, r4, r8` | 16/16 | 0/16 | 1.7e-09 |
| `0xbf14` | `ldr.w r5, [r0, #4]` | 16/16 | 0/16 | 1.7e-09 |
| `0xbf8c` | `lsl.w r6, r6, #4` | 16/16 | 0/16 | 1.7e-09 |
| `0xbfa4` | `eor.w r4, r4, r8` | 16/16 | 0/16 | 1.7e-09 |
| `0xc010` | `lsl.w r6, r6, #4` | 16/16 | 0/16 | 1.7e-09 |
| `0xc028` | `eor.w r4, r4, r8` | 16/16 | 0/16 | 1.7e-09 |
| `0xc154` | `ldr.w r5, [r0, #4]` | 16/16 | 0/16 | 1.7e-09 |
| `0xc304` | `lsl.w r6, r6, #4` | 16/16 | 0/16 | 1.7e-09 |
| `0xc310` | `ldr.w r5, [r0, #4]` | 16/16 | 0/16 | 1.7e-09 |
| `0xc31c` | `eor.w r4, r4, r8` | 16/16 | 0/16 | 1.7e-09 |
| `0xc340` | `ldr.w r5, [r0, #4]` | 16/16 | 0/16 | 1.7e-09 |
| `0xc37c` | `eor.w r5, r5, sb` | 16/16 | 0/16 | 1.7e-09 |
| `0xc394` | `ldr.w r4, [r0]` | 16/16 | 0/16 | 1.7e-09 |
| `0xc3f4` | `ldr.w r8, [r6]` | 16/16 | 0/16 | 1.7e-09 |
| `0xc418` | `ldr.w r4, [r0]` | 16/16 | 0/16 | 1.7e-09 |
| `0xc52c` | `ldr.w r8, [r6]` | 16/16 | 0/16 | 1.7e-09 |
| `0xc760` | `lsl.w r6, r6, #4` | 16/16 | 0/16 | 1.7e-09 |

## Interpretation: the flagged sites are per-key constants, not 16 samples

Every flagged site has A/B = 16/16 and A/A' = 0/16. That is the signature of a computation that does not depend on the message: the P1·O workers (`multiply_P1_right_m4f_V_V_O_asm`, `multiply_P1t_right_m4f_V_V_O_asm`, `multiply_P1_right_m4f_O_asm2`) are only called from `P1P1t_times_O` ← `mayo_expand_sk(sk)`, which reads nothing but the secret key, so all 16 messages replay the identical state per key. The A/A' control is then 0 by construction and the 16 A/B flips are ONE comparison (key A's P1, O vs key B's) repeated 16 times -- effectively n = 1 key pair, so the Fisher p-values overstate the evidence. The flagged `multiply_P1_right_m4f_V_V_K_asm` sites are the same: sites whose no-op status depends only on the per-key matrix, not on the per-message vinegar V (its other sites vary with V and are within the control).

What it does show: at these sites, whether the skip changes the state is decided by key-specific data. With only two keys it cannot say whether that is the secret O or the public P1 (both are derived from `seed_sk`, so they differ together). Deciding it needs a **many-key** test (one signing per key over K keys, check whether each site's ineffectiveness varies across keys and correlates with O), not more messages.

Everything that does depend on the message (V·L, VPV, `compute_rhs`, `sample_solution`, the Gaussian elimination and back-substitution) shows A/B flip rates within the A/A' control: **no key-dependent sites**.

