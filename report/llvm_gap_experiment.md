# Why our sweep finds ~nothing vs the LLVM tool: experiment

Target `firmware/ml-dsa-44_clean_test.elf` (PQClean reference-C 'clean' build; nothing inlined). Fault model held constant = whole-call **skip**, the primitive both tools share. n=8 messages/side.

## Arm A - SCOPE: skip each callee of the signing body (phi_IF / `ineffective`)

Signing body `PQCLEAN_MLDSA44_CLEAN_crypto_sign_signature_ctx` has 49 `bl` sites (direct callees). For each we skip the whole call and compare the released 2420-byte signature. phi_IF A/B = messages where the skip changed the signature for one key but not the other; A/A' is the same for key A on disjoint messages (input-only control). Key-dependent = A/B above A/A' (one-sided Fisher, BH-FDR q=0.05).

| callee (bl) | A/B flips | A/A' flips | key-dep? |
|---|---|---|---|
| `bl PQCLEAN_MLDSA44_CLEAN_polyveck_sub` | 2/8 | 2/8 | no |
| `bl PQCLEAN_MLDSA44_CLEAN_unpack_sk` | 0/8 | 0/8 | no |
| `bl shake256_inc_init` | 0/8 | 0/8 | no |
| `bl shake256_inc_absorb` | 0/8 | 0/8 | no |
| `bl shake256_inc_absorb` | 0/8 | 0/8 | no |
| `bl shake256_inc_absorb` | 0/8 | 0/8 | no |
| `bl shake256_inc_absorb` | 0/8 | 0/8 | no |
| `bl shake256_inc_finalize` | 0/8 | 0/8 | no |
| `bl shake256_inc_squeeze` | 0/8 | 0/8 | no |
| `bl shake256_inc_ctx_release` | 0/8 | 0/8 | no |
| `bl PQCLEAN_randombytes` | 0/8 | 0/8 | no |
| `bl shake256` | 0/8 | 0/8 | no |
| `bl PQCLEAN_MLDSA44_CLEAN_polyvec_matrix_expand` | 0/8 | 0/8 | no |
| `bl PQCLEAN_MLDSA44_CLEAN_polyvecl_ntt` | 0/8 | 0/8 | no |
| `bl PQCLEAN_MLDSA44_CLEAN_polyveck_ntt` | 0/8 | 0/8 | no |
| `bl PQCLEAN_MLDSA44_CLEAN_polyveck_ntt` | 0/8 | 0/8 | no |
| `bl PQCLEAN_MLDSA44_CLEAN_polyvecl_uniform_gamma1` | 0/8 | 0/8 | no |
| `bl memcpy` | 0/8 | 0/8 | no |
| `bl PQCLEAN_MLDSA44_CLEAN_polyvecl_ntt` | 0/8 | 0/8 | no |
| `bl PQCLEAN_MLDSA44_CLEAN_polyvec_matrix_pointwise_montgomery` | 0/8 | 0/8 | no |
| `bl PQCLEAN_MLDSA44_CLEAN_polyveck_reduce` | 0/8 | 0/8 | no |
| `bl PQCLEAN_MLDSA44_CLEAN_polyveck_invntt_tomont` | 0/8 | 0/8 | no |
| `bl PQCLEAN_MLDSA44_CLEAN_polyveck_caddq` | 0/8 | 0/8 | no |
| `bl PQCLEAN_MLDSA44_CLEAN_polyveck_decompose` | 0/8 | 0/8 | no |
| `bl PQCLEAN_MLDSA44_CLEAN_polyveck_pack_w1` | 0/8 | 0/8 | no |
| `bl shake256_inc_init` | 0/8 | 0/8 | no |
| `bl shake256_inc_absorb` | 0/8 | 0/8 | no |
| `bl shake256_inc_absorb` | 0/8 | 0/8 | no |
| `bl shake256_inc_finalize` | 0/8 | 0/8 | no |
| `bl shake256_inc_squeeze` | 0/8 | 0/8 | no |
| `bl shake256_inc_ctx_release` | 0/8 | 0/8 | no |
| `bl PQCLEAN_MLDSA44_CLEAN_poly_challenge` | 0/8 | 0/8 | no |
| `bl PQCLEAN_MLDSA44_CLEAN_poly_ntt` | 0/8 | 0/8 | no |
| `bl PQCLEAN_MLDSA44_CLEAN_polyvecl_pointwise_poly_montgomery` | 0/8 | 0/8 | no |
| `bl PQCLEAN_MLDSA44_CLEAN_polyvecl_invntt_tomont` | 0/8 | 0/8 | no |
| `bl PQCLEAN_MLDSA44_CLEAN_polyvecl_add` | 0/8 | 0/8 | no |
| `bl PQCLEAN_MLDSA44_CLEAN_polyvecl_reduce` | 0/8 | 0/8 | no |
| `bl PQCLEAN_MLDSA44_CLEAN_polyvecl_chknorm` | 0/8 | 0/8 | no |
| `bl PQCLEAN_MLDSA44_CLEAN_polyveck_pointwise_poly_montgomery` | 0/8 | 0/8 | no |
| `bl PQCLEAN_MLDSA44_CLEAN_polyveck_invntt_tomont` | 0/8 | 0/8 | no |
| `bl PQCLEAN_MLDSA44_CLEAN_polyveck_reduce` | 0/8 | 0/8 | no |
| `bl PQCLEAN_MLDSA44_CLEAN_polyveck_chknorm` | 0/8 | 0/8 | no |
| `bl PQCLEAN_MLDSA44_CLEAN_polyveck_pointwise_poly_montgomery` | 0/8 | 0/8 | no |
| `bl PQCLEAN_MLDSA44_CLEAN_polyveck_invntt_tomont` | 0/8 | 0/8 | no |
| `bl PQCLEAN_MLDSA44_CLEAN_polyveck_reduce` | 0/8 | 0/8 | no |
| `bl PQCLEAN_MLDSA44_CLEAN_polyveck_chknorm` | 0/8 | 0/8 | no |
| `bl PQCLEAN_MLDSA44_CLEAN_polyveck_add` | 0/8 | 0/8 | no |
| `bl PQCLEAN_MLDSA44_CLEAN_polyveck_make_hint` | 0/8 | 0/8 | no |
| `bl PQCLEAN_MLDSA44_CLEAN_pack_sig` | 0/8 | 0/8 | no |

**0/49 callees** are key-dependent-ineffective (A/B above the A/A' control). Compare to the CSV's `loopOrFuncSkip ... fnSkip` detections on `signature_internal`.


## Arm B - ORACLE: many-key, per-position phi_IF (the `ineffective` witness)

Our shipped phi_IF uses 2 random keys over the whole 2420-byte signature. Here, for each site, the SECRET arm holds the message+RNG fixed and varies the key over K=32 independent keygens (only sk differs); the INPUT control holds the key fixed and varies the message over K. A byte POSITION is a key-dependent-ineffective witness if the skip is effective for some keys but not others there, significantly more under secret variation than input variation (one-sided Fisher per position, BH-FDR q=0.05). This samples the LLVM tool's 'exists s1 ineffective, s2 effective'.

| callee (bl) | shipped 2-key whole-output phi_IF | many-key witness positions | example attribution |
|---|---|---|---|
| `bl PQCLEAN_MLDSA44_CLEAN_polyveck_decompose` | no flag | **51** / 304 split | pos 105: s1[0,95] mean -2.0 (ineff) vs 0.6 (eff) |
| `bl PQCLEAN_MLDSA44_CLEAN_poly_challenge` | no flag | **146** / 327 split | pos 4: s1[0,181] mean 2.0 (ineff) vs -0.6 (eff) |
| `bl PQCLEAN_MLDSA44_CLEAN_polyvecl_add` | no flag | **14** / 303 split | pos 0: s1[2,153] mean 2.0 (ineff) vs -0.8 (eff) |

Positions flagged here are invisible to the shipped 2-key/whole-output phi_IF but are exactly the LLVM tool's per-position `ineffective` witnesses. A nonzero 'many-key witness positions' with a 'no flag' shipped column is direct evidence that the ORACLE (average-case 2-key vs worst-case per-position secret search), not the fault model, is what hides these sites from us.


## Conclusion: the gap is the ORACLE, not the fault model (and only partly scope)

Holding the fault model fixed (whole-call **skip**, which both tools share) and running on the
reference-style **clean** build whose signing body calls exactly the CSV's callee set, the two
arms separate the causes cleanly:

- **Arm A (scope) alone finds nothing.** Skipping each of the 49 signing-body callees — the very
  sites the CSV flags via `loopOrFuncSkip`/`fnSkip`, Keccak and packing included — yields **0/49**
  key-dependent-ineffective callees under our shipped **2-key / whole-released-signature** phi_IF.
  Even `polyvecl_add` (our one real leak) is 0/8 here, correctly: that leak is a per-coordinate
  TVLA signal on the function *output*, not a whole-signature flip. So **coverage is necessary but
  not sufficient** — skipping the right calls with our oracle still surfaces nothing.

- **Arm B (oracle) recovers the detections.** The same sites, scored by a **many-key, per-position**
  phi_IF (fix the public background, vary the secret over K=32 keys, test each output byte against
  an input-variation control) light up strongly: **polyveck_decompose 51, poly_challenge 146,
  polyvecl_add 14** key-dependent-ineffective byte positions — each attributable to a specific
  `s1` coefficient (e.g. `polyveck_decompose` pos 105 separates on `s1[0,95]`: mean -2.0 for keys
  where the skip is ineffective vs 0.6 where it is effective). This is exactly the LLVM tool's
  "exists s1 ineffective, s2 effective" witness, reproduced by *sampling* instead of SMT.

**Why we were finding ~nothing**, in order of impact:
1. **Oracle (dominant).** Our shipped detector averages over 2 random keys and the whole output; the
   LLVM tool fixes the public input, sweeps the secret, and tests **each output position**. The
   key-dependence lives in individual (coefficient -> position) relations that whole-output 2-key
   sampling averages to zero. Arm B shows the signal is *there* — our oracle just can't see it.
2. **Scope (enabler).** Our shipped study swept *inside* functions and never skipped the signing
   body's calls, and ran on the m4f binary that inlines many of these functions away. Fixing scope
   (clean build + whole-call skip) is what let Arm B even reach these sites — but scope without the
   oracle (Arm A) is still blind.
3. **Fault model (minor).** `binOpFault`/`loadStoreSkip` (10/93 of the CSV) and `direct_leak` have
   no skip-only analog; not needed to explain the bulk of the gap.

**Caveat (candidate-locator framing preserved).** Like the CSV's own wording, a per-position
`ineffective` witness **locates a SIFA/ineffective-fault candidate surface; it is not a proven
exploit.** This experiment explains a *detection-rate* gap and points to the concrete upgrade
(a per-position, secret-sweeping phi_IF oracle) — it makes no exploitability claim.
