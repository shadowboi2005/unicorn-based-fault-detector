# Why the φIF signal concentrates in `ntt` (ML-DSA-44 / Dilithium, m4f)

Companion to `report/llvm_vs_arm.md`. That report finds **71 key-dependent-ineffective
(φIF) sites** across 4 sign-reachable functions, overwhelmingly in `ntt` (**63**), then
`poly_challenge`(5), `polyvecl_uniform_gamma1`(2), `poly_chknorm`(1). This note explains
*why* `ntt` dominates: the φIF sites are the signed-Montgomery **butterfly** ops, and the
m4f build has relocated the secret-dependent arithmetic into them.

φIF recap: A and B sign the **same n=40 messages with the same RNG** (only `sk` differs).
Per skip site, `flips` = how many messages have the single-instruction skip be a **no-op
for one key but output-changing for the other**. A site is φIF if `flips ≥ 1`. This is the
LLVM *ineffective* axis, not a TVLA distribution test.

## 1. `ntt` structure (disassembly)

`pqcrystals_dilithium_ntt`, `0x5714–0x5cdc` (396 instrs) in `firmware/ml-dsa-44_m4f_test.elf`.
This is the pqm4 `m4f` hand-optimised NTT: a length-256 radix-2 NTT done as **merged
3-layer passes** over the coefficient array, not the reference's doubly-nested loop.

Setup (`0x5714–0x572c`): `r2 = qinv = 0xfc7fdfff`, `r3 = q = 0x007fe001 = 8380417`
(constant pool `inv_ntt_asm_smull_q{inv}` at `0x610c/0x6110`); the 7 twiddles for a merged
3-layer group are streamed from the zeta table into FP regs `s2–s8` via `vldmia r1!,{s2-s8}`
(`s0` holds the running table pointer). Each pass:

- loads 8 coefficients at a fixed stride (pass 1 `0x5734`: stride `#128` B = 32 int32;
  pass 2 `0x59c8`: stride `#16` B = 4 int32) into `r4–r8, fp, ip, lr`;
- runs **12 butterflies = 3 merged layers × 4** with twiddles `s2..s8`;
- stores the 8 results and advances `r0` by 4, looping (`cmp r0,sl` / `bne.w 0x5734`,
  `0x599c–0x59a4`) over 32 groups → 384 butterflies = 3 full layers per pass.

8 layers = 3 + 3 + 2, so the same ~18 butterfly PCs in the unrolled bodies each re-execute
across the 32 loop iterations.

### The butterfly op pattern (signed Montgomery)

Canonical group, e.g. `0x5758–0x5790` (operand in `r4`, twiddle `r1←s2`):

```
smull  r9, r4, r4, r1     ; (lo=r9, hi=r4) = coeff · zeta          (full 64-bit signed product)
mul.w  sl, r9, r2         ; sl = lo · qinv  (mod 2^32)             (Montgomery m)
smlal  r9, r4, sl, r3     ; (r9,r4) += m · q ; r4 = hi word = t    (= montgomery_reduce(coeff·zeta))
add    r5, r4             ; a' = a + t                             (butterfly add)
sub.w  r4, r5, r4, lsl #1 ; b' = a' − 2t = a − t                   (butterfly sub)
```

So `smull`+`mul`+`smlal` is `montgomery_reduce(zeta·b)` → `t`; `add`/`sub.w` is the
Cooley–Tukey combine `(a+t, a−t)`.

## 2. The 63 φIF sites are butterfly arithmetic, not loop/address setup

Recomputing the report's φIF detail over `dumps/ntt_instrskip` (n=40/key), broken down by
mnemonic:

| mnemonic | φIF sites | flips |
|---|---|---|
| `smull` | 18 | 84 |
| `smlal` | 18 | 84 |
| `add`   | 18 | 84 |
| `mul`   |  5 |  5 |
| `sub.w` |  4 |  4 |
| **total** | **63** | **261** |

Every one of the 63 sites is butterfly ALU arithmetic. **0** are `ldr`/`str`/`vmov`/
`vldmia`/`cmp`/`bne` (coefficient load/store, twiddle fetch, pointer/loop setup) — those
skips are either unconditionally effective or unconditionally crash/no-op the same way for
both keys, so they never flip. The core combine (`smull`+`smlal`+`add` = 54 sites, 252 of
261 flips, 84 flips each) carries essentially all of the signal; `mul`/`sub.w` contribute 9
sites at 1 flip each (boundary noise). The signal is the arithmetic, not the plumbing.

## 3. Data-flow reason: why it lands in `ntt`

In ML-DSA-44 signing, `ntt` runs on **secret-derived polynomials**: `s1`/`s2` are NTT'd, and
the rejection-sampling loop computes the challenge-scaled products `c·s1`, `c·s2` whose NTT
operands depend on the secret. A butterfly multiply `t = montgomery_reduce(zeta·b)` is
**ineffective** (skipping it leaves the stored output byte-identical) essentially iff `t`
does not affect the reduced result — operationally when the (secret-derived) operand `b`
reduces so that `t ≡ 0 mod q`, or when a skipped `smull`/`smlal` happens to leave a
coincidentally identical reduced coefficient. That is a **per-coefficient, value-dependent
condition on a secret-derived operand**, so whether a given PC is a no-op for message `i`
differs between keys A and B → a flip.

**Why 63 (so many):** the NTT butterfly network is a wide tree of *independently*
conditionally-dead multiply/accumulate ops. The unrolled m4f bodies expose ~18 distinct
`smull` PCs, ~18 `smlal`, ~18 `add`, each re-run across 32 loop iterations over different
coefficients. Each PC is the dead op for *some* coefficient/message under *some* key, so each
is an independent φIF candidate — the count scales with the butterfly population, not with a
single leaky instruction.

### Inlining-relocation argument

In reference Dilithium the obviously secret-dependent multiply is the **pointwise** `c·s`
(`poly_pointwise_montgomery` / `polyvecl_pointwise_poly_montgomery`). The m4f optimising
compiler **inlines those `*_pointwise_poly_montgomery` multiplies out of the signing path**
(`llvm_vs_arm.md`: 8 reference functions inlined, those among them). With no standalone
pointwise-multiply symbol to fault, the visibly faultable secret arithmetic has **migrated
into the NTT butterflies** that transform the secret-derived polynomials. So `ntt` is both
(a) where the secret operands flow and (b) the surviving home of the inlined `c·s` work —
which is exactly why φIF piles up there rather than in a pointwise-mul function.

## 4. Why flip counts per site are small

Max `flips` is 8/40; most φIF sites flip 1–8 times (261 flips / 63 sites ≈ 4.1 avg). Being a
no-op is a **rare boundary condition** — the operand of a specific butterfly, in a specific
message, reduces to the dead case (`t ≡ 0 mod q` / coincident reduction). Across 40 messages
the two keys drive different coefficient values into that butterfly, so only a handful of
messages land on the boundary for exactly one key. The per-site signal is a thin boundary
effect, not a persistent key split — consistent with a candidate surface rather than a
confirmed leak.

## 5. Standing caveat (unchanged from `llvm_vs_arm.md`)

φIF **locates candidate sites; it does not prove SIFA-exploitability.** A and B each run a
full signing, so they also feed *different inputs* (different `c̃`, `μ`) into `ntt` — a flip
conflates genuine **key-dependence** with ordinary **input-dependence**. Publicness of the
driving value does not rule a site out, since SIFA exploits an ineffective-*conditioned bias*
that can arise even for public operands. Deciding each `ntt` butterfly site requires the SIFA
test proper: **fix the key, fault across many inputs, filter to the ineffective subset, and
test the conditional bias** of the recovered coefficients. This note explains the geography
of the candidate surface; it does not upgrade it to a leak.

---
*Numbers: `dumps/ntt_instrskip` (n=40/key); disassembly `firmware/ml-dsa-44_m4f_test.elf`
`pqcrystals_dilithium_ntt` `0x5714–0x5cdc`. φIF computation matches
`scripts/build_llvm_report.py` (`phi_sites`/`phi_flips`) and `scripts/plot_regions.py`
(`phi_by_pc`).*
