# The single correction→ARM leak: `polyvecl_add` (`z = c·s1 + y`)

Under whole-instruction `funcskip` (n=40/key, A vs B share message+RNG, only `sk` differs),
the **distribution-difference detector (A)** -- `per_coord`/TVLA, Welch |t|, flag at FDR≤0.01
(≈|t|4.5) -- flags **exactly one** function across all 21 reachable Dilithium routines:
`pqcrystals_dilithium_polyvecl_add` at `0x46d0`. 5 of its scored sites are LEAK, max |t|=16.9,
versus a no-leak floor of |t|≈3.0–3.7 inside the function and ≤4.5 everywhere else in signing.
This is the canonical *Exploiting-Determinism* fault.

## Disassembly (firmware `firmware/ml-dsa-44_m4f_test.elf`, `objdump`)

```
000046d0 <pqcrystals_dilithium_polyvecl_add>:
  46d0: b5f8        push {r3,r4,r5,r6,r7,lr}
  46d2: 4607        mov  r7, r0            ; r7 = output/acc base &z  (= &c·s1, in-place)
  46d4: 460e        mov  r6, r1            ; r6 = operand-a base &u   (also &z here)
  46d6: 4615        mov  r5, r2            ; r5 = operand-b base &v   (= &y, the mask)
  46d8: 2400        movs r4, #0            ; byte offset = 0
  46da: 192a        adds r2, r5, r4        ; r2 = &y + off   (poly_add arg3)
  46dc: 1931        adds r1, r6, r4        ; r1 = &z + off   (poly_add arg2 = c·s1[i])
  46de: 1938        adds r0, r7, r4        ; r0 = &z + off   (poly_add arg1 = output)
  46e0: f504 6480   add.w r4, r4, #1024    ; off += 1024  (sizeof(poly) = 256*4)
  46e4: f7ff fb56   bl   3d94 <poly_add>   ; z[i] = c·s1[i] + y[i]
  46e8: f5b4 5f80   cmp.w r4, #4096        ; L=4 polys * 1024
  46ec: d1f5        bne.n 46da
  46ee: bdf8        pop  {r3,r4,r5,r6,r7,pc}
```

Call site (`signature_internal`, `0x4d5a`): `mov r0, r1` then `bl 46d0`, i.e. **in-place**
`polyvecl_add(&z, &z, &y)`. Per pqm4 ref the preceding steps leave `&z = c·s1` (after
`polyvecl_pointwise_poly_montgomery` + `polyvecl_invntt_tomont`), so this add is `z = c·s1 + y`.

## LEAK sites (`per_coord`, real |t| from the dump)

| addr | max\|t\| | instruction | role | effect of skip |
|---|---|---|---|---|
| `0x46d2` | 16.9 | `mov r7, r0` | output base `&z` setup | all 4 output pointers stale → `z` never overwritten → `z` stays `= c·s1` (all L=4 polys) |
| `0x46dc` | 4.58 | `adds r1, r6, r4` | per-poly operand-a pointer `&z+off` | not advanced per iter → stale `c·s1[0]` reused; `y` still added & stored → partial corruption (borderline, just over the 4.5 flag) |
| `0x46e4` | 16.9 | `bl poly_add` | the per-poly add call | add dropped every iter → `z` stays `= c·s1` for all 4 polys |
| `0x46e8` | 16.9 | `cmp.w r4, #0x1000` | loop-bound compare | `bne` sees stale flags → iteration count breaks → adds dropped |
| `0x46ec` | 16.9 | `bne.n 46da` | loop back-edge | falls through after poly[0] → polys 1–3 keep `= c·s1` |

Non-LEAK sites in the same function (`mov r6`, `mov r5`, `movs r4`, `adds r2/r0`) sit at
|t|=3.0–3.7 -- the key-independent floor. The 16.9 peak is ~4–5× that floor.

## Mechanism (Exploiting Determinism)

In ML-DSA-44 signing the response is `z = y + c·s1`. `c·s1` is **deterministic** given
(message, key): `c = H(μ, w1)` is public, `s1` is secret, so `c·s1` is a fixed secret-dependent
vector per signature. `y` is the fresh per-attempt mask whose sole job is to hide `c·s1` before
`z` is emitted (and bounded-checked by `polyvecl_chknorm` to prevent `z` from carrying `s1`).

`polyvecl_add` is where the mask is applied. Skipping any site that drops one or more of the
four `poly_add`s removes the `y` contribution for those polynomials, so the emitted `z`
(wholly or partially) equals the bare `c·s1` -- the secret term, directly in the signature.
Because A and B differ only in `sk` (hence differ in `s1`), the faulted `z` distribution
separates by key with large |t|: `0x46d2`/`0x46e4` drop all four polys (full `c·s1`),
`0x46ec` drops three, `0x46e8` corrupts the loop count, and `0x46dc` only staleifies one
operand pointer (hence its near-threshold 4.58). This is exactly the textbook determinism-
exploitation fault: one skipped mask-add and `z` reveals `c·s1`, from which `s1` is
recoverable across a few signatures.

## Why only `polyvecl_add`, and not the polyveck add

1. **`polyveck_add` is not in the m4f signing path.** Its symbol exists (`0x4810`) but the
   capture manifest shows A=B=0 executions during signing (vs 40/40 for `polyvecl_add` and
   `poly_add`); the m4f optimiser inlines `polyveck_add/sub/chknorm/make_hint` out of `sign`
   (they survive only in verify). No executed instruction → nothing to fault.
2. **`z` (polyvecl) is what reaches the signature; `w` (polyveck) does not.** The signature is
   `(c̃, z, h)`. The polyveck vectors (`w`, `w0`, `w1`, `t0`) are commitment/hint material that
   is decomposed, hashed, or carried as hints -- none is emitted as a secret-masked value, so
   even a faulted polyveck add would not expose a deterministic secret term in the output the
   way dropping the `z = c·s1 + y` mask does.

Net: of the 8 LLVM-correction-flagged functions reachable on ARM, **1** leaks under
instruction-skip (`polyvecl_add`); every other reachable function scores 0 LEAK sites
(max |t|≤4.5). Instruction-skip is a coarser fault than LLVM's IR bit/value corruption, so the
only correction leak it reproduces is the one structural mask-removal that determinism makes
unconditionally exploitable.
