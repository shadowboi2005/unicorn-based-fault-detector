# LLVM-IR region → ARM-instruction-range alignment (Dilithium / ML-DSA-44)

For the functions that carry this platform's ARM fault findings, shows which LLVM-IR
basic block / instruction "produced" which contiguous range of ARM instructions, so a
given ARM finding site (`0x….`) can be read back to a specific tainted IR op / block.

- **IR** is the *committed* `Dilithium-LLVM` IR: `llvm/dilithium_IR/dilithium2.ll`
  (reference `ref/` build, `-g`), with secret-taint from
  `llvm/taintResults/pqcrystals_dilithium2_ref_<fn>.json`. **This is real .ll, not inferred C.**
- **ARM** is real `capstone`/objdump disassembly of `firmware/ml-dsa-44_m4f_test.elf`
  (the m4f speed/asm build, Cortex-M4, Thumb-2). All pcs below are from objdump; none invented.
- The two finding axes (see `report/llvm_vs_arm.md`): **LEAK** = (A) TVLA distribution-difference
  site; **φIF** = (B) key-dependent-ineffective skip site.
- The m4f binary is a *different* compilation from the IR (reference C → `arm-none-eabi` at
  `-O3`, hand-tuned asm NTT), so the map anchors on **semantic landmarks** — Montgomery MAC,
  coefficient loads/stores, loop bounds, calls — not on a line-to-instruction identity.

---

## `ntt` — Montgomery butterfly (63 φIF sites)

ARM extent `0x5714`–`0x5cdb` (`pqcrystals_dilithium_ntt`). The secret-tainted IR is the
single butterfly block `for.body6` (taint JSON instrs 19–35):

```llvm
for.body6:                               ; the Cooley–Tukey butterfly, inner j-loop
  %conv   = sext i32 %0 to i64           ; zeta  (loop-invariant, from @zetas[++k])
  %2      = load i32, ptr %arrayidx8     ; a[j+len]                     (taint 21)
  %conv9  = sext i32 %2 to i64                                          ; (taint 22)
  %mul    = mul nsw i64 %conv, %conv9    ; zeta * a[j+len]              (taint 23)
  %call   = call i32 @...montgomery_reduce(i64 %mul)  ; t               (taint 24)
  %3      = load i32, ptr %arrayidx10    ; a[j]                         (taint 26)
  %sub    = sub nsw i32 %3, %call        ; a[j] - t                    (taint 27)
  store i32 %sub, ptr %arrayidx12        ; a[j+len] = a[j] - t          (taint 30)
  %5      = load i32, ptr %arrayidx13    ; a[j]                         (taint 32)
  %add14  = add nsw i32 %5, %call        ; a[j] + t                    (taint 33)
  store i32 %add14, ptr %arrayidx15      ; a[j]     = a[j] + t          (taint 35)
```

In the binary `montgomery_reduce` is **inlined** to `smull;mul;smlal` and the inner j-loop
is **unrolled ×4** (four butterfly lanes interleaved, zetas pre-loaded into the FP register
file `s2..s8` at `0x5724` and fed via `vmov`). One IR butterfly ⇒ four ARM lane-groups.
First lane-group (`0x5758`, len-layer at `0x5714`):

| pc | mnemonic | IR op realised | site |
|---|---|---|---|
| `0x5734`–`0x5750` | `ldr.w r5..lr,[r0,#…]` | loads of `a[j]`,`a[j+len]` (8 coeffs, in regs) | |
| `0x5754` | `vmov r1, s2` | `%conv` zeta (from FP reg, not reloaded) | |
| `0x5758` | `smull r9, r4, r4, r1` | `%mul = zeta*a[j+len]` (lane 0) | **φIF** |
| `0x575c` | `mul.w sl, r9, r2` | `montgomery_reduce`: `*QINV` | |
| `0x5760` | `smlal r9, r4, sl, r3` | `montgomery_reduce`: `-t*Q >>32` ⇒ `%call` r4 | **φIF** |
| `0x5764` | `smull r9, fp, fp, r1` | `%mul` (lane 1) | **φIF** |
| `0x5768` | `mul.w sl, r9, r2` | reduce `*QINV` (lane 1) | |
| `0x576c` | `smlal r9, fp, sl, r3` | reduce ⇒ `%call` (lane 1) | **φIF** |
| `0x5770`/`0x5778` | `smull/smlal …ip…` | `%mul`+reduce (lane 2) | **φIF** |
| `0x577c`/`0x5784` | `smull/smlal …lr…` | `%mul`+reduce (lane 3) | **φIF** |
| `0x5788` | `add r5, r4` | `%add14 = a[j] + t` (lane 0) | **φIF** |
| `0x578a` | `add r6, fp` | `%add14` (lane 1) | **φIF** |
| `0x578c`/`0x578e` | `add r7, ip` / `add r8, lr` | `%add14` (lanes 2,3) | **φIF** |
| `0x5790` | `sub.w r4, r5, r4, lsl #1` | `%sub = a[j] - t` (recomputed as `(a+t)-2t`) | |
| `0x5794`–`0x579c` | `sub.w …` | `%sub` (lanes 1–3) | |

The same template repeats per (len, start) block — e.g. `0x5898` (7 flips) and `0x5b2c`
(8 flips, top sites) are the identical butterfly at later NTT layers, hence 63 φIF sites
total across the function.

**Fidelity: correlation holds at butterfly-*op* granularity, breaks at line/loop granularity.**
`montgomery_reduce` (one IR `call`) = three ARM ops (`smull;mul;smlal`); the inner j-loop is
unrolled ×4; the three nested IR loops (`len`→`start`→`j`) are collapsed with coefficients
held in registers and zetas in the FP file, so there is no per-butterfly load/store to anchor
on. The φIF cluster sits exactly on the tainted `%mul`/reduce/`%add14` ops — skipping one is a
no-op precisely when that lane's (secret-derived) operand makes the MAC irrelevant.

---

## `polyvecl_add` — response mask add `z = y + c·s1` (5 LEAK sites)

ARM extent `0x46d0`–`0x46ef`. IR is the L=4 loop over polynomials calling `poly_add`:

```llvm
for.body:                                ; i = 0..3  (L = 4)
  %arrayidx  = getelementptr [4x[256xi32]], ptr %w, 0, %i.0   ; &z[i]  (taint 4)
  %arrayidx1 = getelementptr [4x[256xi32]], ptr %u, 0, %i.0   ; &y[i]  (taint 5)
  %arrayidx2 = getelementptr [4x[256xi32]], ptr %v, 0, %i.0   ; &(c·s1)[i]
  call void @...poly_add(ptr %arrayidx, %arrayidx1, %arrayidx2)  ; poly_add (taint 7)
  %inc = add nuw nsw i32 %i.0, 1
```

| pc | mnemonic | IR op realised | site |
|---|---|---|---|
| `0x46d2` | `mov r7, r0` | capture `%w` (out `z`) base | **LEAK** |
| `0x46d4`/`0x46d6` | `mov r6,r1` / `mov r5,r2` | capture `%u` (`y`), `%v` (`c·s1`) bases | |
| `0x46d8` | `movs r4, #0` | `%i.0 = 0` (byte offset) | |
| `0x46da` | `adds r2, r5, r4` | `%arrayidx2 = &v[i]` | |
| `0x46dc` | `adds r1, r6, r4` | `%arrayidx1 = &u[i]` | **LEAK** |
| `0x46de` | `adds r0, r7, r4` | `%arrayidx = &w[i]` | |
| `0x46e0` | `add.w r4, r4, #1024` | `%inc` (stride 256·4 B = one poly) | |
| `0x46e4` | `bl 0x3d94 <poly_add>` | the per-poly `z=y+(c·s1)` add | **LEAK** |
| `0x46e8` | `cmp.w r4, #4096` | `%exitcond` (i != 4 ⇔ 4·0x400) | **LEAK** |
| `0x46ec` | `bne.n 0x46da` | loop back-edge | **LEAK** |

**Fidelity: cleanest 1:1 of the four.** The IR loop maps directly onto the ARM loop; GEPs →
`adds base+offset`, the loop counter is byte-strided (`0x400`/poly, `0x1000` bound), and
`poly_add` stays an out-of-line `bl` (not inlined). The 5 LEAK sites are exactly the
output-pointer setup (`mov r7`), the per-poly add (`bl`), and the loop control — skipping any
drops one or more of the four mask adds, exposing the deterministic `c·s1` term (Exploiting-
Determinism). The actual coefficient add lives in `poly_add` (`0x3d94`, 256-iter add loop).

---

## `poly_challenge` — sign-unpack + Fisher-Yates (5 φIF sites)

ARM extent `0x4078`–`0x414d`. Two tainted IR regions: the `signs` byte-assembly loop
(`for.cond`/`for.inc`) and the sampling body (`do.body`/`do.end`) that applies a sign bit:

```llvm
for.inc:                                 ; signs = Σ buf[i] << 8*i   (i=0..7)
  %0   = load i8, ptr %arrayidx          ; buf[i]
  %shl = shl nuw i64 %conv, %sh_prom     ; buf[i] << (8*i)
  %or  = or i64 %signs.0, %shl           ; signs |= …
do.end:                                  ; per-coefficient, i.2 = 217..255
  %2      = load i32, ptr %arrayidx21    ; c[b]
  store i32 %2, ptr %arrayidx22          ; c[i] = c[b]                 (the swap)
  %signs.1.tr = trunc i64 %signs.1 to i32
  %conv24 = sub nsw i32 1, (%signs<<1 & 2) ; 1 - 2*(signs&1)  = ±1 sign
  store i32 %conv24, ptr %arrayidx25     ; c[b] = sign
  %shr = lshr i64 %signs.1, 1            ; signs >>= 1
```

| pc | mnemonic | IR op realised | site |
|---|---|---|---|
| `0x40a2` | `ldrb.w r5,[sp,#2]` | `load buf[2]` (unrolled signs byte) | **φIF** |
| `0x40ae` | `lsls r5, r5, #16` | `buf[2] << 16` (`%shl`) | **φIF** |
| `0x40b0`–`0x40da` | `orr.w …` | `signs |= buf[i]<<8i` (`%or`, 64-bit in r5:r6) | |
| `0x40be` | `orr.w r5,r5,r3,lsl #24` | `buf[3] << 24` into `signs` low word | **φIF** |
| `0x40de`–`0x40ea` | `strd;cmp;bne` | `for.body4`: zero-init `c[0..255]` (2 words/iter) | |
| `0x40ec`–`0x411c` | sampling/`squeeze` | `do.body`: rejection pos scan, re-squeeze | |
| `0x411e` | `ldr.w r0,[r7,r3,lsl#2]` | `%2 = c[b]` | |
| `0x4122` | `str.w r0,[r7,r4,lsl#2]` | `c[i] = c[b]` (the swap write) | **φIF** |
| `0x4126`–`0x412e` | `and;lsls;rsb` | `%conv24 = 1 - 2*(signs&1)` (±1) | |
| `0x4132` | `lsrs r5, r5, #1` | `%shr` low word of `signs >>= 1` | |
| `0x413c` | `str.w r2,[r7,r3,lsl#2]` | `c[b] = sign` (`%conv24`) | |
| `0x4140` | `mov.w r6, r6, lsr #1` | `%shr` high word of `signs >>= 1` | **φIF** |

**Fidelity: partial.** The 8-iteration `signs` loop is fully **unrolled** (`0x40a2`–`0x40da`),
and the 64-bit `signs` lives split across two registers (r5 low / r6 high), so the single IR
`lshr i64` becomes two ARM shifts (`0x4132` + `0x4140`); `0x4140` is the φIF-flagged half.
Otherwise the sampling body maps cleanly: `0x4122` = the swap store, `0x40a2/0x40ae/0x40be` =
`signs` assembly bytes. These φIF sites are where a skip is a no-op iff the (secret `c̃`-seeded)
`signs` bit / position is inert for that key.

---

## `polyvecl_uniform_gamma1` — per-poly nonce derivation (2 φIF sites)

ARM extent `0x4684`–`0x46a9`. IR is the L=4 loop building `nonce' = (nonce<<2)|i` and
calling `poly_uniform_gamma1`:

```llvm
for.body:                                ; i = 0..3
  %conv  = zext i16 %nonce to i32
  %mul   = shl nuw nsw i32 %conv, 2      ; nonce << 2
  %add   = or disjoint i32 %mul, %i.0    ; | i
  %conv1 = trunc i32 %add to i16
  call void @...poly_uniform_gamma1(ptr %arrayidx, %seed, i16 %conv1)
```

| pc | mnemonic | IR op realised | site |
|---|---|---|---|
| `0x4684` | `lsls r2, r2, #2` | `%mul = nonce << 2` (hoisted before loop) | **φIF** |
| `0x468c` | `uxth r4, r2` | `%conv1 = trunc`/`(nonce<<2)&0xffff` → loop base | **φIF** |
| `0x468e` | `add.w r7, r0, #4096` | loop bound (`v + 4·0x400`) | |
| `0x4692`–`0x4696` | `mov r2,r4 / r0,r5 / r1,r6` | marshal `%conv1`,`&v[i]`,`seed` args | |
| `0x469c` | `bl 0x4570 <poly_uniform_gamma1>` | the sampler call (taint-JSON instr 9) | |
| `0x46a0`/`0x46a4` | `adds r4,#1 / uxth r4,r4` | `%add`'s `| i` as running `nonce'` increment | |
| `0x46a2`/`0x46a6` | `cmp r5,r7 / bne` | loop control | |

**Fidelity: good, with a strength-reduction twist.** The `<<2` is hoisted out of the loop
(`0x4684`, before the prologue), and `%add = %mul | i` is realised as a *running increment* of
the nonce register (`adds r4,#1`; valid since the low 2 bits are 0), not an explicit `or`. The
two φIF sites are exactly the nonce-derivation ops — skipping them leaves the per-poly nonce
unchanged, a no-op or not depending on the secret-dependent downstream `gamma1` expansion.

---

## Summary of mapping fidelity

| function | IR→ARM fidelity | dominant break |
|---|---|---|
| `polyvecl_add` | ~1:1 | none; `poly_add` stays a `bl` |
| `polyvecl_uniform_gamma1` | 1:1 ops | `<<2` hoisted, `|i` → running increment |
| `poly_challenge` | partial | 8-iter signs loop unrolled; 64-bit `signs` split r5/r6 |
| `ntt` | op-level only | `montgomery_reduce` inlined (×3 ops), j-loop unrolled ×4, loops collapsed, coeffs/zetas in regs |

The alignment is tightest for the straight C loops that the m4f compiler left as out-of-line
calls (`polyvecl_add`, `gamma1`) and loosest for the hand-optimised NTT, where a single IR
butterfly fans out into four interleaved register lanes with the reduction inlined — so NTT
φIF sites correlate to IR *operations*, never to IR *lines or loop iterations*.
