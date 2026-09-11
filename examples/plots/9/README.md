# ALAFA leakage sweep — results

Automated fault-leakage assessment of ML-DSA-44 (Dilithium) signing, one fault
site at a time, in the Unicorn emulator. This is the results summary; `09.md`
is the long-form explainer, `../../09_alafa_sweep.py` is the sweep itself, and
the plots referenced below live in this directory.

**Question asked at every site:** if I fault *this* instruction of the signing
loop, does the emitted signature start leaking which secret key produced it?

**Headline:** of 20 candidate fault sites, exactly **one** leaks — skipping the
nonce-masking add `z = z + y` (`0x4d5e`), which separates two keys with **100%**
accuracy and a TVLA **max|t| = 15.4**. Every other site either stays at chance
(no leak) or hangs signing. The detector is deliberately narrow, and the
negative results below show it does not cry wolf.

---

## Method of detection

No key is recovered and no secret or public key is used. The detector sees only
the **signatures** and the challenge `c` (re-expanded from `c̃` with the
firmware's own `poly_challenge`), and decides *leak / no leak* by asking whether
**two different keys can be told apart from their outputs**.

1. **Fault model** — instruction skip: step the PC past a `bl`, so that one
   operation never executes. Applied to all 20 operation-calls in the signing
   loop, one at a time.
2. **Feature** — the **matched filter**: negacyclic correlation of the sparse
   challenge `c` against each response polynomial `z` (a 1024-vector, L=4 polys
   × 256 lags). The *marginal* of `z` is secret-independent by design, so a plain
   histogram of `z` is blind; the leak lives only in the joint `(c, z)`
   relationship, which this projection exposes.
3. **Verdict, two equivalent ways:**
   - **Two-key classifier accuracy** (leave-one-out). Signed score
     `score(x) = ⟨x, g_own_LOO⟩ − ⟨x, g_other⟩` against per-key mean templates;
     key-A sigs should score >0, key-B <0. 50% = indistinguishable, 100% = leak,
     flag at **≥ 80%**. Leave-one-out is essential — 1024 dims on ~30 samples
     would otherwise fake separation.
   - **TVLA t-test** (`ttest_09.py`). Welch two-sample *t* at every one of the
     1024 matched-filter coordinates between key A and key B; flag any coordinate
     with **|t| > 4.5** (≈ p < 1e-5). No data-derived direction, so its p-values
     are honest. Backed by a permutation p-value on the accuracy (2000 label
     shuffles, assumption-free) and a Welch t on the 1-D discriminant score.

The two verdicts agree on every site.

---

## Positive result — the one site that leaks

| site | addr | two-key acc | TVLA max\|t\| | #coords > 4.5 | perm p |
|---|---|---|---|---|---|
| **`z = z + y` (polyvecl_add)** | `0x4d5e` | **100%** | **15.4** | **444 / 1024** | **0.0005** (floor) |

**Why it leaks.** Dilithium's response is `z = y + c·s1`, where the fresh nonce
`y` *masks* the secret term `c·s1`. Skip the masking add and `z = c·s1` — the
secret rides out in the clear. The matched filter aligns `z` with `c`, key A
piles entirely on one side of the decision boundary and key B on the other
(`distributions.png`, `score_4d5e.png`). This is **category 4.2** of the
fault-attack catalog (Ravi et al. 2019, *Exploiting Determinism*; ElGhamrawy
2023; Du 2025).

The 1-D discriminant Welch t is **129** (p ≈ 8e-69) and the permutation p sits at
its 1/2001 floor — never once matched by a shuffled control.

---

## Negative results — everything else

Two distinct kinds of non-leak, both meaningful.

### (a) Runs fine, but no leak — output hides the key

Nine sites complete signing yet stay at chance. The mask survives (or the skipped
step doesn't touch it), so key A and key B overlap on the decision boundary.

| site | addr | acc (N=16) | acc (N=28) | TVLA max\|t\| | #coords > 4.5 |
|---|---|---|---|---|---|
| control (no fault) | — | 53% | 52% | 3.6 | 0 |
| memcpy | `0x4c90` | 47% | 46% | 3.6 | 0 |
| y → NTT | `0x4c9a` | 41% | 50% | 3.6 | 0 |
| w = A·y | `0x4cb0` | 41% | 54% | 3.4 | 0 |
| w → invNTT | `0x4cc4` | 75% | 46% | 3.9 | 0 |
| pack w1 | `0x4cec` | 69% | 50% | 3.7 | 0 |
| shake squeeze c̃ | `0x4d18` | 47% | *(hang at N=28)* | — | — |
| reduce z | `0x4d68` | 38% | 46% | 3.5 | 0 |
| pack z into sig | `0x4d88` | 41% | 59% | 3.3 | 0 |
| w0 − c·s2 | `0x4dca` | 59% | 59% | 3.6 | 0 |

**Robustness note.** At the sweep's N=16, two sites drifted up — `w → invNTT`
(75%) and `pack w1` (69%) — close to the 80% line. At N=28 they fall back to
46% / 50% with **zero** TVLA coordinates over threshold. That is the safeguard
working: the accuracy wobble is small-sample noise, and the direction-free TVLA
test refuses to confirm any of them. The non-leak sites all sit at
`max|t| ≈ 3.3–3.9` — the noise ceiling for the largest of 1024 near-null
t-values, and the same number the t-test gives on the **raw z** coefficients
(max|t| ≈ 3.4, blind). Only `z=z+y` breaks out of that band.

### (b) Hangs — the operation is load-bearing

Nine sites never finish. Instrumenting them (`diag_crash.py`) shows they are
**hangs, not crashes**: every one runs to the 20M-instruction cap (a real memory
fault would die in a few thousand). Signing is reject-and-retry; a whole-call
skip drops a value a rejection check depends on, the check fails every iteration,
and the loop never accepts.

`sample y` · `decompose w` · `poly_challenge` · `c*s1` · `z-norm check` ·
`c*s2` · `r0 check` · `c*t0` · `ct0 check` · `make_hint`

**The important negative:** the three **rejection-check** skips (`z-norm`, `r0`,
`ct0`) hang rather than leak — even though those checks *are* the zero-knowledge
mask and faulting them **does** leak. The catch is direction:

| | fault model | effect | outcome |
|---|---|---|---|
| this sweep | skip the whole `bl poly_chknorm` | `r0` = stale ≠ 0 → always **reject** | hang |
| example 08 | force the `cmp` result to 0 | `r0` = 0 → always **accept** | leak |

A whole-call skip breaks the loop in the *wrong* direction to expose the
check-bypass leak; that leak needs example 08's targeted stuck-at-accept fault
and a lattice/polytope solver over many signatures — a different fault class and
heavier analysis than a per-signature two-key distinguisher. This sweep also does
not rediscover **category 4.1** (partial-nonce loop-abort), which a whole-call
skip cannot express.

---

## Scope, honestly

This is a detector of **high-SNR mask-removal faults**. It flags the one such
fault present (`z = z + y`), stays quiet on everything that keeps the mask, and
cleanly declines the check-bypass class it cannot see per-signature. Within that
scope both the classifier and the TVLA t-test give the same, calibrated verdict.

## Plots in this directory

| file | shows |
|---|---|
| `alafa_accuracy.png` | two-key accuracy per site (blue control, red leak, green ok, grey hang) |
| `distributions.png` | two-key score histograms — overlap (hidden) vs separated (leak) |
| `score_<site>.png` | the six representative panels, standalone |
| `tvla_trace.png` | per-coordinate \|t\| across the 1024 features, 4.5 threshold |
| `tvla_maxt.png` | max\|t\| per site (log scale) — the t-test twin of the accuracy chart |

## Reproducing

```bash
.venv/bin/python examples/09_alafa_sweep.py    # ASCII sweep  (N=16/key)
.venv/bin/python examples/plots/plot_09.py     # distribution plots (N=28/key)
.venv/bin/python examples/plots/ttest_09.py    # t-test table + plots (N=28/key)
.venv/bin/python examples/plots/diag_crash.py  # hang-vs-crash diagnosis
```
