# Known Dilithium/MAYO fault attacks vs what the instruction-skip study flags

The framework is a candidate **locator** under one fault model: whole-instruction **skip**, scored
by (A) per_coord/TVLA output-leak and (B) φIF key-dependent ineffectiveness, with a same-key A/A'
control. This table asks, for each published attack: does our sweep reach the location it targets,
and does a detector flag it? "Flagged" is grounded in the measured dumps on `ml-dsa-44_m4f`
(n=40/key) and `mayo1_m4f` / `firmware_ni` (n=16).

Fault-model note: we only *skip* instructions. Attacks that *set* a value (zeroize), corrupt
**memory** (Rowhammer), or need a **cross-signature** or **lattice/ILP** post-step are outside the
single-signature skip model, so "located, not flagged" is expected for them — it is not evidence the
location is safe.

## Dilithium / ML-DSA

| Attack (target) | Our target | Reached? | Flagged? | Notes |
|---|---|---|---|---|
| **Exploiting Determinism — skip the z = y + c·s1 add** (Ravi/Jhanwar AsiaCCS 2019) | `polyvecl_add` | yes | **YES (A)** | **The one real leak.** Unfaulted baseline \|t\|=3.06 (y masks c·s1) → faulted 16.9, 0 under the same-key control. The fault removes the mask and exposes c·s1. |
| **MLWE→RLWE skip on z = y + c·s1** (ElGhamrawy TCHES 2023) | `polyvecl_add` + the c·s1 path | yes | **YES (A)** at polyvecl_add | Same site family; the sweep flags the addition. The MLWE→RLWE reduction itself is a lattice post-step we don't do. |
| **Loop-abort on y sampling** (Espitau SAC 2016; Ulitzsch TCHES 2023) | `poly_uniform_gamma1` (6 sites), `polyvecl_uniform_gamma1` (10) | yes | no | 0 LEAK, φIF within control. Needs the "y partially known → ILP/lattice" observable, not a single-sig key-distribution test. `polyz_unpack` (the actual coefficient writeback) is **not yet swept** — a gap. |
| **Nonce reuse** (Bruinderink–Pessl TCHES 2018; Ravi COSADE 2019) | `nonce++` 0x4e88 (inline) | yes | located, not flagged | Verified: skipping one increment inserts a duplicate rejected iteration; the accepted nonce and the single signature are unchanged. Reuse only shows across **two** signing calls. |
| **Skip the z-norm / r0 rejection** (general; **Finding-a-Polytope** PKC 2025 for r0) | inline branches 0x4d7c (z), 0x4dde (w0/r0), 0x4e22 (ct0), 0x4e3c (hint); plus the dedicated `r0_reject` detector + `force_r0_accept` | yes | partial | Disabling z/w0 changes the output ~half the time but equally for A/B and the A/A' control → not key-dependent by the 2-key test. The **`r0_reject` detector** (profile `force_r0_accept`, validated in example 08) is the attack-specific test for Finding-a-Polytope: it releases out-of-spec r0 and scores it. ct0/hint rejects ~never fire at n=24. |
| **Zeroize NTT(c) / zeroize y in NTT domain** (Jendral FDTC 2024) | `ntt_c` (NTT of public c), `ntt_y` | yes | model differs | `ntt_c` shows 63 φIF sites, but that is skip-sensitivity to c's sparsity (public), within the control. Jendral *sets* values to zero; we *skip*. Location reached, fault model different. |
| **Signature-correction on in-memory s1** (Islam EuroS&P 2022; Krahmer TCHES 2024) | — | n/a | out of model | Rowhammer / after-the-fact correction on memory, not an instruction skip. This is the LLVM "correction" axis; the 1/8 translation rate to skip-leakage is in `report/llvm_vs_arm.md`. |
| **Faulty Keccak** (Wang TIFS 2024) | Keccak permutation | **not swept** | — | Keccak excluded as public/huge. A genuine coverage gap if in scope. |
| **Small-norm poly-mult SCA/fault** (Bronchain TCHES 2024) | `small_asymmetric_mul` (c·s1/c·s2), `polyvecl_small_basemul_invntt` | yes | baseline-separable | Output is raw c·s1 (unfaulted \|t\| already 16.9) → marked n/a, not a fault finding. Decidable only with a many-key test. |

## MAYO

| Attack class (target) | Our target | Reached? | Flagged? | Notes |
|---|---|---|---|---|
| Fault on the secret output `s = v + O·x` | `mat_mul`/`mat_add` (`firmware_ni`) | yes | no | 0 key-dependent after the A/A' control (`report/mayo_secret_output.md`). The op that touches O is located and swept. |
| Vinegar reuse / fault during `shake256(V,…)` retry | (inline in `mayo_sign_signature`) | not swept | — | Top-level body too large to replay whole; a cross-signature observable like Dilithium nonce reuse. |
| Key-dependent ineffectiveness in the GF(16) multiplies | the P1·O / P1·Vᵀ workers | yes | no (post-control) | Raw A/B φIF is large but it is per-key **constants** from `mayo_expand_sk(sk)` (message-independent) → effectively n=1 key pair; needs a many-key test. See `report/mayo_secret_path.md`. |

## One-line summary
The sweep **cleanly flags exactly one** published attack location — the Exploiting-Determinism skip
of z = y + c·s1 (`polyvecl_add`) — because that is the only site where a skip turns a key-masked
output into a key-leaking one. Every other known attack is either **located but needs its own
observable** (nonce/vinegar reuse → cross-signature; loop-abort → lattice/ILP; rejection-skip →
the `r0_reject` detector), uses a **different fault primitive** (zeroize, Rowhammer), or is **not in
the swept set** (`polyz_unpack`, Keccak). The two-key detectors do not, and are not meant to,
confirm exploitability.
