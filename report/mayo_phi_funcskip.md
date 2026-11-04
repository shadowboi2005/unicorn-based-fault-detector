# MAYO intra-function instruction-skip φIF (approach B)

**MAYO1** (`firmware/mayo1_m4f_test.elf`), deterministic signing, 8 messages/key. Skip each instruction inside a secret-dependent function (snapshot-region replay, entry->ret, no arg specs) and compare writable RAM + r0 to the golden run. A site is **φIF** if the skip is a no-op for one key but changes the state for the other, on the same message.

- **φIF sites across the swept functions: 47.**

| function | status | sites (stride) | φIF sites | φIF flips |
|---|---|---|---|---|
| `compute_rhs.isra.0` | ok | 203 (1) | 7 | 14 |
| `sample_solution` | ok | 231 (1) | 8 | 11 |
| `compute_M_and_VPV.isra.0` | ok | 27 (1) | 1 | 1 |
| `P1_times_Vt.isra.0` | ok | 119 (1) | 0 | 0 |
| `P1_times_O.isra.0` | not-reached | — | — | — |
| `P1P1t_times_O.isra.0` | ok | 141 (1) | 0 | 0 |
| `m_upper` | not-reached | — | — | — |
| `mul_add_mat_x_m_mat_m4f_K_V_O_triangular_asm` | ok | 263 (1) | 0 | 0 |
| `mul_add_mat_x_m_mat_m4f_K_V_K_triangular_asm` | ok | 263 (1) | 0 | 0 |
| `mul_add_mat_trans_x_m_mat_m4f_V_O_O_asm` | not-reached | — | — | — |
| `multiply_P1_right_m4f_V_V_O_asm` | ok | 544 (2) | 31 | 248 |

## Takeaways

- **φIF exists intra-function in MAYO**, where whole-call skips (approach A) found 0. It concentrates in: `multiply_P1_right_m4f_V_V_O_asm`(31), `sample_solution`(8), `compute_rhs`(7), `compute_M_and_VPV`(1).
- The fully word-packed GF(16) matrix multiplies that are reached in signing (`P1_times_Vt`, `P1P1t_times_O`, `mul_add_mat_x_m_mat_*`) show **0** φIF: a skip in a fused/bitsliced vector op hits many packed field elements at once, so it is always effective or a crash -- never *conditionally* dead by key. The φIF signal instead lands in the per-element/accumulator-shaped code (`multiply_P1_right_*_V_V_O`, `sample_solution`, `compute_rhs`).
- Functions marked *not-reached* (`P1_times_O`, `m_upper`, `mul_add_mat_trans_*`) are keygen / public-map only, not on the signing path.

## Caveat (same as the Dilithium φIF study)

These counts **locate candidate sites; they do not establish SIFA-exploitability.** The 2-key metric conflates genuine key-dependence with ordinary *input*-dependence: keys A and B each run a full signing, so they feed different secret-derived intermediates (vinegar `V`, oil `O`) AND a different deterministic salt, and a φIF flip only says the two runs differed in ineffectiveness. SIFA-exploitability is **not** decided by whether a value is public -- SIFA exploits an ineffective-conditioned *bias* that correlates with the secret, which can arise for public operands too. Settling each site needs the SIFA test proper: fix the key, fault across many inputs, filter to the ineffective subset, and test the target intermediate's conditional distribution for a secret-correlated bias. (N=8; flip counts are partial and scale with N -- the φIF *site* set is the stable signal.)
