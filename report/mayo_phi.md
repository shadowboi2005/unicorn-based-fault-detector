# MAYO whole-call-skip φIF (key-dependent ineffective) sweep

Scheme ML-DSA? no -- **MAYO1** (`firmware/mayo1_m4f_test.elf`), deterministic signing. 40 messages/key, 28 whole-call skip sites in the signing path. Skip = remove a whole `bl` call; a site is **φIF** if skipping is a no-op for one key but changes the 454-byte signature for the other, on the same message.

- **φIF sites:** 0 of 28 call sites show key-dependent ineffectiveness.
- A skip is *ineffective* (no-op) when the signature is unchanged; most call skips are effective or crash. Swept in 953s.

| addr | call | φIF flips | no-op A/B | crash A/B |
|---|---|---|---|---|
| `0x6eca` | `bl memset` | 0 | 40/40 | 0/0 |
| `0x6ed4` | `bl memset` | 0 | 40/40 | 0/0 |
| `0x6ee2` | `bl mayo_expand_sk` | 0 | 0/0 | 0/0 |
| `0x6f18` | `bl mayo_secure_clear` | 0 | 40/40 | 0/0 |
| `0x6f22` | `bl mayo_secure_clear` | 0 | 40/40 | 0/0 |
| `0x6f2c` | `bl mayo_secure_clear` | 0 | 40/40 | 0/0 |
| `0x6f34` | `bl mayo_secure_clear` | 0 | 40/40 | 0/0 |
| `0x6f40` | `bl mayo_secure_clear` | 0 | 40/40 | 0/0 |
| `0x6f48` | `bl mayo_secure_clear` | 0 | 40/40 | 0/0 |
| `0x6f50` | `bl mayo_secure_clear` | 0 | 40/40 | 0/0 |
| `0x6f58` | `bl mayo_secure_clear` | 0 | 40/40 | 0/0 |
| `0x6f62` | `bl mayo_secure_clear` | 0 | 40/40 | 0/0 |
| `0x6f90` | `bl shake256` | 0 | 0/0 | 0/0 |
| `0x6f9e` | `bl memset` | 0 | 40/40 | 0/0 |
| `0x6fa6` | `bl PQCLEAN_randombytes` | 0 | 0/0 | 0/0 |
| `0x6fb0` | `bl memcpy` | 0 | 0/0 | 0/0 |
| `0x6fbc` | `bl shake256` | 0 | 0/0 | 0/0 |
| `0x6fc6` | `bl memcpy` | 0 | 0/0 | 0/0 |
| `0x6fd2` | `bl shake256` | 0 | 0/0 | 0/0 |
| `0x7046` | `bl shake256` | 0 | 0/0 | 0/0 |
| `0x7092` | `bl compute_M_and_VPV.isra.0` | 0 | 0/0 | 40/40 |
| `0x709c` | `bl compute_rhs.isra.0` | 0 | 0/0 | 0/0 |
| `0x70aa` | `bl memset` | 0 | 0/0 | 0/0 |
| `0x832e` | `bl sample_solution` | 0 | 0/0 | 40/40 |
| `0x833e` | `bl memset` | 0 | 40/40 | 0/0 |
| `0x834a` | `bl memset` | 0 | 40/40 | 0/0 |
| `0x8660` | `bl memcpy` | 0 | 0/0 | 0/0 |
| `0x86b4` | `bl memcpy` | 0 | 0/0 | 0/0 |
