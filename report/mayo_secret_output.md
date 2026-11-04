# MAYO1 m4f (de-inlined `firmware_ni`): the s = v + O·x secret output map

`mat_mul(sk.O, x, Ox)` and `mat_add(vi, Ox, s)` compute the only place the secret oil space O
reaches the released signature (`mayo.c:480-481`). On the default build they are inlined into
`mayo_sign_signature`; the `firmware_ni` build keeps them as functions, so the per-function
instruction-skip sweep can reach them. Snapshot-region replay, 16 msgs/side, A/B two keys +
A/A' same-key control; key-dependent = A/B flips above A/A' (Fisher exact, BH-FDR q=0.05).

| function | role | sites | effective | φIF A/B sites (flips) | φIF A/A' (flips) | key-dep sites |
|---|---|---|---|---|---|---|
| `mat_add.constprop.0` | s = v + O·x | 40 | 51% | 4 (8) | 5 (12) | **0** |
| `mat_mul.constprop.0` | O·x (secret O times solution x) | 40 | 95% | 1 (3) | 1 (2) | **0** |

## Result

**No key-dependent sites.** At `mat_mul`/`mat_add` the A/B φIF flip rate is within the A/A'
input-only control, so the two-key test does not separate key-dependence from the ordinary
input-dependence of the multiply. This is the same outcome as the inlined secret path on the
default build: the operation that touches O is located and swept, but a single skipped
instruction's effect on the output is not key-distinguishable with two keys. A many-key test
(vary the key over K keys, correlate each site's ineffectiveness with O) is the follow-up that
could decide it.

