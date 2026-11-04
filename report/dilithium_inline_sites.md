# Dilithium m4f: inline signing-body fault sites (nonce++, rejection branches)

Sites that live in `crypto_sign_signature_ctx` itself, not in a called function, so the per-function funcskip sweep never reached them. Snapshot the signing body at entry, skip one instruction (first execution), run to return, compare the released signature and writable RAM. n=24 messages/side; A/B = two keys same message, A/A' = key A on disjoint messages (input-only control). Key-dependent = A/B flips above A/A' (Fisher exact, BH-FDR q=0.05).

| site | effective (sig changed) A / B / A' | φIF A/B (flips/n) | φIF A/A' | key-dep? |
|---|---|---|---|---|
| `0x4e88` nonce++ (adds r3,#1), first retry -> nonce reuse | 0/0/0 of 24 | 0/24 | 0/24 | no |
| `0x4d7c` bne after polyvecl_chknorm(z) [persistent] -> disable z-norm reject | 11/14/12 of 24 | 13/24 | 13/24 | no |
| `0x4dde` bne after poly_chknorm(w0-cs2) [persistent] -> disable w0 reject | 9/16/14 of 24 | 13/24 | 13/24 | no |
| `0x4e22` bne after poly_chknorm(ct0) [persistent] -> disable ct0 reject | 0/0/0 of 24 | 0/24 | 0/24 | no |
| `0x4e3c` bhi after hint-count cmp [persistent] -> disable hint-overflow reject | 0/0/0 of 24 | 0/24 | 0/24 | no |

*effective = how many of the n signings had the released signature change when the skip fired. φIF A/B = messages where the skip changed the signature for one key but not the other; A/A' is the same quantity for one key across disjoint messages (input-only control). nonce++ and the reject branches only fire when a rejection actually occurs, so effective < n is expected.*

## What this shows

- **nonce++ (0x4e88): located, but invisible to a single-signature test** (0/24 effective, verified directly). Within one signing, skipping one increment just makes the next retry recompute the same y and reject again; the eventually-accepted nonce is unchanged, so the released signature is identical. Nonce reuse only yields two *different* signatures sharing a y across **separate** signing calls -- a cross-signature test, not this one.
- **Rejection-skip (0x4d7c z-norm, 0x4dde w0-norm): reachable and output-changing** (disabling the check changes the released signature in ~half the signings), but the change rate is the SAME for A/B as for the A/A' control -- input-dependent, not key-dependent by the 2-key test. The ct0 and hint-overflow rejections essentially never fire in n=24 (0 effective), so they are unobserved rather than clean.
- Consistent with the rest of the Dilithium study: instruction skip locates these known fault targets, but the single-signature key-distribution detectors do not flag them. Confirming exploitability needs the attack-specific observable (same-y detection across two signings; the released z checked against the GAMMA1-BETA norm).
