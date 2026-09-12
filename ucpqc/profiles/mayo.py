"""Analysis profile for MAYO (multivariate-quadratic signatures; a NIST
additional-signatures candidate).

MAYO is *not* lattice-based: signing expands the secret oil space O
(`mayo_expand_sk`), builds a linear system from fresh vinegar variables
(`compute_M_and_VPV`), and solves it (`sample_solution`).  There is no sparse
challenge and no masked response polynomial, so Dilithium's matched-filter
feature does **not** apply.

This profile makes MAYO runnable in the `sweep`/`funcskip` modes with two portable,
scheme-neutral choices:
  * fault sites are **discovered by disassembly** of `mayo_sign_signature`
    (`discover_call_sites`) rather than hard-coded addresses;
  * the feature is the **raw released bytes** (F_16 nibbles packed as bytes) --
    a generic "does the output distribution depend on the key?" detector.

The generic feature is a *scaffold*, not a tuned leak detector: MAYO's signature
is randomised (salt + vinegar), so the two-key test may be confounded (golden
already key-separable).  The engine's golden-baseline guard flags exactly that.
A high-SNR MAYO leak feature -- one that isolates the oil-space contribution the
way the matched filter isolates c*s1 -- needs MAYO-specific cryptanalysis and is
left as future work.  Fully running/profiling/faulting MAYO needs none of this
(the scheme-agnostic core handles it).
"""

import numpy as np

from . import AnalysisProfile, register

# MAYO-1 sizes (pk, sk, sig) = (1420, 24, 454); other variants differ.


class MayoProfile(AnalysisProfile):
    patterns = ("mayo*",)
    op = "sign"
    artifact_len = 0                         # variant-agnostic: skip the length check

    # sweep sites are auto-discovered by the base AnalysisProfile.fault_sites,
    # which descends the crypto_sign_signature wrapper into mayo_sign_signature.

    def challenge(self, machine, artifact):
        return None                          # MAYO has no challenge context

    def response_from_signature(self, artifact):
        return np.frombuffer(bytes(artifact), dtype=np.uint8).astype(float)

    def response_from_output(self, output):
        return np.frombuffer(bytes(output), dtype=np.uint8).astype(float)

    def feature(self, context, response):
        return response                      # generic raw-byte feature (see module doc)

    def detector_for(self, target):
        # only two_key is wired for MAYO; check the golden baseline before trust
        return "two_key"


register(MayoProfile)
