"""Per-position phi_IF -- the key-dependent-ineffective (SIFA-candidate) detector.

This is the `ineffective` axis of the platform, promoted from the LLVM-gap experiment
(Arm B; see `report/llvm_gap_experiment.md`).  It replaces the old whole-output phi_IF
(`sifa` / `candidates._phi_counts`), which averaged over two random keys and the whole
released signature and so missed leaks that live in individual (secret coefficient ->
output position) relations.

The question it asks, for each fault site, is the LLVM study's `ineffective` oracle:
"is there a secret making the skip a NO-OP and another making it EFFECTIVE, at this one
output POSITION?"  We answer it by SAMPLING many keys instead of constructing secrets
(no host-side secret packer exists), with an input-variation control:

  * SECRET arm  -- K independent keygens all signing the SAME message+RNG (only sk
    varies); skip the site; record per-signature-byte effectiveness (faulted != that
    key's own golden);
  * INPUT control -- ONE key signing K different messages (secret fixed, background
    varies);
  * a byte POSITION is a phi_IF WITNESS if effectiveness is key-split there (some keys
    ineffective, some effective) significantly MORE under secret variation than under
    input variation (one-sided Fisher per position, BH-FDR at level `q`).

Operating point: tuned for RECALL (a candidate locator favours false positives over
false negatives) -- a loose default `q`, a ranked witness list, and the input control to
keep "secret-dependent" apart from "merely input-dependent".

Scope / caveats:
  * sampling has a false-negative floor the LLVM tool's constructive SMT search does not:
    a leak triggered by a tiny fraction of secrets can be missed at small K -- raise K.
  * a per-position `ineffective` witness LOCATES a SIFA candidate; it is NOT a proven
    exploit.
  * attribution of a position to a secret coefficient needs `profile.secret_coeffs`;
    without it (e.g. MAYO today) positions are reported by index.
"""

from dataclasses import dataclass, field

import numpy as np

from . import assess, detectors
from .faults import SKIP, FaultSpec
from .profiles import _scan_calls, signing_body
from .replay import Injector

DEFAULT_K = 32
DEFAULT_BUDGET = 40_000_000
DEFAULT_Q = 0.05


@dataclass
class PhiSite:
    pc: int
    label: str
    witnesses: list = field(default_factory=list)   # flagged byte positions (ranked)
    n_split: int = 0                                 # key-split positions tested
    attribution: str = ""                            # first witness -> secret coeff, if known


@dataclass
class PhiResult:
    scheme: str
    k: int
    q: float
    sites: list = field(default_factory=list)

    def witnesses(self):
        return [s for s in self.sites if s.witnesses]


def _resolve_sites(machine, body, wanted):
    """[(pc, label)] for the signing-body `bl` callees, optionally restricted to those
    whose label contains one of the `wanted` substrings (first occurrence of each)."""
    sites = []
    for pc, _t, label in _scan_calls(machine, body):
        if wanted is None:
            if pc not in {s[0] for s in sites}:
                sites.append((pc, label))
        else:
            for w in wanted:
                if w in label and not any(w in s[1] for s in sites):
                    sites.append((pc, label))
    return sites


def per_position_phi(scheme, profile, sites=None, k=DEFAULT_K, budget=DEFAULT_BUDGET,
                     q=DEFAULT_Q, sig_bytes=None, progress=None):
    """Score per-position phi_IF for each fault site, returning a `PhiResult`.

    `sites` -- comma/substring list (or list of substrings) restricting the signing-body
    callees to score; None scores every direct callee.  `k` -- keys (secret arm) and
    messages (input control).  `sig_bytes` -- released-artifact length (defaults to
    `profile.artifact_len`).
    """
    if isinstance(sites, str):
        sites = [s.strip() for s in sites.split(",") if s.strip()]
    sig_bytes = sig_bytes or profile.artifact_len
    if not sig_bytes:
        raise ValueError("per_position_phi needs a fixed artifact length "
                         "(profile.artifact_len); pass sig_bytes= for a variant-agnostic "
                         "profile")
    m = scheme.machine
    profile.setup(m)
    m.stub_cycle_counter()
    stream = m.stub_randombytes(b"seed")
    clean = m.snapshot()
    sign_fn = scheme.binding.symbols["signature"]
    entry = m.addr_of(sign_fn)
    body = signing_body(m, sign_fn)
    resolved = _resolve_sites(m, body, sites)

    # K independent keys (+ their labelled secret coeffs, if the profile offers them)
    keys, coeffs = [], []
    for i in range(k):
        sk = assess._keypair(scheme, f"key-{i:03d}".encode())[1]
        keys.append(sk)
        coeffs.append(profile.secret_coeffs(sk))
    key_a = keys[0]
    have_coeffs = all(c is not None for c in coeffs)

    def capture(sk, j):
        """Snapshot the signing body at entry for secret `sk` signing message j."""
        m.restore(clean)
        stream.reset(f"nonce-{j}".encode())
        box = {}

        def on_entry(mm, addr, size):
            if "snap" not in box:
                box["snap"] = mm.snapshot()
                box["ret"] = mm.reg("lr") & ~1
                box["sig"] = mm.reg("r0")
                mm.uc.emu_stop()
        h = m.hook_code(on_entry, begin=entry, end=entry, precise=False)
        try:
            scheme.sign(assess.standard_messages(j + 1)[j], sk, max_instructions=budget * 2)
        except Exception:
            pass
        finally:
            m.unhook(h)
        return box

    def run(box, pc=None):
        m.restore(box["snap"])
        inj = Injector(m, FaultSpec(kind=SKIP, pc=pc, hit=0)) if pc is not None else None
        try:
            m._emu_start(entry | 1, box["ret"], count=budget)
        except Exception:
            return None
        finally:
            if inj:
                inj.detach()
        return bytes(m.uc.mem_read(box["sig"], sig_bytes))

    sec_boxes = [capture(keys[i], 0) for i in range(k)]        # secret arm: fixed message
    sec_gold = [run(b) for b in sec_boxes]
    inp_boxes = [capture(key_a, j) for j in range(k)]          # input control: fixed key
    inp_gold = [run(b) for b in inp_boxes]

    def eff_matrix(boxes, golds, pc):
        M = np.zeros((len(boxes), sig_bytes), bool)
        for i, (box, g) in enumerate(zip(boxes, golds)):
            f = run(box, pc)
            if f is None or g is None:
                M[i, :] = True                                 # crash/runaway == fully effective
            else:
                M[i, :] = np.frombuffer(f, np.uint8) != np.frombuffer(g, np.uint8)
        return M

    coeff_flat = (np.array([c.ravel() for c in coeffs]) if have_coeffs else None)
    out_sites = []
    for pc, label in resolved:
        site = _score_site(pc, label, eff_matrix(sec_boxes, sec_gold, pc),
                           eff_matrix(inp_boxes, inp_gold, pc), coeff_flat, k, q)
        out_sites.append(site)
        if progress:
            progress(site)
    return PhiResult(scheme.name, k, q, out_sites)


def _score_site(pc, label, m_sec, m_inp, coeff_flat, k, q):
    """Per-position Fisher (secret-split vs input-split) + BH-FDR for one site."""
    from scipy.stats import fisher_exact
    sec_eff, inp_eff = m_sec.sum(0), m_inp.sum(0)
    positions, pvals = [], []
    for p in range(m_sec.shape[1]):
        se, ie = int(sec_eff[p]), int(inp_eff[p])
        if 0 < se < k:                                         # key-split here (the witness shape)
            positions.append(p)
            pvals.append(fisher_exact([[se, k - se], [ie, k - ie]], alternative="greater")[1])
    keep = detectors.bh_fdr(np.array(pvals), q) if pvals else []
    flagged = [p for p, ok in zip(positions, keep) if ok]
    attribution = _attribute(flagged, m_sec, coeff_flat) if flagged else ""
    return PhiSite(pc, label, flagged, len(positions), attribution)


def _attribute(flagged, m_sec, coeff_flat):
    """Attribute the first flagged position to the most-separating secret coefficient."""
    if coeff_flat is None:
        return f"pos {flagged[0]} (no secret_coeffs: index only)"
    p0 = flagged[0]
    eff = m_sec[:, p0]
    if not eff.any() or not (~eff).any():
        return f"pos {p0}"
    diff = np.abs(coeff_flat[eff].mean(0) - coeff_flat[~eff].mean(0))
    c = int(np.argmax(diff))                              # 256 coeffs per poly row
    return (f"pos {p0}: coeff[{c // 256},{c % 256}] "
            f"mean {coeff_flat[~eff][:, c].mean():.1f} (ineff) vs "
            f"{coeff_flat[eff][:, c].mean():.1f} (eff)")
